using System.Security.Cryptography;
using System.Text;
using PQAuthKit;

var tests = new (string Name, Action Run)[]
{
    ("selects .NET system provider when supported", SelectsDotNetSystemProviderWhenSupported),
    ("fails closed when no Windows provider exists", FailsClosedWhenNoProviderExists),
    ("selects approved managed fallback only when policy allows", SelectsApprovedManagedFallback),
    ("rejects native fallback dependencies", RejectsNativeFallbackDependencies),
    ("matches ML-DSA-65 lengths", MatchesMldsa65Lengths),
    ("blocks production deterministic entropy", BlocksProductionDeterministicEntropy),
    ("validates shared vector fixture", ValidatesSharedVectorFixture),
    ("smoke-tests .NET MLDsa when runtime supports it", SmokeTestsDotNetMldsaWhenSupported)
};

foreach (var (name, run) in tests)
{
    run();
    Console.WriteLine($"pass: {name}");
}

static void SelectsDotNetSystemProviderWhenSupported()
{
    var provider = WindowsProviderCatalog.Default().SelectProvider(
        WindowsProviderSelectionPolicy.RequiredMldsa65(),
        new WindowsRuntimeCapabilities(DotNetMldsaIsSupported: true, ManagedFallbackAvailable: false));

    Assert.Equal("dotnet.system-security-cryptography.mldsa65", provider.ProviderId);
    Assert.True(provider.IsPlatformNative);
    Assert.False(provider.UsesCOrFFI);
    Assert.False(provider.NativeLibraryDependency);
}

static void FailsClosedWhenNoProviderExists()
{
    Assert.Throws<PQAuthProviderSelectionException>(() =>
        WindowsProviderCatalog.Default().SelectProvider(
            WindowsProviderSelectionPolicy.RequiredMldsa65(),
            new WindowsRuntimeCapabilities(DotNetMldsaIsSupported: false, ManagedFallbackAvailable: false)));
}

static void SelectsApprovedManagedFallback()
{
    var catalog = new WindowsProviderCatalog(new[]
    {
        WindowsProviderCatalog.ManagedFallback(productionApproved: true)
    });

    var provider = catalog.SelectProvider(
        new WindowsProviderSelectionPolicy(
            PQAuthParameterSet.MLDsa65,
            HybridAuthRequired: true,
            AllowManagedFallback: true,
            IsProduction: true),
        new WindowsRuntimeCapabilities(DotNetMldsaIsSupported: false, ManagedFallbackAvailable: true));

    Assert.Equal("dotnet.managed-csharp.mldsa65.approved", provider.ProviderId);
    Assert.True(provider.FallbackAllowedInProduction);
    Assert.True(provider.HasApprovedProductionGates);
}

static void RejectsNativeFallbackDependencies()
{
    var catalog = new WindowsProviderCatalog(new[]
    {
        WindowsProviderCatalog.ManagedFallback(
            productionApproved: true,
            usesCOrFFI: true,
            nativeLibraryDependency: true)
    });

    Assert.Throws<PQAuthProviderSelectionException>(() =>
        catalog.SelectProvider(
            new WindowsProviderSelectionPolicy(
                PQAuthParameterSet.MLDsa65,
                HybridAuthRequired: true,
                AllowManagedFallback: true,
                IsProduction: true),
            new WindowsRuntimeCapabilities(DotNetMldsaIsSupported: false, ManagedFallbackAvailable: true)));
}

static void MatchesMldsa65Lengths()
{
    var metadata = PQAuthParameterSetMetadata.For(PQAuthParameterSet.MLDsa65);
    Assert.Equal(MLDsaAlgorithm.MLDsa65.PrivateKeySizeInBytes, metadata.PrivateKeyLength);
    Assert.Equal(MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes, metadata.PublicKeyLength);
    Assert.Equal(MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes, metadata.SignatureLength);
}

static void BlocksProductionDeterministicEntropy()
{
    Assert.SequenceEqual(new byte[] { 0, 1, 2, 3 }, PQAuthDeterministicTestEntropy.Bytes(4, production: false));
    Assert.Throws<InvalidOperationException>(() => PQAuthDeterministicTestEntropy.Bytes(4, production: true));
}

static void ValidatesSharedVectorFixture()
{
    var path = Path.GetFullPath("../../vectors/hybrid-trust-state-v1.json");
    var json = File.ReadAllText(path);

    Assert.Contains("\"schema\": \"pqauth-kit-hybrid-trust-state-v1\"", json);
    foreach (PQAuthTrustStateObject trustStateObject in Enum.GetValues<PQAuthTrustStateObject>())
    {
        Assert.Contains(trustStateObject.DomainSeparator(), json);
    }

    Assert.Equal(5, Count(json, "\"trustStateObject\""));
    Assert.Equal(9, Count(json, "\"expectedError\""));
    Assert.Contains("\"perMessagePQSignaturesEnabled\": false", json);

    var canonical = "{\"accountId\":\"acct-fixture-001\",\"displayName\":\"Fixture Account\",\"identityVersion\":1}";
    var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
    Assert.Contains($"\"signedBytesHash\": \"{hash}\"", json);
}

static void SmokeTestsDotNetMldsaWhenSupported()
{
    var provider = new DotNetMldsaProvider(PQAuthParameterSet.MLDsa65);
    Assert.Equal(MLDsa.IsSupported, provider.IsRuntimeSupported);

    if (!MLDsa.IsSupported)
    {
        Assert.Throws<PlatformNotSupportedException>(() => provider.GenerateKey());
        return;
    }

    using var key = provider.GenerateKey();
    var data = Encoding.UTF8.GetBytes("pqauth-kit-dotnet-smoke");
    var context = PQAuthTrustStateObject.DeviceIdentity.DomainContext();
    var signature = key.SignData(data, context);
    Assert.True(key.VerifyData(data, signature, context));
}

static int Count(string value, string needle) =>
    value.Split(needle, StringSplitOptions.None).Length - 1;

internal static class Assert
{
    public static void True(bool condition)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Expected condition to be true");
        }
    }

    public static void False(bool condition)
    {
        if (condition)
        {
            throw new InvalidOperationException("Expected condition to be false");
        }
    }

    public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"Expected {expected}, got {actual}");
        }
    }

    public static void Contains(string expected, string actual)
    {
        if (!actual.Contains(expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Expected to find '{expected}'");
        }
    }

    public static void SequenceEqual(byte[] expected, byte[] actual)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException("Expected byte sequences to match");
        }
    }

    public static void Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}");
    }
}
