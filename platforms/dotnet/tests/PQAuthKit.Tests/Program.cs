using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using PQAuthKit;

if (args.Contains("--emit-conformance-vector"))
{
    Console.WriteLine(GenerateMldsaConformanceVector());
    return;
}

var tests = new (string Name, Action Run)[]
{
    ("selects .NET system provider when supported", SelectsDotNetSystemProviderWhenSupported),
    ("fails closed when no Windows provider exists", FailsClosedWhenNoProviderExists),
    ("selects approved managed fallback only when policy allows", SelectsApprovedManagedFallback),
    ("requires explicit production readiness evidence", RequiresExplicitProductionReadinessEvidence),
    ("keeps provider selection distinct from production readiness", KeepsProviderSelectionDistinctFromProductionReadiness),
    ("rejects native fallback dependencies", RejectsNativeFallbackDependencies),
    ("matches ML-DSA-65 lengths", MatchesMldsa65Lengths),
    ("blocks production deterministic entropy", BlocksProductionDeterministicEntropy),
    ("validates shared vector fixture", ValidatesSharedVectorFixture),
    ("validates ML-DSA conformance vector", ValidatesMldsaConformanceVector),
    ("validates readiness evidence manifests", ValidatesReadinessEvidenceManifests),
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
        WindowsProviderCatalog.ManagedFallback(productionApproved: true, evidence: CompleteEvidence())
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
    Assert.True(provider.IsProductionReady);
}

static void RequiresExplicitProductionReadinessEvidence()
{
    var provider = WindowsProviderCatalog.ManagedFallback(productionApproved: true);

    Assert.True(provider.HasApprovedProductionGates);
    Assert.False(provider.IsProductionReady);
    Assert.Contains("required_evidence_missing", PQAuthReadinessGate.Blockers(provider));
}

static void KeepsProviderSelectionDistinctFromProductionReadiness()
{
    var provider = WindowsProviderCatalog.Default().SelectProvider(
        WindowsProviderSelectionPolicy.RequiredMldsa65(),
        new WindowsRuntimeCapabilities(DotNetMldsaIsSupported: true, ManagedFallbackAvailable: false));

    Assert.Equal("dotnet.system-security-cryptography.mldsa65", provider.ProviderId);
    Assert.False(provider.IsProductionReady);
    Assert.Contains("benchmark_status_not_approved", PQAuthReadinessGate.Blockers(provider));
    Assert.Contains("side_channel_review_status_not_approved", PQAuthReadinessGate.Blockers(provider));
}

static void RejectsNativeFallbackDependencies()
{
    var catalog = new WindowsProviderCatalog(new[]
    {
        WindowsProviderCatalog.ManagedFallback(
            productionApproved: true,
            usesCOrFFI: true,
            nativeLibraryDependency: true,
            evidence: CompleteEvidence())
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

static void ValidatesMldsaConformanceVector()
{
    var path = Path.GetFullPath("../../vectors/mldsa-conformance-v1.json");
    using var document = JsonDocument.Parse(File.ReadAllText(path));
    var root = document.RootElement;

    Assert.Equal("pqauth-kit-mldsa-conformance-v1", root.GetProperty("schema").GetString());
    Assert.Equal("cryptographic-provider-conformance", root.GetProperty("fixtureKind").GetString());
    Assert.Contains("keygen", Operations(root));
    Assert.Contains("sign", Operations(root));
    Assert.Contains("verify", Operations(root));
    Assert.Contains("public-key-import", Operations(root));
    Assert.Contains("private-key-import", Operations(root));

    if (!MLDsa.IsSupported)
    {
        Console.WriteLine("skip: .NET MLDsa conformance verification requires runtime support");
        return;
    }

    var testCase = root.GetProperty("cases")[0];
    var signedBytes = Encoding.UTF8.GetBytes(testCase.GetProperty("canonicalBytesUtf8").GetString()!);
    var context = Base64UrlDecode(testCase.GetProperty("context").GetString()!);
    var publicKey = Base64UrlDecode(testCase.GetProperty("publicKey").GetProperty("value").GetString()!);
    var signature = Base64UrlDecode(testCase.GetProperty("signature").GetProperty("value").GetString()!);

    var provider = new DotNetMldsaProvider(PQAuthParameterSet.MLDsa65);
    Assert.True(provider.VerifyData(signedBytes, signature, context, publicKey));
    Assert.False(provider.VerifyData(Encoding.UTF8.GetBytes("wrong canonical bytes"), signature, context, publicKey));
    Assert.False(provider.VerifyData(signedBytes, signature, Encoding.UTF8.GetBytes("wrong context"), publicKey));

    var privateKey = testCase.GetProperty("privateKey");
    if (privateKey.GetProperty("encoding").GetString() == "base64url-raw-fips204-private-key-test-fixture")
    {
        var privateKeyBytes = Base64UrlDecode(privateKey.GetProperty("value").GetString()!);
        var regeneratedSignature = provider.SignData(signedBytes, context, privateKeyBytes);
        Assert.Equal(PQAuthParameterSetMetadata.For(PQAuthParameterSet.MLDsa65).SignatureLength, regeneratedSignature.Length);
        Assert.True(provider.VerifyData(signedBytes, regeneratedSignature, context, publicKey));
    }

    Assert.Throws<ArgumentException>(() => provider.VerifyData(signedBytes, signature, context, publicKey[..^1]));
    Assert.Throws<ArgumentException>(() => provider.VerifyData(signedBytes, signature[..^1], context, publicKey));
}

static void ValidatesReadinessEvidenceManifests()
{
    var readiness = File.ReadAllText(Path.GetFullPath("../../docs/evidence/readiness-gates-v1.json"));
    Assert.Contains("\"schema\": \"pqauth-kit-readiness-gates-v1\"", readiness);
    Assert.Contains("\"providerId\": \"apple.cryptokit.mldsa65.macos\"", readiness);
    Assert.Contains("\"benchmarkReportId\": \"apple-cryptokit-mldsa65-macos-local-benchmark-2026-06-04\"", readiness);
    Assert.Contains("\"sideChannelReviewId\": \"apple-cryptokit-mldsa65-macos-side-channel-review-2026-06-04\"", readiness);
    Assert.Contains("\"productionReady\": false", readiness);

    var benchmark = File.ReadAllText(Path.GetFullPath("../../docs/evidence/apple-cryptokit-mldsa65-macos-benchmark-2026-06-04.json"));
    Assert.Contains("\"schema\" : \"pqauth-kit-benchmark-evidence-v1\"", benchmark);
    Assert.Contains("\"keygen\"", benchmark);
    Assert.Contains("\"sign\"", benchmark);
    Assert.Contains("\"verify\"", benchmark);
    Assert.Contains("\"malformedPublicKeyRejection\"", benchmark);
    Assert.Contains("\"malformedSignatureRejection\"", benchmark);
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

static string GenerateMldsaConformanceVector()
{
    if (!MLDsa.IsSupported)
    {
        throw new PlatformNotSupportedException("ML-DSA is not supported by this .NET runtime");
    }

    using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    var canonicalBytes = "{\"subject\":\"pqauth-kit-conformance\",\"trustStateObject\":\"device_identity\",\"version\":1}";
    var context = Encoding.UTF8.GetBytes(PQAuthTrustStateObject.DeviceIdentity.DomainSeparator());
    var signedBytes = Encoding.UTF8.GetBytes(canonicalBytes);
    var signature = key.SignData(signedBytes, context);
    var publicKey = key.ExportMLDsaPublicKey();
    var privateKey = key.ExportMLDsaPrivateKey();

    var vector = new
    {
        schema = "pqauth-kit-mldsa-conformance-v1",
        version = 1,
        fixtureKind = "cryptographic-provider-conformance",
        generatedAt = "2026-06-04",
        generatedBy = new
        {
            providerId = "dotnet.system-security-cryptography.mldsa65",
            runtimeVersion = Environment.Version.ToString(),
            osDescription = RuntimeInformation.OSDescription,
            architecture = RuntimeInformation.OSArchitecture.ToString(),
            providerSourceId = "dotnet-system-security-cryptography-mldsa-docs-2026-06-04",
            providerCommit = "94ea82652c",
            packageCommitAtGeneration = "bdccefb89a2c933513c99f658cd2070d8740236c"
        },
        algorithm = new
        {
            name = "ML-DSA",
            parameterSet = "ML-DSA-65",
            privateKeyLength = MLDsaAlgorithm.MLDsa65.PrivateKeySizeInBytes,
            publicKeyLength = MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes,
            signatureLength = MLDsaAlgorithm.MLDsa65.SignatureSizeInBytes
        },
        operations = new[]
        {
            "keygen",
            "sign",
            "verify",
            "public-key-export",
            "private-key-export",
            "public-key-import",
            "private-key-import",
            "signed-bytes-mismatch-rejection",
            "wrong-context-rejection",
            "malformed-public-key-rejection",
            "malformed-signature-rejection"
        },
        cases = new[]
        {
            new
            {
                id = "dotnet_mldsa65_device_identity_2026_06_04",
                providerId = "dotnet.system-security-cryptography.mldsa65",
                trustStateObject = "device_identity",
                signedBytesDomain = PQAuthTrustStateObject.DeviceIdentity.DomainSeparator(),
                canonicalBytesUtf8 = canonicalBytes,
                signedBytesHash = Base64Url(SHA256.HashData(signedBytes)),
                context = Base64Url(context),
                publicKey = new
                {
                    encoding = "base64url-raw-fips204-public-key",
                    value = Base64Url(publicKey),
                    length = publicKey.Length
                },
                privateKey = new
                {
                    encoding = "base64url-raw-fips204-private-key-test-fixture",
                    value = Base64Url(privateKey),
                    length = privateKey.Length,
                    secret = false
                },
                signature = new
                {
                    encoding = "base64url-raw-fips204-signature",
                    value = Base64Url(signature),
                    length = signature.Length
                },
                expected = "verify_true"
            }
        },
        negativeCases = new[]
        {
            new { id = "signed_bytes_mismatch", mutation = "replace_canonical_bytes", expected = "verify_false" },
            new { id = "wrong_context", mutation = "replace_context", expected = "verify_false" },
            new { id = "malformed_public_key", mutation = "truncate_public_key", expected = "reject_length" },
            new { id = "malformed_signature", mutation = "truncate_signature", expected = "reject_length" }
        }
    };

    return JsonSerializer.Serialize(vector, new JsonSerializerOptions { WriteIndented = true });
}

static int Count(string value, string needle) =>
    value.Split(needle, StringSplitOptions.None).Length - 1;

static IReadOnlyList<string> Operations(JsonElement root) =>
    root.GetProperty("operations").EnumerateArray().Select(item => item.GetString()!).ToList();

static PQAuthEvidenceReferences CompleteEvidence() => PQAuthEvidenceReferences.Complete(
    providerSourceId: "dotnet-fallback-test-source",
    providerVersion: "test-version",
    license: "test-license",
    conformanceVectorId: "test-conformance-vector",
    auditReportId: "test-audit-report",
    benchmarkReportId: "test-benchmark-report",
    sideChannelReviewId: "test-side-channel-review");

static string Base64Url(byte[] value) =>
    Convert.ToBase64String(value)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

static byte[] Base64UrlDecode(string value)
{
    var padded = value.Replace('-', '+').Replace('_', '/');
    padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
    return Convert.FromBase64String(padded);
}

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

    public static void Contains(string expected, IEnumerable<string> actual)
    {
        if (!actual.Contains(expected))
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
