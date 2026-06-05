using System.Security.Cryptography;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using PQAuthKit;

if (args.Contains("--emit-conformance-vector"))
{
    Console.WriteLine(GenerateMldsaConformanceVector());
    return;
}

if (args.Contains("--emit-benchmark"))
{
    Console.WriteLine(GenerateMldsaBenchmark());
    return;
}

var tests = new (string Name, Action Run)[]
{
    ("selects .NET system provider when supported", SelectsDotNetSystemProviderWhenSupported),
    ("fails closed when no Windows provider exists", FailsClosedWhenNoProviderExists),
    ("selects approved managed fallback only when policy allows", SelectsApprovedManagedFallback),
    ("requires explicit production readiness evidence", RequiresExplicitProductionReadinessEvidence),
    ("approves .NET system provider when evidence is complete", ApprovesDotNetSystemProviderWhenEvidenceIsComplete),
    ("rejects native fallback dependencies", RejectsNativeFallbackDependencies),
    ("matches ML-DSA-65 lengths", MatchesMldsa65Lengths),
    ("blocks production deterministic entropy", BlocksProductionDeterministicEntropy),
    ("validates shared vector fixture", ValidatesSharedVectorFixture),
    ("validates downstream server verifier contract evidence", ValidatesDownstreamServerVerifierContractEvidence),
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

static void ApprovesDotNetSystemProviderWhenEvidenceIsComplete()
{
    var provider = WindowsProviderCatalog.Default().SelectProvider(
        WindowsProviderSelectionPolicy.RequiredMldsa65(),
        new WindowsRuntimeCapabilities(DotNetMldsaIsSupported: true, ManagedFallbackAvailable: false));

    Assert.Equal("dotnet.system-security-cryptography.mldsa65", provider.ProviderId);
    Assert.True(provider.HasApprovedProductionGates);
    Assert.True(provider.IsProductionReady);
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

static void ValidatesDownstreamServerVerifierContractEvidence()
{
    var contract = ServerVerifierContractEvidence.Load(Path.GetFullPath("../../vectors/hybrid-trust-state-v1.json"));

    Assert.Equal("pqauth-kit-hybrid-trust-state-v1", contract.Schema);
    Assert.Equal("ed25519_and_mldsa_required", contract.Policy);
    Assert.Equal(5, contract.PositiveCases.Count);
    foreach (var trustStateObject in new[]
    {
        "account_identity",
        "device_identity",
        "roster_publish",
        "prekey_bundle",
        "safety_number"
    })
    {
        Assert.Contains(trustStateObject, contract.PositiveCases.Select(testCase => testCase.TrustStateObject));
    }

    var serverPolicy = new ServerVerifierPolicy(
        ApprovedMldsaProviderAvailable: true,
        AllowEd25519OnlyMigrationMode: false);
    foreach (var positiveCase in contract.PositiveCases)
    {
        Assert.Equal("ok", contract.VerifyTrustStateWrite(positiveCase, serverPolicy));
        Assert.Equal("ok", contract.VerifyTrustStateRead(positiveCase, serverPolicy));
    }

    Assert.Equal(9, contract.NegativeCases.Count);
    foreach (var negativeCase in contract.NegativeCases)
    {
        var mutated = contract.Mutate(negativeCase);
        Assert.Equal(negativeCase.ExpectedError, contract.VerifyTrustStateWrite(mutated, serverPolicy));
        Assert.Equal(negativeCase.ExpectedError, contract.VerifyTrustStateRead(mutated, serverPolicy));
    }

    var providerUnavailablePolicy = serverPolicy with { ApprovedMldsaProviderAvailable = false };
    Assert.Equal(
        "no_approved_mldsa_provider",
        contract.VerifyTrustStateWrite(contract.PositiveCases[0], providerUnavailablePolicy));
    Assert.Equal(
        "no_approved_mldsa_provider",
        contract.VerifyTrustStateRead(contract.PositiveCases[0], providerUnavailablePolicy));

    var readiness = File.ReadAllText(Path.GetFullPath("../../docs/evidence/readiness-gates-v1.json"));
    Assert.Contains("\"evidenceId\": \"server-verifier-trust-state-integration-2026-06-04\"", readiness);
    Assert.Contains("\"loadsSharedContractDirectly\": true", readiness);
    Assert.Contains("\"failClosedWithoutApprovedMldsaProvider\": true", readiness);
    Assert.Contains("\"ed25519OnlyDowngradeRejectedOutsideMigrationMode\": true", readiness);

    var evidence = File.ReadAllText(Path.GetFullPath("../../docs/evidence/server-verifier-trust-state-integration-2026-06-04.md"));
    Assert.Contains("vectors/hybrid-trust-state-v1.json", evidence);
    Assert.Contains("server/verifier", evidence);
    Assert.Contains("no_approved_mldsa_provider", evidence);
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
    using var readiness = JsonDocument.Parse(File.ReadAllText(Path.GetFullPath("../../docs/evidence/readiness-gates-v1.json")));
    var root = readiness.RootElement;
    Assert.Equal("pqauth-kit-readiness-gates-v1", root.GetProperty("schema").GetString());

    var providers = root.GetProperty("providers").EnumerateArray().ToArray();
    var macOS = ProviderById(providers, "apple.cryptokit.mldsa65.macos");
    Assert.Equal("apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05", macOS.GetProperty("conformanceVectorId").GetString());
    Assert.Equal("apple-cryptokit-mldsa65-macos-local-benchmark-2026-06-04", macOS.GetProperty("benchmarkReportId").GetString());
    Assert.Equal("apple-cryptokit-mldsa65-macos-side-channel-review-2026-06-04", macOS.GetProperty("sideChannelReviewId").GetString());
    Assert.True(macOS.GetProperty("productionReady").GetBoolean());

    var iOS = ProviderById(providers, "apple.cryptokit.mldsa65.ios");
    Assert.Equal("apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05", iOS.GetProperty("conformanceVectorId").GetString());
    Assert.Equal("apple-cryptokit-mldsa65-ios-release-device-benchmark-2026-06-05", iOS.GetProperty("benchmarkReportId").GetString());
    Assert.Equal("apple-cryptokit-mldsa65-ios-side-channel-review-2026-06-05", iOS.GetProperty("sideChannelReviewId").GetString());
    Assert.True(iOS.GetProperty("productionReady").GetBoolean());

    var windows = ProviderById(providers, "dotnet.system-security-cryptography.mldsa65");
    Assert.Equal("windows-dotnet-mldsa-github-actions-evidence-2026-06-05", windows.GetProperty("conformanceVectorId").GetString());
    Assert.Equal("windows-dotnet-mldsa65-github-actions-benchmark-2026-06-05", windows.GetProperty("benchmarkReportId").GetString());
    Assert.Equal("windows-dotnet-mldsa65-side-channel-review-2026-06-05", windows.GetProperty("sideChannelReviewId").GetString());
    Assert.True(windows.GetProperty("productionReady").GetBoolean());

    var benchmark = File.ReadAllText(Path.GetFullPath("../../docs/evidence/apple-cryptokit-mldsa65-macos-benchmark-2026-06-04.json"));
    Assert.Contains("\"schema\" : \"pqauth-kit-benchmark-evidence-v1\"", benchmark);
    Assert.Contains("\"keygen\"", benchmark);
    Assert.Contains("\"sign\"", benchmark);
    Assert.Contains("\"verify\"", benchmark);
    Assert.Contains("\"malformedPublicKeyRejection\"", benchmark);
    Assert.Contains("\"malformedSignatureRejection\"", benchmark);
}

static JsonElement ProviderById(IEnumerable<JsonElement> providers, string providerId)
{
    foreach (var provider in providers)
    {
        if (provider.GetProperty("providerId").GetString() == providerId)
        {
            return provider;
        }
    }

    throw new InvalidOperationException($"Missing provider {providerId}");
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

    var contract = ServerVerifierContractEvidence.Load(Path.GetFullPath("../../vectors/hybrid-trust-state-v1.json"));

    var vector = new
    {
        schema = "pqauth-kit-mldsa-conformance-v1",
        version = 1,
        fixtureKind = "cryptographic-provider-conformance",
        generatedAt = DateTimeOffset.UtcNow.ToString("o"),
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
        providerBackedTrustStateObjects = contract.PositiveCases
            .Select(testCase => testCase.TrustStateObject)
            .ToArray(),
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
        cases = contract.PositiveCases.Select(testCase =>
            {
                using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                var signedBytes = Encoding.UTF8.GetBytes(testCase.CanonicalBytesUtf8);
                var context = Encoding.UTF8.GetBytes(testCase.SignedBytesDomain);
                var signature = key.SignData(signedBytes, context);
                var publicKey = key.ExportMLDsaPublicKey();
                var privateKey = key.ExportMLDsaPrivateKey();

                return new
                {
                    id = $"dotnet_mldsa65_{testCase.TrustStateObject}_{DateTimeOffset.UtcNow:yyyy_MM_dd}",
                    providerId = "dotnet.system-security-cryptography.mldsa65",
                    trustStateObject = testCase.TrustStateObject,
                    signedBytesDomain = testCase.SignedBytesDomain,
                    canonicalBytesUtf8 = testCase.CanonicalBytesUtf8,
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
                };
            })
            .ToArray(),
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

static string GenerateMldsaBenchmark()
{
    if (!MLDsa.IsSupported)
    {
        throw new PlatformNotSupportedException("ML-DSA is not supported by this .NET runtime");
    }

    var contract = ServerVerifierContractEvidence.Load(Path.GetFullPath("../../vectors/hybrid-trust-state-v1.json"));
    var provider = new DotNetMldsaProvider(PQAuthParameterSet.MLDsa65);
    var metadata = PQAuthParameterSetMetadata.For(PQAuthParameterSet.MLDsa65);
    var firstCase = contract.PositiveCases[0];
    var signedBytes = Encoding.UTF8.GetBytes(firstCase.CanonicalBytesUtf8);
    var context = Encoding.UTF8.GetBytes(firstCase.SignedBytesDomain);

    using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    var publicKey = key.ExportMLDsaPublicKey();
    var privateKey = key.ExportMLDsaPrivateKey();
    var signature = key.SignData(signedBytes, context);

    var benchmark = new
    {
        schema = "pqauth-kit-benchmark-evidence-v1",
        benchmarkReportId = "windows-dotnet-mldsa65-github-actions-benchmark-2026-06-05",
        providerId = "dotnet.system-security-cryptography.mldsa65",
        benchmarkDate = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd"),
        benchmarkCommand = "dotnet run --no-build --project PQAuthKit.Tests.csproj --configuration Release -- --emit-benchmark",
        runner = new
        {
            os = Environment.GetEnvironmentVariable("RUNNER_OS") ?? RuntimeInformation.OSDescription,
            architecture = Environment.GetEnvironmentVariable("RUNNER_ARCH") ?? RuntimeInformation.OSArchitecture.ToString(),
            imageOS = Environment.GetEnvironmentVariable("ImageOS"),
            imageVersion = Environment.GetEnvironmentVariable("ImageVersion"),
            githubRunId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID"),
            githubSha = Environment.GetEnvironmentVariable("GITHUB_SHA")
        },
        dotnet = new
        {
            runtimeVersion = Environment.Version.ToString(),
            osDescription = RuntimeInformation.OSDescription,
            architecture = RuntimeInformation.OSArchitecture.ToString()
        },
        algorithm = new
        {
            name = "ML-DSA",
            parameterSet = metadata.WireName,
            privateKeyLength = metadata.PrivateKeyLength,
            publicKeyLength = metadata.PublicKeyLength,
            signatureLength = metadata.SignatureLength
        },
        providerBackedTrustStateObjects = contract.PositiveCases
            .Select(testCase => testCase.TrustStateObject)
            .ToArray(),
        operations = new
        {
            keygen = Measure(20, () =>
            {
                using var generated = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                _ = generated.ExportMLDsaPublicKey();
            }),
            sign = Measure(50, () =>
            {
                _ = key.SignData(signedBytes, context);
            }),
            verify = Measure(50, () =>
            {
                if (!key.VerifyData(signedBytes, signature, context))
                {
                    throw new InvalidOperationException("Expected ML-DSA verification to pass");
                }
            }),
            publicKeyExport = Measure(50, () =>
            {
                _ = key.ExportMLDsaPublicKey();
            }),
            privateKeyExport = Measure(20, () =>
            {
                _ = key.ExportMLDsaPrivateKey();
            }),
            privateKeyImport = Measure(20, () =>
            {
                using var imported = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privateKey);
                _ = imported.ExportMLDsaPublicKey();
            }),
            malformedPublicKeyRejection = Measure(50, () =>
            {
                Assert.Throws<ArgumentException>(() => provider.VerifyData(signedBytes, signature, context, publicKey[..^1]));
            }),
            malformedSignatureRejection = Measure(50, () =>
            {
                Assert.Throws<ArgumentException>(() => provider.VerifyData(signedBytes, signature[..^1], context, publicKey));
            })
        },
        remainingRisk = "GitHub Actions hosted-runner timing evidence; dedicated pinned Windows hardware and provider-internals side-channel review remain separate follow-up evidence."
    };

    return JsonSerializer.Serialize(benchmark, new JsonSerializerOptions { WriteIndented = true });
}

static BenchmarkStats Measure(int iterations, Action operation)
{
    var elapsedMilliseconds = new List<double>(iterations);
    operation();

    for (var index = 0; index < iterations; index += 1)
    {
        var stopwatch = Stopwatch.StartNew();
        operation();
        stopwatch.Stop();
        elapsedMilliseconds.Add(stopwatch.Elapsed.TotalMilliseconds);
    }

    elapsedMilliseconds.Sort();
    return new BenchmarkStats(
        iterations,
        elapsedMilliseconds[0],
        Percentile(elapsedMilliseconds, 0.50),
        Percentile(elapsedMilliseconds, 0.95),
        elapsedMilliseconds[^1]);
}

static double Percentile(IReadOnlyList<double> sortedValues, double percentile)
{
    var index = (int)Math.Ceiling(percentile * sortedValues.Count) - 1;
    return sortedValues[Math.Clamp(index, 0, sortedValues.Count - 1)];
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

internal sealed record ServerVerifierPolicy(
    bool ApprovedMldsaProviderAvailable,
    bool AllowEd25519OnlyMigrationMode);

internal sealed class ServerVerifierContractEvidence
{
    private readonly IReadOnlyDictionary<string, TrustStateCase> positiveCasesById;
    private readonly IReadOnlyDictionary<string, string> domainByTrustStateObject;

    private ServerVerifierContractEvidence(
        string schema,
        string policy,
        MldsaLengths mldsaLengths,
        IReadOnlyList<TrustStateCase> positiveCases,
        IReadOnlyList<NegativeTrustStateCase> negativeCases)
    {
        Schema = schema;
        Policy = policy;
        MldsaLengths = mldsaLengths;
        PositiveCases = positiveCases;
        NegativeCases = negativeCases;
        positiveCasesById = positiveCases.ToDictionary(testCase => testCase.Id);
        domainByTrustStateObject = positiveCases.ToDictionary(
            testCase => testCase.TrustStateObject,
            testCase => testCase.SignedBytesDomain);
    }

    public string Schema { get; }
    public string Policy { get; }
    public MldsaLengths MldsaLengths { get; }
    public IReadOnlyList<TrustStateCase> PositiveCases { get; }
    public IReadOnlyList<NegativeTrustStateCase> NegativeCases { get; }

    public static ServerVerifierContractEvidence Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var algorithms = root.GetProperty("algorithms").GetProperty("mldsa");
        var positiveCases = root.GetProperty("positiveCases")
            .EnumerateArray()
            .Select(ParseTrustStateCase)
            .ToList();
        var negativeCases = root.GetProperty("negativeCases")
            .EnumerateArray()
            .Select(ParseNegativeCase)
            .ToList();

        return new ServerVerifierContractEvidence(
            root.GetProperty("schema").GetString()!,
            root.GetProperty("policy").GetString()!,
            new MldsaLengths(
                algorithms.GetProperty("publicKeyLength").GetInt32(),
                algorithms.GetProperty("signatureLength").GetInt32()),
            positiveCases,
            negativeCases);
    }

    public TrustStateCase Mutate(NegativeTrustStateCase negativeCase)
    {
        var positiveCase = positiveCasesById[negativeCase.BasePositiveCase];
        return negativeCase.Mutation switch
        {
            "remove_mldsa_signature" => positiveCase with { Mldsa = null },
            "remove_ed25519_signature" => positiveCase with { Ed25519 = null },
            "mldsa_signs_different_canonical_bytes" => positiveCase with
            {
                MldsaSignedBytesHash = "server-verifier-negative-different-signed-bytes"
            },
            "replace_mldsa_context" => positiveCase with
            {
                Mldsa = positiveCase.Mldsa! with
                {
                    Context = Base64UrlEncode(Encoding.UTF8.GetBytes("wrong-mldsa-context"))
                }
            },
            "replace_signed_bytes_domain" => positiveCase with
            {
                SignedBytesDomain = "pqauth-kit-wrong-domain-v1"
            },
            "truncate_mldsa_public_key" => positiveCase with
            {
                Mldsa = positiveCase.Mldsa! with
                {
                    PublicKeyLength = positiveCase.Mldsa.PublicKeyLength - 1
                }
            },
            "truncate_mldsa_signature" => positiveCase with
            {
                Mldsa = positiveCase.Mldsa! with
                {
                    SignatureLength = positiveCase.Mldsa.SignatureLength - 1
                }
            },
            "replace_parameter_set_with_ml_dsa_44" => positiveCase with
            {
                Mldsa = positiveCase.Mldsa! with { Algorithm = "ML-DSA-44" }
            },
            "remove_mldsa_signature_without_migration_mode" => positiveCase with
            {
                Mldsa = null,
                Ed25519OnlyDowngrade = true
            },
            _ => throw new InvalidOperationException($"Unsupported mutation {negativeCase.Mutation}")
        };
    }

    public string VerifyTrustStateWrite(TrustStateCase testCase, ServerVerifierPolicy policy) =>
        Verify(testCase, policy);

    public string VerifyTrustStateRead(TrustStateCase testCase, ServerVerifierPolicy policy) =>
        Verify(testCase, policy);

    private string Verify(TrustStateCase testCase, ServerVerifierPolicy policy)
    {
        if (!domainByTrustStateObject.TryGetValue(testCase.TrustStateObject, out var expectedDomain) ||
            testCase.SignedBytesDomain != expectedDomain)
        {
            return "domain_separator_mismatch";
        }

        if (testCase.Ed25519 is null)
        {
            return "ed25519_signature_required";
        }

        if (testCase.Mldsa is null)
        {
            return testCase.Ed25519OnlyDowngrade && !policy.AllowEd25519OnlyMigrationMode
                ? "hybrid_auth_profile_required"
                : "mldsa_signature_required";
        }

        if (!policy.ApprovedMldsaProviderAvailable)
        {
            return "no_approved_mldsa_provider";
        }

        if (testCase.Mldsa.Algorithm != "ML-DSA-65")
        {
            return "mldsa_parameter_set_unsupported";
        }

        if (testCase.Mldsa.PublicKeyLength != MldsaLengths.PublicKeyLength)
        {
            return "mldsa_public_key_length_invalid";
        }

        if (testCase.Mldsa.SignatureLength != MldsaLengths.SignatureLength)
        {
            return "mldsa_signature_length_invalid";
        }

        if (testCase.MldsaSignedBytesHash != testCase.SignedBytesHash ||
            SignedBytesHash(testCase.CanonicalBytesUtf8) != testCase.SignedBytesHash)
        {
            return "signed_bytes_mismatch";
        }

        if (testCase.Mldsa.Context != Base64UrlEncode(Encoding.UTF8.GetBytes(testCase.SignedBytesDomain)))
        {
            return "mldsa_context_mismatch";
        }

        return "ok";
    }

    private static TrustStateCase ParseTrustStateCase(JsonElement entry)
    {
        var signature = entry.GetProperty("hybridSignature");
        return new TrustStateCase(
            entry.GetProperty("id").GetString()!,
            entry.GetProperty("trustStateObject").GetString()!,
            entry.GetProperty("signedBytesDomain").GetString()!,
            entry.GetProperty("canonicalBytesUtf8").GetString()!,
            entry.GetProperty("signedBytesHash").GetString()!,
            ParseEd25519Signature(signature.GetProperty("ed25519")),
            ParseMldsaSignature(signature.GetProperty("mldsa")),
            entry.GetProperty("signedBytesHash").GetString()!,
            Ed25519OnlyDowngrade: false);
    }

    private static Ed25519Signature ParseEd25519Signature(JsonElement entry) => new(
        entry.GetProperty("publicKeyFixture").GetProperty("length").GetInt32(),
        entry.GetProperty("signatureFixture").GetProperty("length").GetInt32());

    private static MldsaSignature ParseMldsaSignature(JsonElement entry) => new(
        entry.GetProperty("algorithm").GetString()!,
        entry.GetProperty("publicKeyFixture").GetProperty("length").GetInt32(),
        entry.GetProperty("signatureFixture").GetProperty("length").GetInt32(),
        entry.GetProperty("context").GetString()!);

    private static NegativeTrustStateCase ParseNegativeCase(JsonElement entry) => new(
        entry.GetProperty("id").GetString()!,
        entry.GetProperty("basePositiveCase").GetString()!,
        entry.GetProperty("mutation").GetString()!,
        entry.GetProperty("expectedError").GetString()!);

    private static string SignedBytesHash(string canonicalBytesUtf8) =>
        Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalBytesUtf8)));

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

internal sealed record MldsaLengths(int PublicKeyLength, int SignatureLength);

internal sealed record BenchmarkStats(
    int Iterations,
    double MinMs,
    double P50Ms,
    double P95Ms,
    double MaxMs);

internal sealed record TrustStateCase(
    string Id,
    string TrustStateObject,
    string SignedBytesDomain,
    string CanonicalBytesUtf8,
    string SignedBytesHash,
    Ed25519Signature? Ed25519,
    MldsaSignature? Mldsa,
    string MldsaSignedBytesHash,
    bool Ed25519OnlyDowngrade);

internal sealed record Ed25519Signature(int PublicKeyLength, int SignatureLength);

internal sealed record MldsaSignature(
    string Algorithm,
    int PublicKeyLength,
    int SignatureLength,
    string Context);

internal sealed record NegativeTrustStateCase(
    string Id,
    string BasePositiveCase,
    string Mutation,
    string ExpectedError);

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
