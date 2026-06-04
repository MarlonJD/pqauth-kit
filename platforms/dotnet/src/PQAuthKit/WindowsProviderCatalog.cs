namespace PQAuthKit;

public sealed record WindowsRuntimeCapabilities(
    bool DotNetMldsaIsSupported,
    bool ManagedFallbackAvailable);

public sealed record WindowsProviderSelectionPolicy(
    PQAuthParameterSet RequestedParameterSet,
    bool HybridAuthRequired,
    bool AllowManagedFallback,
    bool IsProduction)
{
    public static WindowsProviderSelectionPolicy RequiredMldsa65() =>
        new(PQAuthParameterSet.MLDsa65, HybridAuthRequired: true, AllowManagedFallback: false, IsProduction: true);
}

public sealed class WindowsProviderCatalog(IReadOnlyList<PQAuthProviderMetadata> providers)
{
    public IReadOnlyList<PQAuthProviderMetadata> Providers { get; } = providers;

    public PQAuthProviderMetadata SelectProvider(
        WindowsProviderSelectionPolicy policy,
        WindowsRuntimeCapabilities runtime)
    {
        var matchingProviders = Providers.Where(provider => provider.ParameterSet == policy.RequestedParameterSet).ToList();

        var systemProvider = matchingProviders.FirstOrDefault(provider =>
            provider.IsPlatformNative &&
            provider.ProviderId == "dotnet.system-security-cryptography.mldsa65" &&
            runtime.DotNetMldsaIsSupported);

        if (systemProvider is not null)
        {
            return systemProvider;
        }

        if (policy.AllowManagedFallback && runtime.ManagedFallbackAvailable)
        {
            var fallback = matchingProviders.FirstOrDefault(provider => FallbackPermitted(provider, policy));
            if (fallback is not null)
            {
                return fallback;
            }
        }

        if (policy.HybridAuthRequired)
        {
            throw new PQAuthProviderSelectionException("no approved Windows ML-DSA provider");
        }

        throw new PQAuthProviderSelectionException("hybrid auth disabled and no provider selected");
    }

    private static bool FallbackPermitted(
        PQAuthProviderMetadata provider,
        WindowsProviderSelectionPolicy policy)
    {
        if (provider.IsPlatformNative || provider.UsesCOrFFI || provider.NativeLibraryDependency)
        {
            return false;
        }

        return policy.IsProduction
            ? provider.FallbackAllowedInProduction && provider.IsProductionReady
            : provider.IsProductionReady;
    }

    public static WindowsProviderCatalog Default() => new(
        new[]
        {
            DotNetSystemProvider(),
            ManagedFallback(productionApproved: false)
        });

    public static PQAuthProviderMetadata DotNetSystemProvider() => new(
        ProviderId: "dotnet.system-security-cryptography.mldsa65",
        Algorithm: PQAuthAlgorithm.MLDsa,
        ParameterSet: PQAuthParameterSet.MLDsa65,
        IsPlatformNative: true,
        IsHardwareIsolated: false,
        MinimumOSOrRuntime: ".NET 10 with MLDsa.IsSupported",
        SupportsKeyGeneration: true,
        SupportsSign: true,
        SupportsVerify: true,
        PrivateKeyExportPolicy: PQAuthPrivateKeyExportPolicy.PlatformWrapped,
        UsesCOrFFI: false,
        NativeLibraryDependency: false,
        FallbackAllowedInProduction: false,
        AuditStatus: PQAuthGateStatus.Approved,
        BenchmarkStatus: PQAuthGateStatus.Pending,
        SideChannelReviewStatus: PQAuthGateStatus.Pending,
        Evidence: new PQAuthEvidenceReferences(
            ProviderSourceId: "dotnet-system-security-cryptography-mldsa-docs-2026-06-04",
            ProviderVersion: ".NET 10 System.Security.Cryptography.MLDsa",
            ProviderCommit: "94ea82652c",
            License: ".NET documentation and runtime license",
            ConformanceVectorId: "dotnet-system-security-cryptography-mldsa65-runtime-2026-06-04",
            AuditReportId: "dotnet-provider-doc-review-2026-06-04",
            RemainingRisk: "Release-device benchmark and side-channel evidence remain pending."));

    public static PQAuthProviderMetadata ManagedFallback(
        bool productionApproved,
        bool usesCOrFFI = false,
        bool nativeLibraryDependency = false,
        PQAuthEvidenceReferences? evidence = null) => new(
        ProviderId: productionApproved ? "dotnet.managed-csharp.mldsa65.approved" : "dotnet.managed-csharp.mldsa65.pending",
        Algorithm: PQAuthAlgorithm.MLDsa,
        ParameterSet: PQAuthParameterSet.MLDsa65,
        IsPlatformNative: false,
        IsHardwareIsolated: false,
        MinimumOSOrRuntime: "managed C# fallback",
        SupportsKeyGeneration: productionApproved,
        SupportsSign: productionApproved,
        SupportsVerify: productionApproved,
        PrivateKeyExportPolicy: PQAuthPrivateKeyExportPolicy.Exportable,
        UsesCOrFFI: usesCOrFFI,
        NativeLibraryDependency: nativeLibraryDependency,
        FallbackAllowedInProduction: productionApproved,
        AuditStatus: productionApproved ? PQAuthGateStatus.Approved : PQAuthGateStatus.Pending,
        BenchmarkStatus: productionApproved ? PQAuthGateStatus.Approved : PQAuthGateStatus.Pending,
        SideChannelReviewStatus: productionApproved ? PQAuthGateStatus.Approved : PQAuthGateStatus.Pending,
        Evidence: evidence);
}
