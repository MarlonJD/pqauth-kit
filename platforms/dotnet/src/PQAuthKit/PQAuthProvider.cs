using System.Security.Cryptography;

namespace PQAuthKit;

public enum PQAuthAlgorithm
{
    MLDsa
}

public enum PQAuthParameterSet
{
    MLDsa44,
    MLDsa65,
    MLDsa87
}

public enum PQAuthPrivateKeyExportPolicy
{
    Exportable,
    PlatformWrapped,
    Prohibited
}

public enum PQAuthGateStatus
{
    Pending,
    Approved,
    Rejected
}

public sealed record PQAuthParameterSetMetadata(
    PQAuthParameterSet ParameterSet,
    string WireName,
    int PrivateKeyLength,
    int PublicKeyLength,
    int SignatureLength)
{
    public static PQAuthParameterSetMetadata For(PQAuthParameterSet parameterSet)
    {
        return parameterSet switch
        {
            PQAuthParameterSet.MLDsa44 => new(parameterSet, "ML-DSA-44", 2_560, 1_312, 2_420),
            PQAuthParameterSet.MLDsa65 => new(parameterSet, "ML-DSA-65", 4_032, 1_952, 3_309),
            PQAuthParameterSet.MLDsa87 => new(parameterSet, "ML-DSA-87", 4_896, 2_592, 4_627),
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, "Unsupported parameter set")
        };
    }

    public MLDsaAlgorithm ToDotNetAlgorithm()
    {
        return ParameterSet switch
        {
            PQAuthParameterSet.MLDsa44 => MLDsaAlgorithm.MLDsa44,
            PQAuthParameterSet.MLDsa65 => MLDsaAlgorithm.MLDsa65,
            PQAuthParameterSet.MLDsa87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(ParameterSet), ParameterSet, "Unsupported parameter set")
        };
    }
}

public sealed record PQAuthProviderMetadata(
    string ProviderId,
    PQAuthAlgorithm Algorithm,
    PQAuthParameterSet ParameterSet,
    bool IsPlatformNative,
    bool IsHardwareIsolated,
    string MinimumOSOrRuntime,
    bool SupportsKeyGeneration,
    bool SupportsSign,
    bool SupportsVerify,
    PQAuthPrivateKeyExportPolicy PrivateKeyExportPolicy,
    bool UsesCOrFFI,
    bool NativeLibraryDependency,
    bool FallbackAllowedInProduction,
    PQAuthGateStatus AuditStatus,
    PQAuthGateStatus BenchmarkStatus,
    PQAuthGateStatus SideChannelReviewStatus)
{
    public bool HasApprovedProductionGates =>
        AuditStatus == PQAuthGateStatus.Approved &&
        BenchmarkStatus == PQAuthGateStatus.Approved &&
        SideChannelReviewStatus == PQAuthGateStatus.Approved;

    public PQAuthParameterSetMetadata ParameterMetadata => PQAuthParameterSetMetadata.For(ParameterSet);
}

public sealed class PQAuthProviderSelectionException(string message) : InvalidOperationException(message);
