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

public sealed record PQAuthEvidenceReferences(
    string? ProviderSourceId = null,
    string? ProviderVersion = null,
    string? ProviderCommit = null,
    string? License = null,
    string? ConformanceVectorId = null,
    string? AuditReportId = null,
    string? BenchmarkReportId = null,
    string? SideChannelReviewId = null,
    string? RemainingRisk = null)
{
    public bool HasProductionEvidence =>
        !string.IsNullOrWhiteSpace(ProviderSourceId) &&
        !string.IsNullOrWhiteSpace(ProviderVersion) &&
        !string.IsNullOrWhiteSpace(License) &&
        !string.IsNullOrWhiteSpace(ConformanceVectorId) &&
        !string.IsNullOrWhiteSpace(AuditReportId) &&
        !string.IsNullOrWhiteSpace(BenchmarkReportId) &&
        !string.IsNullOrWhiteSpace(SideChannelReviewId);

    public static PQAuthEvidenceReferences None { get; } = new();

    public static PQAuthEvidenceReferences Complete(
        string providerSourceId,
        string providerVersion,
        string license,
        string conformanceVectorId,
        string auditReportId,
        string benchmarkReportId,
        string sideChannelReviewId,
        string? providerCommit = null,
        string? remainingRisk = null) =>
        new(
            providerSourceId,
            providerVersion,
            providerCommit,
            license,
            conformanceVectorId,
            auditReportId,
            benchmarkReportId,
            sideChannelReviewId,
            remainingRisk);
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
    PQAuthGateStatus SideChannelReviewStatus,
    PQAuthEvidenceReferences? Evidence = null)
{
    public bool HasApprovedProductionGates =>
        AuditStatus == PQAuthGateStatus.Approved &&
        BenchmarkStatus == PQAuthGateStatus.Approved &&
        SideChannelReviewStatus == PQAuthGateStatus.Approved;

    public PQAuthEvidenceReferences EvidenceReferences => Evidence ?? PQAuthEvidenceReferences.None;

    public bool HasProductionReadinessEvidence => EvidenceReferences.HasProductionEvidence;

    public bool IsProductionReady =>
        HasApprovedProductionGates &&
        HasProductionReadinessEvidence &&
        !UsesCOrFFI &&
        !NativeLibraryDependency;

    public PQAuthParameterSetMetadata ParameterMetadata => PQAuthParameterSetMetadata.For(ParameterSet);
}

public static class PQAuthReadinessGate
{
    public static IReadOnlyList<string> Blockers(PQAuthProviderMetadata provider)
    {
        var blockers = new List<string>();

        if (provider.AuditStatus != PQAuthGateStatus.Approved)
        {
            blockers.Add("audit_status_not_approved");
        }
        if (provider.BenchmarkStatus != PQAuthGateStatus.Approved)
        {
            blockers.Add("benchmark_status_not_approved");
        }
        if (provider.SideChannelReviewStatus != PQAuthGateStatus.Approved)
        {
            blockers.Add("side_channel_review_status_not_approved");
        }
        if (!provider.HasProductionReadinessEvidence)
        {
            blockers.Add("required_evidence_missing");
        }
        if (provider.UsesCOrFFI)
        {
            blockers.Add("native_or_ffi_dependency_present");
        }
        if (provider.NativeLibraryDependency)
        {
            blockers.Add("native_library_dependency_present");
        }

        return blockers;
    }
}

public sealed class PQAuthProviderSelectionException(string message) : InvalidOperationException(message);
