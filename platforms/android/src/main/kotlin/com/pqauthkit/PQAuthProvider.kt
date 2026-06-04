package com.pqauthkit

enum class PQAuthAlgorithm(val wireName: String) {
    ML_DSA("ML-DSA")
}

enum class PQAuthParameterSet(
    val wireName: String,
    val privateKeyLength: Int,
    val publicKeyLength: Int,
    val signatureLength: Int
) {
    ML_DSA_44("ML-DSA-44", 2_560, 1_312, 2_420),
    ML_DSA_65("ML-DSA-65", 4_032, 1_952, 3_309),
    ML_DSA_87("ML-DSA-87", 4_896, 2_592, 4_627)
}

enum class PQAuthPrivateKeyExportPolicy {
    EXPORTABLE,
    PLATFORM_WRAPPED,
    PROHIBITED
}

enum class PQAuthGateStatus {
    PENDING,
    APPROVED,
    REJECTED
}

enum class PQAuthProviderUsage {
    TRUST_STATE_AUTHENTICATION,
    DISTRIBUTION_IDENTITY_ONLY
}

data class PQAuthEvidenceReferences(
    val providerSourceId: String? = null,
    val providerVersion: String? = null,
    val providerCommit: String? = null,
    val license: String? = null,
    val conformanceVectorId: String? = null,
    val auditReportId: String? = null,
    val benchmarkReportId: String? = null,
    val sideChannelReviewId: String? = null,
    val remainingRisk: String? = null
) {
    val hasProductionEvidence: Boolean
        get() = listOf(
            providerSourceId,
            providerVersion,
            license,
            conformanceVectorId,
            auditReportId,
            benchmarkReportId,
            sideChannelReviewId
        ).all { !it.isNullOrBlank() }

    companion object {
        fun none(): PQAuthEvidenceReferences = PQAuthEvidenceReferences()

        fun complete(
            providerSourceId: String,
            providerVersion: String,
            license: String,
            conformanceVectorId: String,
            auditReportId: String,
            benchmarkReportId: String,
            sideChannelReviewId: String,
            providerCommit: String? = null,
            remainingRisk: String? = null
        ): PQAuthEvidenceReferences = PQAuthEvidenceReferences(
            providerSourceId = providerSourceId,
            providerVersion = providerVersion,
            providerCommit = providerCommit,
            license = license,
            conformanceVectorId = conformanceVectorId,
            auditReportId = auditReportId,
            benchmarkReportId = benchmarkReportId,
            sideChannelReviewId = sideChannelReviewId,
            remainingRisk = remainingRisk
        )
    }
}

data class PQAuthProviderMetadata(
    val providerId: String,
    val algorithm: PQAuthAlgorithm,
    val parameterSet: PQAuthParameterSet,
    val isPlatformNative: Boolean,
    val isHardwareIsolated: Boolean,
    val minimumOSOrRuntime: String,
    val supportsKeyGeneration: Boolean,
    val supportsSign: Boolean,
    val supportsVerify: Boolean,
    val privateKeyExportPolicy: PQAuthPrivateKeyExportPolicy,
    val usesCOrFFI: Boolean,
    val nativeLibraryDependency: Boolean,
    val fallbackAllowedInProduction: Boolean,
    val auditStatus: PQAuthGateStatus,
    val benchmarkStatus: PQAuthGateStatus,
    val sideChannelReviewStatus: PQAuthGateStatus,
    val usage: PQAuthProviderUsage,
    val evidence: PQAuthEvidenceReferences = PQAuthEvidenceReferences.none()
) {
    val hasApprovedProductionGates: Boolean
        get() = auditStatus == PQAuthGateStatus.APPROVED &&
            benchmarkStatus == PQAuthGateStatus.APPROVED &&
            sideChannelReviewStatus == PQAuthGateStatus.APPROVED

    val hasProductionReadinessEvidence: Boolean
        get() = evidence.hasProductionEvidence

    val isProductionReady: Boolean
        get() = hasApprovedProductionGates &&
            hasProductionReadinessEvidence &&
            !usesCOrFFI &&
            !nativeLibraryDependency
}

object PQAuthReadinessGate {
    fun blockers(provider: PQAuthProviderMetadata): List<String> {
        val blockers = mutableListOf<String>()

        if (provider.auditStatus != PQAuthGateStatus.APPROVED) {
            blockers += "audit_status_not_approved"
        }
        if (provider.benchmarkStatus != PQAuthGateStatus.APPROVED) {
            blockers += "benchmark_status_not_approved"
        }
        if (provider.sideChannelReviewStatus != PQAuthGateStatus.APPROVED) {
            blockers += "side_channel_review_status_not_approved"
        }
        if (!provider.evidence.hasProductionEvidence) {
            blockers += "required_evidence_missing"
        }
        if (provider.usesCOrFFI) {
            blockers += "native_or_ffi_dependency_present"
        }
        if (provider.nativeLibraryDependency) {
            blockers += "native_library_dependency_present"
        }

        return blockers
    }
}

data class AndroidRuntimeCapabilities(
    val apiLevel: Int,
    val documentedAppFacingMldsaProviderAvailable: Boolean,
    val pqcApkSigningAvailable: Boolean,
    val auditedFallbackAvailable: Boolean
)

data class AndroidProviderSelectionPolicy(
    val requestedParameterSet: PQAuthParameterSet = PQAuthParameterSet.ML_DSA_65,
    val hybridAuthRequired: Boolean = true,
    val allowAuditedFallback: Boolean = false,
    val isProduction: Boolean = true
)

class PQAuthProviderSelectionException(message: String) : IllegalStateException(message)

class AndroidProviderCatalog(private val providers: List<PQAuthProviderMetadata>) {
    fun selectProvider(
        policy: AndroidProviderSelectionPolicy,
        runtime: AndroidRuntimeCapabilities
    ): PQAuthProviderMetadata {
        providers
            .filter { it.parameterSet == policy.requestedParameterSet }
            .firstOrNull {
                it.usage == PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION &&
                    it.isPlatformNative &&
                    runtime.documentedAppFacingMldsaProviderAvailable
            }
            ?.let { return it }

        if (policy.allowAuditedFallback && runtime.auditedFallbackAvailable) {
            providers
                .filter { it.parameterSet == policy.requestedParameterSet }
                .firstOrNull { fallbackPermitted(it, policy) }
                ?.let { return it }
        }

        if (policy.hybridAuthRequired) {
            throw PQAuthProviderSelectionException("no approved Android ML-DSA provider")
        }

        throw PQAuthProviderSelectionException("hybrid auth disabled and no provider selected")
    }

    private fun fallbackPermitted(
        provider: PQAuthProviderMetadata,
        policy: AndroidProviderSelectionPolicy
    ): Boolean {
        if (provider.isPlatformNative || provider.usesCOrFFI || provider.nativeLibraryDependency) {
            return false
        }

        if (provider.usage != PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION) {
            return false
        }

        return if (policy.isProduction) {
            provider.fallbackAllowedInProduction && provider.isProductionReady
        } else {
            provider.isProductionReady
        }
    }

    companion object {
        fun default(): AndroidProviderCatalog = AndroidProviderCatalog(
            listOf(
                officialAppFacingProvider(),
                apkSigningProvider(),
                bouncyCastleJvmFallback()
            )
        )

        fun officialAppFacingProvider(): PQAuthProviderMetadata = PQAuthProviderMetadata(
            providerId = "android.official-app-facing.mldsa65",
            algorithm = PQAuthAlgorithm.ML_DSA,
            parameterSet = PQAuthParameterSet.ML_DSA_65,
            isPlatformNative = true,
            isHardwareIsolated = false,
            minimumOSOrRuntime = "documented Android app-facing provider",
            supportsKeyGeneration = true,
            supportsSign = true,
            supportsVerify = true,
            privateKeyExportPolicy = PQAuthPrivateKeyExportPolicy.PLATFORM_WRAPPED,
            usesCOrFFI = false,
            nativeLibraryDependency = false,
            fallbackAllowedInProduction = false,
            auditStatus = PQAuthGateStatus.APPROVED,
            benchmarkStatus = PQAuthGateStatus.PENDING,
            sideChannelReviewStatus = PQAuthGateStatus.PENDING,
            usage = PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION,
            evidence = PQAuthEvidenceReferences(
                providerSourceId = "android-app-facing-provider-doc-check-2026-06-04",
                providerVersion = "Android public app-facing provider documentation not found",
                license = "Android documentation content license",
                auditReportId = "android-provider-doc-review-2026-06-04",
                remainingRisk = "No official app-facing ML-DSA signing provider is documented at this checkpoint."
            )
        )

        fun apkSigningProvider(): PQAuthProviderMetadata = PQAuthProviderMetadata(
            providerId = "android.pqc-apk-signing.mldsa",
            algorithm = PQAuthAlgorithm.ML_DSA,
            parameterSet = PQAuthParameterSet.ML_DSA_65,
            isPlatformNative = true,
            isHardwareIsolated = false,
            minimumOSOrRuntime = "Android 17 APK signing",
            supportsKeyGeneration = false,
            supportsSign = false,
            supportsVerify = false,
            privateKeyExportPolicy = PQAuthPrivateKeyExportPolicy.PROHIBITED,
            usesCOrFFI = false,
            nativeLibraryDependency = false,
            fallbackAllowedInProduction = false,
            auditStatus = PQAuthGateStatus.APPROVED,
            benchmarkStatus = PQAuthGateStatus.PENDING,
            sideChannelReviewStatus = PQAuthGateStatus.PENDING,
            usage = PQAuthProviderUsage.DISTRIBUTION_IDENTITY_ONLY,
            evidence = PQAuthEvidenceReferences(
                providerSourceId = "android-pqc-apk-signing-docs-2026-06-04",
                providerVersion = "Android 17 APK signing documentation",
                license = "Android documentation content license",
                auditReportId = "android-apk-signing-doc-review-2026-06-04",
                remainingRisk = "Distribution identity only; not eligible for trust-state authentication."
            )
        )

        fun bouncyCastleJvmFallback(): PQAuthProviderMetadata = PQAuthProviderMetadata(
            providerId = "android.bouncycastle-jvm.mldsa65",
            algorithm = PQAuthAlgorithm.ML_DSA,
            parameterSet = PQAuthParameterSet.ML_DSA_65,
            isPlatformNative = false,
            isHardwareIsolated = false,
            minimumOSOrRuntime = "Android API 26+ JVM runtime",
            supportsKeyGeneration = true,
            supportsSign = true,
            supportsVerify = true,
            privateKeyExportPolicy = PQAuthPrivateKeyExportPolicy.EXPORTABLE,
            usesCOrFFI = false,
            nativeLibraryDependency = false,
            fallbackAllowedInProduction = true,
            auditStatus = PQAuthGateStatus.APPROVED,
            benchmarkStatus = PQAuthGateStatus.APPROVED,
            sideChannelReviewStatus = PQAuthGateStatus.APPROVED,
            usage = PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION,
            evidence = PQAuthEvidenceReferences.complete(
                providerSourceId = "bouncycastle-bcprov-jdk18on-1.84",
                providerVersion = "Bouncy Castle bcprov-jdk18on 1.84",
                license = "Bouncy Castle Licence",
                conformanceVectorId = "android-bouncycastle-mldsa65-emulator-conformance-2026-06-04",
                auditReportId = "android-bouncycastle-mldsa65-package-audit-2026-06-04",
                benchmarkReportId = "android-bouncycastle-mldsa65-emulator-benchmark-2026-06-04",
                sideChannelReviewId = "android-bouncycastle-mldsa65-side-channel-review-2026-06-04",
                remainingRisk = "Managed JVM fallback is production-selectable by owner decision after emulator conformance; release-device benchmark and independent external crypto audit are still recommended."
            )
        )

        fun pureKotlinFallback(
            productionApproved: Boolean,
            usesCOrFFI: Boolean = false,
            nativeLibraryDependency: Boolean = false,
            evidence: PQAuthEvidenceReferences = PQAuthEvidenceReferences.none()
        ): PQAuthProviderMetadata = PQAuthProviderMetadata(
            providerId = if (productionApproved) {
                "android.pure-kotlin.mldsa65.approved"
            } else {
                "android.pure-kotlin.mldsa65.pending"
            },
            algorithm = PQAuthAlgorithm.ML_DSA,
            parameterSet = PQAuthParameterSet.ML_DSA_65,
            isPlatformNative = false,
            isHardwareIsolated = false,
            minimumOSOrRuntime = "Kotlin/JVM fallback",
            supportsKeyGeneration = productionApproved,
            supportsSign = productionApproved,
            supportsVerify = productionApproved,
            privateKeyExportPolicy = PQAuthPrivateKeyExportPolicy.EXPORTABLE,
            usesCOrFFI = usesCOrFFI,
            nativeLibraryDependency = nativeLibraryDependency,
            fallbackAllowedInProduction = productionApproved,
            auditStatus = if (productionApproved) PQAuthGateStatus.APPROVED else PQAuthGateStatus.PENDING,
            benchmarkStatus = if (productionApproved) PQAuthGateStatus.APPROVED else PQAuthGateStatus.PENDING,
            sideChannelReviewStatus = if (productionApproved) PQAuthGateStatus.APPROVED else PQAuthGateStatus.PENDING,
            usage = PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION,
            evidence = evidence
        )
    }
}
