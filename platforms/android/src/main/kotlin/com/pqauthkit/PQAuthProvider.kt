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
    val usage: PQAuthProviderUsage
) {
    val hasApprovedProductionGates: Boolean
        get() = auditStatus == PQAuthGateStatus.APPROVED &&
            benchmarkStatus == PQAuthGateStatus.APPROVED &&
            sideChannelReviewStatus == PQAuthGateStatus.APPROVED
}

data class AndroidRuntimeCapabilities(
    val apiLevel: Int,
    val documentedAppFacingMldsaProviderAvailable: Boolean,
    val pqcApkSigningAvailable: Boolean,
    val auditedPureKotlinFallbackAvailable: Boolean
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

        if (policy.allowAuditedFallback && runtime.auditedPureKotlinFallbackAvailable) {
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
            provider.fallbackAllowedInProduction && provider.hasApprovedProductionGates
        } else {
            provider.hasApprovedProductionGates
        }
    }

    companion object {
        fun default(): AndroidProviderCatalog = AndroidProviderCatalog(
            listOf(
                officialAppFacingProvider(),
                apkSigningProvider(),
                pureKotlinFallback(productionApproved = false)
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
            usage = PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION
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
            usage = PQAuthProviderUsage.DISTRIBUTION_IDENTITY_ONLY
        )

        fun pureKotlinFallback(
            productionApproved: Boolean,
            usesCOrFFI: Boolean = false,
            nativeLibraryDependency: Boolean = false
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
            usage = PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION
        )
    }
}
