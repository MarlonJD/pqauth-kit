package com.pqauthkit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AndroidProviderCatalogTest {
    @Test
    fun `official app-facing provider is selected only when documented as available`() {
        val selected = AndroidProviderCatalog.default().selectProvider(
            policy = AndroidProviderSelectionPolicy(),
            runtime = AndroidRuntimeCapabilities(
                apiLevel = 37,
                documentedAppFacingMldsaProviderAvailable = true,
                pqcApkSigningAvailable = true,
                auditedPureKotlinFallbackAvailable = false
            )
        )

        assertEquals("android.official-app-facing.mldsa65", selected.providerId)
        assertTrue(selected.isPlatformNative)
        assertEquals(PQAuthProviderUsage.TRUST_STATE_AUTHENTICATION, selected.usage)
    }

    @Test
    fun `Android APK signing provider is never selected for trust-state authentication`() {
        val error = assertFailsWith<PQAuthProviderSelectionException> {
            AndroidProviderCatalog.default().selectProvider(
                policy = AndroidProviderSelectionPolicy(),
                runtime = AndroidRuntimeCapabilities(
                    apiLevel = 37,
                    documentedAppFacingMldsaProviderAvailable = false,
                    pqcApkSigningAvailable = true,
                    auditedPureKotlinFallbackAvailable = false
                )
            )
        }

        assertEquals("no approved Android ML-DSA provider", error.message)
    }

    @Test
    fun `approved pure Kotlin fallback can be selected when policy allows it`() {
        val catalog = AndroidProviderCatalog(
            listOf(
                AndroidProviderCatalog.pureKotlinFallback(
                    productionApproved = true,
                    evidence = completeEvidence()
                )
            )
        )

        val selected = catalog.selectProvider(
            policy = AndroidProviderSelectionPolicy(allowAuditedFallback = true),
            runtime = AndroidRuntimeCapabilities(
                apiLevel = 35,
                documentedAppFacingMldsaProviderAvailable = false,
                pqcApkSigningAvailable = false,
                auditedPureKotlinFallbackAvailable = true
            )
        )

        assertEquals("android.pure-kotlin.mldsa65.approved", selected.providerId)
        assertTrue(selected.fallbackAllowedInProduction)
        assertTrue(selected.hasApprovedProductionGates)
        assertTrue(selected.isProductionReady)
    }

    @Test
    fun `approved statuses without evidence do not pass production readiness`() {
        val provider = AndroidProviderCatalog.pureKotlinFallback(productionApproved = true)

        assertTrue(provider.hasApprovedProductionGates)
        assertFalse(provider.isProductionReady)
        assertTrue(PQAuthReadinessGate.blockers(provider).contains("required_evidence_missing"))
    }

    @Test
    fun `runtime provider selection is distinct from production readiness`() {
        val selected = AndroidProviderCatalog.default().selectProvider(
            policy = AndroidProviderSelectionPolicy(),
            runtime = AndroidRuntimeCapabilities(
                apiLevel = 37,
                documentedAppFacingMldsaProviderAvailable = true,
                pqcApkSigningAvailable = true,
                auditedPureKotlinFallbackAvailable = false
            )
        )

        assertEquals("android.official-app-facing.mldsa65", selected.providerId)
        assertFalse(selected.isProductionReady)
        assertTrue(PQAuthReadinessGate.blockers(selected).contains("benchmark_status_not_approved"))
        assertTrue(PQAuthReadinessGate.blockers(selected).contains("side_channel_review_status_not_approved"))
    }

    @Test
    fun `native or FFI fallback is rejected even when approved`() {
        val catalog = AndroidProviderCatalog(
            listOf(
                AndroidProviderCatalog.pureKotlinFallback(
                    productionApproved = true,
                    usesCOrFFI = true,
                    nativeLibraryDependency = true,
                    evidence = completeEvidence()
                )
            )
        )

        assertFailsWith<PQAuthProviderSelectionException> {
            catalog.selectProvider(
                policy = AndroidProviderSelectionPolicy(allowAuditedFallback = true),
                runtime = AndroidRuntimeCapabilities(
                    apiLevel = 35,
                    documentedAppFacingMldsaProviderAvailable = false,
                    pqcApkSigningAvailable = false,
                    auditedPureKotlinFallbackAvailable = true
                )
            )
        }
    }

    @Test
    fun `deterministic entropy cannot be used in production APIs`() {
        assertEquals(listOf(0, 1, 2, 3), PQAuthDeterministicTestEntropy.bytes(4, production = false).map { it.toInt() })
        assertFailsWith<IllegalArgumentException> {
            PQAuthDeterministicTestEntropy.bytes(4, production = true)
        }
    }

    @Test
    fun `provider metadata has no native fallback dependencies`() {
        val fallback = AndroidProviderCatalog.pureKotlinFallback(productionApproved = false)
        assertFalse(fallback.usesCOrFFI)
        assertFalse(fallback.nativeLibraryDependency)
    }

    private fun completeEvidence(): PQAuthEvidenceReferences = PQAuthEvidenceReferences.complete(
        providerSourceId = "android-fallback-test-source",
        providerVersion = "test-version",
        license = "test-license",
        conformanceVectorId = "test-conformance-vector",
        auditReportId = "test-audit-report",
        benchmarkReportId = "test-benchmark-report",
        sideChannelReviewId = "test-side-channel-review"
    )
}
