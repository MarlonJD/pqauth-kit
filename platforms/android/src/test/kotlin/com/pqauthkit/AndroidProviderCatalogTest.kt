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
            listOf(AndroidProviderCatalog.pureKotlinFallback(productionApproved = true))
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
    }

    @Test
    fun `native or FFI fallback is rejected even when approved`() {
        val catalog = AndroidProviderCatalog(
            listOf(
                AndroidProviderCatalog.pureKotlinFallback(
                    productionApproved = true,
                    usesCOrFFI = true,
                    nativeLibraryDependency = true
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
}
