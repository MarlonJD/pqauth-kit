package com.pqauthkit

import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SharedVectorFixtureTest {
    @Test
    fun `fixture uses public package schema and domains`() {
        val json = vectorFixture().readText()
        assertTrue(json.contains("\"schema\": \"pqauth-kit-hybrid-trust-state-v1\""))
        assertTrue(json.contains("pqauth-kit-account-identity-hybrid-auth-v1"))
    }

    @Test
    fun `fixture contains all positive trust-state objects and negative cases`() {
        val json = vectorFixture().readText()
        PQAuthTrustStateObject.entries.forEach { trustStateObject ->
            assertTrue(json.contains("\"trustStateObject\": \"${trustStateObject.wireName}\""))
            assertTrue(json.contains("\"signedBytesDomain\": \"${trustStateObject.domainSeparator}\""))
        }

        assertEquals(5, Regex("\"trustStateObject\"").findAll(json).count())
        assertEquals(9, Regex("\"expectedError\"").findAll(json).count())
        assertTrue(json.contains("\"perMessagePQSignaturesEnabled\": false"))
    }

    @Test
    fun `fixture contains FIPS 204 ML-DSA-65 lengths`() {
        val json = vectorFixture().readText()
        assertTrue(json.contains("\"privateKeyLength\": ${PQAuthParameterSet.ML_DSA_65.privateKeyLength}"))
        assertTrue(json.contains("\"publicKeyLength\": ${PQAuthParameterSet.ML_DSA_65.publicKeyLength}"))
        assertTrue(json.contains("\"signatureLength\": ${PQAuthParameterSet.ML_DSA_65.signatureLength}"))
    }

    @Test
    fun `fixture account identity hash matches canonical bytes`() {
        val json = vectorFixture().readText()
        val canonical = """{"accountId":"acct-fixture-001","displayName":"Fixture Account","identityVersion":1}"""
        val expectedHash = sha256Base64Url(canonical)
        assertTrue(json.contains("\"signedBytesHash\": \"$expectedHash\""))
    }

    @Test
    fun `ML-DSA conformance fixture is cryptographic and separate from structural vectors`() {
        val json = conformanceFixture().readText()
        assertTrue(json.contains("\"schema\" : \"pqauth-kit-mldsa-conformance-v1\""))
        assertTrue(json.contains("\"fixtureKind\" : \"cryptographic-provider-conformance\""))
        assertTrue(json.contains("\"providerId\" : \"apple.cryptokit.mldsa65.macos\""))
        assertTrue(json.contains("\"trustStateObject\" : \"device_identity\""))
        assertTrue(json.contains("\"public-key-import\""))
        assertTrue(json.contains("\"signed-bytes-mismatch-rejection\""))
        assertTrue(json.contains("\"wrong-context-rejection\""))
        assertTrue(json.contains("\"malformed-public-key-rejection\""))
        assertTrue(json.contains("\"malformed-signature-rejection\""))
        assertTrue(json.contains("\"length\" : ${PQAuthParameterSet.ML_DSA_65.publicKeyLength}"))
        assertTrue(json.contains("\"length\" : ${PQAuthParameterSet.ML_DSA_65.signatureLength}"))
        assertFalse(json.contains("\"fixtureKind\" : \"structural-non-cryptographic\""))
    }

    @Test
    fun `readiness evidence manifest links benchmark and side-channel reports`() {
        val readiness = evidenceFixture("readiness-gates-v1.json").readText()
        assertTrue(readiness.contains("\"schema\": \"pqauth-kit-readiness-gates-v1\""))
        assertTrue(readiness.contains("\"providerId\": \"apple.cryptokit.mldsa65.macos\""))
        assertTrue(readiness.contains("\"benchmarkReportId\": \"apple-cryptokit-mldsa65-macos-local-benchmark-2026-06-04\""))
        assertTrue(readiness.contains("\"sideChannelReviewId\": \"apple-cryptokit-mldsa65-macos-side-channel-review-2026-06-04\""))
        assertTrue(readiness.contains("\"productionReady\": false"))

        val benchmark = evidenceFixture("apple-cryptokit-mldsa65-macos-benchmark-2026-06-04.json").readText()
        assertTrue(benchmark.contains("\"schema\" : \"pqauth-kit-benchmark-evidence-v1\""))
        assertTrue(benchmark.contains("\"keygen\""))
        assertTrue(benchmark.contains("\"sign\""))
        assertTrue(benchmark.contains("\"verify\""))
        assertTrue(benchmark.contains("\"malformedPublicKeyRejection\""))
        assertTrue(benchmark.contains("\"malformedSignatureRejection\""))
    }

    private fun vectorFixture(): File {
        return File("../../vectors/hybrid-trust-state-v1.json").canonicalFile
    }

    private fun conformanceFixture(): File {
        return File("../../vectors/mldsa-conformance-v1.json").canonicalFile
    }

    private fun evidenceFixture(name: String): File {
        return File("../../docs/evidence/$name").canonicalFile
    }

    private fun sha256Base64Url(value: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
}
