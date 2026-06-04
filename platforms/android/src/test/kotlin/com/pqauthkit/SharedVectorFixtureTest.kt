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

    private fun vectorFixture(): File {
        return File("../../vectors/hybrid-trust-state-v1.json").canonicalFile
    }

    private fun sha256Base64Url(value: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
}
