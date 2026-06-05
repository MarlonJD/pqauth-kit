package com.pqauthkit.mldsa

import com.pqauthkit.PQAuthParameterSet
import com.pqauthkit.PQAuthTrustStateObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MLDSA65TrustStateProfileTest {
    @Test
    fun `signs and verifies every trust-state object in the shared profile`() {
        val cases = loadPositiveCases()
        assertEquals(PQAuthTrustStateObject.entries.map { it.wireName }.toSet(), cases.keys)

        cases.values.forEach { trustStateCase ->
            val seed = "pqauth-kit-${trustStateCase.id}-provider-backed".encodeToByteArray()
            val keyPair = MLDSA65.generateKeyPair(DeterministicTestEntropySource(seed, production = false))
            val message = trustStateCase.canonicalBytesUtf8.encodeToByteArray()
            val context = trustStateCase.domainSeparator.encodeToByteArray()
            val signature = MLDSA65.sign(
                privateKey = keyPair.privateKey,
                message = message,
                context = context,
                entropy = DeterministicTestEntropySource(seed + byteArrayOf(1), production = false)
            )

            assertEquals(PQAuthParameterSet.ML_DSA_65.publicKeyLength, keyPair.publicKey.encoded.size)
            assertEquals(PQAuthParameterSet.ML_DSA_65.privateKeyLength, keyPair.privateKey.encoded.size)
            assertEquals(PQAuthParameterSet.ML_DSA_65.signatureLength, signature.encoded.size)
            assertTrue(MLDSA65.verify(keyPair.publicKey, message, context, signature))
            assertFalse(MLDSA65.verify(keyPair.publicKey, "wrong canonical bytes".encodeToByteArray(), context, signature))
            assertFalse(MLDSA65.verify(keyPair.publicKey, message, "wrong context".encodeToByteArray(), signature))

            assertFailsWith<IllegalArgumentException> {
                MLDSA65.importPublicKey(keyPair.publicKey.encoded.copyOf(PQAuthParameterSet.ML_DSA_65.publicKeyLength - 1))
            }
            assertFailsWith<IllegalArgumentException> {
                MLDSA65Signature(signature.encoded.copyOf(PQAuthParameterSet.ML_DSA_65.signatureLength - 1))
            }
        }
    }

    @Test
    fun `production readiness manifest is scoped and does not approve unsupported platforms`() {
        val manifest = File("../../docs/evidence/production-readiness-v1.json").canonicalFile.readText()
        assertTrue(manifest.contains("\"schema\": \"pqauth-kit-production-readiness-v1\""))
        assertTrue(manifest.contains("\"overallPackageStatus\": \"scoped_production_ready\""))
        assertTrue(manifest.contains("\"id\": \"android-bouncycastle-jvm-mldsa65-trust-state-v1\""))
        assertTrue(manifest.contains("\"providerId\": \"android.bouncycastle-jvm.mldsa65\""))
        assertTrue(manifest.contains("\"id\": \"all-supported-platforms-trust-state-v1\""))
        assertTrue(manifest.contains("\"status\": \"blocked\""))
        assertTrue(manifest.contains("\"per-message ML-DSA signatures in the default message hot path\""))
    }

    private fun loadPositiveCases(): Map<String, TrustStateCase> {
        val json = File("../../vectors/hybrid-trust-state-v1.json").canonicalFile.readText()
        return PQAuthTrustStateObject.entries.associate { trustStateObject ->
            val canonicalBytes = extractCanonicalBytes(json, trustStateObject.wireName)
            val domainSeparator = extractDomainSeparator(json, trustStateObject.wireName)
            assertEquals(trustStateObject.domainSeparator, domainSeparator)
            trustStateObject.wireName to TrustStateCase(
                id = trustStateObject.wireName,
                domainSeparator = domainSeparator,
                canonicalBytesUtf8 = canonicalBytes
            )
        }
    }

    private fun extractCanonicalBytes(json: String, id: String): String {
        val encoded = extractJsonStringField(json, id, "canonicalBytesUtf8")
        return encoded
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    }

    private fun extractDomainSeparator(json: String, id: String): String =
        extractJsonStringField(json, id, "signedBytesDomain")

    private fun extractJsonStringField(json: String, id: String, fieldName: String): String {
        val pattern = Regex(
            """"id"\s*:\s*"$id".*?"$fieldName"\s*:\s*"((?:\\.|[^"])*)"""",
            setOf(RegexOption.DOT_MATCHES_ALL)
        )
        return requireNotNull(pattern.find(json)?.groupValues?.get(1)) {
            "missing $fieldName for $id"
        }
    }

    private data class TrustStateCase(
        val id: String,
        val domainSeparator: String,
        val canonicalBytesUtf8: String
    )
}
