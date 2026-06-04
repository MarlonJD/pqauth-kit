package com.pqauthkit.mldsa

import com.pqauthkit.PQAuthParameterSet
import java.io.File
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MLDSA65ConformanceTest {
    @Test
    fun `generates signs verifies imports and exports ML-DSA-65 keys`() {
        val keyPair = MLDSA65.generateKeyPair()
        val message = """{"subject":"pqauth-kit-android","version":1}""".encodeToByteArray()
        val context = "pqauth-kit-device-identity-hybrid-auth-v1".encodeToByteArray()

        assertEquals(PQAuthParameterSet.ML_DSA_65.publicKeyLength, keyPair.publicKey.encoded.size)
        assertEquals(PQAuthParameterSet.ML_DSA_65.privateKeyLength, keyPair.privateKey.encoded.size)

        val importedPublicKey = MLDSA65.importPublicKey(keyPair.publicKey.encoded)
        val importedPrivateKey = MLDSA65.importPrivateKey(keyPair.privateKey.encoded)
        val signature = MLDSA65.sign(importedPrivateKey, message, context)

        assertEquals(PQAuthParameterSet.ML_DSA_65.signatureLength, signature.encoded.size)
        assertTrue(MLDSA65.verify(importedPublicKey, message, context, signature))
        assertFalse(MLDSA65.verify(importedPublicKey, "wrong message".encodeToByteArray(), context, signature))
        assertFalse(MLDSA65.verify(importedPublicKey, message, "wrong context".encodeToByteArray(), signature))
    }

    @Test
    fun `verifies Android emulator conformance vector`() {
        val json = File("../../vectors/android-bouncycastle-mldsa-conformance-v1.json").canonicalFile.readText()
        val message = """{"subject":"pqauth-kit-android-emulator","trustStateObject":"device_identity","version":1}"""
            .encodeToByteArray()
        val context = "pqauth-kit-device-identity-hybrid-auth-v1".encodeToByteArray()
        val publicKey = MLDSA65.importPublicKey(decodeVectorValue(json, "publicKey"))
        val signature = MLDSA65Signature(decodeVectorValue(json, "signature"))

        assertTrue(MLDSA65.verify(publicKey, message, context, signature))
        assertFalse(MLDSA65.verify(publicKey, "wrong message".encodeToByteArray(), context, signature))
        assertFalse(MLDSA65.verify(publicKey, message, "wrong context".encodeToByteArray(), signature))
    }

    private fun decodeVectorValue(json: String, objectName: String): ByteArray {
        val objectPattern = Regex(
            """"$objectName"\s*:\s*\{.*?"value"\s*:\s*"([^"]+)"""",
            setOf(RegexOption.DOT_MATCHES_ALL)
        )
        val encoded = requireNotNull(objectPattern.find(json)?.groupValues?.get(1)) {
            "missing $objectName value"
        }
        return Base64.getUrlDecoder().decode(encoded)
    }
}
