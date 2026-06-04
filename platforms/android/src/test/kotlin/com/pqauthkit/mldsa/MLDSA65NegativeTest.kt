package com.pqauthkit.mldsa

import com.pqauthkit.PQAuthParameterSet
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class MLDSA65NegativeTest {
    @Test
    fun `rejects malformed ML-DSA-65 encodings`() {
        val keyPair = MLDSA65.generateKeyPair()
        val signature = MLDSA65.sign(
            keyPair.privateKey,
            "message".encodeToByteArray(),
            "context".encodeToByteArray()
        )

        assertFailsWith<IllegalArgumentException> {
            MLDSA65.importPublicKey(keyPair.publicKey.encoded.copyOf(PQAuthParameterSet.ML_DSA_65.publicKeyLength - 1))
        }
        assertFailsWith<IllegalArgumentException> {
            MLDSA65.importPrivateKey(keyPair.privateKey.encoded.copyOf(PQAuthParameterSet.ML_DSA_65.privateKeyLength - 1))
        }
        assertFailsWith<IllegalArgumentException> {
            MLDSA65Signature(signature.encoded.copyOf(PQAuthParameterSet.ML_DSA_65.signatureLength - 1))
        }
    }

    @Test
    fun `key and signature encodings are defensive copies`() {
        val keyPair = MLDSA65.generateKeyPair()
        val signature = MLDSA65.sign(
            keyPair.privateKey,
            "message".encodeToByteArray(),
            "context".encodeToByteArray()
        )

        val publicKeyBytes = keyPair.publicKey.encoded
        val privateKeyBytes = keyPair.privateKey.encoded
        val signatureBytes = signature.encoded

        publicKeyBytes[0] = (publicKeyBytes[0].toInt() xor 0x01).toByte()
        privateKeyBytes[0] = (privateKeyBytes[0].toInt() xor 0x01).toByte()
        signatureBytes[0] = (signatureBytes[0].toInt() xor 0x01).toByte()

        assertNotEquals(publicKeyBytes[0], keyPair.publicKey.encoded[0])
        assertNotEquals(privateKeyBytes[0], keyPair.privateKey.encoded[0])
        assertNotEquals(signatureBytes[0], signature.encoded[0])
    }

    @Test
    fun `deterministic test entropy copies seed and remains test-only`() {
        val seed = byteArrayOf(1, 2, 3)
        val entropy = DeterministicTestEntropySource(seed, production = false)
        seed[0] = 9

        assertContentEquals(byteArrayOf(1, 2, 3, 1), entropy.nextBytes(4))
        assertEquals(0, entropy.nextBytes(0).size)
        assertFailsWith<IllegalArgumentException> {
            DeterministicTestEntropySource(seed, production = true)
        }
    }
}
