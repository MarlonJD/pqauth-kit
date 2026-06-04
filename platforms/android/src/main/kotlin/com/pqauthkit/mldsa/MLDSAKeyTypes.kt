package com.pqauthkit.mldsa

import com.pqauthkit.PQAuthParameterSet

data class MLDSA65KeyPair(
    val publicKey: MLDSA65PublicKey,
    val privateKey: MLDSA65PrivateKey
)

class MLDSA65PublicKey(encoded: ByteArray) {
    private val bytes: ByteArray = encoded.copyOf()

    val encoded: ByteArray
        get() = bytes.copyOf()

    init {
        require(encoded.size == PQAuthParameterSet.ML_DSA_65.publicKeyLength) {
            "ML-DSA-65 public key must be ${PQAuthParameterSet.ML_DSA_65.publicKeyLength} bytes"
        }
    }
}

class MLDSA65PrivateKey(encoded: ByteArray) {
    private val bytes: ByteArray = encoded.copyOf()

    val encoded: ByteArray
        get() = bytes.copyOf()

    init {
        require(encoded.size == PQAuthParameterSet.ML_DSA_65.privateKeyLength) {
            "ML-DSA-65 private key must be ${PQAuthParameterSet.ML_DSA_65.privateKeyLength} bytes"
        }
    }
}

class MLDSA65Signature(encoded: ByteArray) {
    private val bytes: ByteArray = encoded.copyOf()

    val encoded: ByteArray
        get() = bytes.copyOf()

    init {
        require(encoded.size == PQAuthParameterSet.ML_DSA_65.signatureLength) {
            "ML-DSA-65 signature must be ${PQAuthParameterSet.ML_DSA_65.signatureLength} bytes"
        }
    }
}
