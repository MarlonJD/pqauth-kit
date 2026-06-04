@file:Suppress("DEPRECATION")

package com.pqauthkit.mldsa

import org.bouncycastle.crypto.params.ParametersWithContext
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner

object MLDSA65 {
    private val parameters: MLDSAParameters = MLDSAParameters.ml_dsa_65

    fun generateKeyPair(entropy: MLDSAEntropySource = SecureRandomEntropySource()): MLDSA65KeyPair {
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(entropy.asSecureRandom(), parameters))

        val keyPair = generator.generateKeyPair()
        val publicKey = keyPair.public as MLDSAPublicKeyParameters
        val privateKey = (keyPair.private as MLDSAPrivateKeyParameters)
            .getParametersWithFormat(MLDSAPrivateKeyParameters.BOTH)

        return MLDSA65KeyPair(
            publicKey = MLDSA65PublicKey(publicKey.encoded),
            privateKey = MLDSA65PrivateKey(privateKey.encoded)
        )
    }

    fun importPublicKey(encoded: ByteArray): MLDSA65PublicKey = MLDSA65PublicKey(encoded)

    fun importPrivateKey(encoded: ByteArray): MLDSA65PrivateKey = MLDSA65PrivateKey(encoded)

    fun sign(
        privateKey: MLDSA65PrivateKey,
        message: ByteArray,
        context: ByteArray,
        entropy: MLDSAEntropySource = SecureRandomEntropySource()
    ): MLDSA65Signature {
        val signer = MLDSASigner()
        val privateParameters = MLDSAPrivateKeyParameters(parameters, privateKey.encoded)
        signer.init(
            true,
            ParametersWithContext(
                ParametersWithRandom(privateParameters, entropy.asSecureRandom()),
                context.copyOf()
            )
        )
        signer.update(message, 0, message.size)
        return MLDSA65Signature(signer.generateSignature())
    }

    fun verify(
        publicKey: MLDSA65PublicKey,
        message: ByteArray,
        context: ByteArray,
        signature: MLDSA65Signature
    ): Boolean {
        val signer = MLDSASigner()
        val publicParameters = MLDSAPublicKeyParameters(parameters, publicKey.encoded)
        signer.init(false, ParametersWithContext(publicParameters, context.copyOf()))
        signer.update(message, 0, message.size)
        return signer.verifySignature(signature.encoded)
    }
}
