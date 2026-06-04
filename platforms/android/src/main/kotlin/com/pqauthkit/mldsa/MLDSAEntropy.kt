package com.pqauthkit.mldsa

import java.security.SecureRandom

interface MLDSAEntropySource {
    fun nextBytes(size: Int): ByteArray
}

class SecureRandomEntropySource(
    private val secureRandom: SecureRandom = SecureRandom()
) : MLDSAEntropySource {
    override fun nextBytes(size: Int): ByteArray {
        require(size >= 0) { "size must be non-negative" }
        return ByteArray(size).also(secureRandom::nextBytes)
    }
}

class DeterministicTestEntropySource(
    seed: ByteArray,
    production: Boolean
) : MLDSAEntropySource {
    private val seed: ByteArray = seed.copyOf()
    private var offset: Int = 0

    init {
        require(!production) { "deterministic entropy is test-only" }
        require(seed.isNotEmpty()) { "seed must not be empty" }
    }

    override fun nextBytes(size: Int): ByteArray {
        require(size >= 0) { "size must be non-negative" }
        return ByteArray(size) { index ->
            seed[(offset + index) % seed.size]
        }.also {
            offset += size
        }
    }
}

internal fun MLDSAEntropySource.asSecureRandom(): SecureRandom = object : SecureRandom() {
    override fun nextBytes(bytes: ByteArray) {
        val generated = this@asSecureRandom.nextBytes(bytes.size)
        generated.copyInto(bytes)
    }
}
