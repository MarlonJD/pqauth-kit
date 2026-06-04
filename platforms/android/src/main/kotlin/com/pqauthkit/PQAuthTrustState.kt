package com.pqauthkit

enum class PQAuthTrustStateObject(
    val wireName: String,
    val domainSeparator: String
) {
    ACCOUNT_IDENTITY(
        "account_identity",
        "pqauth-kit-account-identity-hybrid-auth-v1"
    ),
    DEVICE_IDENTITY(
        "device_identity",
        "pqauth-kit-device-identity-hybrid-auth-v1"
    ),
    ROSTER_PUBLISH(
        "roster_publish",
        "pqauth-kit-device-roster-hybrid-auth-v1"
    ),
    PREKEY_BUNDLE(
        "prekey_bundle",
        "pqauth-kit-ratchet-prekey-bundle-hybrid-auth-v1"
    ),
    SAFETY_NUMBER(
        "safety_number",
        "pqauth-kit-safety-number-hybrid-auth-v1"
    )
}

object PQAuthDeterministicTestEntropy {
    fun bytes(count: Int, production: Boolean): ByteArray {
        require(!production) { "deterministic entropy is unavailable to production APIs" }
        return ByteArray(count) { index -> (index % 251).toByte() }
    }
}
