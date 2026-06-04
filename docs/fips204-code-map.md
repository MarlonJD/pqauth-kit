# FIPS 204 Code Map

Date: 2026-06-04

## Status

This map records the package-level ML-DSA contract, provider gates, and current
provider-backed implementation paths. It does not claim FIPS 140 validation.

## Parameter Sets

| Parameter set | Private key bytes | Public key bytes | Signature bytes | Package status |
| --- | ---: | ---: | ---: | --- |
| ML-DSA-44 | 2560 | 1312 | 2420 | Not selected for trust-state v1 |
| ML-DSA-65 | 4032 | 1952 | 3309 | Default candidate |
| ML-DSA-87 | 4896 | 2592 | 4627 | Allowed when provider or hardware policy requires it |

The sizes above come from NIST FIPS 204:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

## Required Code Paths

Every provider implementation must map these FIPS 204 behaviors before
production use:

- Key generation for the selected parameter set.
- Public key import and export in raw FIPS 204 form.
- Private key import and export or a documented non-exportable lifecycle.
- Signing with the package domain context.
- Verification with the same canonical bytes and package domain context.
- Rejection of malformed public keys and malformed signatures by length before
  provider calls where practical.
- Rejection of unsupported parameter sets.
- Deterministic test entropy isolation from production signing APIs.

`vectors/mldsa-conformance-v1.json` records real CryptoKit provider evidence
for ML-DSA-65 key generation, signing, verification, public-key export/import,
provider-specific private-key export/import, wrong-context rejection, signed
bytes mismatch rejection, malformed public key rejection, and malformed
signature rejection.

`vectors/android-bouncycastle-mldsa-conformance-v1.json` records real Android
managed JVM fallback evidence for ML-DSA-65 key generation, signing,
verification, public-key export/import, private-key export/import,
wrong-context rejection, signed-bytes mismatch rejection, malformed public key
rejection, and malformed signature rejection.

Structural fixtures remain non-cryptographic until a provider-backed
conformance vector covers the same case.

## Android Managed JVM Code Map

| FIPS 204 behavior | Package path |
| --- | --- |
| Parameter set selection | `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSA65.kt` |
| Key generation | `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSA65.kt` |
| Public and private key length validation | `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSAKeyTypes.kt` |
| Raw public/private key import and export | `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSA65.kt` |
| Signing and verification with package context | `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSA65.kt` |
| Production entropy and test-only deterministic entropy | `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSAEntropy.kt` |
| Production provider selection gates | `platforms/android/src/main/kotlin/com/pqauthkit/PQAuthProvider.kt` |

## Trust-State Domains

- `pqauth-kit-account-identity-hybrid-auth-v1`
- `pqauth-kit-device-identity-hybrid-auth-v1`
- `pqauth-kit-device-roster-hybrid-auth-v1`
- `pqauth-kit-ratchet-prekey-bundle-hybrid-auth-v1`
- `pqauth-kit-safety-number-hybrid-auth-v1`
- `pqauth-kit-envelope-pq-signature-v1-experimental`

The first five domains are in the default hybrid-auth trust-state profile. The
envelope PQ signature domain is experimental and disabled by default.
