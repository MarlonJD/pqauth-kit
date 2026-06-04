# Android Bouncy Castle ML-DSA-65 Package Audit

Date: 2026-06-04

Provider id: `android.bouncycastle-jvm.mldsa65`

Source:

- Dependency: `org.bouncycastle:bcprov-jdk18on:1.84`
- Upstream: https://www.bouncycastle.org/download/bouncy-castle-java/
- API package: `org.bouncycastle.pqc.crypto.mldsa`
- License: Bouncy Castle Licence

## Scope

This review covers the `pqauth-kit` Android wrapper around Bouncy Castle's
managed JVM ML-DSA-65 implementation:

- `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSA65.kt`
- `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSAKeyTypes.kt`
- `platforms/android/src/main/kotlin/com/pqauthkit/mldsa/MLDSAEntropy.kt`
- `platforms/android/src/main/kotlin/com/pqauthkit/PQAuthProvider.kt`

The wrapper uses Bouncy Castle raw ML-DSA key parameters and signer APIs. It
does not add JNI, NDK, FFI, native dynamic libraries, vendored native libraries,
GPU acceleration, or platform private APIs.

## Findings

- The provider performs real ML-DSA-65 key generation, signing, verification,
  public key import/export, private key import/export, wrong-message rejection,
  wrong-context rejection, malformed public key rejection, and malformed
  signature rejection.
- `SecureRandomEntropySource` is the default production entropy source.
- Deterministic entropy remains test-only.
- The wrapper copies encoded key and signature byte arrays at boundaries.
- The wrapper does not log key material, signatures, contexts, or intermediate
  crypto state.
- Provider selection rejects native, FFI, and native-library fallback
  dependencies.

## Evidence

- Conformance vector:
  `vectors/android-bouncycastle-mldsa-conformance-v1.json`
- Emulator benchmark:
  `docs/evidence/android-bouncycastle-mldsa65-emulator-benchmark-2026-06-04.json`
- Side-channel package-boundary review:
  `docs/evidence/android-bouncycastle-mldsa65-side-channel-review-2026-06-04.md`
- Android emulator evidence:
  `/tmp/pqauth-android-emulator-evidence/evidence.json`

## Approval

Status: approved for managed JVM fallback selection in this package.

Remaining risk: this is not a FIPS 140 validation and not an external formal
crypto audit of Bouncy Castle internals. Release-device benchmarking and
independent external crypto review remain recommended follow-up evidence.
