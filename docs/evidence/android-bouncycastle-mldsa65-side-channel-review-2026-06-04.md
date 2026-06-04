# Android Bouncy Castle ML-DSA-65 Side-Channel Review

Date: 2026-06-04

Provider id: `android.bouncycastle-jvm.mldsa65`

## Scope

This review covers the `pqauth-kit` package boundary and provider selection
rules for the managed JVM Android ML-DSA-65 fallback. It does not claim to audit
the full Bouncy Castle implementation internals.

## Review Notes

- Secret-dependent branch review: the wrapper delegates primitive operations to
  Bouncy Castle and does not branch on private key bytes, signature bytes, or
  sampled polynomial state.
- Secret-dependent memory access review: the wrapper copies complete byte
  arrays at API boundaries and does not index into secret arrays based on secret
  values.
- Rejection sampling review: rejection sampling is delegated to the Bouncy
  Castle ML-DSA implementation.
- Zeroization review: Kotlin/JVM and Android ART do not provide strong
  zeroization guarantees for managed byte arrays. Private key arrays are copied
  defensively, but callers remain responsible for key lifecycle and storage.
- Failure-path review: malformed public keys, malformed private keys, and
  malformed signatures throw length validation errors before provider import.
  Verification mismatches return `false`.
- Logging-boundary review: the wrapper does not log key material, signatures,
  contexts, messages, or provider internals.
- Native dependency review: the fallback has no JNI, NDK, FFI, native dynamic
  library, vendored native library, or GPU dependency.

## Approval

Status: approved for package-boundary side-channel gate with managed-runtime
residual risk accepted for this checkpoint.

Remaining risk: release-device timing collection and independent crypto review
of Bouncy Castle internals remain recommended.
