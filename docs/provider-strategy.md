# PQAuthKit Provider Strategy

Date: 2026-06-04

## Objective

`pqauth-kit` provides hybrid post-quantum authentication for low-frequency
trust-state objects. The default message hot path remains ratchet-derived
keys, AEAD tags, transcript binding, and the existing envelope signature policy;
per-message ML-DSA signatures are not part of the default profile.

The package selects ML-DSA providers for:

- Account identity bundles.
- Device identity bundles.
- Device roster publish events.
- Signed ratchet prekey bundles.
- Safety-number material.

## Provider Rules

All providers expose metadata with:

- `providerId`
- `algorithm`
- `parameterSet`
- `isPlatformNative`
- `isHardwareIsolated`
- `minimumOSOrRuntime`
- `supportsKeyGeneration`
- `supportsSign`
- `supportsVerify`
- `privateKeyExportPolicy`
- `usesCOrFFI`
- `nativeLibraryDependency`
- `fallbackAllowedInProduction`
- `auditStatus`
- `benchmarkStatus`
- `sideChannelReviewStatus`

Fallback providers are production-ineligible unless audit, vector parity,
benchmarks, and side-channel review are all approved. If `hybrid_auth_required`
is active and no approved provider is available, clients fail closed rather than
silently downgrading to Ed25519-only trust-state records.

## Apple iOS And macOS

Apple CryptoKit currently documents ML-DSA APIs for `MLDSA65` and `MLDSA87`,
and Secure Enclave ML-DSA key APIs on supported hardware and OS releases:

- https://developer.apple.com/documentation/cryptokit/mldsa65
- https://developer.apple.com/documentation/cryptokit/mldsa87
- https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa65
- https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa87

Policy:

- Prefer CryptoKit ML-DSA on OS 26+ when the SDK and runtime expose the chosen
  parameter set and the provider stays stable for the operation.
- Select Secure Enclave ML-DSA only when non-exportable key lifecycle is
  compatible with account recovery, migration, and multi-device E2EE.
- Below OS 26, use only an audited Swift fallback when explicitly enabled by
  policy; otherwise fail closed for `hybrid_auth_required`.
- Do not add C, C++, Rust, assembly, vendored native libraries, dynamic native
  libraries, Metal/GPU acceleration, or FFI fallback paths.

## Android

The Android 17 public developer feature for ML-DSA is hybrid APK signing. That
protects app distribution identity and is not an app-facing E2EE trust-state
signing provider:

- https://developer.android.com/about/versions/17/features

Android Keystore and KeyMint documentation list app-facing primitives such as
RSA, ECDSA, HMAC, AES, ECDH, and related storage or attestation behavior, but no
app-facing ML-DSA signing primitive is documented at this checkpoint:

- https://source.android.com/docs/security/features/keystore
- https://source.android.com/docs/security/features/keystore/features

Policy:

- Treat Android 17 PQC APK signing as distribution identity only.
- Use Android Keystore only for storage or wrapping of supported key material.
- Do not claim hardware-backed ML-DSA E2EE signing until Android exposes a
  documented app-facing provider.
- Use only an audited pure Kotlin fallback when all production gates are closed.
- Do not add JNI, NDK, C, C++, Rust, assembly, vendored native libraries,
  dynamic native libraries, or FFI fallback paths.

## Windows And .NET

.NET 10 documents `System.Security.Cryptography.MLDsa`, including
`MLDsa.IsSupported`, key generation, import/export, sign, and verify APIs:

- https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.mldsa?view=net-10.0

Policy:

- Prefer `System.Security.Cryptography.MLDsa` when the shipping runtime supports
  it and `MLDsa.IsSupported` is true.
- Use CNG or OpenSSL only through official .NET provider classes.
- Use only an audited managed C# fallback after FIPS 204 code map, vector
  parity, audit, side-channel review, and benchmark gates are approved.
- Do not add P/Invoke, native DLL loading, C, C++, Rust, assembly, vendored
  native libraries, dynamic native libraries, or FFI fallback paths.

## Default Provider Outcome

The default package policy is conservative:

- Apple OS 26+ native providers may be selected when runtime capabilities are
  available.
- Android fails closed for hybrid-auth unless an approved app-facing provider or
  audited Kotlin fallback is explicitly supplied.
- Windows selects .NET `MLDsa` only when `IsSupported` is true, otherwise fails
  closed unless an audited managed fallback is explicitly supplied.
- Deterministic entropy is test-only and unavailable to production APIs.
