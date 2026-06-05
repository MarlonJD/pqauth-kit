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
- `evidence.providerSourceId`
- `evidence.providerVersion`
- `evidence.providerCommit`
- `evidence.license`
- `evidence.conformanceVectorId`
- `evidence.auditReportId`
- `evidence.benchmarkReportId`
- `evidence.sideChannelReviewId`
- `evidence.remainingRisk`

Fallback providers are production-ineligible unless audit, vector parity,
benchmarks, and side-channel review are all approved. If the required
hybrid-auth profile is active and no approved provider is available, clients
fail closed rather than silently downgrading to Ed25519-only trust-state
records.

Runtime provider selection and production readiness are separate decisions.
Platform-native providers may be selectable when the OS/runtime supports them,
but readiness remains blocked until evidence ids for conformance, audit,
benchmark, and side-channel review are present and approved.

## Apple iOS And macOS

Official documentation re-checked: 2026-06-04.

Apple CryptoKit currently documents ML-DSA APIs for `MLDSA65` and `MLDSA87`,
and Secure Enclave ML-DSA key APIs on supported hardware and OS releases:

- https://developer.apple.com/documentation/cryptokit/mldsa65
- https://developer.apple.com/documentation/cryptokit/mldsa87
- https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa65
- https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa87

Policy:

- Prefer CryptoKit ML-DSA on OS 26+ when the SDK and runtime expose the chosen
  parameter set and the provider stays stable for the operation.
- macOS CryptoKit ML-DSA-65 is approved for package-level trust-state use after
  release-hardware SwiftPM evidence over all five trust-state objects.
- iOS Simulator Swift package coverage exists, but iOS production readiness
  remains blocked until a package-neutral host app or equivalent
  release-device harness runs the provider-backed tests on physical hardware.
- Select Secure Enclave ML-DSA only when non-exportable key lifecycle is
  compatible with account recovery, migration, and multi-device E2EE.
- Below OS 26, use only an audited Swift fallback when explicitly enabled by
  policy; otherwise fail closed for the required hybrid-auth profile.
- Do not add C, C++, Rust, assembly, vendored native libraries, dynamic native
  libraries, Metal/GPU acceleration, or FFI fallback paths.

## Android

Official documentation re-checked: 2026-06-04.

The Android 17 public developer feature for ML-DSA is hybrid APK signing. That
protects app distribution identity and is not an app-facing trust-state
signing provider:

- https://developer.android.com/about/versions/17/features

Android Keystore and KeyMint documentation list app-facing primitives such as
RSA, ECDSA, HMAC, AES, ECDH, and related storage or attestation behavior, but no
app-facing ML-DSA signing primitive is documented at this checkpoint:

- https://source.android.com/docs/security/features/keystore
- https://source.android.com/docs/security/features/keystore/features

Managed fallback evidence:

- `android.bouncycastle-jvm.mldsa65` uses `org.bouncycastle:bcprov-jdk18on:1.84`
  through the Android JVM runtime.
- The fallback has no JNI, NDK, FFI, native dynamic library, vendored native
  library, GPU, C, C++, Rust, assembly, or platform-private dependency.
- Emulator conformance and benchmark evidence are recorded in
  `vectors/android-bouncycastle-mldsa-conformance-v1.json` and
  `docs/evidence/android-bouncycastle-mldsa65-emulator-benchmark-2026-06-04.json`.
- Package-boundary audit and side-channel reviews are recorded in
  `docs/evidence/android-bouncycastle-mldsa65-package-audit-2026-06-04.md` and
  `docs/evidence/android-bouncycastle-mldsa65-side-channel-review-2026-06-04.md`.

Policy:

- Treat Android 17 PQC APK signing as distribution identity only.
- Use Android Keystore only for storage or wrapping of supported key material.
- Do not claim hardware-backed ML-DSA E2EE signing until Android exposes a
  documented app-facing provider.
- Use the approved managed JVM ML-DSA fallback when `allowAuditedFallback` is
  enabled and the runtime has no documented app-facing ML-DSA provider.
- Do not add JNI, NDK, C, C++, Rust, assembly, vendored native libraries,
  dynamic native libraries, or FFI fallback paths.

## Windows And .NET

Official documentation re-checked: 2026-06-04.

.NET 10 documents `System.Security.Cryptography.MLDsa`, including
`MLDsa.IsSupported`, key generation, import/export, sign, and verify APIs:

- https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.mldsa?view=net-10.0

Policy:

- Prefer `System.Security.Cryptography.MLDsa` when the shipping runtime supports
  it and `MLDsa.IsSupported` is true.
- For the package-level Windows gate, GitHub Actions `windows-latest` evidence
  is accepted when the uploaded artifact records `mldsaIsSupported=true` and a
  provider-backed conformance vector over all five trust-state objects.
- Use CNG or OpenSSL only through official .NET provider classes.
- Use only an audited managed C# fallback after FIPS 204 code map, vector
  parity, audit, side-channel review, and benchmark gates are approved.
- Do not add P/Invoke, native DLL loading, C, C++, Rust, assembly, vendored
  native libraries, dynamic native libraries, or FFI fallback paths.

## Default Provider Outcome

The default package policy is conservative:

- Apple OS 26+ native providers may be selected when runtime capabilities are
  available.
- Android selects the approved managed JVM ML-DSA fallback when policy permits
  audited fallback; otherwise it fails closed until an app-facing provider is
  documented.
- Windows selects .NET `MLDsa` only when `IsSupported` is true, otherwise fails
  closed unless an audited managed fallback is explicitly supplied.
- Deterministic entropy is test-only and unavailable to production APIs.
