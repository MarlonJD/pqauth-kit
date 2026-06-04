# PQAuthKit Readiness Evidence

Date: 2026-06-04

## Current Status

`pqauth-kit` is scaffolded as a dedicated ML-DSA hybrid authentication package
for trust-state objects. The package currently contains provider metadata,
fail-closed selection policy, structural vectors, and platform tests. It does
not yet contain an audited pure-language ML-DSA fallback implementation.

## Evidence Matrix

| Surface | Provider status | Production fallback status | Required command |
| --- | --- | --- | --- |
| iOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/swift && swift test` |
| macOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/swift && swift test` |
| Android | No documented app-facing ML-DSA provider at this checkpoint; Android 17 PQC APK signing is distribution identity only | Kotlin fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/android && ./gradlew test` |
| Windows | .NET `System.Security.Cryptography.MLDsa` allowed when `IsSupported` is true | Managed C# fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test` |

## Open Evidence

- Real ML-DSA cryptographic conformance vectors from the audited provider.
- Device benchmark reports for Apple, Android, and Windows.
- Side-channel review reports for any fallback implementation.
- Secure Enclave lifecycle decision for non-exportable account/device keys.
- Backend trust-state verification integration and storage evidence.
