# PQAuthKit Readiness Evidence

Date: 2026-06-04

## Current Status

`pqauth-kit` is scaffolded as a dedicated ML-DSA hybrid authentication package
for trust-state objects. The package currently contains provider metadata,
fail-closed selection policy, structural vectors, and platform tests. It does
not yet contain an audited pure-language ML-DSA fallback implementation.

## Evidence Matrix

| Surface | Provider status | Cryptographic conformance | Production fallback status | Required command |
| --- | --- | --- | --- | --- |
| iOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | Pending release-device provider vector | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/swift && swift test` |
| macOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | `vectors/mldsa-conformance-v1.json` contains a CryptoKit ML-DSA-65 keygen/sign/verify/import/export fixture generated on macOS 26 | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass; local benchmark and package-boundary side-channel notes are in `docs/evidence/` | `cd platforms/swift && swift test` |
| Android | No documented app-facing ML-DSA provider at this checkpoint; Android 17 PQC APK signing is distribution identity only | Pending; no provider-backed app-facing vector exists | Kotlin fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/android && ./gradlew test` |
| Windows | .NET `System.Security.Cryptography.MLDsa` allowed when `IsSupported` is true | Pending runtime-supported .NET vector; this macOS .NET runtime exposes the API but reports `IsSupported=false` | Managed C# fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test` |

## Readiness Checklist

| Gate | Status | Evidence |
| --- | --- | --- |
| Scaffold readiness | Complete | Provider metadata, structural vectors, and platform policy tests exist. |
| Cryptographic conformance readiness | Partial | `vectors/mldsa-conformance-v1.json` proves one CryptoKit ML-DSA-65 provider path. Additional provider/device/runtime vectors remain open. |
| Provider audit readiness | Partial | Official provider document checks are recorded in `docs/evidence/readiness-gates-v1.json`; fallback audit reports are not approved. |
| Benchmark readiness | Partial | A local macOS CryptoKit timing report exists; release-device and allocation evidence remain pending. |
| Side-channel readiness | Partial | A package-boundary CryptoKit review note exists; fallback and provider-internals review remain pending. |
| Integration readiness | Pending | External server/verifier and client integrations must consume the same conformance vectors and fail closed when no approved provider is present. |

## Evidence Manifest Fields

Every production-ready provider entry must carry:

- Provider id.
- Parameter set.
- Source version or commit.
- License.
- OS/runtime and device model when device-specific.
- Benchmark date and command.
- Reviewer or audit owner.
- Conformance vector id.
- Benchmark report id.
- Side-channel review id.
- Remaining risk.

## Open Evidence

- Additional ML-DSA cryptographic conformance vectors from every approved
  provider and target runtime.
- Device benchmark reports for Apple, Android, and Windows.
- Side-channel review reports for any fallback implementation.
- Secure Enclave lifecycle decision for non-exportable account/device keys.
- Server or verifier trust-state integration and storage evidence.
