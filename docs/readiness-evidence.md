# PQAuthKit Readiness Evidence

Date: 2026-06-04

## Current Status

`pqauth-kit` is scaffolded as a dedicated ML-DSA hybrid authentication package
for trust-state objects. The package currently contains provider metadata,
fail-closed selection policy, structural vectors, provider-backed conformance
vectors, and platform tests. Android now has an approved managed JVM ML-DSA-65
fallback for this checkpoint; release-device performance and independent
external crypto review remain recommended follow-up evidence.

## Evidence Matrix

| Surface | Provider status | Cryptographic conformance | Production fallback status | Required command |
| --- | --- | --- | --- | --- |
| iOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | Pending release-device provider vector | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/swift && swift test` |
| macOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | `vectors/mldsa-conformance-v1.json` contains a CryptoKit ML-DSA-65 keygen/sign/verify/import/export fixture generated on macOS 26 | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass; local benchmark and package-boundary side-channel notes are in `docs/evidence/` | `cd platforms/swift && swift test` |
| Android | No documented app-facing ML-DSA provider at this checkpoint; Android 17 PQC APK signing is distribution identity only | `vectors/android-bouncycastle-mldsa-conformance-v1.json` contains a Bouncy Castle ML-DSA-65 keygen/sign/verify/import/export fixture generated in an Android emulator | Managed JVM fallback is approved for this checkpoint with emulator benchmark, package-boundary audit, and side-channel notes; release-device and external audit follow-ups remain recommended | `cd platforms/android && ./gradlew test` |
| Windows | .NET `System.Security.Cryptography.MLDsa` allowed when `IsSupported` is true | Pending runtime-supported .NET vector; `.github/workflows/windows-dotnet-mldsa-evidence.yml` records the Windows runner support status and uploads conformance evidence when supported | Managed C# fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test` |

## Readiness Checklist

| Gate | Status | Evidence |
| --- | --- | --- |
| Scaffold readiness | Complete | Provider metadata, structural vectors, and platform policy tests exist. |
| Cryptographic conformance readiness | Partial | `vectors/mldsa-conformance-v1.json` proves one CryptoKit ML-DSA-65 provider path and `vectors/android-bouncycastle-mldsa-conformance-v1.json` proves the Android managed JVM fallback path. Additional provider/device/runtime vectors remain open. |
| Provider audit readiness | Partial | Official provider document checks are recorded in `docs/evidence/readiness-gates-v1.json`; Android managed fallback package-boundary approval is recorded, and independent external crypto review remains recommended. |
| Benchmark readiness | Partial | Local macOS CryptoKit and Android emulator timing reports exist; release-device and allocation evidence remain pending. |
| Side-channel readiness | Partial | Package-boundary CryptoKit and Android managed fallback review notes exist; provider-internals review remains pending. |
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
- Release-device benchmark reports for Apple, Android, and Windows.
- Windows hosted-runner evidence from
  `.github/workflows/windows-dotnet-mldsa-evidence.yml`; this is sufficient for
  runtime support/conformance discovery, but release-grade performance evidence
  still needs a pinned Windows device or VM.
- Independent provider-internals crypto and side-channel review for fallback
  implementations.
- Secure Enclave lifecycle decision for non-exportable account/device keys.
- Server or verifier trust-state integration and storage evidence.
