# PQAuthKit Readiness Evidence

Date: 2026-06-04

## Current Status

`pqauth-kit` is scaffolded as a dedicated ML-DSA hybrid authentication package
for trust-state objects. The package currently contains provider metadata,
fail-closed selection policy, structural vectors, provider-backed conformance
vectors, integration-readiness evidence, downstream server/verifier contract
evidence, and platform tests. Android now has an approved managed JVM
ML-DSA-65 fallback for this checkpoint; release-device performance and
independent external crypto review remain recommended follow-up evidence.

Production readiness is scoped by
`docs/evidence/production-readiness-v1.json`. The Android managed JVM Bouncy
Castle profile and macOS CryptoKit profile are approved for package-level
trust-state ML-DSA-65 use when a consuming product explicitly accepts that
provider and remaining risk. The Windows .NET provider gate accepts GitHub
Actions `windows-latest` artifact evidence for runtime support and trust-state
conformance, but remains pending until a successful artifact records
`mldsaIsSupported=true` and all five provider-backed trust-state cases. iOS
Simulator package coverage exists, but the iOS production profile remains
blocked until a package-neutral release-device host runs the same tests and
records the required evidence. The all-supported-platform profile remains
blocked until iOS and Windows evidence are approved.

## Evidence Matrix

| Surface | Provider status | Cryptographic conformance | Production fallback status | Required command |
| --- | --- | --- | --- | --- |
| iOS | CryptoKit/Secure Enclave ML-DSA allowed on OS 26+ when runtime-capable and lifecycle-compatible | Simulator package coverage exists in `docs/evidence/apple-cryptokit-mldsa65-ios-simulator-trust-state-coverage-2026-06-05.md`; release-device host evidence is still pending | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/swift && swift test`; `xcodebuild test -scheme PQAuthKitSwift -destination 'platform=iOS Simulator,name=iPhone 17' -derivedDataPath /private/tmp/pqauthkit-swift-ios-sim-derived-data` |
| macOS | CryptoKit ML-DSA-65 approved for package-level trust-state use on OS 26+ release hardware; Secure Enclave remains separate | `docs/evidence/apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05.md` plus Swift tests prove provider-backed keygen/sign/verify over all five trust-state objects | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass; local benchmark and package-boundary side-channel notes are in `docs/evidence/` | `cd platforms/swift && swift test && swift test -c release` |
| Android | No documented app-facing ML-DSA provider at this checkpoint; Android 17 PQC APK signing is distribution identity only | `vectors/android-bouncycastle-mldsa-conformance-v1.json` contains a Bouncy Castle ML-DSA-65 keygen/sign/verify/import/export fixture generated in an Android emulator | Managed JVM fallback is approved for this checkpoint with emulator benchmark, package-boundary audit, and side-channel notes; release-device and external audit follow-ups remain recommended | `cd platforms/android && ./gradlew test` |
| Windows | .NET `System.Security.Cryptography.MLDsa` allowed when `IsSupported` is true | Pending GitHub Actions `windows-latest` artifact; `.github/workflows/windows-dotnet-mldsa-evidence.yml` records runner support and uploads a provider-backed conformance vector over all five trust-state objects when supported | Managed C# fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test` |

## Readiness Checklist

| Gate | Status | Evidence |
| --- | --- | --- |
| Scaffold readiness | Complete | Provider metadata, structural vectors, and platform policy tests exist. |
| Cryptographic conformance readiness | Partial | macOS CryptoKit ML-DSA-65 and Android Bouncy Castle evidence prove all trust-state objects for their approved package profiles. Additional provider/device/runtime vectors remain open. |
| Provider audit readiness | Partial | Official provider document checks are recorded in `docs/evidence/readiness-gates-v1.json`; Android managed fallback package-boundary approval is recorded, and independent external crypto review remains recommended. |
| Benchmark readiness | Partial | Local macOS CryptoKit and Android emulator timing reports exist; release-device and allocation evidence remain pending. |
| Side-channel readiness | Partial | Package-boundary CryptoKit and Android managed fallback review notes exist; provider-internals review remains pending. |
| Integration readiness | Complete | `docs/evidence/trust-state-integration-readiness-2026-06-04.md` approves `vectors/hybrid-trust-state-v1.json` as the shared server/verifier and client contract, and `docs/evidence/server-verifier-trust-state-integration-2026-06-04.md` proves a server/verifier-style consumer loads that vector directly, accepts the five positive trust-state objects, rejects all nine fail-closed negative cases, rejects Ed25519-only downgrade outside documented migration mode, and fails closed when no approved ML-DSA provider is available. |

## Production Readiness Scopes

| Scope | Status | Evidence |
| --- | --- | --- |
| Android managed JVM ML-DSA-65 trust-state profile | Approved | `docs/evidence/production-readiness-v1.json` plus `docs/evidence/android-bouncycastle-mldsa65-trust-state-profile-2026-06-05.md`; the Android test signs and verifies all five trust-state objects with the provider-backed `MLDSA65` path. |
| macOS CryptoKit ML-DSA-65 trust-state profile | Approved | `docs/evidence/apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05.md`; the Swift package test signs and verifies all five trust-state objects with the provider-backed CryptoKit `MLDSA65` path on macOS release hardware. |
| All supported platforms | Blocked | iOS package-level release-device host evidence, successful Windows GitHub Actions ML-DSA artifact evidence, and consuming-repository release approval remain open. |
| Apple iOS CryptoKit ML-DSA-65 trust-state profile | Blocked | `docs/evidence/apple-cryptokit-mldsa65-ios-simulator-trust-state-coverage-2026-06-05.md` records simulator package coverage. Physical iOS devices reject tool-hosted Swift package tests without a host application, so package-level iOS production evidence remains blocked until a package-neutral host app or equivalent release-device harness exists. |
| Windows .NET ML-DSA-65 trust-state profile | Blocked | GitHub Actions `windows-latest` evidence is accepted for this package-level gate, but a successful uploaded artifact with `mldsaIsSupported=true` and all five provider-backed trust-state cases is still required. |

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
  `.github/workflows/windows-dotnet-mldsa-evidence.yml`; this is accepted for
  the Windows .NET ML-DSA runtime support and trust-state conformance gate once
  the uploaded artifact records `mldsaIsSupported=true` and all five
  provider-backed trust-state cases.
- iOS package-neutral release-device host application or equivalent harness for
  the Swift package tests; simulator coverage exists but is not production
  evidence.
- Independent provider-internals crypto and side-channel review for fallback
  implementations.
- Secure Enclave lifecycle decision for non-exportable account/device keys.
- Production storage, migration, and rollout evidence for deployed consuming
  backends. The package-level server/verifier contract evidence is complete.

## Readiness Checker

Run the package-level checker after changing readiness manifests, trust-state
vectors, provider evidence, or production profile documents:

```bash
python3 tools/check_production_readiness.py --manifest docs/evidence/production-readiness-v1.json
```
