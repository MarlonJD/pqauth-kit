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
Castle profile, macOS CryptoKit profile, iOS CryptoKit release-device profile,
and Windows .NET profile are approved for package-level trust-state ML-DSA-65
use when a consuming product explicitly accepts that provider and remaining
risk. This does not approve Secure Enclave non-exportable lifecycle behavior,
fallback implementations, or consuming-repository storage, migration, rollout,
telemetry, and release approval.

## Evidence Matrix

| Surface | Provider status | Cryptographic conformance | Production fallback status | Required command |
| --- | --- | --- | --- | --- |
| iOS | CryptoKit ML-DSA-65 approved for package-level trust-state use on OS 26+ physical release device; Secure Enclave remains separate | `docs/evidence/apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05.md` plus the package-neutral host harness prove provider-backed keygen/sign/verify over all five trust-state objects | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass; release-device benchmark and package-boundary side-channel notes are in `docs/evidence/` | `xcodebuild build -project platforms/swift/DeviceHarness/PQAuthKitIOSDeviceHarness.xcodeproj -scheme PQAuthKitIOSDeviceHarness -configuration Release -destination 'id=00008150-001471191A0A401C' -derivedDataPath /private/tmp/pqauthkit-ios-device-harness-app-derived-data DEVELOPMENT_TEAM=<team-id>`; `xcrun devicectl device process launch --device 02329A9F-84C9-5499-9EBF-074EFCB45F7C --console --terminate-existing --timeout 60 com.pqauthkit.deviceharness` |
| macOS | CryptoKit ML-DSA-65 approved for package-level trust-state use on OS 26+ release hardware; Secure Enclave remains separate | `docs/evidence/apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05.md` plus Swift tests prove provider-backed keygen/sign/verify over all five trust-state objects | Swift fallback blocked until audit, benchmarks, vectors, and side-channel review pass; local benchmark and package-boundary side-channel notes are in `docs/evidence/` | `cd platforms/swift && swift test && swift test -c release` |
| Android | No documented app-facing ML-DSA provider at this checkpoint; Android 17 PQC APK signing is distribution identity only | `vectors/android-bouncycastle-mldsa-conformance-v1.json` contains a Bouncy Castle ML-DSA-65 keygen/sign/verify/import/export fixture generated in an Android emulator | Managed JVM fallback is approved for this checkpoint with emulator benchmark, package-boundary audit, and side-channel notes; release-device and external audit follow-ups remain recommended | `cd platforms/android && ./gradlew test` |
| Windows | .NET `System.Security.Cryptography.MLDsa` approved for package-level trust-state use when `IsSupported` is true | `docs/evidence/windows-dotnet-mldsa-github-actions-evidence-2026-06-05.md` records GitHub Actions Windows runtime support, five provider-backed trust-state cases, and hosted-runner benchmark evidence | Managed C# fallback blocked until audit, benchmarks, vectors, and side-channel review pass | `cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test`; GitHub Actions run `26999599786` |

## Readiness Checklist

| Gate | Status | Evidence |
| --- | --- | --- |
| Scaffold readiness | Complete | Provider metadata, structural vectors, and platform policy tests exist. |
| Cryptographic conformance readiness | Complete for approved package profiles | Android Bouncy Castle, macOS CryptoKit, iOS CryptoKit release-device, and Windows .NET evidence prove all trust-state objects for their approved package profiles. |
| Provider audit readiness | Complete for approved package profiles | Official provider document checks are recorded in `docs/evidence/readiness-gates-v1.json`; package-boundary approval notes are recorded, and independent external crypto review remains recommended. |
| Benchmark readiness | Complete for approved package profiles | macOS CryptoKit, iOS release-device CryptoKit, Android emulator, and Windows hosted-runner timing reports exist; broader device matrices remain recommended. |
| Side-channel readiness | Complete for approved package profiles | Package-boundary CryptoKit, Android managed fallback, and Windows .NET review notes exist; provider-internals review remains pending. |
| Integration readiness | Complete | `docs/evidence/trust-state-integration-readiness-2026-06-04.md` approves `vectors/hybrid-trust-state-v1.json` as the shared server/verifier and client contract, and `docs/evidence/server-verifier-trust-state-integration-2026-06-04.md` proves a server/verifier-style consumer loads that vector directly, accepts the five positive trust-state objects, rejects all nine fail-closed negative cases, rejects Ed25519-only downgrade outside documented migration mode, and fails closed when no approved ML-DSA provider is available. |

## Production Readiness Scopes

| Scope | Status | Evidence |
| --- | --- | --- |
| Android managed JVM ML-DSA-65 trust-state profile | Approved | `docs/evidence/production-readiness-v1.json` plus `docs/evidence/android-bouncycastle-mldsa65-trust-state-profile-2026-06-05.md`; the Android test signs and verifies all five trust-state objects with the provider-backed `MLDSA65` path. |
| macOS CryptoKit ML-DSA-65 trust-state profile | Approved | `docs/evidence/apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05.md`; the Swift package test signs and verifies all five trust-state objects with the provider-backed CryptoKit `MLDSA65` path on macOS release hardware. |
| Apple iOS CryptoKit ML-DSA-65 trust-state profile | Approved | `docs/evidence/apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05.md`; the package-neutral host app signs and verifies all five trust-state objects with provider-backed CryptoKit `MLDSA65` on a physical iOS 26.5.1 release device. |
| Windows .NET ML-DSA-65 trust-state profile | Approved | `docs/evidence/windows-dotnet-mldsa-github-actions-evidence-2026-06-05.md` plus run `26999599786` prove `mldsaIsSupported=true`, all five provider-backed trust-state cases, and hosted-runner benchmark evidence. |
| All supported package platforms | Approved | Android, macOS, iOS, and Windows package-level trust-state profiles are approved. Consuming repositories still own storage, migration, rollout, telemetry, and release approval. |

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
