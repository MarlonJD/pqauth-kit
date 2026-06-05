# Apple CryptoKit ML-DSA-65 iOS Release-Device Trust-State Profile Evidence

Date: 2026-06-05

Evidence id: `apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05`

Provider id: `apple.cryptokit.mldsa65.ios`

Status: approved for the iOS package-level trust-state ML-DSA-65 profile.

## Scope

This evidence approves the package-level iOS CryptoKit ML-DSA-65 profile for
low-frequency hybrid trust-state objects:

- `account_identity`
- `device_identity`
- `roster_publish`
- `prekey_bundle`
- `safety_number`

It does not approve Secure Enclave non-exportable-key production use, Swift
fallback production use, per-message ML-DSA signatures, or consuming-application
storage, migration, rollout, telemetry, and release approval.

## Runtime

- Platform: physical iOS release device.
- Device: Burak iPhone'u, iPhone 17 (`iPhone18,3`).
- OS: iOS 26.5.1.
- Xcode: 26.5, build 17F42.
- Provider: CryptoKit `MLDSA65`.
- Private-key lifecycle: exportable CryptoKit integrity-checked
  representation for this package profile.
- Native dependency policy: no package C, C++, Rust, assembly, vendored native
  library, dynamic native library, GPU, or FFI fallback path.

## Harness

The package-neutral host app lives at
`platforms/swift/DeviceHarness/PQAuthKitIOSDeviceHarness.xcodeproj`.

The harness:

- embeds `vectors/hybrid-trust-state-v1.json` and readiness manifests as app
  resources;
- imports the local `PQAuthKitSwift` package product;
- runs on a physical iOS device instead of relying on tool-hosted Swift package
  tests;
- generates a fresh CryptoKit ML-DSA-65 key pair for each positive trust-state
  object;
- signs each canonical trust-state byte string with its documented domain
  separator as context;
- verifies the signature with the generated public key;
- rejects wrong canonical bytes;
- rejects wrong context;
- rejects malformed public keys and malformed signatures;
- checks ML-DSA-65 public-key and signature lengths;
- records public-key import/export and private-key import/export timing;
- confirms all five trust-state objects are covered.

## Verification

Commands run:

```bash
xcrun devicectl list devices
xcodebuild build -project platforms/swift/DeviceHarness/PQAuthKitIOSDeviceHarness.xcodeproj -scheme PQAuthKitIOSDeviceHarness -configuration Release -destination 'id=00008150-001471191A0A401C' -derivedDataPath /private/tmp/pqauthkit-ios-device-harness-app-derived-data DEVELOPMENT_TEAM=UPK4SC93AN
xcrun devicectl device install app --device 02329A9F-84C9-5499-9EBF-074EFCB45F7C /private/tmp/pqauthkit-ios-device-harness-app-derived-data/Build/Products/Release-iphoneos/PQAuthKitIOSDeviceHarness.app --json-output /private/tmp/pqauthkit-ios-device-install-4.json --log-output /private/tmp/pqauthkit-ios-device-install-4.log
xcrun devicectl device process launch --device 02329A9F-84C9-5499-9EBF-074EFCB45F7C --console --terminate-existing --timeout 60 --json-output /private/tmp/pqauthkit-ios-device-launch-4.json --log-output /private/tmp/pqauthkit-ios-device-launch-4.log com.pqauthkit.deviceharness
```

Results:

- `devicectl`: device available and paired as iPhone 17 (`iPhone18,3`).
- `xcodebuild build`: passed for Release `iphoneos` destination
  `00008150-001471191A0A401C`.
- `devicectl install`: installed `com.pqauthkit.deviceharness`.
- `devicectl launch`: app terminated with exit code 0.
- Evidence marker: `PQAUTH_IOS_DEVICE_EVIDENCE_JSON=...`.
- Evidence JSON schema: `pqauth-kit-ios-device-evidence-v1`.
- Evidence provider: `apple.cryptokit.mldsa65.ios`.
- Evidence parameter set: `ML-DSA-65`.
- Evidence covered all five trust-state objects.
- Evidence confirmed the bundled readiness manifest has
  `readinessManifestIOSProductionReady=true`.
- Benchmark report:
  `docs/evidence/apple-cryptokit-mldsa65-ios-release-device-benchmark-2026-06-05.json`.

The first direct Swift package device attempt is intentionally not used as
approval evidence because Xcode reports that tool-hosted testing is unavailable
on physical device destinations without a host application.

## Remaining Risk

- Secure Enclave ML-DSA is not approved by this evidence because
  non-exportable key lifecycle, recovery, restore, and migration behavior are a
  separate decision.
- Apple provider internals are outside this package-boundary review.
- Power profiling, allocation profiling, and broader device-matrix timing are
  recommended follow-up evidence.
- Consuming applications still own storage, migration, rollout, telemetry, and
  release approval.
