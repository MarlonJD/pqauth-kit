# Apple CryptoKit ML-DSA-65 iOS Simulator Trust-State Coverage

Date: 2026-06-05

Evidence id: `apple-cryptokit-mldsa65-ios-simulator-trust-state-coverage-2026-06-05`

Provider id: `apple.cryptokit.mldsa65.ios`

Status: coverage only; not production approval.

## Scope

The Swift package test suite was executed on an iOS Simulator destination and
covered the same provider-backed trust-state test used for the approved macOS
package profile. This confirms the package compiles and the XCTest coverage can
execute under the iOS simulator runtime.

This evidence does not approve the iOS production profile by itself because
simulator execution is not release-device evidence. The later release-device
profile in
`docs/evidence/apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05.md`
is the approving iOS production evidence.

## Commands

```bash
xcodebuild test -scheme PQAuthKitSwift -destination 'platform=iOS Simulator,name=iPhone 17' -derivedDataPath /private/tmp/pqauthkit-swift-ios-sim-derived-data
```

Result:

- `TEST SUCCEEDED`
- 16 tests passed
- Result bundle:
  `/tmp/pqauthkit-swift-ios-sim-derived-data/Logs/Test/Test-PQAuthKitSwift-2026.06.05_09-25-18-+0300.xcresult`

## Release-Device Blocker

The same Swift package test target cannot run directly on a physical iOS device
because device destinations do not support tool-hosted package tests.

Attempted command:

```bash
xcodebuild test -scheme PQAuthKitSwift -destination 'id=00008150-001471191A0A401C' -derivedDataPath /private/tmp/pqauthkit-swift-ios-device-derived-data
```

Observed blocker:

```text
Cannot test target "PQAuthKitSwiftTests" on a physical iOS device:
Tool-hosted testing is unavailable on device destinations. Select a host
application for the test target, or use a simulator destination instead.
```

Before the release-device profile was added, the iOS package-level production
profile remained blocked until a package-neutral iOS host application or
equivalent release-device harness ran the provider-backed trust-state tests on
a physical iOS device and recorded benchmark, lifecycle, and side-channel
evidence.
