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

This evidence does not approve the iOS production profile because simulator
execution is not release-device evidence.

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

The iOS package-level production profile remains blocked until a
package-neutral iOS host application or equivalent release-device harness runs
the provider-backed trust-state tests on a physical iOS device and records
benchmark, lifecycle, and side-channel evidence.
