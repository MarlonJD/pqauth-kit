# Apple CryptoKit ML-DSA-65 macOS Trust-State Profile Evidence

Date: 2026-06-05

Evidence id: `apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05`

Provider id: `apple.cryptokit.mldsa65.macos`

Status: approved for the macOS package-level trust-state ML-DSA-65 profile.

## Scope

This evidence approves the package-level macOS CryptoKit ML-DSA-65 profile for
low-frequency hybrid trust-state objects:

- `account_identity`
- `device_identity`
- `roster_publish`
- `prekey_bundle`
- `safety_number`

It does not approve Secure Enclave non-exportable-key production use, Swift
fallback production use, Windows production use, iOS production use, or
all-supported-platform production readiness.

## Runtime

- Platform: macOS release hardware.
- OS: macOS 26.5.1, build 25F80.
- Architecture: arm64.
- Swift: Apple Swift 6.3.2, target `arm64-apple-macosx26.0`.
- Provider: CryptoKit `MLDSA65`.
- Private-key lifecycle: exportable CryptoKit integrity-checked
  representation for this package profile.
- Native dependency policy: no package C, C++, Rust, assembly, vendored native
  library, dynamic native library, GPU, or FFI fallback path.

## Conformance

The package test
`platforms/swift/Tests/PQAuthKitSwiftTests/PQAuthVectorFixtureTests.swift`
contains
`testCryptoKitMLDSA65ProviderSignsAndVerifiesEveryTrustStateObject`.

That test:

- loads `vectors/hybrid-trust-state-v1.json`;
- generates a fresh CryptoKit ML-DSA-65 key pair for each positive trust-state
  object;
- signs each canonical trust-state byte string with its documented domain
  separator as context;
- verifies the signature with the generated public key;
- rejects wrong canonical bytes;
- rejects wrong context;
- checks ML-DSA-65 public-key and signature lengths;
- confirms all five trust-state objects are covered.

The provider returns a CryptoKit integrity-checked private-key representation.
That representation is intentionally not asserted to equal the FIPS raw private
key byte length; importability and signing behavior are the lifecycle evidence
for the exportable CryptoKit profile.

## Verification

Commands run on the macOS release hardware:

```bash
sw_vers
uname -m
xcrun swift --version
cd platforms/swift && swift test
cd platforms/swift && swift test -c release
```

Results:

- `sw_vers`: macOS 26.5.1, build 25F80.
- `uname -m`: `arm64`.
- `xcrun swift --version`: Apple Swift 6.3.2, target
  `arm64-apple-macosx26.0`.
- `swift test`: passed with 16 tests, including the provider-backed
  all-trust-state-object test.
- `swift test -c release`: passed with 16 tests, including the
  provider-backed all-trust-state-object test.

## Remaining Risk

- Secure Enclave ML-DSA is not approved by this evidence because
  non-exportable key lifecycle, recovery, restore, and migration behavior are a
  separate decision.
- Provider-internals side-channel properties remain under Apple's provider
  boundary; this package evidence approves the package boundary, API use, input
  validation, fail-closed behavior, and logging boundary only.
- iOS and Windows profile approval remain separate gates.
