# Apple CryptoKit ML-DSA-65 macOS Side-Channel Review

Date: 2026-06-04
Provider id: `apple.cryptokit.mldsa65.macos`
Review id: `apple-cryptokit-mldsa65-macos-side-channel-review-2026-06-04`
Package commit at review: `bdccefb89a2c933513c99f658cd2070d8740236c`

## Scope

This review covers the `pqauth-kit` boundary around Apple CryptoKit ML-DSA-65
on macOS 26. It does not audit Apple's provider internals and does not approve a
Swift fallback implementation.

## Findings

- `pqauth-kit` calls CryptoKit for ML-DSA key generation, signing,
  verification, public-key import, and provider-specific private-key import.
- The package does not add C, C++, Rust, assembly, FFI, native dynamic
  libraries, vendored native libraries, Metal, GPU, or fallback ML-DSA code.
- Structural fixtures are labeled non-cryptographic, and the provider-generated
  conformance fixture is stored separately in `vectors/mldsa-conformance-v1.json`.
- Private-key fixture material in the conformance vector is marked as a
  test-only provider representation and is not a production secret.
- Public-key and signature length checks happen before provider verification
  where the package owns validation.
- Failure paths in the package tests do not log private keys, canonical
  plaintext, raw signatures, or provider exceptions as user-visible strings.

## Remaining Risk

- Apple provider internals are not independently audited by this repository.
- Release-device timing, allocation, power, and low-memory evidence remain
  pending for iOS and macOS hardware.
- Secure Enclave lifecycle compatibility remains a separate approval because
  non-exportable keys can affect migration and recovery.
- No pure Swift fallback is approved.
