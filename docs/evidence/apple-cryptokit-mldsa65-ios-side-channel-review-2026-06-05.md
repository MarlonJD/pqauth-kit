# Apple CryptoKit ML-DSA-65 iOS Side-Channel Review

Date: 2026-06-05

Provider id: `apple.cryptokit.mldsa65.ios`

Review id: `apple-cryptokit-mldsa65-ios-side-channel-review-2026-06-05`

Package commit at review: `cc13378f5789eaca960f987aff1d1febfbf07232`

## Scope

This review covers the `pqauth-kit` boundary around Apple CryptoKit ML-DSA-65
on iOS 26. It does not audit Apple's provider internals and does not approve a
Swift fallback implementation.

## Findings

- `pqauth-kit` calls CryptoKit for ML-DSA key generation, signing,
  verification, public-key import, and provider-specific private-key import.
- The package does not add C, C++, Rust, assembly, FFI, native dynamic
  libraries, vendored native libraries, Metal, GPU, or fallback ML-DSA code.
- The iOS device harness embeds package JSON resources and runs the provider
  path on a physical device; it does not log private keys, raw signatures, or
  canonical trust-state plaintext in approval evidence.
- Public-key and signature length checks happen before provider verification
  where the package owns validation.
- Failure-path evidence covers wrong canonical bytes, wrong context, malformed
  public keys, and malformed signatures.
- The approved package profile uses exportable CryptoKit integrity-checked
  private-key representations; Secure Enclave non-exportable lifecycle is
  intentionally excluded from this approval.

## Remaining Risk

- Apple provider internals are not independently audited by this repository.
- Power profiling, allocation profiling, and a broader device timing matrix
  remain recommended follow-up evidence.
- Secure Enclave lifecycle compatibility remains a separate approval because
  non-exportable keys can affect migration and recovery.
- No pure Swift fallback is approved.
