# PQAuthKit Audit Checklist

Date: 2026-06-04

## Release Gate

No fallback provider is production-eligible until every item in this checklist
has an owner, evidence link, and approval status. A missing item means
`hybrid_auth_required` must fail closed on that platform.

## Provider Audit

- Provider source, version, commit, and license recorded.
- FIPS 204 parameter set mapped to code paths for key generation, signing,
  verification, import, export, context handling, and malformed input rejection.
- Positive vectors pass for account identity, device identity, roster publish,
  prekey bundle, and safety-number material.
- Negative vectors reject missing ML-DSA, missing Ed25519, mismatched signed
  bytes, wrong context, wrong domain separator, wrong public key length, wrong
  signature length, unsupported parameter set, and Ed25519-only records outside
  migration mode.
- Deterministic entropy is limited to tests and fixture generation.
- Provider selection is stable during a signing or verification operation.
- Private keys are never logged, exported through debug tooling, stored with
  ML-KEM material, or exposed to notification-preview paths.

## Side-Channel Review

- Secret-dependent branches, memory access patterns, rejection sampling, and
  timing behavior reviewed for the implementation language and target hardware.
- Allocation and zeroization behavior reviewed for private key material and
  intermediate signing state.
- Failure paths do not leak private material, canonical plaintext, or raw
  signatures to logs, analytics, crash reports, or user-visible errors.

## Benchmark Evidence

Record keygen, sign, verify, import, export, malformed public key rejection, and
malformed signature rejection for:

- At least one supported iPhone.
- Apple Silicon macOS release hardware.
- Low, mid, and high Android devices.
- Windows x64 and ARM64 where hardware is available.

Benchmark evidence must include p50, p95, allocation or memory notes, payload
size impact, device model, OS/runtime version, provider id, and package commit.

## Production Fallback Rules

- Swift fallback: pure Swift only; no C, C++, Rust, assembly, vendored native
  libraries, dynamic native libraries, Metal/GPU acceleration, or FFI.
- Android fallback: pure Kotlin only; no JNI, NDK, C, C++, Rust, assembly,
  vendored native libraries, dynamic native libraries, or FFI.
- Windows fallback: managed C# only; no P/Invoke, native DLL loading, C, C++,
  Rust, assembly, vendored native libraries, dynamic native libraries, or FFI.
