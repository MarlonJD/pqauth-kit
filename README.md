# pqauth-kit

Cross-platform post-quantum authentication package.

This repository is reserved for ML-DSA provider selection, key generation,
signing, verification, shared vectors, and audit evidence used by hybrid
Ed25519 plus ML-DSA trust-state authentication.

It does not implement ML-KEM, message envelopes, ratchets, DM APIs, UI, or
notification preview logic.

## Scope

`pqauth-kit` is a dedicated package for hybrid trust-state
authentication. It owns:

- ML-DSA provider metadata and selection policy.
- Trust-state signature contracts for account identity, device identity,
  roster publish, prekey bundle, and safety-number material.
- Shared positive and negative structural vectors.
- Audit, benchmark, side-channel, and production fallback gates.

`mlkem-kit` remains responsible for ML-KEM confidentiality. `SecureEnvelopeKit`
remains responsible for envelope encoding, AEAD seal/open, and envelope helper
logic. This repository must not grow ratchets, per-message default PQ
signatures, JNI, NDK, P/Invoke, FFI, native dynamic libraries, vendored native
libraries, Metal/GPU acceleration, C, C++, Rust, or assembly fallbacks.

## Layout

- `docs/`: Provider strategy, audit checklist, FIPS 204 code map, and readiness
  evidence.
- `vectors/`: Shared hybrid trust-state signature vectors.
- `platforms/swift/`: Swift package for iOS and macOS provider policy.
- `platforms/android/`: Kotlin/Gradle package for Android provider policy.
- `platforms/dotnet/`: .NET package for Windows provider policy.

## Verification

Run checks from this repository:

```sh
cd platforms/swift && swift test
cd platforms/android && ./gradlew test
cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test
git diff --check
```

The first implementation stage is policy and contract scaffolding. Pure
language ML-DSA fallback implementations are intentionally not enabled for
production until the audit, vector parity, benchmark, and side-channel gates are
closed.
