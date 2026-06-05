# Trust-State Integration Readiness

Date: 2026-06-04

Evidence id: `trust-state-integration-readiness-2026-06-04`

Status: approved for `pqauth-kit` package integration readiness.

## Scope

This evidence closes the package-level integration gate for hybrid trust-state
authentication. It proves that server/verifier and client integrations have one
shared vector contract, one required hybrid-auth profile, and fail-closed
provider selection rules when no approved ML-DSA provider is available.
Downstream server/verifier contract evidence is recorded separately in
`docs/evidence/server-verifier-trust-state-integration-2026-06-04.md`.

This package does not own application storage, server deployment, account
recovery flows, or consuming-repository rollout. Those integrations must import
this contract directly instead of copying or rewriting the fixture.

## Shared Contract

The shared contract is `vectors/hybrid-trust-state-v1.json`.

Contract properties:

- Schema: `pqauth-kit-hybrid-trust-state-v1`
- Policy: `ed25519_and_mldsa_required`
- Fixture kind: `structural-non-cryptographic`
- Default ML-DSA parameter set: `ML-DSA-65`
- Default message hot path: per-message PQ signatures disabled

The vector carries canonical bytes, package domain separators, SHA-256 hashes,
Ed25519 placeholder key/signature descriptors, ML-DSA-65 placeholder
key/signature descriptors, and expected negative-case errors. It is structural
integration evidence, not provider-backed cryptographic signature evidence.
Provider-backed cryptographic evidence remains in the separate ML-DSA
conformance vectors.

## Positive Trust-State Objects

`vectors/hybrid-trust-state-v1.json` contains the complete v1 trust-state
profile:

| Object | Vector id | Domain separator |
| --- | --- | --- |
| Account identity | `account_identity` | `pqauth-kit-account-identity-hybrid-auth-v1` |
| Device identity | `device_identity` | `pqauth-kit-device-identity-hybrid-auth-v1` |
| Roster publish | `roster_publish` | `pqauth-kit-device-roster-hybrid-auth-v1` |
| Prekey bundle | `prekey_bundle` | `pqauth-kit-ratchet-prekey-bundle-hybrid-auth-v1` |
| Safety-number material | `safety_number` | `pqauth-kit-safety-number-hybrid-auth-v1` |

Client and server/verifier integrations must use these object ids, canonical
byte strings, hashes, and domain separators as the v1 contract surface.

## Negative Cases

The shared vector defines fail-closed behavior for these mutations:

| Vector id | Mutation | Expected error |
| --- | --- | --- |
| `mldsa_missing` | Remove ML-DSA signature | `mldsa_signature_required` |
| `ed25519_missing` | Remove Ed25519 signature | `ed25519_signature_required` |
| `signed_bytes_mismatch` | ML-DSA signs different canonical bytes | `signed_bytes_mismatch` |
| `wrong_mldsa_context` | Replace ML-DSA context | `mldsa_context_mismatch` |
| `wrong_domain_separator` | Replace signed-bytes domain | `domain_separator_mismatch` |
| `wrong_public_key_length` | Truncate ML-DSA public key | `mldsa_public_key_length_invalid` |
| `wrong_signature_length` | Truncate ML-DSA signature | `mldsa_signature_length_invalid` |
| `unsupported_parameter_set` | Replace parameter set with ML-DSA-44 | `mldsa_parameter_set_unsupported` |
| `ed25519_only_outside_migration` | Remove ML-DSA without migration mode | `hybrid_auth_profile_required` |

Ed25519-only trust-state records are not accepted by the v1 hybrid-auth profile
outside documented migration mode. Migration mode must be explicit, bounded,
auditable, and unavailable as the default verifier policy.

## Consumer Coverage

The package keeps clients on the shared contract through platform tests that
load `vectors/hybrid-trust-state-v1.json` from the repository root:

| Consumer | Evidence |
| --- | --- |
| Swift client policy | `platforms/swift/Tests/PQAuthKitSwiftTests/PQAuthVectorFixtureTests.swift` checks the schema, all trust-state objects, domain separators, hashes, ML-DSA-65 lengths, nine negative cases, and disabled per-message PQ hot path. |
| Android client policy | `platforms/android/src/test/kotlin/com/pqauthkit/SharedVectorFixtureTest.kt` checks the schema, all trust-state objects, domain separators, ML-DSA-65 lengths, nine negative cases, and disabled per-message PQ hot path. |
| .NET client/verifier policy | `platforms/dotnet/tests/PQAuthKit.Tests/Program.cs` checks the schema, domain separators, five trust-state objects, nine negative cases, hash binding, and disabled per-message PQ hot path. |
| Server/verifier contract adapter | `platforms/dotnet/tests/PQAuthKit.Tests/Program.cs` loads `vectors/hybrid-trust-state-v1.json` directly, applies each vector mutation to its `basePositiveCase`, accepts all five positive trust-state objects on write/read verification paths, rejects all nine negative cases, rejects Ed25519-only downgrade outside migration mode, and fails closed with `no_approved_mldsa_provider` when approved ML-DSA support is absent. |

Server/verifier integrations must consume the same
`vectors/hybrid-trust-state-v1.json` contract and reject the same negative
cases before accepting trust-state writes, verification results, or replicated
roster/prekey/safety-number material. The package evidence now includes a
server/verifier-style adapter test that loads the vector directly instead of
copying the cases. A server-side implementation that accepts different object
ids, canonical bytes, context strings, key lengths, signature lengths,
parameter sets, or downgrade behavior is not compatible with this package gate.

## Provider Fail-Closed Evidence

Provider selection remains evidence-gated and fail closed:

- Swift/iOS: `PQAuthProviderCatalog.apple(platform: .iOS)` throws
  `.noApprovedProvider` on OS 25 without CryptoKit ML-DSA or an audited Swift
  fallback.
- Swift/macOS: `PQAuthProviderCatalog.apple(platform: .macOS)` throws
  `.noApprovedProvider` on macOS 25 without CryptoKit ML-DSA or an audited
  Swift fallback.
- Android: `AndroidProviderCatalog.default()` never selects Android 17 PQC APK
  signing for trust-state authentication and throws `no approved Android ML-DSA
  provider` when no documented app-facing provider or approved managed JVM
  fallback is available.
- Android managed fallback: `android.bouncycastle-jvm.mldsa65` is selectable
  only when audited fallback is allowed and evidence ids for conformance, audit,
  benchmark, and side-channel review are approved.
- Windows/.NET: `WindowsProviderCatalog.Default()` throws `no approved Windows
  ML-DSA provider` when `MLDsa.IsSupported` is false and no approved managed
  fallback is available.
- Fallbacks in Swift, Android, and .NET require approved gates plus concrete
  evidence ids; approved statuses without evidence do not satisfy production
  readiness.
- Native, FFI, or native-library fallback dependencies are rejected by platform
  policy tests.

## Integration Decision

Integration readiness is approved for the `pqauth-kit` package because:

- `vectors/hybrid-trust-state-v1.json` is the single shared contract for
  clients and server/verifier integrations.
- The positive object set covers account identity, device identity, roster
  publish, prekey bundle, and safety-number material.
- The negative object set covers missing ML-DSA, missing Ed25519, signed-byte
  mismatch, wrong ML-DSA context, wrong domain separator, malformed ML-DSA key
  and signature lengths, unsupported parameter set, and Ed25519-only downgrade
  outside migration mode.
- The server/verifier evidence in
  `docs/evidence/server-verifier-trust-state-integration-2026-06-04.md`
  proves direct vector loading, write-path enforcement, read-verification-path
  enforcement, downgrade rejection, and provider-unavailable fail-closed
  behavior.
- Platform policy tests keep clients aligned with the same vector and prove
  fail-closed provider selection when approved ML-DSA support is absent.
- Provider selection remains tied to readiness evidence instead of runtime
  availability alone.

Remaining risk: consuming server and application repositories still need
production storage, rollout, and migration evidence for their deployed
integrations. The direct server/verifier contract evidence is closed for the
`pqauth-kit` package gate.
