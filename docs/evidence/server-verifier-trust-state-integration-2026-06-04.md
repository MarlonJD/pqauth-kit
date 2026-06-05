# Server/Verifier Trust-State Integration Evidence

Date: 2026-06-04

Evidence id: `server-verifier-trust-state-integration-2026-06-04`

Status: approved for downstream server/verifier contract integration evidence.

## Scope

This evidence proves that a downstream server/verifier-style consumer loads the
`pqauth-kit` hybrid trust-state v1 vector directly and enforces the same
fail-closed contract for trust-state writes and verification reads.

The executable evidence is in
`platforms/dotnet/tests/PQAuthKit.Tests/Program.cs`. The test loads
`vectors/hybrid-trust-state-v1.json` from the package root, parses the positive
and negative cases from that JSON, and applies each negative mutation from the
shared vector's `basePositiveCase`. The cases are not copied into the test.

This remains structural contract evidence. Provider-backed cryptographic
signature evidence remains in the ML-DSA conformance vectors, and production
storage/deployment rollout evidence belongs to the consuming backend release.

## Shared Contract

The shared server/verifier contract is `vectors/hybrid-trust-state-v1.json`.

Contract properties enforced by the test:

- Schema: `pqauth-kit-hybrid-trust-state-v1`
- Policy: `ed25519_and_mldsa_required`
- Fixture kind: `structural-non-cryptographic`
- Default ML-DSA parameter set: `ML-DSA-65`
- Direct vector load: true

## Positive Trust-State Objects

The server/verifier contract accepts these positive cases for both write and
read verification paths when an approved ML-DSA provider is available:

| Object | Vector id | Domain separator |
| --- | --- | --- |
| Account identity | `account_identity` | `pqauth-kit-account-identity-hybrid-auth-v1` |
| Device identity | `device_identity` | `pqauth-kit-device-identity-hybrid-auth-v1` |
| Roster publish | `roster_publish` | `pqauth-kit-device-roster-hybrid-auth-v1` |
| Prekey bundle | `prekey_bundle` | `pqauth-kit-ratchet-prekey-bundle-hybrid-auth-v1` |
| Safety-number material | `safety_number` | `pqauth-kit-safety-number-hybrid-auth-v1` |

## Fail-Closed Negative Cases

The server/verifier contract rejects the shared negative vectors on both write
and read verification paths:

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

Ed25519-only downgrade is rejected outside explicit documented migration mode.
Migration mode is not the default server/verifier policy.

## Provider Fail-Closed Check

Provider selection remains fail closed. The server/verifier evidence test
sets `ApprovedMldsaProviderAvailable` to false for a positive trust-state case
and requires `no_approved_mldsa_provider` before the write or verification path
can accept the object.

## Verification

Command:

```bash
cd platforms/dotnet && DOTNET_CLI_HOME=/private/tmp dotnet test
```

Evidence test:

- `validates downstream server verifier contract evidence`

## Integration Decision

Downstream server/verifier contract evidence is approved for the `pqauth-kit`
package gate because the consuming-style test loads the shared vector directly,
accepts all five positive trust-state objects, rejects all nine negative cases,
rejects Ed25519-only downgrade outside migration mode, and fails closed when no
approved ML-DSA provider is available.
