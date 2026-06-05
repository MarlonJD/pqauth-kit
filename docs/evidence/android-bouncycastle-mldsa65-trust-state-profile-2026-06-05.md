# Android Bouncy Castle ML-DSA-65 Trust-State Profile Evidence

Date: 2026-06-05

Evidence id: `android-bouncycastle-mldsa65-trust-state-profile-2026-06-05`

Status: approved for the scoped package profile
`android-bouncycastle-jvm-mldsa65-trust-state-v1`.

## Scope

This evidence proves that the managed JVM Bouncy Castle ML-DSA-65 provider path
can sign and verify every required trust-state object in
`vectors/hybrid-trust-state-v1.json`.

The executable test is
`platforms/android/src/test/kotlin/com/pqauthkit/mldsa/MLDSA65TrustStateProfileTest.kt`.
It loads the shared structural trust-state vector, extracts the canonical bytes
for all five positive cases, generates provider-backed ML-DSA-65 keys through
`MLDSA65.generateKeyPair`, signs each canonical byte string with the matching
domain context, verifies each signature, and rejects wrong bytes, wrong
context, malformed public keys, and malformed signatures.

The checked objects are:

- `account_identity`
- `device_identity`
- `roster_publish`
- `prekey_bundle`
- `safety_number`

## Boundary

This is package-level provider-backed trust-state evidence for the Android
managed JVM fallback. It does not approve Apple, Windows, Swift fallback, C#
fallback, consumer storage, deployment migration, rollout, telemetry, or final
release decisions.

Deterministic entropy in the test is test-only and remains blocked for
production API use by `DeterministicTestEntropySource`.

## Verification

```bash
cd platforms/android && ./gradlew test --tests com.pqauthkit.mldsa.MLDSA65TrustStateProfileTest
cd platforms/android && ./gradlew test
python3 tools/check_production_readiness.py --manifest docs/evidence/production-readiness-v1.json
```
