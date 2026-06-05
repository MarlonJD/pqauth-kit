# Windows .NET ML-DSA GitHub Actions Evidence Path

Date: 2026-06-05

Evidence id: `windows-dotnet-mldsa-github-actions-evidence-2026-06-05`

Status: pending CI artifact.

## Owner Decision

Hosted GitHub Actions `windows-latest` runner evidence is accepted for the
Windows `.NET System.Security.Cryptography.MLDsa` package-level runtime support
and trust-state conformance gate. A separate pinned Windows release device or
VM is not required for this checkpoint.

## Required Workflow

Workflow:
`.github/workflows/windows-dotnet-mldsa-evidence.yml`

Required artifact:
`windows-dotnet-mldsa-evidence`

Required summary file:
`dotnet-mldsa-evidence-summary.json`

Required conformance vector file:
`dotnet-mldsa-conformance-vector.json`

The summary must record:

- schema `pqauth-kit-windows-dotnet-mldsa-ci-evidence-v1`
- provider id `dotnet.system-security-cryptography.mldsa65`
- `mldsaIsSupported=true`
- `conformanceVectorGenerated=true`
- provider-backed trust-state objects:
  - `account_identity`
  - `device_identity`
  - `roster_publish`
  - `prekey_bundle`
  - `safety_number`

## Reviewed Artifact

Existing remote run `26971937181` was downloaded and inspected on 2026-06-05.
It is not accepted for this gate even though the workflow concluded
successfully, because the artifact predates the five-object evidence
requirement.

Observed artifact:

- `dotnet-mldsa-evidence-summary.json` records `mldsaIsSupported=true`.
- `dotnet-mldsa-evidence-summary.json` does not include
  `providerBackedTrustStateObjects`.
- `dotnet-mldsa-conformance-vector.json` contains one provider-backed case:
  `device_identity`.
- The required set is all five trust-state objects:
  `account_identity`, `device_identity`, `roster_publish`, `prekey_bundle`,
  and `safety_number`.

The current workflow and test harness require all five provider-backed cases
before the artifact can be accepted.

## Boundary

This evidence path can approve the Windows .NET provider runtime/conformance
gate only after a successful GitHub Actions run uploads the required artifact.
Until then, `windows-dotnet-mldsa65-trust-state-v1` remains blocked.

This does not approve Apple, Swift fallback, C# fallback, consuming repository
storage, rollout, telemetry, or release decisions.
