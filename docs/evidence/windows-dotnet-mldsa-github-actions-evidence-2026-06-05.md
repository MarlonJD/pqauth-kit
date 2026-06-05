# Windows .NET ML-DSA GitHub Actions Evidence Path

Date: 2026-06-05

Evidence id: `windows-dotnet-mldsa-github-actions-evidence-2026-06-05`

Status: approved for the Windows .NET ML-DSA-65 package-level trust-state
profile.

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

Required benchmark file:
`dotnet-mldsa-benchmark.json`

The summary must record:

- schema `pqauth-kit-windows-dotnet-mldsa-ci-evidence-v1`
- provider id `dotnet.system-security-cryptography.mldsa65`
- `mldsaIsSupported=true`
- `conformanceVectorGenerated=true`
- `benchmarkGenerated=true`
- provider-backed trust-state objects:
  - `account_identity`
  - `device_identity`
  - `roster_publish`
  - `prekey_bundle`
  - `safety_number`

## Approved Artifact

Remote run `26999599786` was downloaded and inspected on 2026-06-05.

Run metadata:

- URL: `https://github.com/MarlonJD/pqauth-kit/actions/runs/26999599786`
- Head SHA: `24b700aa152ae446f9327ee3fef6a3a2df00baf6`
- Event: `push`
- Conclusion: `success`
- Runner OS: Windows x64, `ImageOS=win25`,
  `ImageVersion=20260525.149.1`
- .NET SDK: `10.0.300`
- .NET runtime host: `10.0.8`, commit `94ea82652c`

Approved artifact contents:

- `dotnet-mldsa-evidence-summary.json`
  - `mldsaIsSupported=true`
  - `conformanceVectorGenerated=true`
  - `benchmarkGenerated=true`
  - provider-backed trust-state objects:
    `account_identity`, `device_identity`, `roster_publish`,
    `prekey_bundle`, and `safety_number`
- `dotnet-mldsa-conformance-vector.json`
  - schema `pqauth-kit-mldsa-conformance-v1`
  - five provider-backed cases
  - operations: keygen, sign, verify, public-key export, private-key export,
    public-key import, private-key import, signed-bytes mismatch rejection,
    wrong-context rejection, malformed public-key rejection, and malformed
    signature rejection
- `dotnet-mldsa-benchmark.json`
  - schema `pqauth-kit-benchmark-evidence-v1`
  - report id `windows-dotnet-mldsa65-github-actions-benchmark-2026-06-05`
  - operations: keygen, sign, verify, public-key export, private-key export,
    private-key import, malformed public-key rejection, and malformed
    signature rejection

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

This evidence path approves the Windows .NET provider runtime/conformance and
hosted-runner benchmark gate for the package-level trust-state profile.

This does not approve Apple iOS, Swift fallback, C# fallback, consuming
repository storage, rollout, telemetry, or release decisions.
