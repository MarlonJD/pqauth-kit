# Windows .NET ML-DSA-65 Side-Channel Review

Date: 2026-06-05

Provider id: `dotnet.system-security-cryptography.mldsa65`

Review id: `windows-dotnet-mldsa65-side-channel-review-2026-06-05`

Status: approved for the package-boundary side-channel gate.

## Scope

This review covers the `pqauth-kit` boundary around
`.NET System.Security.Cryptography.MLDsa` on the GitHub Actions Windows runner.
It does not audit .NET runtime provider internals and does not approve a
managed C# fallback implementation.

## Findings

- `pqauth-kit` delegates ML-DSA key generation, signing, verification, public
  key import/export, and private key import/export to .NET runtime APIs.
- The package does not add C, C++, Rust, assembly, FFI, vendored native
  libraries, dynamic native libraries, Metal/GPU acceleration, or custom
  fallback ML-DSA code for the approved Windows provider path.
- Public-key and signature length checks happen before provider verification
  where the package owns validation.
- The GitHub Actions artifact proves malformed public key and malformed
  signature rejection paths.
- The artifact stores provider-generated conformance vectors as test evidence;
  private-key fixture material is marked test-only and is not production secret
  material.
- Failure paths in package tests do not log private keys, canonical plaintext,
  raw signatures, or provider exceptions as user-visible strings.

## Evidence

- Workflow run:
  `https://github.com/MarlonJD/pqauth-kit/actions/runs/26999599786`
- Summary artifact: `dotnet-mldsa-evidence-summary.json`
- Conformance vector artifact: `dotnet-mldsa-conformance-vector.json`
- Benchmark artifact: `dotnet-mldsa-benchmark.json`

## Remaining Risk

- .NET runtime provider internals are not independently audited by this
  repository.
- GitHub Actions hosted-runner timing evidence is accepted for this checkpoint;
  pinned Windows hardware remains recommended follow-up evidence.
- Managed C# fallback remains non-production.
