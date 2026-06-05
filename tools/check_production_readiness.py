#!/usr/bin/env python3
"""Validate pqauth-kit scoped production-readiness evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_OBJECTS = {
    "account_identity",
    "device_identity",
    "roster_publish",
    "prekey_bundle",
    "safety_number",
}

REQUIRED_NEGATIVE_CASES = {
    "mldsa_missing",
    "ed25519_missing",
    "signed_bytes_mismatch",
    "wrong_mldsa_context",
    "wrong_domain_separator",
    "wrong_public_key_length",
    "wrong_signature_length",
    "unsupported_parameter_set",
    "ed25519_only_outside_migration",
}

REQUIRED_PROVIDER_EVIDENCE = {
    "providerSourceId",
    "providerVersion",
    "license",
    "conformanceVectorId",
    "auditReportId",
    "benchmarkReportId",
    "sideChannelReviewId",
}

APPROVED_PROFILE_EVIDENCE = {
    "providerConformanceVector",
    "providerBackedTrustStateProfileTest",
    "providerBackedTrustStateProfileEvidence",
    "auditReport",
    "benchmarkReport",
    "sideChannelReview",
}

REQUIRED_WINDOWS_CI_PROFILE_ID = "windows-dotnet-mldsa65-github-actions-evidence"


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        raise ValueError(f"path must be package-relative: {value}")
    return PACKAGE_ROOT / path


def provider_by_id(readiness: dict) -> dict[str, dict]:
    providers = readiness.get("providers")
    if not isinstance(providers, list):
        raise ValueError("readiness manifest providers must be a list")
    return {provider.get("providerId"): provider for provider in providers}


def validate_structural_vector(manifest: dict, errors: list[str]) -> None:
    vector_path = relative_path(manifest["structuralTrustStateVector"])
    if not vector_path.exists():
        errors.append(f"missing structural vector: {vector_path}")
        return

    vector = load_json(vector_path)
    if not isinstance(vector, dict):
        errors.append("structural vector must be a JSON object")
        return
    if vector.get("schema") != "pqauth-kit-hybrid-trust-state-v1":
        errors.append("structural vector schema mismatch")
    if vector.get("fixtureKind") != "structural-non-cryptographic":
        errors.append("structural vector must not be labeled cryptographic")
    if vector.get("policy") != "ed25519_and_mldsa_required":
        errors.append("structural vector must require Ed25519 and ML-DSA")

    positives = vector.get("positiveCases", [])
    positive_objects = {entry.get("trustStateObject") for entry in positives}
    if positive_objects != REQUIRED_OBJECTS:
        errors.append(f"structural vector trust-state objects mismatch: {sorted(positive_objects)}")

    negatives = vector.get("negativeCases", [])
    negative_ids = {entry.get("id") for entry in negatives}
    if negative_ids != REQUIRED_NEGATIVE_CASES:
        errors.append(f"structural vector negative cases mismatch: {sorted(negative_ids)}")

    hot_path = vector.get("defaultMessageHotPath", {})
    if hot_path.get("perMessagePQSignaturesEnabled") is not False:
        errors.append("default message hot path must keep per-message PQ signatures disabled")


def validate_readiness_manifest(manifest: dict, errors: list[str]) -> dict[str, dict]:
    readiness_path = relative_path(manifest["readinessGateManifest"])
    if not readiness_path.exists():
        errors.append(f"missing readiness gate manifest: {readiness_path}")
        return {}

    readiness = load_json(readiness_path)
    if not isinstance(readiness, dict):
        errors.append("readiness gate manifest must be a JSON object")
        return {}
    if readiness.get("schema") != "pqauth-kit-readiness-gates-v1":
        errors.append("readiness gate manifest schema mismatch")

    providers = provider_by_id(readiness)
    for provider_id, provider in providers.items():
        if provider.get("productionReady") is True:
            missing = sorted(
                field for field in REQUIRED_PROVIDER_EVIDENCE if not provider.get(field)
            )
            if missing:
                errors.append(f"{provider_id} is productionReady but lacks {missing}")
            if provider.get("usesCOrFFI") is True or provider.get("nativeLibraryDependency") is True:
                errors.append(f"{provider_id} is productionReady but declares native dependency risk")
    return providers


def validate_approved_profiles(
    manifest: dict,
    providers: dict[str, dict],
    errors: list[str],
) -> None:
    profiles = manifest.get("productionProfiles", [])
    if not profiles:
        errors.append("at least one scoped production profile must be declared")
        return

    for profile in profiles:
        profile_id = profile.get("id", "<missing id>")
        if profile.get("status") != "approved":
            errors.append(f"{profile_id} production profile must be approved or moved to blockedProfiles")
        if profile.get("approvalClaim") is not True:
            errors.append(f"{profile_id} approved profile must set approvalClaim=true")

        provider_id = profile.get("providerId")
        provider = providers.get(provider_id)
        if provider is None:
            errors.append(f"{profile_id} references unknown provider {provider_id}")
        elif provider.get("productionReady") is not True:
            errors.append(f"{profile_id} references provider {provider_id} that is not productionReady")

        objects = set(profile.get("providerBackedTrustStateObjects", []))
        if objects != REQUIRED_OBJECTS:
            errors.append(f"{profile_id} must cover all trust-state objects, got {sorted(objects)}")

        evidence = profile.get("evidence", {})
        missing_evidence = sorted(key for key in APPROVED_PROFILE_EVIDENCE if not evidence.get(key))
        if missing_evidence:
            errors.append(f"{profile_id} lacks evidence fields {missing_evidence}")
        for key in APPROVED_PROFILE_EVIDENCE:
            if key in evidence and not relative_path(evidence[key]).exists():
                errors.append(f"{profile_id} missing evidence file for {key}: {evidence[key]}")

        test_path = evidence.get("providerBackedTrustStateProfileTest")
        if test_path:
            validate_profile_test(profile_id, relative_path(test_path), errors)


def validate_profile_test(profile_id: str, test_path: Path, errors: list[str]) -> None:
    if not test_path.exists():
        errors.append(f"{profile_id} missing provider-backed test: {test_path}")
        return

    contents = test_path.read_text(encoding="utf-8")
    if profile_id.startswith("apple-cryptokit"):
        required_fragments = [
            "CryptoKitMLDSA65Provider",
            "generateKeyPair",
            "sign",
            "verify",
            "hybrid-trust-state-v1.json",
            "PQAuthTrustStateObject.allCases",
        ]
    else:
        required_fragments = [
            "MLDSA65.generateKeyPair",
            "MLDSA65.sign",
            "MLDSA65.verify",
            "DeterministicTestEntropySource",
            "hybrid-trust-state-v1.json",
        ]
    for fragment in required_fragments:
        if fragment not in contents:
            errors.append(f"{profile_id} test missing fragment {fragment!r}")
    if "PQAuthTrustStateObject.entries" not in contents:
        for trust_state_object in REQUIRED_OBJECTS:
            if trust_state_object not in contents:
                errors.append(f"{profile_id} test does not reference {trust_state_object}")


def validate_blocked_profiles(manifest: dict, errors: list[str]) -> None:
    blocked = manifest.get("blockedProfiles", [])
    blocked_by_id = {profile.get("id"): profile for profile in blocked}
    required_blocked = {
        "all-supported-platforms-trust-state-v1",
        "apple-cryptokit-mldsa65-trust-state-v1",
        "windows-dotnet-mldsa65-trust-state-v1",
    }
    missing = required_blocked - set(blocked_by_id)
    if missing:
        errors.append(f"missing blocked profiles: {sorted(missing)}")

    for profile in blocked:
        profile_id = profile.get("id", "<missing id>")
        if profile.get("status") != "blocked":
            errors.append(f"{profile_id} blocked profile must have status=blocked")
        if profile.get("approvalClaim") is not False:
            errors.append(f"{profile_id} blocked profile must set approvalClaim=false")
        if not profile.get("blockedOn"):
            errors.append(f"{profile_id} blocked profile must list blockers")


def validate_ci_evidence_profiles(manifest: dict, errors: list[str]) -> None:
    profiles = manifest.get("ciEvidenceProfiles", [])
    by_id = {profile.get("id"): profile for profile in profiles}
    profile = by_id.get(REQUIRED_WINDOWS_CI_PROFILE_ID)
    if profile is None:
        errors.append(f"missing CI evidence profile: {REQUIRED_WINDOWS_CI_PROFILE_ID}")
        return

    if profile.get("status") != "pending_ci_artifact":
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} must remain pending_ci_artifact until an artifact is linked")
    if profile.get("approvalClaim") is not False:
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} must not make an approval claim before artifact review")

    workflow = profile.get("workflow")
    if not workflow:
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} must name a workflow")
    else:
        workflow_path = relative_path(workflow)
        if not workflow_path.exists():
            errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} workflow is missing: {workflow}")
        else:
            workflow_text = workflow_path.read_text(encoding="utf-8")
            required_workflow_fragments = [
                "runs-on: windows-latest",
                "actions/setup-dotnet@v5",
                "dotnet-version: \"10.0.x\"",
                "--emit-conformance-vector",
                "windows-dotnet-mldsa-evidence",
                "dotnet-mldsa-evidence-summary.json",
                "dotnet-mldsa-conformance-vector.json",
                "providerBackedTrustStateObjects",
            ]
            for fragment in required_workflow_fragments:
                if fragment not in workflow_text:
                    errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} workflow missing {fragment!r}")

    if profile.get("artifactName") != "windows-dotnet-mldsa-evidence":
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} artifactName mismatch")
    if profile.get("summaryArtifact") != "dotnet-mldsa-evidence-summary.json":
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} summaryArtifact mismatch")
    if profile.get("conformanceVectorArtifact") != "dotnet-mldsa-conformance-vector.json":
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} conformanceVectorArtifact mismatch")

    required_summary = profile.get("requiredSummary", {})
    if required_summary.get("schema") != "pqauth-kit-windows-dotnet-mldsa-ci-evidence-v1":
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} required summary schema mismatch")
    if required_summary.get("mldsaIsSupported") is not True:
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} must require mldsaIsSupported=true")
    if required_summary.get("conformanceVectorGenerated") is not True:
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} must require conformanceVectorGenerated=true")
    if set(required_summary.get("providerBackedTrustStateObjects", [])) != REQUIRED_OBJECTS:
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} required trust-state objects mismatch")

    evidence_doc = profile.get("evidenceDocument")
    if not evidence_doc:
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} must name an evidence document")
    elif not relative_path(evidence_doc).exists():
        errors.append(f"{REQUIRED_WINDOWS_CI_PROFILE_ID} evidence document is missing: {evidence_doc}")


def validate_manifest(path: Path) -> list[str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict):
        return ["production readiness manifest must be a JSON object"]

    errors: list[str] = []
    if manifest.get("schema") != "pqauth-kit-production-readiness-v1":
        errors.append("production readiness schema mismatch")
    if manifest.get("overallPackageStatus") != "scoped_production_ready":
        errors.append("overallPackageStatus must remain scoped_production_ready")

    if set(manifest.get("requiredTrustStateObjects", [])) != REQUIRED_OBJECTS:
        errors.append("requiredTrustStateObjects mismatch")
    if set(manifest.get("requiredNegativeCases", [])) != REQUIRED_NEGATIVE_CASES:
        errors.append("requiredNegativeCases mismatch")

    validate_structural_vector(manifest, errors)
    providers = validate_readiness_manifest(manifest, errors)
    validate_approved_profiles(manifest, providers, errors)
    validate_ci_evidence_profiles(manifest, errors)
    validate_blocked_profiles(manifest, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="docs/evidence/production-readiness-v1.json",
        help="Package-relative production readiness manifest path.",
    )
    args = parser.parse_args()

    try:
        manifest_path = relative_path(args.manifest)
        errors = validate_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001 - checker should return actionable failure text.
        errors = [str(exc)]

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("PASS: pqauth-kit scoped production readiness evidence is internally consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
