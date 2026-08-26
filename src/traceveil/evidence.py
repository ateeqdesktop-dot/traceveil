"""Portable TraceVeil evidence artifacts and optional Ed25519 signatures."""

from __future__ import annotations

import base64
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json_bytes, sha256_file, sha256_json
from .sanitizer import SanitizationResult

PREDICATE_TYPE = "https://traceveil.dev/attestation/privacy-policy/v0.1"
SCHEMA_VERSION = "https://traceveil.dev/evidence/v0.1"


class VerificationError(ValueError):
    """Raised if an evidence artifact cannot be independently verified."""


def _read_key(path: str | Path) -> bytes:
    return base64.b64decode(Path(path).read_text(encoding="utf-8").strip().encode("ascii"), validate=True)


def generate_keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_bytes).decode("ascii"),
        base64.b64encode(public_bytes).decode("ascii"),
    )


def _sign(unsigned_evidence: dict[str, Any], private_key_path: str | Path) -> dict[str, str]:
    private = Ed25519PrivateKey.from_private_bytes(_read_key(private_key_path))
    signature = private.sign(canonical_json_bytes(unsigned_evidence))
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "algorithm": "ed25519",
        "public_key": base64.b64encode(public).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def create_evidence(
    result: SanitizationResult,
    *,
    sanitized_name: str,
    sanitized_file_digest: str,
    private_key_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create a stable evidence statement that never carries raw values."""

    evidence: dict[str, Any] = {
        "_type": SCHEMA_VERSION,
        "predicateType": PREDICATE_TYPE,
        "subject": [{"name": sanitized_name, "digest": {"sha256": sanitized_file_digest}}],
        "predicate": {
            "policy": {"sha256": result.policy_digest},
            "input": {"sha256": result.input_digest},
            "sanitized_payload": {"sha256": result.output_digest},
            "decision_summary": result.summary(),
            "decisions": result.public_decisions(),
            "engine": {"name": "traceveil", "version": "0.1.0", "deterministic": True},
        },
    }
    if private_key_path:
        evidence["signature"] = _sign(evidence, private_key_path)
    evidence["evidence_sha256"] = sha256_json(evidence)
    return evidence


def verify_evidence(
    evidence: dict[str, Any], *, sanitized_path: str | Path, public_key_path: str | Path | None = None
) -> dict[str, Any]:
    """Verify both artifact integrity and the optional evidence signature."""

    if evidence.get("_type") != SCHEMA_VERSION or evidence.get("predicateType") != PREDICATE_TYPE:
        raise VerificationError("Unsupported TraceVeil evidence schema")

    subjects = evidence.get("subject", [])
    if len(subjects) != 1 or "sha256" not in subjects[0].get("digest", {}):
        raise VerificationError("Evidence must contain exactly one SHA-256 subject")
    expected_file_digest = subjects[0]["digest"]["sha256"]
    actual_file_digest = sha256_file(sanitized_path)
    if expected_file_digest != actual_file_digest:
        raise VerificationError("Sanitized artifact digest does not match evidence subject")

    checked_signature = False
    signature = evidence.get("signature")
    if signature:
        if signature.get("algorithm") != "ed25519":
            raise VerificationError("Unsupported signature algorithm")
        public_bytes = _read_key(public_key_path) if public_key_path else base64.b64decode(signature["public_key"])
        unsigned = {key: value for key, value in evidence.items() if key not in {"signature", "evidence_sha256"}}
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                base64.b64decode(signature["signature"]), canonical_json_bytes(unsigned)
            )
        except (InvalidSignature, ValueError) as error:
            raise VerificationError("Evidence signature is invalid") from error
        checked_signature = True

    stored_evidence_digest = evidence.get("evidence_sha256")
    if stored_evidence_digest:
        reconstructed = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
        if stored_evidence_digest != sha256_json(reconstructed):
            raise VerificationError("Evidence digest is invalid")

    return {
        "verified": True,
        "sanitized_artifact_sha256": actual_file_digest,
        "signature_checked": checked_signature,
        "findings": evidence["predicate"]["decision_summary"]["findings"],
    }


def decisions_as_json(result: SanitizationResult) -> list[dict[str, Any]]:
    return [asdict(decision) for decision in result.decisions]

