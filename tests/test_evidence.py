from __future__ import annotations

import json
from pathlib import Path

import pytest

from traceveil.canonical import atomic_write_json, sha256_file
from traceveil.evidence import VerificationError, create_evidence, generate_keypair, verify_evidence
from traceveil.policy import Policy
from traceveil.sanitizer import sanitize_otlp_payload


FIXTURE = Path(__file__).parent / "fixtures" / "agent-trace.json"


def fixture_payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_signed_evidence_verifies_and_tampering_fails(tmp_path: Path) -> None:
    result = sanitize_otlp_payload(fixture_payload(), Policy.default())
    sanitized_path = tmp_path / "sanitized.json"
    atomic_write_json(sanitized_path, result.sanitized)
    private, public = generate_keypair()
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "public.key"
    private_path.write_text(private + "\n", encoding="utf-8")
    public_path.write_text(public + "\n", encoding="utf-8")

    evidence = create_evidence(
        result,
        sanitized_name=sanitized_path.name,
        sanitized_file_digest=sha256_file(sanitized_path),
        private_key_path=private_path,
    )
    verified = verify_evidence(evidence, sanitized_path=sanitized_path, public_key_path=public_path)

    assert verified["verified"] is True
    assert verified["signature_checked"] is True

    sanitized_path.write_text("{}", encoding="utf-8")
    with pytest.raises(VerificationError, match="digest"):
        verify_evidence(evidence, sanitized_path=sanitized_path, public_key_path=public_path)

