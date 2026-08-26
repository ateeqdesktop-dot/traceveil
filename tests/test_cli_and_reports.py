from __future__ import annotations

import json
from pathlib import Path

from traceveil.cli import main
from traceveil.policy import Policy
from traceveil.reports import junit_xml, sarif_report
from traceveil.sanitizer import sanitize_otlp_payload


FIXTURE = Path(__file__).parent / "fixtures" / "agent-trace.json"


def test_reports_are_standard_shape_without_raw_content() -> None:
    result = sanitize_otlp_payload(json.loads(FIXTURE.read_text()), Policy.default())
    sarif = sarif_report(result)
    junit = junit_xml(result).decode("utf-8")

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert "ghp_abcdefghijklmnopqrstuvwx" not in json.dumps(sarif)
    assert "Raw content is intentionally not included" in junit


def test_cli_sanitize_and_verify(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "sanitized.json"
    evidence_path = tmp_path / "evidence.json"
    sarif_path = tmp_path / "findings.sarif"
    junit_path = tmp_path / "findings.xml"
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "public.key"
    input_path.write_text(FIXTURE.read_text(), encoding="utf-8")

    assert main(["keygen", "--private-key", str(private_path), "--public-key", str(public_path)]) == 0
    assert (
        main(
            [
                "sanitize",
                str(input_path),
                "--out",
                str(output_path),
                "--evidence",
                str(evidence_path),
                "--sarif",
                str(sarif_path),
                "--junit",
                str(junit_path),
                "--private-key",
                str(private_path),
            ]
        )
        == 0
    )
    assert main(["verify", "--evidence", str(evidence_path), "--sanitized", str(output_path), "--public-key", str(public_path)]) == 0
    assert output_path.exists() and evidence_path.exists() and sarif_path.exists() and junit_path.exists()
