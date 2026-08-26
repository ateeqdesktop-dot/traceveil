from __future__ import annotations

import copy
import json
from pathlib import Path

from traceveil.policy import Policy
from traceveil.sanitizer import sanitize_otlp_payload


FIXTURE = Path(__file__).parent / "fixtures" / "agent-trace.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def attributes(payload: dict) -> dict[str, str]:
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    return {item["key"]: item["value"]["stringValue"] for item in span["attributes"]}


def test_sanitizes_nested_genai_messages_and_guarded_headers() -> None:
    raw = load_fixture()
    original = copy.deepcopy(raw)
    result = sanitize_otlp_payload(raw, Policy.default())
    sanitized = attributes(result.sanitized)

    assert sanitized["gen_ai.output.messages"] == "The safe response is ready."
    assert "alice@example.com" not in sanitized["gen_ai.input.messages"]
    assert "ghp_abcdefghijklmnopqrstuvwx" not in sanitized["gen_ai.input.messages"]
    assert "deeplySensitiveToken12345" not in sanitized["http.request.header.authorization"]
    assert "TRACEVEIL" in sanitized["gen_ai.input.messages"]
    assert "GUARDED_KEY" in sanitized["http.request.header.authorization"]
    assert raw == original, "sanitization must not mutate the caller's payload"


def test_decisions_and_evidence_metadata_do_not_include_raw_values() -> None:
    result = sanitize_otlp_payload(load_fixture(), Policy.default())
    serialized = json.dumps(result.public_decisions(), ensure_ascii=False)

    assert result.summary()["findings"] >= 3
    assert "ghp_abcdefghijklmnopqrstuvwx" not in serialized
    assert "alice@example.com" not in serialized
    assert all(item.location.startswith("traces/") for item in result.decisions)
    assert result.input_digest != result.output_digest


def test_is_deterministic() -> None:
    left = sanitize_otlp_payload(load_fixture(), Policy.default())
    right = sanitize_otlp_payload(load_fixture(), Policy.default())

    assert left.sanitized == right.sanitized
    assert left.public_decisions() == right.public_decisions()
    assert left.output_digest == right.output_digest

