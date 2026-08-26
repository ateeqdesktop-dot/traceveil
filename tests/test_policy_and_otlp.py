from __future__ import annotations

import pytest

from traceveil.otlp import ensure_otlp_shape, unwrap_any_value, wrap_like_any_value
from traceveil.policy import Policy, PolicyError


def test_policy_mapping_supports_guarded_keys_and_normalized_digest() -> None:
    policy = Policy.from_mapping(
        {
            "policy": {"name": "test-policy", "version": "2", "mode": "fail-closed"},
            "guards": {"key_patterns": ["*authorization*"], "action": "drop"},
            "rules": [
                {
                    "id": "emails",
                    "kinds": ["email"],
                    "paths": ["gen_ai.*"],
                    "action": "redact",
                    "severity": "high",
                }
            ],
        }
    )

    rule = policy.rule_for("gen_ai.input.messages", "email")
    assert rule is not None and rule.id == "emails"
    assert policy.is_guarded_key("http.request.header.authorization")
    assert policy.digest == policy.digest
    assert policy.normalized()["policy"]["name"] == "test-policy"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"policy": {"mode": "unexpected"}}, "policy.mode"),
        ({"policy": {"mode": "fail-closed"}, "rules": []}, "require at least one"),
        (
            {"policy": {"mode": "fail-closed"}, "rules": [{"id": "bad", "kinds": ["unknown"]}]},
            "unsupported detector",
        ),
    ],
)
def test_policy_rejects_ambiguous_or_unsupported_configuration(document: dict, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        Policy.from_mapping(document)


def test_otlp_anyvalue_helpers_preserve_common_shapes() -> None:
    original = {"arrayValue": {"values": [{"stringValue": "one"}, {"intValue": "2"}]}}
    assert unwrap_any_value(original) == ["one", "2"]
    assert wrap_like_any_value(original, ["safe", "3"]) == {
        "arrayValue": {"values": [{"stringValue": "safe"}, {"intValue": "3"}]}
    }

    kvlist = {
        "kvlistValue": {
            "values": [
                {"key": "email", "value": {"stringValue": "alice@example.com"}},
                {"key": "count", "value": {"intValue": "1"}},
            ]
        }
    }
    replaced = wrap_like_any_value(kvlist, {"email": "[REDACTED]", "count": "1"})
    assert unwrap_any_value(replaced) == {"email": "[REDACTED]", "count": "1"}


def test_otlp_shape_rejects_non_otlp_input() -> None:
    with pytest.raises(ValueError, match="resourceSpans"):
        ensure_otlp_shape({"spans": []})
