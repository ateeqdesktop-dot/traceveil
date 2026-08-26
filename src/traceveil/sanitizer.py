"""The local, deterministic sanitization engine."""

from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .canonical import sha256_json
from .detectors import Match, detect
from .otlp import attribute_path, ensure_otlp_shape, iter_spans, unwrap_any_value, wrap_like_any_value
from .policy import Policy


@dataclass(frozen=True, slots=True)
class Decision:
    rule_id: str
    action: str
    kind: str
    severity: str
    attribute_key: str
    location: str
    trace_id: str
    span_id: str
    matches: int
    original_characters: int
    replacement_characters: int


@dataclass(slots=True)
class SanitizationResult:
    sanitized: dict[str, Any]
    decisions: list[Decision] = field(default_factory=list)
    input_digest: str = ""
    output_digest: str = ""
    policy_digest: str = ""

    @property
    def counts_by_kind(self) -> dict[str, int]:
        return dict(sorted(Counter(item.kind for item in self.decisions).items()))

    @property
    def counts_by_severity(self) -> dict[str, int]:
        return dict(sorted(Counter(item.severity for item in self.decisions).items()))

    @property
    def counts_by_action(self) -> dict[str, int]:
        return dict(sorted(Counter(item.action for item in self.decisions).items()))

    def summary(self) -> dict[str, Any]:
        return {
            "findings": len(self.decisions),
            "by_kind": self.counts_by_kind,
            "by_severity": self.counts_by_severity,
            "by_action": self.counts_by_action,
        }

    def public_decisions(self) -> list[dict[str, Any]]:
        return [asdict(item) for item in self.decisions]


def _placeholder(kind: str, value: str) -> str:
    # The fragment is derived from the secret but never persisted in evidence.
    # It allows a reviewer of the sanitized trace to see repeat occurrences in
    # one run without making the complete raw value available.
    return f"[TRACEVEIL:{kind.upper()}:{sha256_json({'v': value})[:10]}]"


def _replace_matches(value: str, matches: list[Match], action: str) -> str:
    if action == "drop":
        return ""
    if action == "hash":
        return sha256_json({"value": value})
    fragments: list[str] = []
    cursor = 0
    for found in matches:
        fragments.append(value[cursor : found.start])
        fragments.append(_placeholder(found.kind, found.value))
        cursor = found.end
    fragments.append(value[cursor:])
    return "".join(fragments)


def _sanitize_json_like(value: Any, attribute_key: str, policy: Policy) -> tuple[Any, list[tuple[Match, str, str]]]:
    """Recursively sanitize strings, preserving JSON structures when possible."""

    findings: list[tuple[Match, str, str]] = []
    if isinstance(value, str):
        matches = detect(value, (kind for rule in policy.rules for kind in rule.kinds))
        applicable: list[tuple[Match, str, str]] = []
        for found in matches:
            rule = policy.rule_for(attribute_key, found.kind)
            if rule:
                applicable.append((found, rule.action, rule.id))
        if not applicable:
            return value, findings
        # One field may contain findings from rules with different actions.
        # Apply longest-leftmost findings grouped by action, with redaction
        # winning over hash and drop for predictable fail-closed behavior.
        action_rank = {"redact": 3, "drop": 2, "hash": 1}
        selected_action = max((item[1] for item in applicable), key=lambda action: action_rank[action])
        selected = [item[0] for item in applicable]
        findings.extend(applicable)
        return _replace_matches(value, selected, selected_action), findings
    if isinstance(value, list):
        sanitized: list[Any] = []
        for item in value:
            next_item, item_findings = _sanitize_json_like(item, attribute_key, policy)
            sanitized.append(next_item)
            findings.extend(item_findings)
        return sanitized, findings
    if isinstance(value, dict):
        sanitized_dict: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{attribute_key}.{key}"
            next_item, item_findings = _sanitize_json_like(item, child_path, policy)
            sanitized_dict[key] = next_item
            findings.extend(item_findings)
        return sanitized_dict, findings
    return value, findings


def _sanitize_attribute_value(value: Any, attribute_key: str, policy: Policy) -> tuple[Any, list[tuple[Match, str, str]]]:
    if policy.is_guarded_key(attribute_key):
        marker = _placeholder("guarded_key", attribute_key)
        pseudo = Match("guarded_key", 0, 0, "")
        return marker if policy.guarded_key_action != "drop" else "", [(pseudo, policy.guarded_key_action, "guarded-key")]

    # Attributes such as gen_ai.input.messages are often JSON encoded as a string.
    # Preserve useful structure when it is valid JSON, otherwise inspect the text.
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return _sanitize_json_like(value, attribute_key, policy)
        sanitized, findings = _sanitize_json_like(decoded, attribute_key, policy)
        if findings:
            return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":")), findings
        return value, findings
    return _sanitize_json_like(value, attribute_key, policy)


def sanitize_otlp_payload(payload: dict[str, Any], policy: Policy) -> SanitizationResult:
    """Sanitize OTLP JSON in memory and return decision metadata without raw values."""

    original = ensure_otlp_shape(payload)
    sanitized = copy.deepcopy(original)
    result = SanitizationResult(
        sanitized=sanitized,
        input_digest=sha256_json(original),
        policy_digest=policy.digest,
    )

    for span, trace_id, span_id in iter_spans(sanitized):
        attributes = span.get("attributes", [])
        if not isinstance(attributes, list):
            continue
        for index, attribute in enumerate(attributes):
            if not isinstance(attribute, dict) or not isinstance(attribute.get("key"), str):
                continue
            key = attribute["key"]
            original_any_value = attribute.get("value", {})
            unwrapped = unwrap_any_value(original_any_value)
            replacement, findings = _sanitize_attribute_value(unwrapped, key, policy)
            if not findings:
                continue
            attribute["value"] = wrap_like_any_value(original_any_value, replacement)

            grouped: dict[tuple[str, str, str, str], list[Match]] = {}
            for found, action, rule_id in findings:
                rule = policy.rule_for(key, found.kind)
                severity = policy.severity_for(rule, found.kind)
                group_key = (rule_id, action, found.kind, severity)
                grouped.setdefault(group_key, []).append(found)
            original_length = len(unwrapped) if isinstance(unwrapped, str) else len(json.dumps(unwrapped, ensure_ascii=False))
            replacement_length = len(replacement) if isinstance(replacement, str) else len(json.dumps(replacement, ensure_ascii=False))
            for (rule_id, action, kind, severity), matches in grouped.items():
                result.decisions.append(
                    Decision(
                        rule_id=rule_id,
                        action=action,
                        kind=kind,
                        severity=severity,
                        attribute_key=key,
                        location=attribute_path(trace_id, span_id, index, key),
                        trace_id=trace_id,
                        span_id=span_id,
                        matches=len(matches),
                        original_characters=original_length,
                        replacement_characters=replacement_length,
                    )
                )

    result.output_digest = sha256_json(sanitized)
    return result

