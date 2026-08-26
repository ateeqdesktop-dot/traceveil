"""Standard CI report emitters built from privacy decisions, never raw values."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .sanitizer import SanitizationResult


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def sarif_report(result: SanitizationResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    report_results: list[dict[str, Any]] = []
    for decision in result.decisions:
        rule_id = f"traceveil/{decision.kind}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": decision.kind,
                "shortDescription": {"text": f"TraceVeil detected {decision.kind.replace('_', ' ')}"},
                "helpUri": "https://github.com/ateeqdesktop-dot/traceveil/blob/main/docs/policy.md",
            }
        report_results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[decision.severity],
                "message": {
                    "text": f"{decision.action} applied by policy rule '{decision.rule_id}' at {decision.location}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "otlp-input.json"},
                            "region": {"snippet": {"text": decision.location}},
                        }
                    }
                ],
                "properties": {
                    "traceveil.action": decision.action,
                    "traceveil.severity": decision.severity,
                    "traceveil.matches": decision.matches,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TraceVeil", "version": "0.1.0", "rules": list(rules.values())}},
                "results": report_results,
            }
        ],
    }


def junit_xml(result: SanitizationResult) -> bytes:
    suite = ET.Element(
        "testsuite",
        {
            "name": "traceveil.policy",
            "tests": str(max(1, len(result.decisions))),
            "failures": str(len(result.decisions)),
        },
    )
    if not result.decisions:
        ET.SubElement(suite, "testcase", {"name": "no-sensitive-data-detected", "classname": "traceveil.policy"})
    for decision in result.decisions:
        case = ET.SubElement(
            suite,
            "testcase",
            {"name": decision.location, "classname": f"traceveil.{decision.kind}"},
        )
        failure = ET.SubElement(
            case,
            "failure",
            {
                "type": decision.kind,
                "message": f"{decision.severity}: {decision.action} by {decision.rule_id}",
            },
        )
        failure.text = (
            f"TraceVeil applied {decision.action} to {decision.matches} match(es) in {decision.attribute_key}. "
            "Raw content is intentionally not included."
        )
    return ET.tostring(suite, encoding="utf-8", xml_declaration=True)

