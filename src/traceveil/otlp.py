"""Small OTLP/JSON traversal utilities; no SDK dependency is required."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from typing import Any


def unwrap_any_value(value: Any) -> Any:
    """Convert OTLP JSON AnyValue into ordinary JSON-compatible values."""

    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "intValue" in value:
        return value["intValue"]
    if "doubleValue" in value:
        return value["doubleValue"]
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        return [unwrap_any_value(item) for item in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return {
            item.get("key", ""): unwrap_any_value(item.get("value"))
            for item in value["kvlistValue"].get("values", [])
        }
    return value


def wrap_like_any_value(original: Any, replacement: Any) -> Any:
    """Return a replacement preserving the original OTLP JSON value shape."""

    if isinstance(original, dict) and "stringValue" in original:
        return {**original, "stringValue": str(replacement)}
    if isinstance(original, dict) and "intValue" in original:
        return {**original, "intValue": str(replacement)}
    if isinstance(original, dict) and "doubleValue" in original:
        return {**original, "doubleValue": replacement}
    if isinstance(original, dict) and "boolValue" in original:
        return {**original, "boolValue": bool(replacement)}
    if isinstance(original, dict) and "bytesValue" in original:
        return {**original, "bytesValue": str(replacement)}
    if isinstance(original, dict) and "arrayValue" in original and isinstance(replacement, list):
        values = original["arrayValue"].get("values", [])
        return {
            **original,
            "arrayValue": {
                **original["arrayValue"],
                "values": [
                    wrap_like_any_value(values[index] if index < len(values) else {}, item)
                    for index, item in enumerate(replacement)
                ],
            },
        }
    if isinstance(original, dict) and "kvlistValue" in original and isinstance(replacement, dict):
        values = original["kvlistValue"].get("values", [])
        return {
            **original,
            "kvlistValue": {
                **original["kvlistValue"],
                "values": [
                    {
                        **item,
                        "value": wrap_like_any_value(item.get("value", {}), replacement.get(item.get("key", ""))),
                    }
                    for item in values
                ],
            },
        }
    return {"stringValue": str(replacement)}


def iter_spans(payload: dict[str, Any]) -> Iterator[tuple[dict[str, Any], str, str]]:
    """Yield (span, trace_id, span_id) for canonical OTLP JSON resourceSpans."""

    for resource_index, resource_span in enumerate(payload.get("resourceSpans", [])):
        scope_spans = resource_span.get("scopeSpans", resource_span.get("instrumentationLibrarySpans", []))
        for scope_index, scope_span in enumerate(scope_spans):
            for span_index, span in enumerate(scope_span.get("spans", [])):
                trace_id = str(span.get("traceId", f"resource-{resource_index}"))
                span_id = str(span.get("spanId", f"scope-{scope_index}-span-{span_index}"))
                yield span, trace_id, span_id


def attribute_path(trace_id: str, span_id: str, index: int, key: str) -> str:
    return f"traces/{trace_id}/spans/{span_id}/attributes/{index}:{key}"


def ensure_otlp_shape(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("resourceSpans"), list):
        raise ValueError("Input must be OTLP JSON with a top-level resourceSpans array")
    return payload


def fingerprint_identifier(value: str) -> str:
    """Short non-secret reference for trace/span identifiers in reports."""

    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    return encoded[:24]
