"""Deterministic secret and PII detectors with no network or model calls."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class Match:
    kind: str
    start: int
    end: int
    value: str


@dataclass(frozen=True, slots=True)
class Detector:
    kind: str
    expression: re.Pattern[str]
    severity: str


_DETECTORS: tuple[Detector, ...] = (
    Detector("private_key", re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"), "critical"),
    Detector("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"), "critical"),
    Detector("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "critical"),
    Detector("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "critical"),
    Detector("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "critical"),
    Detector("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "critical"),
    Detector("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "high"),
    Detector(
        "credential_assignment",
        re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password|authorization)\s*[:=]\s*[^\s,;]{4,}"),
        "high",
    ),
    Detector(
        "email",
        re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"),
        "medium",
    ),
    Detector(
        "phone",
        re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?){2,4}\d{3,4}(?!\w)"),
        "medium",
    ),
)


def supported_kinds() -> set[str]:
    return {detector.kind for detector in _DETECTORS}


def severity_for(kind: str) -> str:
    for detector in _DETECTORS:
        if detector.kind == kind:
            return detector.severity
    return "medium"


def detect(text: str, enabled_kinds: Iterable[str]) -> list[Match]:
    """Return non-overlapping findings in left-to-right order.

    The detector is intentionally deterministic and conservative. It does not
    infer identity or send content to a remote classifier; policies decide which
    supported detector kinds apply to which telemetry attributes.
    """

    enabled = set(enabled_kinds)
    matches: list[Match] = []
    for detector in _DETECTORS:
        if detector.kind not in enabled:
            continue
        for found in detector.expression.finditer(text):
            matches.append(Match(detector.kind, found.start(), found.end(), found.group(0)))

    ranked = sorted(matches, key=lambda item: (item.start, -(item.end - item.start), item.kind))
    selected: list[Match] = []
    cursor = -1
    for found in ranked:
        if found.start >= cursor:
            selected.append(found)
            cursor = found.end
    return selected

