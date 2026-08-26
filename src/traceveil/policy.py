"""TOML policy loading and deterministic rule selection."""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .canonical import sha256_json
from .detectors import severity_for, supported_kinds


class PolicyError(ValueError):
    """Raised when a policy is invalid or unsafe to apply."""


_ACTIONS = {"redact", "drop", "hash"}
_SEVERITIES = {"low", "medium", "high", "critical"}
_DEFAULT_GUARDED_KEYS = (
    "*password*",
    "*secret*",
    "*token*",
    "*authorization*",
    "*cookie*",
    "*api*key*",
    "*private*key*",
)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    kinds: tuple[str, ...]
    paths: tuple[str, ...] = ("*",)
    action: str = "redact"
    severity: str | None = None

    def applies_to(self, attribute_key: str, kind: str) -> bool:
        return kind in self.kinds and any(fnmatch.fnmatchcase(attribute_key, path) for path in self.paths)


@dataclass(frozen=True, slots=True)
class Policy:
    name: str = "traceveil-default"
    version: str = "1"
    mode: str = "fail-closed"
    guarded_key_patterns: tuple[str, ...] = _DEFAULT_GUARDED_KEYS
    guarded_key_action: str = "redact"
    rules: tuple[Rule, ...] = field(default_factory=tuple)

    @classmethod
    def default(cls) -> "Policy":
        return cls(
            rules=(
                Rule(
                    id="credentials",
                    kinds=(
                        "private_key",
                        "jwt",
                        "aws_access_key",
                        "github_token",
                        "openai_key",
                        "slack_token",
                        "bearer_token",
                        "credential_assignment",
                    ),
                    action="redact",
                    severity="critical",
                ),
                Rule(id="personal-data", kinds=("email", "phone"), action="redact", severity="medium"),
            )
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        try:
            document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise PolicyError(f"Cannot read policy: {error}") from error
        return cls.from_mapping(document)

    @classmethod
    def from_mapping(cls, document: dict[str, Any]) -> "Policy":
        policy_section = document.get("policy", {})
        if not isinstance(policy_section, dict):
            raise PolicyError("[policy] must be a table")

        name = str(policy_section.get("name", "traceveil-policy"))
        version = str(policy_section.get("version", "1"))
        mode = str(policy_section.get("mode", "fail-closed"))
        if mode not in {"fail-closed", "report-only"}:
            raise PolicyError("policy.mode must be 'fail-closed' or 'report-only'")

        guard_section = document.get("guards", {})
        if not isinstance(guard_section, dict):
            raise PolicyError("[guards] must be a table")
        guarded_key_patterns = tuple(str(item) for item in guard_section.get("key_patterns", _DEFAULT_GUARDED_KEYS))
        guarded_key_action = str(guard_section.get("action", "redact"))
        if guarded_key_action not in _ACTIONS:
            raise PolicyError("guards.action must be redact, drop, or hash")

        parsed_rules: list[Rule] = []
        for index, item in enumerate(document.get("rules", [])):
            if not isinstance(item, dict):
                raise PolicyError(f"rules[{index}] must be a table")
            rule_id = str(item.get("id", f"rule-{index + 1}"))
            kinds = tuple(str(kind) for kind in item.get("kinds", ()))
            if not kinds:
                raise PolicyError(f"rules[{index}] must declare at least one detector kind")
            unknown = sorted(set(kinds) - supported_kinds())
            if unknown:
                raise PolicyError(f"rules[{index}] has unsupported detector kinds: {', '.join(unknown)}")
            paths = tuple(str(path) for path in item.get("paths", ("*",)))
            action = str(item.get("action", "redact"))
            severity = item.get("severity")
            if action not in _ACTIONS:
                raise PolicyError(f"rules[{index}].action must be redact, drop, or hash")
            if severity is not None and str(severity) not in _SEVERITIES:
                raise PolicyError(f"rules[{index}].severity is invalid")
            parsed_rules.append(Rule(rule_id, kinds, paths, action, str(severity) if severity else None))

        if not parsed_rules and mode == "fail-closed":
            raise PolicyError("fail-closed policies require at least one [[rules]] entry")
        return cls(name, version, mode, guarded_key_patterns, guarded_key_action, tuple(parsed_rules))

    def is_guarded_key(self, attribute_key: str) -> bool:
        normalized = attribute_key.lower().replace("_", ".")
        return any(fnmatch.fnmatchcase(normalized, pattern.lower().replace("_", ".")) for pattern in self.guarded_key_patterns)

    def rule_for(self, attribute_key: str, kind: str) -> Rule | None:
        for rule in self.rules:
            if rule.applies_to(attribute_key, kind):
                return rule
        return None

    def normalized(self) -> dict[str, Any]:
        return {
            "policy": {"name": self.name, "version": self.version, "mode": self.mode},
            "guards": {"key_patterns": list(self.guarded_key_patterns), "action": self.guarded_key_action},
            "rules": [asdict(rule) for rule in self.rules],
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.normalized())

    def severity_for(self, rule: Rule | None, kind: str) -> str:
        return rule.severity if rule and rule.severity else severity_for(kind)


DEFAULT_POLICY_TOML = """# TraceVeil policy. Input content never leaves this process.\n\n[policy]\nname = \"traceveil-default\"\nversion = \"1\"\nmode = \"fail-closed\"\n\n[guards]\n# Keys matching these globs are redacted as a whole before pattern inspection.\nkey_patterns = [\"*password*\", \"*secret*\", \"*token*\", \"*authorization*\", \"*cookie*\", \"*api*key*\", \"*private*key*\"]\naction = \"redact\"\n\n[[rules]]\nid = \"credentials\"\nkinds = [\"private_key\", \"jwt\", \"aws_access_key\", \"github_token\", \"openai_key\", \"slack_token\", \"bearer_token\", \"credential_assignment\"]\npaths = [\"gen_ai.*\", \"llm.*\", \"http.*\", \"db.*\", \"exception.*\", \"*\"]\naction = \"redact\"\nseverity = \"critical\"\n\n[[rules]]\nid = \"personal-data\"\nkinds = [\"email\", \"phone\"]\npaths = [\"gen_ai.*\", \"llm.*\", \"http.*\", \"db.*\", \"exception.*\", \"*\"]\naction = \"redact\"\nseverity = \"medium\"\n"""

