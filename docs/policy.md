# Policy reference

A TraceVeil policy is TOML. It makes the privacy boundary code-reviewable and versionable alongside telemetry instrumentation.

## Policy sections

| Section | Required | Meaning |
|---|---|---|
| `[policy]` | No | Names the policy, records its logical version, and specifies whether invalid policy configuration must fail closed. |
| `[guards]` | No | Redacts an entire attribute whose key matches one of the configured globs before inspecting content. |
| `[[rules]]` | Yes for `fail-closed` mode | Maps one or more built-in detector kinds to attribute path globs, an action, and an optional severity. |

## Built-in detector kinds

| Kind | Intended match class | Default severity |
|---|---|---|
| `private_key` | PEM private-key headers | critical |
| `jwt` | Compact JWS/JWT-like strings | critical |
| `aws_access_key` | `AKIA`/`ASIA` access-key identifiers | critical |
| `github_token` | GitHub token prefixes | critical |
| `openai_key` | `sk-` API-key-like strings | critical |
| `slack_token` | Slack token prefixes | critical |
| `bearer_token` | HTTP Bearer token values | high |
| `credential_assignment` | Common `secret=…`/`token: …` assignments | high |
| `email` | Email addresses | medium |
| `phone` | Phone-number-like sequences | medium |

Detector kinds are intentionally finite in `0.1.0`. A match is a policy-control signal, not a legal classification or proof that a string belongs to a particular individual.

## Actions

| Action | Effect | Appropriate use |
|---|---|---|
| `redact` | Replaces a matched span with a deterministic `TRACEVEIL` marker. | Default for sensitive content where structural context remains useful. |
| `drop` | Replaces the affected string with an empty value. | High-sensitivity fields whose content should not remain in the sanitized trace. |
| `hash` | Replaces a matched string with a SHA-256 digest. | Correlation-only cases; do not mistake hashing for anonymization. |

TraceVeil retains no raw matched values in evidence, SARIF, or JUnit. The redaction marker includes a short per-value fingerprint so a reviewer can identify repeated values within the same output without seeing the value itself.

## Attribute paths

`paths` use case-sensitive shell-style globs against OTLP attribute keys. Use narrow paths when possible:

```toml
[[rules]]
id = "prompt-personal-data"
kinds = ["email", "phone"]
paths = ["gen_ai.input.messages", "gen_ai.output.messages"]
action = "redact"
severity = "medium"
```

The catch-all `*` is useful during initial hardening, but a review should eventually prefer paths that mirror the attributes your instrumentation emits.

## Guarded keys

Guard rules work before content detection. They are safer for fields whose names already establish sensitivity:

```toml
[guards]
key_patterns = ["*authorization*", "*cookie*", "*password*", "*token*", "*api*key*"]
action = "redact"
```

Guarded-key decisions use `guarded_key` as their kind and do not carry the original field value.

## Limitations

Do not rely on this policy language alone for regulatory compliance, arbitrary PII detection, data discovery, or credential revocation. It is a deterministic local control designed to be composed with OpenTelemetry data minimization, secure collectors, access controls, retention limits, code review, and incident response.

