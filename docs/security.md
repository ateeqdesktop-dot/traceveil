# Security model and threat model

## Security goals

TraceVeil aims to minimize accidental disclosure from telemetry exports while making the sanitization decision independently reviewable. Its primary goals are to avoid raw-value leakage through generated artifacts, prevent accidental mismatches between evidence and its sanitized subject, and keep processing local by default.

## Assets and boundaries

| Asset | Primary risk | Control in `0.1.0` |
|---|---|---|
| Raw OTLP telemetry | Prompt, tool, or context disclosure | Processed locally; never serialized in evidence, SARIF, or JUnit. |
| Policy | Unreviewed weakening of controls | Normalized SHA-256 policy digest recorded in evidence; policy belongs in version control and review. |
| Sanitized export | Substitution or corruption after evaluation | SHA-256 subject digest verified offline. |
| Evidence statement | Tampering with findings or bindings | Canonical JSON digest; optional Ed25519 signature. |
| Local private key | Forged provenance statement | Local file only, best-effort mode `0600`; users must use their own key-management controls. |

## Non-goals and residual risks

TraceVeil does not observe a running process, intercept network traffic, or prove that an upstream SDK emitted all relevant spans. It cannot detect every secret or every category of personal data. It does not prevent a malicious local process from replacing both a sanitized artifact and an unsigned evidence file. A signature improves tamper detection only when the private key is protected and the public key is trusted out of band.

Hashing is **not** synonymous with anonymization. Low-entropy identifiers can often be guessed and reversed. Use redaction or dropping for personal data unless a security review explicitly approves a correlation-only design.

## Operational guidance

Keep raw telemetry outside build logs, avoid uploading it as an artifact, and use the least detailed telemetry configuration that supports your operational purpose. Review generated `traceveil.evidence.json`, `traceveil.sarif`, and `traceveil.junit.xml` before sharing them. Run TraceVeil in a controlled CI workspace and grant the action only the permissions it needs.

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected security flaw. Follow the private reporting process in [SECURITY.md](../SECURITY.md).

