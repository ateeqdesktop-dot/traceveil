# Roadmap

## `0.1.0` — implemented

The first release ships a local Python CLI, TOML policy validation, canonical OTLP JSON handling, deterministic pattern detection, structured GenAI-message sanitation, guarded-key rules, evidence digests, optional Ed25519 signing, offline verification, SARIF/JUnit, a composite action, tests, and CI.

## `0.2` — hardening the policy surface

The next release should add policy test fixtures and snapshots, JSON Schema for policy and evidence, user-defined non-secret detector plugins, precise range metadata for structured message formats, and a standalone `traceveil check` command that evaluates a policy against committed fixtures.

## `0.3` — interoperability

The interoperability milestone should add an OpenTelemetry Collector processor adapter, a documented mapping for GenAI semantic conventions, DSSE envelope output, and optional Sigstore/Cosign bridges. These additions must retain local execution as the default.

## `1.0` — stable contract

Version 1.0 requires a policy compatibility promise, stable evidence schema, threat-model review, golden compatibility corpus, documented migration mechanics, release automation, and community feedback from users who run TraceVeil in real CI environments.

