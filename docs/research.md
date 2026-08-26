# Product selection and competitive research

TraceVeil was selected after auditing the public GitHub portfolio, researching the observability/provenance ecosystem, and scoring alternatives against technical depth, real-world value, differentiation, maintenance potential, CI potential, and portfolio value.

## Account fit

The account already contains multiple Python and TypeScript projects around deterministic evidence, AI-agent governance, contract testing, reproducibility, SARIF/JUnit, OpenTelemetry, privacy-aware debugging, and CI actions. It did **not** benefit from another generic agent dashboard, MCP firewall, replay harness, or evidence-bundle generator. A project that turns a standard telemetry format into a verified privacy boundary is adjacent enough to demonstrate depth, while solving a distinct operational problem.

## Competitive boundary

| Existing category | What it already does well | Why TraceVeil is different |
|---|---|---|
| Observability platforms such as Langfuse and Phoenix | Capture, store, visualize, evaluate, and analyze agent traces at platform scale. | TraceVeil is a local compiler that creates a portable policy decision record before telemetry is exported. It does not compete on trace storage or dashboards. |
| OpenTelemetry conventions and Collector processors | Standardize telemetry fields and provide generic attribute/filter/redaction mechanisms. | TraceVeil adds a bounded GenAI-focused policy language, deterministic decision ledger, artifact binding, signed evidence, and CI reports. |
| SLSA and artifact attestations | Prove how a software artifact was built and support supply-chain verification. | TraceVeil addresses the earlier contextual boundary: what sensitive agent telemetry was removed and what policy justified the export. |
| LLM evaluation frameworks | Test quality, safety, and correctness of model or agent behavior. | TraceVeil validates privacy handling of telemetry artifacts; it does not score model outputs. |

The highest-value gap is **verifiable sanitization**, not collection or visualization. Existing systems can record rich traces; privacy controls often remain configuration-only, hard to review after the fact, and weakly bound to the artifact that was eventually exported.

## Sources

1. [OpenTelemetry: Handling sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/) explains that OpenTelemetry cannot decide what is sensitive in a specific context and delegates data minimization and processor configuration to implementers.
2. [OpenTelemetry: GenAI observability](https://opentelemetry.io/blog/2026/genai-observability/) documents standardized GenAI attributes and the optional capture of prompts, messages, tool calls, and results.
3. [Wang et al., *From Agent Traces to Trust*](https://arxiv.org/html/2606.04990v4) frames process-level accountability as distinct from final-output correctness and identifies gaps around unified provenance and privacy-aware audit infrastructure.
4. [Sourcegraph: proving agent provenance](https://sourcegraph.com/blog/compliance-first-ai-proving-agent-provenance) describes the operational need to retain evidence of what an agent read and why before it changed code.
5. [Langfuse: AI agent observability, tracing, and evaluation](https://langfuse.com/blog/2024-07-ai-agent-observability-with-langfuse) documents a broad tracing/evaluation platform with typed observations and agent graphs.
6. [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator) shows the established boundary of build provenance and its separate verification requirements.

