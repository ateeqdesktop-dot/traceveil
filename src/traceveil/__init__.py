"""TraceVeil: privacy policy verification for OpenTelemetry GenAI telemetry."""

from .policy import Policy, PolicyError
from .sanitizer import SanitizationResult, sanitize_otlp_payload

__all__ = ["Policy", "PolicyError", "SanitizationResult", "sanitize_otlp_payload"]
__version__ = "0.1.0"

