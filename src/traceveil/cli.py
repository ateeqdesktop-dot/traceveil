"""CLI entry point for local TraceVeil workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .canonical import atomic_write_bytes, atomic_write_json, sha256_file
from .evidence import VerificationError, create_evidence, generate_keypair, verify_evidence
from .policy import DEFAULT_POLICY_TOML, Policy, PolicyError
from .reports import junit_xml, sarif_report
from .sanitizer import sanitize_otlp_payload


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot read JSON input: {error}") from error
    if not isinstance(loaded, dict):
        raise ValueError("Input JSON must be an object")
    return loaded


def _load_policy(path: str | None) -> Policy:
    return Policy.default() if path is None else Policy.from_file(path)


def _print(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def command_init(args: argparse.Namespace) -> int:
    destination = Path(args.out)
    if destination.exists() and not args.force:
        raise ValueError(f"Refusing to overwrite {destination}; use --force to replace it")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    _print({"created": str(destination), "template": "traceveil-default"})
    return 0


def command_keygen(args: argparse.Namespace) -> int:
    private, public = generate_keypair()
    private_path = Path(args.private_key)
    public_path = Path(args.public_key)
    if (private_path.exists() or public_path.exists()) and not args.force:
        raise ValueError("Refusing to overwrite an existing key; use --force to replace it")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(private + "\n", encoding="utf-8")
    public_path.write_text(public + "\n", encoding="utf-8")
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    _print({"private_key": str(private_path), "public_key": str(public_path), "algorithm": "ed25519"})
    return 0


def command_sanitize(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    payload = _load_json(args.input)
    result = sanitize_otlp_payload(payload, policy)
    atomic_write_json(args.out, result.sanitized)
    file_digest = sha256_file(args.out)
    evidence = create_evidence(
        result,
        sanitized_name=Path(args.out).name,
        sanitized_file_digest=file_digest,
        private_key_path=args.private_key,
    )
    if args.evidence:
        atomic_write_json(args.evidence, evidence)
    if args.sarif:
        atomic_write_json(args.sarif, sarif_report(result))
    if args.junit:
        atomic_write_bytes(args.junit, junit_xml(result))
    _print(
        {
            "sanitized": str(args.out),
            "evidence": str(args.evidence) if args.evidence else None,
            "policy_sha256": result.policy_digest,
            "input_sha256": result.input_digest,
            "sanitized_artifact_sha256": file_digest,
            "summary": result.summary(),
        }
    )
    threshold = args.fail_on
    if threshold and any(decision.severity == threshold for decision in result.decisions):
        return 2
    return 0


def command_verify(args: argparse.Namespace) -> int:
    evidence = _load_json(args.evidence)
    report = verify_evidence(evidence, sanitized_path=args.sanitized, public_key_path=args.public_key)
    _print(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceveil",
        description="Compile and verify privacy policy evidence for OTLP GenAI telemetry.",
    )
    parser.add_argument("--version", action="version", version="traceveil 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="write a documented policy template")
    init.add_argument("--out", default="traceveil.toml")
    init.add_argument("--force", action="store_true")
    init.set_defaults(handler=command_init)

    keygen = commands.add_parser("keygen", help="generate a local Ed25519 key pair")
    keygen.add_argument("--private-key", default="traceveil-private.key")
    keygen.add_argument("--public-key", default="traceveil-public.key")
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(handler=command_keygen)

    sanitize = commands.add_parser("sanitize", help="sanitize OTLP JSON and emit evidence")
    sanitize.add_argument("input", help="OTLP JSON export with resourceSpans")
    sanitize.add_argument("--policy", help="TOML policy; default is built in")
    sanitize.add_argument("--out", default="traceveil.sanitized.json")
    sanitize.add_argument("--evidence", default="traceveil.evidence.json")
    sanitize.add_argument("--sarif", help="optional SARIF output path")
    sanitize.add_argument("--junit", help="optional JUnit XML output path")
    sanitize.add_argument("--private-key", help="optional Ed25519 private key to sign evidence")
    sanitize.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        help="exit 2 after writing artifacts if any finding has this exact severity",
    )
    sanitize.set_defaults(handler=command_sanitize)

    verify = commands.add_parser("verify", help="verify sanitized artifact integrity and optional signature")
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--sanitized", required=True)
    verify.add_argument("--public-key", help="optional public key; defaults to the key embedded in signed evidence")
    verify.set_defaults(handler=command_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except (PolicyError, VerificationError, ValueError) as error:
        print(f"traceveil: {error}", file=sys.stderr)
        return 1

