"""CLI entry point and command router for EnvGuard."""

import argparse
import os
import sys
from typing import List, Optional

from envguard import __version__
from envguard.parser import parse_dotenv, EnvEntry
from envguard.detectors import SecretDetector, Finding, Severity
from envguard.schema import EnvSchemaValidator, SchemaValidationError
from envguard.generator import generate_template
from envguard.reporters import (
    render_ansi_report,
    render_json_report,
    render_markdown_report,
    render_sarif_report,
)


def find_env_files(target_path: str) -> List[str]:
    """Find environment files in target file or directory."""
    if os.path.isfile(target_path):
        return [target_path]

    found = []
    for root, dirs, files in os.walk(target_path):
        # Ignore common non-target directories
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}]
        for file in files:
            lower = file.lower()
            if (
                lower.startswith(".env")
                or lower.endswith(".env")
                or lower in {"env", "secrets.env", "local.env", "production.env"}
            ) and not lower.endswith(".example") and not lower.endswith(".sample"):
                found.append(os.path.join(root, file))
    return sorted(found)


def run_audit(target: str, entropy_threshold: float = 4.2) -> List[Finding]:
    """Audit files or directory for secret leaks."""
    files = find_env_files(target)
    if not files:
        if os.path.exists(target):
            # Target is a single file without standard env extension
            files = [target]
        else:
            print(f"Error: Target path '{target}' not found.", file=sys.stderr)
            return []

    detector = SecretDetector(entropy_threshold=entropy_threshold)
    all_findings: List[Finding] = []

    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            entries = parse_dotenv(content, filepath=fpath)
            findings = detector.scan(entries)
            all_findings.extend(findings)
        except Exception as exc:
            print(f"Warning: Failed to parse '{fpath}': {exc}", file=sys.stderr)

    return all_findings


def run_check(target: str, schema_path: str) -> List[SchemaValidationError]:
    """Validate env file against schema definition."""
    if not os.path.isfile(target):
        print(f"Error: Target env file '{target}' does not exist.", file=sys.stderr)
        return [
            SchemaValidationError(
                variable_name="TARGET_FILE",
                error_type="file_missing",
                message=f"Env file not found: {target}",
                expected="existing file",
            )
        ]

    try:
        validator = EnvSchemaValidator.from_file(schema_path)
    except Exception as exc:
        print(f"Error: Failed to load schema from '{schema_path}': {exc}", file=sys.stderr)
        return [
            SchemaValidationError(
                variable_name="SCHEMA_FILE",
                error_type="schema_load_error",
                message=str(exc),
                expected="valid JSON schema",
            )
        ]

    with open(target, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    entries = parse_dotenv(content, filepath=target)
    return validator.validate(entries)


def infer_schema_from_env(env_path: str) -> dict:
    """Infer schema structure from an existing .env file."""
    if not os.path.isfile(env_path):
        raise FileNotFoundError(f"File not found: {env_path}")

    with open(env_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    entries = parse_dotenv(content, filepath=env_path)
    schema_vars = {}

    for entry in entries:
        val = entry.value.strip()
        lower_val = val.lower()
        key_upper = entry.key.upper()

        if lower_val in {"true", "false", "1", "0", "yes", "no"}:
            var_type = "bool"
        elif val.isdigit():
            if "PORT" in key_upper:
                var_type = "port"
            else:
                var_type = "int"
        elif val.startswith(("http://", "https://", "postgres://", "postgresql://", "mysql://", "redis://", "mongodb://")):
            var_type = "url"
        elif "@" in val and "." in val.split("@")[-1]:
            var_type = "email"
        else:
            var_type = "string"

        schema_vars[entry.key] = {
            "type": var_type,
            "required": True,
            "description": f"Environment variable {entry.key}",
        }

    return {
        "$schema": "https://envguard.dev/schema/v1.json",
        "title": f"EnvGuard Schema for {os.path.basename(env_path)}",
        "allow_extra": True,
        "variables": schema_vars,
    }


def output_report(
    findings: List[Finding],
    schema_errors: List[SchemaValidationError],
    fmt: str = "ansi",
    output_file: Optional[str] = None,
) -> None:
    """Render and output results in specified format."""
    fmt = fmt.lower()
    if fmt == "json":
        text = render_json_report(findings, schema_errors)
    elif fmt == "sarif":
        text = render_sarif_report(findings)
    elif fmt == "markdown" or fmt == "md":
        text = render_markdown_report(findings, schema_errors)
    else:
        text = render_ansi_report(findings, schema_errors)

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Report written to {output_file}")
    else:
        print(text)


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI handler."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="envguard",
        description="🛡️ EnvGuard: Zero-dependency secrets leak detector & environment schema validator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  envguard audit .env
  envguard audit ./src --format sarif --output audit.sarif
  envguard check .env --schema envguard.schema.json
  envguard scan .env --schema envguard.schema.json --ci
  envguard template .env --output .env.example
  envguard init-schema .env --output envguard.schema.json
  envguard serve --port 8080
        """,
    )

    parser.add_argument("--version", "-v", action="version", version=f"EnvGuard {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: audit
    p_audit = subparsers.add_parser("audit", help="Audit file or directory for secret leaks")
    p_audit.add_argument("target", nargs="?", default=".env", help="Path to .env file or project directory (default: .env)")
    p_audit.add_argument("--entropy", type=float, default=4.2, help="Shannon entropy threshold for high-randomness secrets (default: 4.2)")
    p_audit.add_argument("--format", choices=["ansi", "json", "sarif", "markdown"], default="ansi", help="Output format")
    p_audit.add_argument("--output", "-o", help="Write report to file")

    # Command: check
    p_check = subparsers.add_parser("check", help="Validate .env file against schema constraints")
    p_check.add_argument("target", nargs="?", default=".env", help="Path to .env file (default: .env)")
    p_check.add_argument("--schema", "-s", required=True, help="Path to schema JSON file")
    p_check.add_argument("--format", choices=["ansi", "json", "markdown"], default="ansi", help="Output format")
    p_check.add_argument("--output", "-o", help="Write report to file")

    # Command: scan (audit + check combined)
    p_scan = subparsers.add_parser("scan", help="Comprehensive audit + schema verification for CI/CD")
    p_scan.add_argument("target", nargs="?", default=".env", help="Path to .env file or directory (default: .env)")
    p_scan.add_argument("--schema", "-s", help="Optional path to schema JSON file")
    p_scan.add_argument("--entropy", type=float, default=4.2, help="Entropy threshold")
    p_scan.add_argument("--format", choices=["ansi", "json", "sarif", "markdown"], default="ansi", help="Output format")
    p_scan.add_argument("--output", "-o", help="Write report to file")
    p_scan.add_argument("--ci", action="store_true", help="Fail pipeline with non-zero exit code if issues found")

    # Command: template
    p_template = subparsers.add_parser("template", help="Generate sanitized .env.example from existing .env")
    p_template.add_argument("target", nargs="?", default=".env", help="Path to source .env file (default: .env)")
    p_template.add_argument("--output", "-o", default=".env.example", help="Output destination (default: .env.example)")

    # Command: init-schema
    p_init = subparsers.add_parser("init-schema", help="Infer schema JSON from an existing .env file")
    p_init.add_argument("target", nargs="?", default=".env", help="Path to reference .env file (default: .env)")
    p_init.add_argument("--output", "-o", default="envguard.schema.json", help="Destination schema path (default: envguard.schema.json)")

    # Command: serve
    p_serve = subparsers.add_parser("serve", help="Launch local HTTP daemon and interactive web audit dashboard")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    p_serve.add_argument("--port", "-p", type=int, default=8080, help="Port (default: 8080)")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        findings = run_audit(args.target, entropy_threshold=args.entropy)
        output_report(findings, [], fmt=args.format, output_file=args.output)
        critical_or_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return 1 if critical_or_high else 0

    elif args.command == "check":
        errors = run_check(args.target, args.schema)
        output_report([], errors, fmt=args.format, output_file=args.output)
        return 2 if errors else 0

    elif args.command == "scan":
        findings = run_audit(args.target, entropy_threshold=args.entropy)
        errors = run_check(args.target, args.schema) if args.schema else []
        output_report(findings, errors, fmt=args.format, output_file=args.output)

        if args.ci:
            if findings:
                return 1
            if errors:
                return 2
        return 0

    elif args.command == "template":
        if not os.path.isfile(args.target):
            print(f"Error: Source file '{args.target}' does not exist.", file=sys.stderr)
            return 1
        with open(args.target, "r", encoding="utf-8") as f:
            content = f.read()
        generated = generate_template(content)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(generated)
        print(f"✓ Sanitized template successfully created: {args.output}")
        return 0

    elif args.command == "init-schema":
        import json
        try:
            schema_dict = infer_schema_from_env(args.target)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(schema_dict, f, indent=2)
            print(f"✓ Inferred schema generated at: {args.output}")
            return 0
        except Exception as exc:
            print(f"Error generating schema: {exc}", file=sys.stderr)
            return 1

    elif args.command == "serve":
        from envguard.server import run_server
        print(f"🚀 Starting EnvGuard Daemon at http://{args.host}:{args.port}")
        try:
            run_server(host=args.host, port=args.port)
        except KeyboardInterrupt:
            print("\nShutting down EnvGuard Daemon.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
