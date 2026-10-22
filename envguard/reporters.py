"""Reporters for console ANSI, JSON, Markdown, and GitHub SARIF 2.1.0 output."""

import json
from typing import Dict, List, Optional
from envguard.detectors import Finding, Severity
from envguard.schema import SchemaValidationError

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"

def render_ansi_report(findings: List[Finding], schema_errors: List[SchemaValidationError]) -> str:
    """Render beautiful terminal report."""
    lines = []
    lines.append(f"{BOLD}{CYAN}=== EnvGuard Security & Compliance Report ==={RESET}\n")

    if not findings and not schema_errors:
        lines.append(f"{GREEN}{BOLD}✓ ALL CHECKS PASSED:{RESET} No secret leaks or schema violations detected.\n")
        return "\n".join(lines)

    if findings:
        lines.append(f"{RED}{BOLD}🚨 Secret Leaks Detected ({len(findings)}):{RESET}")
        for idx, f in enumerate(findings, 1):
            sev_color = RED if f.severity == Severity.CRITICAL else (YELLOW if f.severity == Severity.HIGH else BLUE)
            lines.append(
                f"  {idx}. [{sev_color}{f.severity.value}{RESET}] {BOLD}{f.rule_name}{RESET} ({f.rule_id})"
            )
            lines.append(f"     Location: {f.filepath}:{f.line_number} (Variable: {BOLD}{f.variable_name}{RESET})")
            lines.append(f"     Masked:   {f.masked_value}")
            lines.append(f"     Action:   {GRAY}{f.recommendation}{RESET}\n")

    if schema_errors:
        lines.append(f"{YELLOW}{BOLD}⚠️ Schema Validation Issues ({len(schema_errors)}):{RESET}")
        for idx, err in enumerate(schema_errors, 1):
            loc = f":{err.line_number}" if err.line_number else ""
            lines.append(f"  {idx}. [{YELLOW}{err.error_type}{RESET}] Variable: {BOLD}{err.variable_name}{RESET}{loc}")
            lines.append(f"     Problem:  {err.message}")
            lines.append(f"     Expected: {err.expected}")
            if err.actual is not None:
                lines.append(f"     Actual:   {err.actual}\n")
            else:
                lines.append("")

    summary = f"{BOLD}Summary:{RESET} {len(findings)} secret leaks, {len(schema_errors)} schema errors."
    lines.append(summary)
    return "\n".join(lines)

def render_json_report(findings: List[Finding], schema_errors: List[SchemaValidationError]) -> str:
    """Render structured JSON report."""
    data = {
        "status": "failed" if (findings or schema_errors) else "passed",
        "total_findings": len(findings),
        "total_schema_errors": len(schema_errors),
        "summary": {
            "total_findings": len(findings),
            "total_schema_errors": len(schema_errors),
            "critical_count": sum(1 for f in findings if f.severity.value == "critical"),
            "high_count": sum(1 for f in findings if f.severity.value == "high"),
            "status": "failed" if (findings or schema_errors) else "passed"
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "description": f.description,
                "filepath": f.filepath,
                "line_number": f.line_number,
                "variable_name": f.variable_name,
                "masked_value": f.masked_value,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "schema_errors": [
            {
                "variable_name": e.variable_name,
                "error_type": e.error_type,
                "message": e.message,
                "expected": e.expected,
                "actual": e.actual,
                "line_number": e.line_number,
            }
            for e in schema_errors
        ],
    }
    return json.dumps(data, indent=2)

def render_markdown_report(findings: List[Finding], schema_errors: List[SchemaValidationError]) -> str:
    """Render GitHub-flavored markdown report."""
    lines = ["# 🛡️ EnvGuard Audit Report\n"]

    if not findings and not schema_errors:
        lines.append("✅ **All checks passed.** No secrets or schema violations found.\n")
        return "\n".join(lines)

    if findings:
        lines.append(f"### 🚨 Secret Leaks Found (`{len(findings)}`)\n")
        lines.append("| Severity | Rule | Variable | File:Line | Recommendation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            lines.append(
                f"| **{f.severity.value}** | `{f.rule_name}` | `{f.variable_name}` | `{f.filepath}:{f.line_number}` | {f.recommendation} |"
            )
        lines.append("")

    if schema_errors:
        lines.append(f"### ⚠️ Schema Errors (`{len(schema_errors)}`)\n")
        lines.append("| Variable | Error | Expected | Actual | Line |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for e in schema_errors:
            lines.append(f"| `{e.variable_name}` | `{e.error_type}` | {e.expected} | `{e.actual or '-'}` | {e.line_number or '-'} |")
        lines.append("")

    return "\n".join(lines)

def render_sarif_report(findings: List[Finding]) -> str:
    """Render standard SARIF 2.1.0 for GitHub Code Scanning / Security tab."""
    rules = {}
    results = []

    for f in findings:
        if f.rule_id not in rules:
            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {"level": level},
                "help": {"text": f.recommendation},
            }

        results.append(
            {
                "ruleId": f.rule_id,
                "message": {"text": f"{f.description} in {f.variable_name}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.filepath.replace("\\", "/")},
                            "region": {"startLine": f.line_number, "startColumn": 1},
                        }
                    }
                ],
            }
        )

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EnvGuard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_data, indent=2)
