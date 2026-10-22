"""Tests for report rendering formats."""

import json
from envguard.detectors import Finding, Severity
from envguard.schema import SchemaValidationError
from envguard.reporters import (
    render_ansi_report,
    render_json_report,
    render_markdown_report,
    render_sarif_report,
)


def test_reporters_empty_pass():
    ansi = render_ansi_report([], [])
    assert "ALL CHECKS PASSED" in ansi

    md = render_markdown_report([], [])
    assert "All checks passed" in md

    json_str = render_json_report([], [])
    data = json.loads(json_str)
    assert data["status"] == "passed"
    assert data["total_findings"] == 0


def test_reporters_with_findings():
    findings = [
        Finding(
            rule_id="SEC001",
            rule_name="AWS Access Key ID",
            severity=Severity.CRITICAL,
            description="Found AWS key",
            filepath=".env",
            line_number=2,
            variable_name="AWS_KEY",
            masked_value="AKIA****MPLE",
            recommendation="Revoke key",
        )
    ]
    schema_errors = [
        SchemaValidationError(
            variable_name="PORT",
            error_type="invalid_port",
            message="Invalid port",
            expected="1-65535",
            actual="99999",
            line_number=5,
        )
    ]

    # Test ANSI
    ansi = render_ansi_report(findings, schema_errors)
    assert "Secret Leaks Detected" in ansi
    assert "Schema Validation Issues" in ansi

    # Test JSON
    json_str = render_json_report(findings, schema_errors)
    data = json.loads(json_str)
    assert data["status"] == "failed"
    assert data["total_findings"] == 1
    assert data["total_schema_errors"] == 1

    # Test Markdown
    md = render_markdown_report(findings, schema_errors)
    assert "| **CRITICAL** | `AWS Access Key ID`" in md
    assert "| `PORT` | `invalid_port`" in md

    # Test SARIF 2.1.0
    sarif_str = render_sarif_report(findings)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SEC001"
