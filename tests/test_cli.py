"""Tests for CLI arguments, workflows, and exit codes."""

import os
import tempfile
import pytest
from envguard.cli import main


def test_cli_version():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_cli_audit_clean(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("PORT=3000\nNODE_ENV=production\n", encoding="utf-8")

    exit_code = main(["audit", str(env_file)])
    assert exit_code == 0


def test_cli_audit_leak(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("AWS_KEY=" + "AKIA" + "IOSFODNN7EXAMPLE\n", encoding="utf-8")

    exit_code = main(["audit", str(env_file)])
    assert exit_code == 1


def test_cli_template_command(tmp_path):
    env_file = tmp_path / ".env"
    out_file = tmp_path / ".env.example"
    env_file.write_text("PORT=3000\nOPENAI_API_KEY=" + "sk-proj-" + "1234567890abcdef1234567890abcdef1234567890\n", encoding="utf-8")

    exit_code = main(["template", str(env_file), "--output", str(out_file)])
    assert exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "sk-your-openai-api-key-here" in content


def test_cli_init_schema_command(tmp_path):
    env_file = tmp_path / ".env"
    schema_file = tmp_path / "envguard.schema.json"
    env_file.write_text("PORT=8080\nDEBUG=true\nAPI_URL=https://api.example.com\n", encoding="utf-8")

    exit_code = main(["init-schema", str(env_file), "--output", str(schema_file)])
    assert exit_code == 0
    assert schema_file.exists()
    schema_content = schema_file.read_text(encoding="utf-8")
    assert '"type": "port"' in schema_content
    assert '"type": "bool"' in schema_content
    assert '"type": "url"' in schema_content
