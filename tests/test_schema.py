"""Tests for schema validation engine."""

from envguard.schema import EnvSchemaValidator
from envguard.parser import parse_dotenv


def test_schema_valid_config():
    schema = {
        "variables": {
            "PORT": {"type": "port", "required": True},
            "NODE_ENV": {"type": "enum", "choices": ["development", "staging", "production"]},
            "DEBUG": {"type": "bool", "required": False},
            "DATABASE_URL": {"type": "url", "required": True},
        }
    }
    content = """
    PORT=3000
    NODE_ENV=production
    DEBUG=false
    DATABASE_URL=postgres://user:pass@localhost:5432/db
    """
    entries = parse_dotenv(content, filepath=".env")
    validator = EnvSchemaValidator(schema)
    errors = validator.validate(entries)

    assert len(errors) == 0


def test_schema_missing_required():
    schema = {
        "variables": {
            "SECRET_KEY": {"type": "string", "required": True},
            "PORT": {"type": "port", "required": True},
        }
    }
    content = "PORT=8080"
    entries = parse_dotenv(content, filepath=".env")
    validator = EnvSchemaValidator(schema)
    errors = validator.validate(entries)

    assert len(errors) == 1
    assert errors[0].variable_name == "SECRET_KEY"
    assert errors[0].error_type == "missing_required"


def test_schema_invalid_port():
    schema = {
        "variables": {
            "PORT": {"type": "port"},
        }
    }
    content = "PORT=99999"  # Port > 65535
    entries = parse_dotenv(content, filepath=".env")
    validator = EnvSchemaValidator(schema)
    errors = validator.validate(entries)

    assert len(errors) == 1
    assert errors[0].error_type == "invalid_port"


def test_schema_invalid_enum():
    schema = {
        "variables": {
            "ENVIRONMENT": {"type": "enum", "choices": ["dev", "prod"]},
        }
    }
    content = "ENVIRONMENT=testing"
    entries = parse_dotenv(content, filepath=".env")
    validator = EnvSchemaValidator(schema)
    errors = validator.validate(entries)

    assert len(errors) == 1
    assert errors[0].error_type == "invalid_enum"
