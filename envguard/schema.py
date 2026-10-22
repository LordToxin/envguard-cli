"""Schema specification and type validation engine for environment variables."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import json
import os
import re

@dataclass
class SchemaValidationError:
    variable_name: str
    error_type: str
    message: str
    expected: str
    actual: Optional[str] = None
    line_number: Optional[int] = None

class EnvSchemaValidator:
    """Validates loaded environment variables against strict schema constraints."""

    def __init__(self, schema_definition: Dict[str, Any]):
        self.schema = schema_definition.get("variables", schema_definition)
        self.allow_extra = schema_definition.get("allow_extra", True)

    @classmethod
    def from_file(cls, filepath: str) -> "EnvSchemaValidator":
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Schema file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    def validate(self, entries: List) -> List[SchemaValidationError]:
        """Validate a list of EnvEntry items against the schema."""
        errors: List[SchemaValidationError] = []
        entry_map = {e.key: e for e in entries}

        for var_name, rules in self.schema.items():
            if not isinstance(rules, dict):
                # Simple type shortcut: "PORT": "port"
                rules = {"type": str(rules)}

            is_required = rules.get("required", False)
            default_val = rules.get("default")
            entry = entry_map.get(var_name)

            if entry is None or not entry.value.strip():
                if is_required and default_val is None:
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="missing_required",
                            message=f"Required environment variable '{var_name}' is missing or empty.",
                            expected="Required value",
                            actual=None,
                            line_number=None,
                        )
                    )
                continue

            val = entry.value
            line_no = entry.line_number
            var_type = rules.get("type", "string").lower()

            # Type validations
            if var_type in ("int", "integer"):
                try:
                    int_val = int(val)
                    if "min" in rules and int_val < rules["min"]:
                        errors.append(
                            SchemaValidationError(
                                variable_name=var_name,
                                error_type="range_min",
                                message=f"'{var_name}' must be >= {rules['min']}, got {int_val}.",
                                expected=f">= {rules['min']}",
                                actual=val,
                                line_number=line_no,
                            )
                        )
                    if "max" in rules and int_val > rules["max"]:
                        errors.append(
                            SchemaValidationError(
                                variable_name=var_name,
                                error_type="range_max",
                                message=f"'{var_name}' must be <= {rules['max']}, got {int_val}.",
                                expected=f"<= {rules['max']}",
                                actual=val,
                                line_number=line_no,
                            )
                        )
                except ValueError:
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="type_mismatch",
                            message=f"'{var_name}' must be an integer, got '{val}'.",
                            expected="integer",
                            actual=val,
                            line_number=line_no,
                        )
                    )

            elif var_type == "port":
                try:
                    port = int(val)
                    if not (1 <= port <= 65535):
                        errors.append(
                            SchemaValidationError(
                                variable_name=var_name,
                                error_type="invalid_port",
                                message=f"Port must be between 1 and 65535, got {port}.",
                                expected="1-65535",
                                actual=val,
                                line_number=line_no,
                            )
                        )
                except ValueError:
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="type_mismatch",
                            message=f"'{var_name}' must be a valid port number, got '{val}'.",
                            expected="port integer (1-65535)",
                            actual=val,
                            line_number=line_no,
                        )
                    )

            elif var_type in ("bool", "boolean"):
                valid_bools = {"true", "false", "1", "0", "yes", "no"}
                if val.lower() not in valid_bools:
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="type_mismatch",
                            message=f"'{var_name}' must be a boolean ('true'/'false'/'1'/'0'), got '{val}'.",
                            expected="boolean",
                            actual=val,
                            line_number=line_no,
                        )
                    )

            elif var_type == "enum":
                choices = rules.get("choices") or rules.get("enum") or rules.get("values") or []
                if val not in choices:
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="invalid_enum",
                            message=f"'{var_name}' must be one of {choices}, got '{val}'.",
                            expected=f"one of {choices}",
                            actual=val,
                            line_number=line_no,
                        )
                    )

            elif var_type == "url":
                schemes = rules.get("schemes", ["http", "https", "postgres", "postgresql", "redis", "mongodb"])
                regex_pattern = r"^(" + "|".join(schemes) + r")://[^\s/$.?#].[^\s]*$"
                if not re.match(regex_pattern, val, re.IGNORECASE):
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="invalid_url",
                            message=f"'{var_name}' must be a valid URL starting with {schemes}.",
                            expected=f"valid URL with schemes {schemes}",
                            actual=val,
                            line_number=line_no,
                        )
                    )

            elif var_type == "email":
                if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", val):
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="invalid_email",
                            message=f"'{var_name}' must be a valid email address.",
                            expected="email format (user@domain.com)",
                            actual=val,
                            line_number=line_no,
                        )
                    )

            # Custom regex pattern check
            if "pattern" in rules:
                pat = rules["pattern"]
                if not re.search(pat, val):
                    errors.append(
                        SchemaValidationError(
                            variable_name=var_name,
                            error_type="pattern_mismatch",
                            message=f"'{var_name}' does not match regex pattern /{pat}/.",
                            expected=f"match /{pat}/",
                            actual=val,
                            line_number=line_no,
                        )
                    )

        return errors
