"""EnvGuard: Zero-dependency environment variables auditor and secret leak detector."""

__version__ = "1.0.0"
__author__ = "Developer"

from envguard.parser import parse_dotenv, EnvEntry
from envguard.detectors import SecretDetector, Finding, Severity
from envguard.schema import EnvSchemaValidator, SchemaValidationError
from envguard.generator import generate_template

__all__ = [
    "__version__",
    "parse_dotenv",
    "EnvEntry",
    "SecretDetector",
    "Finding",
    "Severity",
    "EnvSchemaValidator",
    "SchemaValidationError",
    "generate_template",
]
