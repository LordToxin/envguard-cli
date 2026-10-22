"""Secret leak detection engine with entropy calculation and provider-specific pattern matching."""

from dataclasses import dataclass
from enum import Enum
import math
import re
from typing import Dict, List, Optional

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    filepath: str
    line_number: int
    variable_name: str
    masked_value: str
    recommendation: str

def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string to estimate randomness."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def mask_secret(value: str) -> str:
    """Safely mask a sensitive token for display."""
    if len(value) <= 6:
        return "*" * len(value)
    if len(value) <= 12:
        return value[:2] + ("*" * (len(value) - 4)) + value[-2:]
    return value[:4] + ("*" * (len(value) - 8)) + value[-4:]

RULE_PATTERNS = [
    {
        "id": "SEC001",
        "name": "AWS Access Key ID",
        "pattern": r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        "severity": Severity.CRITICAL,
        "desc": "Found an AWS Access Key ID",
        "rec": "Revoke this key in AWS IAM and inject via AWS Secrets Manager or IAM Instance Roles.",
    },
    {
        "id": "SEC002",
        "name": "OpenAI API Key",
        "pattern": r"\bsk-(?:proj-)?[a-zA-Z0-9_\-]{32,}\b",
        "severity": Severity.CRITICAL,
        "desc": "Exposed OpenAI API Key",
        "rec": "Rotate key in OpenAI Dashboard and configure as encrypted deployment secret.",
    },
    {
        "id": "SEC003",
        "name": "Anthropic Claude API Key",
        "pattern": r"\bsk-ant-[a-zA-Z0-9_\-]{32,}\b",
        "severity": Severity.CRITICAL,
        "desc": "Exposed Anthropic Claude API Key",
        "rec": "Rotate key in Anthropic Console immediately.",
    },
    {
        "id": "SEC004",
        "name": "Stripe Live Secret Key",
        "pattern": r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b",
        "severity": Severity.CRITICAL,
        "desc": "Production Stripe API Secret Key",
        "rec": "Immediately revoke and roll this live Stripe key in the Stripe Dashboard to prevent unauthorized charges.",
    },
    {
        "id": "SEC005",
        "name": "Stripe Publishable/Test Key in Backend Secret",
        "pattern": r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b",
        "severity": Severity.MEDIUM,
        "desc": "Stripe Test Secret Key committed to environment",
        "rec": "Ensure test keys are separated from production and kept out of public repositories.",
    },
    {
        "id": "SEC006",
        "name": "GitHub Personal Access Token",
        "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b",
        "severity": Severity.CRITICAL,
        "desc": "GitHub Personal Access or OAuth Token",
        "rec": "Revoke token under GitHub Settings -> Developer settings -> Personal access tokens.",
    },
    {
        "id": "SEC007",
        "name": "Google API Key",
        "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "severity": Severity.HIGH,
        "desc": "Google Cloud / Firebase API Key",
        "rec": "Restrict API key permissions and HTTP referrers in Google Cloud Console.",
    },
    {
        "id": "SEC008",
        "name": "Slack Bot/User Token",
        "pattern": r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*\b",
        "severity": Severity.CRITICAL,
        "desc": "Slack OAuth / Bot Access Token",
        "rec": "Revoke the Slack App credential and reinstall app.",
    },
    {
        "id": "SEC009",
        "name": "Slack Webhook URL",
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+",
        "severity": Severity.HIGH,
        "desc": "Slack Incoming Webhook URL with secret path",
        "rec": "Regenerate webhook URL in Slack App settings.",
    },
    {
        "id": "SEC010",
        "name": "SendGrid API Key",
        "pattern": r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b",
        "severity": Severity.CRITICAL,
        "desc": "SendGrid Mailer API Key",
        "rec": "Rotate key in SendGrid dashboard to prevent email spoofing/spam abuse.",
    },
    {
        "id": "SEC011",
        "name": "Database URI with Hardcoded Password",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://(?:[^:]+):([^@\s/]+)@",
        "severity": Severity.CRITICAL,
        "desc": "Database connection string containing plaintext user/password credentials",
        "rec": "Use environment variables for database user and password or use IAM authentication.",
    },
    {
        "id": "SEC012",
        "name": "Private Cryptographic Key",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "desc": "Plaintext private asymmetric key",
        "rec": "Store private keys in a Hardware Security Module (HSM) or cloud KMS. Do not keep in source control.",
    },
    {
        "id": "SEC013",
        "name": "JSON Web Token (JWT)",
        "pattern": r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
        "severity": Severity.MEDIUM,
        "desc": "Hardcoded JSON Web Token",
        "rec": "Tokens expire and carry claims; generate tokens dynamically at runtime.",
    },
    {
        "id": "SEC014",
        "name": "Twilio Auth Token / Account SID",
        "pattern": r"\bAC[a-f0-9]{32}\b",
        "severity": Severity.HIGH,
        "desc": "Twilio Account SID",
        "rec": "Verify Twilio credentials are kept in encrypted vault.",
    },
]

SUSPICIOUS_KEY_REGEX = re.compile(
    r"(?:SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN|BEARER_TOKEN|ENCRYPTION_KEY)",
    re.IGNORECASE,
)

class SecretDetector:
    """Scans parsed environment entries or plain text for sensitive tokens and entropy leaks."""

    def __init__(self, entropy_threshold: float = 4.2):
        self.entropy_threshold = entropy_threshold
        self.compiled_rules = [
            {
                "id": rule["id"],
                "name": rule["name"],
                "regex": re.compile(rule["pattern"]),
                "severity": rule["severity"],
                "desc": rule["desc"],
                "rec": rule["rec"],
            }
            for rule in RULE_PATTERNS
        ]

    def scan_entry(self, entry) -> List[Finding]:
        """Scan a single EnvEntry for secret leaks."""
        findings: List[Finding] = []
        val = entry.value.strip()

        # Check known signatures
        for rule in self.compiled_rules:
            if rule["regex"].search(val) or rule["regex"].search(entry.raw_line):
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        description=rule["desc"],
                        filepath=entry.filepath,
                        line_number=entry.line_number,
                        variable_name=entry.key,
                        masked_value=mask_secret(val),
                        recommendation=rule["rec"],
                    )
                )

        # High entropy check for suspicious variable names
        if SUSPICIOUS_KEY_REGEX.search(entry.key) and len(val) >= 16:
            # Check if already caught by a specific rule
            already_caught = any(f.rule_id != "SEC999" for f in findings)
            if not already_caught:
                entropy = calculate_shannon_entropy(val)
                if entropy >= self.entropy_threshold:
                    findings.append(
                        Finding(
                            rule_id="SEC999",
                            rule_name="High Entropy Sensitive Value",
                            severity=Severity.HIGH,
                            description=f"Variable '{entry.key}' contains high-entropy string (entropy {entropy:.2f})",
                            filepath=entry.filepath,
                            line_number=entry.line_number,
                            variable_name=entry.key,
                            masked_value=mask_secret(val),
                            recommendation="Check if this is a raw secret. Move to cloud secrets manager.",
                        )
                    )

        return findings

    def scan_entries(self, entries: List) -> List[Finding]:
        """Scan a collection of EnvEntry objects."""
        all_findings: List[Finding] = []
        for entry in entries:
            all_findings.extend(self.scan_entry(entry))
        return all_findings

    def scan(self, entries: List) -> List[Finding]:
        """Alias for scan_entries."""
        return self.scan_entries(entries)

    def scan(self, target) -> List[Finding]:
        """Scan entries list, single entry, or raw text string."""
        if isinstance(target, str):
            from envguard.parser import parse_dotenv
            entries = parse_dotenv(target)
            return self.scan_entries(entries)
        elif isinstance(target, list):
            return self.scan_entries(target)
        else:
            return self.scan_entry(target)
