"""Tests for secret leak detectors and entropy analysis."""

from envguard.detectors import SecretDetector, Severity, calculate_shannon_entropy
from envguard.parser import parse_dotenv


def test_shannon_entropy_calculation():
    # Low entropy: repetitive characters
    low = calculate_shannon_entropy("aaaaaaaaaa")
    assert low == 0.0

    # Medium entropy: English word
    med = calculate_shannon_entropy("development")
    assert 2.0 < med < 3.5

    # High entropy: Random cryptographic key
    high = calculate_shannon_entropy("7f9b8c2d1e0a4f5b6c8d7e9a0b1c2d3e4f5a6b7c")
    assert high > 3.8


def test_detect_aws_access_key():
    content = "AWS_KEY=" + "AKIA" + "IOSFODNN7EXAMPLE\nREGION=us-east-1"
    entries = parse_dotenv(content, filepath=".env")
    detector = SecretDetector()
    findings = detector.scan(entries)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].variable_name == "AWS_KEY"


def test_detect_openai_api_key():
    token = "sk-" + "proj-" + ("X" * 36)
    content = f"OPENAI_API_KEY={token}"
    entries = parse_dotenv(content, filepath=".env")
    detector = SecretDetector()
    findings = detector.scan(entries)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC002"
    assert findings[0].severity == Severity.CRITICAL


def test_detect_stripe_live_key():
    token = "sk" + "_live_" + ("X" * 26)
    content = f"STRIPE_SECRET={token}"
    entries = parse_dotenv(content, filepath=".env")
    detector = SecretDetector()
    findings = detector.scan(entries)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"
    assert findings[0].severity == Severity.CRITICAL


def test_detect_github_token():
    token = "ghp_" + ("X" * 36)
    content = f"GH_PAT={token}"
    entries = parse_dotenv(content, filepath=".env")
    detector = SecretDetector()
    findings = detector.scan(entries)

    assert any(f.rule_id == "SEC006" for f in findings)


def test_clean_env_no_findings():
    content = """
    PORT=8080
    HOST=0.0.0.0
    NODE_ENV=production
    DATABASE_URL=postgres://localhost:5432/myapp
    OPENAI_API_KEY=your_openai_api_key_here
    STRIPE_SECRET_KEY=your_stripe_secret_key_here
    ENABLE_FEATURE=true
    """
    entries = parse_dotenv(content, filepath=".env")
    detector = SecretDetector()
    findings = detector.scan(entries)

    assert len(findings) == 0
