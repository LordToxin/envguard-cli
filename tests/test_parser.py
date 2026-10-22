"""Tests for the .env parser module."""

from envguard.parser import parse_dotenv, EnvEntry


def test_parse_simple_key_value():
    content = "PORT=3000\nHOST=localhost"
    entries = parse_dotenv(content, filepath=".env")
    assert len(entries) == 2
    assert entries[0].key == "PORT"
    assert entries[0].value == "3000"
    assert entries[0].line_number == 1
    assert entries[1].key == "HOST"
    assert entries[1].value == "localhost"
    assert entries[1].line_number == 2


def test_parse_quotes_and_escapes():
    content = '''
    SINGLE_VAL='single quoted string'
    DOUBLE_VAL="double quoted string"
    ESCAPED_VAL="line1\\nline2"
    '''
    entries = parse_dotenv(content, filepath=".env")
    assert len(entries) == 3
    assert entries[0].key == "SINGLE_VAL"
    assert entries[0].value == "single quoted string"
    assert entries[1].key == "DOUBLE_VAL"
    assert entries[1].value == "double quoted string"


def test_parse_export_prefix():
    content = "export API_KEY=secret123\nexport DEBUG=true"
    entries = parse_dotenv(content, filepath=".env")
    assert len(entries) == 2
    assert entries[0].key == "API_KEY"
    assert entries[0].value == "secret123"
    assert entries[1].key == "DEBUG"
    assert entries[1].value == "true"


def test_parse_comments_and_empty_lines():
    content = """
    # This is a header comment
    APP_NAME=SuperApp

    # Database configuration
    DB_PORT=5432 # inline comment
    """
    entries = parse_dotenv(content, filepath=".env")
    assert len(entries) == 2
    assert entries[0].key == "APP_NAME"
    assert entries[0].value == "SuperApp"
    assert entries[1].key == "DB_PORT"
    assert entries[1].value == "5432"
