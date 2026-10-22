"""Tests for template generation and sanitization."""

from envguard.generator import generate_template


def test_generate_template_sanitization():
    openai_token = "sk-" + "proj-" + ("X" * 36)
    stripe_token = "sk" + "_live_" + ("X" * 26)
    source_env = f"""
    # Application Config
    PORT=3000
    HOST=0.0.0.0
    
    # Secrets
    OPENAI_API_KEY={openai_token}
    STRIPE_SECRET_KEY={stripe_token}
    DATABASE_URL=postgres://root:SuperSecretPassword123@prod.db.internal:5432/main
    """

    template = generate_template(source_env)

    # Secrets should not be present in output
    assert "XXXXXXXXXX" not in template
    assert "SuperSecretPassword123" not in template

    # Placeholders should be present
    assert "OPENAI_API_KEY=sk-your-openai-api-key-here" in template
    assert "STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key" in template
    assert "PORT=3000" in template
