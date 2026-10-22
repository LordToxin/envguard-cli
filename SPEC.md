# SPEC: EnvGuard CLI & Audit Daemon (`envguard-cli`)

## 1. Executive Summary & Vision
`envguard-cli` is a high-performance, zero-dependency environment configuration and secrets security auditor designed for modern engineering teams and Solo Builders. It prevents sensitive production credentials from leaking into Git repositories, enforces strict schema typing on environment variables (types, ranges, enums, regex patterns), automates sanitized `.env.example` generation, and outputs native GitHub SARIF 2.1.0 and JSON reports for CI/CD gates.

## 2. Target Audience & Problem Statement
- **Problem**: Over 100,000 developers leak AWS, Stripe, and OpenAI tokens to GitHub every year, incurring unexpected cloud bills or catastrophic security breaches. Teams frequently suffer deployment crashes due to missing or mistyped `.env` parameters (e.g. `PORT="abc"`, missing `DATABASE_URL`).
- **Target Audience**: Fullstack developers, DevOps engineers, Micro-SaaS founders, Indie Hackers, Enterprise CI/CD pipelines.

## 3. Architecture & Core Modules
```
envguard/
  ├── __init__.py        # Package version and public API
  ├── cli.py             # CLI parser, command dispatcher, exit code handler
  ├── detectors.py       # Regex & Shannon entropy secret detection rules (25+ patterns)
  ├── schema.py          # Schema validation engine (int, bool, url, email, enum, regex)
  ├── parser.py          # Robust .env parser with multiline & export syntax support
  ├── generator.py       # Smart .env.example / template synthesizer
  ├── reporters.py       # CLI ANSI table, JSON, and GitHub SARIF 2.1.0 reporters
  └── server.py          # Lightweight built-in HTTP audit API and inspection UI
```

## 4. Key Functional Requirements
1. **Secret Detection (`envguard audit <file/dir>`)**:
   - High-entropy analysis: Flag high-randomness string tokens.
   - Known signatures: AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, Private Keys (RSA, EC, OpenSSH), Database URIs, JWT.
2. **Schema Compliance (`envguard check --schema <schema.json>`)**:
   - Validate `.env` against JSON schema rules: type constraints, required flags, port ranges, email formats, enum options.
3. **Template Synthesizer (`envguard template`)**:
   - Mask secret values into helpful placeholders (e.g., `sk-ant-...` -> `your_anthropic_api_key_here`).
4. **CI/CD Integration (`envguard scan --ci`)**:
   - Returns exit code `0` on clean state, `1` on critical secret leaks, `2` on schema violations.
   - Generates standard SARIF 2.1.0 files for GitHub Code Scanning alerts.
5. **Local HTTP Daemon (`envguard serve`)**:
   - Serves `GET /api/health`, `POST /api/audit`, `POST /api/validate`, and an interactive web audit UI.

## 5. Monetization & Commercial Potential
- **Open-Core Engine**: Free standalone CLI for individual developers.
- **Pro / Team License ($49/year or $9/mo/seat)**:
  - Centralized team secret drift alerts.
  - Integration with 1Password / Vault / AWS Secrets Manager export pipelines.
- **GitHub Marketplace Action / App ($15/repo/month)**:
  - Managed GitHub Action bot with PR annotations, blocking merges with exposed secrets.
- **GitHub Sponsors & Custom Enterprise Rulesets**:
  - Custom secret regexpacks for proprietary internal API formats.
