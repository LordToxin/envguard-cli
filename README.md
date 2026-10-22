# 🛡️ EnvGuard CLI & Security Daemon

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Runtime Dependencies](https://img.shields.io/badge/dependencies-0%20runtime-success.svg)](#features)
[![Tests Passing](https://img.shields.io/badge/tests-25%2F25%20passing-brightgreen.svg)](tests/)
[![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED.svg)](Dockerfile)

> **Zero-dependency environment variables auditor, secret leak detector, and schema validator for modern dev teams and Solo Builders.**

```
   ______              ______                     __
  / ____/___  _   __  / ____/_  ______ __________/ /
 / __/ / __ \| | / / / / __/ / / / __ `/ ___/ __  / 
/ /___/ / / /| |/ / / /_/ / /_/ / /_/ / /  / /_/ /  
\____/_/ /_/ |___/  \____/\__,_/\__,_/_/   \__,_/   
  High-Performance Environment Configuration & Secrets Engine
```

---

## ⚡ The Problem & The Solution

Every year, developers and startups accidentally commit live AWS credentials, Stripe private keys, and OpenAI tokens to git repositories, costing thousands of dollars in unauthorized usage or catastrophic database breaches. Furthermore, microservices frequently crash in staging or production because a required environment variable is missing or has the wrong type (`PORT="abc"`).

**EnvGuard solves both problems in a single, zero-dependency binary / package:**
1. **Detects 25+ secret patterns & high-entropy tokens** before code gets committed.
2. **Enforces strict schema validation** (types, ranges, enums, URLs, ports).
3. **Generates sanitized `.env.example` files** automatically.
4. **Outputs native GitHub SARIF 2.1.0 and JSON reports** for CI/CD gates.
5. **Includes a local HTTP daemon & real-time web dashboard** for interactive auditing.

---

## 🚀 Quick Start in 1 Command

### Option A: Local Installation (Pure Python Standard Library)
```bash
# Clone or navigate to the directory
cd envguard-cli

# Install package
pip install .

# Audit current directory for leaked secrets
envguard audit .env
```

### Option B: Docker / Docker Compose
```bash
docker compose up -d
# Dashboard available at http://localhost:8080
```

---

## 🛠️ CLI Command Reference

### 1. `envguard audit [path]`
Scans `.env` files or directories for known secret patterns (AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, DB passwords, JWT) and high Shannon-entropy tokens.
```bash
envguard audit .env
envguard audit ./config --format json
envguard audit . --format sarif --output audit.sarif
```

### 2. `envguard check [path] --schema [schema.json]`
Validates environment parameters against schema rules (ports, integers, enums, booleans, URLs, emails, regexes).
```bash
envguard check .env --schema envguard.schema.json
```

### 3. `envguard scan [path] --ci`
Combines secret leak detection and schema verification. Returns non-zero exit codes for broken builds (`1` on secret leak, `2` on schema violation).
```bash
envguard scan .env --schema envguard.schema.json --ci
```

### 4. `envguard template [source] [--output .env.example]`
Reads active `.env` or scans codebase for `process.env` / `os.environ` calls and generates a clean, sanitized `.env.example` with masked placeholders.
```bash
envguard template .env --output .env.example
```

### 5. `envguard init-schema [source]`
Infers a starter `.envguard.json` schema from an existing `.env` file.
```bash
envguard init-schema .env --output envguard.schema.json
```

### 6. `envguard serve [--port 8080]`
Launches the embedded HTTP daemon and modern web dashboard for browser-based auditing and REST integrations.
```bash
envguard serve --port 8080
# Visit http://127.0.0.1:8080 in your browser
```

---

## 🤖 GitHub Actions CI/CD Integration

Block pull requests with leaked secrets and populate GitHub Security tab using native SARIF 2.1.0 output:

```yaml
name: Security & Env Compliance
on: [push, pull_request]

jobs:
  envguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install EnvGuard
        run: pip install .

      - name: Run Secret Audit & Generate SARIF
        run: envguard audit . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 💼 Monetization & Commercial Potential

EnvGuard is built with an **Open-Core Commercialization Model** targeting developers, tech leads, and security teams:

| Tier | Price | Features |
| :--- | :--- | :--- |
| **Community (OSS)** | **Free / MIT** | Standalone CLI, 25+ secret detectors, schema linter, SARIF exporter, local web UI. |
| **Pro / Indie Hacker** | **$49 / year** | Pre-commit git hooks manager, automated 1Password/Vault export sync, Slack notifications. |
| **Team / Enterprise** | **$19 / seat / mo** | Centralized team env-drift dashboard, encrypted secrets sync, SOC-2 compliance audit logs. |
| **GitHub Marketplace App**| **$12 / repo / mo** | Zero-config PR comment bot with automated inline remediation suggestions. |

### Commercial Expansion Roadmap:
1. **Cloud Sync Micro-SaaS**: A lightweight backend where teams encrypt `.env` files end-to-end and share variables across staging/production without raw values touching Slack or email.
2. **Sponsorware Custom Rulesets**: Proprietary rule packs for FinTech, Healthcare (HIPAA), and Web3/Crypto private keys.

---

## 🧪 Testing & Verification

EnvGuard includes a comprehensive test suite covering all modules:

```bash
# Run test suite
pytest -v

# Run with test coverage
pytest --cov=envguard tests/
```

Results: **25 passed, 0 failed, 100% green**.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
