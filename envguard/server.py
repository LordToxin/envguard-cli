"""Lightweight embedded HTTP daemon and interactive web audit dashboard for EnvGuard."""

import http.server
import json
import urllib.parse
from typing import Tuple

from envguard import __version__
from envguard.detectors import SecretDetector
from envguard.generator import generate_template
from envguard.parser import parse_dotenv
from envguard.schema import EnvSchemaValidator

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EnvGuard | Secrets Audit & Schema Security</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: rgba(23, 32, 54, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #38bdf8;
      --primary-hover: #0284c7;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --success: #10b981;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --font-mono: "Fira Code", monospace, Consolas;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, var(--bg) 70%);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      padding: 1.5rem 2rem;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      backdrop-filter: blur(12px);
      background: rgba(11, 15, 25, 0.8);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.025em;
    }
    .badge {
      background: rgba(56, 189, 248, 0.15);
      color: var(--primary);
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    main {
      max-width: 1200px;
      width: 100%;
      margin: 2rem auto;
      padding: 0 1.5rem;
      flex: 1;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
    }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      backdrop-filter: blur(16px);
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .panel h2 {
      font-size: 1.1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    textarea {
      width: 100%;
      height: 340px;
      background: #060911;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      color: #38bdf8;
      font-family: var(--font-mono);
      font-size: 0.85rem;
      padding: 1rem;
      resize: vertical;
      line-height: 1.5;
      outline: none;
    }
    textarea:focus { border-color: var(--primary); }
    .btn-group {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    button {
      background: var(--primary);
      color: #0b0f19;
      font-weight: 600;
      border: none;
      border-radius: 6px;
      padding: 0.6rem 1.2rem;
      cursor: pointer;
      transition: all 0.15s ease;
      font-size: 0.85rem;
    }
    button:hover { background: var(--primary-hover); color: #fff; }
    button.secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
    }
    button.secondary:hover { background: rgba(255, 255, 255, 0.15); }
    .metrics {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 0.5rem;
    }
    .metric-card {
      background: rgba(0, 0, 0, 0.25);
      border-radius: 8px;
      padding: 0.75rem;
      text-align: center;
      border: 1px solid var(--card-border);
    }
    .metric-val { font-size: 1.4rem; font-weight: 700; margin-top: 0.25rem; }
    .results-box {
      flex: 1;
      overflow-y: auto;
      max-height: 480px;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .finding-card {
      background: rgba(0, 0, 0, 0.3);
      border-left: 4px solid var(--critical);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
    }
    .finding-card.high { border-left-color: var(--high); }
    .finding-card.medium { border-left-color: var(--medium); }
    .finding-card.low { border-left-color: var(--low); }
    .finding-title {
      font-weight: 600;
      display: flex;
      justify-content: space-between;
      margin-bottom: 0.35rem;
    }
    .clean-msg {
      padding: 3rem 1rem;
      text-align: center;
      color: var(--success);
      font-size: 1.1rem;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>🛡️</span>
      <span>EnvGuard Audit Daemon</span>
      <span class="badge">v__VERSION__</span>
    </div>
    <div style="font-size: 0.85rem; color: var(--text-muted);">
      Commercial Security Auditor for Developers
    </div>
  </header>
  <main>
    <section class="panel">
      <h2>
        <span>Environment Variables Input</span>
        <span style="font-size:0.8rem; color:var(--text-muted);" id="lineCount">0 lines</span>
      </h2>
      <div class="btn-group">
        <button type="button" class="secondary" onclick="loadSample('leaky')">Sample: Secret Leaks</button>
        <button type="button" class="secondary" onclick="loadSample('clean')">Sample: Safe Clean</button>
      </div>
      <textarea id="envInput" placeholder="Paste your .env contents here..."></textarea>
      <div class="btn-group">
        <button type="button" onclick="runAudit()">🚀 Audit Secrets</button>
        <button type="button" class="secondary" onclick="generateCleanTemplate()">✨ Synthesize .env.example</button>
      </div>
    </section>

    <section class="panel">
      <h2>Audit Findings & Security Analysis</h2>
      <div class="metrics">
        <div class="metric-card">
          <div style="color:var(--text-muted); font-size:0.7rem;">CRITICAL</div>
          <div class="metric-val" id="cntCritical" style="color:var(--critical);">0</div>
        </div>
        <div class="metric-card">
          <div style="color:var(--text-muted); font-size:0.7rem;">HIGH</div>
          <div class="metric-val" id="cntHigh" style="color:var(--high);">0</div>
        </div>
        <div class="metric-card">
          <div style="color:var(--text-muted); font-size:0.7rem;">MEDIUM</div>
          <div class="metric-val" id="cntMedium" style="color:var(--medium);">0</div>
        </div>
        <div class="metric-card">
          <div style="color:var(--text-muted); font-size:0.7rem;">SAFE</div>
          <div class="metric-val" id="cntSafe" style="color:var(--success);">0</div>
        </div>
      </div>
      <div class="results-box" id="resultsBox">
        <div class="clean-msg">Paste an environment configuration and click "Audit Secrets" to inspect.</div>
      </div>
    </section>
  </main>

  <script>
    const SAMPLES = {
      leaky: [
        'PORT=3000',
        'DATABASE_URL=postgres://root:SuperSecretP@ssw0rd!@db.production.internal:5432/app',
        'OPENAI_API_KEY=' + 'sk-' + 'dummy-mock-token-not-a-real-key',
        'STRIPE_SECRET_KEY=' + 'sk_test_' + 'mockkeydummy1234567890',
        'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'JWT_SECRET=super_secret_jwt_hmac_sha256_token_key_here',
        'GITHUB_TOKEN=' + 'ghp_' + 'mockkeydummy1234567890'
      ].join('\n'),
      clean: `PORT=8080
HOST=0.0.0.0
NODE_ENV=production
DATABASE_URL=postgres://user:password@localhost:5432/myapp
OPENAI_API_KEY=your_openai_api_key_here
STRIPE_SECRET_KEY=your_stripe_secret_key_here
ENABLE_METRICS=true`
    };

    function loadSample(key) {
      document.getElementById('envInput').value = SAMPLES[key] || '';
      updateLineCount();
      runAudit();
    }

    function updateLineCount() {
      const txt = document.getElementById('envInput').value;
      const count = txt ? txt.split('\\n').length : 0;
      document.getElementById('lineCount').textContent = count + ' lines';
    }

    document.getElementById('envInput').addEventListener('input', updateLineCount);

    async function runAudit() {
      const content = document.getElementById('envInput').value;
      if (!content.trim()) return;

      try {
        const res = await fetch('/api/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        const data = await res.json();
        renderResults(data);
      } catch (err) {
        alert('Audit failed: ' + err.message);
      }
    }

    async function generateCleanTemplate() {
      const content = document.getElementById('envInput').value;
      if (!content.trim()) return;

      try {
        const res = await fetch('/api/template', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        const data = await res.json();
        document.getElementById('envInput').value = data.template;
        updateLineCount();
        runAudit();
      } catch (err) {
        alert('Template generation failed: ' + err.message);
      }
    }

    function renderResults(data) {
      const box = document.getElementById('resultsBox');
      box.innerHTML = '';

      let crit = 0, high = 0, med = 0;
      if (!data.findings || data.findings.length === 0) {
        box.innerHTML = '<div class="clean-msg">✅ Clean Configuration! No secret leaks or exposed credentials detected.</div>';
        document.getElementById('cntCritical').textContent = 0;
        document.getElementById('cntHigh').textContent = 0;
        document.getElementById('cntMedium').textContent = 0;
        document.getElementById('cntSafe').textContent = data.total_variables || 0;
        return;
      }

      data.findings.forEach(f => {
        if (f.severity === 'CRITICAL') crit++;
        else if (f.severity === 'HIGH') high++;
        else med++;

        const card = document.createElement('div');
        const sevClass = f.severity.toLowerCase();
        card.className = 'finding-card ' + sevClass;
        card.innerHTML = `
          <div class="finding-title">
            <span>\${f.rule_name}</span>
            <span class="badge" style="background:rgba(255,255,255,0.1);">\${f.severity}</span>
          </div>
          <div style="color:var(--text-muted); font-size:0.75rem; margin-bottom:0.35rem;">
            Variable: <strong style="color:var(--text);">\${f.variable_name}</strong> | Line: \${f.line_number}
          </div>
          <div style="font-family:var(--font-mono); font-size:0.75rem; background:rgba(0,0,0,0.4); padding:0.3rem 0.5rem; border-radius:4px; margin-bottom:0.35rem;">
            \${f.masked_value}
          </div>
          <div style="font-size:0.75rem; color:#38bdf8;">
            💡 \${f.recommendation}
          </div>
        `;
        box.appendChild(card);
      });

      document.getElementById('cntCritical').textContent = crit;
      document.getElementById('cntHigh').textContent = high;
      document.getElementById('cntMedium').textContent = med;
      document.getElementById('cntSafe').textContent = Math.max(0, (data.total_variables || 0) - data.findings.length);
    }

    // Initialize with leaky sample for instant demo
    loadSample('leaky');
  </script>
</body>
</html>
""".replace("__VERSION__", __version__)


class EnvGuardRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for EnvGuard daemon and API."""

    def _send_response(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self._send_response(204, "text/plain", b"")

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in {"/", "/index.html"}:
            body = DASHBOARD_HTML.encode("utf-8")
            self._send_response(200, "text/html; charset=utf-8", body)
            return

        if path in {"/health", "/api/health"}:
            resp = {
                "status": "ok",
                "version": __version__,
                "service": "EnvGuard Security Daemon",
            }
            body = json.dumps(resp).encode("utf-8")
            self._send_response(200, "application/json", body)
            return

        self._send_response(404, "application/json", json.dumps({"error": "Not Found"}).encode("utf-8"))

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        raw_data = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Parse request body
        content_text = ""
        schema_dict = None

        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                payload = json.loads(raw_data)
                content_text = payload.get("content", "")
                schema_dict = payload.get("schema")
            except Exception:
                self._send_response(400, "application/json", json.dumps({"error": "Invalid JSON"}).encode("utf-8"))
                return
        else:
            content_text = raw_data

        if path == "/api/audit":
            entries = parse_dotenv(content_text, filepath="memory://.env")
            detector = SecretDetector()
            findings = detector.scan(entries)

            resp = {
                "total_variables": len(entries),
                "total_findings": len(findings),
                "status": "failed" if findings else "passed",
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "rule_name": f.rule_name,
                        "severity": f.severity.value,
                        "description": f.description,
                        "variable_name": f.variable_name,
                        "masked_value": f.masked_value,
                        "recommendation": f.recommendation,
                        "line_number": f.line_number,
                    }
                    for f in findings
                ],
            }
            self._send_response(200, "application/json", json.dumps(resp).encode("utf-8"))
            return

        elif path == "/api/template":
            template = generate_template(content_text)
            resp = {"template": template}
            self._send_response(200, "application/json", json.dumps(resp).encode("utf-8"))
            return

        elif path == "/api/validate":
            entries = parse_dotenv(content_text, filepath="memory://.env")
            errors = []
            if schema_dict:
                validator = EnvSchemaValidator(schema_dict)
                errors = validator.validate(entries)

            resp = {
                "total_errors": len(errors),
                "errors": [
                    {
                        "variable_name": e.variable_name,
                        "error_type": e.error_type,
                        "message": e.message,
                        "expected": e.expected,
                        "actual": e.actual,
                        "line_number": e.line_number,
                    }
                    for e in errors
                ],
            }
            self._send_response(200, "application/json", json.dumps(resp).encode("utf-8"))
            return

        self._send_response(404, "application/json", json.dumps({"error": "Endpoint Not Found"}).encode("utf-8"))


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run HTTP server daemon using multi-threaded request handler."""
    server_address = (host, port)
    httpd = http.server.ThreadingHTTPServer(server_address, EnvGuardRequestHandler)
    httpd.serve_forever()
