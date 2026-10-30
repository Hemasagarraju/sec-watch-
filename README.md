# SEC WATCH — Web Security Assessment Tool for Authorized Labs

**Offensive Security — Project 2: Web Security Assessment Tool for an Authorized Lab**

SEC WATCH is a beginner-friendly Python web security assessment tool designed for bounded, non-destructive security checks against a student's own web application or an explicitly authorized local training lab. It identifies risk-ranked findings with observed evidence, maps them to OWASP Top 10 and CWE standards, and produces a professional HTML/PDF security assessment report with actionable remediation recommendations and Google Gemini AI insights.

---

## Key Features

- **✨ Gemini AI Security Advisor (Integrated):**
  - Powered by Google Gemini (`gemini-3.5-flash-lite`).
  - **In-Depth Code Fixes:** One-click AI remediation providing tailored Nginx, Apache, and Python/Node code snippets for each vulnerability.
  - **Executive Security Advisory:** Generates a personalized high-level assessment summary and prioritized roadmap for developers.
  - **Zero Third-Party Dependencies:** Built entirely with Python's standard library (`urllib.request`).
  - **Secure Storage:** API key stored safely in `.env` (automatically protected in `.gitignore`).

- **Risk-Based Findings (High / Medium / Low):**
  - **High Risk:**
    - Exposed environment configuration secrets (`/.env` containing database credentials or API keys) — OWASP A05 / CWE-540.
    - Exposed Git repository metadata (`/.git/HEAD` branch ref disclosure) — OWASP A05 / CWE-538.
    - Cleartext password authentication form over unencrypted HTTP — OWASP A02 / CWE-319.
    - Dangerous HTTP `TRACE` method enabled (Cross-Site Tracing / XST vulnerability) — OWASP A05 / CWE-693.
  - **Medium Risk:**
    - Missing Content-Security-Policy (CSP) — OWASP A05 / CWE-693.
    - Missing Strict-Transport-Security (HSTS) on HTTPS — OWASP A02 / CWE-319.
    - Insecure Cookie attributes (missing `Secure`, `HttpOnly`, or `SameSite`) — OWASP A05 / CWE-614.
    - Unencrypted HTTP application origin — OWASP A02 / CWE-319.
    - Directory indexing exposed (`/uploads/`, etc.) — OWASP A01 / CWE-548.
    - Potentially risky HTTP methods advertised (`PUT`, `DELETE`, `CONNECT`) — OWASP A05 / CWE-693.
    - Permissive CORS wildcard configuration — OWASP A05 / CWE-942.
  - **Low Risk:**
    - Missing MIME-sniffing protection (`X-Content-Type-Options: nosniff`) — OWASP A05 / CWE-693.
    - Missing clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`) — OWASP A05 / CWE-1021.
    - Missing `Referrer-Policy` — OWASP A05 / CWE-200.
    - Missing `Permissions-Policy` — OWASP A05 / CWE-693.
    - Server software banner exposed (`Server` header) — OWASP A05 / CWE-200.
    - Technology stack banner exposed (`X-Powered-By` header) — OWASP A05 / CWE-200.
    - Information disclosure in `/robots.txt` — OWASP A05 / CWE-200.

- **OWASP Top 10 (2021) & CWE Mapping:**
  Every finding is tagged with its official OWASP category and Common Weakness Enumeration (CWE) identifier.

- **Executive Reporting (HTML / PDF / JSON):**
  - Visual Security Posture Grade (A to F) & Risk Status.
  - Summary KPI cards (Total Findings, High, Medium, Low).
  - OWASP Top 10 breakdown table.
  - Formatted findings table with risk badges, technical evidence snippets, and clear remediation guidance.
  - Prioritized Remediation Action Plan checklist.
  - Direct **"🖨️ Print / Save as PDF"** button (with `@media print` optimized styling).

- **Intentionally Vulnerable Local Training Lab:**
  - Built-in safe mock target binding exclusively to `127.0.0.1` on a dynamic local port.
  - Demonstrates realistic signals for High, Medium, and Low risk findings without real-world credentials or external connections.

- **Unified Interfaces:**
  - **Interactive Web Command Center (`web_demo/`):** Futuristic cybersecurity SOC dashboard with White/Dark theme toggle, Gemini 3.5 AI interactive remediation drawers, real-time threat filters, and dedicated Security Officer Authentication Gateway (`lohitha`).
  - **Desktop GUI (Tkinter):** Interactive desktop window with real-time risk badges, finding filters (All/High/Medium/Low), Gemini AI advisor popup, and 1-click browser report viewing.
  - **Command-Line Interface (CLI):** Headless assessment supporting `--output` (HTML), `--json` (JSON), and `--ai` (Gemini AI advisory).

---

## Safety Boundaries & Scope

- **Strict Authorization Requirement:** Requires explicit `--authorized` confirmation in CLI or checkbox in GUI.
- **Local/Private Scope Only:** Targets must be `localhost` or a loopback, private (RFC 1918), or link-local IP address. Public domains and external IPs are strictly blocked.
- **Non-Destructive:** Uses only GET requests on a fixed list of paths and OPTIONS on `/`. Never sends POST, PUT, DELETE, fuzzing payloads, or authentication attempts.
- **Proxy & Redirect Isolation:** Proxies are bypassed and redirects are not followed.

---

## Quick Start

### 1. Launch the Desktop App (GUI)
```powershell
python .\run_sec_watch.py
```
1. Target Scope options: Select **"Explicitly Authorized Training Lab"** or **"Student's Own Application"**.
2. Click **"⚡ Launch & Assess Authorized Lab"** for 1-click startup and automated audit.
3. Select any finding and click **"✨ Ask Gemini AI for Code Fix & Remediation"** to get tailored code snippets!
4. Click **Open in Browser** to view your report and print/save it to PDF.

### 2. 1-Click Explicitly Authorized Training Lab Mode (CLI)
Instantly launch, scan, and shut down the built-in explicitly authorized training lab with Gemini AI advisory in a single command:
```powershell
python .\web_security_assessment.py --authorized-training-lab --ai --output reports/sec-watch-report.html --json reports/sec-watch-report.json
```

### 3. Assess a Custom Student-Owned Application (CLI)
```powershell
python .\web_security_assessment.py http://127.0.0.1:8000 --authorized --ai --output reports/sec-watch-report.html --json reports/sec-watch-report.json
```

---

## Running the Unit Tests

Execute the comprehensive test suite:
```powershell
python -m unittest -v test_web_security_assessment.py
```

---

## Project Structure

```text
sec_watch/
  assessment.py       Core engine: target validation, checks, OWASP mapping, HTML & JSON report generation
  gui.py              Tkinter desktop interface with risk badges, filters, and Gemini AI Advisor
  ai_advisor.py       Google Gemini integration (explain findings, generate executive advisory)
  training_lab.py     Intentionally misconfigured loopback training target
  __main__.py         python -m sec_watch launcher
run_sec_watch.py      Desktop application convenience launcher
web_security_assessment.py  CLI assessment launcher with JSON and AI export
test_web_security_assessment.py  Automated unit and integration test suite
web_demo/             Static sample report dashboard for public previews
.env                  Secure configuration for GEMINI_API_KEY (git-ignored)
```
