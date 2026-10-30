#!/usr/bin/env python3
"""Non-destructive security checks for an explicitly authorized local lab."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import sys
import threading
import time
from http.client import HTTPMessage
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

USER_AGENT = "SEC-WATCH-Authorized-Lab-Assessment/1.0"
MAX_BODY_BYTES = 64 * 1024
DIRECTORY_PATHS = ("/admin/", "/backup/", "/uploads/", "/.git/", "/server-status")
SENSITIVE_FILE_PATHS = ("/.env", "/.git/HEAD", "/robots.txt")


class AssessmentError(Exception):
    """Raised when an assessment cannot safely or reliably continue."""


@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    recommendation: str
    owasp: str = "A05:2021 - Security Misconfiguration"
    cwe: str = "CWE-693"


def parse_target(value: str) -> tuple[str, str, int, str]:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as exc:
        raise AssessmentError("Target URL is malformed.") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise AssessmentError("Target must be an http:// or https:// URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AssessmentError("Target URL cannot contain credentials, query, or fragment.")
    if parsed.path not in ("", "/"):
        raise AssessmentError("Specify only the application origin, not a path.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AssessmentError("Target URL contains an invalid port.") from exc
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise AssessmentError("Target port is outside the valid range.")

    host = parsed.hostname.lower()
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise AssessmentError(
                "For safety, use localhost or a private IP address; DNS hostnames are not allowed."
            ) from exc
        if address.is_global or address.is_multicast or address.is_unspecified:
            raise AssessmentError("Public, multicast, and unspecified IP addresses are not allowed.")
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise AssessmentError("Target must be a loopback, private, or link-local IP address.")

    authority = f"[{host}]" if ":" in host else host
    origin = f"{parsed.scheme}://{authority}:{port}"
    return origin, parsed.scheme, port, host


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class LabAssessment:
    def __init__(
        self,
        origin: str,
        scheme: str,
        timeout: float,
        cancel_event: threading.Event | None = None,
    ):
        self.origin = origin
        self.scheme = scheme
        self.timeout = timeout
        self.cancel_event = cancel_event
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirectHandler
        )
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.request_count = 0

    def request(self, path: str, method: str = "GET") -> tuple[int, HTTPMessage, bytes]:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise AssessmentError("Assessment cancelled.")
        request = urllib.request.Request(
            self.origin + path,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            method=method,
        )
        self.request_count += 1
        time.sleep(0.05)
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                return error.code, error.headers, b""
            return error.code, error.headers, error.read(MAX_BODY_BYTES)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AssessmentError(f"{method} {path} failed: {exc}") from exc
        with response:
            return response.status, response.headers, response.read(MAX_BODY_BYTES)

    def add(
        self,
        severity: str,
        title: str,
        evidence: str,
        recommendation: str,
        owasp: str = "A05:2021 - Security Misconfiguration",
        cwe: str = "CWE-693",
    ) -> None:
        self.findings.append(Finding(severity, title, evidence, recommendation, owasp, cwe))

    def assess_headers(self, header_map: HTTPMessage) -> None:
        if not header_map.get("Content-Security-Policy"):
            self.add(
                "Medium",
                "Content Security Policy is missing",
                "The root response does not include Content-Security-Policy.",
                "Define a restrictive Content-Security-Policy, starting with default-src 'self', "
                "and allow only required sources.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-693",
            )
        if not header_map.get("X-Content-Type-Options"):
            self.add(
                "Low",
                "MIME-sniffing protection is missing",
                "The root response does not include X-Content-Type-Options.",
                "Set X-Content-Type-Options: nosniff.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-693",
            )
        if not header_map.get("X-Frame-Options") and "frame-ancestors" not in (
            header_map.get("Content-Security-Policy", "").lower()
        ):
            self.add(
                "Low",
                "Clickjacking protection is missing",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
                "Set an appropriate Content-Security-Policy frame-ancestors directive; "
                "X-Frame-Options may be used for legacy clients.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-1021",
            )
        if not header_map.get("Referrer-Policy"):
            self.add(
                "Low",
                "Referrer Policy is missing",
                "The root response does not include Referrer-Policy.",
                "Set Referrer-Policy to a deliberate value such as strict-origin-when-cross-origin.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-200",
            )
        if not header_map.get("Permissions-Policy"):
            self.add(
                "Low",
                "Permissions Policy is missing",
                "The root response does not include Permissions-Policy.",
                "Disable browser features the application does not use with Permissions-Policy.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-693",
            )
        if self.scheme == "https" and not header_map.get("Strict-Transport-Security"):
            self.add(
                "Medium",
                "HTTP Strict Transport Security is missing",
                "The HTTPS root response does not include Strict-Transport-Security.",
                "After confirming HTTPS works across the application, configure HSTS with an "
                "appropriate max-age and includeSubDomains only if all subdomains support HTTPS.",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-319",
            )
        server = header_map.get("Server")
        if server:
            self.add(
                "Low",
                "Server software banner is exposed",
                f"Server response header: {server[:200]}",
                "Remove or generalize the Server header where practical; keep software patched.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-200",
            )
        powered_by = header_map.get("X-Powered-By")
        if powered_by:
            self.add(
                "Low",
                "Technology stack banner exposed via X-Powered-By",
                f"X-Powered-By response header: {powered_by[:200]}",
                "Disable or suppress the X-Powered-By header in web application configuration to prevent framework profiling.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-200",
            )
        cors_origin = header_map.get("Access-Control-Allow-Origin")
        if cors_origin == "*":
            self.add(
                "Medium",
                "Permissive Cross-Origin Resource Sharing (CORS) wildcard",
                "The response contains Access-Control-Allow-Origin: *.",
                "Restrict CORS origins to explicitly trusted domains rather than wildcard '*' on private or sensitive endpoints.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-942",
            )
        for cookie in header_map.get_all("Set-Cookie", []):
            cookie_name = cookie.split("=", 1)[0].strip() or "(unnamed)"
            missing = []
            attributes = {
                attribute.partition("=")[0].strip().lower()
                for attribute in cookie.split(";")[1:]
            }
            if self.scheme == "https" and "secure" not in attributes:
                missing.append("Secure")
            if "httponly" not in attributes:
                missing.append("HttpOnly")
            if "samesite" not in attributes:
                missing.append("SameSite")
            if missing:
                self.add(
                    "Medium",
                    f"Cookie {cookie_name} has missing security attributes",
                    f"Set-Cookie for {cookie_name} is missing: {', '.join(missing)}.",
                    "Set Secure on HTTPS cookies, HttpOnly unless JavaScript access is required, "
                    "and an appropriate SameSite value.",
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe="CWE-614",
                )

    def run(self) -> None:
        status, headers, body = self.request("/")
        if status >= 500:
            self.add(
                "Medium",
                "Application root returned a server error",
                f"GET / returned HTTP {status}.",
                "Review application and web-server logs and ensure expected routes are healthy.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-209",
            )
        self.assess_headers(headers)

        root_sample = body[:8192].decode("utf-8", errors="replace").lower()

        if self.scheme == "http":
            self.add(
                "Medium",
                "Application is served over unencrypted HTTP",
                "The target origin uses HTTP rather than HTTPS.",
                "Use HTTPS for applications handling accounts, sessions, or sensitive data; "
                "redirect HTTP to HTTPS in production.",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-319",
            )
            if 'type="password"' in root_sample or "type='password'" in root_sample:
                self.add(
                    "High",
                    "Cleartext password authentication form over unencrypted HTTP",
                    "A password input field was detected on an unencrypted HTTP page at /.",
                    "Enforce HTTPS across all authentication pages to prevent credentials from being intercepted on the network.",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe="CWE-319",
                )

        options_status, options_headers, _ = self.request("/", "OPTIONS")
        allowed = options_headers.get("Allow", "")
        methods = {item.strip().upper() for item in allowed.split(",")} if allowed else set()

        if "TRACE" in methods:
            self.add(
                "High",
                "Dangerous HTTP TRACE method enabled (Cross-Site Tracing risk)",
                f"OPTIONS / advertised TRACE in Allow header: {allowed[:300]}.",
                "Disable the HTTP TRACE method on the web server to prevent Cross-Site Tracing (XST) attacks that steal session cookies.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-693",
            )

        risky_methods = sorted(method for method in ("PUT", "DELETE", "CONNECT") if method in methods)
        if risky_methods:
            self.add(
                "Medium",
                "Potentially risky HTTP methods are advertised",
                f"OPTIONS / returned Allow: {allowed[:300]}; review: {', '.join(risky_methods)}.",
                "Disable methods not required by the application and verify authorization for "
                "any write-capable endpoints.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-693",
            )
        elif options_status in (200, 204) and allowed and "TRACE" not in methods:
            self.add(
                "Low",
                "HTTP methods are advertised",
                f"OPTIONS / returned Allow: {allowed[:300]}.",
                "Confirm that only required methods are enabled and that write operations enforce authorization.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-693",
            )

        for path in DIRECTORY_PATHS:
            status, headers, body = self.request(path)
            sample = body[:4096].decode("utf-8", errors="replace").lower()
            content_type = headers.get("Content-Type", "").lower()
            listing_signatures = ("index of /", "directory listing for", "<title>index of")
            if 200 <= status < 300 and (
                any(signature in sample for signature in listing_signatures)
                or ("directory" in content_type and "listing" in content_type)
            ):
                self.add(
                    "Medium",
                    f"Directory listing may be exposed at {path}",
                    f"GET {path} returned HTTP {status} with directory-listing content.",
                    "Disable directory indexing and ensure private files are outside the web root "
                    "or protected by access controls.",
                    owasp="A01:2021 - Broken Access Control",
                    cwe="CWE-548",
                )

        for path in SENSITIVE_FILE_PATHS:
            status, headers, body = self.request(path)
            sample = body[:4096].decode("utf-8", errors="replace")
            sample_lower = sample.lower()

            if path == "/.env" and 200 <= status < 300:
                env_indicators = (
                    "db_password",
                    "db_host",
                    "app_key",
                    "secret_key",
                    "api_key",
                    "app_env",
                    "database_url",
                )
                if any(indicator in sample_lower for indicator in env_indicators):
                    self.add(
                        "High",
                        "Exposed environment configuration file (/.env)",
                        f"GET /.env returned HTTP {status} containing application configuration secrets: {sample[:120].strip()}...",
                        "Block public web-server access to .env files and relocate sensitive secrets outside the web root.",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-540",
                    )
            elif path == "/.git/HEAD" and 200 <= status < 300:
                if "ref: refs/" in sample or sample.startswith("ref:"):
                    self.add(
                        "High",
                        "Exposed Git repository metadata (/.git/HEAD)",
                        f"GET /.git/HEAD returned HTTP {status} revealing repository branch metadata: {sample[:100].strip()}.",
                        "Configure the web server to block requests to .git directories and version-control metadata files.",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-538",
                    )
            elif path == "/robots.txt" and 200 <= status < 300:
                if "disallow:" in sample_lower or "user-agent:" in sample_lower:
                    self.add(
                        "Low",
                        "Information disclosure in robots.txt",
                        f"GET /robots.txt returned HTTP {status} advertising path restrictions: {sample[:150].strip()}...",
                        "Review robots.txt entries to ensure administrative or private application endpoints are secured with authentication.",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-200",
                    )


def render_json(
    target: str,
    findings: list[Finding],
    errors: list[str],
    requests: int,
    authorization_type: str = "Explicitly Authorized Training Lab",
) -> str:
    """Export assessment findings as structured machine-readable JSON."""
    data = {
        "target": target,
        "authorization_scope": authorization_type,
        "authorized_training_lab": authorization_type == "Explicitly Authorized Training Lab",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "requests_count": requests,
        "safety_boundaries": {
            "destructive_checks_disabled": True,
            "private_loopback_only": True,
            "explicit_authorization_confirmed": True,
        },
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "High"),
            "medium": sum(1 for f in findings if f.severity == "Medium"),
            "low": sum(1 for f in findings if f.severity == "Low"),
        },
        "findings": [asdict(f) for f in findings],
        "errors": errors,
    }
    return json.dumps(data, indent=2)


def render_html(
    target: str,
    findings: list[Finding],
    errors: list[str],
    requests: int,
    ai_summary: str | None = None,
    authorization_type: str = "Explicitly Authorized Training Lab",
) -> str:
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    ordered = sorted(findings, key=lambda finding: severity_order.get(finding.severity, 3))
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    high_count = sum(1 for f in findings if f.severity == "High")
    med_count = sum(1 for f in findings if f.severity == "Medium")
    low_count = sum(1 for f in findings if f.severity == "Low")

    if high_count > 0:
        posture_badge = "CRITICAL / HIGH RISK"
        posture_class = "risk-high"
        posture_grade = "F"
    elif med_count > 0:
        posture_badge = "MODERATE RISK"
        posture_class = "risk-medium"
        posture_grade = "C"
    elif low_count > 0:
        posture_badge = "LOW RISK"
        posture_class = "risk-low"
        posture_grade = "B"
    else:
        posture_badge = "SECURE / CLEAN"
        posture_class = "risk-clean"
        posture_grade = "A"

    owasp_counts: dict[str, int] = {}
    for f in findings:
        owasp_counts[f.owasp] = owasp_counts.get(f.owasp, 0) + 1

    owasp_rows = "\n".join(
        f"<tr><td><strong>{html.escape(cat)}</strong></td>"
        f"<td><span class=\"badge count-badge\">{count}</span></td></tr>"
        for cat, count in sorted(owasp_counts.items())
    ) or "<tr><td colspan='2'>No OWASP categories triggered.</td></tr>"

    rows = "\n".join(
        f"<tr class=\"finding-row\" data-severity=\"{html.escape(item.severity.lower())}\">"
        f"<td><span class=\"severity-badge {html.escape(item.severity.lower())}\">{html.escape(item.severity)}</span></td>"
        f"<td><span class=\"owasp-tag\">{html.escape(item.owasp)}</span><br><code class=\"cwe-tag\">{html.escape(item.cwe)}</code></td>"
        f"<td><strong class=\"title-cell\">{html.escape(item.title)}</strong></td>"
        f"<td><pre class=\"evidence-box\">{html.escape(item.evidence)}</pre></td>"
        f"<td><span class=\"recom-cell\">{html.escape(item.recommendation)}</span></td>"
        "</tr>"
        for item in ordered
    )

    remediation_items = "\n".join(
        f"<li><strong>[{html.escape(item.severity)}] {html.escape(item.title)}:</strong> "
        f"{html.escape(item.recommendation)}</li>"
        for item in ordered
    ) or "<li>All automated checks passed cleanly. Regularly conduct non-destructive assessments.</li>"

    errors_html = "".join(f"<li>{html.escape(error)}</li>" for error in errors)
    findings_json = json.dumps([asdict(f) for f in ordered])

    ai_html = ""
    if ai_summary:
        ai_html = f"""
  <div class="summary-box ai-summary-card">
    <div class="ai-box-head">
      <span class="ai-spark">✨</span>
      <h3>Gemini AI Security Advisory</h3>
      <span class="ai-model-tag">gemini-3.5-flash-lite</span>
    </div>
    <div class="ai-box-body">{html.escape(ai_summary)}</div>
  </div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SEC WATCH | Security Assessment Report</title>
<link rel="icon" type="image/svg+xml" href="./sec-watch-logo.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;700;800;900&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@600;700;800;900&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {{
  color-scheme: light;
  --font-sans: 'Space Grotesk', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-display: 'Orbitron', 'Space Grotesk', -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, Menlo, Monaco, Consolas, monospace;
  --bg: #f8fafc;
  --surface: #ffffff;
  --ink: #0f172a;
  --muted: #475569;
  --dim: #64748b;
  --border: #e2e8f0;
  --neon-mint: #059669;
  --neon-cyan: #0284c7;
  --high: #dc2626;
  --high-bg: #fef2f2;
  --med: #d97706;
  --med-bg: #fffbeb;
  --low: #0284c7;
  --low-bg: #f0f9ff;
  --clean: #059669;
  --clean-bg: #ecfdf5;
  --shadow: 0 4px 20px -2px rgba(15, 23, 42, 0.06), 0 2px 6px -1px rgba(15, 23, 42, 0.04);
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: var(--font-sans);
  line-height: 1.6;
  background: var(--bg);
  color: var(--ink);
  background-image:
    radial-gradient(ellipse 90% 60% at 50% -20%, rgba(2, 132, 199, 0.05), transparent 70%),
    radial-gradient(circle at 10% 40%, rgba(5, 150, 105, 0.05), transparent 45%),
    linear-gradient(to right, rgba(0, 0, 0, 0.03) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(0, 0, 0, 0.03) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 48px 48px, 48px 48px;
  background-attachment: fixed;
  margin: 0;
  padding: 2.5rem 1rem;
}}
.container {{
  max-width: 1180px;
  margin: 0 auto;
}}
.header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
  padding-bottom: 1.8rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 2rem;
}}
.brand-group {{
  display: flex;
  align-items: center;
  gap: 16px;
}}
.brand-logo {{
  width: 52px;
  height: 52px;
  flex-shrink: 0;
  filter: drop-shadow(0 2px 8px rgba(0, 0, 0, 0.12));
}}
h1 {{
  margin: 0;
  font-family: var(--font-display);
  font-size: 1.85rem;
  font-weight: 800;
  letter-spacing: .04em;
  text-transform: uppercase;
  color: #0f172a;
}}
.subtitle {{ margin-top: .35rem; color: var(--muted); font-size: 0.95rem; }}
.actions {{ display: flex; gap: .75rem; }}
.btn {{
  cursor: pointer;
  border: 1px solid var(--border);
  background: #ffffff;
  color: var(--ink);
  font-family: var(--font-display);
  font-size: .8rem;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
  padding: .55rem 1.15rem;
  border-radius: 8px;
  display: inline-flex;
  align-items: center;
  gap: .45rem;
  transition: all .2s ease;
  box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}}
.btn:hover {{
  background: #f1f5f9;
  border-color: #cbd5e1;
  transform: translateY(-1px);
}}
.btn-primary {{
  background: #0f172a;
  border-color: #0f172a;
  color: #fff;
}}
.btn-primary:hover {{
  background: #1e293b;
  box-shadow: 0 4px 12px rgba(15, 23, 42, 0.15);
}}

.card-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.25rem;
  margin-bottom: 2rem;
}}
.card {{
  position: relative;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.35rem;
  box-shadow: var(--shadow);
  transition: transform .2s ease;
}}
.card:hover {{ transform: translateY(-2px); }}
.card-label {{
  font-family: var(--font-display);
  font-size: .75rem;
  text-transform: uppercase;
  letter-spacing: .12em;
  color: var(--muted);
  font-weight: 750;
}}
.card-value {{
  font-family: var(--font-display);
  font-size: 2.1rem;
  font-weight: 800;
  margin-top: .4rem;
  letter-spacing: .02em;
  color: #0f172a;
}}
.card-sub {{ font-size: .85rem; color: var(--dim); margin-top: .25rem; font-weight: 550; }}

.risk-high {{ color: var(--high); }}
.risk-medium {{ color: var(--med); }}
.risk-low {{ color: var(--low); }}
.risk-clean {{ color: var(--clean); }}

.summary-box {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.4rem;
  margin-bottom: 2rem;
  box-shadow: var(--shadow);
}}
.meta-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.25rem;
  font-size: .92rem;
}}
.meta-grid div strong {{ color: #334155; }}
.meta-grid code {{
  font-family: var(--font-mono);
  color: #0284c7;
  background: #f0f9ff;
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid #bae6fd;
}}

.owasp-table {{ width: 100%; border-collapse: collapse; margin-top: .8rem; font-size: .9rem; }}
.owasp-table th, .owasp-table td {{ padding: .65rem .85rem; border: 1px solid var(--border); text-align: left; }}
.owasp-table th {{
  font-family: var(--font-display);
  background: #f1f5f9;
  color: #334155;
  font-weight: 750;
  letter-spacing: .06em;
  text-transform: uppercase;
  font-size: .75rem;
}}
.owasp-table td {{ color: #1e293b; }}

table.findings-table {{
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  font-size: .92rem;
  margin-bottom: 2rem;
  box-shadow: var(--shadow);
}}
table.findings-table th, table.findings-table td {{
  padding: .95rem 1.15rem;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}}
table.findings-table th {{
  font-family: var(--font-display);
  background: #f1f5f9;
  font-weight: 750;
  color: #334155;
  text-transform: uppercase;
  font-size: .75rem;
  letter-spacing: .08em;
}}
table.findings-table tr:hover td {{ background: #f8fafc; }}

.severity-badge {{
  display: inline-block;
  padding: .25rem .6rem;
  border-radius: 6px;
  font-family: var(--font-display);
  font-weight: 800;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .08em;
}}
.severity-badge.high {{ background: var(--high-bg); color: var(--high); border: 1px solid rgba(220, 38, 38, 0.3); }}
.severity-badge.medium {{ background: var(--med-bg); color: var(--med); border: 1px solid rgba(217, 119, 6, 0.3); }}
.severity-badge.low {{ background: var(--low-bg); color: var(--low); border: 1px solid rgba(2, 132, 199, 0.3); }}

.owasp-tag {{ font-family: var(--font-mono); font-size: .8rem; font-weight: 700; color: #0284c7; }}
.cwe-tag {{
  font-family: var(--font-mono);
  font-size: .74rem;
  color: var(--muted);
  background: #f1f5f9;
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid var(--border);
}}
.title-cell {{ color: #0f172a; font-size: .95rem; font-weight: 600; }}
.recom-cell {{ color: #334155; }}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-family: var(--font-display);
  font-weight: 750;
  font-size: .75rem;
  letter-spacing: .06em;
  text-transform: uppercase;
}}
.count-badge {{ background: #f1f5f9; color: #0f172a; border: 1px solid var(--border); }}
.scope-badge {{
  background: #ecfdf5;
  color: #065f46;
  border: 1px solid #a7f3d0;
}}

.evidence-box {{
  font-family: var(--font-mono);
  font-size: .82rem;
  background: #0f172a;
  color: #7dd3fc;
  border: 1px solid #1e293b;
  padding: .65rem .75rem;
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}}

/* AI EXECUTIVE ADVISORY BOX */
.ai-summary-card {{
  border: 1px solid #a7f3d0;
  background: linear-gradient(135deg, #f0fdf4, #f0f9ff);
  box-shadow: var(--shadow);
  padding: 1.5rem;
  border-radius: 12px;
}}
.ai-box-head {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: .85rem;
}}
.ai-box-head h3 {{
  margin: 0;
  color: #065f46;
  font-family: var(--font-display);
  font-size: 1.15rem;
  font-weight: 800;
  letter-spacing: .04em;
  text-transform: uppercase;
}}
.ai-spark {{ color: #059669; font-size: 1.25rem; }}
.ai-model-tag {{
  margin-left: auto;
  font-family: var(--font-mono);
  font-size: .75rem;
  font-weight: 700;
  color: #065f46;
  background: #d1fae5;
  border: 1px solid #a7f3d0;
  padding: 2px 8px;
  border-radius: 20px;
}}
.ai-box-body {{
  font-size: .94rem;
  color: #1e293b;
  white-space: pre-wrap;
  line-height: 1.7;
}}

.remediation-section {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.6rem;
  margin-bottom: 2rem;
  box-shadow: var(--shadow);
}}
.remediation-section h3 {{
  margin-top: 0;
  color: #0f172a;
  font-family: var(--font-display);
  font-size: 1.15rem;
  font-weight: 800;
  letter-spacing: .04em;
  text-transform: uppercase;
}}
.remediation-section ul {{ padding-left: 1.25rem; margin-bottom: 0; }}
.remediation-section li {{ margin-bottom: .7rem; color: #334155; }}
.remediation-section li strong {{ color: #0f172a; }}

.scope-notice {{
  font-size: .85rem;
  color: var(--dim);
  border-top: 1px solid var(--border);
  padding-top: 1.5rem;
  text-align: center;
}}
.creator-end-card {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  margin: 0 auto 1rem;
  text-align: center;
}}
.creator-name-tag {{
  display: inline-block;
  font-family: var(--font-display);
  font-size: .95rem;
  font-weight: 900;
  letter-spacing: .22em;
  text-transform: uppercase;
  color: #0f172a;
  background: linear-gradient(135deg, rgba(2, 132, 199, 0.08), rgba(5, 150, 105, 0.08));
  border: 1px solid rgba(2, 132, 199, 0.3);
  padding: .35rem 1.3rem;
  border-radius: 20px;
  margin-bottom: .4rem;
}}
.creator-credit-text {{
  font-family: var(--font-sans);
  font-size: .82rem;
  font-weight: 500;
  color: var(--muted);
}}

/* CLEAN PRINT TO PDF STYLES */
@media print {{
  .no-print {{ display: none !important; }}
  body {{ background: #fff !important; color: #000 !important; padding: 0; font-size: 10.5pt; background-image: none !important; }}
  .container {{ max-width: none; }}
  h1 {{ background: none !important; -webkit-text-fill-color: #000 !important; color: #000 !important; }}
  .card, tr, .remediation-section, .summary-box, .ai-summary-card {{
    break-inside: avoid;
    page-break-inside: avoid;
    background: #fff !important;
    border: 1px solid #ccc !important;
    color: #000 !important;
    box-shadow: none !important;
  }}
  .card-value, .title-cell, .recom-cell, .ai-box-body, .remediation-section li, .remediation-section li strong {{
    color: #000 !important;
  }}
  table.findings-table {{
    background: #fff !important;
    border: 1px solid #ccc !important;
  }}
  table.findings-table th {{
    background: #f1f5f9 !important;
    color: #000 !important;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }}
  .evidence-box {{
    background: #f8fafc !important;
    color: #000 !important;
    border: 1px solid #ccc !important;
  }}
  .severity-badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
}}
</style>
</head>
<body>
<div class="container">
  <header class="header">
    <div class="brand-group">
      <svg class="brand-logo" viewBox="0 0 64 64" fill="none">
        <defs>
          <linearGradient id="hdrShield" x1="32" y1="4" x2="32" y2="60" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#111c2a"/>
            <stop offset="100%" stop-color="#0a1019"/>
          </linearGradient>
          <linearGradient id="hdrNeon" x1="10" y1="10" x2="54" y2="58" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#00F5A0"/>
            <stop offset="50%" stop-color="#00D2FF"/>
            <stop offset="100%" stop-color="#3B82F6"/>
          </linearGradient>
          <radialGradient id="hdrPulse" cx="32" cy="31" r="8" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#FFFFFF"/>
            <stop offset="50%" stop-color="#A5F3FC"/>
            <stop offset="100%" stop-color="#00D2FF" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <path d="M 32 4.5 L 53.5 13.8 C 53.5 28.5 44 47.5 32 59.5 C 20 47.5 10.5 28.5 10.5 13.8 Z" fill="url(#hdrShield)" stroke="url(#hdrNeon)" stroke-width="2.6" stroke-linejoin="round"/>
        <path d="M 32 10 L 48.5 17.5 C 48.5 29 40.8 44.5 32 54 C 23.2 44.5 15.5 29 15.5 17.5 Z" stroke="#1e3247" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
        <circle cx="32" cy="31" r="16.5" stroke="url(#hdrNeon)" stroke-width="1.4" stroke-dasharray="14 7 4 7" stroke-opacity="0.65"/>
        <path d="M 17 31 C 22.5 21.5 41.5 21.5 47 31" stroke="url(#hdrNeon)" stroke-width="2.4" stroke-linecap="round"/>
        <path d="M 17 31 C 22.5 40.5 41.5 40.5 47 31" stroke="url(#hdrNeon)" stroke-width="2.4" stroke-linecap="round"/>
        <circle cx="32" cy="31" r="8.5" fill="#0c1724" stroke="url(#hdrNeon)" stroke-width="2"/>
        <circle cx="32" cy="31" r="4.2" fill="url(#hdrPulse)"/>
        <circle cx="32" cy="24" r="2" fill="#FFFFFF"/>
        <circle cx="44.5" cy="24" r="2.2" fill="#00F5A0"/>
        <line x1="32" y1="18.5" x2="32" y2="20.5" stroke="#00F5A0" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="32" y1="41.5" x2="32" y2="43.5" stroke="#00F5A0" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="19.5" y1="31" x2="21.5" y2="31" stroke="#00F5A0" stroke-width="1.8" stroke-linecap="round"/>
        <line x1="42.5" y1="31" x2="44.5" y2="31" stroke="#00F5A0" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
      <div>
        <h1>SEC WATCH Security Assessment</h1>
        <div class="subtitle">Bounded, non-destructive checks against an authorized local/private lab</div>
      </div>
    </div>
    <div class="actions no-print">
      <a href="../web_demo/" class="btn" style="text-decoration:none">🌐 Interactive Demo</a>
      <button class="btn btn-primary" onclick="window.print()">🖨️ Print / Save as PDF</button>
    </div>
  </header>

  <div class="card-grid">
    <div class="card">
      <div class="card-label">Security Posture</div>
      <div class="card-value {posture_class}">{posture_grade}</div>
      <div class="card-sub">{posture_badge}</div>
    </div>
    <div class="card">
      <div class="card-label">High Severity</div>
      <div class="card-value risk-high">{high_count}</div>
      <div class="card-sub">Immediate action required</div>
    </div>
    <div class="card">
      <div class="card-label">Medium Severity</div>
      <div class="card-value risk-medium">{med_count}</div>
      <div class="card-sub">Configuration weaknesses</div>
    </div>
    <div class="card">
      <div class="card-label">Low Severity</div>
      <div class="card-value risk-low">{low_count}</div>
      <div class="card-sub">Hardening indicators</div>
    </div>
  </div>

  {ai_html}

  <div class="summary-box">
    <h3 style="margin-top:0;color:#0f172a">Assessment Scope & Target Overview</h3>
    <div class="meta-grid">
      <div><strong>Target Origin:</strong> <code>{html.escape(target)}</code></div>
      <div><strong>Environment Scope:</strong> <span class="badge scope-badge">{html.escape(authorization_type)}</span></div>
      <div><strong>Timestamp:</strong> {generated}</div>
      <div><strong>Total HTTP Requests:</strong> {requests}</div>
      <div><strong>Assessor Confirmation:</strong> Explicitly authorized lab scope confirmed</div>
      <div><strong>Safety Boundaries:</strong> Non-destructive checks, loopback/private IPs only</div>
    </div>

    <h4 style="margin: 1.25rem 0 .5rem 0;color:#334155">OWASP Top 10 Mapping Breakdown</h4>
    <table class="owasp-table">
      <thead><tr><th>OWASP Category</th><th style="width:100px">Findings</th></tr></thead>
      <tbody>{owasp_rows}</tbody>
    </table>
  </div>

  <h2 style="color:#0f172a;margin-bottom:.85rem">Findings ({len(ordered)})</h2>
  {('<table class="findings-table"><thead><tr><th style="width:85px">Risk</th><th style="width:190px">OWASP & CWE</th><th style="width:230px">Finding</th><th>Observed Evidence</th><th>Remediation Recommendation</th></tr></thead><tbody>' + rows + '</tbody></table>') if ordered else '<p>No configured checks produced findings.</p>'}

  {('<h2>Assessment Errors</h2><ul style="color:#b91c1c">' + errors_html + '</ul>') if errors else ''}

  <section class="remediation-section">
    <h3>Prioritized Remediation Action Plan</h3>
    <p style="color:var(--muted);font-size:.9rem">Address High risk findings first, followed by Medium and Low configuration hardening:</p>
    <ul>{remediation_items}</ul>
  </section>

  <footer class="scope-notice">
    <div class="creator-end-card">
      <div class="creator-name-tag">LOHITHA .K</div>
      <div class="creator-credit-text">Designed & Developed @ 2026 | All Rights Reserved</div>
    </div>
    <p style="margin:0;padding-top:.85rem;border-top:1px dashed var(--border);font-size:.82rem;">
      <strong>Scope & Safety Boundary:</strong> Assessment is restricted to the supplied local/private IP origin and fixed paths in this tool.
      Redirects are not followed. Directory checks use non-destructive GET on a short fixed list; HTTP-method checking
      uses OPTIONS only. Review each result in the context of the application before deployment to production.
    </p>
  </footer>
</div>
</body>
</html>"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SEC WATCH: bounded checks against an explicitly authorized local/training lab."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Application origin, e.g. http://127.0.0.1:8000 (optional if using --authorized-training-lab).",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you own or are explicitly authorized to assess this target.",
    )
    parser.add_argument(
        "--authorized-training-lab",
        "--training-lab",
        dest="authorized_training_lab",
        action="store_true",
        help="Option: Automatically spin up, assess, and stop the built-in explicitly authorized training lab.",
    )
    parser.add_argument(
        "--scope-type",
        default="Explicitly Authorized Training Lab",
        choices=["Explicitly Authorized Training Lab", "Student Own Application", "Authorized Private Lab"],
        help="Explicit authorization type recorded in assessment report (default: Explicitly Authorized Training Lab).",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5).")
    parser.add_argument("--output", default="reports/sec-watch-report.html", help="HTML report path.")
    parser.add_argument("--json", dest="json_output", help="Optional path to write a machine-readable JSON report.")
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Generate an AI-powered Security Advisory with Google Gemini.",
    )
    args = parser.parse_args()

    lab_instance = None
    target_url = args.target

    if args.authorized_training_lab or (target_url is None and not args.authorized):
        if target_url is None and not args.authorized_training_lab:
            print("Notice: No target specified. Defaulting to --authorized-training-lab mode.")
        args.authorized_training_lab = True

    if args.authorized_training_lab:
        from sec_watch.training_lab import TrainingLab

        lab_instance = TrainingLab()
        try:
            target_url = lab_instance.start()
        except OSError as exc:
            print(f"Could not start training lab: {exc}", file=sys.stderr)
            return 2
        args.authorized = True
        args.scope_type = "Explicitly Authorized Training Lab"
        print(f"[+] Started explicitly authorized training lab at {target_url}")

    if not args.authorized:
        parser.error(
            "assessment requires --authorized confirmation (or run with --authorized-training-lab)."
        )
    if not 0 < args.timeout <= 30:
        parser.error("--timeout must be greater than 0 and no more than 30 seconds.")

    try:
        origin, scheme, _, _ = parse_target(target_url)
        assessment = LabAssessment(origin, scheme, args.timeout)
        assessment.run()

        ai_summary = None
        if args.ai:
            from sec_watch import ai_advisor

            if ai_advisor.is_available():
                print("Querying Google Gemini AI for Executive Advisory...")
                try:
                    ai_summary = ai_advisor.generate_executive_summary(assessment.findings, origin)
                    print("Gemini AI Advisory generated successfully.")
                except Exception as ai_err:
                    print(f"Warning: Gemini AI advisory could not be generated: {ai_err}", file=sys.stderr)
            else:
                print("Notice: --ai specified but GEMINI_API_KEY is not set in environment or .env.", file=sys.stderr)

        report = render_html(
            origin,
            assessment.findings,
            assessment.errors,
            assessment.request_count,
            ai_summary=ai_summary,
            authorization_type=args.scope_type,
        )
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")

        if args.json_output:
            json_path = Path(args.json_output)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                render_json(
                    origin,
                    assessment.findings,
                    assessment.errors,
                    assessment.request_count,
                    authorization_type=args.scope_type,
                ),
                encoding="utf-8",
            )
            print(f"JSON findings exported to: {json_path}")

    except (AssessmentError, OSError) as exc:
        print(f"Assessment failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if lab_instance is not None:
            lab_instance.stop()
            print("[+] Explicitly authorized training lab safely stopped.")

    counts = {
        severity: sum(f.severity == severity for f in assessment.findings)
        for severity in ("High", "Medium", "Low")
    }
    print(
        f"Assessment complete: {counts['High']} High, {counts['Medium']} Medium, "
        f"{counts['Low']} Low finding(s). HTML Report: {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
