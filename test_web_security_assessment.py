import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request

from sec_watch import ai_advisor
from sec_watch.assessment import (
    AssessmentError,
    Finding,
    LabAssessment,
    parse_target,
    render_html,
    render_json,
)
from sec_watch.training_lab import TrainingLab


class LabHandler(BaseHTTPRequestHandler):
    observed_methods = []

    def do_GET(self):
        self.observed_methods.append(("GET", self.path))
        if self.path == "/uploads/":
            body = b"<html><title>Index of /uploads</title></html>"
        elif self.path == "/.env":
            body = b"DB_PASSWORD=secret123\nAPP_KEY=xyz"
        elif self.path == "/.git/HEAD":
            body = b"ref: refs/heads/main\n"
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin/\n"
        else:
            body = b"Training app <input type='password' name='pw'>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "LabServer")
        self.send_header("X-Powered-By", "PHP/8.0")
        self.send_header("Set-Cookie", "session=abc; HttpOnlyx")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.observed_methods.append(("OPTIONS", self.path))
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()

    def log_message(self, format, *args):
        pass


class AssessmentTests(unittest.TestCase):
    def test_target_scope(self):
        self.assertEqual(parse_target("http://127.0.0.1:8080")[0], "http://127.0.0.1:8080")
        self.assertEqual(parse_target("http://localhost")[2], 80)
        for target in (
            "https://example.com",
            "http://8.8.8.8",
            "file:///etc/passwd",
            "http://127.0.0.1/app",
            "http://127.0.0.1:70000",
            "http://127.0.0.1:0",
            "http://[invalid",
        ):
            with self.subTest(target=target), self.assertRaises(AssessmentError):
                parse_target(target)

    def test_local_checks_and_findings(self):
        server = HTTPServer(("127.0.0.1", 0), LabHandler)
        LabHandler.observed_methods = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            assessment = LabAssessment(origin, "http", timeout=2)
            assessment.run()
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertEqual(assessment.request_count, 10)
        self.assertIn(("OPTIONS", "/"), LabHandler.observed_methods)
        self.assertTrue(all(method in ("GET", "OPTIONS") for method, _ in LabHandler.observed_methods))
        titles = {finding.title for finding in assessment.findings}
        self.assertIn("Directory listing may be exposed at /uploads/", titles)
        self.assertIn("Dangerous HTTP TRACE method enabled (Cross-Site Tracing risk)", titles)
        self.assertIn("Exposed environment configuration file (/.env)", titles)
        self.assertIn("Exposed Git repository metadata (/.git/HEAD)", titles)
        self.assertIn("Cleartext password authentication form over unencrypted HTTP", titles)
        self.assertIn("Technology stack banner exposed via X-Powered-By", titles)
        self.assertIn("Information disclosure in robots.txt", titles)
        self.assertIn("Content Security Policy is missing", titles)
        self.assertIn("Cookie session has missing security attributes", titles)

        # Check risk-based findings: High, Medium, Low
        severities = {f.severity for f in assessment.findings}
        self.assertIn("High", severities)
        self.assertIn("Medium", severities)
        self.assertIn("Low", severities)

        # Check OWASP mapping
        self.assertTrue(all(hasattr(f, "owasp") and f.owasp for f in assessment.findings))
        self.assertTrue(all(hasattr(f, "cwe") and f.cwe for f in assessment.findings))

    def test_report_escapes_untrusted_text(self):
        report = render_html(
            "http://localhost",
            [],
            ["<script>alert(1)</script>"],
            1,
        )
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_json_and_html_export(self):
        findings = [
            Finding(
                severity="High",
                title="Exposed environment configuration file (/.env)",
                evidence="DB_PASSWORD=secret",
                recommendation="Protect .env files.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-540",
            ),
            Finding(
                severity="Low",
                title="Server banner exposed",
                evidence="Server: Apache",
                recommendation="Generalize server banner.",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-200",
            ),
        ]
        json_output = render_json("http://127.0.0.1:8000", findings, [], 10)
        parsed = json.loads(json_output)
        self.assertEqual(parsed["summary"]["high"], 1)
        self.assertEqual(parsed["summary"]["low"], 1)
        self.assertEqual(parsed["summary"]["total"], 2)
        self.assertEqual(parsed["findings"][0]["cwe"], "CWE-540")
        self.assertEqual(parsed["authorization_scope"], "Explicitly Authorized Training Lab")
        self.assertTrue(parsed["authorized_training_lab"])

        html_output = render_html(
            "http://127.0.0.1:8000",
            findings,
            [],
            10,
            ai_summary="Priority: Fix .env immediately.",
            authorization_type="Explicitly Authorized Training Lab",
        )
        self.assertIn("CRITICAL / HIGH RISK", html_output)
        self.assertIn("Print / Save as PDF", html_output)
        self.assertIn("A05:2021 - Security Misconfiguration", html_output)
        self.assertIn("CWE-540", html_output)
        self.assertIn("Gemini AI Security Advisory", html_output)
        self.assertIn("Fix .env immediately.", html_output)
        self.assertIn("Explicitly Authorized Training Lab", html_output)

    def test_authorized_training_lab_cli_mode(self):
        import subprocess, sys
        cmd = [
            sys.executable,
            "web_security_assessment.py",
            "--authorized-training-lab",
            "--output",
            "reports/test-lab-report.html",
            "--json",
            "reports/test-lab-report.json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"CLI failed: {result.stderr}")
        self.assertIn("Started explicitly authorized training lab", result.stdout)
        self.assertIn("Explicitly authorized training lab safely stopped", result.stdout)

    def test_ai_advisor_key_loading(self):
        key = ai_advisor.get_api_key()
        self.assertTrue(isinstance(key, str))
        self.assertTrue(len(key) > 10)
        self.assertTrue(ai_advisor.is_available())

    def test_training_lab_is_loopback_only_and_exposes_demo_signals(self):
        lab = TrainingLab()
        target = lab.start()
        try:
            self.assertTrue(target.startswith("http://127.0.0.1:"))
            with urllib.request.urlopen(target + "/uploads/", timeout=2) as response:
                self.assertIn(b"Index of /uploads/", response.read())
                self.assertIsNone(response.headers.get("Content-Security-Policy"))
            with urllib.request.urlopen(target + "/.env", timeout=2) as response:
                self.assertIn(b"DB_PASSWORD=", response.read())
            with urllib.request.urlopen(target + "/.git/HEAD", timeout=2) as response:
                self.assertIn(b"ref: refs/heads/main", response.read())

            request = urllib.request.Request(target + "/", method="OPTIONS")
            with urllib.request.urlopen(request, timeout=2) as options:
                self.assertIn("TRACE", options.headers["Allow"])

            assessment = LabAssessment(target, "http", timeout=2)
            assessment.run()
            titles = {finding.title for finding in assessment.findings}
            self.assertIn("Exposed environment configuration file (/.env)", titles)
            self.assertIn("Exposed Git repository metadata (/.git/HEAD)", titles)
            self.assertIn("Dangerous HTTP TRACE method enabled (Cross-Site Tracing risk)", titles)
            self.assertIn("Directory listing may be exposed at /uploads/", titles)

            report = render_html(target, assessment.findings, assessment.errors, assessment.request_count)
            self.assertIn("SEC WATCH Security Assessment", report)
            self.assertIn("Disable directory indexing", report)
            self.assertIn("Print / Save as PDF", report)
        finally:
            lab.stop()
        self.assertFalse(lab.running)


if __name__ == "__main__":
    unittest.main()
