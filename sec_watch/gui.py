"""Tkinter desktop interface for SEC WATCH with Gemini AI Security Advisor."""

from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

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

APP_TITLE = "SEC WATCH"


class SecWatchApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_TITLE} | Authorized Lab Web Security Assessment")
        self.root.geometry("1080x780")
        self.root.minsize(860, 620)
        self.lab = TrainingLab()
        self._scan_running = False
        self._closing = False
        self._cancel_event: threading.Event | None = None
        self._raw_findings: list[Finding] = []
        self._finding_details: dict[str, Finding] = {}
        self._selected_finding: Finding | None = None
        self._last_report_path: Path | None = None
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel", foreground="#536273")
        style.configure("Treeview", rowheight=28)
        self.root.configure(bg="#f4f7fa")

        container = ttk.Frame(self.root, padding=20)
        container.pack(fill="both", expand=True)

        header_frame = ttk.Frame(container)
        header_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(header_frame, text="SEC WATCH", style="Title.TLabel").pack(side="left")

        self.badge_frame = ttk.Frame(header_frame)
        self.badge_frame.pack(side="right")

        if ai_advisor.is_available():
            self.ai_badge = tk.Label(
                self.badge_frame,
                text="✨ Gemini AI: Active",
                bg="#ecfdf5",
                fg="#059669",
                font=("Segoe UI", 9, "bold"),
                padx=8,
                pady=3,
            )
            self.ai_badge.pack(side="left", padx=4)

        self.high_badge = tk.Label(
            self.badge_frame,
            text="High: 0",
            bg="#fee2e2",
            fg="#dc2626",
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=3,
        )
        self.high_badge.pack(side="left", padx=4)
        self.med_badge = tk.Label(
            self.badge_frame,
            text="Medium: 0",
            bg="#fef3c7",
            fg="#d97706",
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=3,
        )
        self.med_badge.pack(side="left", padx=4)
        self.low_badge = tk.Label(
            self.badge_frame,
            text="Low: 0",
            bg="#dbeafe",
            fg="#2563eb",
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=3,
        )
        self.low_badge.pack(side="left", padx=4)

        ttk.Label(
            container,
            text="Non-destructive checks against your own web application or an authorized local training lab",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(0, 12))

        target_box = ttk.LabelFrame(container, text="Assessment Target & Scope", padding=12)
        target_box.pack(fill="x")

        scope_row = ttk.Frame(target_box)
        scope_row.pack(fill="x", pady=(0, 8))
        ttk.Label(scope_row, text="Target Scope:").pack(side="left", padx=(0, 10))
        self.scope_mode_var = tk.StringVar(value="Explicitly Authorized Training Lab")
        self.scope_combo = ttk.Combobox(
            scope_row,
            textvariable=self.scope_mode_var,
            values=[
                "Explicitly Authorized Training Lab",
                "Student's Own Application (Local/Private)",
            ],
            state="readonly",
            width=38,
        )
        self.scope_combo.pack(side="left")
        self.scope_combo.bind("<<ComboboxSelected>>", self._on_scope_changed)

        self.quick_lab_btn = ttk.Button(
            scope_row,
            text="⚡ Launch & Assess Authorized Lab",
            command=self._launch_and_assess_lab,
        )
        self.quick_lab_btn.pack(side="right")

        target_row = ttk.Frame(target_box)
        target_row.pack(fill="x")
        self.target_var = tk.StringVar(value="http://127.0.0.1:8000")
        ttk.Label(target_row, text="Origin URL:").pack(side="left", padx=(0, 10))
        self.target_entry = ttk.Entry(target_row, textvariable=self.target_var)
        self.target_entry.pack(side="left", fill="x", expand=True)
        self.lab_button = ttk.Button(
            target_row, text="Start Explicitly Authorized Lab", command=self._start_lab
        )
        self.lab_button.pack(side="left", padx=(10, 0))

        action_row = ttk.Frame(target_box)
        action_row.pack(fill="x", pady=(10, 0))
        self.authorized_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            action_row,
            text="I confirm this is an explicitly authorized training lab or my own student application",
            variable=self.authorized_var,
        ).pack(side="left")
        ttk.Label(action_row, text="Timeout (s):").pack(side="left", padx=(20, 6))
        self.timeout_var = tk.StringVar(value="5")
        ttk.Spinbox(action_row, from_=1, to=30, width=5, textvariable=self.timeout_var).pack(side="left")

        self.use_ai_var = tk.BooleanVar(value=ai_advisor.is_available())
        if ai_advisor.is_available():
            ttk.Checkbutton(
                action_row,
                text="Include Gemini AI Advisory in Report",
                variable=self.use_ai_var,
            ).pack(side="left", padx=(20, 0))

        self.scan_button = ttk.Button(action_row, text="Run Assessment", command=self._start_scan)
        self.scan_button.pack(side="right")

        report_row = ttk.Frame(container)
        report_row.pack(fill="x", pady=10)
        ttk.Label(report_row, text="Report File:").pack(side="left", padx=(0, 10))
        default_report = Path.cwd() / "reports" / "sec-watch-report.html"
        self.report_var = tk.StringVar(value=str(default_report))
        ttk.Entry(report_row, textvariable=self.report_var).pack(side="left", fill="x", expand=True)
        ttk.Button(report_row, text="Choose…", command=self._choose_report).pack(side="left", padx=(6, 0))
        self.open_report_btn = ttk.Button(
            report_row, text="Open in Browser", command=self._open_report, state="disabled"
        )
        self.open_report_btn.pack(side="left", padx=(6, 0))

        toolbar = ttk.Frame(container)
        toolbar.pack(fill="x", pady=(0, 6))
        self.status_var = tk.StringVar(value="Ready. Start the demo lab or enter your authorized local target.")
        ttk.Label(toolbar, textvariable=self.status_var, style="Sub.TLabel").pack(side="left")

        filter_frame = ttk.Frame(toolbar)
        filter_frame.pack(side="right")
        ttk.Label(filter_frame, text="Filter:").pack(side="left", padx=(0, 6))
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_var,
            values=["All", "High", "Medium", "Low"],
            state="readonly",
            width=10,
        )
        self.filter_combo.pack(side="left")
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())

        columns = ("severity", "owasp", "title", "evidence")
        self.findings = ttk.Treeview(container, columns=columns, show="headings", selectmode="browse")
        self.findings.heading("severity", text="Risk")
        self.findings.heading("owasp", text="OWASP Category")
        self.findings.heading("title", text="Finding")
        self.findings.heading("evidence", text="Evidence")
        self.findings.column("severity", width=80, stretch=False)
        self.findings.column("owasp", width=200, stretch=False)
        self.findings.column("title", width=280)
        self.findings.column("evidence", width=420)
        self.findings.tag_configure("High", foreground="#dc2626")
        self.findings.tag_configure("Medium", foreground="#d97706")
        self.findings.tag_configure("Low", foreground="#2563eb")
        self.findings.pack(fill="both", expand=True)
        self.findings.bind("<<TreeviewSelect>>", self._show_finding)

        detail_frame = ttk.LabelFrame(
            container, text="Finding Details, OWASP Mapping & Recommendation", padding=10
        )
        detail_frame.pack(fill="x", pady=(10, 0))
        self.details = tk.Text(detail_frame, height=5, wrap="word", state="disabled", font=("Consolas", 9))
        self.details.pack(fill="x")
        self.details.bind("<Key>", lambda _event: "break")

        detail_action_row = ttk.Frame(detail_frame)
        detail_action_row.pack(fill="x", pady=(8, 0))
        self.ai_btn = ttk.Button(
            detail_action_row,
            text="✨ Ask Gemini AI for Code Fix & Remediation",
            command=self._ask_gemini,
            state="disabled",
        )
        self.ai_btn.pack(side="right")

        footer_row = ttk.Frame(container)
        footer_row.pack(fill="x", pady=(8, 0))
        ttk.Label(
            footer_row,
            text="Scope: non-destructive GET/OPTIONS checks only. Strictly for authorized training/local targets.",
            style="Sub.TLabel",
        ).pack(side="left")

    def _choose_report(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Save SEC WATCH HTML report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html")],
            initialfile="sec-watch-report.html",
        )
        if selected:
            self.report_var.set(selected)

    def _open_report(self) -> None:
        if self._last_report_path and self._last_report_path.exists():
            webbrowser.open(self._last_report_path.as_uri())
        else:
            path = Path(self.report_var.get())
            if path.exists():
                webbrowser.open(path.as_uri())

    def _on_scope_changed(self, _event: tk.Event | None = None) -> None:
        mode = self.scope_mode_var.get()
        if "Authorized Training Lab" in mode:
            self.authorized_var.set(True)
            if self.lab.running:
                self.target_var.set(self.lab.url)
                self.status_var.set(f"Target set to active authorized training lab: {self.lab.url}")
            else:
                self.status_var.set("Click 'Start Explicitly Authorized Lab' to boot the local vulnerable target.")
        else:
            self.status_var.set("Target set to student-owned application. Enter your local origin URL.")

    def _launch_and_assess_lab(self) -> None:
        if not self.lab.running:
            self._start_lab()
        self.scope_mode_var.set("Explicitly Authorized Training Lab")
        self.authorized_var.set(True)
        self._start_scan()

    def _start_lab(self) -> None:
        try:
            target = self.lab.start()
        except OSError as exc:
            messagebox.showerror("Could not start training lab", str(exc))
            return
        self.target_var.set(target)
        self.scope_mode_var.set("Explicitly Authorized Training Lab")
        self.authorized_var.set(True)
        self.status_var.set(f"Explicitly authorized training lab listening at {target} (loopback only).")
        self.lab_button.configure(text="Authorized Lab Running", state="disabled")

    def _start_scan(self) -> None:
        if self._scan_running:
            return
        if not self.authorized_var.get():
            messagebox.showwarning(
                "Authorization required",
                "Confirm ownership or explicit authorization before scanning.",
            )
            return
        try:
            target, _scheme, _port, _host = parse_target(self.target_var.get().strip())
            timeout = float(self.timeout_var.get())
            if not 0 < timeout <= 30:
                raise ValueError("Timeout must be between 1 and 30 seconds.")
            report_path = Path(self.report_var.get()).expanduser()
            if not report_path.name:
                raise ValueError("Choose a valid filename for the HTML report.")
        except (AssessmentError, ValueError, OSError) as exc:
            messagebox.showerror("Invalid assessment settings", str(exc))
            return

        self._scan_running = True
        self._cancel_event = threading.Event()
        self.scan_button.configure(state="disabled")
        self.open_report_btn.configure(state="disabled")
        self.ai_btn.configure(state="disabled")
        self.status_var.set("Assessment running…")

        include_ai = self.use_ai_var.get() and ai_advisor.is_available()

        worker = threading.Thread(
            target=self._scan_worker,
            args=(target, timeout, report_path, self._cancel_event, include_ai),
            name="sec-watch-assessment",
            daemon=True,
        )
        worker.start()

    def _scan_worker(
        self,
        target: str,
        timeout: float,
        report_path: Path,
        cancel_event: threading.Event,
        include_ai: bool,
    ) -> None:
        try:
            _origin, scheme, _port, _host = parse_target(target)
            assessment = LabAssessment(target, scheme, timeout, cancel_event)
            assessment.run()

            ai_summary = None
            if include_ai:
                try:
                    self.root.after(0, lambda: self.status_var.set("Generating Gemini AI Advisory…"))
                    ai_summary = ai_advisor.generate_executive_summary(assessment.findings, target)
                except Exception:
                    pass

            scope_type = self.scope_mode_var.get()
            report = render_html(
                target,
                assessment.findings,
                assessment.errors,
                assessment.request_count,
                ai_summary=ai_summary,
                authorization_type=scope_type,
            )
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
        except (AssessmentError, OSError) as exc:
            if not self._closing:
                self.root.after(0, self._scan_failed, str(exc))
            return
        if not self._closing:
            self.root.after(0, self._scan_finished, assessment, report_path)

    def _scan_failed(self, error: str) -> None:
        self._scan_running = False
        self.scan_button.configure(state="normal")
        self.status_var.set("Assessment failed.")
        messagebox.showerror("Assessment failed", error)

    def _scan_finished(self, assessment: LabAssessment, report_path: Path) -> None:
        self._scan_running = False
        self.scan_button.configure(state="normal")
        self.open_report_btn.configure(state="normal")
        self._last_report_path = report_path
        self._raw_findings = assessment.findings

        highs = sum(1 for f in assessment.findings if f.severity == "High")
        meds = sum(1 for f in assessment.findings if f.severity == "Medium")
        lows = sum(1 for f in assessment.findings if f.severity == "Low")

        self.high_badge.configure(text=f"High: {highs}")
        self.med_badge.configure(text=f"Medium: {meds}")
        self.low_badge.configure(text=f"Low: {lows}")

        self._apply_filter()
        self.status_var.set(
            f"Complete: {highs} High, {meds} Medium, {lows} Low findings. Report saved: {report_path.name}"
        )

    def _apply_filter(self) -> None:
        for item in self.findings.get_children():
            self.findings.delete(item)
        self._finding_details.clear()

        filter_val = self.filter_var.get()
        displayed = [
            f for f in self._raw_findings if filter_val == "All" or f.severity == filter_val
        ]

        for index, finding in enumerate(displayed):
            item_id = f"finding-{index}"
            self.findings.insert(
                "",
                "end",
                iid=item_id,
                values=(finding.severity, finding.owasp, finding.title, finding.evidence),
                tags=(finding.severity,),
            )
            self._finding_details[item_id] = finding

        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if displayed:
            first = self.findings.get_children()[0]
            self.findings.selection_set(first)
            self._show_finding(None)
        else:
            self._selected_finding = None
            self.ai_btn.configure(state="disabled")
            self.details.insert("1.0", "No findings match the current filter.")
        self.details.configure(state="disabled")

    def _show_finding(self, _event: tk.Event | None) -> None:
        selection = self.findings.selection()
        if not selection:
            self._selected_finding = None
            self.ai_btn.configure(state="disabled")
            return
        finding = self._finding_details.get(selection[0])
        if not finding:
            self._selected_finding = None
            self.ai_btn.configure(state="disabled")
            return

        self._selected_finding = finding
        self.ai_btn.configure(state="normal" if ai_advisor.is_available() else "disabled")

        text = (
            f"[{finding.severity.upper()}] {finding.title}\n"
            f"OWASP Category : {finding.owasp}\n"
            f"CWE Reference  : {finding.cwe}\n\n"
            f"Observed Evidence:\n{finding.evidence}\n\n"
            f"Remediation Guidance:\n{finding.recommendation}"
        )
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _ask_gemini(self) -> None:
        if not self._selected_finding:
            return

        finding = self._selected_finding
        dialog = tk.Toplevel(self.root)
        dialog.title(f"✨ Gemini AI Security Advisor | {finding.title}")
        dialog.geometry("740x580")
        dialog.minsize(600, 450)

        header_frame = ttk.Frame(dialog, padding=(16, 12))
        header_frame.pack(fill="x")
        ttk.Label(
            header_frame,
            text=f"AI Remediation for: {finding.title}",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            header_frame,
            text=f"Risk: {finding.severity} | OWASP: {finding.owasp} | CWE: {finding.cwe}",
            style="Sub.TLabel",
        ).pack(anchor="w")

        text_frame = ttk.Frame(dialog, padding=(16, 0))
        text_frame.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        output_text = tk.Text(
            text_frame,
            wrap="word",
            yscrollcommand=scrollbar.set,
            font=("Consolas", 10),
            bg="#fdfefe",
            padx=10,
            pady=10,
        )
        output_text.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=output_text.yview)

        output_text.insert("1.0", "Consulting Google Gemini AI for tailored code fixes and remediation…\nPlease wait a moment.")
        output_text.configure(state="disabled")

        btn_row = ttk.Frame(dialog, padding=14)
        btn_row.pack(fill="x")

        def copy_text() -> None:
            dialog.clipboard_clear()
            dialog.clipboard_append(output_text.get("1.0", "end"))
            messagebox.showinfo("Copied", "Gemini AI remediation guidance copied to clipboard!", parent=dialog)

        copy_btn = ttk.Button(btn_row, text="Copy to Clipboard", command=copy_text, state="disabled")
        copy_btn.pack(side="left")
        ttk.Button(btn_row, text="Close", command=dialog.destroy).pack(side="right")

        def fetch_ai() -> None:
            try:
                explanation = ai_advisor.explain_finding(finding)
            except Exception as exc:
                explanation = f"Could not generate AI advice: {exc}"

            def update_ui() -> None:
                if dialog.winfo_exists():
                    output_text.configure(state="normal")
                    output_text.delete("1.0", "end")
                    output_text.insert("1.0", explanation)
                    output_text.configure(state="disabled")
                    copy_btn.configure(state="normal")

            dialog.after(0, update_ui)

        threading.Thread(target=fetch_ai, daemon=True).start()

    def _close(self) -> None:
        self._closing = True
        if self._cancel_event is not None:
            self._cancel_event.set()
        self.lab.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    SecWatchApp(root)
    root.mainloop()
