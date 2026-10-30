"""Compatibility launcher for the original SEC WATCH assessment command."""

from sec_watch.assessment import (
    AssessmentError,
    Finding,
    LabAssessment,
    main,
    parse_target,
    render_html,
    render_json,
)

__all__ = [
    "AssessmentError",
    "Finding",
    "LabAssessment",
    "parse_target",
    "render_html",
    "render_json",
]

if __name__ == "__main__":
    raise SystemExit(main())
