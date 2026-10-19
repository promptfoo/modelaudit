"""Human-readable advisory output with no untrusted Markdown/HTML execution."""

from __future__ import annotations

import html
import json

from .models import ReviewReport


def escaped(value: str) -> str:
    # JSON escaping makes terminal controls visible; HTML escaping prevents injected links/images.
    visible = json.dumps(value, ensure_ascii=True)[1:-1]
    return html.escape(visible).replace("`", "&#96;").replace("[", "&#91;").replace("*", "&#42;").replace("_", "&#95;")


def render_markdown(report: ReviewReport) -> str:
    issues = report.scanner_issue_count if report.scanner_issue_count is not None else "unavailable"
    failed = report.scanner_failed_check_count if report.scanner_failed_check_count is not None else "unavailable"
    lines = [
        "# Advisory documentation review",
        "",
        f"Scanner exit code: **{report.scan_exit_code}**. Original findings and verdict are unchanged.",
        "",
        f"Review status: **{report.review_status}**; "
        f"reviewed {report.reviewed_count}/{report.selected_count} selected findings.",
        f"Original scanner counts: {issues} issues, {failed} failed checks.",
        "",
        (
            "The complete authoritative report is in `scan.json`. De-emphasis is a review suggestion only."
            if report.scan_sha256
            else "No reviewable scanner report was captured; inspect the manifest and diagnostics."
        ),
        "",
    ]
    for entry in report.entries:
        lines.extend(
            [f"- {escaped(entry.pointer)}: **{entry.display_action}** ({entry.status}). {escaped(entry.reason)}"]
        )
        if entry.assessment:
            assessment = entry.assessment
            lines.append(f"  {assessment.assessment}: {escaped(assessment.explanation)}")
            lines.append(f"  Execution: {escaped(assessment.execution_implications)}")
            lines.append(f"  Evidence: {escaped(', '.join(assessment.evidence_ids))}")
            if assessment.limitations:
                lines.append(f"  Limitations: {escaped('; '.join(assessment.limitations))}")
    if report.errors:
        lines.extend(["", "Review errors:", "", *[f"- {escaped(error)}" for error in report.errors]])
    return "\n".join(lines) + "\n"
