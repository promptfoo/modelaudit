"""Supervisor: freeze scanner output, validate advisory output, preserve the exit code."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import platform
import subprocess
import sys
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from modelaudit.core_results import results_have_inconclusive_outcome, results_have_operational_error
from modelaudit.models import ModelAuditResultModel

from .bundle import digest, index_findings, is_document, snapshot, verify_artifact, write_json
from .models import (
    MAX_GROUP_FINDINGS,
    POLICY_VERSION,
    SCHEMA_VERSION,
    AgentResponse,
    Artifact,
    Evidence,
    Finding,
    ReviewEntry,
    ReviewReport,
    ReviewStatus,
)
from .policy import POLICY
from .process import kill_process_group
from .render import render_markdown


class Reviewer(Protocol):
    def review(
        self, findings: list[Finding], evidence: list[Evidence], artifacts: Path, output: Path
    ) -> AgentResponse: ...


def installed_version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "unavailable (source checkout)"


def validate_assessments(
    response: AgentResponse, findings: list[Finding], evidence: list[Evidence], *, coverage_complete: bool
) -> list[ReviewEntry]:
    expected = {finding.finding_id: finding for finding in findings}
    ids = [item.finding_id for item in response.assessments]
    if len(ids) != len(set(ids)) or set(ids) != set(expected):
        raise ValueError("Reviewer must assess each selected finding exactly once, without unknown IDs")
    by_id = {item.evidence_id: item for item in evidence}
    entries: list[ReviewEntry] = []
    for item in response.assessments:
        finding = expected[item.finding_id]
        if (
            len(item.evidence_ids) != len(set(item.evidence_ids))
            or not set(item.evidence_ids).issubset(finding.evidence_ids)
            or not set(item.evidence_ids).issubset(by_id)
        ):
            raise ValueError("Reviewer cited duplicate, unknown, or unrelated evidence")
        favorable = item.assessment in {"benign_context", "false_positive"}
        if favorable and (
            item.context != "documentation"
            or item.trigger not in {"user_follows_documentation", "none_established"}
            or not all(by_id[key].complete for key in item.evidence_ids)
        ):
            raise ValueError("Favorable advice requires complete documentation evidence and an established trigger")
        entries.append(
            ReviewEntry(
                finding_id=item.finding_id,
                pointer=finding.pointer,
                status="reviewed",
                assessment=item,
                display_action="de_emphasize" if favorable and coverage_complete else "retain",
                reason="Advisory only; scanner result unchanged"
                if coverage_complete
                else "Scanner coverage is incomplete",
            )
        )
    return entries


def review_findings(
    report: dict[str, Any],
    raw: bytes,
    exit_code: int,
    artifacts: list[Artifact],
    root: Path,
    output: Path,
    reviewer: Reviewer | None,
    *,
    max_groups: int = 8,
) -> ReviewReport:
    findings, evidence = index_findings(report, digest(raw), root, artifacts)
    write_json(output / "findings.json", [item.model_dump() for item in findings])
    evidence_dir = output / "evidence"
    evidence_dir.mkdir(mode=0o700)
    write_json(evidence_dir / "index.json", [item.model_dump(exclude={"text"}) for item in evidence])
    for item in evidence:
        artifact = next(a for a in artifacts if a.path == item.artifact_path)
        (evidence_dir / f"{item.evidence_id}.bin").write_bytes(verify_artifact(root, artifact)[: item.byte_end])
    entries = {
        f.finding_id: ReviewEntry(
            finding_id=f.finding_id,
            pointer=f.pointer,
            status="not_reviewed",
            display_action="retain",
            assessment=None,
            reason=f.selection_reason if not f.selected else "Review not requested",
        )
        for f in findings
    }
    selected = [item for item in findings if item.selected]
    errors: list[str] = []
    if reviewer and selected:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in selected:
            assert finding.artifact_path is not None
            groups[finding.artifact_path].append(finding)
        model = ModelAuditResultModel.model_validate(report)
        coverage_complete = (
            exit_code in {0, 1}
            and model.files_scanned > 0
            and not results_have_operational_error(model)
            and not results_have_inconclusive_outcome(model)
        )
        batches = (
            (path, findings[start : start + MAX_GROUP_FINDINGS])
            for path, findings in groups.items()
            for start in range(0, len(findings), MAX_GROUP_FINDINGS)
        )
        for number, (artifact_path, group) in enumerate(batches):
            if number >= max_groups:
                if number == max_groups:
                    errors.append("Review session budget exhausted; remaining findings retained")
                for finding in group:
                    entries[finding.finding_id] = entries[finding.finding_id].model_copy(
                        update={"reason": "Review session budget exhausted"}
                    )
                continue
            group_evidence = [e for e in evidence if e.artifact_path == artifact_path]
            group_dir = output / f"group-{number:04d}"
            group_dir.mkdir(mode=0o700)
            try:
                if not all(e.complete for e in group_evidence):
                    raise ValueError("Document context exceeds the bounded review scope")
                artifact = next(a for a in artifacts if a.path == artifact_path)
                verify_artifact(root, artifact)
                response = reviewer.review(group, group_evidence, root, group_dir)
                verify_artifact(root, artifact)
                if (output / "scan.json").read_bytes() != raw:
                    raise ValueError("Original scanner report changed during review")
                approved = validate_assessments(response, group, group_evidence, coverage_complete=coverage_complete)
                entries.update({entry.finding_id: entry for entry in approved})
            except Exception as exc:
                error = f"group-{number:04d}: {type(exc).__name__}: {exc}"
                errors.append(error)
                for finding in group:
                    entries[finding.finding_id] = ReviewEntry(
                        finding_id=finding.finding_id,
                        pointer=finding.pointer,
                        status="failed",
                        display_action="retain",
                        assessment=None,
                        reason=error,
                    )
    reviewed = sum(entry.status == "reviewed" for entry in entries.values())
    status: ReviewStatus = (
        "not_requested"
        if reviewer is None
        else "not_needed"
        if not selected
        else "complete"
        if reviewed == len(selected)
        else "partial"
        if reviewed
        else "failed"
    )
    return ReviewReport(
        scan_sha256=digest(raw),
        scan_exit_code=exit_code,
        scanner_issue_count=len(report.get("issues", [])),
        scanner_failed_check_count=report.get("failed_checks"),
        review_status=status,
        selected_count=len(selected),
        reviewed_count=reviewed,
        entries=list(entries.values()),
        errors=errors,
    )


def scan_command(input_path: Path, report_path: Path, timeout: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "modelaudit",
        "scan",
        str(input_path),
        "--format",
        "json",
        "--output",
        str(report_path),
        "--verbose",
        "--quiet",
        "--no-cache",
        "--timeout",
        str(timeout),
    ]


def run_scan(command: list[str], output: Path) -> int:
    # Use the scanner's actual process exit; never duplicate verdict/exit precedence here.
    environment = {name: value for name, value in os.environ.items() if name in {"PATH", "LANG", "LC_ALL"}}
    environment.update(
        PYTHONPATH=str(Path(__file__).resolve().parents[2]), PROMPTFOO_DISABLE_TELEMETRY="1", NO_ANALYTICS="1"
    )
    with (
        (output / "scan.stdout.txt").open("xb") as stdout,
        (output / "scan.stderr.txt").open("xb") as stderr,
        subprocess.Popen(
            command, cwd=output, stdout=stdout, stderr=stderr, env=environment, start_new_session=True
        ) as process,
    ):
        try:
            returncode = process.wait()
            if returncode < 0:
                stderr.write(f"\nScanner terminated by signal {-returncode}; returning scan error 2.\n".encode())
                return 2
            return returncode
        finally:
            kill_process_group(process)


def run(
    source: Path,
    output: Path,
    reviewer: Reviewer | None,
    *,
    max_snapshot_bytes: int = 2 * 1024**3,
    scan_timeout: int = 300,
    max_review_groups: int = 8,
) -> int:
    source = Path(os.path.abspath(source))
    output = output.resolve()
    if source.is_file() and not is_document(source.name):
        raise ValueError(
            "Individual inputs must use a supported README/model-card filename; "
            "for other inputs, pass a directory containing the model and all required companion files"
        )
    if output == source or source in output.parents or output in source.parents:
        raise ValueError("Output must be outside the input tree")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "prompt_sha256": digest(POLICY.encode()),
        "response_schema_sha256": digest(json.dumps(AgentResponse.model_json_schema(), sort_keys=True).encode()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "modelaudit_version": installed_version("modelaudit"),
        "picklescan_version": installed_version("modelaudit-picklescan"),
        "picklescan_source": getattr(importlib.util.find_spec("modelaudit_picklescan"), "origin", None),
        "modelaudit_source": str(Path(__file__).resolve().parents[1]),
        "python_version": platform.python_version(),
        "scan_status": "not_run",
        "scan_exit_code": None,
        "scan_sha256": None,
        "policy": {
            "cache": False,
            "suppressions": [],
            "severity_overrides": [],
            "whitelist": "scanner default",
            "scan_timeout_seconds": scan_timeout,
            "max_snapshot_bytes": max_snapshot_bytes,
            "max_review_groups": max_review_groups,
            "review_scope": "README/model-card network findings",
        },
    }
    exit_code = 2
    raw = b""
    try:
        root = output / "artifacts"
        artifacts = snapshot(source, root, max_bytes=max_snapshot_bytes)
        manifest["artifacts"] = [item.model_dump() for item in artifacts]
        # Container mount readability; the worker receives this tree read-only.
        root.chmod(0o755)
        for path in root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
        input_path = root / source.name
        if input_path.is_file():
            if not is_document(input_path.name):
                raise ValueError("Individual inputs must use a supported README/model-card filename")
            from modelaudit.utils.file.detection import detect_file_format_from_magic

            detected = detect_file_format_from_magic(str(input_path))
            if detected not in {"unknown", "text"}:
                raise ValueError(
                    f"Individual document input has non-text format {detected!r}; "
                    "pass a directory containing the model and all required companion files"
                )
        command = scan_command(input_path, output / "scan.json", scan_timeout)
        manifest["scan_argv"] = command
        exit_code = run_scan(command, output)
        manifest.update(scan_status="finished", scan_exit_code=exit_code)
        scan_path = output / "scan.json"
        if scan_path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("Scanner JSON exceeds the 64 MiB review parsing limit")
        raw = scan_path.read_bytes()
        scan_path.chmod(0o400)
        manifest["scan_sha256"] = digest(raw)
        report = json.loads(raw)
        if not isinstance(report, dict):
            raise ValueError("Scanner JSON is not an object")
        manifest["scanner_coverage"] = {
            key: report.get(key)
            for key in ("success", "files_scanned", "scanner_names", "scanner_selection", "file_metadata", "assets")
        }
        review = review_findings(
            report, raw, exit_code, artifacts, root, output, reviewer, max_groups=max_review_groups
        )
    except (Exception, KeyboardInterrupt) as exc:
        review = ReviewReport(
            scan_sha256=digest(raw) if raw else "",
            scan_exit_code=exit_code,
            review_status="failed",
            selected_count=0,
            reviewed_count=0,
            entries=[],
            errors=[
                "Review interrupted; scanner result unchanged"
                if isinstance(exc, KeyboardInterrupt)
                else f"{type(exc).__name__}: {exc}"
            ],
        )
    try:
        write_json(output / "manifest.json", manifest)
        write_json(output / "review.json", review.model_dump())
        (output / "review.md").write_text(render_markdown(review), encoding="utf-8")
        # Escape controls in paths/errors; raw diagnostics remain in the private bundle.
        print(
            f"Advisory review: {review.review_status}; scanner exit: {exit_code}; bundle: {str(output)!a}",
            file=sys.stderr,
        )
        for error in review.errors:
            print(ascii(error), file=sys.stderr)
    except (Exception, KeyboardInterrupt) as exc:
        # Failed or interrupted advisory output, including diagnostics, cannot replace the scanner exit.
        with suppress(Exception, KeyboardInterrupt):
            print(f"Review output incomplete: {str(exc)!a}; scanner exit: {exit_code}", file=sys.stderr)
    return exit_code
