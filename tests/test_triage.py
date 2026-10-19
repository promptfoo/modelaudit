"""Triage is advisory, bounded, and separate from the scanner contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests
from click.testing import CliRunner

from modelaudit import cli as cli_module
from modelaudit import triage
from modelaudit.core_results import determine_exit_code
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanner_results import IssueSeverity

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
    return result


def mock_api(monkeypatch: pytest.MonkeyPatch, assessments: list[dict[str, str]]) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value = response
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
    assert output and "needs_attention" in output
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
    assert output and "inconclusive" in output and "likely_benign" not in output


@pytest.mark.skipif(os.name != "posix", reason="no-follow document reader is POSIX-only")
@pytest.mark.parametrize("ancestor", [False, True])
def test_documents_do_not_follow_symlinks(tmp_path: Path, ancestor: bool) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "README.md"
    target.write_text("private context")
    link = tmp_path / ("linked" if ancestor else "README.md")
    link.symlink_to(real if ancestor else target)
    assert triage._read_document(str(link / "README.md" if ancestor else link)) is None


def test_request_budgets_are_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = report_for_case(tmp_path)
    result.issues = [result.issues[0].model_copy(deep=True) for _ in range(triage.MAX_FINDINGS + 2)]
    post = mock_api(monkeypatch, [assessment(f"/issues/{i}") for i in range(triage.MAX_FINDINGS)])
    output = triage.triage_findings(result)
    assert output and "20/22 documentation findings" in output
    assert post.call_count == 1
    monkeypatch.setattr(triage, "MAX_INPUT_BYTES", 1)
    post.reset_mock()
    assert "exceed the request limit" in (triage.triage_findings(result) or "")
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
    monkeypatch.setattr(triage, "triage_findings", lambda result: "advice\x1b[2J\rhidden")
    echo = MagicMock()
    monkeypatch.setattr(cli_module.click, "echo", echo)
    cli_module._emit_triage(report_for_case(tmp_path))
    text = echo.call_args.args[0]
    assert "\x1b" not in text and "\r" not in text
    assert "\\x1b" in text


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
    monkeypatch.setattr(triage, "triage_findings", lambda result: "Advice")
    monkeypatch.setattr(cli_module.click, "echo", MagicMock(side_effect=error))
    cli_module._emit_triage(scanned)
    assert scanned.model_dump_json() == before
