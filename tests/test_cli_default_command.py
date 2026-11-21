"""Default scan dispatch and top-level CLI commands."""

import pickle
from pathlib import Path

import pytest
from click import Context
from click.testing import CliRunner

from modelaudit.cli import cli
from tests.cli_output import parse_click_json_output


@pytest.mark.parametrize(
    "args",
    [
        ["first.pkl", "--format", "json", "--no-cache"],
        ["--format", "json", "--no-cache", "first.pkl"],
        ["-f", "json", "--no-cache", "first.pkl"],
        ["scan", "--format=json", "--no-cache", "first.pkl"],
        ["--no-cache", "--format=json", "first.pkl", "second.pkl"],
    ],
)
def test_scan_argument_order(args: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    first = tmp_path / "first.pkl"
    first.write_bytes(pickle.dumps({"weight": 1}))
    second = tmp_path / "second.pkl"
    second.write_bytes(b"cbuiltins\neval\n(V1+1\ntR.")

    result = CliRunner().invoke(cli, args, catch_exceptions=False)
    flagged = "second.pkl" in args
    assert result.exit_code == int(flagged), result.output
    report = parse_click_json_output(result.output)
    assert report["files_scanned"] == 1 + int(flagged)
    assert any(issue["severity"] == "critical" for issue in report["issues"]) is flagged
    # Catch leaked handles before fixture teardown on Windows.
    first.unlink()
    second.unlink()


@pytest.mark.parametrize(
    ("args", "paths"),
    [
        (["weights.pkl"], ("weights.pkl",)),
        (["first.pkl", "second.h5"], ("first.pkl", "second.h5")),
        (["https://example.invalid/model.pkl"], ("https://example.invalid/model.pkl",)),
        (["--", "doctor", "--version"], ("doctor", "--version")),
    ],
)
def test_implicit_scan_preserves_literal_paths(
    args: list[str], paths: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, ...]] = []

    def capture(paths: tuple[str, ...], **_options: object) -> None:
        seen.append(paths)

    monkeypatch.setattr(cli.commands["scan"], "callback", capture)
    assert CliRunner().invoke(cli, args).exit_code == 0
    assert seen == [paths]


def test_unknown_command_is_a_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli.get_command(Context(cli), "missing") is None
    result = CliRunner().invoke(cli, ["missing"])
    assert result.exit_code == 2
    assert "Path does not exist: missing" in result.output


def test_named_commands_and_global_help() -> None:
    runner = CliRunner()
    doctor = runner.invoke(cli, ["doctor"])
    assert doctor.exit_code == 0
    assert "ModelAudit Scanner Diagnostic Report" in doctor.output
    help_result = runner.invoke(cli, ["--help"])
    assert help_result.exit_code == 0
    assert "modelaudit [OPTIONS] PATHS..." in help_result.output
    assert "modelaudit scan [OPTIONS] PATHS..." in help_result.output
