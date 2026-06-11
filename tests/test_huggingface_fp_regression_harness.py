"""Opt-in Hugging Face false-positive regression harness."""

from __future__ import annotations

import json
import os
import struct
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.core import determine_exit_code, scan_model_directory_or_file, scan_model_streaming
from modelaudit.scanner_results import IssueSeverity
from modelaudit.scanner_selection import scanner_selection_config_from_inputs
from modelaudit.utils.sources.huggingface import _select_streamable_hf_files
from tests.cli_output import parse_click_json_output
from tests.helpers import create_mock_pytorch_zip

MANIFEST_PATH = Path(__file__).parent / "assets" / "huggingface_false_positive_manifest.json"
LIVE_ENV_VAR = "MODELAUDIT_RUN_HF_FP_LIVE"
FULL_MATRIX_ENV_VAR = "MODELAUDIT_RUN_HF_FP_FULL_MATRIX"
REQUIRED_REVISIONS = {
    "sentence-transformers/all-MiniLM-L6-v2": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    "nvidia/LocateAnything-3B": "272068e81a31e88a48ea03c20a09decba2b62ed6",
    "unsloth/gemma-4-12b-it-GGUF": "3249fa54d5efa384afc552cc6700ad091efd5c39",
    "google-bert/bert-base-uncased": "86b5e0934494bd15c9632b12f734a8a67f723594",
    "nvidia/nemotron-3.5-asr-streaming-0.6b": "24b151a851dd15909e1fc611b11bb2da52b9fc81",
    "meta-llama/Llama-3.1-8B-Instruct": "0e9e39f249a16976918f6564b8830bc894c89659",
    "BAAI/bge-m3": "5617a9f61b028005a4858fdac845db406aefb181",
}


def _load_manifest() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(manifest, dict)
    return manifest


def _manifest_cases() -> list[dict[str, Any]]:
    cases = _load_manifest()["cases"]
    assert isinstance(cases, list)
    return [case for case in cases if isinstance(case, dict)]


def _case_by_rank(rank: int) -> dict[str, Any]:
    for case in _manifest_cases():
        if case["rank"] == rank:
            return case
    raise AssertionError(f"manifest is missing rank {rank}")


def _write_minimal_safetensors(path: Path) -> Path:
    header = {
        "__metadata__": {"format": "pt"},
        "weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header_bytes += b" " * ((8 - len(header_bytes) % 8) % 8)
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + struct.pack("<f", 1.0))
    return path


def _write_malicious_pickle(path: Path) -> Path:
    path.write_bytes(b"cos\nsystem\n(S'echo hf-fp-control'\ntR.")
    return path


def _generate_malicious_control(path: Path, control: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    generator = control["generator"]
    if generator == "synthetic_malicious_pytorch_zip":
        return create_mock_pytorch_zip(path, malicious=True)
    if generator == "synthetic_malicious_pickle":
        return _write_malicious_pickle(path)
    raise AssertionError(f"unknown malicious control generator: {generator}")


def _scanner_config(scanners: Sequence[str]) -> dict[str, Any]:
    return scanner_selection_config_from_inputs(scanners=tuple(scanners))


def _noisy_issue_messages(result: Any) -> list[str]:
    return [
        issue.message for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]


def _stream(paths: Sequence[Path]) -> Iterator[tuple[Path, bool]]:
    for index, path in enumerate(paths):
        yield path, index == len(paths) - 1


def test_manifest_records_required_pinned_revisions_and_controls() -> None:
    manifest = _load_manifest()

    assert manifest["schema_version"] == 1
    assert manifest["live"]["enabled_by_env"] == LIVE_ENV_VAR
    assert manifest["live"]["full_matrix_env"] == FULL_MATRIX_ENV_VAR

    cases_by_model = {case["model_id"]: case for case in manifest["cases"]}
    assert {model_id: cases_by_model[model_id]["revision"] for model_id in REQUIRED_REVISIONS} == REQUIRED_REVISIONS

    for case in cases_by_model.values():
        assert set(case.get("modes", manifest["defaults"]["modes"])) >= {
            "local-directory",
            "streaming",
            "dry-run",
            "scanner-selective",
        }
        assert isinstance(case["wall_time_budget_seconds"], int)
        assert case["wall_time_budget_seconds"] > 0
        assert isinstance(case["max_download_bytes"], int)
        assert case["max_download_bytes"] > 0
        assert case["expected_outcome"]["exit_code"] == 0
        assert case["expected_outcome"]["success"] is True
        assert case["triggering_paths"]
        for trigger in case["triggering_paths"]:
            assert trigger["path"]
            assert trigger["size_bytes"] > 0
            assert trigger["scanners"]
            assert trigger["expected_outcome"] == "clean"
        control = case["malicious_control"]
        assert control["path"]
        assert control["generator"].startswith("synthetic_malicious_")
        assert control["scanners"]
        assert control["expected_exit_code"] == 1
        assert control["expected_issue_severities"]


def test_local_directory_mode_pairs_clean_snapshot_with_malicious_control(tmp_path: Path) -> None:
    case = _case_by_rank(2)
    trigger = case["triggering_paths"][0]
    snapshot_dir = tmp_path / "snapshot" / case["revision"]
    snapshot_dir.mkdir(parents=True)
    _write_minimal_safetensors(snapshot_dir / trigger["path"])
    (snapshot_dir / "config.json").write_text('{"model_type":"bert"}\n', encoding="utf-8")

    benign = scan_model_directory_or_file(
        str(snapshot_dir),
        skip_file_types=True,
        max_file_size=case["max_download_bytes"],
        max_total_size=case["max_download_bytes"],
        **_scanner_config(trigger["scanners"]),
    )

    assert determine_exit_code(benign) == case["expected_outcome"]["exit_code"]
    assert benign.success is True
    assert not _noisy_issue_messages(benign)

    control = case["malicious_control"]
    control_path = _generate_malicious_control(tmp_path / control["path"], control)
    malicious = scan_model_directory_or_file(
        str(control_path),
        skip_file_types=True,
        **_scanner_config(control["scanners"]),
    )

    assert determine_exit_code(malicious) == control["expected_exit_code"]
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in malicious.issues)


def test_streaming_and_scanner_selective_modes_keep_malicious_controls_explicit(tmp_path: Path) -> None:
    safe_path = _write_minimal_safetensors(tmp_path / "model.safetensors")
    malicious_path = create_mock_pytorch_zip(tmp_path / "payload.pt", malicious=True)

    safetensors_only = scan_model_streaming(
        _stream([safe_path, malicious_path]),
        delete_after_scan=False,
        skip_file_types=True,
        **_scanner_config(["safetensors"]),
    )

    assert determine_exit_code(safetensors_only) == 0
    assert safetensors_only.files_scanned == 2
    assert "safetensors" in safetensors_only.scanner_names
    payload_metadata = safetensors_only.file_metadata[str(malicious_path)]
    assert getattr(payload_metadata, "skipped_scanner_id", None) == "zip"
    assert getattr(payload_metadata, "skip_reason", None) == "scanner_not_enabled"

    full_control = scan_model_streaming(
        _stream([safe_path, malicious_path]),
        delete_after_scan=False,
        skip_file_types=True,
        **_scanner_config(["safetensors", "pytorch_zip", "pickle"]),
    )

    assert determine_exit_code(full_control) == 1
    assert "pytorch_zip" in full_control.scanner_names
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in full_control.issues)


def test_huggingface_streaming_selector_respects_selected_scanner_ids() -> None:
    repo_files = ["model.safetensors", "renamed.payload", "notes.txt"]

    def detect_format(_repo_id: str, filename: str, _revision: str, _budget: object) -> str | None:
        return "pytorch_zip" if filename == "renamed.payload" else None

    with patch("modelaudit.utils.sources.huggingface._detect_huggingface_content_route_format", detect_format):
        safetensors_selected = _select_streamable_hf_files(
            "test/model",
            repo_files,
            "a" * 40,
            scannable_extensions={".safetensors"},
            scannable_scanner_ids={"safetensors"},
        )
        pytorch_selected = _select_streamable_hf_files(
            "test/model",
            repo_files,
            "a" * 40,
            scannable_extensions={".pt"},
            scannable_scanner_ids={"pytorch_zip"},
        )

    assert safetensors_selected == ["model.safetensors"]
    assert "renamed.payload" in pytorch_selected


def test_hf_repo_dry_run_preview_does_not_download_or_scan() -> None:
    runner = CliRunner()
    metadata = {
        "repo_id": "test/model",
        "model_id": "test/model",
        "total_size": 35,
        "file_count": 3,
        "files": [
            {"name": "model.safetensors", "size": 20},
            {"name": "README.md", "size": 10},
            {"name": "notes.txt", "size": 5},
        ],
    }

    with (
        patch("modelaudit.cli.get_model_info", return_value=metadata) as mock_get_model_info,
        patch("modelaudit.cli.download_model") as mock_download_model,
        patch("modelaudit.cli.scan_model_directory_or_file") as mock_scan,
    ):
        result = runner.invoke(
            cli,
            ["scan", "--dry-run", "--format", "json", "--scanners", "safetensors", "hf://test/model"],
        )

    parsed = parse_click_json_output(result.stdout)
    assert result.exit_code == 0
    assert result.stdout.lstrip().startswith("{")
    assert parsed["files_scanned"] == 0
    assert "Download: skipped (--dry-run)" in result.stderr
    assert "Scannable files: 1 of 3" in result.stderr
    mock_get_model_info.assert_called_once_with("hf://test/model")
    mock_download_model.assert_not_called()
    mock_scan.assert_not_called()


def test_hf_file_dry_run_preview_does_not_download_or_scan() -> None:
    url = "https://huggingface.co/test/model/resolve/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/config.json"
    runner = CliRunner()

    with (
        patch(
            "modelaudit.cli.get_huggingface_file_info",
            return_value={
                "repo_id": "test/model",
                "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_revision": "b" * 40,
                "filename": "config.json",
                "size": 123,
            },
        ) as mock_get_file_info,
        patch("modelaudit.cli.download_file_from_hf") as mock_download_file,
        patch("modelaudit.cli.scan_model_directory_or_file") as mock_scan,
    ):
        result = runner.invoke(cli, ["scan", "--dry-run", "--format", "json", url])

    parsed = parse_click_json_output(result.stdout)
    assert result.exit_code == 0
    assert result.stdout.lstrip().startswith("{")
    assert parsed["files_scanned"] == 0
    assert "Type: Hugging Face file" in result.stderr
    assert "Revision: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in result.stderr
    mock_get_file_info.assert_called_once_with(url, max_size=None)
    mock_download_file.assert_not_called()
    mock_scan.assert_not_called()


def test_hf_dry_run_gated_error_redacts_credentials() -> None:
    url = "https://hf_user:hunter2@huggingface.co/meta-llama/Llama-3.1-8B-Instruct?token=secret-query"
    runner = CliRunner()

    with patch("modelaudit.cli.get_model_info") as mock_get_model_info:
        mock_get_model_info.side_effect = Exception(f"403 gated while opening {url}")
        result = runner.invoke(cli, ["scan", "--dry-run", url])

    assert result.exit_code == 2
    assert "meta-llama/Llama-3.1-8B-Instruct" in result.output
    assert "hunter2" not in result.output
    assert "secret-query" not in result.output


def test_hf_file_dry_run_validation_error_redacts_credentials() -> None:
    url = "https://hf_user:hunter2@huggingface.co/test/model/resolve/main/config.json?token=secret-query"
    runner = CliRunner()

    with patch("modelaudit.cli.get_huggingface_file_info") as mock_get_file_info:
        mock_get_file_info.side_effect = Exception(f"404 while opening {url}")
        result = runner.invoke(cli, ["scan", "--dry-run", url])

    assert result.exit_code == 2
    assert "test/model" in result.output
    assert "hunter2" not in result.output
    assert "secret-query" not in result.output


@pytest.mark.integration
@pytest.mark.parametrize("case", _manifest_cases(), ids=lambda case: str(case["id"]))
def test_live_pinned_hf_manifest_case_end_to_end(tmp_path: Path, case: dict[str, Any]) -> None:
    if os.getenv(LIVE_ENV_VAR) != "1":
        pytest.skip(f"set {LIVE_ENV_VAR}=1 to run pinned Hugging Face live regressions")
    if os.getenv(FULL_MATRIX_ENV_VAR) != "1" and case["rank"] != 2:
        pytest.skip(f"set {FULL_MATRIX_ENV_VAR}=1 to run the full pinned Hugging Face matrix")

    auth = case.get("auth", {})
    token_env = str(auth.get("token_env") or _load_manifest()["live"]["token_env"])
    token = os.getenv(token_env)
    if auth.get("gated") and not token:
        pytest.skip(f"{case['model_id']} is gated; set {token_env} for this live case")

    from huggingface_hub import hf_hub_download

    trigger = case["triggering_paths"][0]
    cache_dir = Path(os.getenv("MODELAUDIT_HF_FP_CACHE_DIR", str(tmp_path / "hf-cache")))
    local_dir = tmp_path / "snapshot"
    local_path = Path(
        hf_hub_download(
            repo_id=case["model_id"],
            revision=case["revision"],
            filename=trigger["path"],
            cache_dir=str(cache_dir),
            local_dir=str(local_dir),
            token=token,
        )
    )
    assert local_path.is_file()
    assert local_path.stat().st_size <= case["max_download_bytes"]

    result = scan_model_directory_or_file(
        str(local_path),
        timeout=case["wall_time_budget_seconds"],
        max_file_size=case["max_download_bytes"],
        max_total_size=case["max_download_bytes"],
        skip_file_types=True,
        **_scanner_config(trigger["scanners"]),
    )

    assert determine_exit_code(result) == case["expected_outcome"]["exit_code"]
    assert result.success is case["expected_outcome"]["success"]
    assert not _noisy_issue_messages(result)
