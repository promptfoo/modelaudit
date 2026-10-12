"""Pinned Hugging Face reproductions for incomplete aggregate coverage."""

from pathlib import Path

import pytest
import requests
from click.testing import CliRunner

from modelaudit.cli import cli
from tests.cli_output import parse_click_json_output

_MAX_DOWNLOAD_BYTES = 2_000_000
_PINNED_FILES = {
    "Fig1.png": (
        "https://huggingface.co/microsoft/VibeVoice-1.5B/resolve/"
        "c00898d257e6b46004e3e2866a47534085fb685a/figures/Fig1.png"
    ),
    "merges.txt": (
        "https://huggingface.co/Qwen/Qwen2.5-VL-7B-Instruct/resolve/cc594898137f460bfe9f0759e9844b3ce807cfb5/merges.txt"
    ),
}


def _mock_pinned_payload(filename: str) -> bytes:
    if filename == "Fig1.png":
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (b"\x00" * 32)
        return png_header + (b"\x00" * (100_000 - len(png_header)))
    if filename == "merges.txt":
        token_merge_fragment = b"\xc4\xa0 \n"
        return (token_merge_fragment * ((1_048_576 // len(token_merge_fragment)) + 1))[:1_048_576]
    raise AssertionError(f"unexpected pinned file requested: {filename}")


def test_pinned_huggingface_inconclusive_files_fail_coverage_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pinned false-positive files must not produce success=true with incomplete metadata."""

    def fake_get(url: str, *args: object, **kwargs: object) -> None:
        pytest.fail(f"unexpected HTTP request during local scan: {url}")

    monkeypatch.setattr(requests, "get", fake_get)

    for filename in _PINNED_FILES:
        payload_bytes = _mock_pinned_payload(filename)
        if len(payload_bytes) > _MAX_DOWNLOAD_BYTES:
            pytest.fail(f"pinned reproduction exceeded byte cap before download: {len(payload_bytes)}")
        (tmp_path / filename).write_bytes(payload_bytes)

    result = CliRunner().invoke(
        cli,
        ["scan", str(tmp_path), "--strict", "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 2, result.output
    payload = parse_click_json_output(result.output)
    assert payload["success"] is False
    assert payload["has_errors"] is False
    assert payload["files_scanned"] == 2

    file_metadata = payload["file_metadata"]
    vibevoice_metadata = file_metadata[str(tmp_path / "Fig1.png")]
    qwen_metadata = file_metadata[str(tmp_path / "merges.txt")]
    assert vibevoice_metadata["scan_outcome"] == "inconclusive"
    assert vibevoice_metadata["analysis_incomplete"] is True
    assert vibevoice_metadata["operational_error"] is True
    assert vibevoice_metadata["operational_error_reason"] == "pickle_routing_incomplete"
    assert "pickle_routing_incomplete" in vibevoice_metadata["scan_outcome_reasons"]
    assert qwen_metadata["scan_outcome"] == "inconclusive"
    assert qwen_metadata["analysis_incomplete"] is True
    assert "flax_msgpack_routing_incomplete" in qwen_metadata["scan_outcome_reasons"]
