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


def _download_bounded(url: str, destination: Path) -> None:
    with requests.get(url, stream=True, timeout=(5, 30)) as response:
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > _MAX_DOWNLOAD_BYTES:
            pytest.fail(f"pinned reproduction exceeded byte cap before download: {content_length}")

        total = 0
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > _MAX_DOWNLOAD_BYTES:
                    pytest.fail(f"pinned reproduction exceeded byte cap: {total}")
                handle.write(chunk)


@pytest.mark.integration
def test_pinned_huggingface_inconclusive_files_fail_coverage_success(tmp_path: Path) -> None:
    """Pinned false-positive files must not produce success=true with incomplete metadata."""
    for filename, url in _PINNED_FILES.items():
        _download_bounded(url, tmp_path / filename)

    result = CliRunner().invoke(
        cli,
        ["scan", str(tmp_path), "--strict", "--format", "json", "--no-cache"],
        catch_exceptions=False,
    )

    assert result.exit_code == 1, result.output
    payload = parse_click_json_output(result.output)
    assert payload["success"] is False
    assert payload["has_errors"] is False
    assert payload["files_scanned"] == 2

    file_metadata = payload["file_metadata"]
    vibevoice_metadata = file_metadata[str(tmp_path / "Fig1.png")]
    qwen_metadata = file_metadata[str(tmp_path / "merges.txt")]
    assert vibevoice_metadata["scan_outcome"] == "inconclusive"
    assert vibevoice_metadata["analysis_incomplete"] is True
    assert "pickle_analysis_incomplete" in vibevoice_metadata["scan_outcome_reasons"]
    assert qwen_metadata["scan_outcome"] == "inconclusive"
    assert qwen_metadata["analysis_incomplete"] is True
    assert "flax_msgpack_routing_incomplete" in qwen_metadata["scan_outcome_reasons"]
