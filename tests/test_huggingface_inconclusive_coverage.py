"""Pinned Hugging Face reproductions for incomplete aggregate coverage."""

from collections.abc import Iterator
from pathlib import Path
from types import TracebackType

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


class _MockResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self) -> "_MockResponse":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        for offset in range(0, len(self._payload), chunk_size):
            yield self._payload[offset : offset + chunk_size]


def _mock_pinned_payload(filename: str) -> bytes:
    if filename == "Fig1.png":
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (b"\x00" * 32)
        return png_header + (b"\x00" * (100_000 - len(png_header)))
    if filename == "merges.txt":
        token_merge_fragment = b"\xc4\xa0 \n"
        return (token_merge_fragment * ((1_048_576 // len(token_merge_fragment)) + 1))[:1_048_576]
    raise AssertionError(f"unexpected pinned file requested: {filename}")


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


def test_pinned_huggingface_inconclusive_files_fail_coverage_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pinned false-positive files must not produce success=true with incomplete metadata."""
    payloads_by_url = {url: _mock_pinned_payload(filename) for filename, url in _PINNED_FILES.items()}
    requested_urls: list[str] = []

    def fake_get(url: str, *args: object, **kwargs: object) -> _MockResponse:
        requested_urls.append(url)
        return _MockResponse(payloads_by_url[url])

    monkeypatch.setattr(requests, "get", fake_get)

    for filename, url in _PINNED_FILES.items():
        _download_bounded(url, tmp_path / filename)
    assert requested_urls == list(_PINNED_FILES.values())

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
