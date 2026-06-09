import pickle
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock
from urllib.parse import urlsplit, urlunsplit

import fsspec
import pytest
from fsspec.implementations.local import LocalFileSystem

from modelaudit.scanners.base import BaseScanner, IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.utils.file import streaming
from modelaudit.utils.file.streaming import STREAMING_ANALYSIS_DEFAULT_MAX_BYTES


class HeaderOnlyScanner(BaseScanner):
    name = "header_only"

    def scan(self, path: str) -> ScanResult:
        del path
        raise RuntimeError("full scan is not available for streaming fallback")


class RecordingStreamScanner(HeaderOnlyScanner):
    def __init__(self) -> None:
        super().__init__()
        self.seen_size: int | None = None

    def scan_stream(self, file_obj: object, size: int, source: str = "<stream>") -> ScanResult:
        del file_obj, source
        self.seen_size = size
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = size
        result.finish(success=True)
        return result


class _FakeLargeRemoteFile:
    def __init__(self, payload: bytes, read_sizes: list[int], first_read_limit: int | None = None) -> None:
        self._payload = payload
        self._read_sizes = read_sizes
        self._first_read_limit = first_read_limit
        self._offset = 0
        self._read_count = 0

    def __enter__(self) -> "_FakeLargeRemoteFile":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback

    def read(self, size: int = -1) -> bytes:
        self._read_sizes.append(size)
        effective_size = size
        if self._read_count == 0 and self._first_read_limit is not None and size >= 0:
            effective_size = min(size, self._first_read_limit)
        self._read_count += 1
        if effective_size < 0:
            chunk = self._payload[self._offset :]
        else:
            chunk = self._payload[self._offset : self._offset + effective_size]
        self._offset += len(chunk)
        return chunk


class _FakeLargeRemoteFileSystem:
    def __init__(
        self,
        *,
        size: object,
        payload: bytes,
        read_sizes: list[int],
        first_read_limit: int | None = None,
    ) -> None:
        self._size = size
        self._payload = payload
        self._read_sizes = read_sizes
        self._first_read_limit = first_read_limit

    def info(self, path: str) -> dict[str, object]:
        del path
        return {"size": self._size}

    def open(self, path: str, mode: str = "rb") -> _FakeLargeRemoteFile:
        del path, mode
        return _FakeLargeRemoteFile(self._payload, self._read_sizes, self._first_read_limit)


def _mock_stream_filesystem(
    monkeypatch: pytest.MonkeyPatch,
    *,
    declared_size: object,
    payload: bytes,
) -> MagicMock:
    fs = MagicMock()
    fs.info.return_value = {"size": declared_size}
    fs.open.return_value.__enter__.return_value = BytesIO(payload)
    monkeypatch.setattr(streaming, "get_fs_protocol", lambda _url: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda _protocol, **_kwargs: fs)
    return fs


def test_stream_source_path_distinguishes_encoded_query_from_filename() -> None:
    signed_url = "https://bucket.example/model.pkl%3FX-Amz-Signature%3Dsecret"
    double_encoded_signed_url = "https://bucket.example/model.pkl%253FX-Amz-Signature%253Dsecret"
    four_times_encoded_signed_url = "https://bucket.example/model.pkl%2525253FX-Amz-Signature%2525253Dsecret"
    literal_question_mark = "https://bucket.example/model%3Fv1.pkl"
    double_encoded_literal_question_mark = "https://bucket.example/model%253Fv1.pkl"
    literal_question_mark_with_signed_query = "https://bucket.example/model%3Fv1.pkl%3FX-Amz-Signature%3Dsecret"

    assert streaming.stream_source_path(signed_url) == "/model.pkl"
    assert streaming.stream_source_path(double_encoded_signed_url) == "/model.pkl"
    assert streaming.stream_source_path(four_times_encoded_signed_url) == "/model.pkl"
    assert streaming.can_stream_analyze(double_encoded_signed_url, PickleScanner()) is True
    assert streaming.stream_source_path(literal_question_mark) == "/model?v1.pkl"
    assert streaming.stream_source_path(double_encoded_literal_question_mark) == "/model?v1.pkl"
    assert streaming.stream_source_path(literal_question_mark_with_signed_query) == "/model?v1.pkl"
    assert streaming.can_stream_analyze(literal_question_mark_with_signed_query, PickleScanner()) is True


@pytest.mark.parametrize(
    "url",
    [
        "s3://bucket/model?variant.pkl",
        "gs://bucket/model#variant.pkl",
        "r2://bucket/model?variant#fragment.pkl",
    ],
)
def test_stream_source_path_preserves_native_object_key_delimiters(url: str) -> None:
    assert streaming.stream_source_path(url).endswith(".pkl")
    assert streaming.can_stream_analyze(url, PickleScanner()) is True


def test_stream_analyze_file_uses_normalized_provider_path(monkeypatch: pytest.MonkeyPatch) -> None:
    fs = MagicMock()
    fs.info.return_value = {"size": 4}
    fs.open.return_value.__enter__.return_value = BytesIO(b"data")
    filesystem = MagicMock(return_value=fs)
    source_url = "https://bucket.s3.us-west-2.amazonaws.com/model.pkl"
    normalized_url = "s3://bucket/model.pkl"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda _url: "s3")
    monkeypatch.setattr(
        streaming,
        "get_cloud_filesystem_config",
        lambda _url: ("s3", normalized_url, {"anon": True}),
    )
    monkeypatch.setattr(fsspec, "filesystem", filesystem)

    result, analysis_complete = streaming.stream_analyze_file(source_url, RecordingStreamScanner())

    assert result is not None
    assert analysis_complete is True
    filesystem.assert_called_once_with("s3", anon=True)
    fs.info.assert_called_once_with(normalized_url)
    fs.open.assert_called_once_with(normalized_url, "rb")


def test_stream_analyze_file_preserves_authoritative_coverage_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MisreportingScanner(RecordingStreamScanner):
        def scan_stream(self, file_obj: object, size: int, source: str = "<stream>") -> ScanResult:
            result = super().scan_stream(file_obj, size, source)
            result.metadata.update(
                {
                    "analysis_complete": True,
                    "bytes_analyzed": 999,
                    "bytes_complete": True,
                    "file_size": 1,
                    "file_size_known": True,
                    "max_bytes": 999,
                    "streaming_analysis": False,
                }
            )
            return result

    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=100, payload=b"payload", read_sizes=read_sizes)
    monkeypatch.setattr(streaming, "get_fs_protocol", lambda _url: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda _protocol, **_kwargs: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/model.pkl",
        MisreportingScanner(),
        max_bytes=4,
    )

    assert result is not None
    assert analysis_complete is False
    assert result.metadata["analysis_complete"] is False
    assert result.metadata["bytes_analyzed"] == 4
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["file_size"] == 100
    assert result.metadata["file_size_known"] is True
    assert result.metadata["reported_file_size"] == 100
    assert result.metadata["max_bytes"] == 4
    assert result.metadata["streaming_analysis"] is True


def test_stream_analyze_file_default_read_is_bounded_for_large_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"model-header-only"
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=STREAMING_ANALYSIS_DEFAULT_MAX_BYTES + 4096,
        payload=payload,
        read_sizes=read_sizes,
    )

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/large.joblib", HeaderOnlyScanner())

    assert read_sizes == [STREAMING_ANALYSIS_DEFAULT_MAX_BYTES]
    assert analysis_complete is False
    assert result is not None
    assert result.issues == []
    assert result.bytes_scanned == len(payload)
    assert result.success is False
    assert result.metadata["max_bytes"] == STREAMING_ANALYSIS_DEFAULT_MAX_BYTES
    assert result.metadata["bytes_analyzed"] == len(payload)
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]


def test_stream_analyze_file_bounded_large_remote_still_reports_header_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=STREAMING_ANALYSIS_DEFAULT_MAX_BYTES + 4096,
        payload=b"os\nsystem",
        read_sizes=read_sizes,
    )

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/large.pkl", HeaderOnlyScanner())

    assert read_sizes == [STREAMING_ANALYSIS_DEFAULT_MAX_BYTES]
    assert analysis_complete is False
    assert result is not None
    assert any(issue.type == "streaming_security_check" for issue in result.issues)
    assert result.has_errors is True
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_passes_actual_short_read_size_to_scanner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"short-read"
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=STREAMING_ANALYSIS_DEFAULT_MAX_BYTES + 4096,
        payload=payload,
        read_sizes=read_sizes,
    )
    scanner = RecordingStreamScanner()

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/large.pkl", scanner)

    assert read_sizes == [STREAMING_ANALYSIS_DEFAULT_MAX_BYTES]
    assert scanner.seen_size == len(payload)
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == len(payload)
    assert result.metadata["bytes_analyzed"] == len(payload)


def test_stream_analyze_file_detects_remote_growth_after_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"grew!"
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=len(payload) - 1,
        payload=payload,
        read_sizes=read_sizes,
    )
    scanner = RecordingStreamScanner()

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/changing.pkl", scanner)

    assert read_sizes == [len(payload)]
    assert scanner.seen_size == len(payload)
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == len(payload)
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_probes_after_exact_reported_size_short_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported_size = 4
    payload = b"safeX"
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=reported_size,
        payload=payload,
        read_sizes=read_sizes,
        first_read_limit=reported_size,
    )
    scanner = RecordingStreamScanner()

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/changing.pkl", scanner)

    assert read_sizes == [reported_size + 1, 1]
    assert scanner.seen_size == reported_size
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == reported_size
    assert result.success is False
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_fails_closed_when_reported_size_equals_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"safe" + b"os\nsystem"
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=4,
        payload=payload,
        read_sizes=read_sizes,
    )
    scanner = RecordingStreamScanner()

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/changing.pkl",
        scanner,
        max_bytes=4,
    )

    assert read_sizes == [4]
    assert scanner.seen_size == 4
    assert analysis_complete is False
    assert result is not None
    assert result.success is False
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"


@pytest.mark.parametrize("reported_size", [-1, None])
def test_stream_analyze_file_bounds_reads_when_remote_size_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
    reported_size: object,
) -> None:
    payload = b"short-read"
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=reported_size,
        payload=payload,
        read_sizes=read_sizes,
    )

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/unknown-size.joblib", HeaderOnlyScanner())

    assert read_sizes == [STREAMING_ANALYSIS_DEFAULT_MAX_BYTES]
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == len(payload)
    assert result.success is False
    assert result.metadata["file_size"] == reported_size
    assert result.metadata["file_size_known"] is False
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_treats_empty_remote_as_known_and_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=0,
        payload=b"",
        read_sizes=read_sizes,
    )
    scanner = RecordingStreamScanner()

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file("s3://bucket/empty.pkl", scanner)

    assert read_sizes == [1, 1]
    assert scanner.seen_size == 0
    assert analysis_complete is True
    assert result is not None
    assert result.bytes_scanned == 0
    assert result.success is True
    assert result.metadata["file_size_known"] is True
    assert result.metadata["bytes_complete"] is True


def test_stream_analyze_file_uses_scanner_read_cap_when_file_size_is_unlimited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=100,
        payload=b"abcdef",
        read_sizes=read_sizes,
    )

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_size": 0, "max_file_read_size": 4}),
    )

    assert read_sizes == [4]
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == 4
    assert result.metadata["max_bytes"] == 4
    assert result.metadata["bytes_analyzed"] == 4


def test_stream_analyze_file_does_not_expand_default_cap_to_large_file_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=STREAMING_ANALYSIS_DEFAULT_MAX_BYTES + 4096,
        payload=b"header",
        read_sizes=read_sizes,
    )

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_size": 50 * 1024 * 1024 * 1024}),
    )

    assert read_sizes == [STREAMING_ANALYSIS_DEFAULT_MAX_BYTES]
    assert analysis_complete is False
    assert result is not None
    assert result.metadata["max_bytes"] == STREAMING_ANALYSIS_DEFAULT_MAX_BYTES
    assert result.metadata["bytes_complete"] is False


def test_stream_analyze_file_uses_scanner_config_cap_for_large_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(
        size=100,
        payload=b"abcdef",
        read_sizes=read_sizes,
    )

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_size": 4}),
    )

    assert read_sizes == [4]
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == 4
    assert result.metadata["max_bytes"] == 4
    assert result.metadata["bytes_analyzed"] == 4
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_prefers_streaming_specific_config_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=100, payload=b"abcdef", read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_size": 8, "streaming_max_bytes": 3}),
    )

    assert read_sizes == [3]
    assert analysis_complete is False
    assert result is not None
    assert result.bytes_scanned == 3
    assert result.metadata["max_bytes"] == 3


def test_stream_analyze_file_tightens_streaming_specific_cap_with_scanner_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=100, payload=b"abcdef", read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_read_size": 4, "streaming_max_bytes": 8}),
    )

    assert read_sizes == [4]
    assert analysis_complete is False
    assert result is not None
    assert result.metadata["max_bytes"] == 4


def test_stream_analyze_file_tightens_explicit_cap_with_scanner_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=100, payload=b"abcdef", read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_read_size": 4}),
        max_bytes=8,
    )

    assert read_sizes == [4]
    assert analysis_complete is False
    assert result is not None
    assert result.metadata["max_bytes"] == 4


@pytest.mark.parametrize("invalid_streaming_max", [0, -1, True, "3"])
def test_stream_analyze_file_ignores_invalid_streaming_specific_cap(
    monkeypatch: pytest.MonkeyPatch,
    invalid_streaming_max: object,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=100, payload=b"abcdef", read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_read_size": 4, "streaming_max_bytes": invalid_streaming_max}),
    )

    assert read_sizes == [4]
    assert analysis_complete is False
    assert result is not None
    assert result.metadata["max_bytes"] == 4


@pytest.mark.parametrize("invalid_max_bytes", [0, -1, True])
def test_stream_analyze_file_ignores_invalid_explicit_cap(
    monkeypatch: pytest.MonkeyPatch,
    invalid_max_bytes: int,
) -> None:
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=100, payload=b"abcdef", read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/large.joblib",
        HeaderOnlyScanner(config={"max_file_read_size": 4}),
        max_bytes=invalid_max_bytes,
    )

    assert read_sizes == [4]
    assert analysis_complete is False
    assert result is not None
    assert result.metadata["max_bytes"] == 4


def test_stream_analyze_file_uses_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    called: dict[str, bool] = {"called": False}

    def fake_scan_stream(
        self: PickleScanner,
        file_obj: object,
        size: int,
        source: str = "<stream>",
    ) -> ScanResult:
        called["called"] = True
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Test Check",
            passed=False,
            message="scanner issue",
            severity=IssueSeverity.WARNING,
            location=source,
        )
        result.metadata["scanner_used"] = True
        result.bytes_scanned = size
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner)

    assert was_complete is True
    assert result is not None
    assert called["called"] is True
    assert any(issue.message == "scanner issue" for issue in result.issues)
    assert all(issue.location == url for issue in result.issues)
    assert result.metadata.get("scanner_used") is True


def test_stream_analyze_file_falls_back_to_bytes_to_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00." * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    called: dict[str, bool] = {"called": False}

    def fake_scan_stream(self: PickleScanner, file_obj: object, size: int) -> ScanResult:
        called["called"] = True
        result = ScanResult(scanner_name=self.name)
        result.add_check(
            name="Test Check", passed=False, message="scanner issue", severity=IssueSeverity.WARNING, location="memory"
        )
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner, max_bytes=4)

    assert called["called"] is True
    assert was_complete is False
    assert result is not None
    assert result.bytes_scanned == 4
    assert result.success is False
    assert result.has_warnings is True
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_bounds_negative_declared_size(monkeypatch: pytest.MonkeyPatch) -> None:
    fs = _mock_stream_filesystem(monkeypatch, declared_size=-1, payload=b"malicious payload")

    result, was_complete = streaming.stream_analyze_file("file:///model.pkl", HeaderOnlyScanner(), max_bytes=4)

    assert result is not None
    assert was_complete is False
    assert result.metadata["file_size_known"] is False
    assert result.metadata["bytes_analyzed"] == 4
    fs.open.assert_called_once()


def test_stream_analyze_file_marks_short_reads_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_stream_filesystem(monkeypatch, declared_size=8, payload=b"1234")

    result, was_complete = streaming.stream_analyze_file("file:///model.pkl", HeaderOnlyScanner(), max_bytes=8)

    assert result is not None
    assert was_complete is False
    assert result.metadata["bytes_analyzed"] == 4
    assert result.metadata["bytes_complete"] is False


def test_stream_analyze_file_detects_underreported_size_within_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_stream_filesystem(monkeypatch, declared_size=2, payload=b"1234")

    result, was_complete = streaming.stream_analyze_file("file:///model.pkl", HeaderOnlyScanner(), max_bytes=4)

    assert result is not None
    assert was_complete is False
    assert result.metadata["bytes_analyzed"] == 3
    assert result.metadata["bytes_complete"] is False
    assert result.metadata["file_size"] is None
    assert result.metadata["file_size_known"] is False
    assert result.metadata["reported_file_size"] == 2


def test_stream_analyze_file_detects_content_reported_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_stream_filesystem(monkeypatch, declared_size=0, payload=b"malicious payload")

    result, was_complete = streaming.stream_analyze_file("file:///model.pkl", HeaderOnlyScanner(), max_bytes=4)

    assert result is not None
    assert was_complete is False
    assert result.metadata["bytes_analyzed"] == 1
    assert result.metadata["bytes_complete"] is False


def test_stream_analyze_file_confirms_reported_empty_content(monkeypatch: pytest.MonkeyPatch) -> None:
    fs = _mock_stream_filesystem(monkeypatch, declared_size=0, payload=b"")

    result, was_complete = streaming.stream_analyze_file("file:///model.pkl", HeaderOnlyScanner(), max_bytes=4)

    assert result is not None
    assert was_complete is False
    assert result.metadata["bytes_complete"] is True
    assert result.metadata["analysis_complete"] is False
    fs.open.assert_called_once()


def test_stream_analyze_file_fails_closed_when_declared_size_equals_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_stream_filesystem(monkeypatch, declared_size=4, payload=b"1234")

    result, was_complete = streaming.stream_analyze_file("file:///model.pkl", HeaderOnlyScanner(), max_bytes=4)

    assert result is not None
    assert was_complete is False
    assert result.metadata["bytes_analyzed"] == 4
    assert result.metadata["bytes_complete"] is False


def test_stream_analyze_file_returns_clean_partial_scanner_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00." * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    def fake_scan_stream(self: PickleScanner, file_obj: object, size: int) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        result.bytes_scanned = size
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner, max_bytes=4)

    assert was_complete is False
    assert result is not None
    assert result.issues == []
    assert result.bytes_scanned == 4
    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_does_not_report_truncation_as_a_security_issue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pickle.dumps({"weights": list(range(1000))}, protocol=4)
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=len(payload), payload=payload, read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/benign.pkl",
        PickleScanner(),
        max_bytes=32,
    )

    assert read_sizes == [32]
    assert analysis_complete is False
    assert result is not None
    assert result.issues == []
    assert result.metadata["pickle_verdict"] == "unknown"
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_preserves_malicious_findings_from_partial_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malicious_pickle = b"cos\nsystem\n(S'echo hi'\ntR."
    payload = malicious_pickle + (b"padding" * 16)
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=len(payload), payload=payload, read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/malicious.pkl",
        PickleScanner(),
        max_bytes=len(malicious_pickle),
    )

    assert read_sizes == [len(malicious_pickle)]
    assert analysis_complete is False
    assert result is not None
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("os.system" in issue.message for issue in result.issues)
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_preserves_proven_oversized_frame_from_partial_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed_pickle = b"\x80\x04\x95" + (1000).to_bytes(8, "little") + b"N."
    payload = malformed_pickle + (b"padding" * 16)
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=len(payload), payload=payload, read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/malformed.pkl",
        PickleScanner(),
        max_bytes=len(malformed_pickle),
    )

    assert analysis_complete is False
    assert result is not None
    assert any(issue.details.get("tamper_type") == "oversized_frame" for issue in result.issues)
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_does_not_use_stale_size_to_prove_oversized_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00}."
    read_sizes: list[int] = []
    fake_fs = _FakeLargeRemoteFileSystem(size=len(payload) - 2, payload=payload, read_sizes=read_sizes)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "s3")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: fake_fs)

    result, analysis_complete = streaming.stream_analyze_file(
        "s3://bucket/growing.pkl",
        PickleScanner(),
    )

    assert read_sizes == [len(payload) - 1]
    assert analysis_complete is False
    assert result is not None
    assert not any(issue.details.get("tamper_type") == "oversized_frame" for issue in result.issues)
    assert result.metadata["pickle_verdict"] == "unknown"
    assert result.metadata["scan_outcome"] == "inconclusive"


def test_stream_analyze_file_returns_clean_partial_header_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.joblib"
    file_path.write_bytes(b"model-header-only" * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, was_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner(), max_bytes=4)

    assert was_complete is False
    assert result is not None
    assert result.issues == []
    assert result.bytes_scanned == 4
    assert result.success is False
    assert result.has_warnings is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["streaming_analysis"] is True
    assert result.metadata["bytes_analyzed"] == 4
    assert result.metadata["analysis_complete"] is False
    assert "streaming_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_signed_pickle_url_uses_path_for_header_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signed URL queries must not hide pickle extensions from fallback checks."""
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"os\nsystem")
    signed_url = f"{file_path.as_uri()}?X-Amz-Signature=secret"

    class QueryIgnoringLocalFileSystem(LocalFileSystem):
        @staticmethod
        def _without_query(path: str) -> str:
            parts = urlsplit(path)
            return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

        def info(self, path: str, **kwargs: object) -> dict[str, object]:
            return dict(super().info(self._without_query(path), **kwargs))

        def open(self, path: str, mode: str = "rb", **kwargs: object) -> object:
            return super().open(self._without_query(path), mode=mode, **kwargs)

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: QueryIgnoringLocalFileSystem())

    result, analysis_complete = streaming.stream_analyze_file(signed_url, HeaderOnlyScanner())

    assert analysis_complete is False
    assert result is not None
    assert any(issue.type == "streaming_security_check" for issue in result.issues)


def test_stream_analyze_file_returns_incomplete_full_header_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.joblib"
    file_path.write_bytes(b"model-header-only")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, analysis_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner())

    assert analysis_complete is False
    assert result is not None
    assert result.issues == []
    assert result.bytes_scanned == file_path.stat().st_size
    assert result.success is False
    assert result.metadata["bytes_complete"] is True
    assert result.metadata["analysis_complete"] is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "streaming_header_only_fallback" in result.metadata["scan_outcome_reasons"]
    assert "failed closed" in result.metadata["scan_outcome_message"]


def test_stream_analyze_file_protocol_marker_only_does_not_emit_protocol_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "protocol_only.pkl"
    file_path.write_bytes(b"\x80\x03")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, analysis_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner())

    assert analysis_complete is False
    assert result is not None
    assert not any(issue.type == "streaming_pickle_protocol_check" for issue in result.issues)
    assert result.has_warnings is False


def test_stream_analyze_file_protocol_with_payload_still_emits_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "protocol_payload.pkl"
    file_path.write_bytes(b"\x80\x03N.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, analysis_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner())

    assert analysis_complete is False
    assert result is not None
    assert any(issue.type == "streaming_pickle_protocol_check" for issue in result.issues)
    assert result.has_warnings is True


def test_stream_analyze_file_partial_protocol_marker_still_emits_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "partial_protocol.pkl"
    file_path.write_bytes(b"\x80\x03N.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    result, analysis_complete = streaming.stream_analyze_file(url, HeaderOnlyScanner(), max_bytes=2)

    assert analysis_complete is False
    assert result is not None
    assert any(issue.type == "streaming_pickle_protocol_check" for issue in result.issues)
    assert result.has_warnings is True


def test_stream_analyze_file_does_not_retry_sourceful_scan_stream_typeerror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    call_count = 0

    def fake_scan_stream(
        self: PickleScanner,
        file_obj: object,
        size: int,
        source: str = "<stream>",
    ) -> ScanResult:
        del self, file_obj, size, source
        nonlocal call_count
        call_count += 1
        raise TypeError("simulated runtime type error")

    monkeypatch.setattr(PickleScanner, "scan_stream", fake_scan_stream)

    scanner = PickleScanner()
    result, analysis_complete = streaming.stream_analyze_file(url, scanner)

    assert call_count == 1
    assert analysis_complete is False
    assert result is not None
