from pathlib import Path
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
    def __init__(self, payload: bytes, read_sizes: list[int]) -> None:
        self._payload = payload
        self._read_sizes = read_sizes

    def __enter__(self) -> "_FakeLargeRemoteFile":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback

    def read(self, size: int = -1) -> bytes:
        self._read_sizes.append(size)
        if size < 0:
            return self._payload
        return self._payload[:size]


class _FakeLargeRemoteFileSystem:
    def __init__(self, *, size: object, payload: bytes, read_sizes: list[int]) -> None:
        self._size = size
        self._payload = payload
        self._read_sizes = read_sizes

    def info(self, path: str) -> dict[str, object]:
        del path
        return {"size": self._size}

    def open(self, path: str, mode: str = "rb") -> _FakeLargeRemoteFile:
        del path, mode
        return _FakeLargeRemoteFile(self._payload, self._read_sizes)


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

    assert read_sizes == [1]
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
