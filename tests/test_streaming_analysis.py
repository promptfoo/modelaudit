import fsspec
from fsspec.implementations.local import LocalFileSystem

from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.utils import streaming


def test_stream_analyze_file_uses_scanner(tmp_path, monkeypatch):
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00.")
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    called: dict[str, bool] = {"called": False}

    def fake_scan_pickle_bytes(self, file_obj, size):
        called["called"] = True
        result = ScanResult(scanner_name=self.name)
        result.add_issue("scanner issue", IssueSeverity.WARNING, location="memory")
        result.metadata["scanner_used"] = True
        result.bytes_scanned = size
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", fake_scan_pickle_bytes)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner)

    assert was_complete is True
    assert result is not None
    assert called["called"] is True
    assert any(issue.message == "scanner issue" for issue in result.issues)
    assert result.metadata.get("scanner_used") is True


def test_stream_analyze_file_falls_back_to_bytes_to_read(tmp_path, monkeypatch):
    file_path = tmp_path / "sample.pkl"
    file_path.write_bytes(b"\x80\x04K*\x85q\x00." * 2)
    url = f"file://{file_path}"

    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())

    called: dict[str, bool] = {"called": False}

    def fake_scan_pickle_bytes(self, file_obj, size):
        called["called"] = True
        result = ScanResult(scanner_name=self.name)
        result.add_issue("scanner issue", IssueSeverity.WARNING, location="memory")
        result.finish(success=True)
        return result

    monkeypatch.setattr(PickleScanner, "_scan_pickle_bytes", fake_scan_pickle_bytes)

    scanner = PickleScanner()
    result, was_complete = streaming.stream_analyze_file(url, scanner, max_bytes=4)

    assert called["called"] is True
    assert was_complete is False
    assert result is not None
    assert result.bytes_scanned == 4
