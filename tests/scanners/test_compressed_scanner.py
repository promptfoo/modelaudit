import bz2
import gzip
import io
import lzma
import pickle
import tarfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

from modelaudit.scanners import get_scanner_for_file
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.compressed_scanner import CompressedScanner, _MissingOptionalDependencyError

TarWriteMode = Literal["w:gz", "w:bz2", "w:xz"]


class _MaliciousPayload:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("print('owned')",))


def test_compressed_scanner_can_handle_requires_matching_signature(tmp_path: Path) -> None:
    valid_gzip_path = tmp_path / "model.pkl.gz"
    valid_gzip_path.write_bytes(gzip.compress(pickle.dumps({"weights": [1, 2, 3]})))

    invalid_gzip_path = tmp_path / "model.txt.gz"
    invalid_gzip_path.write_bytes(b"not-gzip")

    assert CompressedScanner.can_handle(str(valid_gzip_path)) is True
    assert CompressedScanner.can_handle(str(invalid_gzip_path)) is False


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("model.tar.gz", "w:gz"),
        ("model.tar.bz2", "w:bz2"),
        ("model.tar.xz", "w:xz"),
    ],
)
def test_compound_tar_wrappers_route_to_tar_scanner(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = tmp_path / filename
    payload = b"weights"

    with tarfile.open(archive_path, mode) as tar:
        info = tarfile.TarInfo("weights.bin")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "tar"


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("safe.tar.gz", "w:gz"),
        ("safe.tar.bz2", "w:bz2"),
        ("safe.tar.xz", "w:xz"),
    ],
)
def test_compound_tar_wrappers_scan_benign_payloads_without_critical_findings(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = tmp_path / filename
    payload = pickle.dumps({"weights": [1, 2, 3]})

    with tarfile.open(archive_path, mode) as tar:
        info = tarfile.TarInfo("safe.pkl")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "tar"

    result = scanner.scan(str(archive_path))
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues == []


@pytest.mark.parametrize(
    ("filename", "mode"),
    [
        ("malicious.tar.gz", "w:gz"),
        ("malicious.tar.bz2", "w:bz2"),
        ("malicious.tar.xz", "w:xz"),
    ],
)
def test_compound_tar_wrappers_surface_malicious_inner_findings(
    tmp_path: Path,
    filename: str,
    mode: TarWriteMode,
) -> None:
    archive_path = tmp_path / filename
    payload = pickle.dumps({"payload": _MaliciousPayload()})

    with tarfile.open(archive_path, mode) as tar:
        info = tarfile.TarInfo("evil.pkl")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    scanner = get_scanner_for_file(str(archive_path))

    assert scanner is not None
    assert scanner.name == "tar"

    result = scanner.scan(str(archive_path))
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues
    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(issue.location == f"{archive_path}:evil.pkl" for issue in critical_issues)


def test_compressed_scanner_routes_benign_inner_payload(tmp_path: Path) -> None:
    safe_pickle = pickle.dumps({"layer": [1, 2, 3]})
    path = tmp_path / "safe_model.pkl.gz"
    path.write_bytes(gzip.compress(safe_pickle))

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    assert result.success is True

    routing_checks = [c for c in result.checks if c.name == "Compressed Wrapper Inner Scanner Routing"]
    assert routing_checks and routing_checks[0].status == CheckStatus.PASSED

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_compressed_scanner_surfaces_malicious_inner_findings(tmp_path: Path) -> None:
    malicious_pickle = pickle.dumps({"payload": _MaliciousPayload()})
    path = tmp_path / "malicious.pkl.gz"
    path.write_bytes(gzip.compress(malicious_pickle))

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert critical_issues
    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(issue.location == f"{path} -> malicious.pkl" for issue in critical_issues)


def test_compressed_scanner_corrupt_stream_is_warning_not_critical(tmp_path: Path) -> None:
    path = tmp_path / "broken_payload.gz"
    path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00")

    scanner = CompressedScanner()
    result = scanner.scan(str(path))

    decode_checks = [c for c in result.checks if c.name == "Compressed Wrapper Stream Decode"]
    assert decode_checks and decode_checks[0].status == CheckStatus.FAILED
    assert decode_checks[0].severity == IssueSeverity.WARNING


@pytest.mark.parametrize(
    ("extension", "compressor"),
    [
        (".bz2", bz2.compress),
        (".xz", lzma.compress),
        (".zlib", zlib.compress),
    ],
)
def test_compressed_scanner_enforces_decompression_size_limit(
    tmp_path: Path,
    extension: str,
    compressor: Callable[[bytes], bytes],
) -> None:
    data = b"A" * 4096
    path = tmp_path / f"oversize_payload.bin{extension}"
    path.write_bytes(compressor(data))

    scanner = CompressedScanner(config={"compressed_max_decompressed_bytes": 512})
    result = scanner.scan(str(path))

    limit_checks = [c for c in result.checks if c.name == "Compressed Wrapper Decompression Limits"]
    assert limit_checks and limit_checks[0].status == CheckStatus.FAILED
    assert limit_checks[0].severity == IssueSeverity.WARNING


def test_compressed_scanner_enforces_decompression_ratio_limit(tmp_path: Path) -> None:
    highly_compressible = b"0" * 20_000
    path = tmp_path / "ratio_payload.bin.gz"
    path.write_bytes(gzip.compress(highly_compressible))

    scanner = CompressedScanner(config={"compressed_max_decompression_ratio": 5.0})
    result = scanner.scan(str(path))

    ratio_checks = [c for c in result.checks if c.name == "Compressed Wrapper Decompression Limits"]
    assert ratio_checks and ratio_checks[0].status == CheckStatus.FAILED
    assert ratio_checks[0].severity == IssueSeverity.WARNING


def test_compressed_scanner_false_positive_control_high_ratio_within_policy(tmp_path: Path) -> None:
    highly_compressible = b"0" * 20_000
    path = tmp_path / "policy_ok_payload.txt.gz"
    path.write_bytes(gzip.compress(highly_compressible))

    scanner = CompressedScanner(
        config={
            "compressed_max_decompressed_bytes": 64 * 1024,
            "compressed_max_decompression_ratio": 5000.0,
        },
    )
    result = scanner.scan(str(path))

    ratio_failures = [
        c
        for c in result.checks
        if c.name == "Compressed Wrapper Decompression Limits" and c.status == CheckStatus.FAILED
    ]
    assert len(ratio_failures) == 0


def test_read_zlib_stream_uses_bounded_decompression(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeDecompressor:
        def __init__(self) -> None:
            self.max_lengths: list[int] = []
            self.flush_lengths: list[int] = []

        def decompress(self, _chunk: bytes, max_length: int = 0) -> bytes:
            self.max_lengths.append(max_length)
            return b"x" * min(256, max_length)

        def flush(self, length: int = 0) -> bytes:
            self.flush_lengths.append(length)
            return b""

    fake_decompressor = _FakeDecompressor()

    monkeypatch.setattr(
        "modelaudit.scanners.compressed_scanner.zlib.decompressobj",
        lambda: fake_decompressor,
    )

    CompressedScanner._read_zlib_stream_with_limits(
        source=io.BytesIO(b"compressed"),
        destination=io.BytesIO(),
        max_decompressed_bytes=1024,
        max_ratio=100.0,
        compressed_size=10,
        chunk_size=4,
    )

    assert fake_decompressor.max_lengths
    assert fake_decompressor.max_lengths == [1025, 769, 513]
    assert fake_decompressor.flush_lengths == [257]


def test_read_zlib_stream_allows_exact_limit_real_stream() -> None:
    payload = b"A" * 1024
    compressed = zlib.compress(payload)
    destination = io.BytesIO()

    total_out = CompressedScanner._read_zlib_stream_with_limits(
        source=io.BytesIO(compressed),
        destination=destination,
        max_decompressed_bytes=len(payload),
        max_ratio=1000.0,
        compressed_size=len(compressed),
        chunk_size=1,
    )

    assert total_out == len(payload)
    assert destination.getvalue() == payload


def test_compressed_scanner_missing_lz4_dependency_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lz4_path = tmp_path / "payload.bin.lz4"
    lz4_path.write_bytes(b"\x04\x22\x4d\x18" + b"\x00" * 16)

    def _raise_missing_dependency() -> None:
        raise _MissingOptionalDependencyError("Optional dependency 'lz4' is not installed")

    monkeypatch.setattr(CompressedScanner, "_get_lz4_frame_module", staticmethod(_raise_missing_dependency))

    scanner = CompressedScanner()
    result = scanner.scan(str(lz4_path))

    dependency_checks = [c for c in result.checks if c.name == "Compressed Wrapper Optional Dependency"]
    assert dependency_checks and dependency_checks[0].status == CheckStatus.FAILED
    assert dependency_checks[0].severity == IssueSeverity.INFO
