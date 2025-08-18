from __future__ import annotations

import io
import lzma
import os
import zlib
from typing import Any, ClassVar

from ..utils.filetype import read_magic_bytes
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner


class JoblibScanner(BaseScanner):
    """Scanner for joblib serialized files."""

    name = "joblib"
    description = "Scans joblib files by decompressing and analyzing embedded pickle"
    supported_extensions: ClassVar[list[str]] = [".joblib"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.pickle_scanner = PickleScanner(config)
        # Security limits
        self.max_decompression_ratio = self.config.get("max_decompression_ratio", 100.0)
        self.max_decompressed_size = self.config.get(
            "max_decompressed_size",
            100 * 1024 * 1024,
        )  # 100MB
        self.chunk_size = self.config.get("chunk_size", 8192)  # 8KB chunks

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        return ext == ".joblib"

    def _read_file_safely(self, path: str) -> bytes:
        """Read file in chunks using the base class helper."""
        return super()._read_file_safely(path)

    def _safe_decompress(self, data: bytes) -> bytes:
        """Safely decompress data with bomb protection"""
        compressed_size = len(data)

        # Try zlib first
        decompressed = None
        try:
            decompressed = zlib.decompress(data)
        except Exception:
            # Try lzma
            try:
                decompressed = lzma.decompress(data)
            except Exception as e:
                raise ValueError(f"Unable to decompress joblib file: {e}") from e

        # Check decompression ratio for compression bomb detection
        if compressed_size > 0:
            ratio = len(decompressed) / compressed_size
            if ratio > self.max_decompression_ratio:
                raise ValueError(
                    f"Suspicious compression ratio: {ratio:.1f}x (max: {self.max_decompression_ratio}x) - "
                    f"possible compression bomb"
                )

        # Check absolute decompressed size
        if len(decompressed) > self.max_decompressed_size:
            raise ValueError(
                f"Decompressed size too large: {len(decompressed)} bytes (max: {self.max_decompressed_size})",
            )

        return decompressed

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path
            magic = read_magic_bytes(path, 4)
            data = self._read_file_safely(path)

            if magic.startswith(b"PK"):
                # Treat as zip archive
                from .zip_scanner import ZipScanner

                zip_scanner = ZipScanner(self.config)
                sub_result = zip_scanner.scan(path)
                result.merge(sub_result)
                result.bytes_scanned = sub_result.bytes_scanned
                result.metadata.update(sub_result.metadata)
                result.finish(success=sub_result.success)
                return result

            if magic.startswith(b"\x80"):
                with io.BytesIO(data) as file_like:
                    sub_result = self.pickle_scanner._scan_pickle_bytes(
                        file_like,
                        len(data),
                    )
                result.merge(sub_result)
                result.bytes_scanned = len(data)
            else:
                # Try safe decompression
                try:
                    decompressed = self._safe_decompress(data)
                    # Record successful decompression check
                    compressed_size = len(data)
                    decompressed_size = len(decompressed)
                    if compressed_size > 0:
                        ratio = decompressed_size / compressed_size
                        result.add_check(
                            name="Compression Bomb Detection",
                            passed=True,
                            message=f"Compression ratio ({ratio:.1f}x) is within safe limits",
                            location=path,
                            details={
                                "compressed_size": compressed_size,
                                "decompressed_size": decompressed_size,
                                "ratio": ratio,
                                "max_ratio": self.max_decompression_ratio,
                            },
                        )
                except ValueError as e:
                    result.add_check(
                        name="Compression Bomb Detection",
                        passed=False,
                        message=str(e),
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"security_check": "compression_bomb_detection"},
                    )
                    result.finish(success=False)
                    return result
                except Exception as e:
                    result.add_check(
                        name="Joblib Decompression",
                        passed=False,
                        message=f"Error decompressing joblib file: {e}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"exception": str(e), "exception_type": type(e).__name__},
                    )
                    result.finish(success=False)
                    return result
                with io.BytesIO(decompressed) as file_like:
                    sub_result = self.pickle_scanner._scan_pickle_bytes(
                        file_like,
                        len(decompressed),
                    )
                result.merge(sub_result)
                result.bytes_scanned = len(decompressed)
        except Exception as e:  # pragma: no cover
            result.add_check(
                name="Joblib File Scan",
                passed=False,
                message=f"Error scanning joblib file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
