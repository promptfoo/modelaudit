from __future__ import annotations

import os
from typing import ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

SUSPICIOUS_PATTERNS = [
    b"/tmp/",
    b"../",
    b".so",
    b"python",
    b"import",
    b"exec",
    b"eval",
]


class TensorRTScanner(BaseScanner):
    """Basic scanner for NVIDIA TensorRT engine files."""

    name = "tensorrt"
    description = "Scans TensorRT engine files for suspicious strings"
    supported_extensions: ClassVar[list[str]] = [".engine", ".plan"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return os.path.isfile(path) and os.path.splitext(path)[1].lower() in cls.supported_extensions

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
            data = self._read_file_safely(path)
            result.bytes_scanned = len(data)
        except Exception as e:  # pragma: no cover - unexpected read errors
            result.add_check(
                name="TensorRT Engine Read",
                passed=False,
                message=f"Error reading TensorRT engine: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in data:
                result.add_check(
                    name="Suspicious Pattern Detection",
                    passed=False,
                    message=f"Suspicious pattern '{pattern.decode('utf-8', 'ignore')}' found",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"pattern": pattern.decode("utf-8", "ignore")},
                )

        result.finish(success=not result.has_errors)
        return result
