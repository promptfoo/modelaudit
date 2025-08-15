import os
import re
from typing import ClassVar

from modelaudit.suspicious_symbols import BINARY_CODE_PATTERNS, SUSPICIOUS_STRING_PATTERNS

from .base import BaseScanner, IssueSeverity, ScanResult

try:
    HAS_PADDLE = True
except Exception:  # pragma: no cover - optional dependency
    HAS_PADDLE = False


class PaddleScanner(BaseScanner):
    """Scanner for PaddlePaddle model files (.pdmodel/.pdiparams)."""

    name = "paddle"
    description = "Scans PaddlePaddle models for embedded code patterns"
    supported_extensions: ClassVar[list[str]] = [".pdmodel", ".pdiparams"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not HAS_PADDLE:
            return False
        if not os.path.isfile(path):
            return False
        return os.path.splitext(path)[1].lower() in cls.supported_extensions

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)

        if not HAS_PADDLE:
            result.add_check(
                name="PaddlePaddle Library Check",
                passed=False,
                message="paddlepaddle package not installed. Install with 'pip install paddlepaddle'",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"required_package": "paddlepaddle"},
            )
            result.finish(success=False)
            return result

        ext = os.path.splitext(path)[1].lower()
        counterpart_ext = ".pdiparams" if ext == ".pdmodel" else ".pdmodel"
        counterpart_path = os.path.splitext(path)[0] + counterpart_ext
        result.metadata["has_counterpart"] = os.path.exists(counterpart_path)

        bytes_scanned = 0
        chunk_size = 1024 * 1024
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    bytes_scanned += len(chunk)
                    self._check_chunk(chunk, result, bytes_scanned - len(chunk), path)
            result.bytes_scanned = bytes_scanned
        except Exception as e:  # pragma: no cover - unexpected I/O errors
            result.add_check(
                name="Paddle File Read",
                passed=False,
                message=f"Error reading file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    def _check_chunk(self, chunk: bytes, result: ScanResult, offset: int, path: str) -> None:
        for pattern in BINARY_CODE_PATTERNS:
            if pattern in chunk:
                pos = chunk.find(pattern)
                result.add_check(
                    name="Binary Pattern Detection",
                    passed=False,
                    message=f"Suspicious binary pattern found: {pattern.decode('ascii', 'ignore')}",
                    severity=IssueSeverity.INFO,
                    location=f"{path} (offset: {offset + pos})",
                    details={"pattern": pattern.decode("ascii", "ignore"), "offset": offset + pos},
                )

        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError:
            text = chunk.decode("utf-8", "ignore")
        for regex in SUSPICIOUS_STRING_PATTERNS:
            if re.search(regex, text):
                result.add_check(
                    name="String Pattern Detection",
                    passed=False,
                    message=f"Suspicious string pattern found: {regex}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"pattern": regex},
                )
