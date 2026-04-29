"""Scanner for PaddlePaddle model files (.pdparams, .pdiparams, .pdmodel)."""

import os
import re
from typing import ClassVar

from modelaudit.detectors.suspicious_symbols import BINARY_CODE_PATTERNS, SUSPICIOUS_STRING_PATTERNS

from .base import BaseScanner, IssueSeverity, ScanResult

HAS_PADDLE = True

# Patterns that are expected in raw binary weight files and should be skipped
# for .pdiparams files to avoid false positives.  The hex-escape pattern
# (r"\\x[0-9a-fA-F]{2}") fires on virtually every .pdiparams file because
# raw float32 tensor data decoded as lossy UTF-8 produces abundant \xNN
# sequences.  The __[\w]+__ (magic-method) pattern similarly matches
# byte sequences that look like dunder names after lossy decoding.
_BINARY_WEIGHT_SKIP_PATTERNS: frozenset[str] = frozenset(
    {
        r"\\x[0-9a-fA-F]{2}",
        r"__[\w]+__",
    }
)


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
                severity=IssueSeverity.WARNING,
                location=path,
                details={"required_package": "paddlepaddle"},
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        ext = os.path.splitext(path)[1].lower()
        counterpart_ext = ".pdiparams" if ext == ".pdmodel" else ".pdmodel"
        counterpart_path = os.path.splitext(path)[0] + counterpart_ext
        result.metadata["has_counterpart"] = os.path.exists(counterpart_path)

        # For binary weight files (.pdiparams), skip string patterns that are
        # expected to match raw tensor data (hex escapes, dunder-like byte runs).
        is_binary_weights = ext == ".pdiparams"

        bytes_scanned = 0
        chunk_size = 1024 * 1024
        previous_chunk_tail = b""
        chunk_overlap = self._get_chunk_overlap_size(chunk_size)
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    bytes_scanned += len(chunk)
                    chunk_offset = bytes_scanned - len(chunk)
                    scan_window = previous_chunk_tail + chunk
                    self._check_chunk(
                        scan_window,
                        result,
                        chunk_offset - len(previous_chunk_tail),
                        path,
                        is_binary_weights,
                        overlap_prefix_len=len(previous_chunk_tail),
                    )
                    previous_chunk_tail = chunk[-chunk_overlap:] if chunk_overlap else b""
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

    @staticmethod
    def _get_chunk_overlap_size(chunk_size: int) -> int:
        """Return the trailing bytes to carry into the next Paddle scan window."""
        longest_pattern = max(
            [
                *(len(pattern) for pattern in BINARY_CODE_PATTERNS),
                *(len(pattern.encode("utf-8")) for pattern in SUSPICIOUS_STRING_PATTERNS if pattern),
            ]
        )
        return max(0, min(chunk_size - 1, longest_pattern - 1))

    def _check_chunk(
        self,
        chunk: bytes,
        result: ScanResult,
        offset: int,
        path: str,
        is_binary_weights: bool = False,
        *,
        overlap_prefix_len: int = 0,
    ) -> None:
        for pattern in BINARY_CODE_PATTERNS:
            search_start = 0
            while True:
                pos = chunk.find(pattern, search_start)
                if pos == -1:
                    break
                search_start = pos + 1
                if pos + len(pattern) <= overlap_prefix_len:
                    continue
                result.add_check(
                    name="Binary Pattern Detection",
                    passed=False,
                    message=f"Suspicious binary pattern found: {pattern.decode('ascii', 'ignore')}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} (offset: {offset + pos})",
                    details={"pattern": pattern.decode("ascii", "ignore"), "offset": offset + pos},
                    rule_code="S902",
                )

        text = chunk.decode("latin-1")
        for regex in SUSPICIOUS_STRING_PATTERNS:
            # Skip patterns known to produce false positives on raw binary
            # weight data (e.g. hex-escape sequences in float tensors).
            if is_binary_weights and regex in _BINARY_WEIGHT_SKIP_PATTERNS:
                continue
            if any(match.end() > overlap_prefix_len for match in re.finditer(regex, text, flags=re.ASCII)):
                result.add_check(
                    name="String Pattern Detection",
                    passed=False,
                    message=f"Suspicious string pattern found: {regex}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"pattern": regex},
                    rule_code="S902",
                )
