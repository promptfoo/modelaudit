"""Scanner for TensorRT engine files (.engine, .plan, .trt)."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from typing import ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

SUSPICIOUS_PATTERN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("../", re.compile(r"(?<![A-Za-z0-9_.-])(?:\.\./|\.\.\\)", re.IGNORECASE)),
    ("/tmp/", re.compile(r"(?:^|[\s'\"=:])(?:/tmp/|(?:[A-Za-z]:)?\\tmp\\)", re.IGNORECASE)),
    (
        ".so",
        re.compile(
            r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_+.-]+)?\.so(?:\.[A-Za-z0-9_+.-]+)?(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        ),
    ),
    ("python", re.compile(r"(?<![A-Za-z0-9_])python(?:[0-9.]+)?(?:\.exe)?(?![A-Za-z0-9_])", re.IGNORECASE)),
    ("import", re.compile(r"(?<![A-Za-z0-9_])import(?![A-Za-z0-9_])", re.IGNORECASE)),
    (
        "exec",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:execvpe|execvp|execve|execlpe|execlp|execle|execl|execv|exec)(?![A-Za-z0-9_])",
            re.IGNORECASE,
        ),
    ),
    ("eval", re.compile(r"(?<![A-Za-z0-9_])eval(?![A-Za-z0-9_])", re.IGNORECASE)),
)
_ASCII_STRING_PATTERN = re.compile(rb"[\t\n\r\x20-\x7e]{3,}")
_UTF16LE_STRING_PATTERN = re.compile(rb"(?:(?:[\t\n\r\x20-\x7e]\x00){3,})")
_UTF16BE_STRING_PATTERN = re.compile(rb"(?:(?:\x00[\t\n\r\x20-\x7e]){3,})")


def _iter_engine_strings(data: bytes) -> Iterator[str]:
    """Yield printable ASCII and UTF-16 strings extracted from engine bytes."""
    for match in _ASCII_STRING_PATTERN.finditer(data):
        yield match.group(0).decode("utf-8", "ignore")

    for match in _UTF16LE_STRING_PATTERN.finditer(data):
        yield match.group(0).decode("utf-16le", "ignore")

    for match in _UTF16BE_STRING_PATTERN.finditer(data):
        yield match.group(0).decode("utf-16be", "ignore")


class TensorRTScanner(BaseScanner):
    """Basic scanner for NVIDIA TensorRT engine files."""

    name = "tensorrt"
    description = "Scans TensorRT engine files for suspicious strings"
    supported_extensions: ClassVar[list[str]] = [".engine", ".plan", ".trt"]

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

        matched_patterns: set[str] = set()
        for engine_string in _iter_engine_strings(data):
            for pattern_name, pattern_regex in SUSPICIOUS_PATTERN_RULES:
                if pattern_name in matched_patterns:
                    continue
                if not pattern_regex.search(engine_string):
                    continue

                matched_patterns.add(pattern_name)
                result.add_check(
                    name="Suspicious Pattern Detection",
                    passed=False,
                    message=f"Suspicious pattern '{pattern_name}' found",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"pattern": pattern_name},
                    rule_code="S902",
                )

        result.finish(success=not result.has_errors)
        return result
