from __future__ import annotations

import io
import lzma
import os
import zlib
from typing import Any, ClassVar

from ..cve_patterns import analyze_cve_patterns, enhance_scan_result_with_cve
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

    def _detect_cve_patterns(self, data: bytes, result: ScanResult, context: str) -> None:
        """Detect CVE-specific patterns in joblib file data."""
        # Convert bytes to string for pattern analysis (ignore decode errors)
        try:
            content_str = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            content_str = ""

        # Analyze for CVE patterns
        cve_attributions = analyze_cve_patterns(content_str, data)

        if cve_attributions:
            # Add CVE information to result
            enhance_scan_result_with_cve(result, [content_str], data)

            # Add specific checks for each CVE found
            for attr in cve_attributions:
                severity = IssueSeverity.CRITICAL if attr.severity == "CRITICAL" else IssueSeverity.WARNING

                result.add_check(
                    name=f"CVE Detection: {attr.cve_id}",
                    passed=False,
                    message=f"Detected {attr.cve_id}: {attr.description}",
                    severity=severity,
                    location=f"{context}",
                    details={
                        "cve_id": attr.cve_id,
                        "cvss": attr.cvss,
                        "cwe": attr.cwe,
                        "affected_versions": attr.affected_versions,
                        "confidence": attr.confidence,
                        "patterns_matched": attr.patterns_matched,
                        "remediation": attr.remediation,
                    },
                    why=f"This file contains patterns associated with {attr.cve_id}, "
                    f"a {attr.severity.lower()} vulnerability affecting {attr.affected_versions}. "
                    f"Remediation: {attr.remediation}",
                )

    def _scan_for_joblib_specific_threats(self, data: bytes, result: ScanResult, context: str) -> None:
        """Scan for joblib-specific security threats beyond general pickle issues."""
        # CVE-2024-34997 specific detection
        numpy_wrapper_patterns = [
            b"NumpyArrayWrapper",
            b"read_array",
            b"numpy_pickle",
        ]

        found_numpy_patterns = []
        for pattern in numpy_wrapper_patterns:
            if pattern in data:
                found_numpy_patterns.append(pattern.decode("utf-8", errors="ignore"))

        if found_numpy_patterns and b"pickle.load" in data:
            result.add_check(
                name="CVE-2024-34997 Risk Detection",
                passed=False,
                message="Detected NumpyArrayWrapper with pickle.load - potential CVE-2024-34997 exploitation",
                severity=IssueSeverity.WARNING,
                location=context,
                details={
                    "cve": "CVE-2024-34997",
                    "patterns": found_numpy_patterns,
                    "risk": "NumpyArrayWrapper deserialization vulnerability",
                },
                why="NumpyArrayWrapper.read_array() combined with pickle.load() can be exploited "
                "for arbitrary code execution if the data source is untrusted.",
            )

        # Check for sklearn model loading patterns with dangerous operations
        if b"sklearn" in data and b"joblib.load" in data:
            dangerous_combos = [
                (b"os.system", "system command execution"),
                (b"subprocess", "process spawning"),
                (b"eval", "code evaluation"),
                (b"exec", "code execution"),
            ]

            for pattern, description in dangerous_combos:
                if pattern in data:
                    result.add_check(
                        name="CVE-2020-13092 Risk Detection",
                        passed=False,
                        message=f"Detected sklearn/joblib.load with {description} - "
                        f"potential CVE-2020-13092 exploitation",
                        severity=IssueSeverity.CRITICAL,
                        location=context,
                        details={
                            "cve": "CVE-2020-13092",
                            "sklearn_pattern": "sklearn + joblib.load",
                            "dangerous_pattern": pattern.decode("utf-8", errors="ignore"),
                            "risk": "scikit-learn deserialization vulnerability",
                        },
                        why=f"scikit-learn models loaded via joblib.load() with {description} "
                        f"can execute arbitrary code during deserialization.",
                    )

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
                # Scan for CVE patterns in raw pickle data
                self._detect_cve_patterns(data, result, path)
                self._scan_for_joblib_specific_threats(data, result, path)

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
                # Scan decompressed data for CVE patterns
                self._detect_cve_patterns(decompressed, result, f"{path} (decompressed)")
                self._scan_for_joblib_specific_threats(decompressed, result, f"{path} (decompressed)")

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
