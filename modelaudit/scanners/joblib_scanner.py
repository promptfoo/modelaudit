"""Scanner for Joblib serialized model files (.joblib)."""

from __future__ import annotations

import bz2
import io
import lzma
import os
import pickletools
import zlib
from collections.abc import Callable
from typing import Any, ClassVar

from ..detectors.cve_patterns import analyze_cve_patterns, enhance_scan_result_with_cve
from ..utils.file.detection import read_magic_bytes
from .base import BaseScanner, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner, _looks_like_pickle


class JoblibScanner(BaseScanner):
    """Scanner for joblib serialized files."""

    name = "joblib"
    description = "Scans joblib files by decompressing and analyzing embedded pickle"
    supported_extensions: ClassVar[list[str]] = [".joblib"]

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize Joblib scanning limits and the embedded Pickle scanner."""
        super().__init__(config)
        self.pickle_scanner = PickleScanner(config)
        # Security limits
        self.max_decompression_ratio = self.config.get("max_decompression_ratio", 100.0)
        self.max_decompressed_size = self.config.get(
            "max_decompressed_size",
            10 * 1024 * 1024 * 1024,
        )  # 10GB for large ML models
        self.chunk_size = self.config.get("chunk_size", 8192)  # 8KB chunks

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Return True for existing `.joblib` files."""
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        return ext == ".joblib"

    def _read_file_safely(self, path: str) -> bytes:
        """Read file in chunks using the base class helper."""
        return super()._read_file_safely(path)

    def _max_decompressed_output_bytes(self, compressed_size: int) -> int:
        """Compute the effective decompression output cap for one compressed payload."""
        max_by_ratio = self.max_decompressed_size
        if compressed_size > 0:
            max_by_ratio = int(self.max_decompression_ratio * compressed_size)
        return min(self.max_decompressed_size, max_by_ratio)

    def _check_decompressed_size(self, decompressed_size: int) -> None:
        """Fail when the decompressed payload exceeds the absolute size limit."""
        if decompressed_size > self.max_decompressed_size:
            raise ValueError(
                f"Decompressed size too large: {decompressed_size} bytes (max: {self.max_decompressed_size})",
            )

    def _check_decompression_ratio(self, decompressed_size: int, compressed_size: int) -> None:
        """Fail when decompression expands beyond the configured ratio limit."""
        if compressed_size <= 0:
            return

        ratio = decompressed_size / compressed_size
        if ratio > self.max_decompression_ratio:
            raise ValueError(
                f"Suspicious compression ratio: {ratio:.1f}x (max: {self.max_decompression_ratio}x) - "
                f"possible compression bomb"
            )

    def _decompress_with_limited_output(self, decompressor: Any, data: bytes) -> bytes:
        """Decompress one stream while enforcing absolute-size and ratio budgets."""
        compressed_size = len(data)
        max_output_bytes = self._max_decompressed_output_bytes(compressed_size)
        output_limit = max_output_bytes + 1

        decompressed = bytearray(decompressor.decompress(data, output_limit))
        if len(decompressed) > output_limit:
            raise ValueError("Internal decompression limit exceeded")

        self._check_decompressed_size(len(decompressed))
        self._check_decompression_ratio(len(decompressed), compressed_size)

        if len(decompressed) == output_limit:
            raise ValueError(
                f"Decompressed size too large: {len(decompressed)} bytes (max: {max_output_bytes})",
            )

        remaining_output_budget = output_limit - len(decompressed)
        if remaining_output_budget > 0 and hasattr(decompressor, "flush"):
            decompressed.extend(decompressor.flush(remaining_output_budget))
            self._check_decompressed_size(len(decompressed))
            self._check_decompression_ratio(len(decompressed), compressed_size)
            if len(decompressed) > output_limit:
                raise ValueError(
                    f"Decompressed size too large: {len(decompressed)} bytes (max: {max_output_bytes})",
                )

        if getattr(decompressor, "unused_data", b""):
            raise ValueError("Trailing data found after compressed joblib stream")

        if not getattr(decompressor, "eof", True):
            raise ValueError("Incomplete compressed joblib stream")

        return bytes(decompressed)

    def _safe_decompress(self, data: bytes) -> bytes:
        """Safely decompress data with bomb protection"""
        codec_attempts: list[tuple[str, Callable[[], Any]]] = [
            ("zlib", zlib.decompressobj),
            ("gzip", lambda: zlib.decompressobj(zlib.MAX_WBITS | 16)),
            ("bz2", bz2.BZ2Decompressor),
            ("lzma", lzma.LZMADecompressor),
        ]
        decode_errors: list[str] = []

        for codec_name, decompressor_factory in codec_attempts:
            try:
                return self._decompress_with_limited_output(decompressor_factory(), data)
            except (OSError, EOFError, lzma.LZMAError, zlib.error) as exc:
                decode_errors.append(f"{codec_name}: {exc}")

        raise ValueError(
            "Unable to decompress joblib file: " + "; ".join(decode_errors or ["no supported decoder matched"]),
        )

    def _scan_pickle_payload(self, payload: bytes, result: ScanResult, context: str) -> None:
        """Analyze a raw or decompressed pickle payload with CVE and opcode checks."""
        self._detect_cve_patterns(payload, result, context)
        self._scan_for_joblib_specific_threats(payload, result, context)
        self.pickle_scanner.current_file_path = context

        with io.BytesIO(payload) as file_like:
            sub_result = self.pickle_scanner._scan_pickle_bytes(
                file_like,
                len(payload),
            )
        result.merge(sub_result)
        result.bytes_scanned = len(payload)

    def _looks_like_raw_pickle_payload(self, data: bytes) -> bool:
        """Return True when `.joblib` bytes should be scanned directly as pickle."""
        if _looks_like_pickle(data):
            return True

        if len(data) >= 2 and data[0] == 0x80 and data[1] <= 5:
            return True

        try:
            probe = io.BytesIO(data[:4096])
            for _opcode_count, (opcode, _arg, _pos) in enumerate(pickletools.genops(probe), 1):
                if opcode.name == "STOP":
                    return True
                if _opcode_count >= 16:
                    break
        except Exception:
            return False

        return False

    def _record_joblib_operational_error(self, result: ScanResult, reason: str) -> None:
        """Mark a Joblib scan as operationally incomplete for CLI exit-code aggregation."""
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = reason

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
        """Scan one Joblib file as direct pickle, compressed pickle, or zip-backed content."""
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

            if self._looks_like_raw_pickle_payload(data):
                self._scan_pickle_payload(data, result, path)
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
                            rule_code=None,  # Passing check
                        )
                except ValueError as e:
                    # Size/ratio limit errors are informational - may indicate large legitimate models
                    # Compression bombs are DoS concerns, not RCE vectors
                    result.add_check(
                        name="Compression Bomb Detection",
                        passed=False,
                        message=str(e),
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"security_check": "compression_bomb_detection"},
                        rule_code="S902",
                    )
                    self._record_joblib_operational_error(result, "joblib_wrapper_decode_failed")
                    result.finish(success=False)
                    return result
                except Exception as e:
                    result.add_check(
                        name="Joblib Decompression",
                        passed=False,
                        message=f"Error decompressing joblib file: {e}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "exception": str(e),
                            "exception_type": type(e).__name__,
                        },
                        rule_code="S902",
                    )
                    self._record_joblib_operational_error(result, "joblib_decompression_failed")
                    result.finish(success=False)
                    return result
                self._scan_pickle_payload(decompressed, result, f"{path} (decompressed)")
        except Exception as e:  # pragma: no cover
            result.add_check(
                name="Joblib File Scan",
                passed=False,
                message=f"Error scanning joblib file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
                rule_code="S902",
            )
            self._record_joblib_operational_error(result, "joblib_scan_failed")
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract joblib metadata."""
        metadata = super().extract_metadata(file_path)

        allow_deserialization = bool(self.config.get("allow_metadata_deserialization"))

        if not allow_deserialization:
            metadata["deserialization_skipped"] = True
            metadata["reason"] = "Deserialization disabled for metadata extraction"
            return metadata

        try:
            import joblib

            # Try to load the joblib file
            obj = joblib.load(file_path)

            metadata.update(
                {
                    "joblib_version": joblib.__version__,
                    "object_type": type(obj).__name__,
                    "object_module": getattr(type(obj), "__module__", "unknown"),
                }
            )

            # Analyze sklearn models specifically
            if hasattr(obj, "_sklearn_version"):
                metadata["sklearn_version"] = str(obj._sklearn_version)

            if hasattr(obj, "get_params"):
                try:
                    try:
                        params = obj.get_params(deep=False)
                    except TypeError:
                        params = obj.get_params()
                    metadata.update(
                        {
                            "model_parameters": len(params),
                            "key_parameters": list(params.keys())[:10],  # First 10 parameters
                        }
                    )
                except Exception:
                    pass

            # Check for common sklearn model attributes
            if hasattr(obj, "n_features_in_"):
                metadata["n_features_in"] = obj.n_features_in_

            if hasattr(obj, "classes_"):
                metadata.update(
                    {
                        "n_classes": len(obj.classes_),
                        "classes": list(obj.classes_)[:10]
                        if len(obj.classes_) <= 10
                        else f"{len(obj.classes_)} classes",
                    }
                )

            if hasattr(obj, "feature_importances_"):
                metadata["has_feature_importances"] = True
                try:
                    importances = obj.feature_importances_
                    metadata["feature_importance_stats"] = {
                        "min": float(min(importances)),
                        "max": float(max(importances)),
                        "mean": float(sum(importances) / len(importances)),
                    }
                except Exception:
                    pass
            else:
                metadata["has_feature_importances"] = False

            # Check for ensemble models
            if hasattr(obj, "estimators_"):
                metadata.update(
                    {
                        "is_ensemble": True,
                        "n_estimators": len(obj.estimators_),
                    }
                )
            else:
                metadata["is_ensemble"] = False

        except Exception as e:
            metadata["extraction_error"] = str(e)
            metadata["extraction_error_type"] = type(e).__name__

        return metadata
