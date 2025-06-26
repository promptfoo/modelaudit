from __future__ import annotations

import os
import re
from typing import Any, ClassVar

try:
    import msgpack  # type: ignore

    HAS_MSGPACK = True
except Exception:  # pragma: no cover - optional dependency missing
    HAS_MSGPACK = False

from .base import BaseScanner, IssueSeverity, ScanResult


class FlaxMsgpackScanner(BaseScanner):
    """Scanner for Flax msgpack checkpoint files with security threat detection."""

    name = "flax_msgpack"
    description = "Scans Flax/JAX msgpack checkpoints for security threats and integrity issues"
    supported_extensions: ClassVar[list[str]] = [".msgpack"]  # Removed .ckpt to avoid conflicts with PyTorch

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_blob_bytes = self.config.get(
            "max_blob_bytes",
            50 * 1024 * 1024,
        )  # 50MB reasonable for model weights
        self.max_recursion_depth = self.config.get("max_recursion_depth", 100)
        self.max_items_per_container = self.config.get("max_items_per_container", 10000)
        self.suspicious_patterns = self.config.get(
            "suspicious_patterns",
            [
                r"__reduce__",
                r"__getstate__",
                r"__setstate__",
                r"eval\s*\(",
                r"exec\s*\(",
                r"subprocess",
                r"os\.system",
                r"import\s+os",
                r"import\s+subprocess",
                r"__import__",
                r"compile\s*\(",
                r"pickle\.loads",
                r"marshal\.loads",
                r"base64\.decode",
            ],
        )
        self.suspicious_keys = self.config.get(
            "suspicious_keys",
            {
                "__class__",
                "__module__",
                "__reduce__",
                "__getstate__",
                "__setstate__",
                "__dict__",
                "__code__",
                "__globals__",
                "__builtins__",
                "__import__",
            },
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        return bool(ext in cls.supported_extensions and HAS_MSGPACK)

    def _check_suspicious_strings(
        self,
        value: str,
        location: str,
        result: ScanResult,
    ) -> None:
        """Check string values for suspicious patterns that might indicate code injection."""
        for pattern in self.suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result.add_issue(
                    f"Suspicious code pattern detected: {pattern}",
                    severity=IssueSeverity.CRITICAL,
                    location=location,
                    details={
                        "pattern": pattern,
                        "sample": value[:200] + "..." if len(value) > 200 else value,
                        "full_length": len(value),
                    },
                )

    def _check_suspicious_keys(
        self,
        key: str,
        location: str,
        result: ScanResult,
    ) -> None:
        """Check dictionary keys for suspicious names that might indicate serialization attacks."""
        if key in self.suspicious_keys:
            result.add_issue(
                f"Suspicious object attribute detected: {key}",
                severity=IssueSeverity.CRITICAL,
                location=location,
                details={"suspicious_key": key},
            )

    def _analyze_content(
        self,
        value: Any,
        location: str,
        result: ScanResult,
        depth: int = 0,
    ) -> None:
        """Recursively analyze msgpack content for security threats and anomalies."""
        if depth > self.max_recursion_depth:
            result.add_issue(
                f"Maximum recursion depth exceeded: {depth}",
                severity=IssueSeverity.CRITICAL,
                location=location,
                details={"depth": depth, "max_allowed": self.max_recursion_depth},
            )
            return

        if isinstance(value, (bytes, bytearray)):
            size = len(value)
            if size > self.max_blob_bytes:
                result.add_issue(
                    f"Suspiciously large binary blob: {size:,} bytes",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={"size": size, "max_allowed": self.max_blob_bytes},
                )

            # Check for embedded executable content in binary data
            try:
                # Try to decode as UTF-8 to check for hidden text
                decoded = value.decode("utf-8", errors="ignore")
                if len(decoded) > 50:  # Only check substantial text
                    self._check_suspicious_strings(
                        decoded,
                        f"{location}[decoded_binary]",
                        result,
                    )
            except Exception:  # pragma: no cover - encoding edge cases
                pass

        elif isinstance(value, str):
            # Check for suspicious string patterns
            self._check_suspicious_strings(value, location, result)

            # Check for very long strings that might be attacks
            if len(value) > 100000:  # 100KB string
                result.add_issue(
                    f"Extremely long string found: {len(value):,} characters",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={"length": len(value)},
                )

        elif isinstance(value, dict):
            if len(value) > self.max_items_per_container:
                result.add_issue(
                    f"Dictionary with excessive items: {len(value):,}",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={
                        "item_count": len(value),
                        "max_allowed": self.max_items_per_container,
                    },
                )

            for k, v in value.items():
                key_str = str(k)
                self._check_suspicious_keys(key_str, f"{location}/{key_str}", result)

                # Check if key itself contains suspicious patterns
                if isinstance(k, str):
                    self._check_suspicious_strings(k, f"{location}[key:{k}]", result)

                self._analyze_content(v, f"{location}/{key_str}", result, depth + 1)

        elif isinstance(value, (list, tuple)):
            if len(value) > self.max_items_per_container:
                result.add_issue(
                    f"Array with excessive items: {len(value):,}",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={
                        "item_count": len(value),
                        "max_allowed": self.max_items_per_container,
                    },
                )

            for i, v in enumerate(value):
                self._analyze_content(v, f"{location}[{i}]", result, depth + 1)

        elif isinstance(value, (int, float)):
            # Check for suspicious numerical values that might indicate attacks
            if isinstance(value, int) and abs(value) > 2**63:
                result.add_issue(
                    f"Extremely large integer value: {value}",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={"value": value},
                )

    def _validate_flax_structure(self, obj: Any, result: ScanResult) -> None:
        """Validate that the msgpack structure looks like a legitimate Flax checkpoint."""
        if not isinstance(obj, dict):
            result.add_issue(
                f"Unexpected top-level type: {type(obj).__name__} (expected dict)",
                severity=IssueSeverity.WARNING,
                location="root",
                details={"actual_type": type(obj).__name__},
            )
            return

        # Check for common Flax checkpoint patterns
        expected_keys = {"params", "state", "opt_state", "model_state", "step", "epoch"}
        found_keys = set(obj.keys()) if isinstance(obj, dict) else set()

        if not any(key in found_keys for key in expected_keys):
            result.add_issue(
                "No standard Flax checkpoint keys found - may not be a legitimate model",
                severity=IssueSeverity.INFO,
                location="root",
                details={
                    "found_keys": list(found_keys)[:20],  # Limit output
                    "expected_any_of": list(expected_keys),
                },
            )

        # Check for non-standard keys that might be suspicious
        suspicious_top_level = found_keys - expected_keys - {"metadata", "config", "hyperparams"}
        if suspicious_top_level:
            result.add_issue(
                f"Unusual top-level keys found: {suspicious_top_level}",
                severity=IssueSeverity.INFO,
                location="root",
                details={"unusual_keys": list(suspicious_top_level)},
            )

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        if not HAS_MSGPACK:
            result.add_issue(
                "msgpack library not installed - cannot analyze Flax checkpoints",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"required_package": "msgpack"},
            )
            result.finish(success=False)
            return result

        try:
            self.current_file_path = path

            # Read entire file to check for trailing data
            with open(path, "rb") as f:
                file_data = f.read()

            # Try to unpack and detect trailing data
            try:
                obj = msgpack.unpackb(file_data, raw=False, strict_map_key=False)
                # If we get here, the entire file was valid msgpack - no trailing data
            except msgpack.exceptions.ExtraData:
                # This means there's extra data after valid msgpack
                result.add_issue(
                    "Extra trailing data found after msgpack content",
                    severity=IssueSeverity.WARNING,
                    location=path,
                )
                # Unpack just the first object
                unpacker = msgpack.Unpacker(None, raw=False, strict_map_key=False)
                unpacker.feed(file_data)
                obj = unpacker.unpack()
            except (
                msgpack.exceptions.UnpackException,
                msgpack.exceptions.OutOfData,
            ) as e:
                result.add_issue(
                    f"Invalid msgpack format: {e!s}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"msgpack_error": str(e)},
                )
                result.finish(success=False)
                return result

            # Record metadata
            result.metadata["top_level_type"] = type(obj).__name__
            if isinstance(obj, dict):
                result.metadata["top_level_keys"] = list(obj.keys())[:50]  # Limit for large dicts
                result.metadata["key_count"] = len(obj.keys())

            # Validate Flax structure
            self._validate_flax_structure(obj, result)

            # Perform deep security analysis
            self._analyze_content(obj, "root", result)

            result.bytes_scanned = file_size
        except MemoryError:
            result.add_issue(
                "File too large to process safely - potential memory exhaustion attack",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
            result.finish(success=False)
            return result
        except Exception as e:
            result.add_issue(
                f"Unexpected error processing Flax msgpack file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error_type": type(e).__name__, "error_message": str(e)},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
