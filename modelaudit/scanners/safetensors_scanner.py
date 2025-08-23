"""SafeTensors model scanner."""

from __future__ import annotations

import json
import os
import re
import struct
from typing import Any, ClassVar, Optional

from modelaudit.suspicious_symbols import SUSPICIOUS_METADATA_PATTERNS

from .base import BaseScanner, IssueSeverity, ScanResult

# Map SafeTensors dtypes to byte sizes for integrity checking
_DTYPE_SIZES = {
    "F16": 2,
    "F32": 4,
    "F64": 8,
    "I8": 1,
    "I16": 2,
    "I32": 4,
    "I64": 8,
    "U8": 1,
    "U16": 2,
    "U32": 4,
    "U64": 8,
}


class SafeTensorsScanner(BaseScanner):
    """Scanner for SafeTensors model files."""

    name = "safetensors"
    description = "Scans SafeTensors model files for integrity issues"
    supported_extensions: ClassVar[list[str]] = [".safetensors"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path."""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True

        try:
            from modelaudit.utils.filetype import detect_file_format

            return detect_file_format(path) == "safetensors"
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan a SafeTensors file."""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                header_len_bytes = f.read(8)
                if len(header_len_bytes) != 8:
                    result.add_check(
                        name="SafeTensors Header Size Check",
                        passed=False,
                        message="File too small to contain SafeTensors header length",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"bytes_read": len(header_len_bytes), "required": 8},
                    )
                    result.finish(success=False)
                    return result

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                if header_len <= 0 or header_len > file_size - 8:
                    result.add_check(
                        name="Header Length Validation",
                        passed=False,
                        message="Invalid SafeTensors header length",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"header_len": header_len, "max_allowed": file_size - 8},
                    )
                    result.finish(success=False)
                    return result
                else:
                    result.add_check(
                        name="Header Length Validation",
                        passed=True,
                        message="SafeTensors header length is valid",
                        location=path,
                        details={"header_len": header_len},
                    )

                header_bytes = f.read(header_len)
                if len(header_bytes) != header_len:
                    result.add_check(
                        name="SafeTensors Header Read",
                        passed=False,
                        message="Failed to read SafeTensors header",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"bytes_read": len(header_bytes), "expected": header_len},
                    )
                    result.finish(success=False)
                    return result

                if not header_bytes.strip().startswith(b"{"):
                    result.add_check(
                        name="Header Format Validation",
                        passed=False,
                        message="SafeTensors header does not start with '{'",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                    )
                    result.finish(success=False)
                    return result
                else:
                    result.add_check(
                        name="Header Format Validation",
                        passed=True,
                        message="SafeTensors header format is valid JSON",
                        location=path,
                    )

                try:
                    header = json.loads(header_bytes.decode("utf-8"))
                except json.JSONDecodeError as e:
                    result.add_check(
                        name="SafeTensors JSON Parse",
                        passed=False,
                        message=f"Invalid JSON header: {e!s}",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"exception": str(e), "exception_type": type(e).__name__},
                        why="SafeTensors header contained invalid JSON.",
                    )
                    result.finish(success=False)
                    return result

                tensor_names = [k for k in header if k != "__metadata__"]
                result.metadata["tensor_count"] = len(tensor_names)
                result.metadata["tensors"] = tensor_names

                # Enhanced SafeTensors metadata injection detection
                self._detect_metadata_injection_attacks(header, result, path)

                # Validate tensor offsets and sizes
                tensor_entries: list[tuple[str, Any]] = [(k, v) for k, v in header.items() if k != "__metadata__"]

                data_size = file_size - (8 + header_len)
                offsets = []
                for name, info in tensor_entries:
                    if not isinstance(info, dict):
                        result.add_check(
                            name="Tensor Entry Type Validation",
                            passed=False,
                            message=f"Invalid tensor entry for {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"tensor": name, "actual_type": type(info).__name__, "expected_type": "dict"},
                        )
                        continue

                    begin, end = info.get("data_offsets", [0, 0])
                    dtype = info.get("dtype")
                    shape = info.get("shape", [])

                    if not isinstance(begin, int) or not isinstance(end, int):
                        result.add_check(
                            name="Tensor Offset Type Validation",
                            passed=False,
                            message=f"Invalid data_offsets for {name}",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "tensor": name,
                                "begin_type": type(begin).__name__,
                                "end_type": type(end).__name__,
                            },
                        )
                        continue

                    if begin < 0 or end <= begin or end > data_size:
                        result.add_check(
                            name="Tensor Offset Validation",
                            passed=False,
                            message=f"Tensor {name} offsets out of bounds",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"tensor": name, "begin": begin, "end": end, "data_size": data_size},
                        )
                        continue
                    else:
                        result.add_check(
                            name="Tensor Offset Validation",
                            passed=True,
                            message=f"Tensor {name} offsets are valid",
                            location=path,
                            details={"tensor": name, "begin": begin, "end": end},
                        )

                    offsets.append((begin, end))

                    # Validate dtype/shape size
                    expected_size = self._expected_size(dtype, shape)
                    if expected_size is not None:
                        if expected_size != end - begin:
                            result.add_check(
                                name="Tensor Size Consistency Check",
                                passed=False,
                                message=f"Size mismatch for tensor {name}",
                                severity=IssueSeverity.CRITICAL,
                                location=path,
                                details={
                                    "tensor": name,
                                    "expected_size": expected_size,
                                    "actual_size": end - begin,
                                },
                            )
                        else:
                            result.add_check(
                                name="Tensor Size Consistency Check",
                                passed=True,
                                message=f"Tensor {name} size matches dtype/shape",
                                location=path,
                                details={
                                    "tensor": name,
                                    "size": expected_size,
                                },
                            )

                # Check offset continuity
                offsets.sort(key=lambda x: x[0])
                last_end = 0
                has_gap_or_overlap = False
                for begin, end in offsets:
                    if begin != last_end:
                        has_gap_or_overlap = True
                        result.add_check(
                            name="Offset Continuity Check",
                            passed=False,
                            message="Tensor data offsets have gaps or overlap",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={"gap_at": begin, "expected": last_end},
                        )
                        break
                    last_end = end

                if not has_gap_or_overlap and offsets:
                    result.add_check(
                        name="Offset Continuity Check",
                        passed=True,
                        message="Tensor offsets are continuous without gaps",
                        location=path,
                        details={"total_offsets": len(offsets)},
                    )

                data_size = file_size - (8 + header_len)
                if last_end != data_size:
                    result.add_check(
                        name="Tensor Data Coverage Check",
                        passed=False,
                        message="Tensor data does not cover entire file",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"last_offset": last_end, "data_size": data_size},
                    )

                # Check metadata
                metadata = header.get("__metadata__", {})
                if isinstance(metadata, dict):
                    for key, value in metadata.items():
                        if isinstance(value, str) and len(value) > 1000:
                            result.add_check(
                                name="Metadata Length Check",
                                passed=False,
                                message=f"Metadata value for {key} is very long",
                                severity=IssueSeverity.INFO,
                                location=path,
                                details={"key": key, "length": len(value), "threshold": 1000},
                                why=(
                                    "Metadata fields over 1000 characters are unusual in model files. Long strings "
                                    "in metadata could contain encoded payloads, scripts, or data exfiltration "
                                    "attempts."
                                ),
                            )

                        if isinstance(value, str):
                            lower_val = value.lower()

                            # Check for simple code-like patterns
                            if any(s in lower_val for s in ["import ", "#!/", "\\"]):
                                result.add_check(
                                    name="Metadata Code Pattern Check",
                                    passed=False,
                                    message=f"Suspicious metadata value for {key}",
                                    severity=IssueSeverity.INFO,
                                    location=path,
                                    details={"key": key, "pattern": "code-like"},
                                    why=(
                                        "Metadata containing code-like patterns (import statements, shebangs, escape "
                                        "sequences) is atypical for model files and may indicate embedded scripts or "
                                        "injection attempts."
                                    ),
                                )

                            # Check for regex-based suspicious patterns (independent of above check)
                            for pattern in SUSPICIOUS_METADATA_PATTERNS:
                                if re.search(pattern, value):
                                    result.add_check(
                                        name="Metadata Pattern Check",
                                        passed=False,
                                        message=f"Suspicious metadata value for {key}",
                                        severity=IssueSeverity.INFO,
                                        location=path,
                                        details={"key": key, "pattern": pattern},
                                        why="Metadata matched known suspicious pattern",
                                    )
                                    break

                # Bytes scanned = file size
                result.bytes_scanned = file_size

        except Exception as e:
            result.add_check(
                name="SafeTensors File Scan",
                passed=False,
                message=f"Error scanning SafeTensors file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    @staticmethod
    def _expected_size(dtype: Optional[str], shape: list[int]) -> Optional[int]:
        """Return expected tensor byte size from dtype and shape."""
        if dtype not in _DTYPE_SIZES:
            return None
        size = _DTYPE_SIZES[dtype]
        total = 1
        for dim in shape:
            if not isinstance(dim, int) or dim < 0:
                return None
            total *= dim
        return total * size

    def _detect_metadata_injection_attacks(self, header: dict[str, Any], result: ScanResult, path: str) -> None:
        """Detect metadata injection attacks in SafeTensors files"""

        # Check if __metadata__ exists and analyze it
        metadata = header.get("__metadata__", {})

        if metadata:
            # Analyze the metadata for injection patterns
            self._analyze_metadata_content(metadata, result, path)

            # Check metadata size - unusually large metadata can indicate injection
            import json

            metadata_size = len(json.dumps(metadata, separators=(",", ":")))
            if metadata_size > 50000:  # 50KB threshold
                result.add_check(
                    name="SafeTensors Metadata Size Check",
                    passed=False,
                    message=f"Unusually large metadata section ({metadata_size:,} bytes) may indicate injection attack",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "metadata_size": metadata_size,
                        "size_threshold": 50000,
                        "potential_attack": "metadata_bloat_injection",
                    },
                )

        # Check tensor names for injection attempts
        tensor_names = [k for k in header if k != "__metadata__"]
        for tensor_name in tensor_names:
            if self._is_suspicious_tensor_name(tensor_name):
                result.add_check(
                    name="SafeTensors Tensor Name Injection Check",
                    passed=False,
                    message=f"Suspicious tensor name detected: {tensor_name}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "tensor_name": tensor_name,
                        "attack_type": "tensor_name_injection",
                        "reason": "Contains path traversal or dangerous characters",
                    },
                )

        # Check tensor metadata for injection
        for tensor_name, tensor_info in header.items():
            if tensor_name == "__metadata__":
                continue

            if isinstance(tensor_info, dict):
                # Check for unusual keys in tensor metadata
                expected_keys = {"dtype", "shape", "data_offsets"}
                unexpected_keys = set(tensor_info.keys()) - expected_keys

                if unexpected_keys:
                    result.add_check(
                        name="SafeTensors Tensor Metadata Injection Check",
                        passed=False,
                        message=f"Tensor {tensor_name} contains unexpected metadata keys: {list(unexpected_keys)}",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={
                            "tensor_name": tensor_name,
                            "unexpected_keys": list(unexpected_keys),
                            "attack_type": "tensor_metadata_injection",
                        },
                    )

    def _analyze_metadata_content(self, metadata: dict[str, Any], result: ScanResult, path: str) -> None:
        """Analyze SafeTensors metadata content for injection attacks"""

        # Convert metadata to string for pattern analysis
        import json

        metadata_str = json.dumps(metadata, indent=2)

        # XSS/HTML injection patterns
        html_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",  # Event handlers like onclick, onload
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<form[^>]*>",
            r"<img[^>]*onerror",
            r"vbscript:",
            r"data:text/html",
        ]

        for pattern in html_patterns:
            matches = re.findall(pattern, metadata_str, re.IGNORECASE | re.DOTALL)
            if matches:
                result.add_check(
                    name="SafeTensors XSS/HTML Injection Detection",
                    passed=False,
                    message="Potential XSS/HTML injection detected in metadata",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "matches": matches[:5],  # Limit to first 5 matches
                        "attack_type": "xss_html_injection",
                        "total_matches": len(matches),
                    },
                )

        # Code injection patterns
        code_patterns = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__\s*\(",
            r"compile\s*\(",
            r"subprocess\.",
            r"os\.system",
            r"os\.popen",
            r"\\x[0-9a-fA-F]{2}",  # Hex encoded data
            r"\\u[0-9a-fA-F]{4}",  # Unicode escapes
            r"base64\.",
            r"pickle\.",
            r"marshal\.",
        ]

        for pattern in code_patterns:
            matches = re.findall(pattern, metadata_str, re.IGNORECASE)
            if matches:
                result.add_check(
                    name="SafeTensors Code Injection Detection",
                    passed=False,
                    message="Potential code injection detected in metadata",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "matches": matches[:5],
                        "attack_type": "code_injection",
                        "total_matches": len(matches),
                    },
                )

        # Path traversal patterns
        path_traversal_patterns = [
            r"\.\./+",
            r"\.\.\\+",
            r"/etc/",
            r"/proc/",
            r"/root/",
            r"/home/",
            r"C:\\",
            r"%[0-9a-fA-F]{2}",  # URL encoded characters
            r"\\[a-zA-Z]:",  # Windows drive letters
        ]

        for pattern in path_traversal_patterns:
            matches = re.findall(pattern, metadata_str, re.IGNORECASE)
            if matches:
                result.add_check(
                    name="SafeTensors Path Traversal Detection",
                    passed=False,
                    message="Potential path traversal detected in metadata",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "matches": matches[:5],
                        "attack_type": "path_traversal",
                        "total_matches": len(matches),
                    },
                )

        # Check for embedded credentials or secrets
        credential_patterns = [
            r'password["\'\s]*[:=]["\'\s]*\w+',
            r'api[_-]?key["\'\s]*[:=]["\'\s]*[\w-]+',
            r'secret["\'\s]*[:=]["\'\s]*[\w-]+',
            r'token["\'\s]*[:=]["\'\s]*[\w.-]+',
            r"-----BEGIN [A-Z ]+-----",
            r"sk-[a-zA-Z0-9]{32,}",  # OpenAI API keys
            r"xox[boaprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",  # Slack tokens
            r"ghp_[a-zA-Z0-9]{36}",  # GitHub personal access tokens
        ]

        for pattern in credential_patterns:
            matches = re.findall(pattern, metadata_str, re.IGNORECASE)
            if matches:
                result.add_check(
                    name="SafeTensors Embedded Credentials Detection",
                    passed=False,
                    message="Potential embedded credentials detected in metadata",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={
                        "pattern_matched": pattern,
                        "attack_type": "credential_exposure",
                        "total_matches": len(matches),
                    },
                )

        # Check for unusually deep nesting (JSON bomb)
        max_depth = self._calculate_json_depth(metadata)
        if max_depth > 50:
            result.add_check(
                name="SafeTensors JSON Depth Bomb Detection",
                passed=False,
                message=f"Unusually deep JSON nesting ({max_depth} levels) may indicate DoS attack",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"max_depth": max_depth, "depth_threshold": 50, "attack_type": "json_depth_bomb"},
            )

    def _is_suspicious_tensor_name(self, name: str) -> bool:
        """Check if a tensor name contains suspicious patterns"""
        suspicious_patterns = [
            "../",  # Path traversal
            "..\\",  # Windows path traversal
            "/etc/",  # System directories
            "/proc/",
            "/root/",
            "\\x",  # Hex encoding
            "\\u",  # Unicode escapes
            "<script",  # HTML/XSS
            "javascript:",
            "eval(",
            "exec(",
        ]

        name_lower = name.lower()
        return any(pattern in name_lower for pattern in suspicious_patterns)

    def _calculate_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate maximum depth of JSON object"""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._calculate_json_depth(v, current_depth + 1) for v in obj.values())

        if isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._calculate_json_depth(v, current_depth + 1) for v in obj)

        # For primitive types (str, int, float, bool, None)
        return current_depth
