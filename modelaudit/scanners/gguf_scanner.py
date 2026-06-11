"""GGUF/GGML scanner that combines comprehensive parsing with security checks."""

from __future__ import annotations

import os
import struct
from typing import Any, BinaryIO, ClassVar, NamedTuple

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult

# Map ggml_type enum to (block_size, type_size) for comprehensive validation
# Values derived from ggml source
_GGML_TYPE_INFO = {
    0: (1, 4),  # F32
    1: (1, 2),  # F16
    2: (32, 18),  # Q4_0
    3: (32, 20),  # Q4_1
    6: (32, 22),  # Q5_0
    7: (32, 24),  # Q5_1
    8: (32, 34),  # Q8_0
    9: (32, 36),  # Q8_1
    10: (256, 84),  # Q2_K
    11: (256, 110),  # Q3_K
    12: (256, 144),  # Q4_K
    13: (256, 176),  # Q5_K
    14: (256, 210),  # Q6_K
    15: (256, 292),  # Q8_K
    21: (256, 110),  # IQ3_S
    23: (256, 136),  # IQ4_XS
    30: (1, 2),  # BF16
}
_UINT64_MAX: int = 2**64 - 1

# Accepted GGML variant magic bytes
GGML_VARIANT_MAGICS = {
    b"GGML",
    b"GGMF",
    b"GGJT",
    b"GGLA",
    b"GGSA",
}
GGUF_PARSE_INCONCLUSIVE_REASON = "gguf_parse_incomplete"
GGUF_STRUCTURE_INCONCLUSIVE_REASON = "gguf_structure_validation_failed"
GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON = "gguf_duplicate_metadata_keys"
GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON = "gguf_metadata_limit_exceeded"
GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON = "gguf_tensor_limit_exceeded"


class _GgufMetadataLimitExceeded(ValueError):
    """Raised when declared GGUF metadata would exceed bounded parsing."""


class _GgufTensorLimitExceeded(ValueError):
    """Raised when declared GGUF tensor information would exceed bounded parsing."""


class _GgufByteBudget:
    """Track bounded parser input before allocating decoded GGUF values."""

    def __init__(self, limit: int, section: str, error_type: type[ValueError]) -> None:
        self.limit = limit
        self.section = section
        self.error_type = error_type
        self.consumed = 0

    def consume(self, size: int) -> None:
        if size > self.limit - self.consumed:
            raise self.error_type(f"{self.section.capitalize()} bytes exceed limit {self.limit}")
        self.consumed += size


class _GgufTensorInfo(NamedTuple):
    name: str
    dims: tuple[int, ...]
    tensor_type: int
    offset: int


class GgufScanner(BaseScanner):
    """Scanner for GGUF/GGML model files with comprehensive parsing and security checks."""

    name = "gguf"
    description = "Validates GGUF/GGML model file headers, metadata, and tensor integrity"
    default_max_file_read_size: ClassVar[int] = 0
    DEFAULT_MAX_METADATA_KEYS: ClassVar[int] = 100_000
    DEFAULT_MAX_METADATA_BYTES: ClassVar[int] = 256 * 1024 * 1024
    DEFAULT_MAX_METADATA_ARRAY_ITEMS: ClassVar[int] = 1_000_000
    DEFAULT_MAX_TOTAL_METADATA_ARRAY_ITEMS: ClassVar[int] = 2_000_000
    DEFAULT_MAX_METADATA_ARRAY_DEPTH: ClassVar[int] = 32
    DEFAULT_MAX_TENSORS: ClassVar[int] = 50_000
    DEFAULT_MAX_TENSOR_INFO_BYTES: ClassVar[int] = 16 * 1024 * 1024
    DEFAULT_MAX_REPORTED_TENSORS: ClassVar[int] = 1024
    # Include common GGML variant extensions as well
    supported_extensions: ClassVar[list[str]] = [
        ".gguf",
        ".ggml",
        ".ggmf",
        ".ggjt",
        ".ggla",
        ".ggsa",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_uncompressed = self.config.get(
            "max_uncompressed",
            100 * 1024 * 1024 * 1024,
        )  # 100GB for large GGUF models
        self.max_metadata_keys = self._normalize_positive_int_config(
            self.config.get("gguf_max_metadata_keys"),
            self.DEFAULT_MAX_METADATA_KEYS,
        )
        self.max_metadata_bytes = self._normalize_positive_int_config(
            self.config.get("gguf_max_metadata_bytes"),
            self.DEFAULT_MAX_METADATA_BYTES,
        )
        self.max_metadata_array_items = self._normalize_positive_int_config(
            self.config.get("gguf_max_metadata_array_items"),
            self.DEFAULT_MAX_METADATA_ARRAY_ITEMS,
        )
        self.max_total_metadata_array_items = self._normalize_positive_int_config(
            self.config.get("gguf_max_total_metadata_array_items"),
            self.DEFAULT_MAX_TOTAL_METADATA_ARRAY_ITEMS,
        )
        self.max_metadata_array_depth = self._normalize_positive_int_config(
            self.config.get("gguf_max_metadata_array_depth"),
            self.DEFAULT_MAX_METADATA_ARRAY_DEPTH,
        )
        self.max_tensors = self._normalize_positive_int_config(
            self.config.get("gguf_max_tensors"),
            self.DEFAULT_MAX_TENSORS,
        )
        self.max_tensor_info_bytes = self._normalize_positive_int_config(
            self.config.get("gguf_max_tensor_info_bytes"),
            self.DEFAULT_MAX_TENSOR_INFO_BYTES,
        )
        self.max_reported_tensors = self._normalize_positive_int_config(
            self.config.get("gguf_max_reported_tensors"),
            self.DEFAULT_MAX_REPORTED_TENSORS,
        )

    @staticmethod
    def _mark_inconclusive(result: ScanResult, reason: str) -> None:
        """Mark malformed GGUF/GGML framing as an explicit inconclusive scan."""
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME

        reasons = result.metadata.get("scan_outcome_reasons")
        if not isinstance(reasons, list):
            reasons = []
            result.metadata["scan_outcome_reasons"] = reasons
        if reason not in reasons:
            reasons.append(reason)

    @staticmethod
    def _has_security_findings(result: ScanResult) -> bool:
        """Return True when GGUF scanning found WARNING/CRITICAL security findings."""
        return any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def _finish_result(self, result: ScanResult) -> None:
        """Finalize success so inconclusive/no-finding scans fail closed."""
        if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME and not self._has_security_findings(result):
            result.finish(success=False)
            return

        result.finish(success=not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        try:
            with open(path, "rb") as f:
                magic = f.read(4)
            return magic == b"GGUF" or magic in GGML_VARIANT_MAGICS
        except Exception:
            return False

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

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == b"GGUF":
                    self._scan_gguf(f, file_size, result)
                elif magic in GGML_VARIANT_MAGICS:
                    self._scan_ggml(f, file_size, magic, result)
                else:
                    result.add_check(
                        name="File Format Recognition",
                        passed=False,
                        message=f"Unrecognized file format: {magic!r}",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"magic_bytes": magic.hex()},
                        rule_code="S903",
                    )
                    self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
                    result.finish(success=False)
                    return result
        except Exception as e:
            result.add_check(
                name="GGUF/GGML File Scan",
                passed=False,
                message=f"Error scanning GGUF/GGML file: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
                rule_code="S1005",  # Invalid signature/corrupted file
            )
            self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
            result.finish(success=False)
            return result

        self._finish_result(result)
        return result

    @staticmethod
    def _read_bytes(f: BinaryIO, size: int, budget: _GgufByteBudget | None = None) -> bytes:
        if budget is not None:
            budget.consume(size)
        return f.read(size)

    def _read_string(
        self,
        f: BinaryIO,
        max_length: int = 1024 * 1024,
        budget: _GgufByteBudget | None = None,
    ) -> str:
        """Read a string with length checking for security.

        Args:
            f: Binary file to read from
            max_length: Maximum allowed string length (default 1MB)

        Returns:
            Decoded UTF-8 string

        Raises:
            ValueError: String length exceeds limit, unexpected EOF, or other parsing error
        """
        (length,) = struct.unpack("<Q", self._read_bytes(f, 8, budget))
        if length > max_length:
            raise ValueError(f"String length {length} exceeds maximum {max_length}")
        data = self._read_bytes(f, length, budget)
        if len(data) != length:
            raise ValueError("Unexpected end of file while reading string")
        return data.decode("utf-8", "ignore")

    def _scan_gguf(self, f: BinaryIO, file_size: int, result: ScanResult) -> None:
        """Comprehensive GGUF file scanning with security checks."""
        if file_size < 24:
            result.add_check(
                name="GGUF File Size Validation",
                passed=False,
                message="File too small to contain GGUF metadata",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"file_size": file_size, "min_required": 24},
                rule_code="S902",
            )
            self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
            return

        # Read header
        version = struct.unpack("<I", f.read(4))[0]
        n_tensors = struct.unpack("<Q", f.read(8))[0]
        n_kv = struct.unpack("<Q", f.read(8))[0]

        result.metadata.update(
            {
                "format": "gguf",
                "version": version,
                "n_tensors": n_tensors,
                "n_kv": n_kv,
            },
        )

        metadata_key_limit_exceeded = n_kv > self.max_metadata_keys
        if metadata_key_limit_exceeded:
            self._report_metadata_limit(
                result,
                f"File declares {n_kv} metadata keys, exceeding limit {self.max_metadata_keys}",
                declared_metadata_keys=n_kv,
            )

        # Parse metadata with security checks
        metadata: dict[str, Any] = {}
        chat_templates: dict[str, str] = {}
        metadata_key_occurrences: dict[str, int] = {}
        metadata_array_items_read = [0]
        metadata_byte_budget = _GgufByteBudget(
            self.max_metadata_bytes,
            "metadata",
            _GgufMetadataLimitExceeded,
        )
        try:
            for _i in range(min(n_kv, self.max_metadata_keys)):
                key = self._read_string(f, budget=metadata_byte_budget)
                occurrence = metadata_key_occurrences.get(key, 0) + 1
                metadata_key_occurrences[key] = occurrence

                # Security check for suspicious keys
                if any(x in key for x in ("../", "..\\", "/", "\\")):
                    result.add_check(
                        name="Metadata Key Security Check",
                        passed=False,
                        message=f"Suspicious metadata key with path traversal: {key}",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"suspicious_key": key},
                        rule_code="S405",
                    )

                (value_type,) = struct.unpack("<I", self._read_bytes(f, 4, metadata_byte_budget))
                value = self._read_value(
                    f,
                    value_type,
                    array_items_read=metadata_array_items_read,
                    byte_budget=metadata_byte_budget,
                )
                if self._is_chat_template_key(key) and isinstance(value, str) and value.strip():
                    self._record_chat_template_occurrence(chat_templates, key, value, occurrence)
                metadata[key] = value

                # Security check for suspicious values
                if isinstance(value, str) and any(p in value for p in ("/", "\\", ";", "&&", "|", "`")):
                    result.add_check(
                        name="Metadata Value Security Check",
                        passed=False,
                        message=f"Suspicious metadata value for key '{key}': {value}",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"key": key, "value": str(value)[:200]},
                        rule_code="S902",
                    )

            result.metadata["metadata"] = metadata
            self._report_duplicate_metadata_keys(metadata_key_occurrences, result)
            self._scan_embedded_chat_templates(chat_templates, result)
            if metadata_key_limit_exceeded:
                return
        except _GgufMetadataLimitExceeded as e:
            self._report_metadata_limit(result, str(e))
            self._report_duplicate_metadata_keys(metadata_key_occurrences, result)
            self._scan_embedded_chat_templates(chat_templates, result)
            return
        except Exception as e:
            # Parsing errors are informational - indicate corruption/format issues, not security threats
            result.add_check(
                name="GGUF Metadata Parsing",
                passed=False,
                message=f"GGUF metadata parse error: {e}",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )
            self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
            self._report_duplicate_metadata_keys(metadata_key_occurrences, result)
            self._scan_embedded_chat_templates(chat_templates, result)
            return

        if n_tensors > self.max_tensors:
            self._report_tensor_limit(result, n_tensors)
            return

        # Align to tensor data
        # Note: general.alignment may be absent in files created by some tools (e.g., llama.cpp).
        # Only apply alignment if explicitly specified in metadata.
        metadata_end = f.tell()
        tensor_data_alignment = 32
        alignment = metadata.get("general.alignment")

        if alignment is not None:
            # Accept only positive power-of-two integers
            if (
                isinstance(alignment, int)
                and not isinstance(alignment, bool)
                and alignment > 0
                and (alignment & (alignment - 1)) == 0
            ):
                # Explicit alignment specified - apply it
                tensor_data_alignment = alignment
                pad = (alignment - (metadata_end % alignment)) % alignment
                if pad:
                    f.seek(pad, os.SEEK_CUR)
            else:
                result.add_check(
                    name="GGUF Alignment Validation",
                    passed=False,
                    message=f"Invalid alignment value: {alignment}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"alignment": alignment, "requirement": "power-of-two positive integer"},
                    rule_code="S902",
                )

        # Parse tensor information once to establish section bounds and retain a capped summary.
        tensor_info_start = f.tell()
        reported_tensors: list[dict[str, Any]] = []
        tensor_metadata_truncated = False
        tensor_byte_budget = _GgufByteBudget(
            self.max_tensor_info_bytes,
            "tensor information",
            _GgufTensorLimitExceeded,
        )
        try:
            for _i in range(n_tensors):
                tensor = self._read_tensor_info(f, tensor_byte_budget, result, record_checks=False)
                if tensor is None:
                    continue
                if len(reported_tensors) < self.max_reported_tensors:
                    reported_tensors.append(self._tensor_metadata_summary(tensor))
                else:
                    tensor_metadata_truncated = True

            result.metadata["tensors"] = reported_tensors
            result.metadata["tensor_count_reported"] = len(reported_tensors)
            if tensor_metadata_truncated:
                result.metadata["tensor_metadata_truncated"] = True
                result.metadata["max_reported_tensors"] = self.max_reported_tensors
        except _GgufTensorLimitExceeded as e:
            self._report_tensor_limit(result, n_tensors, message=str(e))
            return
        except Exception as e:
            # Parsing errors are informational - indicate corruption/format issues, not security threats
            result.add_check(
                name="GGUF Tensor Parsing",
                passed=False,
                message=f"GGUF tensor parse error: {e}",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )
            self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
            return

        # Calculate tensor data section start (offsets in tensor info are relative to this)
        # According to GGUF spec, tensor data is aligned after tensor info section
        tensor_info_end = f.tell()
        # Use default 32-byte alignment if not specified (GGUF spec default)
        pad_to_tensor_data = (tensor_data_alignment - (tensor_info_end % tensor_data_alignment)) % tensor_data_alignment
        tensor_data_start = tensor_info_end + pad_to_tensor_data
        # Only check bounds if there are tensors (empty models don't have tensor data)
        tensor_data_section_out_of_bounds = n_tensors > 0 and tensor_data_start > file_size
        if tensor_data_section_out_of_bounds:
            result.add_check(
                name="Tensor Data Section Bounds",
                passed=False,
                message="Tensor data start exceeds file size",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"tensor_data_start": tensor_data_start, "file_size": file_size},
            )
            self._mark_inconclusive(result, GGUF_STRUCTURE_INCONCLUSIVE_REASON)

        # Validate tensor sizes and offsets in a second streaming pass so large
        # GGUFs do not require retaining every tensor record in memory.
        f.seek(tensor_info_start)
        validation_budget = _GgufByteBudget(
            self.max_tensor_info_bytes,
            "tensor information",
            _GgufTensorLimitExceeded,
        )
        previous_tensor: _GgufTensorInfo | None = None
        try:
            for _i in range(n_tensors):
                tensor = self._read_tensor_info(f, validation_budget, result, record_checks=True)
                if tensor is None:
                    continue
                if tensor_data_section_out_of_bounds:
                    continue
                if previous_tensor is not None:
                    self._validate_tensor_info(
                        previous_tensor,
                        next_offset=tensor.offset,
                        tensor_data_start=tensor_data_start,
                        file_size=file_size,
                        tensor_data_alignment=tensor_data_alignment,
                        result=result,
                    )
                previous_tensor = tensor

            if previous_tensor is not None:
                self._validate_tensor_info(
                    previous_tensor,
                    next_offset=None,
                    tensor_data_start=tensor_data_start,
                    file_size=file_size,
                    tensor_data_alignment=tensor_data_alignment,
                    result=result,
                )
        except _GgufTensorLimitExceeded as e:
            self._report_tensor_limit(result, n_tensors, message=str(e))
            return
        except Exception as e:
            result.add_check(
                name="GGUF Tensor Parsing",
                passed=False,
                message=f"GGUF tensor parse error: {e}",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )
            self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
            return

        if tensor_data_section_out_of_bounds:
            return

        result.bytes_scanned = f.tell()

    @staticmethod
    def _tensor_metadata_summary(tensor: _GgufTensorInfo) -> dict[str, Any]:
        return {"name": tensor.name, "type": tensor.tensor_type, "dims": list(tensor.dims)}

    def _read_tensor_info(
        self,
        f: BinaryIO,
        budget: _GgufByteBudget,
        result: ScanResult,
        *,
        record_checks: bool,
    ) -> _GgufTensorInfo | None:
        t_name = self._read_string(f, budget=budget)
        (nd,) = struct.unpack("<I", self._read_bytes(f, 4, budget))

        if nd > 1000:
            if record_checks:
                result.add_check(
                    name="Tensor Dimension Validation",
                    passed=False,
                    message=f"Tensor {t_name} has excessive dimensions ({nd}), skipping for security",
                    rule_code="S804",
                    severity=IssueSeverity.CRITICAL,
                    location=self.current_file_path,
                    details={"tensor_name": t_name, "dimensions": nd, "max_allowed": 1000},
                )
            budget.consume(nd * 8 + 4 + 8)
            f.seek(nd * 8 + 4 + 8, os.SEEK_CUR)
            return None

        if nd > 8 and record_checks:
            result.add_check(
                name="Tensor Dimension Count Check",
                passed=False,
                message=f"Tensor {t_name} has suspicious number of dimensions: {nd}",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={"tensor_name": t_name, "dimensions": nd, "max_normal": 8},
                rule_code="S804",
            )

        dims = tuple(struct.unpack("<Q", self._read_bytes(f, 8, budget))[0] for _ in range(nd))
        (tensor_type,) = struct.unpack("<I", self._read_bytes(f, 4, budget))
        (offset,) = struct.unpack("<Q", self._read_bytes(f, 8, budget))
        return _GgufTensorInfo(name=t_name, dims=dims, tensor_type=tensor_type, offset=offset)

    def _validate_tensor_info(
        self,
        tensor: _GgufTensorInfo,
        *,
        next_offset: int | None,
        tensor_data_start: int,
        file_size: int,
        tensor_data_alignment: int,
        result: ScanResult,
    ) -> None:
        try:
            nelements = 1
            for dimension in tensor.dims:
                if dimension <= 0 or dimension > 2**31:
                    result.add_check(
                        name="Tensor Dimension Value Validation",
                        passed=False,
                        message=f"Tensor {tensor.name} has invalid dimension: {dimension}",
                        severity=IssueSeverity.INFO,
                        location=self.current_file_path,
                        details={"tensor_name": tensor.name, "invalid_dimension": dimension},
                        rule_code="S902",
                    )
                    self._mark_inconclusive(result, GGUF_STRUCTURE_INCONCLUSIVE_REASON)
                    return
                nelements *= dimension

            info = _GGML_TYPE_INFO.get(tensor.tensor_type)
            if info is None:
                result.add_check(
                    name="Tensor Type Validation",
                    passed=False,
                    message=f"Tensor {tensor.name} uses unknown GGML type {tensor.tensor_type}",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"tensor_name": tensor.name, "tensor_type": tensor.tensor_type},
                    rule_code="S902",
                )
                self._mark_inconclusive(result, GGUF_STRUCTURE_INCONCLUSIVE_REASON)
                return

            blck, ts = info
            estimated_size = ((nelements + blck - 1) // blck) * ts

            if estimated_size > self.max_uncompressed:
                result.add_check(
                    name="Tensor Size Limit Check",
                    passed=False,
                    message=f"Tensor {tensor.name} estimated size ({estimated_size}) exceeds limit",
                    rule_code="S902",
                    severity=IssueSeverity.CRITICAL,
                    location=self.current_file_path,
                    details={
                        "tensor_name": tensor.name,
                        "estimated_size": estimated_size,
                        "limit": self.max_uncompressed,
                    },
                )

            if nelements % blck != 0:
                result.add_check(
                    name="Tensor Block Alignment Check",
                    passed=False,
                    message=f"Tensor {tensor.name} not aligned to block size {blck}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"tensor_name": tensor.name, "block_size": blck, "elements": nelements},
                    rule_code="S804",
                )

            expected = ((nelements + blck - 1) // blck) * ts
            tensor_abs_start = tensor_data_start + tensor.offset
            tensor_abs_end = tensor_abs_start + expected
            offset_overflows_uint64 = tensor.offset > _UINT64_MAX - tensor_data_start
            end_overflows_uint64 = tensor_abs_start > _UINT64_MAX - expected

            if (
                offset_overflows_uint64
                or end_overflows_uint64
                or tensor_abs_start > file_size
                or tensor_abs_end > file_size
            ):
                result.add_check(
                    name="Tensor Data Bounds Check",
                    passed=False,
                    message=f"Tensor {tensor.name} data extends outside file bounds",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "tensor_name": tensor.name,
                        "offset": tensor.offset,
                        "expected": expected,
                        "tensor_data_start": tensor_data_start,
                        "tensor_abs_start": tensor_abs_start,
                        "tensor_abs_end": tensor_abs_end,
                        "file_size": file_size,
                        "offset_overflows_uint64": offset_overflows_uint64,
                        "end_overflows_uint64": end_overflows_uint64,
                    },
                    rule_code="S902",
                )
                return

            if next_offset is not None:
                if next_offset < tensor.offset:
                    result.add_check(
                        name="Tensor Offset Order Validation",
                        passed=False,
                        message=f"Non-monotonic offsets for tensor {tensor.name}",
                        severity=IssueSeverity.WARNING,
                        location=self.current_file_path,
                        details={"current_offset": tensor.offset, "next_offset": next_offset},
                    )
                    return
                actual = next_offset - tensor.offset
            else:
                actual = file_size - tensor_abs_start

            if abs(expected - actual) > tensor_data_alignment:
                result.add_check(
                    name="Tensor Size Consistency Check",
                    passed=False,
                    message=f"Size mismatch for tensor {tensor.name}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "tensor_name": tensor.name,
                        "expected": expected,
                        "actual": actual,
                        "alignment_tolerance": tensor_data_alignment,
                    },
                    rule_code="S902",
                )
        except (OverflowError, ValueError) as e:
            result.add_check(
                name="Tensor Validation Error",
                passed=False,
                message=f"Error validating tensor {tensor.name}: {e}",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"tensor_name": tensor.name, "error": str(e)},
                rule_code="S804",
            )
            self._mark_inconclusive(result, GGUF_STRUCTURE_INCONCLUSIVE_REASON)

    def _scan_ggml(
        self,
        f: BinaryIO,
        file_size: int,
        magic: bytes,
        result: ScanResult,
    ) -> None:
        """Basic GGML file validation with security checks."""
        result.metadata["format"] = "ggml"
        result.metadata["magic"] = magic.decode("ascii", "ignore")

        if file_size < 32:
            result.add_check(
                name="GGML File Size Validation",
                passed=False,
                message="File too small to be valid GGML",
                severity=IssueSeverity.INFO,
                location=self.current_file_path,
                details={"file_size": file_size, "min_required": 32},
                rule_code="S1005",  # Invalid signature/corrupted file
            )
            self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
            return

        # Basic heuristic validation
        try:
            version_bytes = f.read(4)
            if len(version_bytes) < 4:
                result.add_check(
                    name="GGML Header Integrity Check",
                    passed=False,
                    message="Truncated GGML header",
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={"header_bytes_read": len(version_bytes), "expected": 4},
                    rule_code="S902",
                )
                self._mark_inconclusive(result, GGUF_PARSE_INCONCLUSIVE_REASON)
                return

            version = struct.unpack("<I", version_bytes)[0]
            result.metadata["version"] = version

            if version > 10000:  # Reasonable upper bound
                result.add_check(
                    name="GGML Version Check",
                    passed=False,
                    message=f"Suspicious GGML version: {version}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={"version": version, "max_expected": 10000},
                    rule_code="S902",
                )
        except Exception as e:
            result.add_check(
                name="GGML Header Parsing",
                passed=False,
                message=f"Error parsing GGML header: {e}",
                severity=IssueSeverity.CRITICAL,
                location=self.current_file_path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )

        result.bytes_scanned = file_size

    def _read_value(
        self,
        f: BinaryIO,
        vtype: int,
        *,
        array_depth: int = 0,
        array_items_read: list[int] | None = None,
        byte_budget: _GgufByteBudget | None = None,
    ) -> Any:
        """Read a value of the specified type with security checks."""
        if vtype == 0:  # UINT8
            return struct.unpack("<B", self._read_bytes(f, 1, byte_budget))[0]
        if vtype == 1:  # INT8
            return struct.unpack("<b", self._read_bytes(f, 1, byte_budget))[0]
        if vtype == 2:  # UINT16
            return struct.unpack("<H", self._read_bytes(f, 2, byte_budget))[0]
        if vtype == 3:  # INT16
            return struct.unpack("<h", self._read_bytes(f, 2, byte_budget))[0]
        if vtype == 4:  # UINT32
            return struct.unpack("<I", self._read_bytes(f, 4, byte_budget))[0]
        if vtype == 5:  # INT32
            return struct.unpack("<i", self._read_bytes(f, 4, byte_budget))[0]
        if vtype == 6:  # FLOAT32
            return struct.unpack("<f", self._read_bytes(f, 4, byte_budget))[0]
        if vtype == 7:  # BOOL
            return struct.unpack("<B", self._read_bytes(f, 1, byte_budget))[0] != 0
        if vtype == 8:  # STRING
            return self._read_string(f, budget=byte_budget)
        if vtype == 9:  # ARRAY
            subtype = struct.unpack("<I", self._read_bytes(f, 4, byte_budget))[0]
            (count,) = struct.unpack("<Q", self._read_bytes(f, 8, byte_budget))
            next_depth = array_depth + 1
            if next_depth > self.max_metadata_array_depth:
                raise _GgufMetadataLimitExceeded(
                    f"Metadata array depth {next_depth} exceeds limit {self.max_metadata_array_depth}"
                )
            if count > self.max_metadata_array_items:
                raise _GgufMetadataLimitExceeded(
                    f"Metadata array item count {count} exceeds per-array limit {self.max_metadata_array_items}"
                )

            if array_items_read is None:
                array_items_read = [0]
            if count > self.max_total_metadata_array_items - array_items_read[0]:
                raise _GgufMetadataLimitExceeded(
                    f"Metadata array item count exceeds aggregate limit {self.max_total_metadata_array_items}"
                )
            array_items_read[0] += count
            return [
                self._read_value(
                    f,
                    subtype,
                    array_depth=next_depth,
                    array_items_read=array_items_read,
                    byte_budget=byte_budget,
                )
                for _ in range(count)
            ]
        if vtype == 10:  # UINT64
            return struct.unpack("<Q", self._read_bytes(f, 8, byte_budget))[0]
        if vtype == 11:  # INT64
            return struct.unpack("<q", self._read_bytes(f, 8, byte_budget))[0]
        if vtype == 12:  # FLOAT64
            return struct.unpack("<d", self._read_bytes(f, 8, byte_budget))[0]

        raise ValueError(f"Unknown metadata type {vtype}")

    @staticmethod
    def _is_chat_template_key(key: str) -> bool:
        return key == "tokenizer.chat_template" or key.startswith("tokenizer.chat_template.")

    @staticmethod
    def _record_chat_template_occurrence(
        templates: dict[str, str],
        key: str,
        value: str,
        occurrence: int,
    ) -> None:
        """Retain every parsed template even when GGUF metadata keys collide."""
        location = key if occurrence == 1 else f"{key} [metadata occurrence {occurrence}]"
        while location in templates:
            location = f"{location} [duplicate]"
        templates[location] = value

    def _report_duplicate_metadata_keys(self, occurrences: dict[str, int], result: ScanResult) -> None:
        duplicate_keys = {key: count for key, count in occurrences.items() if count > 1}
        if not duplicate_keys:
            return

        self._mark_inconclusive(result, GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON)
        result.add_check(
            name="GGUF Duplicate Metadata Keys",
            passed=False,
            message="Duplicate metadata keys have ambiguous consumer interpretation",
            severity=IssueSeverity.INFO,
            location=self.current_file_path,
            details={
                "duplicate_keys": sorted(duplicate_keys),
                "occurrences": duplicate_keys,
                "analysis_incomplete": True,
                "scan_outcome_reason": GGUF_DUPLICATE_METADATA_INCONCLUSIVE_REASON,
            },
            rule_code=None,
        )

    def _report_metadata_limit(self, result: ScanResult, message: str, **details: Any) -> None:
        self._mark_inconclusive(result, GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON)
        result.add_check(
            name="GGUF Metadata Resource Limits",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=self.current_file_path,
            details={
                "max_metadata_keys": self.max_metadata_keys,
                "max_metadata_bytes": self.max_metadata_bytes,
                "max_metadata_array_items": self.max_metadata_array_items,
                "max_total_metadata_array_items": self.max_total_metadata_array_items,
                "max_metadata_array_depth": self.max_metadata_array_depth,
                "analysis_incomplete": True,
                "scan_outcome_reason": GGUF_METADATA_LIMIT_INCONCLUSIVE_REASON,
                **details,
            },
            rule_code=None,
        )

    def _report_tensor_limit(self, result: ScanResult, declared_tensors: int, *, message: str | None = None) -> None:
        self._mark_inconclusive(result, GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON)
        result.add_check(
            name="GGUF Tensor Resource Limits",
            passed=False,
            message=message or f"File declares {declared_tensors} tensors, exceeding limit {self.max_tensors}",
            severity=IssueSeverity.INFO,
            location=self.current_file_path,
            details={
                "declared_tensors": declared_tensors,
                "max_tensors": self.max_tensors,
                "max_tensor_info_bytes": self.max_tensor_info_bytes,
                "analysis_incomplete": True,
                "scan_outcome_reason": GGUF_TENSOR_LIMIT_INCONCLUSIVE_REASON,
            },
            rule_code=None,
        )

    def _scan_embedded_chat_templates(self, templates: dict[str, str], result: ScanResult) -> None:
        if not templates:
            return

        from .jinja2_template_scanner import Jinja2TemplateScanner

        result.merge(
            Jinja2TemplateScanner(config=self.config).scan_extracted_templates(
                self.current_file_path,
                templates,
            )
        )

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract GGUF metadata."""
        metadata = super().extract_metadata(file_path)

        try:
            with open(file_path, "rb") as f:
                # Read GGUF header
                magic = f.read(4)
                if magic != b"GGUF":
                    metadata["error"] = "Invalid GGUF magic bytes"
                    return metadata

                version = struct.unpack("<I", f.read(4))[0]
                tensor_count = struct.unpack("<Q", f.read(8))[0]
                metadata_count = struct.unpack("<Q", f.read(8))[0]

                metadata.update(
                    {
                        "gguf_version": version,
                        "tensor_count": tensor_count,
                        "metadata_count": metadata_count,
                    }
                )

                # Read metadata fields
                gguf_metadata = {}
                if metadata_count > self.max_metadata_keys:
                    metadata["error_reading_metadata"] = (
                        f"File declares {metadata_count} metadata keys, exceeding limit {self.max_metadata_keys}"
                    )
                    return metadata
                metadata_array_items_read = [0]
                metadata_byte_budget = _GgufByteBudget(
                    self.max_metadata_bytes,
                    "metadata",
                    _GgufMetadataLimitExceeded,
                )
                for _ in range(metadata_count):
                    try:
                        # Read key
                        key = self._read_string(f, budget=metadata_byte_budget)

                        # Read value type
                        vtype = struct.unpack("<I", self._read_bytes(f, 4, metadata_byte_budget))[0]

                        # Read value
                        value = self._read_value(
                            f,
                            vtype,
                            array_items_read=metadata_array_items_read,
                            byte_budget=metadata_byte_budget,
                        )
                        gguf_metadata[key] = value

                    except Exception as e:
                        metadata["error_reading_metadata"] = str(e)
                        break

                # Extract key model information
                model_info = {}

                # Common GGUF metadata keys
                key_fields = [
                    "general.name",
                    "general.architecture",
                    "general.quantization_version",
                    "general.file_type",
                    "general.parameter_count",
                    "general.context_length",
                    "tokenizer.ggml.model",
                    "tokenizer.ggml.tokens",
                    "tokenizer.chat_template",
                ]

                for field in key_fields:
                    if field in gguf_metadata:
                        model_info[field.replace(".", "_")] = gguf_metadata[field]

                if model_info:
                    metadata["model_info"] = model_info

                # Summary info
                metadata.update(
                    {
                        "has_model_name": "general.name" in gguf_metadata,
                        "has_tokenizer": any(key.startswith("tokenizer.") for key in gguf_metadata),
                        "has_chat_template": "tokenizer.chat_template" in gguf_metadata,
                        "architecture": gguf_metadata.get("general.architecture", "unknown"),
                        "parameter_count": gguf_metadata.get("general.parameter_count", "unknown"),
                    }
                )

                # Security relevant info
                if "tokenizer.chat_template" in gguf_metadata:
                    template = gguf_metadata["tokenizer.chat_template"]
                    if isinstance(template, str) and len(template) > 1000:
                        metadata["large_chat_template"] = True
                        metadata["chat_template_size"] = len(template)

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
