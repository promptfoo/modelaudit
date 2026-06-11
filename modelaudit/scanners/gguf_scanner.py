"""GGUF/GGML scanner that combines comprehensive parsing with security checks."""

from __future__ import annotations

import os
import re
import struct
from collections.abc import Iterable
from typing import Any, BinaryIO, ClassVar, NamedTuple
from urllib.parse import unquote

from modelaudit.detectors.suspicious_symbols import JINJA2_SSTI_PATTERNS

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
_GGUF_MAX_METADATA_VALUE_SECURITY_CHECKS = 64
_GGUF_METADATA_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "python_command_api",
        re.compile(
            r"(?i)(?:\b(?:os\.system|os\.popen|subprocess\."
            r"(?:popen|call|run|check_call|check_output|getoutput|getstatusoutput))"
            r"|(?<![\w.])(?:eval|exec|__import__))\s*\(",
        ),
    ),
    (
        "shell_command",
        re.compile(
            r"(?i)(?:^|[;&|`$()]\s*)(?:(?:[a-z]:)?[\\/](?:[^\\/\s]+[\\/])*)?"
            r"(?:bash|sh|zsh|fish|cmd(?:\.exe)?|powershell|pwsh|python(?:3)?|perl|ruby|node)\s+(?:-[ce]|/c)\b",
        ),
    ),
    ("backtick_command", re.compile(r"(?i)`\s*(?:rm|curl|wget|bash|sh|python(?:3)?|powershell|pwsh|cmd(?:\.exe)?)\b")),
)
_GGUF_DESTRUCTIVE_COMMAND_PREFIXES = ("sudo", "doas", "command", "env", "nohup", "nice", "setsid", "timeout")
_GGUF_METADATA_SHELL_FETCH_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("shell_download", ("curl", "wget")),
    ("powershell_download", ("invoke-webrequest", "iwr")),
)
_GGUF_FETCH_OPTIONS_WITH_VALUE = frozenset(
    {
        "-a",
        "--append-output",
        "-d",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "-f",
        "--form",
        "--form-string",
        "-h",
        "--header",
        "-m",
        "--connect-timeout",
        "--limit-rate",
        "--max-time",
        "-o",
        "--output",
        "--output-document",
        "--post-data",
        "--post-file",
        "--proxy",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "--speed-limit",
        "--speed-time",
        "-u",
        "--user",
        "-x",
        "--request",
        "--url",
        "-uri",
        "-outfile",
    }
)
_GGUF_FETCH_DESTINATION_OPTIONS_WITH_VALUE = frozenset({"--url", "-uri"})
_GGUF_FETCH_SHORT_OPTIONS_WITH_SEPARATE_VALUE = frozenset({"a", "d", "h", "m", "o", "u", "x"})
_GGUF_METADATA_NETWORK_APIS = (
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.options",
    "httpx.request",
    "httpx.stream",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urlopen",
    "urlretrieve",
    "fetch",
)
_GGUF_NETWORK_URL_ASSIGNMENT_PATTERN = re.compile(
    r"""(?is)\b(?P<name>[a-z_][a-z0-9_]*)\s*=\s*(?:[rubf]{0,2})?(?P<quote>['"])(?:https?|ftp)://[^'"\s<>]+(?P=quote)""",
)
_GGUF_SHELL_IFS_PATTERN = re.compile(r"(?i)\$\{ifs(?:[^}]*)?\}|\$ifs\b")
_GGUF_SHELL_VARIABLE_NAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*$")
_GGUF_DEFAULT_MAX_TEMPLATE_SIZE = 50000
_GGUF_CHAT_TEMPLATE_METADATA_PATTERN_TYPES = tuple(JINJA2_SSTI_PATTERNS)
_GGUF_CHAT_TEMPLATE_METADATA_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (pattern_type, re.compile(pattern, re.IGNORECASE | re.MULTILINE))
    for pattern_type in _GGUF_CHAT_TEMPLATE_METADATA_PATTERN_TYPES
    for pattern in JINJA2_SSTI_PATTERNS.get(pattern_type, [])
)
_GGUF_TIMEOUT_OPTIONS_WITH_VALUE = frozenset({"-k", "--kill-after"})
_GGUF_TIMEOUT_DURATION_PATTERN = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_GGUF_REMOTE_URL_SCHEMES = ("http://", "https://", "ftp://")
_GGUF_SHELL_SEGMENT_SEPARATORS = ";&|`()"


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
        return data.decode("utf-8")

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
                if self._contains_path_traversal(key):
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

                self._report_metadata_value_security_checks(key, value, result)

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
    def _is_tokenizer_vocabulary_key(key: str) -> bool:
        return key == "tokenizer.ggml.tokens" or key.startswith("tokenizer.ggml.tokens.")

    @staticmethod
    def _metadata_decode_variants(value: str) -> tuple[str, ...]:
        variants: list[str] = []
        current = value
        for _ in range(3):
            if current not in variants:
                variants.append(current)
            decoded = unquote(current)
            if decoded == current:
                break
            current = decoded
        if current not in variants:
            variants.append(current)
        return tuple(variants)

    @classmethod
    def _contains_path_traversal(cls, value: str) -> bool:
        for candidate in cls._metadata_decode_variants(value):
            if ".." not in candidate:
                continue
            normalized = candidate.replace("\\", "/")
            if normalized == ".." or normalized.startswith("../") or normalized.endswith("/..") or "/../" in normalized:
                return True
        return False

    @staticmethod
    def _shell_command_segments(value: str) -> list[list[str]]:
        value = _GGUF_SHELL_IFS_PATTERN.sub(" ", value)
        segments: list[list[str]] = []
        current_segment: list[str] = []
        current_word: list[str] = []
        quote: str | None = None

        for character in value:
            if quote is not None:
                if character == quote:
                    quote = None
                    continue
                current_word.append(character)
                continue
            if character in {"'", '"'}:
                quote = character
                continue
            if character.isspace():
                if current_word:
                    current_segment.append("".join(current_word))
                    current_word = []
                continue
            if character in _GGUF_SHELL_SEGMENT_SEPARATORS:
                if current_word:
                    current_segment.append("".join(current_word))
                    current_word = []
                if current_segment:
                    segments.append(current_segment)
                    current_segment = []
                continue
            current_word.append(character)

        if current_word:
            current_segment.append("".join(current_word))
        if current_segment:
            segments.append(current_segment)
        return segments

    @staticmethod
    def _is_documentation_metadata_key(key: str) -> bool:
        lowered = key.lower()
        return any(
            marker in lowered
            for marker in (
                "description",
                "documentation",
                "instructions",
                "readme",
                "model_card",
                "license",
                "author",
            )
        )

    @classmethod
    def _metadata_value_looks_like_documentation(cls, key: str, value: str) -> bool:
        if not cls._is_documentation_metadata_key(key):
            return False

        lines = [line.strip() for line in value.splitlines() if line.strip()]
        if not lines:
            return False

        doc_lines = 0
        in_fence = False
        for line in lines:
            lowered = line.lower()
            if lowered.startswith(("```", "~~~")):
                in_fence = not in_fence
                doc_lines += 1
                continue
            if in_fence:
                doc_lines += 1
                continue
            if lowered.startswith(("#", "//", "*", "-", ">")) or cls._line_looks_like_documentation(lowered):
                if cls._line_contains_security_evidence(line):
                    continue
                doc_lines += 1

        return doc_lines > len(lines) / 2

    @classmethod
    def _line_contains_security_evidence(cls, line: str) -> bool:
        return (
            cls._contains_path_traversal(line)
            or cls._destructive_rm_pattern(line)
            or cls._shell_remote_fetch_pattern(line) is not None
            or cls._network_api_remote_fetch_pattern(line) is not None
            or any(pattern.search(line) for _pattern_name, pattern in _GGUF_METADATA_COMMAND_PATTERNS)
        )

    @staticmethod
    def _line_looks_like_documentation(lowered_line: str) -> bool:
        return lowered_line.startswith(
            (
                "example:",
                "examples:",
                "documentation:",
                "instructions:",
                "model card",
                "repository instructions:",
                "usage:",
            )
        ) or any(
            marker in lowered_line
            for marker in (
                " example is documentation",
                " examples are documented",
                " examples are listed",
                " model card ",
            )
        )

    @staticmethod
    def _shell_command_name(word: str) -> str:
        command = word.strip("\"'").replace("\\", "/").rsplit("/", 1)[-1]
        if command.endswith(".exe"):
            return command[:-4]
        return command

    @staticmethod
    def _is_destructive_rm_target(word: str) -> bool:
        target = word.strip("\"'").replace("\\", "/")
        return target.startswith(("/", "~", "$", "..")) or "/.." in target

    @staticmethod
    def _rm_option_flags(word: str) -> tuple[bool, bool]:
        option = word.lower().split("=", 1)[0]
        if option in {"--recursive", "--force"}:
            return option == "--recursive", option == "--force"
        if option.startswith("--"):
            return False, False
        short_options = option.lstrip("-")
        return "r" in short_options, "f" in short_options

    @staticmethod
    def _is_timeout_duration(word: str) -> bool:
        return bool(_GGUF_TIMEOUT_DURATION_PATTERN.fullmatch(word.strip("\"'")))

    @classmethod
    def _skip_timeout_prefix_arguments(cls, words: list[str], index: int) -> int:
        while index < len(words):
            word = words[index]
            option = word.split("=", 1)[0]
            if option in _GGUF_TIMEOUT_OPTIONS_WITH_VALUE:
                index += 1 if "=" in word else 2
                continue
            if word.startswith("-"):
                index += 1
                continue
            if cls._is_timeout_duration(word):
                return index + 1
            return index
        return index

    @classmethod
    def _destructive_rm_segment(cls, words: list[str]) -> bool:
        index = 0
        while index < len(words):
            word = words[index]
            command_name = cls._shell_command_name(word)
            if command_name in _GGUF_DESTRUCTIVE_COMMAND_PREFIXES:
                index += 1
                if command_name == "timeout":
                    index = cls._skip_timeout_prefix_arguments(words, index)
                    continue
                while index < len(words) and words[index].startswith("-"):
                    index += 1
                while index < len(words) and "=" in words[index] and not words[index].startswith("-"):
                    index += 1
                continue
            if "=" in word and not word.startswith("-"):
                index += 1
                continue
            break

        if index >= len(words) or cls._shell_command_name(words[index]) != "rm":
            return False

        has_recursive = False
        has_force = False
        has_target = False
        index += 1
        while index < len(words):
            word = words[index]
            if word.startswith("-"):
                option_recursive, option_force = cls._rm_option_flags(word)
                has_recursive = has_recursive or option_recursive
                has_force = has_force or option_force
            else:
                has_target = has_target or cls._is_destructive_rm_target(word)
            index += 1

        return has_recursive and has_force and has_target

    @classmethod
    def _destructive_rm_pattern(cls, value: str) -> bool:
        value_lower = value.lower()
        if "rm" not in value_lower:
            return False
        return any(cls._destructive_rm_segment(segment) for segment in cls._shell_command_segments(value_lower))

    @staticmethod
    def _iter_substring_positions(value: str, needle: str) -> Iterable[int]:
        start = 0
        while True:
            position = value.find(needle, start)
            if position == -1:
                return
            yield position
            start = position + 1

    @staticmethod
    def _is_remote_url_token(word: str) -> bool:
        token = word.strip("\"'<>[]{}(),")
        return any(token.startswith(scheme) for scheme in _GGUF_REMOTE_URL_SCHEMES)

    @classmethod
    def _shell_url_variable_names(cls, words: list[str]) -> set[str]:
        names: set[str] = set()
        for word in words:
            if "=" not in word or word.startswith("-"):
                continue
            name, value = word.split("=", 1)
            name = name.strip("\"'")
            if _GGUF_SHELL_VARIABLE_NAME_PATTERN.fullmatch(name) and cls._is_remote_url_token(value):
                names.add(name)
        return names

    @staticmethod
    def _shell_word_references_variable(word: str, names: set[str]) -> bool:
        if not names:
            return False

        token = word.strip("\"'<>[](),")
        if token.startswith("${"):
            close_position = token.find("}", 2)
            if close_position == -1:
                return False
            name = token[2:close_position]
            return name in names

        if not token.startswith("$"):
            return False

        name_chars: list[str] = []
        for character in token[1:]:
            if character.isalnum() or character == "_":
                name_chars.append(character)
                continue
            break
        return "".join(name_chars) in names

    @staticmethod
    def _is_fetch_option_with_value(word: str) -> bool:
        if word in _GGUF_FETCH_OPTIONS_WITH_VALUE:
            return True
        if "=" in word:
            option_name, _option_value = word.split("=", 1)
            return option_name in _GGUF_FETCH_OPTIONS_WITH_VALUE
        if word.startswith("-") and not word.startswith("--") and len(word) > 2:
            return any(option in _GGUF_FETCH_SHORT_OPTIONS_WITH_SEPARATE_VALUE for option in word[1:])
        return False

    @staticmethod
    def _is_fetch_destination_option_with_value(word: str) -> bool:
        option_name = word.split("=", 1)[0]
        return option_name in _GGUF_FETCH_DESTINATION_OPTIONS_WITH_VALUE

    @classmethod
    def _fetch_segment_has_remote_url(cls, words: list[str], command: str, shell_url_variables: set[str]) -> bool:
        for command_index, word in enumerate(words):
            if cls._shell_command_name(word) != command:
                continue
            index = command_index + 1
            while index < len(words):
                candidate = words[index]
                if cls._is_remote_url_token(candidate) or cls._shell_word_references_variable(
                    candidate,
                    shell_url_variables,
                ):
                    return True
                if candidate.startswith("-"):
                    if not cls._is_fetch_option_with_value(candidate) and any(
                        scheme in candidate for scheme in _GGUF_REMOTE_URL_SCHEMES
                    ):
                        return True
                    if cls._is_fetch_option_with_value(candidate):
                        if "=" in candidate:
                            _option_name, option_value = candidate.split("=", 1)
                            if cls._is_fetch_destination_option_with_value(candidate) and (
                                cls._is_remote_url_token(option_value)
                                or cls._shell_word_references_variable(option_value, shell_url_variables)
                            ):
                                return True
                            index += 1
                            continue
                        index += 1
                        if (
                            cls._is_fetch_destination_option_with_value(candidate)
                            and index < len(words)
                            and (
                                cls._is_remote_url_token(words[index])
                                or cls._shell_word_references_variable(words[index], shell_url_variables)
                            )
                        ):
                            return True
                    index += 1
                    continue
                break
        return False

    @classmethod
    def _has_fetch_command_with_url(cls, value: str, commands: tuple[str, ...]) -> bool:
        shell_url_variables: set[str] = set()
        for segment in cls._shell_command_segments(value):
            for command in commands:
                if cls._fetch_segment_has_remote_url(segment, command, shell_url_variables):
                    return True
            shell_url_variables.update(cls._shell_url_variable_names(segment))
        return False

    @staticmethod
    def _has_remote_url(value: str) -> bool:
        return any(scheme in value for scheme in _GGUF_REMOTE_URL_SCHEMES)

    @staticmethod
    def _has_token_boundary(value: str, position: int, token: str) -> bool:
        before = value[position - 1] if position else ""
        after_position = position + len(token)
        after = value[after_position] if after_position < len(value) else ""
        if before and (before.isalnum() or before in "._-"):
            return False
        return not (after and (after.isalnum() or after in "._-"))

    @classmethod
    def _has_network_api_boundary(cls, value: str, position: int, token: str) -> bool:
        if token == "fetch" and position > 0 and value[position - 1] == ".":
            after_position = position + len(token)
            after = value[after_position] if after_position < len(value) else ""
            return not (after and (after.isalnum() or after in "._-"))
        return cls._has_token_boundary(value, position, token)

    @staticmethod
    def _api_argument_window(value: str, after_position: int) -> str | None:
        open_position = value.find("(", after_position, after_position + 128)
        if open_position == -1:
            return None
        close_position = value.find(")", open_position + 1, open_position + 2049)
        end_position = close_position if close_position != -1 else open_position + 2048
        return value[open_position:end_position]

    @classmethod
    def _api_argument_window_has_remote_url(cls, value: str, after_position: int) -> bool:
        argument_window = cls._api_argument_window(value, after_position)
        return argument_window is not None and cls._has_remote_url(argument_window)

    @staticmethod
    def _remote_url_variable_assignments(value: str) -> tuple[tuple[int, str], ...]:
        assignments: list[tuple[int, str]] = []
        for match in _GGUF_NETWORK_URL_ASSIGNMENT_PATTERN.finditer(value):
            assignments.append((match.start(), match.group("name")))
            if len(assignments) >= 64:
                break
        return tuple(assignments)

    @staticmethod
    def _remote_url_variable_names_before(assignments: tuple[tuple[int, str], ...], position: int) -> set[str]:
        return {name for assignment_position, name in assignments if assignment_position < position}

    @classmethod
    def _argument_window_uses_variable(cls, argument_window: str, names: set[str]) -> bool:
        for name in names:
            if not name:
                continue
            for position in cls._iter_substring_positions(argument_window, name):
                if cls._has_token_boundary(argument_window, position, name):
                    return True
        return False

    @classmethod
    def _shell_remote_fetch_pattern(cls, value: str) -> str | None:
        value_lower = value.lower()
        if not cls._has_remote_url(value_lower):
            return None
        if not any(
            command in value_lower
            for _pattern_name, commands in _GGUF_METADATA_SHELL_FETCH_COMMANDS
            for command in commands
        ):
            return None

        for pattern_name, commands in _GGUF_METADATA_SHELL_FETCH_COMMANDS:
            if cls._has_fetch_command_with_url(value_lower, commands):
                return pattern_name
        return None

    @classmethod
    def _network_api_remote_fetch_pattern(cls, value: str) -> str | None:
        value_lower = value.lower()
        if not cls._has_remote_url(value_lower):
            return None

        remote_url_assignments = cls._remote_url_variable_assignments(value_lower)
        for api_name in _GGUF_METADATA_NETWORK_APIS:
            for api_position in cls._iter_substring_positions(value_lower, api_name):
                if not cls._has_network_api_boundary(value_lower, api_position, api_name):
                    continue
                after_position = api_position + len(api_name)
                argument_window = cls._api_argument_window(value_lower, after_position)
                if argument_window is None:
                    continue
                if cls._has_remote_url(argument_window):
                    return "network_api"
                remote_url_variables = cls._remote_url_variable_names_before(remote_url_assignments, api_position)
                if remote_url_variables and cls._argument_window_uses_variable(argument_window, remote_url_variables):
                    return "network_api"
        return None

    @classmethod
    def _oversized_chat_template_security_evidence(cls, value: str) -> list[dict[str, str]]:
        for pattern_type, pattern in _GGUF_CHAT_TEMPLATE_METADATA_PATTERNS:
            if pattern.search(value):
                return [{"evidence_type": "template_injection", "pattern": f"jinja2_{pattern_type}"}]
        return []

    @classmethod
    def _metadata_value_security_evidence(
        cls,
        key: str,
        value: str,
        *,
        max_template_size: int = _GGUF_DEFAULT_MAX_TEMPLATE_SIZE,
    ) -> list[dict[str, str]]:
        if cls._metadata_value_looks_like_documentation(key, value):
            return []

        if cls._is_chat_template_key(key):
            if len(value) <= max_template_size:
                return []
            return cls._oversized_chat_template_security_evidence(value)

        evidence: list[dict[str, str]] = []
        if cls._contains_path_traversal(value):
            evidence.append({"evidence_type": "path_traversal", "pattern": "dot_dot_path_segment"})

        if cls._destructive_rm_pattern(value):
            evidence.append({"evidence_type": "command_execution", "pattern": "destructive_rm"})
        else:
            for pattern_name, pattern in _GGUF_METADATA_COMMAND_PATTERNS:
                if pattern.search(value):
                    evidence.append({"evidence_type": "command_execution", "pattern": pattern_name})
                    break

        shell_remote_fetch_pattern = cls._shell_remote_fetch_pattern(value)
        if shell_remote_fetch_pattern is not None:
            evidence.append({"evidence_type": "remote_fetch", "pattern": shell_remote_fetch_pattern})
            return evidence

        network_remote_fetch_pattern = cls._network_api_remote_fetch_pattern(value)
        if network_remote_fetch_pattern is not None:
            evidence.append({"evidence_type": "remote_fetch", "pattern": network_remote_fetch_pattern})

        return evidence

    @classmethod
    def _iter_metadata_strings(cls, value: Any) -> Iterable[tuple[str, str]]:
        stack: list[tuple[str, Any]] = [("", value)]
        while stack:
            path, current = stack.pop()
            if isinstance(current, str):
                yield path, current
                continue
            if isinstance(current, list):
                for index in range(len(current) - 1, -1, -1):
                    item = current[index]
                    item_path = f"{path}[{index}]" if path else f"[{index}]"
                    stack.append((item_path, item))

    def _report_metadata_value_security_checks(self, key: str, value: Any, result: ScanResult) -> None:
        if self._is_tokenizer_vocabulary_key(key):
            return

        reported = sum(
            1
            for check in result.checks
            if check.name == "Metadata Value Security Check" and check.status.value == "failed"
        )
        max_template_size = self.config.get("max_template_size", _GGUF_DEFAULT_MAX_TEMPLATE_SIZE)

        for value_path, string_value in self._iter_metadata_strings(value):
            for evidence in self._metadata_value_security_evidence(
                key,
                string_value,
                max_template_size=max_template_size,
            ):
                if reported >= _GGUF_MAX_METADATA_VALUE_SECURITY_CHECKS:
                    result.metadata["metadata_value_security_checks_truncated"] = True
                    result.metadata["max_metadata_value_security_checks"] = _GGUF_MAX_METADATA_VALUE_SECURITY_CHECKS
                    return
                result.add_check(
                    name="Metadata Value Security Check",
                    passed=False,
                    message=(
                        f"Suspicious metadata value for key '{key}' contains "
                        f"{evidence['evidence_type'].replace('_', ' ')} evidence"
                    ),
                    severity=IssueSeverity.INFO,
                    location=self.current_file_path,
                    details={
                        "key": key,
                        "value_path": value_path,
                        "value": string_value[:200],
                        **evidence,
                    },
                    rule_code="S902",
                )
                reported += 1

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
