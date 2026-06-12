"""Scanner for NumPy serialized array files (.npy, .npz)."""

from __future__ import annotations

import ast
import io
import struct
import sys
import warnings
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, BinaryIO, ClassVar

from modelaudit_picklescan.call_graph import import_only_reference_is_proven_trusted

from ..core_results import mark_operational_scan_error
from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, Check, CheckStatus, Issue, IssueSeverity, ScanResult
from .pickle_scanner import PickleScanner

_PicklescanOwnerProof = Callable[[str, str, object], bool]
_PicklescanLoadedReferenceState = Callable[[str, str], tuple[bool, object | None]]
_PicklescanModuleOriginKind = Callable[[str], str | None]
_PicklescanPayloadProof = Callable[[bytes | None], bool]
_picklescan_current_loaded_interpreter_reference_state: _PicklescanLoadedReferenceState | None
_picklescan_loaded_site_package_reference_owner_matches: _PicklescanOwnerProof | None
_picklescan_trusted_module_origin_kind: _PicklescanModuleOriginKind | None
_picklescan_payload_has_only_safe_numpy_ndarray_reconstruction: _PicklescanPayloadProof | None
try:
    from modelaudit_picklescan.call_graph import (
        _current_loaded_interpreter_reference_state as _picklescan_current_loaded_interpreter_reference_state,
    )
    from modelaudit_picklescan.call_graph import (
        _loaded_site_package_reference_owner_matches as _picklescan_loaded_site_package_reference_owner_matches,
    )
    from modelaudit_picklescan.call_graph import _trusted_module_origin_kind as _picklescan_trusted_module_origin_kind
except ImportError:
    _picklescan_current_loaded_interpreter_reference_state = None
    _picklescan_loaded_site_package_reference_owner_matches = None
    _picklescan_trusted_module_origin_kind = None
try:
    from modelaudit_picklescan import api as _picklescan_api

    _picklescan_payload_has_only_safe_numpy_ndarray_reconstruction = (
        _picklescan_api._pickle_payload_has_only_safe_numpy_ndarray_reconstruction
    )
except (ImportError, AttributeError):
    _picklescan_payload_has_only_safe_numpy_ndarray_reconstruction = None

# Import NumPy with compatibility handling
try:
    import numpy as np

    # Handle NumPy format module imports with version compatibility
    try:
        import numpy.lib.format as fmt

        NUMPY_FORMAT_AVAILABLE = True
    except (ImportError, AttributeError):
        # Fallback for potential import issues
        NUMPY_FORMAT_AVAILABLE = False
        if TYPE_CHECKING:
            import numpy.lib.format as fmt  # type: ignore[no-redef]
        else:
            fmt = None  # type: ignore[assignment]

    NUMPY_AVAILABLE = True
    NUMPY_VERSION = getattr(np, "__version__", "unknown")
    NUMPY_MAJOR_VERSION = int(NUMPY_VERSION.split(".")[0]) if NUMPY_VERSION != "unknown" else 1
except ImportError:
    NUMPY_AVAILABLE = False
    NUMPY_FORMAT_AVAILABLE = False
    NUMPY_VERSION = "not available"
    NUMPY_MAJOR_VERSION = 0
    if TYPE_CHECKING:
        import numpy as np  # type: ignore[no-redef]
        import numpy.lib.format as fmt  # type: ignore[no-redef]
    else:
        np = None  # type: ignore[assignment]
        fmt = None  # type: ignore[assignment]


def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    reasons = result.metadata.setdefault("scan_outcome_reasons", [])
    if isinstance(reasons, list) and reason not in reasons:
        reasons.append(reason)
    result.metadata["analysis_incomplete"] = True


def _finish_with_inconclusive_contract(result: ScanResult, *, default_success: bool) -> None:
    result.finish(success=default_success and not result.has_errors)


NUMPY_OBJECT_EMBEDDED_PICKLE_SELECTION_SKIP_REASON = "numpy_object_embedded_pickle_scanner_selection_skip"
_VALIDATED_NUMPY_OBJECT_DTYPE_RECONSTRUCTION_REFERENCES = frozenset(
    {
        "numpy._core.multiarray._reconstruct",
        "numpy.core.multiarray._reconstruct",
        "numpy.dtype",
        "numpy.ndarray",
    }
)
_VALIDATED_NUMPY_OBJECT_DTYPE_RECONSTRUCT_REFERENCES = frozenset(
    {
        "numpy._core.multiarray._reconstruct",
        "numpy.core.multiarray._reconstruct",
    }
)
_NUMPY_OBJECT_SAFE_RECONSTRUCT_PROOF_MAX_BYTES = 10 * 1024 * 1024
NUMPY_HEADER_MAX_SIZE = 10_000
NUMPY_V3_HEADER_MAX_BYTES = NUMPY_HEADER_MAX_SIZE * 4


def _numpy_object_reconstruction_reference_is_trusted(module: str, name: str) -> bool:
    try:
        return import_only_reference_is_proven_trusted(module, name)
    except Exception as error:
        warnings.warn(
            f"Falling back to loaded NumPy reconstruction owner proof for {module}.{name}: {error}",
            RuntimeWarning,
            stacklevel=2,
        )

    try:
        if (
            _picklescan_current_loaded_interpreter_reference_state is None
            or _picklescan_loaded_site_package_reference_owner_matches is None
            or _picklescan_trusted_module_origin_kind is None
            or _picklescan_trusted_module_origin_kind(module) != "site_packages"
        ):
            return False
        loaded, value = _picklescan_current_loaded_interpreter_reference_state(module, name)
        if not loaded:
            return False
        return _picklescan_loaded_site_package_reference_owner_matches(module, name, value)
    except Exception:
        return False


def _numpy_object_payload_has_safe_reconstruct_proof(payload: bytes) -> bool:
    try:
        return (
            _picklescan_payload_has_only_safe_numpy_ndarray_reconstruction is not None
            and _picklescan_payload_has_only_safe_numpy_ndarray_reconstruction(payload)
        )
    except Exception:
        return False


def _read_numpy_array_header(handle: BinaryIO, version: tuple[int, int]) -> tuple[tuple[int, ...], bool, Any]:
    """Read a bounded NumPy header while preserving v3 UTF-8 field names."""
    if version == (1, 0):
        header_length_format = "<H"
    elif version in {(2, 0), (3, 0)}:
        header_length_format = "<I"
    else:
        raise ValueError(f"Unsupported NumPy file format version: {version}")

    header_length_size = struct.calcsize(header_length_format)
    header_length_bytes = handle.read(header_length_size)
    if len(header_length_bytes) != header_length_size:
        raise ValueError("EOF while reading NumPy header length")
    header_length = struct.unpack(header_length_format, header_length_bytes)[0]
    max_header_bytes = NUMPY_V3_HEADER_MAX_BYTES if version == (3, 0) else NUMPY_HEADER_MAX_SIZE
    if header_length > max_header_bytes:
        raise ValueError(
            f"NumPy header is too large: {header_length} bytes (max: {max_header_bytes})",
        )

    header_bytes = handle.read(header_length)
    if len(header_bytes) != header_length:
        raise ValueError("EOF while reading NumPy header")

    if version == (1, 0):
        shape, fortran_order, dtype = fmt.read_array_header_1_0(io.BytesIO(header_length_bytes + header_bytes))
    elif version == (2, 0):
        shape, fortran_order, dtype = fmt.read_array_header_2_0(io.BytesIO(header_length_bytes + header_bytes))
    else:
        header_text = header_bytes.decode("utf-8")
        if len(header_text) > NUMPY_HEADER_MAX_SIZE:
            raise ValueError(
                f"NumPy header is too large: {len(header_text)} characters (max: {NUMPY_HEADER_MAX_SIZE})",
            )
        header = ast.literal_eval(header_text)
        if not isinstance(header, dict) or set(header) != {"descr", "fortran_order", "shape"}:
            raise ValueError("Invalid NumPy v3 header dictionary")

        shape = header["shape"]
        fortran_order = header["fortran_order"]
        if not isinstance(shape, tuple) or not all(isinstance(dim, int) for dim in shape):
            raise ValueError("Invalid NumPy v3 array shape")
        if not isinstance(fortran_order, bool):
            raise ValueError("Invalid NumPy v3 fortran_order value")
        dtype = fmt.descr_to_dtype(header["descr"])

    if any(isinstance(dim, bool) for dim in shape):
        raise ValueError("Boolean NumPy shape dimensions are invalid")
    if any(dim < 0 for dim in shape):
        raise ValueError("Negative NumPy shape dimensions are invalid")

    return shape, fortran_order, dtype


class NumPyScanner(BaseScanner):
    """Scanner for NumPy binary files (.npy) with cross-version compatibility."""

    name = "numpy"
    description = f"Scans NumPy .npy files for integrity issues (NumPy {NUMPY_VERSION})"
    supported_extensions: ClassVar[list[str]] = [".npy"]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.scanner_selection = policy_from_config(self.config)
        # Security limits
        self.max_array_bytes = self.config.get(
            "max_array_bytes",
            100 * 1024 * 1024 * 1024,
        )  # 100GB for large numpy arrays
        self.max_dimensions = self.config.get("max_dimensions", 32)
        self.max_dimension_size = self.config.get("max_dimension_size", 100_000_000)
        self.max_itemsize = self.config.get("max_itemsize", 1024)  # 1KB per element

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not NUMPY_AVAILABLE or not NUMPY_FORMAT_AVAILABLE:
            return False
        return super().can_handle(path)

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _finish_read_failure(result: ScanResult, path: str, error: OSError) -> ScanResult:
        mark_operational_scan_error(result, "numpy_read_failed")
        _mark_inconclusive_scan_result(result, "numpy_read_failed")
        result.add_check(
            name="NumPy File Read",
            passed=False,
            message=f"Unable to read NumPy file: {error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "numpy_version": NUMPY_VERSION,
                "analysis_incomplete": True,
                "operational_error": True,
                "operational_error_reason": "numpy_read_failed",
                "scan_outcome_reason": "numpy_read_failed",
            },
        )
        _finish_with_inconclusive_contract(result, default_success=False)
        return result

    def _validate_array_dimensions(self, shape: tuple[int, ...]) -> None:
        """Validate array dimensions for security"""
        # Check number of dimensions
        if len(shape) > self.max_dimensions:
            raise ValueError(
                f"Too many dimensions: {len(shape)} (max: {self.max_dimensions})",
            )

        # Check individual dimension sizes
        for i, dim in enumerate(shape):
            if dim < 0:
                raise ValueError(f"Negative dimension at index {i}: {dim}")
            if dim > self.max_dimension_size:
                raise ValueError(
                    f"Dimension {i} too large: {dim} (max: {self.max_dimension_size})",
                )

    # CVE-2019-6446 constants
    CVE_2019_6446_ID = "CVE-2019-6446"
    CVE_2019_6446_CVSS = 9.8
    CVE_2019_6446_CWE = "CWE-502"

    def _scan_embedded_pickle_payload(
        self,
        file_obj: BinaryIO,
        payload_size: int,
        context_path: str,
    ) -> ScanResult:
        """Reuse PickleScanner analysis for object-dtype NumPy payloads."""
        if not self.scanner_selection.allows("pickle"):
            result = ScanResult(scanner_name="scanner_selection")
            result.bytes_scanned = payload_size
            add_scanner_selection_skip_check(
                result,
                context_path,
                "pickle",
                self.scanner_selection,
                context="embedded NumPy object pickle analysis",
            )
            if result.checks:
                result.checks[-1].details.update(
                    {
                        "analysis_incomplete": True,
                        "scan_outcome": INCONCLUSIVE_SCAN_OUTCOME,
                        "scan_outcome_reason": NUMPY_OBJECT_EMBEDDED_PICKLE_SELECTION_SKIP_REASON,
                    }
                )
            _mark_inconclusive_scan_result(result, NUMPY_OBJECT_EMBEDDED_PICKLE_SELECTION_SKIP_REASON)
            _finish_with_inconclusive_contract(result, default_success=False)
            return result

        pickle_scanner = PickleScanner(config=self.config)
        return pickle_scanner.scan_stream(
            file_obj,
            payload_size,
            source=context_path,
        )

    @staticmethod
    def _is_trailing_pickle_parse_noise(item: Check | Issue) -> bool:
        """Return True for parse diagnostics superseded by NumPy trailing-byte validation."""
        details = item.details or {}
        if details.get("analysis_incomplete") is not True:
            return False

        message = item.message.lower()
        return (
            "pickle parsing failed before full scan completion" in message
            or "pickle parsing stopped before the stream was fully consumed" in message
            or details.get("pickle_notice_code") == "parse_incomplete"
            or details.get("failure_reason") == "unknown_opcode_or_format_error"
        )

    @staticmethod
    def _remove_validated_numpy_object_reconstruction_findings(
        result: ScanResult,
        *,
        safe_numpy_reconstruct_payload: bool,
        validated_position_limit: int | None = None,
    ) -> None:
        def is_validated_numpy_object_reconstruction(item: Check | Issue) -> bool:
            if (
                item.rule_code != "NON_ALLOWLISTED_GLOBAL"
                or item.details.get("import_reference") not in _VALIDATED_NUMPY_OBJECT_DTYPE_RECONSTRUCTION_REFERENCES
            ):
                return False
            if validated_position_limit is not None:
                position = item.details.get("position")
                if not isinstance(position, int) or position >= validated_position_limit:
                    return False
            if (
                item.details.get("import_reference") in _VALIDATED_NUMPY_OBJECT_DTYPE_RECONSTRUCT_REFERENCES
                and not safe_numpy_reconstruct_payload
            ):
                return False
            module = item.details.get("module")
            name = item.details.get("name")
            if not isinstance(module, str) or not isinstance(name, str):
                return False
            return _numpy_object_reconstruction_reference_is_trusted(module, name)

        result.issues = [issue for issue in result.issues if not is_validated_numpy_object_reconstruction(issue)]
        result.checks = [check for check in result.checks if not is_validated_numpy_object_reconstruction(check)]

    def _validate_dtype(self, dtype: Any) -> None:
        """Validate numpy dtype for security"""
        # Check for problematic data types
        # CVE-2019-6446: object dtype requires pickle deserialization,
        # enabling arbitrary code execution via numpy.load(allow_pickle=True)
        # dtype.hasobject is True when the dtype contains Python objects
        # (including object arrays and structured dtypes with object fields).
        # Pure numeric structured dtypes (kind="V") are safe.
        if dtype.kind == "O" or bool(getattr(dtype, "hasobject", False)):
            raise ValueError(
                f"Dangerous dtype not allowed: {dtype.name} (kind: {dtype.kind})",
            )

        # Check for extremely large item sizes
        if dtype.itemsize > self.max_itemsize:
            raise ValueError(
                f"Itemsize too large: {dtype.itemsize} bytes (max: {self.max_itemsize})",
            )

    def _calculate_safe_array_size(self, shape: tuple[int, ...], dtype: Any) -> int:
        """Calculate array size with overflow protection"""
        total_elements = 1
        max_elements = sys.maxsize // max(dtype.itemsize, 1)

        for dim in shape:
            # Check for overflow before multiplication
            if total_elements > max_elements // max(dim, 1):
                raise ValueError(
                    f"Array size would overflow: shape={shape}, dtype={dtype}",
                )

            total_elements *= dim

        total_bytes = total_elements * dtype.itemsize

        if total_bytes > self.max_array_bytes:
            raise ValueError(
                f"Array too large: {total_bytes} bytes (max: {self.max_array_bytes}) for shape={shape}, dtype={dtype}",
            )

        return total_bytes

    def scan(self, path: str) -> ScanResult:
        # Check if NumPy and format module are available
        if not NUMPY_AVAILABLE:
            result = self._create_result()
            result.add_check(
                name="NumPy Library Check",
                passed=False,
                message="NumPy not available for scanning .npy files",
                severity=IssueSeverity.WARNING,
                location=path,
                rule_code=None,  # Library availability, no rule
                details={"numpy_version": NUMPY_VERSION},
            )
            result.finish(success=False)
            return result

        if not NUMPY_FORMAT_AVAILABLE:
            result = self._create_result()
            result.metadata["numpy_version"] = NUMPY_VERSION
            result.metadata["numpy_major_version"] = NUMPY_MAJOR_VERSION
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "numpy_format_module_unavailable"
            _mark_inconclusive_scan_result(result, "numpy_format_module_unavailable")
            result.add_check(
                name="NumPy Format Module Check",
                passed=False,
                message=f"NumPy format module not available (NumPy {NUMPY_VERSION}). May be a compatibility issue.",
                severity=IssueSeverity.INFO,
                location=path,
                rule_code=None,  # Library availability, no rule
                details={
                    "numpy_version": NUMPY_VERSION,
                    "numpy_major": NUMPY_MAJOR_VERSION,
                    "analysis_incomplete": True,
                    "scan_outcome": result.metadata["scan_outcome"],
                    "scan_outcome_reason": "numpy_format_module_unavailable",
                    "operational_error": True,
                    "operational_error_reason": "numpy_format_module_unavailable",
                },
            )
            _finish_with_inconclusive_contract(result, default_success=False)
            return result

        path_check_result = self._check_path(path)
        if path_check_result:
            if self._is_unreadable_path_result(path_check_result):
                return self._finish_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        result.metadata["numpy_version"] = NUMPY_VERSION
        result.metadata["numpy_major_version"] = NUMPY_MAJOR_VERSION

        try:
            self.current_file_path = path
            with warnings.catch_warnings():
                # Suppress NumPy warnings during scanning
                warnings.simplefilter("ignore")

                with open(path, "rb") as f:
                    # Verify magic string
                    magic = f.read(6)
                    if magic != b"\x93NUMPY":
                        result.add_check(
                            name="NumPy Magic String Validation",
                            passed=False,
                            message="Invalid NumPy file magic",
                            severity=IssueSeverity.INFO,
                            location=path,
                            rule_code="S903",  # Invalid magic bytes
                            details={"expected": "\x93NUMPY", "found": magic.hex()},
                        )
                        result.finish(success=False)
                        return result
                    else:
                        result.add_check(
                            name="NumPy Magic String Validation",
                            passed=True,
                            message="Valid NumPy file magic string found",
                            location=path,
                            rule_code=None,  # Passing check
                            details={"magic": magic.hex()},
                        )
                    f.seek(0)

                    # Use format module with version compatibility
                    try:
                        major, minor = fmt.read_magic(f)
                        shape, fortran, dtype = _read_numpy_array_header(f, (major, minor))
                    except OSError:
                        raise
                    except Exception as header_error:
                        result.add_check(
                            name="NumPy Header Read",
                            passed=False,
                            message=f"Failed to read NumPy array header: {header_error}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            rule_code="S902",  # Corrupted structure
                            details={"numpy_version": NUMPY_VERSION, "header_error": str(header_error)},
                        )
                        result.finish(success=False)
                        return result

                    data_offset = f.tell()

                    # Validate array dimensions and dtype for security
                    try:
                        self._validate_array_dimensions(shape)
                        result.add_check(
                            name="Array Dimension Validation",
                            passed=True,
                            message="Array dimensions are within safe limits",
                            location=path,
                            rule_code=None,  # Passing check
                            details={
                                "shape": shape,
                                "dimensions": len(shape),
                                "max_dimensions": self.max_dimensions,
                            },
                        )

                        # CVE-2019-6446: object dtype requires pickle
                        # deserialization via numpy.load(allow_pickle=True),
                        # enabling arbitrary code execution.
                        # dtype.hasobject catches structured dtypes with
                        # object fields; kind=="O" catches plain object arrays.
                        has_object_dtype = dtype.kind == "O" or bool(getattr(dtype, "hasobject", False))
                        if has_object_dtype:
                            result.add_check(
                                name=f"{self.CVE_2019_6446_ID}: Object Dtype Pickle Deserialization",
                                passed=False,
                                message=(
                                    f"{self.CVE_2019_6446_ID}: NumPy array "
                                    f"uses '{dtype}' dtype which requires "
                                    "pickle deserialization. This is a potential RCE vector "
                                    "when consumer code loads with allow_pickle=True."
                                ),
                                severity=IssueSeverity.INFO,
                                location=path,
                                details={
                                    "dtype": str(dtype),
                                    "dtype_kind": dtype.kind,
                                    "cve_id": self.CVE_2019_6446_ID,
                                    "cvss": self.CVE_2019_6446_CVSS,
                                    "cwe": self.CVE_2019_6446_CWE,
                                    "requires_allow_pickle_true": True,
                                    "description": (
                                        "NumPy object arrays use pickle for "
                                        "serialization. numpy.load() with "
                                        "allow_pickle=True deserializes "
                                        "arbitrary Python objects, enabling RCE."
                                    ),
                                    "remediation": (
                                        "Use NumPy >= 1.16.3 where "
                                        "allow_pickle defaults to False. "
                                        "Never set allow_pickle=True with "
                                        "untrusted .npy/.npz files. Use "
                                        "numeric dtypes instead of object."
                                    ),
                                },
                                why=(
                                    "This NumPy file contains an array with "
                                    f"'{dtype}' dtype that stores arbitrary "
                                    "Python objects via pickle. If consumer code "
                                    "loads this file with numpy.load(allow_pickle=True), "
                                    "it can execute embedded code "
                                    f"({self.CVE_2019_6446_ID}, CVSS 9.8)."
                                ),
                            )

                            f.seek(data_offset)
                            embedded_payload_proof = f.read(
                                min(
                                    file_size - data_offset,
                                    _NUMPY_OBJECT_SAFE_RECONSTRUCT_PROOF_MAX_BYTES + 1,
                                )
                            )
                            safe_numpy_reconstruct_payload = _numpy_object_payload_has_safe_reconstruct_proof(
                                embedded_payload_proof
                            )
                            f.seek(data_offset)
                            embedded_result = self._scan_embedded_pickle_payload(
                                f,
                                file_size - data_offset,
                                path,
                            )

                            pickle_end_offset = embedded_result.metadata.get("first_pickle_end_pos")
                            if isinstance(pickle_end_offset, int) and pickle_end_offset < file_size:
                                first_stream_safe_numpy_reconstruct_payload = False
                                if data_offset <= pickle_end_offset <= data_offset + len(embedded_payload_proof):
                                    first_stream_safe_numpy_reconstruct_payload = (
                                        _numpy_object_payload_has_safe_reconstruct_proof(
                                            embedded_payload_proof[: pickle_end_offset - data_offset]
                                        )
                                    )
                                trailing_bytes = file_size - pickle_end_offset
                                result.issues.extend(
                                    issue
                                    for issue in embedded_result.issues
                                    if not self._is_trailing_pickle_parse_noise(issue)
                                )
                                result.checks.extend(
                                    check
                                    for check in embedded_result.checks
                                    if not self._is_trailing_pickle_parse_noise(check)
                                )
                                self._remove_validated_numpy_object_reconstruction_findings(
                                    result,
                                    safe_numpy_reconstruct_payload=first_stream_safe_numpy_reconstruct_payload,
                                    validated_position_limit=pickle_end_offset,
                                )
                                result.add_check(
                                    name="File Integrity Check",
                                    passed=False,
                                    message=(
                                        "Object-dtype payload contains trailing bytes after the embedded pickle stream"
                                    ),
                                    severity=IssueSeverity.INFO,
                                    location=path,
                                    rule_code="S902",
                                    details={
                                        "expected_pickle_end": pickle_end_offset,
                                        "actual_size": file_size,
                                        "trailing_bytes": trailing_bytes,
                                        "dtype": str(dtype),
                                    },
                                )
                                _mark_inconclusive_scan_result(result, "numpy_object_pickle_trailing_bytes")
                                _finish_with_inconclusive_contract(result, default_success=False)
                                return result

                            result.issues.extend(embedded_result.issues)
                            result.checks.extend(embedded_result.checks)
                            self._remove_validated_numpy_object_reconstruction_findings(
                                result,
                                safe_numpy_reconstruct_payload=safe_numpy_reconstruct_payload,
                            )

                            # Object-dtype .npy payloads are stored as a pickle stream rather than
                            # fixed-width element data, so the numeric dtype/size validation path
                            # is not applicable after we recurse into the embedded pickle payload.
                            pickle_scan_skipped = embedded_result.scanner_name == "scanner_selection"
                            data_type_details: dict[str, Any] = {
                                "dtype": str(dtype),
                                "dtype_kind": dtype.kind,
                                "handled_via": (
                                    "scanner_selection_skip" if pickle_scan_skipped else "embedded_pickle_scan"
                                ),
                                "cve_id": self.CVE_2019_6446_ID,
                            }
                            if pickle_scan_skipped:
                                data_type_details.update(
                                    {
                                        "analysis_incomplete": True,
                                        "scan_outcome": INCONCLUSIVE_SCAN_OUTCOME,
                                        "scan_outcome_reason": NUMPY_OBJECT_EMBEDDED_PICKLE_SELECTION_SKIP_REASON,
                                    }
                                )
                            result.add_check(
                                name="Data Type Safety Check",
                                passed=True,
                                message=(
                                    f"Object dtype '{dtype}' embedded pickle analysis skipped by scanner selection"
                                    if pickle_scan_skipped
                                    else f"Object dtype '{dtype}' handled via recursive pickle analysis"
                                ),
                                location=path,
                                rule_code=None,
                                details=data_type_details,
                            )
                            result.bytes_scanned = file_size
                            result.metadata.update(
                                embedded_result.metadata,
                            )
                            result.metadata.update(
                                {
                                    "shape": shape,
                                    "dtype": str(dtype),
                                    "fortran_order": fortran,
                                    "embedded_pickle_scan_success": embedded_result.success,
                                },
                            )
                            if (
                                result.metadata.get("analysis_incomplete") is True
                                or result.metadata.get("operational_error") is True
                                or result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
                            ):
                                _mark_inconclusive_scan_result(
                                    result,
                                    "numpy_object_embedded_pickle_incomplete",
                                )
                                _finish_with_inconclusive_contract(result, default_success=False)
                            else:
                                result.finish(success=not result.has_errors and not result.has_warnings)
                            return result

                        self._validate_dtype(dtype)
                        result.add_check(
                            name="Data Type Safety Check",
                            passed=True,
                            message=f"Data type '{dtype}' is safe",
                            location=path,
                            rule_code=None,  # Passing check
                            details={
                                "dtype": str(dtype),
                                "dtype_kind": dtype.kind,
                                "itemsize": dtype.itemsize,
                            },
                        )

                        expected_data_size = self._calculate_safe_array_size(shape, dtype)
                        result.add_check(
                            name="Array Size Validation",
                            passed=True,
                            message="Array size is within safe limits",
                            location=path,
                            rule_code=None,  # Passing check
                            details={
                                "calculated_size": expected_data_size,
                                "max_size": self.max_array_bytes,
                                "shape": shape,
                                "dtype": str(dtype),
                            },
                        )
                        expected_size = data_offset + expected_data_size
                    except ValueError as e:
                        # Determine which validation failed based on error message
                        error_msg = str(e).lower()
                        if "dimensions" in error_msg:
                            check_name = "Array Dimension Validation"
                        elif "dtype" in error_msg:
                            check_name = "Data Type Safety Check"
                        else:
                            check_name = "Array Size Validation"

                        # Determine rule code based on validation failure type.
                        validation_rule = None
                        error_msg = str(e).lower()
                        if "dimension" in error_msg or "excessive" in error_msg:
                            validation_rule = "S804"  # Excessive dimensions
                        elif "size" in error_msg:
                            validation_rule = "S904"  # Excessive file size
                        elif "dtype" in error_msg or "object" in error_msg:
                            validation_rule = "S213"  # Pickle/serialization risk
                        else:
                            validation_rule = "S902"  # Generic structural corruption

                        # Size/dimension limit errors are informational - they may indicate
                        # large legitimate arrays as well as malformed content.
                        result.add_check(
                            name=check_name,
                            passed=False,
                            message=f"Array validation failed: {e}",
                            severity=IssueSeverity.INFO,
                            location=path,
                            rule_code=validation_rule,
                            details={
                                "security_check": "array_validation",
                                "shape": shape,
                                "dtype": str(dtype),
                                "error": str(e),
                            },
                        )
                        result.finish(success=False)
                        return result

                    if file_size != expected_size:
                        result.add_check(
                            name="File Integrity Check",
                            passed=False,
                            message="File size does not match header information",
                            severity=IssueSeverity.INFO,
                            location=path,
                            rule_code="S902",  # Corrupted structure
                            details={
                                "expected_size": expected_size,
                                "actual_size": file_size,
                                "shape": shape,
                                "dtype": str(dtype),
                            },
                        )
                        result.finish(success=False)
                        return result
                    else:
                        result.add_check(
                            name="File Integrity Check",
                            passed=True,
                            message="File size matches header information",
                            location=path,
                            rule_code=None,  # Passing check
                            details={
                                "file_size": file_size,
                                "shape": shape,
                                "dtype": str(dtype),
                            },
                        )

                    result.bytes_scanned = file_size
                    result.metadata.update(
                        {"shape": shape, "dtype": str(dtype), "fortran_order": fortran},
                    )
        except OSError as e:
            return self._finish_read_failure(result, path, e)
        except Exception as e:  # pragma: no cover - unexpected errors
            result.add_check(
                name="NumPy File Scan",
                passed=False,
                message=f"Error scanning NumPy file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                rule_code="S902",  # Scan error/corruption
                details={"exception": str(e), "exception_type": type(e).__name__, "numpy_version": NUMPY_VERSION},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract NumPy array metadata without deserializing object arrays."""
        metadata = super().extract_metadata(file_path)

        try:
            import numpy as np

            with open(file_path, "rb") as handle:
                major, minor = fmt.read_magic(handle)
                shape, fortran_order, dtype = _read_numpy_array_header(handle, (major, minor))

                array_size = 1
                for dim in shape:
                    array_size *= int(dim)
                array_nbytes = array_size * int(dtype.itemsize)

                metadata.update(
                    {
                        "numpy_version": np.__version__,
                        "array_shape": list(shape),
                        "array_dtype": str(dtype),
                        "array_size": array_size,
                        "array_nbytes": array_nbytes,
                        "array_ndim": len(shape),
                        "memory_usage_mb": array_nbytes / (1024 * 1024),
                    }
                )

                has_object_dtype = dtype.kind == "O" or bool(getattr(dtype, "hasobject", False))
                if has_object_dtype:
                    metadata["contains_objects"] = True
                    metadata["security_note"] = "Object arrays may contain arbitrary Python objects"
                    metadata["deserialization_skipped"] = True
                    metadata["reason"] = "File contains object arrays requiring unsafe pickle deserialization"
                    if self.config.get("allow_metadata_deserialization"):
                        metadata["allow_metadata_deserialization_ignored"] = True
                    return metadata

                metadata["contains_objects"] = False
                if dtype.kind in ["U", "S"]:
                    metadata["contains_strings"] = True

                data_offset = handle.tell()
                handle.seek(0, io.SEEK_END)
                actual_file_size = handle.tell()
                expected_file_size = data_offset + array_nbytes
                if actual_file_size < expected_file_size:
                    available_bytes = max(0, actual_file_size - data_offset)
                    raise ValueError(
                        f"NumPy array data is truncated: expected {array_nbytes} bytes, found {available_bytes}",
                    )
                handle.seek(data_offset)

                if array_size > 0:
                    if array_nbytes < 10 * 1024 * 1024 and np.issubdtype(dtype, np.number):
                        payload = handle.read(array_nbytes)
                        if len(payload) != array_nbytes:
                            raise ValueError(
                                f"NumPy array data is truncated: expected {array_nbytes} bytes, found {len(payload)}",
                            )
                        try:
                            array = np.frombuffer(payload, dtype=dtype, count=array_size).reshape(
                                shape,
                                order="F" if fortran_order else "C",
                            )
                            metadata.update(
                                {
                                    "min_value": float(np.min(array)),
                                    "max_value": float(np.max(array)),
                                    "mean_value": float(np.mean(array)),
                                    "std_value": float(np.std(array)),
                                }
                            )
                        except Exception:
                            pass  # Skip optional statistics if the numeric operation is unsupported
                    elif array_nbytes >= 10 * 1024 * 1024:
                        metadata["large_array_stats"] = "Skipped statistics for large array"

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
