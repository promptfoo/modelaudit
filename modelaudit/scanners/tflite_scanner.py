"""Scanner for TensorFlow Lite model files (.tflite)."""

import mmap
import os
from typing import Any, ClassVar

from ..scanner_results import mark_inconclusive_scan_result
from .base import BaseScanner, IssueSeverity, ScanResult


def _memory_map(path: str, file_size: int) -> Any:
    """Memory-map a TFLite file read-only for zero-copy FlatBuffer parsing.

    ``GetRootAsModel`` indexes into the buffer lazily without copying it, so an
    mmap keeps resident memory bounded to the pages actually touched during
    traversal instead of loading the whole (potentially multi-GB) file into RAM.
    The caller — and the parsed model, which references the buffer — keeps the
    mapping alive for the scan's duration. Empty files return ``b""`` because
    ``mmap`` rejects a zero-length mapping.

    ``file_size`` is the size the caller already validated against the configured
    read limit. We re-``fstat`` the opened descriptor and map only
    ``min(file_size, current_size)`` rather than the whole file: if the file grew
    after the caller's check we must not map past the validated size (a TOCTOU
    bypass of the limit that the previous chunked read caught), and if it shrank
    we must not map past EOF.
    """
    if file_size <= 0:
        return b""
    with open(path, "rb") as f:
        # The mapping outlives the file descriptor (POSIX), so closing f is fine.
        length = min(file_size, os.fstat(f.fileno()).st_size)
        if length <= 0:
            return b""
        return mmap.mmap(f.fileno(), length, access=mmap.ACCESS_READ)


try:
    import tflite

    HAS_TFLITE = True
except Exception:  # pragma: no cover - optional dependency
    HAS_TFLITE = False

_MAX_COUNT = 100000  # Guardrail for excessive tensor/operator/subgraph counts
_MAX_DIM = 10_000_000  # Guardrail for pathological tensor dimensions
_TFLITE_MAGIC_OFFSET = 4
_TFLITE_MAGIC_SIZE = 4
_TFLITE_MIN_HEADER_SIZE = _TFLITE_MAGIC_OFFSET + _TFLITE_MAGIC_SIZE
_TFLITE_MAGIC_BYTES = b"TFL3"
_CONTENT_ROUTE_BLOCKED_EXTENSIONS = frozenset(
    {
        ".bin",
        ".cmf",
        ".dnn",
        ".exe",
        ".lgb",
        ".lightgbm",
        ".llamafile",
        ".meta",
        ".model",
        ".net",
        ".pb",
        ".rknn",
        ".t7",
        ".th",
    }
)
TFLITE_MAGIC_INCONCLUSIVE_REASON = "tflite_magic_validation_failed"
TFLITE_PARSE_INCONCLUSIVE_REASON = "tflite_parse_incomplete"
TFLITE_STRUCTURE_INCONCLUSIVE_REASON = "tflite_structure_validation_failed"
TFLITE_DEPENDENCY_INCONCLUSIVE_REASON = "tflite_dependency_unavailable"
TFLITE_READ_INCONCLUSIVE_REASON = "tflite_read_failed"


def _has_tflite_magic_bytes(data: bytes) -> bool:
    return (
        len(data) >= _TFLITE_MIN_HEADER_SIZE
        and data[_TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + _TFLITE_MAGIC_SIZE] == _TFLITE_MAGIC_BYTES
    )


def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
    mark_inconclusive_scan_result(result, reason)


def _mark_operational_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
    _mark_inconclusive_scan_result(result, reason)
    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = reason


class TFLiteScanner(BaseScanner):
    """Scanner for TensorFlow Lite model files."""

    name = "tflite"
    description = "Scans TensorFlow Lite models for integrity and safety issues"
    supported_extensions: ClassVar[list[str]] = [".tflite"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            return True
        if ext in _CONTENT_ROUTE_BLOCKED_EXTENSIONS:
            return False

        try:
            with open(path, "rb") as f:
                header = f.read(_TFLITE_MIN_HEADER_SIZE)
        except OSError:
            return False

        return _has_tflite_magic_bytes(header)

    def scan(self, path: str) -> ScanResult:
        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result

        result.metadata["file_size"] = self.get_file_size(path)

        if not HAS_TFLITE:
            _mark_operational_inconclusive_scan_result(result, TFLITE_DEPENDENCY_INCONCLUSIVE_REASON)
            result.add_check(
                name="TFLite Library Check",
                passed=False,
                message="tflite package not installed. Install with 'pip install modelaudit[tflite]'",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "required_package": "tflite",
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "scan_outcome_reason": TFLITE_DEPENDENCY_INCONCLUSIVE_REASON,
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        try:
            file_size = self.get_file_size(path)
            max_read = self.max_file_read_size
            if max_read and max_read > 0 and file_size > max_read:
                raise ValueError(f"File too large: {file_size} bytes (max: {max_read})")
            data = _memory_map(path, file_size)
        except (OSError, ValueError) as e:
            _mark_operational_inconclusive_scan_result(result, TFLITE_READ_INCONCLUSIVE_REASON)
            result.add_check(
                name="TFLite File Read",
                passed=False,
                message=f"Unable to read TFLite file for analysis: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "scan_outcome_reason": TFLITE_READ_INCONCLUSIVE_REASON,
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        result.bytes_scanned = len(data)

        # Check for TFLite magic bytes "TFL3" at offset 4.
        if not _has_tflite_magic_bytes(data):
            _mark_inconclusive_scan_result(result, TFLITE_MAGIC_INCONCLUSIVE_REASON)
            result.add_check(
                name="TFLite Magic Bytes Check",
                passed=False,
                message="File does not have valid TFLite magic bytes (expected 'TFL3' at offset 4)",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "magic_bytes_at_offset_4": data[
                        _TFLITE_MAGIC_OFFSET : _TFLITE_MAGIC_OFFSET + _TFLITE_MAGIC_SIZE
                    ].hex()
                    if len(data) >= _TFLITE_MIN_HEADER_SIZE
                    else "file_too_short"
                },
                why="Valid TFLite files use FlatBuffer format with 'TFL3' identifier at bytes 4-7. "
                "Missing or incorrect identifier may indicate file corruption or spoofing.",
            )
            result.finish(success=False)
            return result

        try:
            model = tflite.Model.GetRootAsModel(data, 0)
        except Exception as e:  # pragma: no cover - parse errors
            _mark_inconclusive_scan_result(result, TFLITE_PARSE_INCONCLUSIVE_REASON)
            result.add_check(
                name="TFLite File Parse",
                passed=False,
                message=f"Invalid TFLite file or parse error: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        try:
            subgraph_count = model.SubgraphsLength()
            result.metadata["subgraph_count"] = subgraph_count
            if subgraph_count > _MAX_COUNT:
                result.add_check(
                    name="Subgraph Count Validation",
                    passed=False,
                    message=f"Model declares {subgraph_count} subgraphs which exceeds the safe limit",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"subgraph_count": subgraph_count, "max_allowed": _MAX_COUNT},
                    rule_code="S902",
                )
                result.finish(success=False)
                return result

            for sg_index in range(subgraph_count):
                subgraph = model.Subgraphs(sg_index)
                tensors_len = subgraph.TensorsLength()
                operators_len = subgraph.OperatorsLength()
                result.metadata.setdefault("tensor_counts", []).append(tensors_len)
                result.metadata.setdefault("operator_counts", []).append(operators_len)

                if tensors_len > _MAX_COUNT or operators_len > _MAX_COUNT:
                    result.add_check(
                        name="Tensor/Operator Count Validation",
                        passed=False,
                        message="TFLite model has extremely large tensor or operator count",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"tensors": tensors_len, "operators": operators_len, "max_allowed": _MAX_COUNT},
                        rule_code="S902",
                    )
                    continue

                for t_index in range(tensors_len):
                    tensor = subgraph.Tensors(t_index)
                    shape = [tensor.Shape(i) for i in range(tensor.ShapeLength())]
                    if any(dim > _MAX_DIM for dim in shape):
                        result.add_check(
                            name="Tensor Dimension Validation",
                            passed=False,
                            message="Tensor dimension extremely large (possible overflow)",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path} (tensor {t_index})",
                            details={"tensor_index": t_index, "shape": shape, "max_allowed_dim": _MAX_DIM},
                            rule_code="S703",
                        )
                for o_index in range(operators_len):
                    op = subgraph.Operators(o_index)
                    opcode = model.OperatorCodes(op.OpcodeIndex())
                    builtin = opcode.BuiltinCode()
                    if builtin == tflite.BuiltinOperator.CUSTOM:
                        custom = opcode.CustomCode()
                        name = custom.decode("utf-8", "ignore") if custom else "unknown"
                        result.add_check(
                            name="Custom Operator Detection",
                            passed=False,
                            message=f"Model uses custom operator '{name}'",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path} (operator {o_index})",
                            rule_code="S302",
                            details={"operator_name": name, "operator_index": o_index},
                        )
        except Exception as e:  # pragma: no cover - malformed structure traversal
            _mark_inconclusive_scan_result(result, TFLITE_STRUCTURE_INCONCLUSIVE_REASON)
            result.add_check(
                name="TFLite Model Structure Parse",
                passed=False,
                message=f"Invalid TFLite model structure or traversal error: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
                why=(
                    "Malformed TFLite FlatBuffer tables can raise parser exceptions during subgraph/operator traversal."
                ),
            )
            result.finish(success=False)
            return result

        result.finish(success=not result.has_errors)
        return result

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract TensorFlow Lite metadata."""
        metadata = super().extract_metadata(file_path)

        if not HAS_TFLITE:
            metadata["error"] = "TensorFlow Lite library not available"
            return metadata

        try:
            import tflite

            # Limit file read to avoid OOM on very large files
            max_size = 2 * 1024 * 1024 * 1024  # 2GB
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                metadata["error"] = f"File too large for metadata extraction ({file_size} bytes)"
                return metadata

            # Zero-copy mmap: GetRootAsModel indexes into the buffer lazily, so
            # this avoids loading the whole file into RAM (bounded already by the
            # 2GB guard above, but mmap keeps actual RSS far lower).
            model_data = _memory_map(file_path, file_size)

            model = tflite.Model.GetRootAsModel(model_data, 0)

            # Basic model info
            metadata.update(
                {
                    "tflite_version": model.Version(),
                    "model_description": model.Description().decode("utf-8") if model.Description() else None,
                    "subgraph_count": model.SubgraphsLength(),
                    "operator_codes_count": model.OperatorCodesLength(),
                }
            )

            if metadata["subgraph_count"] > _MAX_COUNT:
                metadata["extraction_error"] = (
                    f"Model declares {metadata['subgraph_count']} subgraphs which exceeds the safe limit"
                )
                return metadata

            # Analyze subgraphs
            if model.SubgraphsLength() > 0:
                subgraph = model.Subgraphs(0)  # Main subgraph

                metadata.update(
                    {
                        "tensors_count": subgraph.TensorsLength(),
                        "operators_count": subgraph.OperatorsLength(),
                        "inputs_count": subgraph.InputsLength(),
                        "outputs_count": subgraph.OutputsLength(),
                    }
                )

                # Get input/output tensor info
                inputs = []
                outputs = []

                for i in range(subgraph.InputsLength()):
                    tensor_idx = subgraph.Inputs(i)
                    tensor = subgraph.Tensors(tensor_idx)
                    inputs.append(
                        {
                            "name": tensor.Name().decode("utf-8") if tensor.Name() else f"input_{i}",
                            "shape": [tensor.Shape(j) for j in range(tensor.ShapeLength())],
                            "type": tensor.Type(),
                        }
                    )

                for i in range(subgraph.OutputsLength()):
                    tensor_idx = subgraph.Outputs(i)
                    tensor = subgraph.Tensors(tensor_idx)
                    outputs.append(
                        {
                            "name": tensor.Name().decode("utf-8") if tensor.Name() else f"output_{i}",
                            "shape": [tensor.Shape(j) for j in range(tensor.ShapeLength())],
                            "type": tensor.Type(),
                        }
                    )

                metadata.update(
                    {
                        "inputs": inputs,
                        "outputs": outputs,
                    }
                )

                # Analyze operators
                operator_types = []
                custom_operators = []

                for i in range(subgraph.OperatorsLength()):
                    op = subgraph.Operators(i)
                    opcode = model.OperatorCodes(op.OpcodeIndex())
                    builtin = opcode.BuiltinCode()

                    if builtin == tflite.BuiltinOperator.CUSTOM:
                        custom = opcode.CustomCode()
                        name = custom.decode("utf-8", "ignore") if custom else "unknown"
                        custom_operators.append(name)
                    else:
                        operator_types.append(builtin)

                metadata.update(
                    {
                        "operator_types": list(set(operator_types)),
                        "custom_operators": custom_operators,
                        "has_custom_operators": len(custom_operators) > 0,
                    }
                )

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
