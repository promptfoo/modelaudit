"""Scanner for ONNX model files (.onnx)."""

import hashlib
import logging
import math
import ntpath
import numbers
import os
import re
import stat
from collections.abc import Callable, Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, NoReturn

from ..scanner_results import SUPPRESSED_FAILED_CHECKS_METADATA_KEY, VALIDATED_FORMAT_METADATA_KEY
from ..utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from ._evidence_redaction import redact_untrusted_error_message
from .base import (
    FORMAT_VALIDATION_CONFIG_KEY,
    INCONCLUSIVE_SCAN_OUTCOME,
    BaseScanner,
    CheckStatus,
    IssueSeverity,
    ScanResult,
)

logger = logging.getLogger("modelaudit.scanners")


def _is_contained_in(child: Path, parent: Path) -> bool:
    """Return True when child resolves under parent directory."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _get_onnx_mapping() -> Any:
    """Get ONNX mapping module from different locations depending on version."""
    try:
        # Try ONNX 1.12+ location
        import onnx

        if hasattr(onnx, "mapping"):
            return onnx.mapping
        if hasattr(onnx, "_mapping"):
            return onnx._mapping
    except (ImportError, AttributeError):
        logger.debug("ONNX mapping module is unavailable in the installed onnx package", exc_info=True)

    try:
        # Try older ONNX location
        from onnx.onnx_cpp2py_export import mapping as mapping_export  # type: ignore[attr-defined]

        return mapping_export
    except (ImportError, AttributeError):
        logger.debug("Legacy ONNX mapping export is unavailable", exc_info=True)

    return None


# Defer ONNX availability check to avoid module-level imports
HAS_ONNX: bool | None = None
mapping = None
STANDARD_ONNX_DOMAINS: frozenset[str] = frozenset(
    {
        "",
        "ai.onnx",
        "ai.onnx.ml",
        "ai.onnx.preview.training",
    }
)
SCHEMA_VALIDATED_ONNX_DOMAINS: frozenset[str] = frozenset({"ai.onnx.preview"})
_AMBIGUOUS_ONNX_OPSET_VERSION = -1
_LOW_NOISE_ONNX_RUNTIME_OPERATORS: dict[str, dict[str, frozenset[int]]] = {
    # ONNX Runtime optimization passes commonly emit these contrib kernels in
    # public transformer exports. Suppress S1111 only for exact domain/operator
    # tuples with an imported supported opset and empty overload; unknown vendor
    # operators remain custom-domain findings.
    "com.microsoft": {
        "FastGelu": frozenset({1}),
        "SkipLayerNormalization": frozenset({1}),
    },
}
ONNX_STRUCTURE_INCONCLUSIVE_REASON = "onnx_structure_validation_failed"
ONNX_SCHEMA_INCONCLUSIVE_REASON = "onnx_schema_validation_failed"
ONNX_RAW_DETECTION_INCONCLUSIVE_REASON = "onnx_raw_detection_analysis_incomplete"
ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON = "onnx_weight_distribution_analysis_incomplete"
ONNX_RESULT_REPORTING_INCONCLUSIVE_REASON = "onnx_result_reporting_incomplete"
ONNX_DEPENDENCY_UNAVAILABLE_REASON = "onnx_dependency_unavailable"
ONNX_TENTATIVE_CANDIDATE_UNAVAILABLE_REASON = "onnx_tentative_candidate_analysis_unavailable"
ONNX_TENTATIVE_CANDIDATE_PARSE_INCOMPLETE_REASON = "onnx_tentative_candidate_parse_incomplete"
_ONNX_FORMAT_INTEGRITY_CHECK_NAMES: frozenset[str] = frozenset(
    {
        "ONNX Structure Validation",
        "ONNX Schema Validation",
        "Tensor Size Validation",
        "Tensor Validation",
        "External Data Size Validation",
    }
)
_PYTHON_OPERATOR_TYPES: frozenset[str] = frozenset(
    {
        "pyfunc",
        "pyfuncstateless",
        "eagerpyfunc",
        "python",
        "pythonop",
    }
)
_PYTHON_OPERATOR_PATTERN = re.compile(
    r"^(?:pyfunc(?:stateless)?|eagerpyfunc|python(?:op)?)(?:v[0-9]+)?$",
    re.IGNORECASE,
)
_OP_TYPE_TOKEN_PATTERN = re.compile(
    r"[A-Z]+(?=[A-Z][a-z0-9]|[^A-Za-z0-9]|$)|[A-Z]?[a-z0-9]+",
)
_ONNX_WEIGHT_METADATA_SAMPLE_LIMIT = 100
_ONNX_WEIGHT_CONSUMER_SAMPLE_LIMIT = 20
_ONNX_WEIGHT_ANALYSIS_GROUP_LIMIT = 100
_ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT = 32
_ONNX_WEIGHT_LINEAGE_GAP_COUNT_LIMIT = 1_000_000
_ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT = 32
_ONNX_WEIGHT_RESHAPE_RANK_LIMIT = 64
_ONNX_RUNTIME_BOOKKEEPING_LINEAGE_REASONS: frozenset[str] = frozenset(
    {"dynamic_activation_lineage", "dynamic_input_lineage"}
)
_ONNX_WEIGHT_METADATA_TEXT_LIMIT = 256
_ONNX_WEIGHT_METADATA_SEQUENCE_LIMIT = 64
_ONNX_CUSTOM_OPERATOR_REPRESENTATIVE_LIMIT = 5
_ONNX_CUSTOM_OPERATOR_SAMPLE_LIMIT = 20
_ONNX_CUSTOM_OPERATOR_TEXT_LIMIT = 256
_ONNX_WEIGHT_DEFAULT_MAX_ARRAY_SIZE = 100 * 1024 * 1024
_ONNX_RAW_DETECTOR_DEFAULT_MAX_BYTES = 512 * 1024 * 1024
_ONNX_NETWORK_TEXT_MAX_BYTES = 4 * 1024 * 1024
_ONNX_NETWORK_TEXT_MAX_FIELDS = 100_000
_ONNX_METADATA_DETECTOR_SECTION_MAX_ENTRIES = 1024
_ONNX_METADATA_PROP_LABEL_PATTERN = re.compile(
    r"^(?P<prefix>.+\.metadata_props)\[(?P<index>[0-9]+)\]\.(?P<field>key|value)$"
)
_ONNX_RAW_OR_NUMERIC_TENSOR_PAYLOAD_FIELD_NAMES: frozenset[str] = frozenset(
    {
        # TensorProto.string_data is semantic model data and stays in the
        # bounded network-text path; only raw bytes and numeric payloads skip it.
        "raw_data",
        "float_data",
        "int32_data",
        "int64_data",
        "double_data",
        "uint64_data",
    }
)
_ONNX_STRUCTURE_STRING_MAX_BYTES = 1024 * 1024
_ONNX_STRUCTURE_MAX_DEPTH = 128
_ONNX_STRUCTURE_MAX_NODES = 1_000_000
_ONNX_STRUCTURE_MAX_TENSORS = 1_000_000
_ONNX_STRUCTURE_MAX_GRAPHS = 100_000
_ONNX_STRUCTURE_MAX_TENSOR_RANK = 4096
_ONNX_STRUCTURE_MAX_SEQUENCE_VALUES = 1_000_000
_ONNX_STRUCTURE_MAX_NODE_ATTRIBUTES = 4096
_ONNX_STRUCTURE_MAX_EXTERNAL_DATA_ENTRIES = 1024
_ONNX_STRUCTURE_MAX_STRING_DATA_FIELDS = 100_000
_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES = 100_000
_ONNX_STRUCTURE_MAX_FIELD_NUMBER = (1 << 29) - 1
_ONNX_STRUCTURE_MAX_PARSE_STEPS = 5_000_000
_ONNX_STRUCTURE_MAX_UNKNOWN_FIELD_SAMPLES = 20
_ONNX_STRUCTURE_MAX_RETAINED_OBJECTS = 1_000_000
_ONNX_STRUCTURE_MAX_RETAINED_SEQUENCE_ENTRIES = 1_000_000
_ONNX_STRUCTURE_MAX_RETAINED_STRING_BYTES = 64 * 1024 * 1024
_ONNX_STRUCTURE_MAX_RETAINED_ALLOCATION_BYTES = 128 * 1024 * 1024
_ONNX_STRUCTURE_RETAINED_OBJECT_BYTES = 1024
_ONNX_STRUCTURE_RETAINED_SEQUENCE_ENTRY_BYTES = 64
_ONNX_STRUCTURE_RETAINED_STRING_OVERHEAD_BYTES = 64
_ONNX_SEMANTIC_FINGERPRINT_MAX_SERIALIZED_BYTES = _ONNX_STRUCTURE_STRING_MAX_BYTES
_ONNX_REENTRY_ANALYSIS_MAX_GRAPH_OUTPUTS = 1024
_ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK = 4096
_ONNX_RESULT_MAX_DISTINCT_GROUPS = 1024
_STANDARD_NEURAL_NETWORK_DOMAINS: frozenset[str] = frozenset({"", "ai.onnx"})
_SAME_TYPE_ELEMENTWISE_OPERATORS: frozenset[str] = frozenset(
    {
        "Add",
        "Div",
        "Max",
        "Mean",
        "Min",
        "Mod",
        "Mul",
        "PRelu",
        "Sub",
        "Sum",
        "Where",
    }
)
_SAME_TYPE_UNARY_ELEMENTWISE_OPERATORS: frozenset[str] = frozenset(
    {
        "Abs",
        "Acos",
        "Acosh",
        "Asin",
        "Asinh",
        "Atan",
        "Atanh",
        "BitwiseNot",
        "Ceil",
        "Celu",
        "Cos",
        "Cosh",
        "Elu",
        "Erf",
        "Exp",
        "Floor",
        "Gelu",
        "HardSigmoid",
        "HardSwish",
        "Hardmax",
        "LeakyRelu",
        "Log",
        "LogSoftmax",
        "LpNormalization",
        "Mish",
        "Neg",
        "Not",
        "Reciprocal",
        "Relu",
        "Round",
        "Selu",
        "Sigmoid",
        "Sign",
        "Sin",
        "Sinh",
        "Softplus",
        "Softmax",
        "Softsign",
        "Sqrt",
        "Shrink",
        "Swish",
        "Tan",
        "Tanh",
        "ThresholdedRelu",
    }
)
_SHAPE_PRESERVING_UNARY_RANK_OPERATORS: frozenset[str] = _SAME_TYPE_UNARY_ELEMENTWISE_OPERATORS | frozenset(
    {
        "Clip",
        "Dropout",
    }
)
_RANK_PRESERVING_VARIADIC_OPERATORS: frozenset[str] = frozenset({"Concat"})
_RANK_GAP_PROMOTING_OPERATORS: frozenset[str] = frozenset(
    {
        "Expand",
        "Flatten",
        "Gather",
        "GatherND",
        "Reshape",
        "Squeeze",
        "Unsqueeze",
    }
)
_QUANTIZED_WEIGHT_OPERATORS: frozenset[str] = frozenset(
    {
        "ConvInteger",
        "DequantizeLinear",
        "DynamicQuantizeLinear",
        "MatMulInteger",
        "QLinearConv",
        "QLinearMatMul",
        "QuantizeLinear",
    },
)
_RECURRENT_WEIGHT_OPERATORS: frozenset[str] = frozenset({"GRU", "LSTM", "RNN"})


def resolve_onnx_raw_detector_max_bytes(config: dict[str, Any] | None = None) -> int:
    """Resolve the shared ONNX whole-file read and hash threshold."""
    value = (config or {}).get("onnx_raw_detector_max_bytes")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return _ONNX_RAW_DETECTOR_DEFAULT_MAX_BYTES
    return value


def _check_onnx() -> bool:
    """Check if ONNX is available, with caching."""
    global HAS_ONNX, mapping
    if HAS_ONNX is None:
        try:
            import numpy as np  # noqa: F401
            import onnx  # noqa: F401

            mapping = _get_onnx_mapping()
            HAS_ONNX = True
        except Exception:
            HAS_ONNX = False
            mapping = None
    return HAS_ONNX


def _is_python_operator(op_type: str) -> bool:
    """Return True for known Python-backed ONNX operator names."""
    normalized_op_type = "".join(char.lower() for char in op_type if char.isalnum())
    if normalized_op_type in _PYTHON_OPERATOR_TYPES or _PYTHON_OPERATOR_PATTERN.fullmatch(normalized_op_type):
        return True

    tokens = [token.lower() for token in _OP_TYPE_TOKEN_PATTERN.findall(op_type)]
    for index, token in enumerate(tokens):
        next_token = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token == "python" and next_token in {"op", "func"}:
            return True
        if token == "py" and next_token in {"op", "func"}:
            return True
    return False


def _onnx_int_attribute(node: Any, name: str, default: int = 0) -> int:
    """Read an integer ONNX node attribute without importing ONNX eagerly."""
    for attribute in getattr(node, "attribute", []):
        if attribute.name == name:
            return int(attribute.i)
    return default


def _onnx_int_sequence_attribute(node: Any, name: str) -> tuple[int, ...] | None:
    """Read an integer-list ONNX node attribute without importing ONNX eagerly."""
    for attribute in getattr(node, "attribute", []):
        if attribute.name == name:
            return tuple(int(value) for value in attribute.ints)
    return None


def _onnx_concat_output_shape(
    node: Any,
    input_shapes: Iterable[tuple[int, ...] | None],
    *,
    axis: int | None = None,
) -> tuple[int, ...] | None:
    shapes = list(input_shapes)
    if not shapes or any(shape is None for shape in shapes):
        return None
    concrete_shapes = [shape for shape in shapes if shape is not None]
    ranks = {len(shape) for shape in concrete_shapes}
    if len(ranks) != 1:
        return None
    rank = next(iter(ranks))
    axis = _onnx_int_attribute(node, "axis", 0) if axis is None else axis
    axis = axis if axis >= 0 else rank + axis
    if axis < 0 or axis >= rank:
        return None
    output_dimensions = list(concrete_shapes[0])
    for shape in concrete_shapes[1:]:
        for index, dimension in enumerate(shape):
            current = output_dimensions[index]
            if index == axis:
                output_dimensions[index] = -1 if current < 0 or dimension < 0 else current + dimension
            elif current < 0 or dimension < 0:
                output_dimensions[index] = -1
            elif dimension != current:
                return None
    return tuple(output_dimensions)


def _onnx_text_attribute(node: Any, name: str) -> str | None:
    """Read a UTF-8 ONNX string attribute without importing ONNX eagerly."""
    for attribute in getattr(node, "attribute", []):
        if attribute.name != name:
            continue
        try:
            return bytes(attribute.s).decode("utf-8")
        except (AttributeError, UnicodeDecodeError):
            return None
    return None


def _onnx_gather_axis(node: Any, rank: int) -> int | None:
    axis = _onnx_int_attribute(node, "axis")
    axis = axis if axis >= 0 else rank + axis
    return axis if 0 <= axis < rank else None


def _onnx_weight_output_axes(node: Any, input_index: int, rank: int) -> tuple[tuple[int, ...] | None, str]:
    """Classify an initializer consumer for statistical weight analysis."""
    op_type = node.op_type
    domain = getattr(node, "domain", "")
    if domain not in _STANDARD_NEURAL_NETWORK_DOMAINS:
        return None, "custom_domain_consumer"

    if op_type == "Gemm":
        if input_index not in {0, 1}:
            return None, "non_weight_input"
        if rank != 2:
            return None, "unsupported_weight_rank"
        if input_index == 0:
            return (1 if _onnx_int_attribute(node, "transA") else 0,), "eligible_gemm_left_weight"
        return (0 if _onnx_int_attribute(node, "transB") else 1,), "eligible_gemm_weight"

    if op_type == "MatMul":
        if input_index not in {0, 1}:
            return None, "non_weight_input"
        if rank < 2:
            return None, "unsupported_weight_rank"
        batch_axes = tuple(range(rank - 2))
        if input_index == 0:
            return (*batch_axes, rank - 2), "eligible_matmul_left_weight"
        return (*batch_axes, rank - 1), "eligible_matmul_weight"

    if op_type == "Conv":
        if input_index != 1:
            return None, "non_weight_input"
        if rank < 3:
            return None, "unsupported_weight_rank"
        return (0,), "eligible_conv_weight"

    if op_type == "ConvTranspose":
        if input_index != 1:
            return None, "non_weight_input"
        if rank < 3:
            return None, "unsupported_weight_rank"
        return (1,), "eligible_conv_transpose_weight"

    if op_type in _RECURRENT_WEIGHT_OPERATORS:
        if input_index not in {1, 2}:
            return None, "non_weight_input"
        if rank != 3:
            return None, "unsupported_weight_rank"
        return (0, 1), "eligible_recurrent_weight"

    if op_type == "Einsum":
        equation = _onnx_text_attribute(node, "equation")
        if equation is None or "..." in equation or equation.count("->") != 1:
            return None, "unsupported_einsum_equation"
        input_expression, output_expression = (part.strip() for part in equation.split("->", 1))
        input_terms = [term.strip() for term in input_expression.split(",")]
        if input_index >= len(input_terms):
            return None, "unsupported_einsum_equation"
        weight_term = input_terms[input_index]
        if (
            len(input_terms) != len(getattr(node, "input", ()))
            or len(weight_term) != rank
            or len(set(weight_term)) != len(weight_term)
            or len(set(output_expression)) != len(output_expression)
        ):
            return None, "unsupported_einsum_equation"
        output_axes = tuple(index for index, label in enumerate(weight_term) if label in output_expression)
        if not output_axes or len(output_axes) == rank:
            return None, "unsupported_einsum_orientation"
        return output_axes, "eligible_einsum_weight"

    if op_type == "Gather":
        if input_index != 0:
            return None, "non_weight_input"
        if rank < 2:
            return None, "unsupported_weight_rank"
        axis = _onnx_gather_axis(node, rank)
        if axis is None:
            return None, "unsupported_weight_axis"
        return tuple(candidate for candidate in range(rank) if candidate != axis), "eligible_gather_table"
    if op_type == "PRelu":
        if input_index != 1:
            return None, "non_weight_input"
        if rank < 2:
            return None, "unsupported_weight_rank"
        return (rank - 1,), "eligible_prelu_slope"
    if op_type in _QUANTIZED_WEIGHT_OPERATORS:
        return None, "quantized_operator"
    if op_type in {
        "Add",
        "Cast",
        "Div",
        "Flatten",
        "Mul",
        "Reshape",
        "Shape",
        "Slice",
        "Squeeze",
        "Sub",
        "Transpose",
        "Unsqueeze",
    }:
        return None, "bookkeeping_constant"
    return None, "unsupported_consumer"


def _onnx_remove_shape_axis(shape: tuple[int, ...], raw_axis: int) -> tuple[int, ...] | None:
    axis = raw_axis if raw_axis >= 0 else len(shape) + raw_axis
    if axis < 0 or axis >= len(shape):
        return None
    return (*shape[:axis], *shape[axis + 1 :])


def _onnx_remove_rank_axis(rank: int, raw_axis: int) -> int | None:
    axis = raw_axis if raw_axis >= 0 else rank + raw_axis
    if axis < 0 or axis >= rank:
        return None
    return rank - 1


def _onnx_remove_known_axis(
    shape: tuple[int, ...] | None, rank: int | None, raw_axis: int
) -> tuple[tuple[int, ...] | None, int | None]:
    if shape is not None:
        shape = _onnx_remove_shape_axis(shape, raw_axis)
        return shape, len(shape) if shape is not None else None
    if rank is not None:
        return None, _onnx_remove_rank_axis(rank, raw_axis)
    return shape, rank


def _onnx_scan_bound_subgraph_input_shape(
    parent_shape: tuple[int, ...] | None,
    parent_rank: int | None,
    *,
    pair_index: int,
    scan_input_start: int,
    scan_input_offset: int,
    scan_input_axes: tuple[int, ...],
) -> tuple[tuple[int, ...] | None, int | None]:
    scan8_batched_input = bool(scan_input_offset and pair_index >= scan_input_offset)
    if scan8_batched_input and pair_index < scan_input_start:
        return _onnx_remove_known_axis(parent_shape, parent_rank, 0)
    if pair_index < scan_input_start:
        return parent_shape, parent_rank

    scan_input_index = pair_index - scan_input_start
    default_scan_input_axis = 1 if scan_input_offset else 0
    scan_input_axis = (
        scan_input_axes[scan_input_index] if scan_input_index < len(scan_input_axes) else default_scan_input_axis
    )
    parent_shape, parent_rank = _onnx_remove_known_axis(parent_shape, parent_rank, scan_input_axis)
    if scan8_batched_input:
        parent_shape, parent_rank = _onnx_remove_known_axis(parent_shape, parent_rank, 0)
    return parent_shape, parent_rank


def _iter_attribute_graphs(attribute: Any) -> Any:
    """Yield graph values declared by an ONNX attribute."""
    yield from attribute.graphs
    if _onnx_has_singular_field(attribute, "g"):
        yield attribute.g


def _onnx_has_singular_field(message: Any, field_name: str) -> bool:
    has_field = getattr(message, "HasField", None)
    if callable(has_field):
        try:
            return bool(has_field(field_name))
        except (AttributeError, ValueError):
            pass
    return getattr(message, field_name, None) is not None


@dataclass(frozen=True)
class _OnnxNetworkDetectorSection:
    name: str
    data: bytes
    field_count: int
    metadata_owned: bool


@dataclass(frozen=True)
class _OnnxNetworkDetectorInput:
    data: bytes
    sections: tuple[_OnnxNetworkDetectorSection, ...]
    field_count: int
    metadata_field_count: int
    omitted_field_count: int
    truncated: bool
    truncation_reason: str | None


class _OnnxNetworkTextCollector:
    def __init__(
        self,
        *,
        max_bytes: int,
        max_fields: int,
        check_interrupted: Callable[[], None],
    ) -> None:
        self._chunks: list[bytes] = []
        self._metadata_chunks: list[bytes] = []
        self._structural_chunks: list[bytes] = []
        self._max_bytes = max_bytes
        self._max_fields = max_fields
        self._check_interrupted = check_interrupted
        self._byte_count = 0
        self._visited_field_count = 0
        self._field_count = 0
        self._metadata_field_count = 0
        self._structural_field_count = 0
        self._metadata_chunk_entries: list[tuple[str, bytes]] = []
        self._omitted_field_count = 0
        self._truncated = False
        self._truncation_reason: str | None = None
        self._metadata_props: dict[tuple[str, int], dict[str, str]] = {}

    def is_truncated(self) -> bool:
        return self._truncated

    def check_interrupted(self) -> None:
        self._check_interrupted()

    def visit_field(self) -> bool:
        self.check_interrupted()
        if self._visited_field_count >= self._max_fields:
            self.omit()
            return False
        self._visited_field_count += 1
        return True

    def visit_message(self) -> bool:
        return self.visit_field()

    def add(self, label: str, value: Any, *, field_visited: bool = False) -> None:
        self.check_interrupted()
        if value is None:
            return
        if isinstance(value, (str, bytes)) and not value:
            return
        if not field_visited and not self.visit_field():
            return
        label_bytes = label.encode("utf-8", errors="surrogatepass")
        entry_overhead = len(label_bytes) + len(b": \n")
        remaining_bytes = self._max_bytes - self._byte_count - entry_overhead
        value_bytes = _onnx_network_text_value_bytes(value, max_bytes=remaining_bytes)
        if value_bytes is None:
            self._truncated = True
            self._truncation_reason = self._truncation_reason or "text_field_budget_exceeded"
            self._omitted_field_count += 1
            return
        if not value_bytes:
            return
        entry = label_bytes + b": " + value_bytes + b"\n"
        self._chunks.append(entry)
        if _is_onnx_metadata_text_label(label):
            self._metadata_chunks.append(entry)
            self._metadata_chunk_entries.append((label, entry))
            self._metadata_field_count += 1
            self._record_metadata_prop(label, value)
        else:
            self._structural_chunks.append(entry)
            self._structural_field_count += 1
        self._byte_count += len(entry)
        self._field_count += 1

    def _record_metadata_prop(self, label: str, value: Any) -> None:
        if not isinstance(value, str):
            return
        match = _ONNX_METADATA_PROP_LABEL_PATTERN.fullmatch(label)
        if match is None:
            return
        entry_key = (match.group("prefix"), int(match.group("index")))
        self._metadata_props.setdefault(entry_key, {})[match.group("field")] = value

    def metadata_prop_entries(self) -> list[tuple[str, int, str, str]]:
        entries: list[tuple[str, int, str, str]] = []
        for prefix, index in sorted(self._metadata_props):
            fields = self._metadata_props[(prefix, index)]
            key = fields.get("key")
            value = fields.get("value")
            if key is not None and value is not None:
                entries.append((prefix, index, key, value))
        return entries

    def omit(self, reason: str = "text_field_budget_exceeded") -> None:
        self._truncated = True
        self._truncation_reason = self._truncation_reason or reason
        self._omitted_field_count += 1

    def finish(
        self,
        *,
        metadata_data_sections: tuple[tuple[frozenset[str], bytes], ...] = (),
    ) -> _OnnxNetworkDetectorInput:
        sections: list[_OnnxNetworkDetectorSection] = []
        if self._structural_chunks:
            sections.append(
                _OnnxNetworkDetectorSection(
                    name="structured_text_fields",
                    data=b"".join(self._structural_chunks),
                    field_count=self._structural_field_count,
                    metadata_owned=False,
                )
            )
        if self._metadata_chunks:
            metadata_data_labels: set[str] = set()
            for labels, metadata_data in metadata_data_sections:
                metadata_data_labels.update(labels)
                sections.append(
                    _OnnxNetworkDetectorSection(
                        name="metadata_props",
                        data=metadata_data,
                        field_count=len(labels),
                        metadata_owned=True,
                    )
                )
            metadata_text_chunks = [
                entry for label, entry in self._metadata_chunk_entries if label not in metadata_data_labels
            ]
            if metadata_data_sections and not metadata_text_chunks:
                metadata_text_data = b""
            else:
                metadata_text_data = b"".join(metadata_text_chunks or self._metadata_chunks)
            if metadata_text_data:
                section_name = "metadata_text_fields" if metadata_data_sections else "metadata_props"
                field_count = len(metadata_text_chunks) if metadata_data_sections else self._metadata_field_count
                sections.append(
                    _OnnxNetworkDetectorSection(
                        name=section_name,
                        data=metadata_text_data,
                        field_count=field_count,
                        metadata_owned=True,
                    )
                )
        return _OnnxNetworkDetectorInput(
            data=b"".join(self._chunks),
            sections=tuple(sections),
            field_count=self._field_count,
            metadata_field_count=self._metadata_field_count,
            omitted_field_count=self._omitted_field_count,
            truncated=self._truncated,
            truncation_reason=self._truncation_reason,
        )


def _onnx_network_text_value_bytes(value: Any, *, max_bytes: int) -> bytes | None:
    if max_bytes <= 0:
        return None
    if value is None:
        return b""
    if isinstance(value, bytes):
        if len(value) > max_bytes:
            return None
        return value
    if isinstance(value, str):
        if len(value) > max_bytes:
            return None
        value_bytes = value.encode("utf-8", errors="surrogatepass")
        if len(value_bytes) > max_bytes:
            return None
        return value_bytes
    return b""


def _network_communication_max_findings(config: dict[str, Any] | None) -> int | None:
    network_config = (config or {}).get("network_comm_config")
    if not isinstance(network_config, dict):
        return None
    max_findings = network_config.get("max_findings")
    if isinstance(max_findings, int) and not isinstance(max_findings, bool) and max_findings > 0:
        return max_findings
    return None


def _is_network_redaction_work_limit(finding: dict[str, Any]) -> bool:
    return finding.get("type") == "detector_finding_limit" and finding.get("truncated_finding_type") in {
        "endpoint_redaction_classification",
        "evidence_redaction",
    }


def _network_finding_limit_payload(
    section: _OnnxNetworkDetectorSection,
    context: str,
    *,
    max_findings: int,
) -> dict[str, Any]:
    return {
        "type": "detector_finding_limit",
        "detector": "network_communication",
        "severity": "INFO",
        "message": "Network communication findings exceeded the configured reporting limit",
        "max_findings": max_findings,
        "truncated_finding_type": "onnx_detector_section",
        "truncated_finding": {
            "onnx_detector_input": section.name,
            "onnx_metadata_owned": section.metadata_owned,
        },
        "analysis_incomplete": True,
        "context": context,
        "onnx_detector_input": section.name,
        "onnx_detector_context": context,
        "onnx_detector_field_count": section.field_count,
        "onnx_metadata_owned": section.metadata_owned,
    }


def _is_onnx_metadata_text_label(label: str) -> bool:
    return ".metadata_props[" in label


def _onnx_proto_field_is_repeated(proto_field: Any) -> bool:
    is_repeated = getattr(proto_field, "is_repeated", None)
    if is_repeated is not None:
        return bool(is_repeated() if callable(is_repeated) else is_repeated)
    return getattr(proto_field, "label", None) == getattr(proto_field, "LABEL_REPEATED", 3)


def _collect_onnx_network_detector_input(
    model: Any,
    *,
    check_interrupted: Callable[[], None],
) -> _OnnxNetworkDetectorInput:
    collector = _OnnxNetworkTextCollector(
        max_bytes=_ONNX_NETWORK_TEXT_MAX_BYTES,
        max_fields=_ONNX_NETWORK_TEXT_MAX_FIELDS,
        check_interrupted=check_interrupted,
    )
    _collect_onnx_proto_text_fields(collector, model, "model")
    metadata_props = collector.metadata_prop_entries()
    metadata_data_sections = _onnx_metadata_props_detector_sections(
        model,
        metadata_props,
        max_bytes=_ONNX_NETWORK_TEXT_MAX_BYTES,
    )
    return collector.finish(
        metadata_data_sections=metadata_data_sections,
    )


def _onnx_metadata_props_detector_sections(
    model: Any,
    metadata_props: Iterable[tuple[str, int, str, str]],
    *,
    max_bytes: int,
) -> tuple[tuple[frozenset[str], bytes], ...]:
    metadata_entries = list(metadata_props)
    if not metadata_entries:
        return ()
    candidate_entries: list[tuple[str, int, str, str]] = []
    estimated_bytes = 0
    for prefix, index, key, value in metadata_entries:
        value_with_boundary = value + "\n"
        entry_bytes = len(key.encode("utf-8", errors="surrogatepass")) + len(
            value_with_boundary.encode("utf-8", errors="surrogatepass")
        )
        if candidate_entries and estimated_bytes + entry_bytes + 64 > max_bytes:
            break
        candidate_entries.append((prefix, index, key, value_with_boundary))
        estimated_bytes += entry_bytes + 64
    if not candidate_entries:
        return ()
    try:
        sections: list[tuple[frozenset[str], bytes]] = []
        position = 0
        while position < len(candidate_entries):
            batch_entries = candidate_entries[position : position + _ONNX_METADATA_DETECTOR_SECTION_MAX_ENTRIES]
            while batch_entries:
                metadata_model = type(model)()
                metadata_model.ir_version = int(getattr(model, "ir_version", 0) or 1)
                metadata_model.graph.name = "modelaudit_metadata"
                metadata_model.graph.input.add().name = "modelaudit_input"
                metadata_model.graph.output.add().name = "modelaudit_output"
                for _prefix, _index, key, value in batch_entries:
                    metadata_prop = metadata_model.metadata_props.add()
                    metadata_prop.key = key
                    metadata_prop.value = value
                metadata_data = metadata_model.SerializeToString()
                if len(metadata_data) <= max_bytes:
                    break
                batch_entries.pop()
            if not batch_entries:
                break
            metadata_data_labels = frozenset(
                label
                for prefix, index, _key, _value in batch_entries
                for label in (f"{prefix}[{index}].key", f"{prefix}[{index}].value")
            )
            sections.append((metadata_data_labels, metadata_data))
            position += len(batch_entries)
        return tuple(sections)
    except Exception:  # pragma: no cover - protobuf compatibility fallback
        return ()


def _onnx_network_detector_input_metadata(network_detector_input: _OnnxNetworkDetectorInput) -> dict[str, Any]:
    return {
        "source": "structured_text_fields",
        "field_count": network_detector_input.field_count,
        "metadata_field_count": network_detector_input.metadata_field_count,
        "omitted_field_count": network_detector_input.omitted_field_count,
        "truncated": network_detector_input.truncated,
        "truncation_reason": network_detector_input.truncation_reason,
        "max_bytes": _ONNX_NETWORK_TEXT_MAX_BYTES,
        "max_fields": _ONNX_NETWORK_TEXT_MAX_FIELDS,
        "sections": [
            {
                "name": section.name,
                "field_count": section.field_count,
                "metadata_owned": section.metadata_owned,
            }
            for section in network_detector_input.sections
        ],
    }


def _collect_onnx_proto_text_fields(
    collector: _OnnxNetworkTextCollector,
    message: Any,
    label: str,
    *,
    depth: int = 0,
) -> None:
    if message is None or collector.is_truncated():
        return
    if depth > _ONNX_STRUCTURE_MAX_DEPTH:
        collector.omit()
        return
    descriptor = getattr(message, "DESCRIPTOR", None)
    if descriptor is None:
        if depth == 0:
            collector.omit("structured_text_unavailable")
        return
    for proto_field in getattr(descriptor, "fields", []):
        collector.check_interrupted()
        field_label = f"{label}.{proto_field.name}"
        if _is_onnx_tensor_payload_field(descriptor, proto_field):
            continue
        repeated_field = _onnx_proto_field_is_repeated(proto_field)
        if repeated_field and proto_field.type not in {
            proto_field.TYPE_MESSAGE,
            proto_field.TYPE_BYTES,
            proto_field.TYPE_STRING,
        }:
            continue
        value = getattr(message, proto_field.name)
        if repeated_field:
            for index, item in enumerate(value):
                item_label = f"{field_label}[{index}]"
                if proto_field.type == proto_field.TYPE_MESSAGE:
                    if not collector.visit_message():
                        return
                    _collect_onnx_proto_text_fields(collector, item, item_label, depth=depth + 1)
                elif proto_field.type in {proto_field.TYPE_BYTES, proto_field.TYPE_STRING}:
                    if not collector.visit_field():
                        return
                    collector.add(item_label, item, field_visited=True)
                if collector.is_truncated():
                    return
            continue
        if proto_field.type == proto_field.TYPE_MESSAGE:
            if not _onnx_has_singular_field(message, proto_field.name):
                continue
            if not collector.visit_message():
                return
            _collect_onnx_proto_text_fields(collector, value, field_label, depth=depth + 1)
        elif proto_field.type in {proto_field.TYPE_BYTES, proto_field.TYPE_STRING}:
            collector.add(field_label, value)


def _is_onnx_tensor_payload_field(descriptor: Any, proto_field: Any) -> bool:
    return (
        getattr(descriptor, "full_name", "") == "onnx.TensorProto"
        and proto_field.name in _ONNX_RAW_OR_NUMERIC_TENSOR_PAYLOAD_FIELD_NAMES
    )


def _iter_graph_nodes(graph: Any) -> Any:
    """Yield every node in an ONNX graph or function, recursing into subgraphs."""
    for node in graph.node:
        yield node
        for attribute in node.attribute:
            for subgraph in _iter_attribute_graphs(attribute):
                yield from _iter_graph_nodes(subgraph)


def _onnx_value_name(value: Any) -> str:
    return str(getattr(value, "name", value))


def _graph_declared_value_names(graph: Any) -> set[str]:
    """Return names that shadow values captured from an enclosing ONNX graph."""
    declared = {_onnx_value_name(value) for value in getattr(graph, "input", []) if _onnx_value_name(value)}
    declared.update(initializer.name for initializer in getattr(graph, "initializer", []) if initializer.name)
    for sparse_initializer in getattr(graph, "sparse_initializer", []):
        if sparse_initializer.values.name:
            declared.add(sparse_initializer.values.name)
    for node in getattr(graph, "node", []):
        declared.update(output_name for output_name in node.output if output_name)
    return declared


def _iter_model_graphs(model: Any) -> Any:
    """Yield graph-bearing ONNX model fields that may declare operators."""
    for graph, _opset_versions in _iter_model_graphs_with_opsets(model):
        yield graph


def _iter_model_graphs_with_opsets(model: Any) -> Any:
    """Yield model graphs with the operator-set versions governing each graph."""
    model_opset_versions = _opset_versions_by_domain(getattr(model, "opset_import", []))
    yield model.graph, model_opset_versions
    for function in getattr(model, "functions", []):
        function_opset_versions = _opset_versions_by_domain(getattr(function, "opset_import", []))
        yield function, function_opset_versions
        for attribute in getattr(function, "attribute_proto", []):
            for graph in _iter_attribute_graphs(attribute):
                yield graph, function_opset_versions
    for training_info in getattr(model, "training_info", []):
        yield training_info.initialization, model_opset_versions
        yield training_info.algorithm, model_opset_versions


def _opset_versions_by_domain(opset_imports: Iterable[Any]) -> dict[str, int]:
    """Collect opset imports, preserving ambiguity for conflicting duplicates."""
    versions: dict[str, int] = {}
    for opset in opset_imports:
        domain = opset.domain or ""
        version = int(opset.version)
        previous = versions.get(domain)
        if previous is None:
            versions[domain] = version
        elif previous != version:
            versions[domain] = _AMBIGUOUS_ONNX_OPSET_VERSION
    return versions


def _model_local_function_identifiers(model: Any) -> frozenset[tuple[str, str, str]]:
    """Return identifiers for functions implemented inside the ONNX model."""
    return frozenset(
        (
            function.domain or "",
            function.name or "",
            getattr(function, "overload", "") or "",
        )
        for function in getattr(model, "functions", [])
    )


def _operator_identifier(node: Any) -> tuple[str, str, str]:
    """Return an ONNX operator's domain, name, and overload identity."""
    return (node.domain or "", node.op_type or "", getattr(node, "overload", "") or "")


def _bounded_custom_operator_value(value: Any) -> str:
    text = str(value or "")
    if len(text) <= _ONNX_CUSTOM_OPERATOR_TEXT_LIMIT:
        return text
    return f"{text[:_ONNX_CUSTOM_OPERATOR_TEXT_LIMIT]}..."


def _custom_operator_identity_display(value: str) -> str:
    return _bounded_custom_operator_value(value) if value else "<default>"


def _custom_operator_values_hash(*values: str) -> str:
    digest = hashlib.sha256()
    for value in values:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
        digest.update(encoded)
    return digest.hexdigest()


def _custom_operator_domain_hash(domain: str) -> str:
    return _custom_operator_values_hash(domain)


def _custom_operator_identity_hash(domain: str, op_type: str, overload: str) -> str:
    return _custom_operator_values_hash(domain, op_type, overload)


@dataclass
class _CustomOperatorAggregate:
    occurrence_count: int = 0
    operator_samples: list[str] = field(default_factory=list)
    operator_identities: list[dict[str, str]] = field(default_factory=list)
    representative_nodes: list[dict[str, str]] = field(default_factory=list)
    operator_samples_truncated: bool = False
    operator_identities_truncated: bool = False
    _operator_sample_seen: set[str] = field(default_factory=set)
    _operator_identity_seen: set[tuple[str, str, str]] = field(default_factory=set)

    def add_node(self, node: Any) -> None:
        self.occurrence_count += 1
        raw_op_type = str(getattr(node, "op_type", "") or "")
        raw_domain = str(getattr(node, "domain", "") or "")
        raw_overload = str(getattr(node, "overload", "") or "")
        op_type = _bounded_custom_operator_value(raw_op_type)
        domain = _bounded_custom_operator_value(raw_domain)
        overload = _bounded_custom_operator_value(raw_overload)
        if op_type not in self._operator_sample_seen:
            if len(self.operator_samples) < _ONNX_CUSTOM_OPERATOR_SAMPLE_LIMIT:
                self.operator_samples.append(op_type)
                self._operator_sample_seen.add(op_type)
            else:
                self.operator_samples_truncated = True

        operator_identity = (raw_domain, raw_op_type, raw_overload)
        if operator_identity not in self._operator_identity_seen:
            if len(self.operator_identities) < _ONNX_CUSTOM_OPERATOR_SAMPLE_LIMIT:
                self._operator_identity_seen.add(operator_identity)
                self.operator_identities.append(
                    {
                        "domain": domain,
                        "op_type": op_type,
                        "overload": overload,
                        "operator_identity_hash": _custom_operator_identity_hash(
                            raw_domain,
                            raw_op_type,
                            raw_overload,
                        ),
                    }
                )
            else:
                self.operator_identities_truncated = True

        if len(self.representative_nodes) >= _ONNX_CUSTOM_OPERATOR_REPRESENTATIVE_LIMIT:
            return

        node_summary = {
            "op_type": op_type,
            "domain": domain,
        }
        node_name = _bounded_custom_operator_value(getattr(node, "name", ""))
        if node_name:
            node_summary["name"] = node_name
        if overload:
            node_summary["overload"] = overload
        self.representative_nodes.append(node_summary)

    def details(self, *, domain: str, security_note: str, check_consolidation_key: str | None = None) -> dict[str, Any]:
        details: dict[str, Any] = {
            "domain": domain,
            "occurrence_count": self.occurrence_count,
            "operator_samples": self.operator_samples,
            "operator_samples_truncated": self.operator_samples_truncated,
            "operator_identities": self.operator_identities,
            "operator_identities_truncated": self.operator_identities_truncated,
            "distinct_operator_identity_count": len(self._operator_identity_seen),
            "distinct_operator_identity_count_truncated": self.operator_identities_truncated,
            "representative_nodes": self.representative_nodes,
            "representative_nodes_truncated": self.occurrence_count > len(self.representative_nodes),
            "security_note": security_note,
        }
        if check_consolidation_key:
            details["check_consolidation_key"] = check_consolidation_key
        if self.operator_samples:
            details["op_type"] = self.operator_samples[0]
        return details


@dataclass
class _OnnxExternalLocationAggregate:
    occurrence_count: int = 0
    tensor_samples: list[str] = field(default_factory=list)

    def add(self, tensor_name: str) -> None:
        self.occurrence_count += 1
        if len(self.tensor_samples) < 5:
            self.tensor_samples.append(tensor_name)


@dataclass(frozen=True)
class _OnnxExternalSizeValidation:
    category: str
    passed: bool
    message: str
    severity: IssueSeverity | None
    location: str
    details: dict[str, Any]
    rule_code: str | None = None


def _has_operator_schema(op_type: str, version: int, domain: str) -> bool:
    """Return whether the installed ONNX release registers an operator schema."""
    try:
        import onnx

        return bool(onnx.defs.has(op_type, version, domain))
    except Exception as exc:  # pragma: no cover - fail closed on optional API errors
        logger.debug("Unable to validate ONNX operator schema %s::%s at version %s: %s", domain, op_type, version, exc)
        return False


def _is_schema_validated_operator(node: Any, opset_versions: dict[str, int]) -> bool:
    """Return whether this graph's imports register the preview operator."""
    domain = node.domain or ""
    version = opset_versions.get(domain)
    return bool(
        domain in SCHEMA_VALIDATED_ONNX_DOMAINS
        and not (getattr(node, "overload", "") or "")
        and version is not None
        and _has_operator_schema(node.op_type or "", version, domain)
    )


def _is_low_noise_vendor_operator(node: Any, opset_versions: dict[str, int]) -> bool:
    """Return whether a custom-domain node matches the documented vendor policy."""
    domain = node.domain or ""
    domain_policy = _LOW_NOISE_ONNX_RUNTIME_OPERATORS.get(domain)
    overload = str(getattr(node, "overload", "") or "")
    if domain_policy is None or overload:
        return False

    supported_versions = domain_policy.get(node.op_type or "")
    if supported_versions is None:
        return False

    version = opset_versions.get(domain)
    return version in supported_versions


def _is_external_custom_operator(
    node: Any,
    local_function_identifiers: frozenset[tuple[str, str, str]],
    opset_versions: dict[str, int],
) -> bool:
    """Return True for non-standard operators without a model-local implementation."""
    domain = node.domain or ""
    return bool(
        domain
        and domain not in STANDARD_ONNX_DOMAINS
        and _operator_identifier(node) not in local_function_identifiers
        and not _is_schema_validated_operator(node, opset_versions)
        and not _is_low_noise_vendor_operator(node, opset_versions)
    )


def _is_explicit_custom_operator(
    node: Any,
    local_function_identifiers: frozenset[tuple[str, str, str]],
) -> bool:
    """Return whether an actual graph node carries the raw custom-op marker."""
    return bool(
        "custom_op" in (node.op_type or "").casefold() and _operator_identifier(node) not in local_function_identifiers
    )


def _check_onnx_traversal_interrupted(interrupt_check: Callable[[], None] | None) -> None:
    if interrupt_check is not None:
        interrupt_check()


def _iter_graph_and_subgraphs(
    graph: Any,
    interrupt_check: Callable[[], None] | None = None,
) -> Any:
    """Yield an ONNX graph and every graph nested below node attributes."""
    _check_onnx_traversal_interrupted(interrupt_check)
    yield graph
    for node in getattr(graph, "node", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        for attribute in getattr(node, "attribute", []):
            _check_onnx_traversal_interrupted(interrupt_check)
            for subgraph in _iter_attribute_graphs(attribute):
                yield from _iter_graph_and_subgraphs(subgraph, interrupt_check)


def _iter_model_initializer_graphs(
    model: Any,
    interrupt_check: Callable[[], None] | None = None,
) -> Any:
    """Yield every ONNX graph that can carry tensor initializers."""
    yield from _iter_graph_and_subgraphs(model.graph, interrupt_check)
    for function in getattr(model, "functions", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield from _iter_graph_and_subgraphs(function, interrupt_check)
        for attribute in getattr(function, "attribute_proto", []):
            _check_onnx_traversal_interrupted(interrupt_check)
            for subgraph in _iter_attribute_graphs(attribute):
                yield from _iter_graph_and_subgraphs(subgraph, interrupt_check)
    for training_info in getattr(model, "training_info", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield from _iter_graph_and_subgraphs(training_info.initialization, interrupt_check)
        yield from _iter_graph_and_subgraphs(training_info.algorithm, interrupt_check)


def _iter_attribute_external_data_tensors(
    attribute: Any,
    interrupt_check: Callable[[], None] | None = None,
) -> Any:
    """Yield tensor values declared by an ONNX attribute."""
    for tensor in getattr(attribute, "tensors", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield tensor
    for sparse_tensor in getattr(attribute, "sparse_tensors", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield sparse_tensor.values
        yield sparse_tensor.indices
    if _onnx_has_singular_field(attribute, "t"):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield attribute.t
    if _onnx_has_singular_field(attribute, "sparse_tensor"):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield attribute.sparse_tensor.values
        yield attribute.sparse_tensor.indices


def _iter_graph_external_data_tensors(
    graph: Any,
    interrupt_check: Callable[[], None] | None = None,
) -> Any:
    """Yield graph-owned tensors that can carry external_data references."""
    for tensor in getattr(graph, "initializer", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield tensor
    for sparse_tensor in getattr(graph, "sparse_initializer", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        yield sparse_tensor.values
        yield sparse_tensor.indices
    for node in getattr(graph, "node", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        for attribute in getattr(node, "attribute", []):
            _check_onnx_traversal_interrupted(interrupt_check)
            yield from _iter_attribute_external_data_tensors(attribute, interrupt_check)


def _iter_model_external_data_tensor_groups(
    model: Any,
    interrupt_check: Callable[[], None] | None = None,
) -> Any:
    """Yield model tensor groups that can declare external_data."""
    for graph in _iter_model_initializer_graphs(model, interrupt_check):
        yield _iter_graph_external_data_tensors(graph, interrupt_check)
    for function in getattr(model, "functions", []):
        _check_onnx_traversal_interrupted(interrupt_check)
        for attribute in getattr(function, "attribute_proto", []):
            _check_onnx_traversal_interrupted(interrupt_check)
            yield _iter_attribute_external_data_tensors(attribute, interrupt_check)


def _model_has_external_data(
    model: Any,
    interrupt_check: Callable[[], None] | None = None,
) -> bool:
    """Return True when an ONNX model declares tensors stored in external_data."""
    for tensors in _iter_model_external_data_tensor_groups(model, interrupt_check):
        for tensor in tensors:
            if int(getattr(tensor, "data_location", 0)) == 1:
                return True
    return False


def _model_declares_python_operator(model: Any) -> bool:
    """Return True when the parsed ONNX model actually declares a Python operator.

    The raw-byte JIT detector matches short, case-insensitive operator-name
    tokens (e.g. ``PyOp``) anywhere in the file, so on large models it collides
    with arbitrary tensor weight bytes. The parsed graph is the authoritative
    operator inventory, so it is consulted before trusting a raw-byte match.
    """
    return any(
        _is_python_operator(node.op_type or "")
        for graph in _iter_model_graphs(model)
        for node in _iter_graph_nodes(graph)
    )


def _jit_finding_type(finding: Any) -> Any:
    """Return the detector finding type across dict and object results."""
    return finding.get("type") if hasattr(finding, "get") else getattr(finding, "type", None)


def _confirmed_python_operator_findings(findings: list[Any], model: Any) -> list[Any]:
    """Drop raw-byte ``python_operator`` findings the parsed graph does not confirm.

    A ``python_operator`` finding with no matching node in the parsed graph is a
    false positive from the raw-byte regex colliding with tensor weight data.
    If the graph cannot be inspected, the finding is kept (fail closed).
    """
    if not any(_jit_finding_type(finding) == "python_operator" for finding in findings):
        return findings

    try:
        if _model_declares_python_operator(model):
            return findings
    except Exception as exc:  # pragma: no cover - defensive: keep finding if unsure
        logger.debug("Unable to validate ONNX python operator finding against graph: %s", exc)
        return findings

    confirmed: list[Any] = []
    for finding in findings:
        if _jit_finding_type(finding) == "python_operator":
            logger.debug("Suppressing unconfirmed raw-byte ONNX python_operator finding (no PyOp node in graph)")
            continue
        confirmed.append(finding)
    return confirmed


def _confirmed_onnx_operator_findings(findings: list[Any], model: Any) -> list[Any]:
    """Let parsed graph checks own custom-op findings when inventory is readable."""
    confirmed = _confirmed_python_operator_findings(findings, model)
    if not any(_jit_finding_type(finding) == "custom_operator" for finding in confirmed):
        return confirmed

    try:
        if hasattr(model, "HasField") and not _onnx_has_singular_field(model, "graph"):
            return confirmed
        for graph in _iter_model_graphs(model):
            for node in _iter_graph_nodes(graph):
                _operator_identifier(node)
    except Exception as exc:  # pragma: no cover - defensive: keep finding if unsure
        logger.debug("Unable to validate ONNX custom operator finding against graph: %s", exc)
        return confirmed

    logger.debug("Suppressing raw-byte ONNX custom_operator finding in favor of parsed graph checks")
    return [finding for finding in confirmed if _jit_finding_type(finding) != "custom_operator"]


def _is_windows_absolute_path(path: str) -> bool:
    """Return True when a serialized path is absolute in Windows syntax."""
    return ntpath.isabs(path.replace("/", "\\"))


def _resolve_external_location(model_dir: Path, location: str) -> Path:
    """Resolve an ONNX external_data location for checks and reporting."""
    if _is_windows_absolute_path(location):
        return Path(location)
    return (model_dir / location).resolve()


def _resolve_external_location_lexically(model_dir: Path, location: str) -> Path:
    """Resolve an external_data location without following symlinks."""
    if _is_windows_absolute_path(location):
        return Path(location)
    return Path(os.path.normpath(str(model_dir / location)))


def _has_symlink_component(path: Path, root: Path) -> bool:
    """Return True when any component from root to path is a symlink."""
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return False

    current = root
    for part in relative_parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _is_trusted_huggingface_cache_external_alias(
    model_path: Path,
    lexical_external_path: Path,
    external_path: Path,
) -> bool:
    """Return True for Hugging Face snapshot symlinks that resolve to the model cache blobs directory."""
    try:
        from ..utils.sources._huggingface_cache import (
            _find_hf_cache_root,
            _hf_cache_snapshot_revision,
            _trusted_hf_blobs_root,
        )
    except Exception:
        return False

    model_cache_root = _find_hf_cache_root(model_path)
    if model_cache_root is None or _find_hf_cache_root(lexical_external_path) != model_cache_root:
        return False
    model_revision = _hf_cache_snapshot_revision(model_path, model_cache_root)
    external_revision = _hf_cache_snapshot_revision(lexical_external_path, model_cache_root)
    if model_revision is None or external_revision != model_revision:
        return False
    if (
        not model_path.is_symlink()
        or not lexical_external_path.is_symlink()
        or _has_symlink_component(
            lexical_external_path.parent,
            model_path.parent,
        )
    ):
        return False
    blobs_root = _trusted_hf_blobs_root(model_cache_root)
    if blobs_root is None:
        return False
    try:
        model_path.resolve(strict=True).relative_to(blobs_root)
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        external_path.relative_to(blobs_root)
    except ValueError:
        return False
    return True


def _tensor_data_type_to_np_dtype(data_type: int) -> Any:
    """Resolve an ONNX tensor dtype across current and legacy ONNX APIs."""
    import numpy as np
    import onnx

    try:
        return np.dtype(onnx.helper.tensor_dtype_to_np_dtype(data_type))
    except Exception as exc:
        logger.debug("Unable to resolve ONNX dtype through helper API: %s", exc)

    if mapping is None:
        raise ValueError(f"ONNX tensor dtype mapping unavailable for data_type={data_type}")

    if hasattr(mapping, "TENSOR_TYPE_TO_NP_TYPE"):
        return np.dtype(mapping.TENSOR_TYPE_TO_NP_TYPE[data_type])

    if hasattr(mapping, "TENSOR_TYPE_MAP"):
        return np.dtype(mapping.TENSOR_TYPE_MAP[data_type].np_dtype)

    raise ValueError(f"Unsupported ONNX tensor dtype mapping API for data_type={data_type}")


@dataclass(frozen=True)
class _OnnxWeightTransform:
    kind: str
    parameters: tuple[int, ...] = ()


@dataclass(frozen=True)
class _OnnxWeightLineage:
    initializer_index: int
    shape: tuple[int, ...] | None
    data_type: int | None
    transforms: tuple[_OnnxWeightTransform, ...] = ()
    unresolved_reason: str | None = None


@dataclass(frozen=True)
class _OnnxWeightLineageGapSummary:
    lineages: tuple[_OnnxWeightLineage, ...] = ()
    truncated: bool = False


@dataclass
class _OnnxWeightConsumerGroup:
    lineage: _OnnxWeightLineage
    node: Any
    node_index: int
    input_index: int
    output_axes: tuple[int, ...]
    analysis_kind: str
    group: int
    consumer_count: int = 0
    consumers: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _OnnxWeightAnalysisSpec:
    initializer_index: int
    analysis_id: int
    weights: Any
    output_axes: tuple[int, ...]
    matrix_analysis: bool
    context: dict[str, Any]


@dataclass
class _OnnxWeightAnalysisPlan:
    specs: list[_OnnxWeightAnalysisSpec] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    coverage_gaps: dict[str, int] = field(default_factory=dict)
    eligible_initializer_count: int = 0
    analyzed_initializer_count: int = 0
    external_initializers_skipped: int = 0
    oversized_initializers_skipped: int = 0
    extraction_failures: int = 0
    string_truncation_count: int = 0
    exclusion_counts: dict[str, int] = field(default_factory=dict)
    exclusion_samples: list[dict[str, Any]] = field(default_factory=list)
    unresolved_lineage_samples: list[dict[str, Any]] = field(default_factory=list)

    def record_coverage_gap(self, reason: str, count: int = 1) -> None:
        current = self.coverage_gaps.get(reason, 0)
        if reason == "lineages_per_value_limit":
            self.coverage_gaps[reason] = _bounded_onnx_weight_lineage_gap_count(current, count)
        else:
            self.coverage_gaps[reason] = current + count


def _bounded_onnx_weight_lineage_gap_count(*counts: int) -> int:
    total = 0
    for count in counts:
        if count <= 0:
            continue
        if count >= _ONNX_WEIGHT_LINEAGE_GAP_COUNT_LIMIT - total:
            return _ONNX_WEIGHT_LINEAGE_GAP_COUNT_LIMIT
        total += count
    return total


def _bounded_onnx_metadata_text(plan: _OnnxWeightAnalysisPlan, value: Any) -> tuple[str, int, bool]:
    text = str(value)
    original_length = len(text)
    if original_length <= _ONNX_WEIGHT_METADATA_TEXT_LIMIT:
        return text, original_length, False

    marker = "...<truncated>"
    plan.string_truncation_count += 1
    return (
        text[: _ONNX_WEIGHT_METADATA_TEXT_LIMIT - len(marker)] + marker,
        original_length,
        True,
    )


def _bounded_onnx_metadata_fields(
    plan: _OnnxWeightAnalysisPlan,
    field_name: str,
    value: Any,
) -> dict[str, Any]:
    text, original_length, truncated = _bounded_onnx_metadata_text(plan, value)
    return {
        field_name: text,
        f"{field_name}_length": original_length,
        f"{field_name}_truncated": truncated,
    }


def _bounded_onnx_integer_sequence(field_name: str, values: Any) -> dict[str, Any]:
    value_count = len(values)
    sequence = [int(values[index]) for index in range(min(value_count, _ONNX_WEIGHT_METADATA_SEQUENCE_LIMIT))]
    return {
        field_name: sequence,
        f"{field_name}_count": value_count,
        f"{field_name}_truncated": value_count > _ONNX_WEIGHT_METADATA_SEQUENCE_LIMIT,
    }


def _onnx_inline_storage_nbytes(initializer: Any) -> int:
    raw_bytes = len(getattr(initializer, "raw_data", b""))
    typed_bytes = 0
    for field_name, itemsize in (
        ("float_data", 4),
        ("int32_data", 4),
        ("int64_data", 8),
        ("double_data", 8),
        ("uint64_data", 8),
    ):
        typed_bytes += len(getattr(initializer, field_name, ())) * itemsize
    typed_bytes += sum(len(value) for value in getattr(initializer, "string_data", ()))
    return raw_bytes + typed_bytes


def _onnx_tensor_uses_external_storage(initializer: Any, *, onnx: Any) -> bool:
    if getattr(initializer, "data_location", None) == onnx.TensorProto.EXTERNAL:
        return True
    return bool(getattr(initializer, "external_data", ())) and _onnx_inline_storage_nbytes(initializer) == 0


def _configured_onnx_weight_array_limit(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        return _ONNX_WEIGHT_DEFAULT_MAX_ARRAY_SIZE
    try:
        numeric_value = float(value)
    except (OverflowError, TypeError, ValueError):
        return _ONNX_WEIGHT_DEFAULT_MAX_ARRAY_SIZE
    if not math.isfinite(numeric_value) or numeric_value < 0:
        return _ONNX_WEIGHT_DEFAULT_MAX_ARRAY_SIZE
    if numeric_value == 0:
        return None
    return max(int(numeric_value), 1)


def _resolve_onnx_reshape_shape(
    input_shape: tuple[int, ...],
    shape_initializer: Any,
    *,
    allowzero: bool,
    onnx: Any,
) -> tuple[int, ...] | None:
    if any(dimension < 0 for dimension in input_shape):
        return None
    dims = tuple(int(dimension) for dimension in getattr(shape_initializer, "dims", ()))
    element_count = math.prod(dims) if dims else 0
    if (
        len(dims) != 1
        or element_count < 0
        or element_count > _ONNX_WEIGHT_RESHAPE_RANK_LIMIT
        or int(getattr(shape_initializer, "data_type", -1)) != int(onnx.TensorProto.INT64)
        or _onnx_inline_storage_nbytes(shape_initializer) > _ONNX_WEIGHT_RESHAPE_RANK_LIMIT * 8
        or _onnx_tensor_uses_external_storage(shape_initializer, onnx=onnx)
    ):
        return None

    try:
        target_values = onnx.numpy_helper.to_array(shape_initializer).reshape(-1).tolist()
        target = [int(value) for value in target_values]
    except Exception:
        return None
    if len(target) != element_count or any(value < -1 for value in target) or target.count(-1) > 1:
        return None
    if allowzero and -1 in target and 0 in target:
        return None

    normalized: list[int] = []
    for index, value in enumerate(target):
        if value == 0 and not allowzero:
            if index >= len(input_shape):
                return None
            normalized.append(int(input_shape[index]))
        else:
            normalized.append(value)

    input_size = math.prod(input_shape)
    known_size = math.prod(value for value in normalized if value != -1)
    if -1 in normalized:
        if known_size <= 0 or input_size % known_size != 0:
            return None
        normalized[normalized.index(-1)] = input_size // known_size
    elif math.prod(normalized) != input_size:
        return None
    return tuple(normalized)


def _resolve_onnx_axes(
    node: Any,
    constants: dict[str, Any],
    *,
    onnx: Any,
    resolve_attribute: Callable[[Any], Any | None] | None = None,
) -> tuple[int, ...] | None:
    for attribute in getattr(node, "attribute", ()):
        if attribute.name == "axes":
            resolved_attribute = resolve_attribute(attribute) if resolve_attribute is not None else attribute
            if resolved_attribute is None:
                return None
            return tuple(int(value) for value in getattr(resolved_attribute, "ints", ()))
    if len(getattr(node, "input", ())) < 2:
        return ()

    axes_initializer = constants.get(str(node.input[1]))
    if axes_initializer is None:
        return None
    dims = tuple(int(dimension) for dimension in getattr(axes_initializer, "dims", ()))
    element_count = math.prod(dims) if dims else 0
    if (
        len(dims) != 1
        or element_count < 0
        or element_count > _ONNX_WEIGHT_RESHAPE_RANK_LIMIT
        or int(getattr(axes_initializer, "data_type", -1)) != int(onnx.TensorProto.INT64)
        or _onnx_inline_storage_nbytes(axes_initializer) > _ONNX_WEIGHT_RESHAPE_RANK_LIMIT * 8
        or _onnx_tensor_uses_external_storage(axes_initializer, onnx=onnx)
    ):
        return None
    try:
        axes = tuple(int(value) for value in onnx.numpy_helper.to_array(axes_initializer).reshape(-1).tolist())
    except Exception:
        return None
    return axes if len(axes) == element_count else None


def _onnx_initializer_name_issues(
    graph: Any,
    plan: _OnnxWeightAnalysisPlan,
) -> tuple[int, int, list[dict[str, Any]]]:
    empty_count = 0
    duplicate_count = 0
    samples: list[dict[str, Any]] = []

    def walk(current_graph: Any, graph_index: int) -> int:
        nonlocal empty_count, duplicate_count
        names = [str(initializer.name) for initializer in getattr(current_graph, "initializer", ())]
        names.extend(
            str(sparse_initializer.values.name)
            for sparse_initializer in getattr(current_graph, "sparse_initializer", ())
        )
        seen: set[str] = set()
        duplicated: set[str] = set()
        for name in names:
            if not name:
                empty_count += 1
                if len(samples) < _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
                    samples.append({"graph_index": graph_index, "reason": "empty_initializer_name"})
                continue
            if name in seen:
                duplicate_count += 1
                if name not in duplicated and len(samples) < _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
                    samples.append(
                        {
                            "graph_index": graph_index,
                            "reason": "duplicate_initializer_name",
                            **_bounded_onnx_metadata_fields(plan, "initializer", name),
                        },
                    )
                duplicated.add(name)
            seen.add(name)

        next_graph_index = graph_index + 1
        for node in getattr(current_graph, "node", ()):
            for attribute in getattr(node, "attribute", ()):
                for subgraph in _iter_attribute_graphs(attribute):
                    next_graph_index = walk(subgraph, next_graph_index)
        return next_graph_index

    walk(graph, 0)
    return empty_count, duplicate_count, samples


def _onnx_potential_weight_input(
    node: Any,
    input_index: int,
    *,
    is_model_local_function: bool = False,
    is_registered_standard_operator: bool = True,
) -> bool:
    """Return whether initializer lineage at this input needs weight coverage."""
    domain = getattr(node, "domain", "")
    if domain not in _STANDARD_NEURAL_NETWORK_DOMAINS:
        # ONNX-ML operators store learned parameters in attributes; tensor inputs are data.
        if is_registered_standard_operator and domain == "ai.onnx.ml":
            return False
        return not is_model_local_function and (
            domain in STANDARD_ONNX_DOMAINS or domain in SCHEMA_VALIDATED_ONNX_DOMAINS
        )
    if node.op_type in {"Gemm", "MatMul"}:
        return input_index in {0, 1}
    if node.op_type in {"Conv", "ConvTranspose"}:
        return input_index == 1
    if node.op_type in _RECURRENT_WEIGHT_OPERATORS:
        return input_index in {1, 2}
    if node.op_type == "Gather":
        return input_index == 0
    if node.op_type == "PRelu":
        return input_index == 1
    return node.op_type == "Einsum" or not is_registered_standard_operator


def _onnx_activation_input_candidate(node: Any, input_index: int) -> bool:
    if getattr(node, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS:
        return False
    if node.op_type in {"Einsum", "Gemm", "MatMul"}:
        return True
    if node.op_type in {"Conv", "ConvTranspose"}:
        return input_index == 0
    if node.op_type in _RECURRENT_WEIGHT_OPERATORS:
        return input_index not in {1, 2}
    return node.op_type == "Gather" and input_index == 1


def _onnx_opaque_activation_input_candidate(node: Any, _input_index: int) -> bool:
    """Recognize opaque-domain inputs whose schema fixes an activation-only role."""
    return getattr(node, "domain", "") == "ai.onnx.ml"


def _build_onnx_weight_analysis_plan(
    model: Any,
    *,
    onnx: Any,
    np: Any,
    max_array_size: int | None,
    pre_materialization_check: Callable[[Any, str, int], bool] | None = None,
    retain_array_check: Callable[[str, int], bool] | None = None,
) -> _OnnxWeightAnalysisPlan:
    """Build a bounded, semantically oriented plan for ONNX weight analysis."""
    plan = _OnnxWeightAnalysisPlan()
    graph = model.graph
    functions = {
        (
            str(getattr(function, "domain", "")),
            str(getattr(function, "name", "")),
            str(getattr(function, "overload", "")),
        ): function
        for function in getattr(model, "functions", ())
    }
    model_opset_versions = {
        str(getattr(opset, "domain", "") or ""): int(opset.version) for opset in getattr(model, "opset_import", ())
    }
    training_infos = list(getattr(model, "training_info", ()))
    analysis_graph_roots: list[tuple[tuple[Any, ...], Any]] = [(("root_graph",), graph)]
    for training_index, training_info in enumerate(training_infos):
        for field_name in ("initialization", "algorithm"):
            training_graph = getattr(training_info, field_name)
            if training_graph.node or training_graph.initializer or training_graph.sparse_initializer:
                analysis_graph_roots.append((("training_info", training_index, field_name), training_graph))
    initializers: list[Any] = []
    initializer_graph_indexes: list[int] = []
    initializer_source_indexes: dict[tuple[Any, ...], int] = {}
    constant_output_initializer_indexes: set[int] = set()
    empty_names = 0
    duplicate_names = 0
    invalid_name_samples: list[dict[str, Any]] = []
    for _source_scope, analysis_graph in analysis_graph_roots:
        graph_empty_names, graph_duplicate_names, graph_invalid_name_samples = _onnx_initializer_name_issues(
            analysis_graph,
            plan,
        )
        empty_names += graph_empty_names
        duplicate_names += graph_duplicate_names
        remaining_sample_count = _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT - len(invalid_name_samples)
        invalid_name_samples.extend(graph_invalid_name_samples[:remaining_sample_count])
    main_initializer_names = {
        str(initializer.name) for initializer in getattr(graph, "initializer", ()) if initializer.name
    }
    main_initializer_names.update(
        str(sparse_initializer.values.name)
        for sparse_initializer in getattr(graph, "sparse_initializer", ())
        if sparse_initializer.values.name
    )
    for training_index, training_info in enumerate(training_infos):
        algorithm_initializer_names = {
            str(initializer.name)
            for initializer in getattr(training_info.algorithm, "initializer", ())
            if initializer.name
        }
        algorithm_initializer_names.update(
            str(sparse_initializer.values.name)
            for sparse_initializer in getattr(training_info.algorithm, "sparse_initializer", ())
            if sparse_initializer.values.name
        )
        for name in sorted(main_initializer_names & algorithm_initializer_names):
            duplicate_names += 1
            if len(invalid_name_samples) < _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
                invalid_name_samples.append(
                    {
                        "graph_index": training_index,
                        "reason": "duplicate_combined_training_initializer_name",
                        **_bounded_onnx_metadata_fields(plan, "initializer", name),
                    },
                )
    invalid_name_count = empty_names + duplicate_names
    if invalid_name_count:
        plan.record_coverage_gap("invalid_initializer_names", invalid_name_count)
        plan.metadata = {
            "eligible_initializer_count": 0,
            "analyzed_layer_count": 0,
            "eligible": [],
            "eligible_metadata_truncated": False,
            "exclusion_counts": {},
            "exclusion_samples": [],
            "exclusion_metadata_truncated": False,
            "consumer_count": 0,
            "consumer_metadata_sample_count": 0,
            "consumer_metadata_truncated": False,
            "unresolved_lineage_samples": [],
            "unresolved_lineage_metadata_truncated": False,
            "initializer_name_validation": {
                "empty_name_count": empty_names,
                "duplicate_name_count": duplicate_names,
                "samples": invalid_name_samples,
                "samples_truncated": invalid_name_count > len(invalid_name_samples),
            },
            "coverage_gaps": dict(plan.coverage_gaps),
            "metadata_string_truncation_count": plan.string_truncation_count,
            "metadata_strings_truncated": plan.string_truncation_count > 0,
        }
        return plan

    floating_types = {
        int(getattr(onnx.TensorProto, name))
        for name in (
            "FLOAT",
            "FLOAT16",
            "DOUBLE",
            "BFLOAT16",
            "FLOAT8E4M3FN",
            "FLOAT8E4M3FNUZ",
            "FLOAT8E5M2",
            "FLOAT8E5M2FNUZ",
            "FLOAT4E2M1",
        )
        if hasattr(onnx.TensorProto, name)
    }

    def lineage_could_be_weight(lineage: _OnnxWeightLineage) -> bool:
        return (
            lineage.unresolved_reason != "shape_control_lineage"
            and (lineage.data_type is None or lineage.data_type in floating_types)
            and (lineage.shape is None or len(lineage.shape) >= 2)
        )

    def lineage_could_be_weight_after_rank_increase(lineage: _OnnxWeightLineage) -> bool:
        return (
            lineage.unresolved_reason != "shape_control_lineage"
            and lineage.shape is not None
            and len(lineage.shape) < 2
        )

    def cast_output_data_type(
        node: Any,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> int | None:
        target_data_type = -1
        for attribute in getattr(node, "attribute", []):
            if attribute.name == "to":
                resolved_attribute = resolve_attribute(attribute) if resolve_attribute is not None else attribute
                if resolved_attribute is not None:
                    target_data_type = int(getattr(resolved_attribute, "i", -1))
                break
        return target_data_type if target_data_type >= 0 else None

    def cast_output_may_be_floating(
        node: Any,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> bool:
        target_data_type = cast_output_data_type(node, resolve_attribute)
        return target_data_type is None or target_data_type in floating_types

    def constant_int64_vector_values(initializer: Any | None) -> tuple[int, ...] | None:
        if initializer is None:
            return None
        dims = tuple(int(dimension) for dimension in getattr(initializer, "dims", ()))
        element_count = math.prod(dims) if dims else 0
        if (
            len(dims) != 1
            or element_count < 0
            or element_count > _ONNX_WEIGHT_RESHAPE_RANK_LIMIT
            or int(getattr(initializer, "data_type", -1)) != int(onnx.TensorProto.INT64)
            or _onnx_inline_storage_nbytes(initializer) > _ONNX_WEIGHT_RESHAPE_RANK_LIMIT * 8
            or _onnx_tensor_uses_external_storage(initializer, onnx=onnx)
        ):
            return None
        try:
            values = tuple(int(value) for value in onnx.numpy_helper.to_array(initializer).reshape(-1).tolist())
        except Exception:
            return None
        return values if len(values) == element_count else None

    def constant_scalar_value(initializer: Any | None, expected_data_type: int) -> Any | None:
        if initializer is None:
            return None
        dims = tuple(int(dimension) for dimension in getattr(initializer, "dims", ()))
        element_count = math.prod(dims) if dims else 1
        if (
            element_count != 1
            or int(getattr(initializer, "data_type", -1)) != expected_data_type
            or _onnx_tensor_uses_external_storage(initializer, onnx=onnx)
        ):
            return None
        try:
            return onnx.numpy_helper.to_array(initializer).reshape(-1)[0].item()
        except Exception:
            return None

    def graph_initializer_constants(current_graph: Any, inherited_constants: dict[str, Any]) -> dict[str, Any]:
        local_declared_names = _graph_declared_value_names(current_graph)
        graph_constants = {
            name: initializer for name, initializer in inherited_constants.items() if name not in local_declared_names
        }
        for initializer in getattr(current_graph, "initializer", ()):
            name = str(getattr(initializer, "name", "") or "")
            if name:
                graph_constants[name] = initializer
        return graph_constants

    def function_opset_versions(function: Any, caller_opset_versions: dict[str, int]) -> dict[str, int]:
        return _opset_versions_by_domain(getattr(function, "opset_import", ())) or caller_opset_versions

    def bound_function_attributes(
        function: Any,
        node: Any,
        resolve_attribute: Callable[[Any], Any | None],
    ) -> dict[str, Any]:
        attributes = {str(attribute.name): attribute for attribute in getattr(function, "attribute_proto", ())}
        for attribute in getattr(node, "attribute", ()):
            resolved_attribute = resolve_attribute(attribute)
            if resolved_attribute is not None:
                attributes[str(attribute.name)] = resolved_attribute
        return attributes

    def bound_function_constants(
        function: Any, node_input_names: list[str], constants: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        inherited: dict[str, Any] = {}
        bound_inputs: dict[str, Any] = {}
        for input_index, actual_name in enumerate(node_input_names):
            if input_index >= len(getattr(function, "input", ())):
                break
            formal_name = _onnx_value_name(function.input[input_index])
            if formal_name and actual_name in constants:
                inherited[formal_name] = constants[actual_name]
                bound_inputs[formal_name] = constants[actual_name]
        for captured_name in graph_external_reference_names(function):
            if captured_name in constants:
                inherited[captured_name] = constants[captured_name]
        return inherited, bound_inputs

    def constant_node_tensor(node: Any) -> Any | None:
        for attribute in getattr(node, "attribute", ()):
            if attribute.name == "value" and _onnx_has_singular_field(attribute, "t"):
                return attribute.t
        return None

    def resolved_constant_node_tensor(
        node: Any,
        resolve_attribute: Callable[[Any], Any | None],
    ) -> Any | None:
        def repeated_attribute_tensor_values(values: Any) -> list[Any] | None:
            if len(values) > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK:
                return None
            return list(values)

        for attribute in getattr(node, "attribute", ()):
            resolved_attribute = resolve_attribute(attribute)
            if resolved_attribute is None:
                continue
            if attribute.name == "value" and _onnx_has_singular_field(resolved_attribute, "t"):
                return resolved_attribute.t
            if attribute.name == "value_ints":
                values = repeated_attribute_tensor_values(resolved_attribute.ints)
                if values is None:
                    return None
                return onnx.helper.make_tensor(
                    "",
                    onnx.TensorProto.INT64,
                    [len(values)],
                    values,
                )
            if attribute.name == "value_int":
                return onnx.helper.make_tensor("", onnx.TensorProto.INT64, [], [resolved_attribute.i])
            if attribute.name == "value_floats":
                values = repeated_attribute_tensor_values(resolved_attribute.floats)
                if values is None:
                    return None
                return onnx.helper.make_tensor(
                    "",
                    onnx.TensorProto.FLOAT,
                    [len(values)],
                    values,
                )
            if attribute.name == "value_float":
                return onnx.helper.make_tensor("", onnx.TensorProto.FLOAT, [], [resolved_attribute.f])
            if attribute.name == "sparse_value" and _onnx_has_singular_field(resolved_attribute, "sparse_tensor"):
                return resolved_attribute.sparse_tensor
        return None

    def graph_value_is_constant_false(
        current_graph: Any,
        value_name: str,
        inherited_constants: dict[str, Any],
    ) -> bool:
        graph_constants = graph_initializer_constants(current_graph, inherited_constants)
        producers = {
            str(output_name): node
            for node in getattr(current_graph, "node", ())
            for output_name in getattr(node, "output", ())
            if output_name
        }
        seen: set[str] = set()
        current_name = value_name
        for _ in range(8):
            if not current_name or current_name in seen:
                return False
            seen.add(current_name)
            constant_value = constant_scalar_value(graph_constants.get(current_name), int(onnx.TensorProto.BOOL))
            if constant_value is not None:
                return constant_value is False
            producer = producers.get(current_name)
            if (
                producer is not None
                and getattr(producer, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and producer.op_type == "Identity"
                and getattr(producer, "input", ())
                and producer.input[0]
            ):
                current_name = str(producer.input[0])
                continue
            if (
                producer is not None
                and getattr(producer, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and producer.op_type == "Constant"
            ):
                constant_value = constant_scalar_value(constant_node_tensor(producer), int(onnx.TensorProto.BOOL))
                return constant_value is False if constant_value is not None else False
            return False
        return False

    def loop_body_condition_is_constant_false(node: Any, constants: dict[str, Any]) -> bool:
        for attribute in getattr(node, "attribute", ()):
            if getattr(attribute, "name", "") != "body":
                continue
            for body in _iter_attribute_graphs(attribute):
                if not getattr(body, "output", ()):
                    return False
                condition_output_name = _onnx_value_name(body.output[0])
                return graph_value_is_constant_false(body, condition_output_name, constants)
        return False

    def graph_input_is_runtime_overridable(
        value_name: str,
        graph_input_names: set[str],
        constants: dict[str, Any],
    ) -> bool:
        return bool(value_name) and value_name in graph_input_names and value_name not in constants

    def loop_may_skip_body(node: Any, constants: dict[str, Any], graph_input_names: set[str]) -> bool:
        trip_input = str(node.input[0]) if len(node.input) > 0 and node.input[0] else ""
        condition_input = str(node.input[1]) if len(node.input) > 1 and node.input[1] else ""
        if graph_input_is_runtime_overridable(trip_input, graph_input_names, constants) or (
            graph_input_is_runtime_overridable(condition_input, graph_input_names, constants)
        ):
            return True
        trip_count = (
            constant_scalar_value(constants.get(trip_input), int(onnx.TensorProto.INT64)) if trip_input else None
        )
        initial_condition = (
            constant_scalar_value(constants.get(condition_input), int(onnx.TensorProto.BOOL))
            if condition_input
            else True
        )
        if trip_count is not None and int(trip_count) <= 0:
            return True
        if condition_input and initial_condition is False:
            return True
        trip_guarantees_iteration = not trip_input or (trip_count is not None and int(trip_count) > 0)
        condition_guarantees_iteration = not condition_input or initial_condition is True
        return not (trip_guarantees_iteration and condition_guarantees_iteration)

    def loop_may_repeat_body(node: Any, constants: dict[str, Any], graph_input_names: set[str]) -> bool:
        trip_input = str(node.input[0]) if len(node.input) > 0 and node.input[0] else ""
        condition_input = str(node.input[1]) if len(node.input) > 1 and node.input[1] else ""
        if loop_body_condition_is_constant_false(node, constants):
            return False
        if graph_input_is_runtime_overridable(trip_input, graph_input_names, constants) or (
            graph_input_is_runtime_overridable(condition_input, graph_input_names, constants)
        ):
            return True
        trip_count = (
            constant_scalar_value(constants.get(trip_input), int(onnx.TensorProto.INT64)) if trip_input else None
        )
        initial_condition = (
            constant_scalar_value(constants.get(condition_input), int(onnx.TensorProto.BOOL))
            if condition_input
            else True
        )
        if condition_input and initial_condition is False:
            return False
        return trip_count is None or int(trip_count) > 1

    def constant_initializer_shape(constants: dict[str, Any], value_name: Any) -> tuple[int, ...] | None:
        initializer = constants.get(str(value_name)) if value_name else None
        if initializer is None:
            return None
        try:
            return tuple(int(dimension) for dimension in initializer.dims)
        except (AttributeError, TypeError, ValueError):
            return None

    def squeeze_with_empty_axes_is_noop(
        node: Any,
        axes: tuple[int, ...],
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> bool:
        noop_value = 0
        for attribute in getattr(node, "attribute", ()):
            if attribute.name != "noop_with_empty_axes":
                continue
            resolved_attribute = resolve_attribute(attribute) if resolve_attribute is not None else attribute
            noop_value = int(getattr(resolved_attribute, "i", 0)) if resolved_attribute is not None else 0
            break
        return node.op_type == "Squeeze" and not axes and bool(noop_value)

    def gathernd_output_shape(
        node: Any,
        *,
        input_shape: tuple[int, ...],
        index_shape: tuple[int, ...],
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> tuple[int, ...] | None:
        if not index_shape:
            return None
        batch_dims = _onnx_int_attribute(node, "batch_dims")
        if resolve_attribute is not None:
            for attribute in getattr(node, "attribute", ()):
                if attribute.name != "batch_dims":
                    continue
                resolved_attribute = resolve_attribute(attribute)
                batch_dims = int(getattr(resolved_attribute, "i", batch_dims)) if resolved_attribute is not None else 0
                break
        index_depth = index_shape[-1]
        if (
            batch_dims < 0
            or batch_dims >= len(index_shape)
            or index_depth <= 0
            or batch_dims + index_depth > len(input_shape)
        ):
            return None
        return (*index_shape[:-1], *input_shape[batch_dims + index_depth :])

    def scan_input_shape(
        constants: dict[str, Any],
        known_shapes: dict[str, tuple[int, ...]],
        value_name: str,
        trusted_shape_names: set[str],
        untrusted_shape_names: set[str] | None = None,
    ) -> tuple[int, ...] | None:
        if value_name in (untrusted_shape_names or set()):
            return None
        initializer_shape = constant_initializer_shape(constants, value_name)
        if initializer_shape is not None:
            return initializer_shape
        if value_name not in trusted_shape_names:
            return None
        return known_shapes.get(value_name)

    def scan_may_skip_body(
        node: Any,
        constants: dict[str, Any],
        graph_input_names: set[str],
        known_shapes: dict[str, tuple[int, ...]] | None = None,
        trusted_shape_names: set[str] | None = None,
        untrusted_shape_names: set[str] | None = None,
        *,
        scan_input_axes: tuple[int, ...] | None = None,
        scan_input_offset: int = 0,
        num_scan_inputs: int | None = None,
    ) -> bool:
        num_scan_inputs = (
            _onnx_int_attribute(node, "num_scan_inputs", 1) if num_scan_inputs is None else num_scan_inputs
        )
        if num_scan_inputs <= 0:
            return True
        scan_input_start = max(len(node.input) - num_scan_inputs, scan_input_offset)
        scan_inputs = [str(input_name) for input_name in node.input[scan_input_start:] if input_name]
        if len(scan_inputs) < num_scan_inputs:
            return True
        constant_sequence_lens: tuple[int, ...] | None = None
        if scan_input_offset and node.input:
            sequence_lens_input = str(node.input[0] or "")
            if sequence_lens_input:
                if graph_input_is_runtime_overridable(sequence_lens_input, graph_input_names, constants):
                    return True
                constant_sequence_lens = constant_int64_vector_values(constants.get(sequence_lens_input))
                if constant_sequence_lens is None or any(length <= 0 for length in constant_sequence_lens):
                    return True
        scan_input_axes = (
            scan_input_axes
            if scan_input_axes is not None
            else _onnx_int_sequence_attribute(node, "scan_input_axes") or ()
        )
        known_shapes = known_shapes or {}
        trusted_shape_names = trusted_shape_names or set()
        for input_index, scan_input in enumerate(scan_inputs):
            shape = scan_input_shape(constants, known_shapes, scan_input, trusted_shape_names, untrusted_shape_names)
            if not shape:
                if constant_sequence_lens:
                    continue
                return True
            default_axis = 1 if scan_input_offset else 0
            raw_axis = scan_input_axes[input_index] if input_index < len(scan_input_axes) else default_axis
            axis = raw_axis if raw_axis >= 0 else len(shape) + raw_axis
            if axis < 0 or axis >= len(shape):
                return True
            if shape[axis] <= 0:
                return True
        return False

    def scan_may_repeat_body(
        node: Any,
        constants: dict[str, Any],
        graph_input_names: set[str],
        known_shapes: dict[str, tuple[int, ...]] | None = None,
        trusted_shape_names: set[str] | None = None,
        untrusted_shape_names: set[str] | None = None,
        *,
        scan_input_axes: tuple[int, ...] | None = None,
        scan_input_offset: int = 0,
        num_scan_inputs: int | None = None,
    ) -> bool:
        num_scan_inputs = (
            _onnx_int_attribute(node, "num_scan_inputs", 1) if num_scan_inputs is None else num_scan_inputs
        )
        if num_scan_inputs <= 0:
            return True
        known_shapes = known_shapes or {}
        scan_input_start = max(len(node.input) - num_scan_inputs, scan_input_offset)
        scan_inputs = [str(input_name) for input_name in node.input[scan_input_start:] if input_name]
        if len(scan_inputs) < num_scan_inputs:
            return True
        constant_sequence_lens: tuple[int, ...] | None = None
        if scan_input_offset and node.input:
            sequence_lens_input = str(node.input[0] or "")
            if sequence_lens_input:
                if graph_input_is_runtime_overridable(sequence_lens_input, graph_input_names, constants):
                    return True
                constant_sequence_lens = constant_int64_vector_values(constants.get(sequence_lens_input))
                if constant_sequence_lens is not None:
                    if any(length < 0 for length in constant_sequence_lens):
                        return True
                    if max(constant_sequence_lens, default=0) <= 1:
                        return False
        scan_input_axes = (
            scan_input_axes
            if scan_input_axes is not None
            else _onnx_int_sequence_attribute(node, "scan_input_axes") or ()
        )
        trusted_shape_names = trusted_shape_names or set()
        for input_index, scan_input in enumerate(scan_inputs):
            shape = scan_input_shape(constants, known_shapes, scan_input, trusted_shape_names, untrusted_shape_names)
            if not shape:
                return True
            default_axis = 1 if scan_input_offset else 0
            raw_axis = scan_input_axes[input_index] if input_index < len(scan_input_axes) else default_axis
            axis = raw_axis if raw_axis >= 0 else len(shape) + raw_axis
            if axis < 0 or axis >= len(shape):
                return True
            if shape[axis] <= 0 or shape[axis] > 1:
                return True
        return False

    def is_rank_gap_promoting_operator(node: Any) -> bool:
        return (
            getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
            and node.op_type in _RANK_GAP_PROMOTING_OPERATORS
        )

    def scan_sequence_lens_input_offset(node: Any, opset_versions: dict[str, int]) -> int:
        if node.op_type != "Scan":
            return 0
        domain = str(getattr(node, "domain", "") or "")
        if domain not in _STANDARD_NEURAL_NETWORK_DOMAINS:
            return 0
        version = opset_versions.get(domain)
        if version is None and domain in {"", "ai.onnx"}:
            version = opset_versions.get("ai.onnx" if domain == "" else "")
        if version is None:
            return 0
        return 1 if version <= 8 else 0

    def control_flow_subgraph_state_output_index(
        node: Any,
        parent_input_index: int,
        opset_versions: dict[str, int],
    ) -> int:
        if node.op_type == "Loop":
            return parent_input_index - 1
        if node.op_type == "Scan":
            return parent_input_index - scan_sequence_lens_input_offset(node, opset_versions)
        return -1

    def mapped_node_outputs(
        body_outputs: list[str],
        output_indexes: set[int],
        *,
        graph_output_offset: int = 0,
    ) -> set[str]:
        if not output_indexes:
            return set()
        mapped_outputs: set[str] = set()
        for output_index in output_indexes:
            output_index -= graph_output_offset
            if output_index < 0:
                continue
            if output_index >= len(body_outputs):
                return set(body_outputs)
            mapped_outputs.add(body_outputs[output_index])
        return mapped_outputs

    def control_flow_output_offset(node: Any) -> int:
        return 1 if node.op_type == "Loop" else 0

    def resolved_onnx_int_attribute(
        node: Any,
        name: str,
        default: int = 0,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> int:
        if resolve_attribute is None:
            return _onnx_int_attribute(node, name, default)
        for attribute in getattr(node, "attribute", ()):
            if attribute.name != name:
                continue
            resolved_attribute = resolve_attribute(attribute)
            return int(getattr(resolved_attribute, "i", default)) if resolved_attribute is not None else default
        return default

    def scan_stacked_output_start(
        node: Any,
        opset_versions: dict[str, int],
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> int:
        if node.op_type != "Scan" or getattr(node, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS:
            return len(getattr(node, "output", ()))
        scan_input_offset = scan_sequence_lens_input_offset(node, opset_versions)
        num_scan_inputs = resolved_onnx_int_attribute(
            node,
            "num_scan_inputs",
            1,
            resolve_attribute=resolve_attribute,
        )
        if num_scan_inputs <= 0:
            return len(getattr(node, "output", ()))
        return max(len(getattr(node, "input", ())) - scan_input_offset - num_scan_inputs, 0)

    def control_flow_graph_output_is_stacked_output(
        node: Any,
        graph_output_index: int,
        opset_versions: dict[str, int],
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> bool:
        if getattr(node, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS:
            return False
        parent_output_index = graph_output_index - control_flow_output_offset(node)
        if parent_output_index < 0:
            return False
        if node.op_type == "Loop":
            return parent_output_index >= max(len(getattr(node, "input", ())) - 2, 0)
        if node.op_type == "Scan":
            return parent_output_index >= scan_stacked_output_start(
                node,
                opset_versions,
                resolve_attribute=resolve_attribute,
            )
        return False

    cache_fingerprints: dict[int, tuple[Any, tuple[str, str]]] = {}
    semantic_mapping_keys: dict[
        tuple[int, tuple[str, ...] | None],
        tuple[Any, int, tuple[tuple[str, str, str], ...]],
    ] = {}
    trusted_shape_keys: dict[
        tuple[int, tuple[str, ...] | None],
        tuple[Any, int, tuple[tuple[str, tuple[int, ...]], ...]],
    ] = {}
    rank_reentry_constant_name_cache: dict[tuple[int, int], frozenset[str]] = {}

    def semantic_cache_fingerprint(value: Any) -> tuple[str, str]:
        return semantic_cache_fingerprint_with_owner(value, retain_owner=True)

    def semantic_cache_fingerprint_with_owner(value: Any, *, retain_owner: bool) -> tuple[str, str]:
        value_id = id(value)
        if retain_owner:
            cached_fingerprint = cache_fingerprints.get(value_id)
            if cached_fingerprint is not None and cached_fingerprint[0] is value:
                return cached_fingerprint[1]
        type_name = f"{type(value).__module__}.{type(value).__qualname__}"
        byte_size = getattr(value, "ByteSize", None)
        if callable(byte_size):
            try:
                protobuf_size = int(byte_size())
            except Exception:
                protobuf_size = None
            if protobuf_size is not None and protobuf_size > _ONNX_SEMANTIC_FINGERPRINT_MAX_SERIALIZED_BYTES:
                descriptor = getattr(value, "DESCRIPTOR", None)
                descriptor_name = str(getattr(descriptor, "full_name", ""))
                payload = (
                    f"protobuf:{descriptor_name}:bytes={protobuf_size}:owner={value_id}".encode(
                        "utf-8", errors="surrogatepass"
                    )
                    if retain_owner
                    else f"protobuf:{descriptor_name}:bytes={protobuf_size}:bounded".encode(
                        "utf-8", errors="surrogatepass"
                    )
                )
                fingerprint = (type_name, hashlib.sha256(payload).hexdigest())
                if retain_owner:
                    cache_fingerprints[value_id] = (value, fingerprint)
                return fingerprint
        serializer = getattr(value, "SerializeToString", None)
        try:
            if callable(serializer):
                try:
                    payload = serializer(deterministic=True)
                except TypeError:
                    payload = serializer()
            elif isinstance(value, (bytes, bytearray, memoryview)):
                payload = bytes(value)
            else:
                payload = repr(value).encode("utf-8", errors="surrogatepass")
        except Exception:
            payload = repr(value).encode("utf-8", errors="surrogatepass")
        fingerprint = (type_name, hashlib.sha256(payload).hexdigest())
        if retain_owner:
            cache_fingerprints[value_id] = (value, fingerprint)
        return fingerprint

    dependency_names_key_cache: dict[frozenset[str], tuple[str, ...]] = {}

    def dependency_names_cache_key(names: frozenset[str]) -> tuple[str, ...]:
        cached_key = dependency_names_key_cache.get(names)
        if cached_key is not None:
            return cached_key
        key = tuple(sorted(str(name) for name in names))
        dependency_names_key_cache[names] = key
        return key

    def semantic_mapping_cache_key(
        mapping: dict[str, Any] | None,
        names: frozenset[str] | None = None,
    ) -> tuple[tuple[str, str, str], ...]:
        if not mapping:
            return ()
        names_key = dependency_names_cache_key(names) if names is not None else None
        owner_key = (id(mapping), names_key)
        cached_mapping_key = semantic_mapping_keys.get(owner_key)
        if (
            cached_mapping_key is not None
            and cached_mapping_key[0] is mapping
            and cached_mapping_key[1] == len(mapping)
        ):
            return cached_mapping_key[2]
        items = (
            tuple(sorted((str(name), value) for name, value in mapping.items()))
            if names_key is None
            else tuple((name, mapping[name]) for name in names_key if name in mapping)
        )
        cache_key = tuple((str(name), *semantic_cache_fingerprint(value)) for name, value in items)
        semantic_mapping_keys[owner_key] = (mapping, len(mapping), cache_key)
        return cache_key

    def attribute_binding_cache_key(attribute_bindings: dict[str, Any] | None) -> tuple[tuple[str, str, str], ...]:
        if not attribute_bindings:
            return ()
        return semantic_mapping_cache_key(attribute_bindings)

    def constant_binding_cache_key(
        constants: dict[str, Any],
        names: frozenset[str],
    ) -> tuple[tuple[str, str, str], ...]:
        return semantic_mapping_cache_key(constants, names)

    def trusted_context_shape_cache_key(
        trusted_context_shapes: dict[str, tuple[int, ...]],
        names: frozenset[str] | None = None,
    ) -> tuple[tuple[str, tuple[int, ...]], ...]:
        if not trusted_context_shapes:
            return ()
        names_key = dependency_names_cache_key(names) if names is not None else None
        owner_key = (id(trusted_context_shapes), names_key)
        cached_key = trusted_shape_keys.get(owner_key)
        if (
            cached_key is not None
            and cached_key[0] is trusted_context_shapes
            and cached_key[1] == len(trusted_context_shapes)
        ):
            return cached_key[2]
        cache_key = (
            tuple(sorted((str(name), tuple(shape)) for name, shape in trusted_context_shapes.items()))
            if names_key is None
            else tuple(
                (name, tuple(trusted_context_shapes[name])) for name in names_key if name in trusted_context_shapes
            )
        )
        trusted_shape_keys[owner_key] = (trusted_context_shapes, len(trusted_context_shapes), cache_key)
        return cache_key

    def opset_cache_key(opset_versions: dict[str, int]) -> tuple[tuple[str, int], ...]:
        return tuple(sorted((str(domain), int(version)) for domain, version in opset_versions.items()))

    def bound_control_flow_graph_inputs(
        node: Any,
        nested_graph: Any,
        source_names: set[str],
        opset_versions: dict[str, int],
    ) -> dict[str, str]:
        if node.op_type == "Loop":
            input_pairs = zip(node.input[2:], nested_graph.input[2:], strict=False)
        elif node.op_type == "Scan":
            scan_input_offset = scan_sequence_lens_input_offset(node, opset_versions)
            input_pairs = zip(node.input[scan_input_offset:], nested_graph.input, strict=False)
        else:
            return {}
        bindings: dict[str, str] = {}
        for parent_input, graph_input in input_pairs:
            parent_name = str(parent_input)
            graph_input_name = _onnx_value_name(graph_input)
            if parent_name in source_names and graph_input_name:
                bindings[graph_input_name] = parent_name
        return bindings

    def bound_control_flow_graph_constant_inputs(
        node: Any,
        nested_graph: Any,
        inherited_constants: dict[str, Any],
        opset_versions: dict[str, int],
        local_constants: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        local_constants = local_constants or {}
        if node.op_type == "Loop":
            input_pairs = zip(node.input[2:], nested_graph.input[2:], strict=False)
        elif node.op_type == "Scan":
            return {}
        else:
            return {}
        bindings: dict[str, str] = {}
        for parent_input, graph_input in input_pairs:
            parent_name = str(parent_input)
            graph_input_name = _onnx_value_name(graph_input)
            if (parent_name in inherited_constants or parent_name in local_constants) and graph_input_name:
                bindings[graph_input_name] = parent_name
        return bindings

    def rank_reentry_constant_names(subgraph: Any, *, depth: int = 0) -> frozenset[str]:
        cache_key = (id(subgraph), depth)
        if cache_key in rank_reentry_constant_name_cache:
            return rank_reentry_constant_name_cache[cache_key]
        if depth > 6:
            return frozenset()
        names: set[str] = set()
        for body_node in getattr(subgraph, "node", ()):
            if getattr(body_node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS and (
                body_node.op_type in {"Expand", "Gather", "GatherND", "Reshape", "Squeeze", "Unsqueeze"}
                or body_node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS
                or body_node.op_type == "Pow"
            ):
                input_indexes = (
                    range(1, len(getattr(body_node, "input", ())))
                    if body_node.op_type in {"Expand", "Gather", "GatherND", "Reshape", "Squeeze", "Unsqueeze"}
                    else range(len(getattr(body_node, "input", ())))
                )
                names.update(
                    str(body_node.input[input_index]) for input_index in input_indexes if body_node.input[input_index]
                )
            function_key = (
                str(getattr(body_node, "domain", "")),
                str(getattr(body_node, "op_type", "")),
                str(getattr(body_node, "overload", "")),
            )
            function = functions.get(function_key)
            if function is not None:
                function_names = rank_reentry_constant_names(function, depth=depth + 1)
                if function_names:
                    input_bindings = {
                        _onnx_value_name(function.input[input_index]): str(actual_name)
                        for input_index, actual_name in enumerate(getattr(body_node, "input", ()))
                        if input_index < len(getattr(function, "input", ()))
                    }
                    names.update(input_bindings.get(name, name) for name in function_names)
            for attribute in getattr(body_node, "attribute", ()):
                for nested_graph in _iter_attribute_graphs(attribute):
                    if body_node.op_type == "Loop":
                        names.update(
                            str(input_name) for input_name in getattr(body_node, "input", ())[:2] if input_name
                        )
                        names.update(graph_external_reference_names(nested_graph))
                    names.update(rank_reentry_constant_names(nested_graph, depth=depth + 1))
        result = frozenset(names)
        rank_reentry_constant_name_cache[cache_key] = result
        return result

    reentry_promotion_cache: dict[tuple[Any, ...], frozenset[int]] = {}
    reentry_shape_cache: dict[tuple[Any, ...], dict[int, tuple[int, ...]]] = {}
    reentry_promotion_in_progress: set[tuple[Any, ...]] = set()
    reentry_external_context_shape_cache: dict[tuple[Any, ...], dict[str, tuple[int, ...]]] = {}
    graph_output_dependency_cache: dict[
        tuple[int, tuple[int, ...] | None, tuple[tuple[str, str, str], ...]], frozenset[str]
    ] = {}
    graph_value_dependency_cache: dict[
        tuple[int, tuple[str, ...], tuple[tuple[str, str, str], ...]], tuple[Any, frozenset[str]]
    ] = {}
    graph_node_direct_dependency_cache: dict[
        tuple[int, tuple[tuple[str, str, str], ...]], tuple[Any, frozenset[str]]
    ] = {}
    node_input_names_cache: dict[int, tuple[Any, list[str]]] = {}
    node_input_slots_cache: dict[int, tuple[Any, list[str]]] = {}
    node_output_names_cache: dict[int, tuple[Any, list[str]]] = {}
    graph_output_producer_cache: dict[int, tuple[Any, dict[str, frozenset[int]]]] = {}
    dependency_collection_limit_marker = "\0modelaudit_dependency_collection_limit\0"

    def dependency_names_exceeded_limit(dependency_names: frozenset[str]) -> bool:
        return dependency_collection_limit_marker in dependency_names

    def merge_dependency_names(target: set[str], dependency_names: Iterable[str]) -> bool:
        for dependency_name in dependency_names:
            if dependency_name:
                target.add(str(dependency_name))
            if len(target) > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK:
                target.add(dependency_collection_limit_marker)
                return True
        return dependency_collection_limit_marker in target

    def node_input_names(node: Any) -> list[str]:
        cache_key = id(node)
        cached = node_input_names_cache.get(cache_key)
        if cached is not None and cached[0] is node:
            return cached[1]
        names = [str(input_name) for input_name in getattr(node, "input", ()) if input_name]
        node_input_names_cache[cache_key] = (node, names)
        return names

    def node_input_slots(node: Any) -> list[str]:
        cache_key = id(node)
        cached = node_input_slots_cache.get(cache_key)
        if cached is not None and cached[0] is node:
            return cached[1]
        slots = [str(input_name) for input_name in getattr(node, "input", ())]
        node_input_slots_cache[cache_key] = (node, slots)
        return slots

    def node_output_names(node: Any) -> list[str]:
        cache_key = id(node)
        cached = node_output_names_cache.get(cache_key)
        if cached is not None and cached[0] is node:
            return cached[1]
        names = [str(output_name) for output_name in getattr(node, "output", ()) if output_name]
        node_output_names_cache[cache_key] = (node, names)
        return names

    def graph_output_producer_ids_by_name(subgraph: Any) -> dict[str, frozenset[int]]:
        cache_key = id(subgraph)
        cached = graph_output_producer_cache.get(cache_key)
        if cached is not None and cached[0] is subgraph:
            return cached[1]
        producers: dict[str, set[int]] = {}
        for node in getattr(subgraph, "node", ()):
            node_id = id(node)
            for output_name in node_output_names(node):
                producers.setdefault(output_name, set()).add(node_id)
        frozen = {name: frozenset(node_ids) for name, node_ids in producers.items()}
        graph_output_producer_cache[cache_key] = (subgraph, frozen)
        return frozen

    def graph_nodes_producing_names(subgraph: Any, dependency_names: Iterable[str]) -> frozenset[int]:
        producers = graph_output_producer_ids_by_name(subgraph)
        node_ids: set[int] = set()
        for dependency_name in dependency_names:
            node_ids.update(producers.get(dependency_name, ()))
        return frozenset(node_ids)

    def graph_node_direct_dependency_names(
        node: Any,
        local_attribute_bindings: dict[str, Any],
    ) -> frozenset[str]:
        attribute_key = attribute_binding_cache_key(local_attribute_bindings)
        cache_key = (id(node), attribute_key)
        cached = graph_node_direct_dependency_cache.get(cache_key)
        if cached is not None and cached[0] is node:
            return cached[1]
        dependencies: set[str] = set()
        merge_dependency_names(dependencies, getattr(node, "input", ()))
        if not dependency_names_exceeded_limit(frozenset(dependencies)):
            for attribute in getattr(node, "attribute", ()):
                reference_name = str(getattr(attribute, "ref_attr_name", ""))
                resolved_attribute = local_attribute_bindings.get(reference_name) if reference_name else attribute
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    if merge_dependency_names(dependencies, graph_external_reference_names(nested_graph)):
                        break
                if dependency_collection_limit_marker in dependencies:
                    break
        result = frozenset(dependencies)
        graph_node_direct_dependency_cache[cache_key] = (node, result)
        return result

    def graph_output_dependency_names(
        subgraph: Any,
        output_indexes: Iterable[int] | None = None,
        attribute_bindings: dict[str, Any] | None = None,
    ) -> frozenset[str]:
        graph_outputs = getattr(subgraph, "output", ())
        output_index_key = None if output_indexes is None else tuple(sorted(set(output_indexes)))
        cache_key = (id(subgraph), output_index_key, attribute_binding_cache_key(attribute_bindings))
        if cache_key in graph_output_dependency_cache:
            return graph_output_dependency_cache[cache_key]
        local_attribute_bindings = attribute_bindings or {}
        if output_index_key is None:
            selected_outputs = graph_outputs
        else:
            selected_outputs = tuple(
                graph_outputs[index] for index in output_index_key if 0 <= index < len(graph_outputs)
            )
        dependencies = {name for output in selected_outputs if (name := _onnx_value_name(output))}
        for body_node in reversed(getattr(subgraph, "node", ())):
            body_outputs = {str(output_name) for output_name in getattr(body_node, "output", ()) if output_name}
            if not body_outputs & dependencies:
                continue
            if merge_dependency_names(
                dependencies, graph_node_direct_dependency_names(body_node, local_attribute_bindings)
            ):
                break
        result = frozenset(dependencies)
        graph_output_dependency_cache[cache_key] = result
        return result

    def graph_value_dependency_names(
        subgraph: Any,
        value_names: Iterable[str],
        attribute_bindings: dict[str, Any] | None = None,
    ) -> frozenset[str]:
        value_name_key = tuple(sorted(str(value_name) for value_name in value_names if value_name))
        attribute_key = attribute_binding_cache_key(attribute_bindings)
        cache_key = (id(subgraph), value_name_key, attribute_key)
        cached_dependencies = graph_value_dependency_cache.get(cache_key)
        if cached_dependencies is not None and cached_dependencies[0] is subgraph:
            return cached_dependencies[1]
        local_attribute_bindings = attribute_bindings or {}
        dependencies = set(value_name_key)
        for body_node in reversed(getattr(subgraph, "node", ())):
            body_outputs = {str(output_name) for output_name in getattr(body_node, "output", ()) if output_name}
            if not body_outputs & dependencies:
                continue
            if merge_dependency_names(
                dependencies,
                graph_node_direct_dependency_names(body_node, local_attribute_bindings),
            ):
                break
        result = frozenset(dependencies)
        graph_value_dependency_cache[cache_key] = (subgraph, result)
        return result

    def reentry_shape_preserving_unary_operator(node: Any, inputs: Sequence[str]) -> bool:
        return (
            getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
            and node.op_type in (_SHAPE_PRESERVING_UNARY_RANK_OPERATORS | {"Cast", "Identity"})
            and (len(inputs) == 1 or node.op_type in {"Clip", "Dropout"})
        )

    def subgraph_analysis_work_exceeds_limit(
        subgraph: Any,
        dependency_names: frozenset[str] | None = None,
        *,
        include_potential_weight_consumers: bool = False,
        opset_versions: dict[str, int] | None = None,
        attribute_bindings: dict[str, Any] | None = None,
    ) -> bool:
        graph_nodes = tuple(getattr(subgraph, "node", ()))
        potential_weight_consumer_seen = False
        potential_weight_consumer_input_edges = 0
        local_attribute_bindings = attribute_bindings or {}

        def resolve_work_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return local_attribute_bindings.get(reference_name) if reference_name else attribute

        def node_may_have_potential_weight_input(
            node: Any,
            *,
            is_model_local_function: bool,
            is_registered_standard_operator: bool,
        ) -> bool:
            domain = getattr(node, "domain", "")
            if (
                domain in _STANDARD_NEURAL_NETWORK_DOMAINS
                and is_registered_standard_operator
                and not is_model_local_function
            ):
                return (
                    node.op_type in {"Conv", "ConvTranspose", "Einsum", "Gather", "Gemm", "MatMul", "PRelu"}
                    or node.op_type in _RECURRENT_WEIGHT_OPERATORS
                )
            return True

        live_nodes: list[Any]
        if dependency_names is None:
            live_nodes = list(graph_nodes)
        elif dependency_names_exceeded_limit(dependency_names):
            return True
        else:
            live_node_ids = graph_nodes_producing_names(subgraph, dependency_names)
            live_nodes = []
            for node in graph_nodes:
                if id(node) in live_node_ids:
                    live_nodes.append(node)
                    continue
                if not include_potential_weight_consumers:
                    continue
                function_key = (
                    str(getattr(node, "domain", "")),
                    str(getattr(node, "op_type", "")),
                    str(getattr(node, "overload", "")),
                )
                is_model_local_function = function_key in functions
                is_registered_standard_operator = is_model_local_function or has_registered_standard_operator(
                    node,
                    opset_versions or {},
                )
                function = functions.get(function_key)
                if function is not None:
                    function_attributes = bound_function_attributes(function, node, resolve_work_attribute)
                    function_versions = function_opset_versions(function, opset_versions or {})
                    if subgraph_has_potential_weight_consumer(
                        function,
                        function_versions,
                        attribute_bindings=function_attributes,
                    ):
                        potential_weight_consumer_seen = True
                        potential_weight_consumer_input_edges += len(node_input_names(node))
                    continue
                if not node_may_have_potential_weight_input(
                    node,
                    is_model_local_function=is_model_local_function,
                    is_registered_standard_operator=is_registered_standard_operator,
                ):
                    continue
                input_count = len(node_input_names(node))
                node_is_potential_weight_consumer = any(
                    _onnx_potential_weight_input(
                        node,
                        input_index,
                        is_model_local_function=is_model_local_function,
                        is_registered_standard_operator=is_registered_standard_operator,
                    )
                    for input_index in range(input_count)
                )
                if node_is_potential_weight_consumer:
                    potential_weight_consumer_seen = True
                    potential_weight_consumer_input_edges += input_count
        graph_node_count = len(live_nodes)
        graph_input_count = len(getattr(subgraph, "input", ()))
        node_input_edges = sum(len(getattr(node, "input", ())) for node in live_nodes)
        work = graph_node_count * max(graph_input_count, 1) + node_input_edges
        if potential_weight_consumer_seen:
            potential_work = len(graph_nodes) * max(graph_input_count, 1) + potential_weight_consumer_input_edges
            if potential_work > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK:
                return True
        return work > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK

    def subgraph_reenters_state_with_rank_promotion(
        subgraph: Any,
        graph_input_name: str,
        graph_output_index: int,
        constants: dict[str, Any],
        opset_versions: dict[str, int],
        graph_input_shape: tuple[int, ...] | None,
        attribute_bindings: dict[str, Any] | None = None,
        bound_input_constants: dict[str, Any] | None = None,
        trusted_context_shapes: dict[str, tuple[int, ...]] | None = None,
        output_shapes_out: dict[int, tuple[int, ...]] | None = None,
        related_graph_input_shapes: dict[str, tuple[int, ...] | None] | None = None,
        output_dependency_names_override: frozenset[str] | None = None,
        restorable_output_indexes_override: frozenset[int] | None = None,
        promoted_outputs_out: set[int] | None = None,
        related_graph_input_shapes_cache_key: tuple[tuple[str, tuple[int, ...] | None], ...] | None = None,
        *,
        depth: int = 0,
    ) -> bool:
        if depth > 6:
            return True
        graph_outputs = getattr(subgraph, "output", ())
        if graph_output_index < 0 or graph_output_index >= len(graph_outputs):
            return False
        graph_output_name = _onnx_value_name(graph_outputs[graph_output_index])
        if not graph_output_name:
            return False
        if output_dependency_names_override is None:
            output_dependency_names = graph_output_dependency_names(
                subgraph,
                (graph_output_index,),
                attribute_bindings=attribute_bindings,
            )
        else:
            output_dependency_names = output_dependency_names_override
        if len(graph_outputs) > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_OUTPUTS or subgraph_analysis_work_exceeds_limit(
            subgraph,
            output_dependency_names,
            include_potential_weight_consumers=True,
            opset_versions=opset_versions,
            attribute_bindings=attribute_bindings,
        ):
            return True
        restorable_output_indexes = (
            restorable_output_indexes_override
            if restorable_output_indexes_override is not None
            else frozenset({graph_output_index})
        )
        trusted_context_shapes = trusted_context_shapes or {}
        related_graph_input_shapes = related_graph_input_shapes or {}
        if related_graph_input_shapes_cache_key is None:
            related_graph_input_shapes_cache_key = tuple(sorted(related_graph_input_shapes.items()))
        cache_key = (
            id(subgraph),
            graph_input_name,
            graph_input_shape,
            dependency_names_cache_key(output_dependency_names),
            tuple(sorted(restorable_output_indexes)),
            trusted_context_shape_cache_key(trusted_context_shapes, output_dependency_names),
            related_graph_input_shapes_cache_key,
            opset_cache_key(opset_versions),
            attribute_binding_cache_key(attribute_bindings),
            constant_binding_cache_key(constants, rank_reentry_constant_names(subgraph)),
            depth,
        )
        if cache_key in reentry_promotion_cache:
            promoted_output_indexes = reentry_promotion_cache[cache_key]
            if promoted_outputs_out is not None:
                promoted_outputs_out.update(promoted_output_indexes)
            if output_shapes_out is not None:
                output_shapes_out.update(reentry_shape_cache.get(cache_key, {}))
            return graph_output_index in promoted_output_indexes
        if cache_key in reentry_promotion_in_progress:
            return True
        reentry_promotion_in_progress.add(cache_key)
        local_attribute_bindings = attribute_bindings or {}

        def resolve_reentry_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return local_attribute_bindings.get(reference_name) if reference_name else attribute

        subgraph_constants = graph_initializer_constants(subgraph, constants)
        if bound_input_constants:
            subgraph_constants.update(bound_input_constants)
        tainted = {graph_input_name}
        tainted_shapes = {graph_input_name: graph_input_shape} if graph_input_shape is not None else {}
        promoted: set[str] = set()

        def reentry_input_shape(input_name: str) -> tuple[int, ...] | None:
            if input_name in tainted_shapes:
                return tainted_shapes[input_name]
            if input_name in related_graph_input_shapes:
                return related_graph_input_shapes[input_name]
            initializer_shape = constant_initializer_shape(subgraph_constants, input_name)
            if initializer_shape is not None:
                return initializer_shape
            return trusted_context_shapes.get(input_name)

        output_dependency_node_ids = graph_nodes_producing_names(subgraph, output_dependency_names)
        for body_node in getattr(subgraph, "node", ()):
            body_outputs = node_output_names(body_node)
            if not body_outputs:
                continue
            body_outputs_feed_selected_output = id(body_node) in output_dependency_node_ids
            if not body_outputs_feed_selected_output:
                continue
            body_inputs = node_input_names(body_node)
            if getattr(body_node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS and body_node.op_type == "Constant":
                constant_tensor = resolved_constant_node_tensor(body_node, resolve_reentry_attribute)
                if constant_tensor is not None:
                    for output_name in body_outputs:
                        subgraph_constants[output_name] = constant_tensor
                        tainted.discard(output_name)
                        promoted.discard(output_name)
                        tainted_shapes.pop(output_name, None)
            function_key = (
                str(getattr(body_node, "domain", "")),
                str(getattr(body_node, "op_type", "")),
                str(getattr(body_node, "overload", "")),
            )
            function = functions.get(function_key)
            is_model_local_function = function is not None
            is_registered_standard_operator = is_model_local_function or has_registered_standard_operator(
                body_node,
                opset_versions,
            )
            standard_reentry_operator = (
                is_registered_standard_operator
                and not is_model_local_function
                and getattr(body_node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
            )
            is_shape_query = standard_reentry_operator and body_node.op_type in {"Shape", "Size"}
            data_input_promoted = bool(body_inputs and body_inputs[0] in promoted)
            data_input_tainted = bool(body_inputs and body_inputs[0] in tainted)
            any_promoted = any(input_name in promoted for input_name in body_inputs)
            any_tainted = any(input_name in tainted for input_name in body_inputs)
            data_input_shape = reentry_input_shape(body_inputs[0]) if body_inputs else None
            index_input_shape = reentry_input_shape(body_inputs[1]) if len(body_inputs) > 1 else None
            if (
                index_input_shape is None
                and body_node.op_type in {"Gather", "GatherElements", "GatherND"}
                and len(body_inputs) > 1
            ):
                index_input_shape = constant_initializer_shape(subgraph_constants, body_inputs[1])
            input_shapes_by_name = {input_name: reentry_input_shape(input_name) for input_name in body_inputs}
            elementwise_operator = standard_reentry_operator and (
                body_node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS or body_node.op_type == "Pow"
            )
            promotion_input_tainted = (
                any_tainted
                if elementwise_operator
                or (standard_reentry_operator and body_node.op_type in {"Einsum", "MatMul", "OneHot"})
                else data_input_tainted
            )
            promotion_input_shapes = (
                [input_shapes_by_name.get(input_name) for input_name in body_inputs if input_name in tainted]
                if elementwise_operator
                else None
            )
            data_input_may_promote = (
                standard_reentry_operator
                and promotion_input_tainted
                and operator_output_may_have_weight_rank(
                    body_node,
                    input_shape=data_input_shape,
                    index_shape=index_input_shape,
                    constants=subgraph_constants,
                    resolve_attribute=resolve_reentry_attribute,
                    input_shapes_by_name=input_shapes_by_name,
                    promotion_input_shapes=promotion_input_shapes,
                )
            )
            function_promoted_outputs: set[str] = set()
            function_tainted_outputs: set[str] = set()
            function_output_shapes: dict[int, tuple[int, ...]] = {}
            nested_promoted_outputs: set[str] = set()
            if function is not None and (any_tainted or body_outputs_feed_selected_output):
                function_attributes = bound_function_attributes(function, body_node, resolve_reentry_attribute)
                function_constants, function_bound_input_constants = bound_function_constants(
                    function,
                    body_inputs,
                    subgraph_constants,
                )
                function_versions = function_opset_versions(function, opset_versions)
                function_context_shapes: dict[str, tuple[int, ...]] = {}
                for input_index, input_name in enumerate(body_inputs):
                    if input_index >= len(getattr(function, "input", ())):
                        continue
                    function_input_name = _onnx_value_name(function.input[input_index])
                    input_shape = input_shapes_by_name.get(input_name)
                    if function_input_name and input_shape is not None:
                        function_context_shapes[function_input_name] = input_shape
                function_tainted_inputs: dict[str, tuple[int, ...] | None] = {}
                for input_index, input_name in enumerate(body_inputs):
                    if input_name not in tainted or input_index >= len(getattr(function, "input", ())):
                        continue
                    function_input_name = _onnx_value_name(function.input[input_index])
                    if function_input_name:
                        function_tainted_inputs[function_input_name] = tainted_shapes.get(input_name)
                downstream_live_function_output_indexes = {
                    output_index
                    for output_index, output_name in enumerate(body_outputs)
                    if output_name in output_dependency_names
                }
                function_tainted_output_indexes: set[int] = set()
                if function_tainted_inputs:
                    function_tainted_output_indexes = graph_tainted_output_indexes(
                        function,
                        set(function_tainted_inputs),
                        function_versions,
                        attribute_bindings=function_attributes,
                        depth=depth + 1,
                    )
                    function_tainted_outputs.update(
                        mapped_node_outputs(
                            body_outputs,
                            function_tainted_output_indexes,
                        )
                    )
                valid_function_tainted_output_indexes = {
                    output_index
                    for output_index in function_tainted_output_indexes
                    if 0 <= output_index < len(body_outputs)
                }
                if valid_function_tainted_output_indexes or downstream_live_function_output_indexes:
                    restorable_function_output_indexes = (
                        valid_function_tainted_output_indexes | downstream_live_function_output_indexes
                    )
                    function_output_dependency_names = graph_output_dependency_names(
                        function,
                        restorable_function_output_indexes,
                        attribute_bindings=function_attributes,
                    )
                    relevant_function_inputs: dict[str, tuple[int, ...] | None] = {
                        function_input_name: function_input_shape
                        for function_input_name, function_input_shape in function_tainted_inputs.items()
                        if function_input_name in function_output_dependency_names
                    }
                    if not relevant_function_inputs and downstream_live_function_output_indexes:
                        relevant_function_inputs = {
                            function_input_name: function_input_shape
                            for function_input_name, function_input_shape in function_context_shapes.items()
                            if function_input_name in function_output_dependency_names
                        }
                    if (
                        not relevant_function_inputs
                        and downstream_live_function_output_indexes
                        and function_tainted_inputs
                    ):
                        probe_name, probe_shape = next(iter(function_tainted_inputs.items()))
                        relevant_function_inputs = {probe_name: probe_shape}
                else:
                    restorable_function_output_indexes = set()
                    function_output_dependency_names = frozenset()
                    relevant_function_inputs = {}
                if restorable_function_output_indexes:
                    function_analysis_exceeds_limit = (
                        len(restorable_function_output_indexes) * max(len(relevant_function_inputs), 1)
                        > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK
                        or len(getattr(function, "output", ())) > _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_OUTPUTS
                        or subgraph_analysis_work_exceeds_limit(
                            function,
                            function_output_dependency_names,
                            include_potential_weight_consumers=True,
                            opset_versions=function_versions,
                            attribute_bindings=function_attributes,
                        )
                    )
                    if function_analysis_exceeds_limit:
                        function_promoted_outputs.update(
                            mapped_node_outputs(
                                body_outputs,
                                valid_function_tainted_output_indexes,
                            )
                        )
                    else:
                        representative_output_index = min(restorable_function_output_indexes)
                        for function_input_name, function_input_shape in relevant_function_inputs.items():
                            function_promoted_output_indexes: set[int] = set()
                            representative_promoted = subgraph_reenters_state_with_rank_promotion(
                                function,
                                function_input_name,
                                representative_output_index,
                                function_constants,
                                function_versions,
                                function_input_shape,
                                attribute_bindings=function_attributes,
                                bound_input_constants=function_bound_input_constants,
                                trusted_context_shapes=function_context_shapes,
                                output_shapes_out=function_output_shapes,
                                output_dependency_names_override=function_output_dependency_names,
                                restorable_output_indexes_override=frozenset(restorable_function_output_indexes),
                                promoted_outputs_out=function_promoted_output_indexes,
                                depth=depth + 1,
                            )
                            if representative_promoted and not function_promoted_output_indexes:
                                function_promoted_output_indexes.update(valid_function_tainted_output_indexes)
                            function_promoted_outputs.update(
                                mapped_node_outputs(
                                    body_outputs,
                                    valid_function_tainted_output_indexes & function_promoted_output_indexes,
                                )
                            )
                for output_index, output_name in enumerate(body_outputs):
                    output_shape = function_output_shapes.get(output_index)
                    if output_shape is not None:
                        tainted_shapes[output_name] = output_shape
            for attribute in getattr(body_node, "attribute", ()):
                resolved_attribute = resolve_reentry_attribute(attribute)
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    nested_bound_input_constant_names = bound_control_flow_graph_constant_inputs(
                        body_node,
                        nested_graph,
                        constants,
                        opset_versions,
                        subgraph_constants,
                    )
                    nested_graph_inputs = bound_control_flow_graph_inputs(
                        body_node,
                        nested_graph,
                        tainted,
                        opset_versions,
                    )
                    nested_tainted_shapes = {
                        graph_input: tainted_shapes.get(parent_input)
                        for graph_input, parent_input in nested_graph_inputs.items()
                    }
                    nested_context_shapes = {
                        graph_input: shape
                        for graph_input, parent_input in nested_graph_inputs.items()
                        if (shape := reentry_input_shape(parent_input)) is not None
                    }
                    nested_external_names = graph_external_reference_names(nested_graph)
                    captured_names = nested_external_names & tainted
                    related_nested_tainted_shapes = {
                        name: shape
                        for name, shape in related_graph_input_shapes.items()
                        if name in nested_external_names
                    }
                    nested_tainted_shapes.update(
                        {captured_name: tainted_shapes.get(captured_name) for captured_name in captured_names}
                    )
                    external_context_cache_key = (
                        id(nested_graph),
                        trusted_context_shape_cache_key(trusted_context_shapes, nested_external_names),
                        constant_binding_cache_key(subgraph_constants, nested_external_names),
                        depth,
                    )
                    external_context_shapes = reentry_external_context_shape_cache.get(external_context_cache_key)
                    if external_context_shapes is None:
                        external_context_shapes = {}
                        for external_name in nested_external_names:
                            initializer_shape = constant_initializer_shape(subgraph_constants, external_name)
                            if initializer_shape is not None:
                                external_context_shapes[external_name] = initializer_shape
                            elif (trusted_shape := trusted_context_shapes.get(external_name)) is not None:
                                external_context_shapes[external_name] = trusted_shape
                        reentry_external_context_shape_cache[external_context_cache_key] = external_context_shapes
                    nested_context_shapes.update(external_context_shapes)
                    nested_context_shapes.update(
                        {
                            captured_name: shape
                            for captured_name in captured_names
                            if (shape := tainted_shapes.get(captured_name)) is not None
                        }
                    )
                    if not nested_tainted_shapes:
                        continue
                    available_nested_constants = {**constants, **subgraph_constants}
                    nested_bound_input_constants = {}
                    if body_node.op_type == "Loop" and not loop_may_repeat_body(
                        body_node,
                        available_nested_constants,
                        set(),
                    ):
                        nested_bound_input_constants = {
                            graph_input: available_nested_constants[parent_input]
                            for graph_input, parent_input in nested_bound_input_constant_names.items()
                            if parent_input in available_nested_constants
                        }
                    nested_constants = graph_initializer_constants(nested_graph, available_nested_constants)
                    nested_constants.update(nested_bound_input_constants)
                    nested_output_shapes: dict[int, tuple[int, ...]] = {}
                    nested_captured_names = set(nested_tainted_shapes)
                    related_nested_names = set(related_nested_tainted_shapes) | nested_captured_names
                    related_nested_output_indexes: set[int] | None = None
                    if related_nested_names != nested_captured_names:
                        related_nested_output_indexes = graph_tainted_output_indexes(
                            nested_graph,
                            related_nested_names,
                            opset_versions,
                            attribute_bindings=local_attribute_bindings,
                            depth=depth + 1,
                        )
                    if related_nested_output_indexes == set():
                        nested_tainted_output_indexes = set()
                    else:
                        nested_tainted_output_indexes = graph_tainted_output_indexes(
                            nested_graph,
                            nested_captured_names,
                            opset_versions,
                            attribute_bindings=local_attribute_bindings,
                            depth=depth + 1,
                        )
                    nested_output_offset = control_flow_output_offset(body_node)
                    downstream_live_nested_output_indexes = {
                        output_index + nested_output_offset
                        for output_index, output_name in enumerate(body_outputs)
                        if output_name in output_dependency_names
                    }
                    nested_tainted_output_indexes &= downstream_live_nested_output_indexes
                    if not nested_tainted_output_indexes:
                        continue
                    tainted.update(
                        mapped_node_outputs(
                            body_outputs,
                            nested_tainted_output_indexes,
                            graph_output_offset=nested_output_offset,
                        )
                    )
                    nested_promoted_output_indexes: set[int] = set()
                    for output_index in nested_tainted_output_indexes:
                        if control_flow_graph_output_is_stacked_output(
                            body_node,
                            output_index,
                            opset_versions,
                            resolve_attribute=resolve_reentry_attribute,
                        ):
                            nested_promoted_output_indexes.add(output_index)
                    nested_promotion_work_remaining = _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK
                    nested_promotion_call_work = max(len(getattr(nested_graph, "node", ())), 1)
                    for captured_name, captured_shape in nested_tainted_shapes.items():
                        if nested_promotion_work_remaining <= 0:
                            break
                        for output_index in sorted(nested_tainted_output_indexes):
                            if nested_promotion_work_remaining < nested_promotion_call_work:
                                nested_promoted_output_indexes.update(nested_tainted_output_indexes)
                                nested_promotion_work_remaining = 0
                                break
                            nested_promotion_work_remaining -= nested_promotion_call_work
                            if subgraph_reenters_state_with_rank_promotion(
                                nested_graph,
                                captured_name,
                                output_index,
                                nested_constants,
                                opset_versions,
                                captured_shape,
                                attribute_bindings=local_attribute_bindings,
                                output_shapes_out=nested_output_shapes,
                                bound_input_constants=nested_bound_input_constants,
                                trusted_context_shapes=nested_context_shapes,
                                related_graph_input_shapes=related_nested_tainted_shapes,
                                depth=depth + 1,
                            ):
                                nested_promoted_output_indexes.add(output_index)
                    nested_promoted_outputs.update(
                        mapped_node_outputs(
                            body_outputs,
                            nested_promoted_output_indexes,
                            graph_output_offset=control_flow_output_offset(body_node),
                        )
                    )
                    for output_index, output_shape in nested_output_shapes.items():
                        node_output_index = output_index - nested_output_offset
                        if 0 <= node_output_index < len(body_outputs):
                            tainted_shapes[body_outputs[node_output_index]] = output_shape
            promoted_outputs = function_promoted_outputs | nested_promoted_outputs
            body_tainted_outputs = function_tainted_outputs if function is not None else set(body_outputs)
            if (
                data_input_promoted
                or any_promoted
                or (
                    (
                        (standard_reentry_operator and is_rank_gap_promoting_operator(body_node))
                        or body_node.op_type == "Einsum"
                        or body_node.op_type == "MatMul"
                        or body_node.op_type == "OneHot"
                        or body_node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS
                        or body_node.op_type == "Pow"
                    )
                    and data_input_may_promote
                )
                or promoted_outputs
            ):
                outputs_to_promote = set(promoted_outputs)
                if data_input_promoted or any_promoted or data_input_may_promote:
                    outputs_to_promote.update(body_tainted_outputs)
                promoted.update(outputs_to_promote or body_tainted_outputs)
                tainted.update(body_tainted_outputs)
            elif any_tainted:
                tainted.update(body_tainted_outputs)
            if (
                any_tainted
                or is_shape_query
                or any(input_shapes_by_name.get(input_name) is not None for input_name in body_inputs)
            ):
                output_shape = None
                if (
                    standard_reentry_operator
                    and reentry_shape_preserving_unary_operator(body_node, body_inputs)
                    and data_input_shape is not None
                ):
                    output_shape = data_input_shape
                elif standard_reentry_operator and body_node.op_type in _RANK_PRESERVING_VARIADIC_OPERATORS:
                    concat_axis = None
                    for attribute in getattr(body_node, "attribute", ()):
                        if attribute.name != "axis":
                            continue
                        resolved_attribute = resolve_reentry_attribute(attribute)
                        concat_axis = int(getattr(resolved_attribute, "i", 0)) if resolved_attribute is not None else 0
                        break
                    output_shape = _onnx_concat_output_shape(
                        body_node,
                        (input_shapes_by_name.get(input_name) for input_name in body_inputs),
                        axis=0 if concat_axis is None else concat_axis,
                    )
                elif standard_reentry_operator and body_node.op_type == "MatMul":
                    output_shape = matmul_output_shape(
                        input_shapes_by_name.get(body_inputs[0]) if body_inputs else None,
                        input_shapes_by_name.get(body_inputs[1]) if len(body_inputs) > 1 else None,
                    )
                elif standard_reentry_operator and body_node.op_type == "OneHot":
                    output_shape = onehot_output_shape(
                        body_node,
                        input_shapes_by_name.get(body_inputs[0]) if body_inputs else None,
                        subgraph_constants,
                    )
                elif standard_reentry_operator and body_node.op_type == "Einsum":
                    output_shape = einsum_output_shape(body_node, input_shapes_by_name)
                elif standard_reentry_operator and body_node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS | {"Pow"}:
                    output_shape = broadcast_shapes(input_shapes_by_name.get(input_name) for input_name in body_inputs)
                elif standard_reentry_operator and body_node.op_type == "Expand" and data_input_shape is not None:
                    shape_name = body_inputs[1] if len(body_inputs) > 1 else ""
                    target_shape = constant_int64_vector_values(subgraph_constants.get(shape_name))
                    if target_shape is not None:
                        output_shape = broadcast_shapes((data_input_shape, target_shape))
                elif standard_reentry_operator and body_node.op_type == "Gather" and data_input_shape is not None:
                    if index_input_shape is not None:
                        gather_axis = _onnx_gather_axis(body_node, len(data_input_shape))
                        if gather_axis is not None:
                            output_shape = (
                                *data_input_shape[:gather_axis],
                                *index_input_shape,
                                *data_input_shape[gather_axis + 1 :],
                            )
                elif standard_reentry_operator and body_node.op_type == "GatherElements":
                    output_shape = index_input_shape
                elif standard_reentry_operator and body_node.op_type == "GatherND" and data_input_shape is not None:
                    if index_input_shape:
                        output_shape = gathernd_output_shape(
                            body_node,
                            input_shape=data_input_shape,
                            index_shape=index_input_shape,
                            resolve_attribute=resolve_reentry_attribute,
                        )
                elif standard_reentry_operator and body_node.op_type == "Reshape" and data_input_shape is not None:
                    shape_name = body_inputs[1] if len(body_inputs) > 1 else ""
                    shape_initializer = subgraph_constants.get(shape_name)
                    if shape_initializer is not None:
                        output_shape = _resolve_onnx_reshape_shape(
                            data_input_shape,
                            shape_initializer,
                            allowzero=bool(_onnx_int_attribute(body_node, "allowzero")),
                            onnx=onnx,
                        )
                elif standard_reentry_operator and body_node.op_type == "Unsqueeze" and data_input_shape is not None:
                    axes = _resolve_onnx_axes(
                        body_node,
                        subgraph_constants,
                        onnx=onnx,
                        resolve_attribute=resolve_reentry_attribute,
                    )
                    if axes is not None:
                        output_rank = len(data_input_shape) + len(axes)
                        normalized_axes = tuple(axis if axis >= 0 else output_rank + axis for axis in axes)
                        if (
                            normalized_axes
                            and len(set(normalized_axes)) == len(normalized_axes)
                            and all(0 <= axis < output_rank for axis in normalized_axes)
                        ):
                            source_dimensions = iter(data_input_shape)
                            output_shape = tuple(
                                1 if index in normalized_axes else next(source_dimensions)
                                for index in range(output_rank)
                            )
                elif standard_reentry_operator and body_node.op_type == "Squeeze" and data_input_shape is not None:
                    axes = _resolve_onnx_axes(
                        body_node,
                        subgraph_constants,
                        onnx=onnx,
                        resolve_attribute=resolve_reentry_attribute,
                    )
                    if axes is not None:
                        normalized_axes = tuple(axis if axis >= 0 else len(data_input_shape) + axis for axis in axes)
                        if not normalized_axes:
                            if squeeze_with_empty_axes_is_noop(body_node, axes, resolve_reentry_attribute):
                                output_shape = data_input_shape
                            else:
                                output_shape = tuple(dimension for dimension in data_input_shape if dimension != 1)
                        elif len(set(normalized_axes)) == len(normalized_axes) and all(
                            0 <= axis < len(data_input_shape) and data_input_shape[axis] == 1
                            for axis in normalized_axes
                        ):
                            squeeze_axes = set(normalized_axes)
                            output_shape = tuple(
                                dimension
                                for index, dimension in enumerate(data_input_shape)
                                if index not in squeeze_axes
                            )
                elif is_shape_query and body_node.op_type == "Shape" and data_input_shape is not None:
                    output_shape = (len(data_input_shape),)
                elif is_shape_query and body_node.op_type == "Size" and not any_tainted:
                    output_shape = ()
                if output_shape is not None:
                    for output_name in body_outputs:
                        tainted_shapes[output_name] = output_shape
            elif (
                standard_reentry_operator
                and reentry_shape_preserving_unary_operator(body_node, body_inputs)
                and data_input_shape is not None
            ):
                for output_name in body_outputs:
                    tainted_shapes[output_name] = data_input_shape
        promoted_output_indexes = frozenset(
            output_index for output_index, output in enumerate(graph_outputs) if _onnx_value_name(output) in promoted
        )
        output_shapes = {
            output_index: output_shape
            for output_index, output in enumerate(graph_outputs)
            if output_index in restorable_output_indexes
            and (output_shape := tainted_shapes.get(_onnx_value_name(output))) is not None
        }
        reentry_promotion_in_progress.discard(cache_key)
        reentry_promotion_cache[cache_key] = promoted_output_indexes
        reentry_shape_cache[cache_key] = output_shapes
        if promoted_outputs_out is not None:
            promoted_outputs_out.update(promoted_output_indexes)
        if output_shapes_out is not None:
            output_shapes_out.update(output_shapes)
        return graph_output_index in promoted_output_indexes

    def graph_outputs_may_reference_tainted(
        subgraph: Any,
        graph_input_names: set[str],
        opset_versions: dict[str, int],
        attribute_bindings: dict[str, Any] | None = None,
        *,
        depth: int = 0,
    ) -> bool:
        return bool(
            graph_tainted_output_indexes(
                subgraph,
                graph_input_names,
                opset_versions,
                attribute_bindings=attribute_bindings,
                depth=depth,
            )
        )

    graph_taint_cache: dict[tuple[Any, ...], set[int]] = {}
    graph_taint_in_progress: set[tuple[Any, ...]] = set()

    def graph_tainted_output_indexes(
        subgraph: Any,
        graph_input_names: set[str],
        opset_versions: dict[str, int],
        attribute_bindings: dict[str, Any] | None = None,
        *,
        depth: int = 0,
    ) -> set[int]:
        if not graph_input_names:
            return set()
        graph_outputs = getattr(subgraph, "output", ())
        if depth > 6:
            return set(range(len(graph_outputs)))
        cache_key = (
            id(subgraph),
            tuple(sorted(graph_input_names)),
            opset_cache_key(opset_versions),
            attribute_binding_cache_key(attribute_bindings),
            depth,
        )
        if cache_key in graph_taint_cache:
            return set(graph_taint_cache[cache_key])
        if cache_key in graph_taint_in_progress:
            return set(range(len(graph_outputs)))
        graph_taint_in_progress.add(cache_key)
        local_attribute_bindings = attribute_bindings or {}
        output_dependency_names = graph_output_dependency_names(subgraph, attribute_bindings=attribute_bindings)
        if dependency_names_exceeded_limit(output_dependency_names):
            graph_taint_in_progress.discard(cache_key)
            result = set(range(len(graph_outputs)))
            graph_taint_cache[cache_key] = set(result)
            return result
        output_dependency_node_ids = graph_nodes_producing_names(subgraph, output_dependency_names)

        def resolve_reentry_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return local_attribute_bindings.get(reference_name) if reference_name else attribute

        tainted = set(graph_input_names)
        for body_node in getattr(subgraph, "node", ()):
            body_inputs = [str(input_name) for input_name in getattr(body_node, "input", ())]
            body_outputs = [str(output_name) for output_name in getattr(body_node, "output", ()) if output_name]
            if not body_outputs:
                continue
            if id(body_node) not in output_dependency_node_ids:
                continue
            function_key = (
                str(getattr(body_node, "domain", "")),
                str(getattr(body_node, "op_type", "")),
                str(getattr(body_node, "overload", "")),
            )
            function = functions.get(function_key)
            any_tainted = any(input_name in tainted for input_name in body_inputs)
            inspected_function_taint = False
            if function is not None and any_tainted:
                inspected_function_taint = True
                mapped_outputs: set[str] = set()
                function_attributes = bound_function_attributes(function, body_node, resolve_reentry_attribute)
                function_versions = function_opset_versions(function, opset_versions)
                function_input_names = {
                    _onnx_value_name(function.input[input_index])
                    for input_index, input_name in enumerate(body_inputs)
                    if input_name in tainted and input_index < len(getattr(function, "input", ()))
                }
                function_input_names.discard("")
                if function_input_names:
                    mapped_outputs.update(
                        mapped_node_outputs(
                            body_outputs,
                            graph_tainted_output_indexes(
                                function,
                                function_input_names,
                                function_versions,
                                attribute_bindings=function_attributes,
                                depth=depth + 1,
                            ),
                        )
                    )
                if mapped_outputs:
                    tainted.update(mapped_outputs)
                    continue
            nested_outputs: set[str] = set()
            inspected_nested_taint = False
            for attribute in getattr(body_node, "attribute", ()):
                resolved_attribute = resolve_reentry_attribute(attribute)
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    captured_names = set(graph_external_reference_names(nested_graph) & tainted)
                    nested_input_names = set(
                        bound_control_flow_graph_inputs(
                            body_node,
                            nested_graph,
                            tainted,
                            opset_versions,
                        )
                    )
                    captured_names |= nested_input_names
                    if not captured_names:
                        continue
                    inspected_nested_taint = True
                    nested_outputs.update(
                        mapped_node_outputs(
                            body_outputs,
                            graph_tainted_output_indexes(
                                nested_graph,
                                captured_names,
                                opset_versions,
                                attribute_bindings=local_attribute_bindings,
                                depth=depth + 1,
                            ),
                            graph_output_offset=control_flow_output_offset(body_node),
                        )
                    )
            if nested_outputs:
                tainted.update(nested_outputs)
            elif any_tainted and not inspected_nested_taint and not inspected_function_taint:
                tainted.update(body_outputs)
        result = {
            output_index for output_index, output in enumerate(graph_outputs) if _onnx_value_name(output) in tainted
        }
        graph_taint_in_progress.discard(cache_key)
        graph_taint_cache[cache_key] = set(result)
        return result

    weight_reachability_cache: dict[tuple[Any, ...], bool] = {}
    weight_reachability_in_progress: set[tuple[Any, ...]] = set()
    potential_weight_consumer_cache: dict[tuple[Any, ...], bool] = {}
    potential_weight_consumer_dependency_cache: dict[tuple[Any, ...], frozenset[str]] = {}

    def subgraph_has_potential_weight_consumer(
        subgraph: Any,
        opset_versions: dict[str, int],
        *,
        attribute_bindings: dict[str, Any] | None = None,
        depth: int = 0,
    ) -> bool:
        if depth > 6:
            return True
        cache_key = (
            id(subgraph),
            opset_cache_key(opset_versions),
            attribute_binding_cache_key(attribute_bindings),
            depth,
        )
        if cache_key in potential_weight_consumer_cache:
            return potential_weight_consumer_cache[cache_key]
        local_attribute_bindings = attribute_bindings or {}

        def resolve_reentry_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return local_attribute_bindings.get(reference_name) if reference_name else attribute

        for body_node in getattr(subgraph, "node", ()):
            body_inputs = [str(input_name) for input_name in getattr(body_node, "input", ())]
            function_key = (
                str(getattr(body_node, "domain", "")),
                str(getattr(body_node, "op_type", "")),
                str(getattr(body_node, "overload", "")),
            )
            function = functions.get(function_key)
            is_model_local_function = function_key in functions
            is_registered_standard_operator = is_model_local_function or has_registered_standard_operator(
                body_node,
                opset_versions,
            )
            if function is not None:
                function_attributes = bound_function_attributes(function, body_node, resolve_reentry_attribute)
                function_versions = function_opset_versions(function, opset_versions)
                if subgraph_has_potential_weight_consumer(
                    function,
                    function_versions,
                    attribute_bindings=function_attributes,
                    depth=depth + 1,
                ):
                    potential_weight_consumer_cache[cache_key] = True
                    return True
            elif any(
                _onnx_potential_weight_input(
                    body_node,
                    input_index,
                    is_model_local_function=is_model_local_function,
                    is_registered_standard_operator=is_registered_standard_operator,
                )
                for input_index in range(len(body_inputs))
            ):
                potential_weight_consumer_cache[cache_key] = True
                return True
            for attribute in getattr(body_node, "attribute", ()):
                resolved_attribute = resolve_reentry_attribute(attribute)
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    if subgraph_has_potential_weight_consumer(
                        nested_graph,
                        opset_versions,
                        attribute_bindings=local_attribute_bindings,
                        depth=depth + 1,
                    ):
                        potential_weight_consumer_cache[cache_key] = True
                        return True
        potential_weight_consumer_cache[cache_key] = False
        return False

    def subgraph_potential_weight_consumer_dependency_names(
        subgraph: Any,
        opset_versions: dict[str, int],
        *,
        attribute_bindings: dict[str, Any] | None = None,
        depth: int = 0,
    ) -> frozenset[str]:
        cache_key = (
            id(subgraph),
            opset_cache_key(opset_versions),
            attribute_binding_cache_key(attribute_bindings),
            depth,
        )
        if cache_key in potential_weight_consumer_dependency_cache:
            return potential_weight_consumer_dependency_cache[cache_key]
        local_attribute_bindings = attribute_bindings or {}

        def resolve_reentry_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return local_attribute_bindings.get(reference_name) if reference_name else attribute

        dependencies: set[str] = set()
        for body_node in getattr(subgraph, "node", ()):
            body_input_slots = node_input_slots(body_node)
            function_key = (
                str(getattr(body_node, "domain", "")),
                str(getattr(body_node, "op_type", "")),
                str(getattr(body_node, "overload", "")),
            )
            function = functions.get(function_key)
            is_model_local_function = function_key in functions
            is_registered_standard_operator = is_model_local_function or has_registered_standard_operator(
                body_node,
                opset_versions,
            )
            if function is not None:
                function_attributes = bound_function_attributes(function, body_node, resolve_reentry_attribute)
                function_versions = function_opset_versions(function, opset_versions)
                if subgraph_has_potential_weight_consumer(
                    function,
                    function_versions,
                    attribute_bindings=function_attributes,
                    depth=depth + 1,
                ):
                    dependencies.update(input_name for input_name in body_input_slots if input_name)
                continue
            for input_index, input_name in enumerate(body_input_slots):
                if input_name and _onnx_potential_weight_input(
                    body_node,
                    input_index,
                    is_model_local_function=is_model_local_function,
                    is_registered_standard_operator=is_registered_standard_operator,
                ):
                    dependencies.add(input_name)
            parent_inputs = {input_name for input_name in body_input_slots if input_name}
            for attribute in getattr(body_node, "attribute", ()):
                resolved_attribute = resolve_reentry_attribute(attribute)
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    if not subgraph_has_potential_weight_consumer(
                        nested_graph,
                        opset_versions,
                        attribute_bindings=local_attribute_bindings,
                        depth=depth + 1,
                    ):
                        continue
                    dependencies.update(graph_external_reference_names(nested_graph))
                    if parent_inputs:
                        dependencies.update(
                            bound_control_flow_graph_inputs(
                                body_node,
                                nested_graph,
                                parent_inputs,
                                opset_versions,
                            ).values()
                        )
        result = frozenset(dependencies)
        potential_weight_consumer_dependency_cache[cache_key] = result
        return result

    def subgraph_state_input_can_reach_weight_consumer(
        subgraph: Any,
        graph_input_name: str,
        opset_versions: dict[str, int],
        *,
        attribute_bindings: dict[str, Any] | None = None,
        depth: int = 0,
    ) -> bool:
        if not graph_input_name:
            return False
        if depth > 6:
            return True
        cache_key = (
            id(subgraph),
            graph_input_name,
            opset_cache_key(opset_versions),
            attribute_binding_cache_key(attribute_bindings),
            depth,
        )
        if cache_key in weight_reachability_cache:
            return weight_reachability_cache[cache_key]
        if subgraph_analysis_work_exceeds_limit(
            subgraph,
            graph_output_dependency_names(subgraph, attribute_bindings=attribute_bindings),
            include_potential_weight_consumers=True,
            opset_versions=opset_versions,
            attribute_bindings=attribute_bindings,
        ):
            result = subgraph_has_potential_weight_consumer(
                subgraph,
                opset_versions,
                attribute_bindings=attribute_bindings,
                depth=depth,
            )
            weight_reachability_cache[cache_key] = result
            return result
        if cache_key in weight_reachability_in_progress:
            return True
        weight_reachability_in_progress.add(cache_key)

        def finish(result: bool) -> bool:
            weight_reachability_in_progress.discard(cache_key)
            weight_reachability_cache[cache_key] = result
            return result

        local_attribute_bindings = attribute_bindings or {}

        def resolve_reentry_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return local_attribute_bindings.get(reference_name) if reference_name else attribute

        body_nodes = tuple(getattr(subgraph, "node", ()))
        live_names = {name for output in getattr(subgraph, "output", ()) if (name := _onnx_value_name(output))}
        live_names.update(
            subgraph_potential_weight_consumer_dependency_names(
                subgraph,
                opset_versions,
                attribute_bindings=attribute_bindings,
                depth=depth,
            )
        )
        live_node_ids = set(graph_nodes_producing_names(subgraph, live_names))
        node_output_is_live_after_node: dict[int, bool] = {}
        for body_node in reversed(body_nodes):
            output_is_live = id(body_node) in live_node_ids
            node_output_is_live_after_node[id(body_node)] = output_is_live
            if not output_is_live:
                for attribute in getattr(body_node, "attribute", ()):
                    resolved_attribute = resolve_reentry_attribute(attribute)
                    if resolved_attribute is None:
                        continue
                    for nested_graph in _iter_attribute_graphs(resolved_attribute):
                        if not subgraph_has_potential_weight_consumer(
                            nested_graph,
                            opset_versions,
                            attribute_bindings=local_attribute_bindings,
                            depth=depth + 1,
                        ):
                            continue
                        external_names = graph_external_reference_names(nested_graph)
                        live_names.update(external_names)
                        live_node_ids.update(graph_nodes_producing_names(subgraph, external_names))
                continue
            live_body_inputs = node_input_names(body_node)
            live_names.update(live_body_inputs)
            live_node_ids.update(graph_nodes_producing_names(subgraph, live_body_inputs))
            for attribute in getattr(body_node, "attribute", ()):
                resolved_attribute = resolve_reentry_attribute(attribute)
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    external_names = graph_external_reference_names(nested_graph)
                    live_names.update(external_names)
                    live_node_ids.update(graph_nodes_producing_names(subgraph, external_names))

        tainted = {graph_input_name}
        for body_node in body_nodes:
            body_outputs = node_output_names(body_node)
            if not body_outputs:
                continue
            body_outputs_live_after = node_output_is_live_after_node.get(id(body_node), False)
            function_key = (
                str(getattr(body_node, "domain", "")),
                str(getattr(body_node, "op_type", "")),
                str(getattr(body_node, "overload", "")),
            )
            function = functions.get(function_key)
            is_model_local_function = function_key in functions
            is_registered_standard_operator = is_model_local_function or has_registered_standard_operator(
                body_node,
                opset_versions,
            )
            function_attributes: dict[str, Any] | None = None
            function_versions: dict[str, int] | None = None
            function_has_weight_consumer: bool | None = None
            if not body_outputs_live_after and function is not None:
                function_attributes = bound_function_attributes(function, body_node, resolve_reentry_attribute)
                function_versions = function_opset_versions(function, opset_versions)
                function_has_weight_consumer = subgraph_has_potential_weight_consumer(
                    function,
                    function_versions,
                    attribute_bindings=function_attributes,
                    depth=depth + 1,
                )
                if not function_has_weight_consumer:
                    continue
            if not body_outputs_live_after and function is None:
                raw_input_count = len(getattr(body_node, "input", ()))
                direct_potential_weight_input = any(
                    _onnx_potential_weight_input(
                        body_node,
                        input_index,
                        is_model_local_function=is_model_local_function,
                        is_registered_standard_operator=is_registered_standard_operator,
                    )
                    for input_index in range(raw_input_count)
                )
                has_nested_graph = False
                if not direct_potential_weight_input:
                    for attribute in getattr(body_node, "attribute", ()):
                        resolved_attribute = resolve_reentry_attribute(attribute)
                        if resolved_attribute is not None and any(_iter_attribute_graphs(resolved_attribute)):
                            has_nested_graph = True
                            break
                if not direct_potential_weight_input and not has_nested_graph:
                    continue
            body_inputs = node_input_names(body_node)
            any_tainted = any(input_name in tainted for input_name in body_inputs)
            has_tainted_nested_capture = False
            if not any_tainted:
                for attribute in getattr(body_node, "attribute", ()):
                    resolved_attribute = resolve_reentry_attribute(attribute)
                    if resolved_attribute is None:
                        continue
                    for nested_graph in _iter_attribute_graphs(resolved_attribute):
                        if not subgraph_has_potential_weight_consumer(
                            nested_graph,
                            opset_versions,
                            attribute_bindings=local_attribute_bindings,
                            depth=depth + 1,
                        ):
                            continue
                        if graph_external_reference_names(nested_graph) & tainted:
                            has_tainted_nested_capture = True
                            break
                    if has_tainted_nested_capture:
                        break
            if not body_outputs_live_after and not any_tainted and not has_tainted_nested_capture:
                continue
            function_tainted_outputs: set[str] = set()
            nested_tainted_outputs: set[str] = set()
            inspected_nested_taint = False
            if any_tainted:
                if function is not None:
                    if function_attributes is None:
                        function_attributes = bound_function_attributes(function, body_node, resolve_reentry_attribute)
                    if function_versions is None:
                        function_versions = function_opset_versions(function, opset_versions)
                    if function_has_weight_consumer is None:
                        function_has_weight_consumer = subgraph_has_potential_weight_consumer(
                            function,
                            function_versions,
                            attribute_bindings=function_attributes,
                            depth=depth + 1,
                        )
                    function_input_names: set[str] = set()
                    for input_index, input_name in enumerate(body_inputs):
                        if input_name not in tainted or input_index >= len(getattr(function, "input", ())):
                            continue
                        function_input_name = _onnx_value_name(function.input[input_index])
                        if not function_input_name:
                            continue
                        function_input_names.add(function_input_name)
                        if function_has_weight_consumer and subgraph_state_input_can_reach_weight_consumer(
                            function,
                            function_input_name,
                            function_versions,
                            attribute_bindings=function_attributes,
                            depth=depth + 1,
                        ):
                            return finish(True)
                    if function_input_names:
                        function_tainted_outputs.update(
                            mapped_node_outputs(
                                body_outputs,
                                graph_tainted_output_indexes(
                                    function,
                                    function_input_names,
                                    function_versions,
                                    attribute_bindings=function_attributes,
                                    depth=depth + 1,
                                ),
                            )
                        )
                    tainted.update(function_tainted_outputs)
                for attribute in getattr(body_node, "attribute", ()):
                    resolved_attribute = resolve_reentry_attribute(attribute)
                    if resolved_attribute is None:
                        continue
                    for nested_graph in _iter_attribute_graphs(resolved_attribute):
                        nested_contains_weight_consumer = subgraph_has_potential_weight_consumer(
                            nested_graph,
                            opset_versions,
                            attribute_bindings=local_attribute_bindings,
                            depth=depth + 1,
                        )
                        for input_index, input_name in enumerate(node_input_slots(body_node)):
                            if not input_name or input_name not in tainted:
                                continue
                            nested_input_index: int | None = None
                            if body_node.op_type == "Loop" and input_index >= 2:
                                nested_input_index = input_index
                            elif body_node.op_type == "Scan":
                                nested_input_index = input_index - scan_sequence_lens_input_offset(
                                    body_node,
                                    opset_versions,
                                )
                            if nested_input_index is None:
                                continue
                            if nested_input_index < 0 or nested_input_index >= len(getattr(nested_graph, "input", ())):
                                return finish(True)
                            inspected_nested_taint = True
                            nested_input_name = _onnx_value_name(nested_graph.input[nested_input_index])
                            if nested_contains_weight_consumer and subgraph_state_input_can_reach_weight_consumer(
                                nested_graph,
                                nested_input_name,
                                opset_versions,
                                attribute_bindings=local_attribute_bindings,
                                depth=depth + 1,
                            ):
                                return finish(True)
                            if body_outputs_live_after:
                                nested_tainted_outputs.update(
                                    mapped_node_outputs(
                                        body_outputs,
                                        graph_tainted_output_indexes(
                                            nested_graph,
                                            {nested_input_name},
                                            opset_versions,
                                            attribute_bindings=local_attribute_bindings,
                                            depth=depth + 1,
                                        ),
                                        graph_output_offset=control_flow_output_offset(body_node),
                                    )
                                )
                    tainted.update(nested_tainted_outputs)
            for attribute in getattr(body_node, "attribute", ()):
                resolved_attribute = resolve_reentry_attribute(attribute)
                if resolved_attribute is None:
                    continue
                for nested_graph in _iter_attribute_graphs(resolved_attribute):
                    captured_names = set(graph_external_reference_names(nested_graph) & tainted)
                    if captured_names:
                        inspected_nested_taint = True
                    nested_contains_weight_consumer = subgraph_has_potential_weight_consumer(
                        nested_graph,
                        opset_versions,
                        attribute_bindings=local_attribute_bindings,
                        depth=depth + 1,
                    )
                    if nested_contains_weight_consumer:
                        for captured_name in captured_names:
                            if subgraph_state_input_can_reach_weight_consumer(
                                nested_graph,
                                captured_name,
                                opset_versions,
                                attribute_bindings=local_attribute_bindings,
                                depth=depth + 1,
                            ):
                                return finish(True)
                    if body_outputs_live_after:
                        tainted.update(
                            mapped_node_outputs(
                                body_outputs,
                                graph_tainted_output_indexes(
                                    nested_graph,
                                    captured_names,
                                    opset_versions,
                                    attribute_bindings=local_attribute_bindings,
                                    depth=depth + 1,
                                ),
                                graph_output_offset=control_flow_output_offset(body_node),
                            )
                        )
            if any(
                input_name in tainted
                and _onnx_potential_weight_input(
                    body_node,
                    input_index,
                    is_model_local_function=is_model_local_function,
                    is_registered_standard_operator=is_registered_standard_operator,
                )
                for input_index, input_name in enumerate(body_inputs)
            ):
                return finish(True)
            if any_tainted and body_outputs_live_after and function is None and not inspected_nested_taint:
                tainted.update(body_outputs)
        return finish(False)

    def stacked_scan_output_insert_axis(
        scan_output_axes: tuple[int, ...],
        stacked_scan_output_start: int,
        output_index: int,
        *,
        default_axis: int = 0,
    ) -> int:
        scan_output_index = output_index - stacked_scan_output_start
        if scan_output_index < 0 or scan_output_index >= len(scan_output_axes):
            return default_axis
        return scan_output_axes[scan_output_index]

    def insert_shape_axis(shape: tuple[int, ...], raw_axis: int, extent: int = -1) -> tuple[int, ...] | None:
        output_rank = len(shape) + 1
        axis = raw_axis if raw_axis >= 0 else output_rank + raw_axis
        if axis < 0 or axis > len(shape):
            return None
        return (*shape[:axis], extent, *shape[axis:])

    def insert_rank_axis(rank: int, raw_axis: int) -> int | None:
        output_rank = rank + 1
        axis = raw_axis if raw_axis >= 0 else output_rank + raw_axis
        if axis < 0 or axis > rank:
            return None
        return output_rank

    graph_external_reference_cache: dict[int, tuple[Any, frozenset[str]]] = {}

    def graph_external_reference_names(graph: Any) -> frozenset[str]:
        cache_key = id(graph)
        cached_reference_names = graph_external_reference_cache.get(cache_key)
        if cached_reference_names is not None and cached_reference_names[0] is graph:
            return cached_reference_names[1]
        local_names = {name for value_info in getattr(graph, "input", ()) if (name := _onnx_value_name(value_info))}
        local_names.update(
            str(initializer.name)
            for initializer in getattr(graph, "initializer", ())
            if getattr(initializer, "name", "")
        )
        local_names.update(
            str(sparse_initializer.values.name)
            for sparse_initializer in getattr(graph, "sparse_initializer", ())
            if getattr(getattr(sparse_initializer, "values", None), "name", "")
        )
        produced_names = set(local_names)
        referenced_names: set[str] = set()
        for graph_output in getattr(graph, "output", ()):
            if output_name := _onnx_value_name(graph_output):
                referenced_names.add(output_name)
        for graph_node in getattr(graph, "node", ()):
            referenced_names.update(str(input_name) for input_name in getattr(graph_node, "input", ()) if input_name)
            produced_names.update(str(output_name) for output_name in getattr(graph_node, "output", ()) if output_name)
            for attribute in getattr(graph_node, "attribute", ()):
                for subgraph in _iter_attribute_graphs(attribute):
                    referenced_names.update(graph_external_reference_names(subgraph))
        reference_names = frozenset(referenced_names - produced_names - local_names)
        graph_external_reference_cache[cache_key] = (graph, reference_names)
        return reference_names

    def einsum_output_shape(
        node: Any,
        input_shapes_by_name: dict[str, tuple[int, ...] | None],
    ) -> tuple[int, ...] | None:
        equation = _onnx_text_attribute(node, "equation")
        if equation is None or "..." in equation or equation.count("->") != 1:
            return None
        input_expression, output_expression = (part.strip() for part in equation.split("->", 1))
        input_terms = [term.strip() for term in input_expression.split(",")]
        input_names = [str(input_name) for input_name in getattr(node, "input", ()) if input_name]
        if len(input_terms) != len(input_names) or len(set(output_expression)) != len(output_expression):
            return None
        label_dimensions: dict[str, int] = {}
        for term, input_name in zip(input_terms, input_names, strict=False):
            input_shape = input_shapes_by_name.get(input_name)
            if input_shape is None or len(term) != len(input_shape) or len(set(term)) != len(term):
                return None
            for label, dimension in zip(term, input_shape, strict=False):
                existing_dimension = label_dimensions.get(label)
                if existing_dimension is None:
                    label_dimensions[label] = dimension
                elif existing_dimension != dimension:
                    label_dimensions[label] = -1
        output_dimensions: list[int] = []
        for label in output_expression:
            if label not in label_dimensions:
                return None
            output_dimensions.append(label_dimensions[label])
        return tuple(output_dimensions)

    def gap_summary_may_exceed_input_rank(summary: _OnnxWeightLineageGapSummary, input_rank: int | None) -> bool:
        if summary.truncated:
            return True
        if input_rank is None:
            return bool(summary.lineages)
        return any(lineage.shape is None or len(lineage.shape) > input_rank for lineage in summary.lineages)

    def gap_summary_has_known_rank_above_input(
        summary: _OnnxWeightLineageGapSummary,
        input_rank: int | None,
    ) -> bool:
        if summary.truncated:
            return True
        if input_rank is None:
            return bool(summary.lineages)
        return any(lineage.shape is not None and len(lineage.shape) > input_rank for lineage in summary.lineages)

    def gap_summary_is_dynamic_activation(summary: _OnnxWeightLineageGapSummary, count: int) -> bool:
        if count <= 0:
            return True
        if summary.truncated or not summary.lineages:
            return False
        return all(
            lineage.unresolved_reason in {"dynamic_activation_lineage", "shape_control_lineage"}
            for lineage in summary.lineages
        )

    def operator_output_may_have_weight_rank(
        node: Any,
        *,
        input_shape: tuple[int, ...] | None,
        index_shape: tuple[int, ...] | None,
        constants: dict[str, Any],
        resolve_attribute: Callable[[Any], Any | None] | None = None,
        input_shapes_by_name: dict[str, tuple[int, ...] | None] | None = None,
        promotion_input_shapes: Sequence[tuple[int, ...] | None] | None = None,
    ) -> bool:
        if node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS or node.op_type == "Pow":
            input_names = [str(input_name) for input_name in getattr(node, "input", ()) if input_name]
            input_shapes = (
                [input_shapes_by_name.get(input_name) for input_name in input_names] if input_shapes_by_name else []
            )
            if not input_shapes or any(shape is None for shape in input_shapes):
                return True
            output_shape = broadcast_shapes(input_shapes)
            if output_shape is None:
                return True
            if promotion_input_shapes:
                if any(shape is None for shape in promotion_input_shapes):
                    return True
                if all(shape == output_shape for shape in promotion_input_shapes):
                    return False
            return len(output_shape) >= 2
        if node.op_type == "MatMul":
            input_names = [str(input_name) for input_name in getattr(node, "input", ()) if input_name]
            left_shape = input_shape
            right_shape = index_shape
            if input_shapes_by_name and input_names:
                left_shape = input_shapes_by_name.get(input_names[0])
                right_shape = input_shapes_by_name.get(input_names[1]) if len(input_names) > 1 else None
            output_shape = matmul_output_shape(left_shape, right_shape)
            if output_shape is None:
                return True
            if output_shape in (left_shape, right_shape):
                return False
            return len(output_shape) >= 2
        if node.op_type == "OneHot":
            input_names = [str(input_name) for input_name in getattr(node, "input", ()) if input_name]
            indices_shape = input_shape
            if input_shapes_by_name and input_names:
                indices_shape = input_shapes_by_name.get(input_names[0])
            output_shape = onehot_output_shape(node, indices_shape, constants)
            return output_shape is None or len(output_shape) >= 2
        if node.op_type == "Einsum":
            output_shape = einsum_output_shape(node, input_shapes_by_name or {})
            return output_shape is None or len(output_shape) >= 2
        if node.op_type == "Expand":
            shape_name = str(node.input[1]) if len(node.input) > 1 else ""
            target_shape = constant_int64_vector_values(constants.get(shape_name))
            if target_shape is None or input_shape is None:
                return True
            output_shape = broadcast_shapes((input_shape, target_shape))
            return output_shape is None or len(output_shape) >= 2
        if node.op_type == "Gather":
            if input_shape is None or index_shape is None:
                return True
            axis = _onnx_gather_axis(node, len(input_shape))
            if axis is None:
                return True
            return len(input_shape) + len(index_shape) - 1 >= 2
        if node.op_type == "GatherElements":
            return index_shape is None or len(index_shape) >= 2
        if node.op_type == "GatherND":
            if input_shape is None or index_shape is None or not index_shape:
                return True
            output_shape = gathernd_output_shape(
                node,
                input_shape=input_shape,
                index_shape=index_shape,
                resolve_attribute=resolve_attribute,
            )
            if output_shape is None:
                return True
            return len(output_shape) >= 2
        if node.op_type == "Flatten":
            return True
        if node.op_type == "Unsqueeze":
            axes = _resolve_onnx_axes(node, constants, onnx=onnx, resolve_attribute=resolve_attribute)
            if axes is None or input_shape is None:
                return True
            output_rank = len(input_shape) + len(axes)
            normalized_axes = tuple(axis if axis >= 0 else output_rank + axis for axis in axes)
            if (
                not normalized_axes
                or len(set(normalized_axes)) != len(normalized_axes)
                or any(axis < 0 or axis >= output_rank for axis in normalized_axes)
            ):
                return True
            return output_rank >= 2
        if node.op_type == "Squeeze":
            axes = _resolve_onnx_axes(node, constants, onnx=onnx, resolve_attribute=resolve_attribute)
            if axes is None or input_shape is None:
                return True
            normalized_axes = tuple(axis if axis >= 0 else len(input_shape) + axis for axis in axes)
            if not normalized_axes:
                if squeeze_with_empty_axes_is_noop(node, axes, resolve_attribute):
                    return len(input_shape) >= 2
                normalized_axes = tuple(index for index, dimension in enumerate(input_shape) if dimension == 1)
            if (
                len(set(normalized_axes)) != len(normalized_axes)
                or any(axis < 0 or axis >= len(input_shape) for axis in normalized_axes)
                or any(input_shape[axis] != 1 for axis in normalized_axes)
            ):
                return True
            return len(input_shape) - len(set(normalized_axes)) >= 2
        if node.op_type == "Reshape":
            shape_name = str(node.input[1]) if len(node.input) > 1 else ""
            shape_initializer = constants.get(shape_name)
            if shape_initializer is None or input_shape is None:
                return True
            resolved_shape = _resolve_onnx_reshape_shape(
                input_shape,
                shape_initializer,
                allowzero=bool(_onnx_int_attribute(node, "allowzero")),
                onnx=onnx,
            )
            return resolved_shape is None or len(resolved_shape) >= 2
        return False

    def value_info_shape(value_info: Any) -> tuple[int, ...] | None:
        try:
            tensor_type = value_info.type.tensor_type
            if not tensor_type.HasField("shape"):
                return None
            dimensions: list[int] = []
            for dimension in tensor_type.shape.dim:
                if not dimension.HasField("dim_value"):
                    return None
                dimensions.append(int(dimension.dim_value))
            return tuple(dimensions)
        except (AttributeError, TypeError, ValueError):
            return None

    def value_info_rank(value_info: Any) -> int | None:
        try:
            tensor_type = value_info.type.tensor_type
            if not tensor_type.HasField("shape"):
                return None
            return len(tensor_type.shape.dim)
        except AttributeError:
            return None

    def broadcast_shapes(shapes: Iterable[tuple[int, ...] | None]) -> tuple[int, ...] | None:
        concrete_shapes = list(shapes)
        if not concrete_shapes or any(shape is None for shape in concrete_shapes):
            return None
        known_shapes = [shape for shape in concrete_shapes if shape is not None]
        output_rank = max((len(shape) for shape in known_shapes), default=0)
        output_dimensions: list[int] = []
        for offset in range(1, output_rank + 1):
            dimensions = [shape[-offset] if len(shape) >= offset else 1 for shape in known_shapes]
            non_singleton_dimensions = {dimension for dimension in dimensions if dimension != 1}
            if len(non_singleton_dimensions) > 1:
                return None
            output_dimensions.append(next(iter(non_singleton_dimensions), 1))
        return tuple(reversed(output_dimensions))

    def matmul_output_shape(
        left_shape: tuple[int, ...] | None,
        right_shape: tuple[int, ...] | None,
    ) -> tuple[int, ...] | None:
        if left_shape is None or right_shape is None:
            return None
        left_rank = len(left_shape)
        right_rank = len(right_shape)
        if left_rank == 0 or right_rank == 0:
            return None
        if left_rank == 1 and right_rank == 1:
            return ()
        if left_rank == 1:
            return (*right_shape[:-2], right_shape[-1])
        if right_rank == 1:
            return left_shape[:-1]
        batch_shape = broadcast_shapes((left_shape[:-2], right_shape[:-2]))
        if batch_shape is None:
            return None
        return (*batch_shape, left_shape[-2], right_shape[-1])

    def onehot_output_shape(
        node: Any,
        indices_shape: tuple[int, ...] | None,
        constants: dict[str, Any],
    ) -> tuple[int, ...] | None:
        if indices_shape is None:
            return None
        output_rank = len(indices_shape) + 1
        raw_axis = _onnx_int_attribute(node, "axis", -1)
        axis = raw_axis if raw_axis >= 0 else output_rank + raw_axis
        if axis < 0 or axis >= output_rank:
            return None
        depth_extent = -1
        depth_name = str(node.input[1]) if len(node.input) > 1 else ""
        depth_value = constant_scalar_value(constants.get(depth_name), int(onnx.TensorProto.INT64))
        if depth_value is not None:
            try:
                depth_extent = max(int(depth_value), -1)
            except (TypeError, ValueError):
                depth_extent = -1
        return (*indices_shape[:axis], depth_extent, *indices_shape[axis:])

    def flattened_shape_extent(dimensions: tuple[int, ...]) -> int:
        return -1 if any(dimension < 0 for dimension in dimensions) else math.prod(dimensions)

    def broadcast_rank_from_input_ranks(ranks: Iterable[int | None]) -> int | None:
        observed_ranks = list(ranks)
        known_ranks = [rank for rank in observed_ranks if rank is not None]
        if not known_ranks:
            return None
        output_rank = max(known_ranks)
        if any(rank is None for rank in observed_ranks) and output_rank < 2:
            return None
        return output_rank

    groups: list[dict[tuple[Any, ...], _OnnxWeightConsumerGroup]] = []
    eligible_initializer_indexes: set[int] = set()
    terminal_consumer_counts: list[int] = []
    transform_counts: list[int] = []
    total_consumer_count = 0
    consumer_sample_count = 0
    node_counter = 0
    graph_counter = 0
    schema_cache: dict[tuple[str, str, int], bool] = {}

    def register_initializer(
        initializer: Any,
        graph_index: int,
        *,
        shape: tuple[int, ...] | None = None,
        unresolved_reason: str | None = None,
        source_key: tuple[Any, ...] | None = None,
        constant_output: bool = False,
    ) -> _OnnxWeightLineage:
        resolved_shape = shape if shape is not None else tuple(int(dimension) for dimension in initializer.dims)
        if source_key is not None and source_key in initializer_source_indexes:
            if constant_output:
                constant_output_initializer_indexes.add(initializer_source_indexes[source_key])
            return _OnnxWeightLineage(
                initializer_index=initializer_source_indexes[source_key],
                shape=resolved_shape,
                data_type=int(initializer.data_type),
                unresolved_reason=unresolved_reason,
            )

        initializer_index = len(initializers)
        initializers.append(initializer)
        initializer_graph_indexes.append(graph_index)
        groups.append({})
        terminal_consumer_counts.append(0)
        transform_counts.append(0)
        if source_key is not None:
            initializer_source_indexes[source_key] = initializer_index
        if constant_output:
            constant_output_initializer_indexes.add(initializer_index)
        return _OnnxWeightLineage(
            initializer_index=initializer_index,
            shape=resolved_shape,
            data_type=int(initializer.data_type),
            unresolved_reason=unresolved_reason,
        )

    def record_exclusion(
        initializer_index: int,
        reason: str,
        node: Any | None = None,
        input_index: int | None = None,
    ) -> None:
        plan.exclusion_counts[reason] = plan.exclusion_counts.get(reason, 0) + 1
        if len(plan.exclusion_samples) >= _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
            return
        initializer = initializers[initializer_index]
        sample: dict[str, Any] = {
            **_bounded_onnx_metadata_fields(plan, "initializer", initializer.name),
            "initializer_graph_index": initializer_graph_indexes[initializer_index],
            "reason": reason,
            **_bounded_onnx_integer_sequence("stored_shape", initializer.dims),
        }
        if node is not None:
            sample.update(_bounded_onnx_metadata_fields(plan, "consumer_op", node.op_type))
            sample.update(_bounded_onnx_metadata_fields(plan, "consumer_node", node.name))
            sample["consumer_input_index"] = input_index
        plan.exclusion_samples.append(sample)

    def consumer_metadata(node: Any, node_index: int, input_index: int) -> dict[str, Any]:
        return {
            **_bounded_onnx_metadata_fields(plan, "op", node.op_type),
            **_bounded_onnx_metadata_fields(plan, "node", node.name),
            "node_index": node_index,
            "input_index": input_index,
        }

    def record_unresolved_lineage(
        lineage: _OnnxWeightLineage,
        node: Any,
        node_index: int,
        input_index: int,
    ) -> None:
        eligible_initializer_indexes.add(lineage.initializer_index)
        plan.record_coverage_gap("unresolved_initializer_lineage")
        if len(plan.unresolved_lineage_samples) >= _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
            return
        initializer = initializers[lineage.initializer_index]
        plan.unresolved_lineage_samples.append(
            {
                **_bounded_onnx_metadata_fields(plan, "initializer", initializer.name),
                "initializer_graph_index": initializer_graph_indexes[lineage.initializer_index],
                **_bounded_onnx_metadata_fields(plan, "consumer_op", node.op_type),
                **_bounded_onnx_metadata_fields(plan, "consumer_node", node.name),
                "consumer_node_index": node_index,
                "consumer_input_index": input_index,
                "reason": lineage.unresolved_reason or "unknown_lineage",
                "lineage_transform_count": len(lineage.transforms),
            },
        )

    def record_training_binding_gap(
        lineage: _OnnxWeightLineage,
        *,
        binding_kind: str,
        state_name: str,
    ) -> None:
        eligible_initializer_indexes.add(lineage.initializer_index)
        plan.record_coverage_gap("unresolved_initializer_lineage")
        if len(plan.unresolved_lineage_samples) >= _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
            return
        initializer = initializers[lineage.initializer_index]
        plan.unresolved_lineage_samples.append(
            {
                **_bounded_onnx_metadata_fields(plan, "initializer", initializer.name),
                "initializer_graph_index": initializer_graph_indexes[lineage.initializer_index],
                **_bounded_onnx_metadata_fields(plan, "consumer_op", "TrainingInfoBinding"),
                **_bounded_onnx_metadata_fields(plan, "consumer_node", state_name),
                "consumer_node_index": -1,
                "consumer_input_index": 0,
                "reason": f"unresolved_{binding_kind}_binding",
                "lineage_transform_count": len(lineage.transforms),
            },
        )

    def add_consumer_group(
        lineage: _OnnxWeightLineage,
        node: Any,
        node_index: int,
        input_index: int,
        output_axes: tuple[int, ...],
    ) -> None:
        nonlocal consumer_sample_count
        initializer = initializers[lineage.initializer_index]
        if int(initializer.data_type) not in floating_types:
            record_exclusion(lineage.initializer_index, "non_floating_weight", node, input_index)
            return

        analysis_kind = (
            "tensor" if node.op_type in {"Conv", "ConvTranspose"} or len(lineage.shape or ()) > 2 else "matrix"
        )
        group_value = _onnx_int_attribute(node, "group", 1) if node.op_type in {"Conv", "ConvTranspose"} else 1
        signature = (
            lineage.transforms,
            node.op_type,
            input_index,
            output_axes,
            analysis_kind,
            group_value,
        )
        initializer_groups = groups[lineage.initializer_index]
        consumer_group = initializer_groups.get(signature)
        if consumer_group is None:
            if len(initializer_groups) >= _ONNX_WEIGHT_ANALYSIS_GROUP_LIMIT:
                plan.record_coverage_gap("initializer_analysis_group_limit")
                return
            consumer_group = _OnnxWeightConsumerGroup(
                lineage=lineage,
                node=node,
                node_index=node_index,
                input_index=input_index,
                output_axes=output_axes,
                analysis_kind=analysis_kind,
                group=group_value,
            )
            initializer_groups[signature] = consumer_group
        consumer_group.consumer_count += 1
        if len(consumer_group.consumers) < _ONNX_WEIGHT_CONSUMER_SAMPLE_LIMIT:
            consumer_group.consumers.append(consumer_metadata(node, node_index, input_index))
            consumer_sample_count += 1
        eligible_initializer_indexes.add(lineage.initializer_index)

    def transformed_lineage(
        lineage: _OnnxWeightLineage,
        node: Any,
        constants: dict[str, Any],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> _OnnxWeightLineage:
        has_referenced_attributes = any(
            getattr(attribute, "ref_attr_name", "") for attribute in getattr(node, "attribute", ())
        )
        if has_referenced_attributes and not (
            (node.op_type == "Cast" and cast_target_data_type is not None)
            or (node.op_type == "GatherND" and resolve_attribute is not None)
        ):
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=None,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "referenced_function_attribute",
            )
        if node.op_type == "Identity":
            return lineage
        if node.op_type == "Cast":
            target_data_type = (
                cast_target_data_type if cast_target_data_type is not None else _onnx_int_attribute(node, "to", -1)
            )
            if target_data_type == lineage.data_type:
                return lineage
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=lineage.shape,
                data_type=target_data_type if target_data_type >= 0 else None,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "dtype_changing_cast_lineage",
            )
        if len(lineage.transforms) >= _ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT:
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=None,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "lineage_transform_depth_limit",
            )
        if lineage.shape is None:
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=None,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "lineage_shape_unavailable",
            )

        output_shape: tuple[int, ...]
        transform: _OnnxWeightTransform
        if node.op_type == "Flatten":
            axis = _onnx_int_attribute(node, "axis", 1)
            axis = axis if axis >= 0 else len(lineage.shape) + axis
            if axis < 0 or axis > len(lineage.shape):
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "invalid_flatten_lineage",
                )
            output_shape = (math.prod(lineage.shape[:axis]), math.prod(lineage.shape[axis:]))
            transform = _OnnxWeightTransform("Reshape", output_shape)
        elif node.op_type in {"Squeeze", "Unsqueeze"}:
            axes = _resolve_onnx_axes(node, constants, onnx=onnx)
            if axes is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or f"unresolved_{node.op_type.lower()}_lineage",
                )
            if node.op_type == "Squeeze":
                normalized_axes = tuple(axis if axis >= 0 else len(lineage.shape) + axis for axis in axes)
                if not normalized_axes:
                    if squeeze_with_empty_axes_is_noop(node, axes):
                        output_shape = lineage.shape
                        transform = _OnnxWeightTransform("Reshape", output_shape)
                        transformed = _OnnxWeightLineage(
                            initializer_index=lineage.initializer_index,
                            shape=output_shape,
                            data_type=lineage.data_type,
                            transforms=(*lineage.transforms, transform),
                            unresolved_reason=lineage.unresolved_reason,
                        )
                        return transformed if transformed != lineage else lineage
                    normalized_axes = tuple(index for index, dimension in enumerate(lineage.shape) if dimension == 1)
                if (
                    len(set(normalized_axes)) != len(normalized_axes)
                    or any(axis < 0 or axis >= len(lineage.shape) for axis in normalized_axes)
                    or any(lineage.shape[axis] != 1 for axis in normalized_axes)
                ):
                    return _OnnxWeightLineage(
                        initializer_index=lineage.initializer_index,
                        shape=None,
                        data_type=lineage.data_type,
                        transforms=lineage.transforms,
                        unresolved_reason=lineage.unresolved_reason or "invalid_squeeze_lineage",
                    )
                output_shape = tuple(
                    dimension for index, dimension in enumerate(lineage.shape) if index not in normalized_axes
                )
            else:
                output_rank = len(lineage.shape) + len(axes)
                normalized_axes = tuple(axis if axis >= 0 else output_rank + axis for axis in axes)
                if (
                    not normalized_axes
                    or len(set(normalized_axes)) != len(normalized_axes)
                    or any(axis < 0 or axis >= output_rank for axis in normalized_axes)
                ):
                    return _OnnxWeightLineage(
                        initializer_index=lineage.initializer_index,
                        shape=None,
                        data_type=lineage.data_type,
                        transforms=lineage.transforms,
                        unresolved_reason=lineage.unresolved_reason or "invalid_unsqueeze_lineage",
                    )
                source_dimensions = iter(lineage.shape)
                output_shape = tuple(
                    1 if index in normalized_axes else next(source_dimensions) for index in range(output_rank)
                )
            transform = _OnnxWeightTransform("Reshape", output_shape)
        elif node.op_type == "Transpose":
            permutation = tuple(
                int(value)
                for value in next(
                    (attribute.ints for attribute in node.attribute if attribute.name == "perm"),
                    tuple(reversed(range(len(lineage.shape)))),
                )
            )
            if sorted(permutation) != list(range(len(lineage.shape))):
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "invalid_transpose_lineage",
                )
            if permutation == tuple(range(len(lineage.shape))):
                return lineage
            transform = _OnnxWeightTransform("Transpose", permutation)
            output_shape = tuple(lineage.shape[index] for index in permutation)
        elif node.op_type == "Expand":
            shape_name = str(node.input[1]) if len(node.input) > 1 else ""
            target_shape = constant_int64_vector_values(constants.get(shape_name))
            if target_shape is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unresolved_expand_lineage",
                )
            expanded_shape = broadcast_shapes((lineage.shape, target_shape))
            if expanded_shape is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unresolved_expand_lineage",
                )
            output_shape = expanded_shape
            transform = _OnnxWeightTransform("Reshape", output_shape)
        elif node.op_type == "Gather":
            index_shape = constant_initializer_shape(constants, node.input[1]) if len(node.input) >= 2 else None
            gather_axis = _onnx_gather_axis(node, len(lineage.shape))
            if gather_axis is None or index_shape is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unresolved_gather_lineage",
                )
            output_shape = (*lineage.shape[:gather_axis], *index_shape, *lineage.shape[gather_axis + 1 :])
            transform = _OnnxWeightTransform("Reshape", output_shape)
        elif node.op_type == "GatherND":
            index_shape = constant_initializer_shape(constants, node.input[1]) if len(node.input) >= 2 else None
            if not index_shape:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unresolved_gathernd_lineage",
                )
            gathered_shape = gathernd_output_shape(
                node,
                input_shape=lineage.shape,
                index_shape=index_shape,
                resolve_attribute=resolve_attribute,
            )
            if gathered_shape is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unresolved_gathernd_lineage",
                )
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=gathered_shape,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "unresolved_gathernd_lineage",
            )
        else:  # Reshape
            shape_name = str(node.input[1]) if len(node.input) > 1 else ""
            shape_initializer = constants.get(shape_name)
            resolved_shape = (
                _resolve_onnx_reshape_shape(
                    lineage.shape,
                    shape_initializer,
                    allowzero=bool(_onnx_int_attribute(node, "allowzero")),
                    onnx=onnx,
                )
                if shape_initializer is not None
                else None
            )
            if resolved_shape is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unresolved_reshape_lineage",
                )
            output_shape = resolved_shape
            transform = _OnnxWeightTransform("Reshape", output_shape)

        if output_shape == lineage.shape:
            return lineage

        return _OnnxWeightLineage(
            initializer_index=lineage.initializer_index,
            shape=output_shape,
            data_type=lineage.data_type,
            transforms=(*lineage.transforms, transform),
            unresolved_reason=lineage.unresolved_reason,
        )

    def compact_runtime_bookkeeping_lineages(
        lineages: dict[int, _OnnxWeightLineage],
    ) -> dict[int, _OnnxWeightLineage]:
        if len(lineages) <= _ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT:
            return lineages
        representatives: dict[str, tuple[int, _OnnxWeightLineage]] = {}
        compacted: dict[int, _OnnxWeightLineage] = {}
        for initializer_index, lineage in sorted(lineages.items()):
            if lineage.unresolved_reason in _ONNX_RUNTIME_BOOKKEEPING_LINEAGE_REASONS:
                if lineage.transforms:
                    compacted[initializer_index] = lineage
                else:
                    representatives.setdefault(lineage.unresolved_reason, (initializer_index, lineage))
            else:
                compacted[initializer_index] = lineage
        if not representatives:
            return lineages
        compacted.update(dict(representatives.values()))
        return dict(sorted(compacted.items()))

    empty_weight_gap_summary = _OnnxWeightLineageGapSummary()
    unknown_weight_gap_summary = _OnnxWeightLineageGapSummary(truncated=True)

    def lineage_gap_summary_key(lineage: _OnnxWeightLineage) -> tuple[Any, ...]:
        return (
            lineage.shape,
            lineage.data_type,
            lineage.transforms,
            lineage.unresolved_reason,
        )

    def summarize_lineage_gap(
        lineages: Iterable[_OnnxWeightLineage],
        predicate: Callable[[_OnnxWeightLineage], bool],
        *,
        truncated: bool = False,
    ) -> _OnnxWeightLineageGapSummary:
        representatives: list[_OnnxWeightLineage] = []
        seen: set[tuple[Any, ...]] = set()
        for lineage in lineages:
            if not predicate(lineage):
                continue
            key = lineage_gap_summary_key(lineage)
            if key in seen:
                continue
            if len(representatives) >= _ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT:
                return _OnnxWeightLineageGapSummary(tuple(representatives), truncated=True)
            seen.add(key)
            representatives.append(lineage)
        return _OnnxWeightLineageGapSummary(tuple(representatives), truncated=truncated)

    def summarize_weight_lineage_gap(
        lineages: Iterable[_OnnxWeightLineage],
        *,
        truncated: bool = False,
    ) -> _OnnxWeightLineageGapSummary:
        return summarize_lineage_gap(lineages, lineage_could_be_weight, truncated=truncated)

    def summarize_non_shape_lineage_gap(
        lineages: Iterable[_OnnxWeightLineage],
        *,
        truncated: bool = False,
    ) -> _OnnxWeightLineageGapSummary:
        return summarize_lineage_gap(
            lineages,
            lambda lineage: lineage.unresolved_reason != "shape_control_lineage",
            truncated=truncated,
        )

    def summarize_rank_promotable_lineage_gap(
        lineages: Iterable[_OnnxWeightLineage],
        *,
        truncated: bool = False,
    ) -> _OnnxWeightLineageGapSummary:
        return summarize_lineage_gap(lineages, lineage_could_be_weight_after_rank_increase, truncated=truncated)

    def merge_weight_lineage_gap_summaries(
        *summaries: _OnnxWeightLineageGapSummary,
    ) -> _OnnxWeightLineageGapSummary:
        representatives: list[_OnnxWeightLineage] = []
        seen: set[tuple[Any, ...]] = set()
        truncated = False
        for summary in summaries:
            truncated |= summary.truncated
            for lineage in summary.lineages:
                key = lineage_gap_summary_key(lineage)
                if key in seen:
                    continue
                if len(representatives) >= _ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT:
                    return _OnnxWeightLineageGapSummary(tuple(representatives), truncated=True)
                seen.add(key)
                representatives.append(lineage)
        return _OnnxWeightLineageGapSummary(tuple(representatives), truncated=truncated)

    def known_weight_gap_summary(
        summary: _OnnxWeightLineageGapSummary | None,
        count: int,
    ) -> _OnnxWeightLineageGapSummary:
        if count <= 0:
            return empty_weight_gap_summary
        if summary is not None and (summary.lineages or summary.truncated):
            return summary
        return unknown_weight_gap_summary

    def floating_cast_non_shape_gap_may_be_weight(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> bool:
        if summary.truncated or not summary.lineages:
            return True
        return any(
            lineage_could_be_weight(
                transformed_lineage(
                    lineage,
                    node,
                    constants,
                    cast_target_data_type=cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                )
            )
            for lineage in summary.lineages
        )

    def weight_gap_summary_demotes_after_transform(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> bool:
        if summary.truncated or not summary.lineages:
            return False
        for lineage in summary.lineages:
            transformed = transformed_lineage(
                lineage,
                node,
                constants,
                cast_target_data_type=cast_target_data_type,
                resolve_attribute=resolve_attribute,
            )
            if lineage_could_be_weight(transformed) or not lineage_could_be_weight_after_rank_increase(transformed):
                return False
        return True

    def transform_lineage_gap_summary(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        predicate: Callable[[_OnnxWeightLineage], bool],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> _OnnxWeightLineageGapSummary:
        if not summary.lineages:
            return summary
        return summarize_lineage_gap(
            (
                transformed_lineage(
                    lineage,
                    node,
                    constants,
                    cast_target_data_type=cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                )
                for lineage in summary.lineages
            ),
            predicate,
            truncated=summary.truncated,
        )

    def transform_weight_gap_summary(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> _OnnxWeightLineageGapSummary:
        return transform_lineage_gap_summary(
            summary,
            node,
            constants,
            lineage_could_be_weight,
            cast_target_data_type=cast_target_data_type,
            resolve_attribute=resolve_attribute,
        )

    def transform_non_shape_gap_summary(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> _OnnxWeightLineageGapSummary:
        return transform_lineage_gap_summary(
            summary,
            node,
            constants,
            lambda lineage: lineage.unresolved_reason != "shape_control_lineage",
            cast_target_data_type=cast_target_data_type,
            resolve_attribute=resolve_attribute,
        )

    def transform_rank_promotable_gap_summary(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        *,
        cast_target_data_type: int | None = None,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> _OnnxWeightLineageGapSummary:
        return transform_lineage_gap_summary(
            summary,
            node,
            constants,
            lineage_could_be_weight_after_rank_increase,
            cast_target_data_type=cast_target_data_type,
            resolve_attribute=resolve_attribute,
        )

    def promoted_rank_gap_weight_summary(
        summary: _OnnxWeightLineageGapSummary,
        node: Any,
        constants: dict[str, Any],
        count: int,
        *,
        resolve_attribute: Callable[[Any], Any | None] | None = None,
    ) -> _OnnxWeightLineageGapSummary:
        if count <= 0:
            return empty_weight_gap_summary
        if not summary.lineages:
            return unknown_weight_gap_summary if summary.truncated else empty_weight_gap_summary
        transformed_summary = transform_weight_gap_summary(
            summary,
            node,
            constants,
            resolve_attribute=resolve_attribute,
        )
        if transformed_summary.lineages or transformed_summary.truncated:
            return transformed_summary
        return empty_weight_gap_summary

    def rank_gap_weight_summary_after_rank_increase(
        summary: _OnnxWeightLineageGapSummary,
        count: int,
        *,
        output_shape: tuple[int, ...] | None = None,
        output_rank: int | None = None,
        insert_axis: int = 0,
    ) -> _OnnxWeightLineageGapSummary:
        if count <= 0:
            return empty_weight_gap_summary
        if not summary.lineages:
            return unknown_weight_gap_summary if summary.truncated else empty_weight_gap_summary
        promoted_lineages: list[_OnnxWeightLineage] = []
        for lineage in summary.lineages:
            shape = None
            if output_shape is not None:
                shape = output_shape
            elif lineage.shape is not None:
                target_rank = output_rank if output_rank is not None else len(lineage.shape) + 1
                if target_rank < len(lineage.shape):
                    shape = None
                elif target_rank == len(lineage.shape):
                    shape = lineage.shape
                else:
                    axis = insert_axis if insert_axis >= 0 else target_rank + insert_axis
                    if axis < 0 or axis > target_rank:
                        axis = 0
                    added_rank = target_rank - len(lineage.shape)
                    shape = (
                        *lineage.shape[:axis],
                        *(-1 for _ in range(added_rank)),
                        *lineage.shape[axis:],
                    )
            promoted_lineages.append(
                _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason,
                )
            )
        return summarize_weight_lineage_gap(promoted_lineages, truncated=summary.truncated)

    def rank_gap_weight_summary_after_repeated_rank_increase(
        summary: _OnnxWeightLineageGapSummary,
        count: int,
    ) -> _OnnxWeightLineageGapSummary:
        if count <= 0:
            return empty_weight_gap_summary
        if not summary.lineages:
            return unknown_weight_gap_summary if summary.truncated else empty_weight_gap_summary
        promoted_lineages: list[_OnnxWeightLineage] = []
        for lineage in summary.lineages:
            shape = lineage.shape
            if shape is not None:
                while len(shape) < 2:
                    shape = (-1, *shape)
            promoted_lineages.append(
                _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason,
                )
            )
        return summarize_weight_lineage_gap(promoted_lineages, truncated=summary.truncated)

    def lineages_after_control_flow_rank_increase(
        lineages: dict[int, _OnnxWeightLineage],
        *,
        output_shape: tuple[int, ...] | None = None,
        output_rank: int | None = None,
        insert_axis: int = 0,
    ) -> dict[int, _OnnxWeightLineage]:
        if not lineages:
            return lineages
        promoted_lineages: dict[int, _OnnxWeightLineage] = {}
        for initializer_index, lineage in lineages.items():
            target_rank = len(output_shape) if output_shape is not None else output_rank
            lineage_rank = len(lineage.shape) if lineage.shape is not None else None
            if (
                lineage.unresolved_reason is None
                and initializer_index in constant_output_initializer_indexes
                and target_rank is not None
                and lineage_rank is not None
                and (target_rank <= lineage_rank or lineage_rank >= 2)
            ):
                promoted_lineages[initializer_index] = lineage
                continue
            shape = None
            if output_shape is not None:
                shape = output_shape
            elif lineage.shape is not None and output_rank is not None:
                target_rank = output_rank
                if target_rank < len(lineage.shape):
                    shape = None
                elif target_rank == len(lineage.shape):
                    shape = lineage.shape
                else:
                    axis = insert_axis if insert_axis >= 0 else target_rank + insert_axis
                    if axis < 0 or axis > target_rank:
                        axis = 0
                    added_rank = target_rank - len(lineage.shape)
                    shape = (
                        *lineage.shape[:axis],
                        *(-1 for _ in range(added_rank)),
                        *lineage.shape[axis:],
                    )
            promoted_lineages[initializer_index] = _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=shape,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason,
            )
        return promoted_lineages

    def non_shape_gap_summary_after_rank_increase(
        summary: _OnnxWeightLineageGapSummary,
        count: int,
        *,
        insert_axis: int = 0,
    ) -> _OnnxWeightLineageGapSummary:
        if count <= 0:
            return empty_weight_gap_summary
        if not summary.lineages:
            return unknown_weight_gap_summary if summary.truncated else empty_weight_gap_summary
        promoted_lineages: list[_OnnxWeightLineage] = []
        for lineage in summary.lineages:
            shape = None
            if lineage.shape is not None:
                target_rank = len(lineage.shape) + 1
                axis = insert_axis if insert_axis >= 0 else target_rank + insert_axis
                if axis < 0 or axis > target_rank:
                    axis = 0
                shape = (
                    *lineage.shape[:axis],
                    -1,
                    *lineage.shape[axis:],
                )
            promoted_lineages.append(
                _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason,
                )
            )
        return summarize_non_shape_lineage_gap(promoted_lineages, truncated=summary.truncated)

    def bounded_lineages(
        lineages: dict[int, _OnnxWeightLineage],
    ) -> tuple[
        dict[int, _OnnxWeightLineage],
        int,
        int,
        _OnnxWeightLineageGapSummary,
        int,
        int,
        _OnnxWeightLineageGapSummary,
        _OnnxWeightLineageGapSummary,
    ]:
        lineages = compact_runtime_bookkeeping_lineages(lineages)
        if len(lineages) <= _ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT:
            return (
                lineages,
                0,
                0,
                empty_weight_gap_summary,
                0,
                0,
                empty_weight_gap_summary,
                empty_weight_gap_summary,
            )
        ordered_lineages = sorted(
            lineages.items(),
            key=lambda item: (
                item[1].unresolved_reason in _ONNX_RUNTIME_BOOKKEEPING_LINEAGE_REASONS,
                item[0],
            ),
        )
        dropped_lineages = ordered_lineages[_ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT:]
        dropped_non_shape_lineages = sum(
            1
            for _initializer_index, lineage in dropped_lineages
            if lineage.unresolved_reason != "shape_control_lineage"
        )
        dropped_weight_lineages = sum(
            1 for _initializer_index, lineage in dropped_lineages if lineage_could_be_weight(lineage)
        )
        dropped_rank_promotable_lineages = sum(
            1
            for _initializer_index, lineage in dropped_lineages
            if lineage_could_be_weight_after_rank_increase(lineage)
        )
        dropped_weight_lineage_summary = summarize_weight_lineage_gap(
            lineage for _initializer_index, lineage in dropped_lineages
        )
        dropped_non_shape_lineage_summary = summarize_non_shape_lineage_gap(
            lineage for _initializer_index, lineage in dropped_lineages
        )
        dropped_rank_promotable_lineage_summary = summarize_rank_promotable_lineage_gap(
            lineage for _initializer_index, lineage in dropped_lineages
        )
        return (
            dict(ordered_lineages[:_ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT]),
            len(dropped_lineages),
            dropped_non_shape_lineages,
            dropped_non_shape_lineage_summary,
            dropped_weight_lineages,
            dropped_rank_promotable_lineages,
            dropped_weight_lineage_summary,
            dropped_rank_promotable_lineage_summary,
        )

    def merge_transform_markers(
        left: tuple[_OnnxWeightTransform, ...],
        right: tuple[_OnnxWeightTransform, ...],
    ) -> tuple[_OnnxWeightTransform, ...]:
        merged: list[_OnnxWeightTransform] = []
        seen: set[_OnnxWeightTransform] = set()
        for transform in (*left, *right):
            if transform in seen:
                continue
            seen.add(transform)
            merged.append(transform)
            if len(merged) >= _ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT:
                break
        return tuple(merged)

    def append_transform_marker(
        transforms: tuple[_OnnxWeightTransform, ...],
        marker: _OnnxWeightTransform,
    ) -> tuple[_OnnxWeightTransform, ...]:
        if marker in transforms or len(transforms) >= _ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT:
            return transforms
        return (*transforms, marker)

    def merge_lineages(
        target: dict[int, _OnnxWeightLineage],
        source: dict[int, _OnnxWeightLineage],
        *,
        ambiguous_reason: str,
    ) -> None:
        for initializer_index, lineage in source.items():
            existing = target.get(initializer_index)
            if existing is None:
                target[initializer_index] = lineage
                continue
            if existing == lineage:
                continue
            if (
                existing.unresolved_reason == "shape_control_lineage"
                and lineage.unresolved_reason != existing.unresolved_reason
            ):
                target[initializer_index] = lineage
                continue
            if (
                lineage.unresolved_reason == "shape_control_lineage"
                and existing.unresolved_reason != lineage.unresolved_reason
            ):
                continue
            reasons = {
                reason for reason in (existing.unresolved_reason, lineage.unresolved_reason) if reason is not None
            }
            stronger_reasons = reasons - {"dynamic_activation_lineage"}
            if len(stronger_reasons) == 1:
                unresolved_reason = next(iter(stronger_reasons))
            elif stronger_reasons:
                unresolved_reason = ambiguous_reason
            elif reasons:
                unresolved_reason = "dynamic_activation_lineage"
            else:
                unresolved_reason = ambiguous_reason
            target[initializer_index] = _OnnxWeightLineage(
                initializer_index=initializer_index,
                shape=None,
                data_type=existing.data_type if existing.data_type == lineage.data_type else None,
                transforms=merge_transform_markers(existing.transforms, lineage.transforms),
                unresolved_reason=unresolved_reason,
            )

    def has_registered_standard_operator(node: Any, opset_versions: dict[str, int]) -> bool:
        domain = str(getattr(node, "domain", "") or "")
        schema_domain = "" if domain == "ai.onnx" else domain
        version = opset_versions.get(domain)
        if version is None and domain in {"", "ai.onnx"}:
            version = opset_versions.get("ai.onnx" if domain == "" else "")
        if version is None:
            return False
        key = (schema_domain, str(getattr(node, "op_type", "")), version)
        if key not in schema_cache:
            try:
                schema_cache[key] = bool(onnx.defs.has(key[1], version, schema_domain))
            except Exception as exc:  # pragma: no cover - fail closed on optional API errors
                logger.debug(
                    "Unable to validate ONNX operator schema %s::%s at version %s: %s",
                    schema_domain,
                    key[1],
                    version,
                    exc,
                )
                schema_cache[key] = False
        return schema_cache[key]

    def walk_graph(
        current_graph: Any,
        inherited_lineages: dict[str, dict[int, _OnnxWeightLineage]],
        inherited_constants: dict[str, Any],
        inherited_dynamic_values: set[str],
        *,
        root_graph: bool,
        source_scope: tuple[Any, ...],
        opset_versions: dict[str, int],
        bound_lineages: dict[str, dict[int, _OnnxWeightLineage]] | None = None,
        bound_constants: dict[str, Any] | None = None,
        bound_dynamic_values: set[str] | None = None,
        inherited_lineage_limit_gap_counts: dict[str, int] | None = None,
        inherited_non_shape_lineage_limit_gap_counts: dict[str, int] | None = None,
        inherited_non_shape_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] | None = None,
        inherited_weight_lineage_limit_gap_counts: dict[str, int] | None = None,
        inherited_weight_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] | None = None,
        inherited_rank_promotable_lineage_limit_gap_counts: dict[str, int] | None = None,
        inherited_rank_promotable_lineage_limit_gap_summaries: (dict[str, _OnnxWeightLineageGapSummary] | None) = None,
        bound_lineage_limit_gap_counts: dict[str, int] | None = None,
        bound_non_shape_lineage_limit_gap_counts: dict[str, int] | None = None,
        bound_non_shape_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] | None = None,
        bound_weight_lineage_limit_gap_counts: dict[str, int] | None = None,
        bound_weight_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] | None = None,
        bound_rank_promotable_lineage_limit_gap_counts: dict[str, int] | None = None,
        bound_rank_promotable_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] | None = None,
        bound_value_shapes: dict[str, tuple[int, ...]] | None = None,
        bound_value_ranks: dict[str, int] | None = None,
        bound_unknown_value_ranks: set[str] | None = None,
        bound_proven_value_ranks: set[str] | None = None,
        bound_attributes: dict[str, Any] | None = None,
        bound_attribute_keys: dict[str, tuple[Any, ...]] | None = None,
        function_depth: int = 0,
        fail_on_unbound_inputs: bool = False,
        captured_state: tuple[
            dict[str, dict[int, _OnnxWeightLineage]],
            dict[str, Any],
            set[str],
            dict[str, int],
            dict[str, int],
            dict[str, _OnnxWeightLineageGapSummary],
            dict[str, int],
            dict[str, _OnnxWeightLineageGapSummary],
            dict[str, int],
            dict[str, _OnnxWeightLineageGapSummary],
        ]
        | None = None,
    ) -> tuple[
        list[dict[int, _OnnxWeightLineage]],
        list[bool],
        list[int],
        list[int],
        list[_OnnxWeightLineageGapSummary],
        list[int],
        list[_OnnxWeightLineageGapSummary],
        list[int],
        list[_OnnxWeightLineageGapSummary],
        list[tuple[int, ...] | None],
        list[int | None],
        list[bool],
    ]:
        nonlocal graph_counter, node_counter, total_consumer_count
        current_graph_index = graph_counter
        graph_counter += 1
        inherited_lineage_limit_gap_counts = inherited_lineage_limit_gap_counts or {}
        inherited_non_shape_lineage_limit_gap_counts = inherited_non_shape_lineage_limit_gap_counts or {}
        inherited_non_shape_lineage_limit_gap_summaries = inherited_non_shape_lineage_limit_gap_summaries or {}
        inherited_weight_lineage_limit_gap_counts = inherited_weight_lineage_limit_gap_counts or {}
        inherited_weight_lineage_limit_gap_summaries = inherited_weight_lineage_limit_gap_summaries or {}
        inherited_rank_promotable_lineage_limit_gap_counts = inherited_rank_promotable_lineage_limit_gap_counts or {}
        inherited_rank_promotable_lineage_limit_gap_summaries = (
            inherited_rank_promotable_lineage_limit_gap_summaries or {}
        )
        if root_graph:
            value_lineages = dict(inherited_lineages)
            constants = dict(inherited_constants)
            dynamic_values = set(inherited_dynamic_values)
            value_lineage_limit_gap_counts = dict(inherited_lineage_limit_gap_counts)
            value_non_shape_lineage_limit_gap_counts = dict(inherited_non_shape_lineage_limit_gap_counts)
            value_non_shape_lineage_limit_gap_summaries = dict(inherited_non_shape_lineage_limit_gap_summaries)
            value_weight_lineage_limit_gap_counts = dict(inherited_weight_lineage_limit_gap_counts)
            value_weight_lineage_limit_gap_summaries = dict(inherited_weight_lineage_limit_gap_summaries)
            value_rank_promotable_lineage_limit_gap_counts = dict(inherited_rank_promotable_lineage_limit_gap_counts)
            value_rank_promotable_lineage_limit_gap_summaries = dict(
                inherited_rank_promotable_lineage_limit_gap_summaries
            )
        else:
            declared_names = _graph_declared_value_names(current_graph)
            value_lineages = {
                name: lineages for name, lineages in inherited_lineages.items() if name not in declared_names
            }
            constants = {name: value for name, value in inherited_constants.items() if name not in declared_names}
            dynamic_values = {name for name in inherited_dynamic_values if name not in declared_names}
            value_lineage_limit_gap_counts = {
                name: count for name, count in inherited_lineage_limit_gap_counts.items() if name not in declared_names
            }
            value_non_shape_lineage_limit_gap_counts = {
                name: count
                for name, count in inherited_non_shape_lineage_limit_gap_counts.items()
                if name not in declared_names
            }
            value_non_shape_lineage_limit_gap_summaries = {
                name: summary
                for name, summary in inherited_non_shape_lineage_limit_gap_summaries.items()
                if name not in declared_names
            }
            value_weight_lineage_limit_gap_counts = {
                name: count
                for name, count in inherited_weight_lineage_limit_gap_counts.items()
                if name not in declared_names
            }
            value_weight_lineage_limit_gap_summaries = {
                name: summary
                for name, summary in inherited_weight_lineage_limit_gap_summaries.items()
                if name not in declared_names
            }
            value_rank_promotable_lineage_limit_gap_counts = {
                name: count
                for name, count in inherited_rank_promotable_lineage_limit_gap_counts.items()
                if name not in declared_names
            }
            value_rank_promotable_lineage_limit_gap_summaries = {
                name: summary
                for name, summary in inherited_rank_promotable_lineage_limit_gap_summaries.items()
                if name not in declared_names
            }

        value_lineages.update(bound_lineages or {})
        constants.update(bound_constants or {})
        dynamic_values.update(bound_dynamic_values or set())
        value_lineage_limit_gap_counts.update(bound_lineage_limit_gap_counts or {})
        value_non_shape_lineage_limit_gap_counts.update(bound_non_shape_lineage_limit_gap_counts or {})
        value_non_shape_lineage_limit_gap_summaries.update(bound_non_shape_lineage_limit_gap_summaries or {})
        value_weight_lineage_limit_gap_counts.update(bound_weight_lineage_limit_gap_counts or {})
        value_weight_lineage_limit_gap_summaries.update(bound_weight_lineage_limit_gap_summaries or {})
        value_rank_promotable_lineage_limit_gap_counts.update(bound_rank_promotable_lineage_limit_gap_counts or {})
        value_rank_promotable_lineage_limit_gap_summaries.update(
            bound_rank_promotable_lineage_limit_gap_summaries or {}
        )
        attribute_bindings = bound_attributes or {}
        attribute_binding_keys = bound_attribute_keys or {}
        bound_proven_ranks = bound_proven_value_ranks or set()
        graph_input_names = {
            name for value_info in getattr(current_graph, "input", ()) if (name := _onnx_value_name(value_info))
        }
        known_value_shapes: dict[str, tuple[int, ...]] = {}
        known_value_ranks: dict[str, int] = {}
        proven_value_ranks: set[str] = set()

        def set_known_value_shape(name: str, shape: tuple[int, ...], *, proven: bool) -> None:
            known_value_shapes[name] = shape
            known_value_ranks[name] = len(shape)
            if proven:
                proven_value_ranks.add(name)
            else:
                proven_value_ranks.discard(name)

        def set_known_value_rank(name: str, rank: int, *, proven: bool) -> None:
            known_value_shapes.pop(name, None)
            known_value_ranks[name] = rank
            if proven:
                proven_value_ranks.add(name)
            else:
                proven_value_ranks.discard(name)

        def clear_known_value_rank(name: str) -> None:
            known_value_shapes.pop(name, None)
            known_value_ranks.pop(name, None)
            proven_value_ranks.discard(name)

        def proven_value_rank(name: str) -> int | None:
            if name in proven_value_ranks:
                return known_value_ranks.get(name)
            return None

        def value_rank_is_proven_or_unknown(name: str) -> bool:
            return name not in known_value_ranks or name in proven_value_ranks

        def value_has_unknown_dynamic_rank(name: str) -> bool:
            return (
                name in dynamic_values
                and name not in value_lineages
                and name not in constants
                and name not in known_value_shapes
                and name not in proven_value_ranks
            )

        def rank_one_weight_gap_is_safe(name: str, summary: _OnnxWeightLineageGapSummary, count: int) -> bool:
            if count <= 0:
                return False
            proven_rank = proven_value_rank(name)
            value_rank = proven_rank
            if value_rank is None and not summary.truncated and summary.lineages:
                summary_ranks = {len(lineage.shape) for lineage in summary.lineages if lineage.shape is not None}
                summary_shapes_known = all(lineage.shape is not None for lineage in summary.lineages)
                if len(summary_ranks) == 1 and summary_shapes_known:
                    value_rank = next(iter(summary_ranks))
                elif summary_shapes_known and (known_rank := known_value_ranks.get(name)) is not None:
                    value_rank = known_rank
            return (
                value_rank is not None
                and value_rank < 2
                and (not summary.truncated or proven_rank is not None)
                and not any(
                    lineage.shape is not None and len(lineage.shape) > value_rank for lineage in summary.lineages
                )
            )

        for value_info in getattr(current_graph, "input", ()):
            name = _onnx_value_name(value_info)
            shape = value_info_shape(value_info)
            if name and shape is not None:
                set_known_value_shape(name, shape, proven=root_graph)
            elif name and (rank := value_info_rank(value_info)) is not None:
                set_known_value_rank(name, rank, proven=root_graph)
        for value_info in (*getattr(current_graph, "value_info", ()), *getattr(current_graph, "output", ())):
            name = _onnx_value_name(value_info)
            if root_graph and name in graph_input_names:
                continue
            shape = value_info_shape(value_info)
            if name and shape is not None:
                set_known_value_shape(name, shape, proven=False)
            elif name and (rank := value_info_rank(value_info)) is not None:
                set_known_value_rank(name, rank, proven=False)
        for name, shape in (bound_value_shapes or {}).items():
            set_known_value_shape(name, shape, proven=name in bound_proven_ranks)
        for name, rank in (bound_value_ranks or {}).items():
            if name not in known_value_shapes:
                set_known_value_rank(name, rank, proven=name in bound_proven_ranks)
        for name in bound_unknown_value_ranks or set():
            clear_known_value_rank(name)
        for name, lineages in value_lineages.items():
            if name in graph_input_names:
                continue
            lineage_shapes = {lineage.shape for lineage in lineages.values()}
            if len(lineage_shapes) == 1 and None not in lineage_shapes:
                set_known_value_shape(name, next(iter(lineage_shapes)), proven=True)  # type: ignore[arg-type]
        for name, constant in constants.items():
            if name in graph_input_names:
                continue
            try:
                set_known_value_shape(name, tuple(int(dimension) for dimension in constant.dims), proven=True)
            except (AttributeError, TypeError, ValueError):
                continue

        def clear_value_gap_state(name: str) -> None:
            value_lineage_limit_gap_counts.pop(name, None)
            value_non_shape_lineage_limit_gap_counts.pop(name, None)
            value_non_shape_lineage_limit_gap_summaries.pop(name, None)
            value_weight_lineage_limit_gap_counts.pop(name, None)
            value_weight_lineage_limit_gap_summaries.pop(name, None)
            value_rank_promotable_lineage_limit_gap_counts.pop(name, None)
            value_rank_promotable_lineage_limit_gap_summaries.pop(name, None)

        def value_has_bound_runtime_state(name: str) -> bool:
            return (
                name in value_lineages
                or name in dynamic_values
                or name in value_lineage_limit_gap_counts
                or name in value_non_shape_lineage_limit_gap_counts
                or name in value_weight_lineage_limit_gap_counts
                or name in value_rank_promotable_lineage_limit_gap_counts
            )

        def resolve_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return attribute_bindings.get(reference_name) if reference_name else attribute

        def resolved_int_attribute(node: Any, name: str, default: int = 0) -> int:
            for attribute in getattr(node, "attribute", []):
                if attribute.name != name:
                    continue
                resolved_attribute = resolve_attribute(attribute)
                return int(getattr(resolved_attribute, "i", default)) if resolved_attribute is not None else default
            return default

        def resolved_int_sequence_attribute(node: Any, name: str) -> tuple[int, ...] | None:
            for attribute in getattr(node, "attribute", []):
                if attribute.name != name:
                    continue
                resolved_attribute = resolve_attribute(attribute)
                if resolved_attribute is None:
                    return None
                return tuple(int(value) for value in getattr(resolved_attribute, "ints", ()))
            return None

        def attribute_source_key(
            attribute: Any,
            node_position: int,
            attribute_position: int,
        ) -> tuple[Any, ...]:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            if reference_name:
                return attribute_binding_keys.get(
                    reference_name,
                    (*source_scope, "unresolved_attribute_reference", reference_name),
                )
            return (*source_scope, "node", node_position, "attribute", attribute_position)

        for initializer_position, initializer in enumerate(getattr(current_graph, "initializer", ())):
            if initializer.name:
                name = str(initializer.name)
                preserve_bound_runtime_state = name in graph_input_names and value_has_bound_runtime_state(name)
                if not preserve_bound_runtime_state:
                    lineage = register_initializer(
                        initializer,
                        current_graph_index,
                        source_key=(*source_scope, "initializer", initializer_position),
                    )
                    value_lineages[name] = {lineage.initializer_index: lineage}
                if name not in graph_input_names:
                    constants[name] = initializer
                    if not preserve_bound_runtime_state:
                        set_known_value_shape(name, lineage.shape or (), proven=True)
                    dynamic_values.discard(name)
                    clear_value_gap_state(name)
                elif name not in constants:
                    dynamic_values.add(name)
                    if not preserve_bound_runtime_state:
                        clear_value_gap_state(name)
        for sparse_position, sparse_initializer in enumerate(getattr(current_graph, "sparse_initializer", ())):
            if sparse_initializer.values.name:
                name = str(sparse_initializer.values.name)
                preserve_bound_runtime_state = name in graph_input_names and value_has_bound_runtime_state(name)
                if not preserve_bound_runtime_state:
                    lineage = register_initializer(
                        sparse_initializer.values,
                        current_graph_index,
                        shape=tuple(int(dimension) for dimension in sparse_initializer.dims),
                        unresolved_reason="sparse_initializer_unsupported",
                        source_key=(*source_scope, "sparse_initializer", sparse_position),
                    )
                    value_lineages[name] = {lineage.initializer_index: lineage}
                if name not in graph_input_names:
                    dynamic_values.discard(name)
                    clear_value_gap_state(name)
                    set_known_value_shape(name, lineage.shape or (), proven=True)
                elif name not in constants:
                    dynamic_values.add(name)
                    if not preserve_bound_runtime_state:
                        clear_value_gap_state(name)

        for graph_input in getattr(current_graph, "input", ()):
            name = _onnx_value_name(graph_input)
            if name and name not in value_lineages and name not in constants:
                dynamic_values.add(name)

        for local_node_index, node in enumerate(getattr(current_graph, "node", ())):
            current_node_index = node_counter
            node_counter += 1
            function_key = (
                str(getattr(node, "domain", "")),
                str(getattr(node, "op_type", "")),
                str(getattr(node, "overload", "")),
            )
            is_model_local_function = function_key in functions
            is_registered_standard_operator = is_model_local_function or has_registered_standard_operator(
                node,
                opset_versions,
            )
            supported_transform = getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS and node.op_type in {
                "Cast",
                "Expand",
                "Flatten",
                "GatherND",
                "Identity",
                "Reshape",
                "Squeeze",
                "Transpose",
                "Unsqueeze",
            }
            rank_gap_promoting_operator = (
                getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and not is_model_local_function
                and is_rank_gap_promoting_operator(node)
            )
            all_input_lineages: dict[int, _OnnxWeightLineage] = {}
            all_input_lineage_limit_gap_count = 0
            all_input_non_shape_lineage_limit_gap_count = 0
            all_input_non_shape_lineage_gap_summary = empty_weight_gap_summary
            all_input_weight_lineage_limit_gap_count = 0
            all_input_weight_lineage_limit_gap_summary = empty_weight_gap_summary
            all_input_rank_promotable_lineage_limit_gap_count = 0
            all_input_rank_promotable_lineage_limit_gap_summary = empty_weight_gap_summary
            all_input_lineage_limit_gap_names: set[str] = set()
            transform_data_input_rank_promotable_lineage_limit_gap_count = 0
            transform_data_input_rank_promotable_lineage_limit_gap_summary = empty_weight_gap_summary
            shape_control_input_lineages: dict[int, _OnnxWeightLineage] = {}
            terminal_weight_lineages: set[int] = set()
            activation_input_lineages: set[int] = set()
            recurrent_state_lineages: dict[int, _OnnxWeightLineage] = {}
            input_names = [str(input_name) for input_name in node.input if input_name]
            if fail_on_unbound_inputs:
                for input_name in input_names:
                    if (
                        input_name not in dynamic_values
                        and input_name not in value_lineages
                        and input_name not in constants
                    ):
                        plan.record_coverage_gap("unresolved_training_graph_input")
            has_dynamic_input = any(
                input_name in dynamic_values or (input_name not in value_lineages and input_name not in constants)
                for input_name in input_names
            )
            has_referenced_attributes = any(
                getattr(attribute, "ref_attr_name", "") for attribute in getattr(node, "attribute", ())
            )
            resolved_weight_input_indexes = {
                input_index
                for input_index, input_name in enumerate(node.input)
                for lineage in value_lineages.get(str(input_name), {}).values()
                if lineage.unresolved_reason is None
                and _onnx_weight_output_axes(node, input_index, len(lineage.shape or ()))[0] is not None
            }
            lineage_input_indexes = {
                input_index for input_index, input_name in enumerate(node.input) if value_lineages.get(str(input_name))
            }
            dynamic_activation_input_indexes = {
                input_index
                for input_index, input_name in enumerate(node.input)
                if value_lineages.get(str(input_name))
                and all(
                    lineage.unresolved_reason == "dynamic_activation_lineage"
                    for lineage in value_lineages[str(input_name)].values()
                )
            }
            batch_normalization_activation_parameter_lineages: set[int] = set()
            if (
                is_registered_standard_operator
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type == "BatchNormalization"
                and input_names
                and (
                    input_names[0] in dynamic_values
                    or (
                        bool(value_lineages.get(input_names[0]))
                        and all(
                            lineage.unresolved_reason == "dynamic_activation_lineage"
                            for lineage in value_lineages[input_names[0]].values()
                        )
                    )
                )
            ):
                for parameter_name in input_names[1:5]:
                    batch_normalization_activation_parameter_lineages.update(value_lineages.get(parameter_name, {}))
            all_lineage_inputs_are_activation_contraction = (
                getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type in {"Einsum", "MatMul"}
                and len(lineage_input_indexes) >= 2
                and lineage_input_indexes == dynamic_activation_input_indexes
            )

            for input_index, input_name in enumerate(node.input):
                input_lineages = value_lineages.get(str(input_name), {})
                input_lineage_limit_gap_count = value_lineage_limit_gap_counts.get(str(input_name), 0)
                input_non_shape_lineage_limit_gap_count = value_non_shape_lineage_limit_gap_counts.get(
                    str(input_name),
                    0,
                )
                input_non_shape_lineage_gap_summary = known_weight_gap_summary(
                    value_non_shape_lineage_limit_gap_summaries.get(str(input_name)),
                    input_non_shape_lineage_limit_gap_count,
                )
                input_weight_lineage_limit_gap_count = value_weight_lineage_limit_gap_counts.get(str(input_name), 0)
                input_weight_lineage_limit_gap_summary = known_weight_gap_summary(
                    value_weight_lineage_limit_gap_summaries.get(str(input_name)),
                    input_weight_lineage_limit_gap_count,
                )
                input_rank_promotable_lineage_limit_gap_count = value_rank_promotable_lineage_limit_gap_counts.get(
                    str(input_name),
                    0,
                )
                input_rank_promotable_lineage_limit_gap_summary = known_weight_gap_summary(
                    value_rank_promotable_lineage_limit_gap_summaries.get(str(input_name)),
                    input_rank_promotable_lineage_limit_gap_count,
                )
                if rank_gap_promoting_operator and input_index == 0:
                    transform_data_input_rank_promotable_lineage_limit_gap_count = (
                        input_rank_promotable_lineage_limit_gap_count
                    )
                    transform_data_input_rank_promotable_lineage_limit_gap_summary = (
                        input_rank_promotable_lineage_limit_gap_summary
                    )
                is_array_feature_selector = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") == "ai.onnx.ml"
                    and node.op_type == "ArrayFeatureExtractor"
                    and input_index == 1
                )
                is_non_data_standard_input = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and (
                        (node.op_type == "Clip" and input_index > 0)
                        or (
                            not is_model_local_function
                            and node.op_type in _RECURRENT_WEIGHT_OPERATORS
                            and input_index == 4
                        )
                    )
                )
                is_shape_control_input = (
                    is_registered_standard_operator
                    and not is_model_local_function
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and (
                        (node.op_type in {"Expand", "Gather", "GatherElements", "GatherND"} and input_index == 1)
                        or (node.op_type == "Reshape" and input_index == 1)
                        or (node.op_type == "Slice" and input_index > 0)
                        or (node.op_type in {"Squeeze", "Unsqueeze"} and input_index == 1)
                        or (node.op_type == "Tile" and input_index == 1)
                        or (node.op_type == "Where" and input_index == 0)
                    )
                )
                if is_shape_control_input:
                    # Shape and Size can later turn output dimensions into numeric data.
                    shape_control_lineages = {
                        initializer_index: _OnnxWeightLineage(
                            initializer_index=initializer_index,
                            shape=None,
                            data_type=None,
                            transforms=lineage.transforms,
                            unresolved_reason="shape_control_lineage",
                        )
                        for initializer_index, lineage in input_lineages.items()
                    }
                    merge_lineages(
                        all_input_lineages,
                        shape_control_lineages,
                        ambiguous_reason="ambiguous_operator_input_lineage",
                    )
                    if input_lineages and input_name not in all_input_lineage_limit_gap_names:
                        all_input_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_lineage_limit_gap_count,
                            input_lineage_limit_gap_count,
                        )
                        all_input_weight_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_weight_lineage_limit_gap_count,
                            input_weight_lineage_limit_gap_count,
                        )
                        all_input_weight_lineage_limit_gap_summary = merge_weight_lineage_gap_summaries(
                            all_input_weight_lineage_limit_gap_summary,
                            input_weight_lineage_limit_gap_summary,
                        )
                        all_input_rank_promotable_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_rank_promotable_lineage_limit_gap_count,
                            input_rank_promotable_lineage_limit_gap_count,
                        )
                        all_input_rank_promotable_lineage_limit_gap_summary = merge_weight_lineage_gap_summaries(
                            all_input_rank_promotable_lineage_limit_gap_summary,
                            input_rank_promotable_lineage_limit_gap_summary,
                        )
                        all_input_lineage_limit_gap_names.add(input_name)
                    merge_lineages(
                        shape_control_input_lineages,
                        shape_control_lineages,
                        ambiguous_reason="ambiguous_operator_input_lineage",
                    )
                elif not is_array_feature_selector and not is_non_data_standard_input:
                    merge_lineages(
                        all_input_lineages,
                        input_lineages,
                        ambiguous_reason="ambiguous_operator_input_lineage",
                    )
                    if input_lineages and input_name not in all_input_lineage_limit_gap_names:
                        all_input_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_lineage_limit_gap_count,
                            input_lineage_limit_gap_count,
                        )
                        all_input_non_shape_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_non_shape_lineage_limit_gap_count,
                            input_non_shape_lineage_limit_gap_count,
                        )
                        all_input_non_shape_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                            all_input_non_shape_lineage_gap_summary,
                            input_non_shape_lineage_gap_summary,
                        )
                        all_input_weight_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_weight_lineage_limit_gap_count,
                            input_weight_lineage_limit_gap_count,
                        )
                        all_input_weight_lineage_limit_gap_summary = merge_weight_lineage_gap_summaries(
                            all_input_weight_lineage_limit_gap_summary,
                            input_weight_lineage_limit_gap_summary,
                        )
                        all_input_rank_promotable_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                            all_input_rank_promotable_lineage_limit_gap_count,
                            input_rank_promotable_lineage_limit_gap_count,
                        )
                        all_input_rank_promotable_lineage_limit_gap_summary = merge_weight_lineage_gap_summaries(
                            all_input_rank_promotable_lineage_limit_gap_summary,
                            input_rank_promotable_lineage_limit_gap_summary,
                        )
                        all_input_lineage_limit_gap_names.add(input_name)
                recurrent_initial_state_input = (
                    is_registered_standard_operator
                    and not is_model_local_function
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and node.op_type in _RECURRENT_WEIGHT_OPERATORS
                    and (input_index == 5 or (node.op_type == "LSTM" and input_index == 6))
                )
                potential_weight_role = _onnx_potential_weight_input(
                    node,
                    input_index,
                    is_model_local_function=is_model_local_function,
                    is_registered_standard_operator=is_registered_standard_operator,
                )
                opposite_resolved_weight_for_input = any(
                    resolved_index != input_index for resolved_index in resolved_weight_input_indexes
                )
                prior_layer_activation_input = bool(input_lineages) and all(
                    lineage.unresolved_reason == "dynamic_activation_lineage" for lineage in input_lineages.values()
                )
                activation_input_role = prior_layer_activation_input and (
                    (is_registered_standard_operator and _onnx_opaque_activation_input_candidate(node, input_index))
                    or (
                        _onnx_activation_input_candidate(node, input_index)
                        and (opposite_resolved_weight_for_input or all_lineage_inputs_are_activation_contraction)
                    )
                )
                activation_input_role |= recurrent_initial_state_input and opposite_resolved_weight_for_input
                recognized_gap_activation_input = activation_input_role and gap_summary_is_dynamic_activation(
                    input_weight_lineage_limit_gap_summary,
                    input_weight_lineage_limit_gap_count,
                )
                rank_one_weight_gap = rank_one_weight_gap_is_safe(
                    str(input_name),
                    input_weight_lineage_limit_gap_summary,
                    input_weight_lineage_limit_gap_count,
                )
                if rank_one_weight_gap:
                    input_rank_for_gap = known_value_ranks.get(str(input_name))
                    rank_one_weight_gap = not (
                        gap_summary_has_known_rank_above_input(input_non_shape_lineage_gap_summary, input_rank_for_gap)
                        or gap_summary_has_known_rank_above_input(
                            input_rank_promotable_lineage_limit_gap_summary,
                            input_rank_for_gap,
                        )
                    )
                recorded_input_lineage_limit_gap = recognized_gap_activation_input
                if (
                    potential_weight_role
                    and input_weight_lineage_limit_gap_count
                    and not recognized_gap_activation_input
                    and not rank_one_weight_gap
                ):
                    plan.record_coverage_gap("lineages_per_value_limit", input_weight_lineage_limit_gap_count)
                    recorded_input_lineage_limit_gap = True
                for initializer_index, lineage in input_lineages.items():
                    invalid_clip_bound = (
                        is_registered_standard_operator
                        and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                        and node.op_type == "Clip"
                        and input_index > 0
                        and lineage.unresolved_reason != "shape_control_lineage"
                        and lineage.shape != ()
                    )
                    if invalid_clip_bound:
                        record_unresolved_lineage(
                            _OnnxWeightLineage(
                                initializer_index=initializer_index,
                                shape=lineage.shape,
                                data_type=lineage.data_type,
                                transforms=lineage.transforms,
                                unresolved_reason="invalid_clip_bound_shape",
                            ),
                            node,
                            current_node_index,
                            input_index,
                        )
                    potential_weight_input = potential_weight_role and lineage_could_be_weight(lineage)
                    if (
                        potential_weight_input
                        and input_weight_lineage_limit_gap_count
                        and not recorded_input_lineage_limit_gap
                    ):
                        plan.record_coverage_gap("lineages_per_value_limit", input_weight_lineage_limit_gap_count)
                        recorded_input_lineage_limit_gap = True
                    if supported_transform and input_index == 0:
                        continue
                    known_input_rank = proven_value_rank(str(input_name))
                    if potential_weight_input and (
                        (lineage.shape is not None and len(lineage.shape) < 2)
                        or (
                            known_input_rank is not None
                            and known_input_rank < 2
                            and (lineage.shape is None or len(lineage.shape) < 2)
                            and not gap_summary_may_exceed_input_rank(
                                input_weight_lineage_limit_gap_summary,
                                known_input_rank,
                            )
                        )
                    ):
                        potential_weight_input = False
                    if potential_weight_input:
                        terminal_weight_lineages.add(initializer_index)
                    terminal_consumer_counts[initializer_index] += 1
                    total_consumer_count += 1
                    recurrent_initial_state = recurrent_initial_state_input
                    if recurrent_initial_state:
                        recurrent_state_lineages[initializer_index] = lineage
                    if lineage.unresolved_reason is not None:
                        if lineage.unresolved_reason == "shape_control_lineage":
                            record_exclusion(initializer_index, "shape_control_input", node, input_index)
                            continue
                        opposite_resolved_weight = any(
                            resolved_index != input_index for resolved_index in resolved_weight_input_indexes
                        )
                        prior_layer_activation = lineage.unresolved_reason == "dynamic_activation_lineage"
                        recurrent_final_state_output = any(
                            transform.kind == "recurrent_state_output" for transform in lineage.transforms
                        )
                        recognized_activation_input = prior_layer_activation and (
                            (
                                is_registered_standard_operator
                                and _onnx_opaque_activation_input_candidate(node, input_index)
                            )
                            or (
                                _onnx_activation_input_candidate(node, input_index)
                                and (opposite_resolved_weight or all_lineage_inputs_are_activation_contraction)
                            )
                        )
                        recognized_activation_input |= recurrent_initial_state and opposite_resolved_weight
                        if recognized_activation_input:
                            if recurrent_initial_state:
                                recurrent_state_lineages[initializer_index] = lineage
                            if opposite_resolved_weight:
                                activation_input_lineages.add(initializer_index)
                            record_exclusion(initializer_index, "dynamic_activation_input", node, input_index)
                        elif potential_weight_input or (
                            (
                                potential_weight_role
                                and lineage.unresolved_reason
                                in {"recurrent_sequence_state_lineage", "recurrent_state_lineage"}
                            )
                            or (
                                potential_weight_role
                                and recurrent_final_state_output
                                and lineage.unresolved_reason != "shape_control_lineage"
                            )
                        ):
                            record_unresolved_lineage(lineage, node, current_node_index, input_index)
                        else:
                            record_exclusion(initializer_index, "unresolved_lineage_consumer", node, input_index)
                        continue
                    if has_referenced_attributes and not (supported_transform and input_index == 0):
                        if potential_weight_input:
                            record_unresolved_lineage(
                                _OnnxWeightLineage(
                                    initializer_index=initializer_index,
                                    shape=None,
                                    data_type=lineage.data_type,
                                    transforms=lineage.transforms,
                                    unresolved_reason="referenced_function_attribute",
                                ),
                                node,
                                current_node_index,
                                input_index,
                            )
                        else:
                            record_exclusion(
                                initializer_index,
                                "referenced_function_attribute_consumer",
                                node,
                                input_index,
                            )
                        continue
                    output_axes, reason = _onnx_weight_output_axes(node, input_index, len(lineage.shape or ()))
                    if output_axes is None:
                        if reason != "non_weight_input" and potential_weight_input:
                            record_unresolved_lineage(
                                _OnnxWeightLineage(
                                    initializer_index=initializer_index,
                                    shape=None,
                                    data_type=lineage.data_type,
                                    transforms=lineage.transforms,
                                    unresolved_reason="unsupported_weight_consumer",
                                ),
                                node,
                                current_node_index,
                                input_index,
                            )
                        else:
                            record_exclusion(initializer_index, reason, node, input_index)
                        continue
                    add_consumer_group(lineage, node, current_node_index, input_index, output_axes)
                    if node.op_type == "Gather":
                        gather_axis = _onnx_gather_axis(node, len(lineage.shape or ()))
                        if gather_axis is not None and (gather_axis,) != output_axes:
                            add_consumer_group(
                                lineage,
                                node,
                                current_node_index,
                                input_index,
                                (gather_axis,),
                            )
                    elif node.op_type == "PRelu":
                        slope_shape = lineage.shape or ()
                        slope_axes = {axis for axis, dimension in enumerate(slope_shape) if dimension != 1}
                        singleton_axes = [axis for axis, dimension in enumerate(slope_shape) if dimension == 1]
                        if singleton_axes:
                            primary_axis = output_axes[0]
                            slope_axes.add(primary_axis if slope_shape[primary_axis] == 1 else singleton_axes[0])
                        for slope_axis in sorted(slope_axes):
                            if (slope_axis,) != output_axes:
                                add_consumer_group(
                                    lineage,
                                    node,
                                    current_node_index,
                                    input_index,
                                    (slope_axis,),
                                )

            subgraph_results: list[
                tuple[
                    list[dict[int, _OnnxWeightLineage]],
                    list[bool],
                    list[int],
                    list[int],
                    list[_OnnxWeightLineageGapSummary],
                    list[int],
                    list[_OnnxWeightLineageGapSummary],
                    list[int],
                    list[_OnnxWeightLineageGapSummary],
                    list[tuple[int, ...] | None],
                    list[int | None],
                    list[bool],
                ]
            ] = []
            for attribute_position, attribute in enumerate(getattr(node, "attribute", ())):
                resolved_attribute = resolve_attribute(attribute)
                if resolved_attribute is None:
                    plan.record_coverage_gap("unresolved_function_attribute")
                    continue
                resolved_attribute_key = attribute_source_key(attribute, local_node_index, attribute_position)
                for subgraph_position, subgraph in enumerate(_iter_attribute_graphs(resolved_attribute)):
                    subgraph_bound_lineages: dict[str, dict[int, _OnnxWeightLineage]] = {}
                    subgraph_bound_constants: dict[str, Any] = {}
                    subgraph_bound_dynamic: set[str] = set()
                    subgraph_bound_lineage_gaps: dict[str, int] = {}
                    subgraph_bound_non_shape_lineage_gaps: dict[str, int] = {}
                    subgraph_bound_non_shape_lineage_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
                    subgraph_bound_weight_lineage_gaps: dict[str, int] = {}
                    subgraph_bound_weight_lineage_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
                    subgraph_bound_rank_promotable_lineage_gaps: dict[str, int] = {}
                    subgraph_bound_rank_promotable_lineage_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
                    subgraph_bound_value_shapes: dict[str, tuple[int, ...]] = {}
                    subgraph_bound_value_ranks: dict[str, int] = {}
                    subgraph_bound_unknown_value_ranks: set[str] = set()
                    subgraph_bound_proven_value_ranks: set[str] = set()
                    subgraph_input_names = {
                        name for value_info in getattr(subgraph, "input", ()) if (name := _onnx_value_name(value_info))
                    }
                    subgraph_trusted_context_shapes = {
                        name: known_value_shapes[name]
                        for name in graph_external_reference_names(subgraph)
                        if name in known_value_shapes and name in proven_value_ranks and name not in value_lineages
                    }
                    input_pairs: Iterable[tuple[Any, Any]]
                    input_pair_index_start = 0
                    scan_input_start = len(node.input)
                    scan_input_offset = 0
                    scan_input_axes: tuple[int, ...] = ()
                    if node.op_type == "Loop":
                        input_pairs = zip(node.input[2:], subgraph.input[2:], strict=False)
                        input_pair_index_start = 2
                    elif node.op_type == "Scan":
                        num_scan_inputs = resolved_int_attribute(node, "num_scan_inputs", 1)
                        scan_input_offset = scan_sequence_lens_input_offset(node, opset_versions)
                        scan_input_start = max(len(node.input) - max(num_scan_inputs, 0), scan_input_offset)
                        scan_input_axes = resolved_int_sequence_attribute(node, "scan_input_axes") or ()
                        input_pairs = zip(node.input[scan_input_offset:], subgraph.input, strict=False)
                        input_pair_index_start = scan_input_offset
                    else:
                        input_pairs = ()
                    input_pairs = tuple(input_pairs)

                    def trusted_bound_context_shape(
                        parent_name: str,
                        pair_index: int,
                        *,
                        op_type: str = node.op_type,
                        scan_input_start: int = scan_input_start,
                        scan_input_offset: int = scan_input_offset,
                        scan_input_axes: tuple[int, ...] = scan_input_axes,
                    ) -> tuple[int, ...] | None:
                        parent_shape = known_value_shapes.get(parent_name)
                        if parent_shape is None:
                            parent_shape = constant_initializer_shape(constants, parent_name)
                        if op_type == "Scan" and pair_index >= scan_input_start:
                            parent_shape, _parent_rank = _onnx_scan_bound_subgraph_input_shape(
                                parent_shape,
                                known_value_ranks.get(parent_name),
                                pair_index=pair_index,
                                scan_input_start=scan_input_start,
                                scan_input_offset=scan_input_offset,
                                scan_input_axes=scan_input_axes,
                            )
                        if parent_shape is None or parent_name in value_lineages:
                            return None
                        if parent_name in proven_value_ranks:
                            return parent_shape
                        if parent_name in constants and parent_name not in graph_input_names:
                            return parent_shape
                        return None

                    if node.op_type == "Loop" and len(node.input) > 1 and len(getattr(subgraph, "input", ())) > 1:
                        loop_condition_name = str(node.input[1])
                        loop_body_condition_name = _onnx_value_name(subgraph.input[1])
                        loop_condition_shape = known_value_shapes.get(loop_condition_name)
                        if loop_condition_shape is None:
                            loop_condition_shape = constant_initializer_shape(constants, loop_condition_name)
                        immutable_scalar_condition = (
                            loop_condition_name in constants
                            and loop_condition_name not in graph_input_names
                            and constant_scalar_value(
                                constants.get(loop_condition_name),
                                int(onnx.TensorProto.BOOL),
                            )
                            is not None
                        )
                        if (
                            loop_body_condition_name
                            and loop_condition_shape is not None
                            and (loop_condition_name in proven_value_ranks or immutable_scalar_condition)
                            and (loop_condition_name not in value_lineages or immutable_scalar_condition)
                        ):
                            subgraph_trusted_context_shapes[loop_body_condition_name] = loop_condition_shape

                    scan_num_inputs = num_scan_inputs if node.op_type == "Scan" else 0

                    def loop_exact_iteration_count(
                        current_node: Any = node,
                        *,
                        max_count: int = 1,
                    ) -> int | None:
                        trip_input = (
                            str(current_node.input[0]) if len(current_node.input) > 0 and current_node.input[0] else ""
                        )
                        condition_input = (
                            str(current_node.input[1]) if len(current_node.input) > 1 and current_node.input[1] else ""
                        )
                        if trip_input in graph_input_names or condition_input in graph_input_names:
                            return None
                        trip_count = (
                            constant_scalar_value(constants.get(trip_input), int(onnx.TensorProto.INT64))
                            if trip_input
                            else None
                        )
                        initial_condition = (
                            constant_scalar_value(constants.get(condition_input), int(onnx.TensorProto.BOOL))
                            if condition_input
                            else True
                        )
                        if trip_count is None or initial_condition is not True:
                            return None
                        exact_count = max(int(trip_count), 0)
                        return exact_count if exact_count <= max_count else None

                    exact_loop_replay_work_remaining = _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK
                    exact_loop_replay_work_exhausted = False
                    nested_attribute_reference_cache: dict[
                        int,
                        tuple[Any, tuple[tuple[Any, frozenset[str] | None], ...]],
                    ] = {}
                    nested_external_reference_cache: dict[int, tuple[Any, frozenset[str] | None]] = {}
                    nested_reference_state = (
                        nested_attribute_reference_cache,
                        nested_external_reference_cache,
                    )
                    nested_reference_work_remaining = _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK

                    def bounded_nested_external_reference_names(
                        graph: Any,
                        external_reference_cache: dict[int, tuple[Any, frozenset[str] | None]],
                    ) -> frozenset[str] | None:
                        nonlocal nested_reference_work_remaining
                        cache_key = id(graph)
                        cached_reference_names = external_reference_cache.get(cache_key)
                        if cached_reference_names is not None and cached_reference_names[0] is graph:
                            return cached_reference_names[1]
                        graph_nodes = tuple(getattr(graph, "node", ()))
                        nested_reference_work_remaining -= max(len(graph_nodes), 1)
                        if nested_reference_work_remaining < 0:
                            return None
                        local_names = {
                            name for value_info in getattr(graph, "input", ()) if (name := _onnx_value_name(value_info))
                        }
                        local_names.update(
                            str(initializer.name)
                            for initializer in getattr(graph, "initializer", ())
                            if getattr(initializer, "name", "")
                        )
                        local_names.update(
                            str(sparse_initializer.values.name)
                            for sparse_initializer in getattr(graph, "sparse_initializer", ())
                            if getattr(getattr(sparse_initializer, "values", None), "name", "")
                        )
                        produced_names = set(local_names)
                        referenced_names: set[str] = set()
                        for graph_output in getattr(graph, "output", ()):
                            if output_name := _onnx_value_name(graph_output):
                                referenced_names.add(output_name)
                        for graph_node in graph_nodes:
                            referenced_names.update(
                                str(input_name) for input_name in getattr(graph_node, "input", ()) if input_name
                            )
                            produced_names.update(
                                str(output_name) for output_name in getattr(graph_node, "output", ()) if output_name
                            )
                            for attribute in getattr(graph_node, "attribute", ()):
                                for subgraph in _iter_attribute_graphs(attribute):
                                    subgraph_references = bounded_nested_external_reference_names(
                                        subgraph,
                                        external_reference_cache,
                                    )
                                    if subgraph_references is None:
                                        return None
                                    referenced_names.update(subgraph_references)
                        reference_names = frozenset(referenced_names - produced_names - local_names)
                        external_reference_cache[cache_key] = (graph, reference_names)
                        return reference_names

                    def nested_attribute_graph_references(
                        body_node: Any,
                        attribute_reference_cache: dict[
                            int,
                            tuple[Any, tuple[tuple[Any, frozenset[str] | None], ...]],
                        ],
                        external_reference_cache: dict[int, tuple[Any, frozenset[str] | None]],
                    ) -> tuple[tuple[Any, frozenset[str] | None], ...]:
                        cache_key = id(body_node)
                        cached_references = attribute_reference_cache.get(cache_key)
                        if cached_references is not None and cached_references[0] is body_node:
                            return cached_references[1]
                        references = tuple(
                            (
                                nested_graph,
                                bounded_nested_external_reference_names(nested_graph, external_reference_cache),
                            )
                            for attribute in getattr(body_node, "attribute", ())
                            for nested_graph in _iter_attribute_graphs(attribute)
                        )
                        attribute_reference_cache[cache_key] = (body_node, references)
                        return references

                    def subgraph_state_input_consumes_weight_rank_at_or_above_two(
                        subgraph: Any,
                        graph_input_name: str,
                        initial_shape: tuple[int, ...],
                        target_graph_output_index: int,
                        related_input_shapes: dict[str, tuple[int, ...] | None] | None = None,
                        reference_state: tuple[
                            dict[int, tuple[Any, tuple[tuple[Any, frozenset[str] | None], ...]]],
                            dict[int, tuple[Any, frozenset[str] | None]],
                        ] = nested_reference_state,
                    ) -> tuple[bool, tuple[int, ...] | None] | None:
                        nonlocal exact_loop_replay_work_exhausted, exact_loop_replay_work_remaining
                        graph_outputs = getattr(subgraph, "output", ())
                        graph_output_name = (
                            _onnx_value_name(graph_outputs[target_graph_output_index])
                            if 0 <= target_graph_output_index < len(graph_outputs)
                            else ""
                        )
                        subgraph_constants = graph_initializer_constants(subgraph, constants)
                        output_dependency_names = graph_output_dependency_names(
                            subgraph,
                            (target_graph_output_index,),
                        )
                        potential_weight_dependency_names = subgraph_potential_weight_consumer_dependency_names(
                            subgraph,
                            opset_versions,
                        )
                        attribute_reference_cache, external_reference_cache = reference_state

                        def graph_input_reaches_target_output_bounded() -> bool | None:
                            nonlocal exact_loop_replay_work_exhausted, exact_loop_replay_work_remaining
                            if not graph_output_name:
                                return None
                            tainted_names = {graph_input_name}
                            for body_node in getattr(subgraph, "node", ()):
                                body_inputs = node_input_names(body_node)
                                body_outputs = node_output_names(body_node)
                                if not body_outputs:
                                    continue
                                nested_attribute_references = nested_attribute_graph_references(
                                    body_node,
                                    attribute_reference_cache,
                                    external_reference_cache,
                                )
                                has_tainted_nested_capture = any(
                                    reference_names is None or bool(reference_names & tainted_names)
                                    for _nested_graph, reference_names in nested_attribute_references
                                )
                                if has_tainted_nested_capture:
                                    return None
                                any_tainted_input = any(input_name in tainted_names for input_name in body_inputs)
                                if not any_tainted_input:
                                    continue
                                input_walk_work = max(len(body_inputs), 1)
                                if exact_loop_replay_work_remaining < input_walk_work:
                                    exact_loop_replay_work_exhausted = True
                                    return None
                                exact_loop_replay_work_remaining -= input_walk_work
                                function_key = (
                                    str(getattr(body_node, "domain", "")),
                                    str(getattr(body_node, "op_type", "")),
                                    str(getattr(body_node, "overload", "")),
                                )
                                has_nested_attribute_graph = any(
                                    _iter_attribute_graphs(attribute)
                                    for attribute in getattr(body_node, "attribute", ())
                                )
                                if functions.get(function_key) is not None or has_nested_attribute_graph:
                                    return None
                                tainted_names.update(body_outputs)
                            return graph_output_name in tainted_names

                        if dependency_names_exceeded_limit(output_dependency_names):
                            reaches_target_output = graph_input_reaches_target_output_bounded()
                            if reaches_target_output is False:
                                return False, initial_shape
                            return None
                        if dependency_names_exceeded_limit(potential_weight_dependency_names):
                            if not subgraph_state_input_can_reach_weight_consumer(
                                subgraph,
                                graph_input_name,
                                opset_versions,
                            ):
                                potential_weight_dependency_names = frozenset()
                            else:
                                return None
                        transitive_weight_dependency_names = graph_value_dependency_names(
                            subgraph,
                            potential_weight_dependency_names,
                        )
                        if dependency_names_exceeded_limit(transitive_weight_dependency_names):
                            return None
                        combined_dependency_names = set(output_dependency_names)
                        if merge_dependency_names(combined_dependency_names, transitive_weight_dependency_names):
                            return None
                        output_dependency_names = frozenset(combined_dependency_names)
                        output_dependency_node_ids = graph_nodes_producing_names(subgraph, output_dependency_names)
                        tainted_shapes: dict[str, tuple[int, ...] | None] = {graph_input_name: initial_shape}
                        context_shapes = related_input_shapes or {}

                        def resolve_literal_attribute(bound_attribute: Any) -> Any:
                            return bound_attribute

                        def known_input_shape(input_name: str) -> tuple[int, ...] | None:
                            if input_name in tainted_shapes:
                                return tainted_shapes[input_name]
                            if input_name in context_shapes:
                                return context_shapes[input_name]
                            return constant_initializer_shape(subgraph_constants, input_name)

                        def transformed_output_shape(
                            body_node: Any,
                            body_inputs: Sequence[str],
                        ) -> tuple[int, ...] | None:
                            data_input_shape = known_input_shape(body_inputs[0]) if body_inputs else None
                            index_input_shape = known_input_shape(body_inputs[1]) if len(body_inputs) > 1 else None
                            if index_input_shape is None and len(body_inputs) > 1:
                                index_input_shape = constant_initializer_shape(subgraph_constants, body_inputs[1])
                            input_shapes_by_name = {
                                input_name: known_input_shape(input_name)
                                for input_name in body_inputs
                                if known_input_shape(input_name) is not None
                            }
                            if (
                                reentry_shape_preserving_unary_operator(body_node, body_inputs)
                                and data_input_shape is not None
                            ):
                                return data_input_shape
                            if body_node.op_type in _RANK_PRESERVING_VARIADIC_OPERATORS:
                                return _onnx_concat_output_shape(
                                    body_node,
                                    (tainted_shapes.get(input_name) for input_name in body_inputs),
                                    axis=_onnx_int_attribute(body_node, "axis"),
                                )
                            if body_node.op_type == "MatMul":
                                return matmul_output_shape(
                                    tainted_shapes.get(body_inputs[0]) if body_inputs else None,
                                    tainted_shapes.get(body_inputs[1]) if len(body_inputs) > 1 else None,
                                )
                            if body_node.op_type == "OneHot":
                                return onehot_output_shape(
                                    body_node,
                                    tainted_shapes.get(body_inputs[0]) if body_inputs else None,
                                    subgraph_constants,
                                )
                            if body_node.op_type == "Einsum":
                                return einsum_output_shape(body_node, input_shapes_by_name)
                            if body_node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS | {"Pow"}:
                                return broadcast_shapes(tainted_shapes.get(input_name) for input_name in body_inputs)
                            if body_node.op_type == "Expand" and data_input_shape is not None:
                                shape_name = body_inputs[1] if len(body_inputs) > 1 else ""
                                target_shape = constant_int64_vector_values(subgraph_constants.get(shape_name))
                                return (
                                    broadcast_shapes((data_input_shape, target_shape))
                                    if target_shape is not None
                                    else None
                                )
                            if body_node.op_type == "Gather" and data_input_shape is not None:
                                if index_input_shape is None:
                                    return None
                                gather_axis = _onnx_gather_axis(body_node, len(data_input_shape))
                                if gather_axis is None:
                                    return None
                                return (
                                    *data_input_shape[:gather_axis],
                                    *index_input_shape,
                                    *data_input_shape[gather_axis + 1 :],
                                )
                            if body_node.op_type == "GatherElements":
                                return index_input_shape
                            if body_node.op_type == "GatherND" and data_input_shape is not None:
                                if not index_input_shape:
                                    return None
                                return gathernd_output_shape(
                                    body_node,
                                    input_shape=data_input_shape,
                                    index_shape=index_input_shape,
                                    resolve_attribute=None,
                                )
                            if body_node.op_type == "Reshape" and data_input_shape is not None:
                                shape_name = body_inputs[1] if len(body_inputs) > 1 else ""
                                shape_initializer = subgraph_constants.get(shape_name)
                                if shape_initializer is None:
                                    return None
                                return _resolve_onnx_reshape_shape(
                                    data_input_shape,
                                    shape_initializer,
                                    allowzero=bool(_onnx_int_attribute(body_node, "allowzero")),
                                    onnx=onnx,
                                )
                            if body_node.op_type == "Unsqueeze" and data_input_shape is not None:
                                axes = _resolve_onnx_axes(body_node, subgraph_constants, onnx=onnx)
                                if axes is None:
                                    return None
                                output_rank = len(data_input_shape) + len(axes)
                                normalized_axes = tuple(axis if axis >= 0 else output_rank + axis for axis in axes)
                                if (
                                    not normalized_axes
                                    or len(set(normalized_axes)) != len(normalized_axes)
                                    or any(axis < 0 or axis >= output_rank for axis in normalized_axes)
                                ):
                                    return None
                                source_dimensions = iter(data_input_shape)
                                return tuple(
                                    1 if index in normalized_axes else next(source_dimensions)
                                    for index in range(output_rank)
                                )
                            if body_node.op_type == "Squeeze" and data_input_shape is not None:
                                axes = _resolve_onnx_axes(body_node, subgraph_constants, onnx=onnx)
                                if axes is None:
                                    return None
                                normalized_axes = tuple(
                                    axis if axis >= 0 else len(data_input_shape) + axis for axis in axes
                                )
                                if not normalized_axes:
                                    if squeeze_with_empty_axes_is_noop(body_node, axes, None):
                                        return data_input_shape
                                    return tuple(dimension for dimension in data_input_shape if dimension != 1)
                                if (
                                    len(set(normalized_axes)) != len(normalized_axes)
                                    or any(axis < 0 or axis >= len(data_input_shape) for axis in normalized_axes)
                                    or any(data_input_shape[axis] != 1 for axis in normalized_axes)
                                ):
                                    return None
                                squeeze_axes = set(normalized_axes)
                                return tuple(
                                    dimension
                                    for index, dimension in enumerate(data_input_shape)
                                    if index not in squeeze_axes
                                )
                            return None

                        def function_input_consumes_weight_rank_at_or_above_two(
                            function_graph: Any,
                            function_input_name: str,
                            function_input_shape: tuple[int, ...],
                            function_versions: dict[str, int],
                            function_attributes: dict[str, Any],
                            function_constants: dict[str, Any],
                            function_context_shapes: dict[str, tuple[int, ...]],
                        ) -> bool | None:
                            nonlocal exact_loop_replay_work_exhausted, exact_loop_replay_work_remaining
                            weight_dependency_names = subgraph_potential_weight_consumer_dependency_names(
                                function_graph,
                                function_versions,
                                attribute_bindings=function_attributes,
                            )
                            if dependency_names_exceeded_limit(weight_dependency_names):
                                return None
                            weight_dependency_names = graph_value_dependency_names(
                                function_graph,
                                weight_dependency_names,
                                attribute_bindings=function_attributes,
                            )
                            if dependency_names_exceeded_limit(weight_dependency_names):
                                return None
                            live_node_ids = graph_nodes_producing_names(function_graph, weight_dependency_names)
                            local_tainted_shapes: dict[str, tuple[int, ...] | None] = {
                                function_input_name: function_input_shape
                            }

                            def local_known_input_shape(input_name: str) -> tuple[int, ...] | None:
                                if input_name in local_tainted_shapes:
                                    return local_tainted_shapes[input_name]
                                if input_name in function_context_shapes:
                                    return function_context_shapes[input_name]
                                return constant_initializer_shape(function_constants, input_name)

                            def local_output_shape(
                                function_node: Any,
                                function_inputs: Sequence[str],
                            ) -> tuple[int, ...] | None:
                                data_input_shape = (
                                    local_known_input_shape(function_inputs[0]) if function_inputs else None
                                )
                                input_shapes_by_name = {
                                    input_name: local_known_input_shape(input_name)
                                    for input_name in function_inputs
                                    if local_known_input_shape(input_name) is not None
                                }
                                if (
                                    reentry_shape_preserving_unary_operator(function_node, function_inputs)
                                    and data_input_shape is not None
                                ):
                                    return data_input_shape
                                if function_node.op_type in _RANK_PRESERVING_VARIADIC_OPERATORS:
                                    return _onnx_concat_output_shape(
                                        function_node,
                                        (local_tainted_shapes.get(input_name) for input_name in function_inputs),
                                        axis=_onnx_int_attribute(function_node, "axis"),
                                    )
                                if function_node.op_type == "MatMul":
                                    return matmul_output_shape(
                                        local_tainted_shapes.get(function_inputs[0]) if function_inputs else None,
                                        (
                                            local_tainted_shapes.get(function_inputs[1])
                                            if len(function_inputs) > 1
                                            else None
                                        ),
                                    )
                                if function_node.op_type == "OneHot":
                                    return onehot_output_shape(
                                        function_node,
                                        local_tainted_shapes.get(function_inputs[0]) if function_inputs else None,
                                        function_constants,
                                    )
                                if function_node.op_type == "Einsum":
                                    return einsum_output_shape(function_node, input_shapes_by_name)
                                if function_node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS | {"Pow"}:
                                    return broadcast_shapes(
                                        local_tainted_shapes.get(input_name) for input_name in function_inputs
                                    )
                                if function_node.op_type == "Expand" and data_input_shape is not None:
                                    shape_name = function_inputs[1] if len(function_inputs) > 1 else ""
                                    target_shape = constant_int64_vector_values(function_constants.get(shape_name))
                                    return (
                                        broadcast_shapes((data_input_shape, target_shape))
                                        if target_shape is not None
                                        else None
                                    )
                                if function_node.op_type == "Reshape" and data_input_shape is not None:
                                    shape_name = function_inputs[1] if len(function_inputs) > 1 else ""
                                    shape_initializer = function_constants.get(shape_name)
                                    if shape_initializer is None:
                                        return None
                                    return _resolve_onnx_reshape_shape(
                                        data_input_shape,
                                        shape_initializer,
                                        allowzero=bool(_onnx_int_attribute(function_node, "allowzero")),
                                        onnx=onnx,
                                    )
                                if function_node.op_type == "Unsqueeze" and data_input_shape is not None:
                                    axes = _resolve_onnx_axes(function_node, function_constants, onnx=onnx)
                                    if axes is None:
                                        return None
                                    output_rank = len(data_input_shape) + len(axes)
                                    normalized_axes = tuple(axis if axis >= 0 else output_rank + axis for axis in axes)
                                    if (
                                        not normalized_axes
                                        or len(set(normalized_axes)) != len(normalized_axes)
                                        or any(axis < 0 or axis >= output_rank for axis in normalized_axes)
                                    ):
                                        return None
                                    source_dimensions = iter(data_input_shape)
                                    return tuple(
                                        1 if index in normalized_axes else next(source_dimensions)
                                        for index in range(output_rank)
                                    )
                                if function_node.op_type == "Squeeze" and data_input_shape is not None:
                                    axes = _resolve_onnx_axes(function_node, function_constants, onnx=onnx)
                                    if axes is None:
                                        return None
                                    normalized_axes = tuple(
                                        axis if axis >= 0 else len(data_input_shape) + axis for axis in axes
                                    )
                                    if not normalized_axes:
                                        if squeeze_with_empty_axes_is_noop(function_node, axes, None):
                                            return data_input_shape
                                        return tuple(dimension for dimension in data_input_shape if dimension != 1)
                                    if (
                                        len(set(normalized_axes)) != len(normalized_axes)
                                        or any(axis < 0 or axis >= len(data_input_shape) for axis in normalized_axes)
                                        or any(data_input_shape[axis] != 1 for axis in normalized_axes)
                                    ):
                                        return None
                                    squeeze_axes = set(normalized_axes)
                                    return tuple(
                                        dimension
                                        for index, dimension in enumerate(data_input_shape)
                                        if index not in squeeze_axes
                                    )
                                return None

                            for function_node in getattr(function_graph, "node", ()):
                                function_inputs = node_input_names(function_node)
                                function_outputs = node_output_names(function_node)
                                if not function_outputs:
                                    continue
                                function_key = (
                                    str(getattr(function_node, "domain", "")),
                                    str(getattr(function_node, "op_type", "")),
                                    str(getattr(function_node, "overload", "")),
                                )
                                function_standard_domain = (
                                    getattr(function_node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                                )
                                if function_standard_domain and function_node.op_type == "Constant":
                                    constant_tensor = resolved_constant_node_tensor(
                                        function_node,
                                        lambda attribute: attribute,
                                    )
                                    if constant_tensor is not None:
                                        for output_name in function_outputs:
                                            function_constants[output_name] = constant_tensor
                                            local_tainted_shapes.pop(output_name, None)
                                        continue
                                nested_function = functions.get(function_key)
                                if nested_function is not None or any(
                                    _iter_attribute_graphs(attribute)
                                    for attribute in getattr(function_node, "attribute", ())
                                ):
                                    return None
                                is_registered_standard_operator = has_registered_standard_operator(
                                    function_node,
                                    function_versions,
                                )
                                is_registered_standard_operator = is_registered_standard_operator or (
                                    function_standard_domain
                                    and (
                                        function_node.op_type
                                        in (
                                            _RANK_PRESERVING_VARIADIC_OPERATORS
                                            | _SAME_TYPE_ELEMENTWISE_OPERATORS
                                            | {
                                                "Cast",
                                                "Constant",
                                                "Einsum",
                                                "Expand",
                                                "Identity",
                                                "MatMul",
                                                "OneHot",
                                                "PRelu",
                                                "Pow",
                                                "Reshape",
                                                "Squeeze",
                                                "Unsqueeze",
                                            }
                                        )
                                    )
                                )
                                any_tainted_input = any(
                                    input_name in local_tainted_shapes for input_name in function_inputs
                                )
                                if not any_tainted_input:
                                    continue
                                input_work = max(len(function_inputs), 1)
                                if exact_loop_replay_work_remaining < input_work:
                                    exact_loop_replay_work_exhausted = True
                                    return None
                                exact_loop_replay_work_remaining -= input_work
                                has_live_output = id(function_node) in live_node_ids
                                has_tainted_weight_input = False
                                for input_index, input_name in enumerate(function_inputs):
                                    if input_name not in local_tainted_shapes:
                                        continue
                                    if not _onnx_potential_weight_input(
                                        function_node,
                                        input_index,
                                        is_model_local_function=False,
                                        is_registered_standard_operator=is_registered_standard_operator,
                                    ):
                                        continue
                                    has_tainted_weight_input = True
                                    input_shape = local_tainted_shapes[input_name]
                                    if input_shape is None:
                                        return None
                                    if len(input_shape) >= 2:
                                        return True
                                if not has_live_output and not has_tainted_weight_input:
                                    continue
                                output_shape = (
                                    local_output_shape(function_node, function_inputs)
                                    if function_standard_domain
                                    else None
                                )
                                for output_name in function_outputs:
                                    local_tainted_shapes[output_name] = output_shape
                            return False

                        for body_node in getattr(subgraph, "node", ()):
                            body_inputs = node_input_names(body_node)
                            body_outputs = node_output_names(body_node)
                            if not body_outputs:
                                body_outputs = []
                            function_key = (
                                str(getattr(body_node, "domain", "")),
                                str(getattr(body_node, "op_type", "")),
                                str(getattr(body_node, "overload", "")),
                            )
                            function = functions.get(function_key)
                            is_model_local_function = function is not None
                            is_registered_standard_operator = (
                                is_model_local_function
                                or has_registered_standard_operator(
                                    body_node,
                                    opset_versions,
                                )
                            )
                            function_attributes: dict[str, Any] | None = None
                            function_versions: dict[str, int] | None = None
                            function_has_weight_consumer = False
                            if function is not None:
                                function_attributes = bound_function_attributes(
                                    function,
                                    body_node,
                                    resolve_literal_attribute,
                                )
                                function_versions = function_opset_versions(function, opset_versions)
                                function_has_weight_consumer = subgraph_has_potential_weight_consumer(
                                    function,
                                    function_versions,
                                    attribute_bindings=function_attributes,
                                )
                            standard_operator = (
                                is_registered_standard_operator
                                and not is_model_local_function
                                and getattr(body_node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                            )
                            nested_attribute_references = nested_attribute_graph_references(
                                body_node,
                                attribute_reference_cache,
                                external_reference_cache,
                            )
                            tainted_shape_names = set(tainted_shapes)
                            has_tainted_nested_capture = any(
                                reference_names is None or reference_names & tainted_shape_names
                                for _nested_graph, reference_names in nested_attribute_references
                            )
                            tainted_inputs = [input_name for input_name in body_inputs if input_name in tainted_shapes]
                            has_tainted_potential_weight_input = any(
                                input_name in tainted_shapes
                                and _onnx_potential_weight_input(
                                    body_node,
                                    input_index,
                                    is_model_local_function=is_model_local_function,
                                    is_registered_standard_operator=is_registered_standard_operator,
                                )
                                for input_index, input_name in enumerate(body_inputs)
                            )
                            has_tainted_function_weight_input = function_has_weight_consumer and any(
                                input_name in tainted_shapes for input_name in body_inputs
                            )
                            node_is_live_for_output = id(body_node) in output_dependency_node_ids
                            if (
                                not node_is_live_for_output
                                and not has_tainted_potential_weight_input
                                and not has_tainted_function_weight_input
                                and not has_tainted_nested_capture
                            ):
                                continue
                            input_walk_work = max(len(body_inputs), 1)
                            if exact_loop_replay_work_remaining < input_walk_work:
                                exact_loop_replay_work_exhausted = True
                                return None
                            exact_loop_replay_work_remaining -= input_walk_work
                            if not tainted_inputs:
                                if has_tainted_nested_capture:
                                    return None
                                continue
                            if function is not None:
                                if function_attributes is None or function_versions is None:
                                    return None
                                function_constants, function_bound_input_constants = bound_function_constants(
                                    function,
                                    body_inputs,
                                    subgraph_constants,
                                )
                                function_constants.update(function_bound_input_constants)
                                function_context_shapes: dict[str, tuple[int, ...]] = {}
                                for input_index, input_name in enumerate(body_inputs):
                                    if input_index >= len(getattr(function, "input", ())):
                                        continue
                                    function_input_name = _onnx_value_name(function.input[input_index])
                                    input_shape = known_input_shape(input_name)
                                    if function_input_name and input_shape is not None:
                                        function_context_shapes[function_input_name] = input_shape
                                for input_index, input_name in enumerate(body_inputs):
                                    if input_name not in tainted_shapes or input_index >= len(
                                        getattr(function, "input", ())
                                    ):
                                        continue
                                    function_input_name = _onnx_value_name(function.input[input_index])
                                    if not function_input_name or not subgraph_state_input_can_reach_weight_consumer(
                                        function,
                                        function_input_name,
                                        function_versions,
                                        attribute_bindings=function_attributes,
                                    ):
                                        continue
                                    tainted_shape = tainted_shapes.get(input_name)
                                    if tainted_shape is None:
                                        return None
                                    function_consumes_weight_rank = function_input_consumes_weight_rank_at_or_above_two(
                                        function,
                                        function_input_name,
                                        tainted_shape,
                                        function_versions,
                                        function_attributes,
                                        function_constants,
                                        function_context_shapes,
                                    )
                                    if function_consumes_weight_rank is None:
                                        return None
                                    if function_consumes_weight_rank:
                                        return True, None
                                if node_is_live_for_output:
                                    return None
                                continue
                            if nested_attribute_references:
                                return None
                            for input_index, input_name in enumerate(body_inputs):
                                if input_name not in tainted_shapes:
                                    continue
                                if not _onnx_potential_weight_input(
                                    body_node,
                                    input_index,
                                    is_model_local_function=is_model_local_function,
                                    is_registered_standard_operator=is_registered_standard_operator,
                                ):
                                    continue
                                tainted_input_shape = tainted_shapes[input_name]
                                if tainted_input_shape is None:
                                    return None
                                if len(tainted_input_shape) >= 2:
                                    return True, None
                            output_shape = (
                                transformed_output_shape(body_node, body_inputs) if standard_operator else None
                            )
                            for output_name in body_outputs:
                                tainted_shapes[output_name] = output_shape
                        return False, tainted_shapes.get(graph_output_name) if graph_output_name else None

                    def exact_loop_repeated_state_weight_rank_bounds(
                        subgraph: Any,
                        graph_input_name: str,
                        graph_output_index: int,
                        initial_shape: tuple[int, ...] | None,
                        initial_rank: int | None,
                        exact_loop_iterations: int,
                        trusted_context_shapes: dict[str, tuple[int, ...]],
                        related_graph_input_shapes: dict[str, tuple[int, ...] | None],
                        node_input_count: int,
                        current_node: Any = node,
                        current_input_pairs: Iterable[tuple[Any, Any]] = input_pairs,
                        current_input_pair_index_start: int = input_pair_index_start,
                    ) -> tuple[bool, bool, tuple[int, ...]] | None:
                        current_shape = initial_shape
                        current_rank = len(current_shape) if current_shape is not None else initial_rank
                        if current_shape is None and current_rank is not None:
                            current_shape = tuple(-1 for _ in range(current_rank))
                        if current_shape is None or current_rank is None:
                            return None
                        body_consumes_weight_rank = False
                        nonlocal exact_loop_replay_work_remaining, exact_loop_replay_work_exhausted
                        current_related_shapes = dict(related_graph_input_shapes)
                        current_related_shapes.pop(graph_input_name, None)
                        for _iteration in range(exact_loop_iterations):
                            related_shape_work = sum(
                                max(len(shape), 1) for shape in current_related_shapes.values() if shape is not None
                            )
                            iteration_work = max(current_rank, 1) + related_shape_work
                            if exact_loop_replay_work_remaining < iteration_work:
                                exact_loop_replay_work_exhausted = True
                                return None
                            exact_loop_replay_work_remaining -= iteration_work
                            body_analysis = subgraph_state_input_consumes_weight_rank_at_or_above_two(
                                subgraph,
                                graph_input_name,
                                current_shape,
                                graph_output_index,
                                current_related_shapes,
                            )
                            if body_analysis is None:
                                return None
                            body_consumes_current_rank, direct_next_shape = body_analysis
                            body_consumes_weight_rank = body_consumes_weight_rank or body_consumes_current_rank
                            promoted = direct_next_shape is not None and len(direct_next_shape) > current_rank
                            next_shape = direct_next_shape
                            if next_shape is None:
                                output_shapes: dict[int, tuple[int, ...]] = {}
                                promoted = subgraph_reenters_state_with_rank_promotion(
                                    subgraph,
                                    graph_input_name,
                                    graph_output_index,
                                    constants,
                                    opset_versions,
                                    current_shape,
                                    trusted_context_shapes=trusted_context_shapes,
                                    output_shapes_out=output_shapes,
                                    related_graph_input_shapes=related_graph_input_shapes,
                                )
                                next_shape = output_shapes.get(graph_output_index)
                                if next_shape is None:
                                    return None
                            next_rank = len(next_shape)
                            if body_consumes_current_rank and promoted and next_rank <= current_rank:
                                return None
                            next_related_shapes: dict[str, tuple[int, ...] | None] = {}
                            for related_input_name, related_shape in current_related_shapes.items():
                                if related_shape is None:
                                    next_related_shapes[related_input_name] = None
                                    continue
                                related_output_index = None
                                for related_pair_index, (_parent_input, related_graph_input) in enumerate(
                                    current_input_pairs,
                                    start=current_input_pair_index_start,
                                ):
                                    if _onnx_value_name(related_graph_input) == related_input_name:
                                        related_output_index = control_flow_subgraph_state_output_index(
                                            current_node,
                                            related_pair_index,
                                            opset_versions,
                                        )
                                        break
                                if related_output_index is None:
                                    next_related_shapes[related_input_name] = related_shape
                                    continue
                                related_analysis = subgraph_state_input_consumes_weight_rank_at_or_above_two(
                                    subgraph,
                                    related_input_name,
                                    related_shape,
                                    related_output_index,
                                    {**current_related_shapes, graph_input_name: next_shape},
                                )
                                if related_analysis is None:
                                    next_related_shapes[related_input_name] = None
                                else:
                                    _related_consumes_weight_rank, related_next_shape = related_analysis
                                    next_related_shapes[related_input_name] = related_next_shape
                            current_related_shapes = next_related_shapes
                            current_shape = next_shape
                            current_rank = next_rank
                        return body_consumes_weight_rank, current_rank >= 2, current_shape

                    def repeated_state_input_reaches_output_bounded(
                        subgraph: Any,
                        graph_input_name: str,
                        graph_output_index: int,
                        nested_attribute_reference_cache_for_node: dict[
                            int,
                            tuple[Any, tuple[tuple[Any, frozenset[str] | None], ...]],
                        ] = nested_attribute_reference_cache,
                        nested_external_reference_cache_for_node: dict[
                            int,
                            tuple[Any, frozenset[str] | None],
                        ] = nested_external_reference_cache,
                    ) -> bool | None:
                        graph_outputs = getattr(subgraph, "output", ())
                        graph_output_name = (
                            _onnx_value_name(graph_outputs[graph_output_index])
                            if 0 <= graph_output_index < len(graph_outputs)
                            else ""
                        )
                        if not graph_input_name or not graph_output_name:
                            return None
                        tainted_names = {graph_input_name}
                        work_remaining = _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK
                        for body_node in getattr(subgraph, "node", ()):
                            body_inputs = node_input_names(body_node)
                            body_outputs = node_output_names(body_node)
                            nested_attribute_references = nested_attribute_graph_references(
                                body_node,
                                nested_attribute_reference_cache_for_node,
                                nested_external_reference_cache_for_node,
                            )
                            has_tainted_nested_capture = any(
                                reference_names is None or bool(reference_names & tainted_names)
                                for _nested_graph, reference_names in nested_attribute_references
                            )
                            if has_tainted_nested_capture:
                                return None
                            if not body_outputs or not any(input_name in tainted_names for input_name in body_inputs):
                                continue
                            work_remaining -= max(len(body_inputs), 1)
                            if work_remaining < 0:
                                return None
                            function_key = (
                                str(getattr(body_node, "domain", "")),
                                str(getattr(body_node, "op_type", "")),
                                str(getattr(body_node, "overload", "")),
                            )
                            has_nested_attribute_graph = any(
                                _iter_attribute_graphs(attribute) for attribute in getattr(body_node, "attribute", ())
                            )
                            if functions.get(function_key) is not None or has_nested_attribute_graph:
                                return None
                            tainted_names.update(body_outputs)
                        return graph_output_name in tainted_names

                    def state_weight_consumer_dependency_names_bounded(
                        subgraph: Any,
                        graph_input_name: str,
                    ) -> frozenset[str] | None:
                        tainted_names = {graph_input_name}
                        dependency_names: set[str] = set()
                        work_remaining = _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK
                        for body_node in getattr(subgraph, "node", ()):
                            body_inputs = node_input_names(body_node)
                            body_outputs = node_output_names(body_node)
                            if not body_outputs or not any(input_name in tainted_names for input_name in body_inputs):
                                continue
                            work_remaining -= max(len(body_inputs), 1)
                            if work_remaining < 0:
                                return None
                            function_key = (
                                str(getattr(body_node, "domain", "")),
                                str(getattr(body_node, "op_type", "")),
                                str(getattr(body_node, "overload", "")),
                            )
                            function = functions.get(function_key)
                            is_model_local_function = function is not None
                            is_registered_standard_operator = (
                                is_model_local_function
                                or has_registered_standard_operator(
                                    body_node,
                                    opset_versions,
                                )
                            )
                            if function is not None:
                                return None
                            has_nested_attribute_graph = any(
                                _iter_attribute_graphs(attribute) for attribute in getattr(body_node, "attribute", ())
                            )
                            if has_nested_attribute_graph:
                                return None
                            for input_index, input_name in enumerate(body_inputs):
                                if input_name not in tainted_names:
                                    continue
                                if not _onnx_potential_weight_input(
                                    body_node,
                                    input_index,
                                    is_model_local_function=is_model_local_function,
                                    is_registered_standard_operator=is_registered_standard_operator,
                                ):
                                    continue
                                if merge_dependency_names(
                                    dependency_names,
                                    graph_value_dependency_names(subgraph, (input_name,)),
                                ):
                                    return None
                            tainted_names.update(body_outputs)
                        return frozenset(dependency_names)

                    repeated_state_output_indexes_by_input: dict[str, int] = {}
                    for related_pair_index, (_parent_input, related_graph_input) in enumerate(
                        input_pairs,
                        start=input_pair_index_start,
                    ):
                        related_graph_input_name = _onnx_value_name(related_graph_input)
                        if not related_graph_input_name:
                            continue
                        repeated_state_output_indexes_by_input[related_graph_input_name] = (
                            control_flow_subgraph_state_output_index(
                                node,
                                related_pair_index,
                                opset_versions,
                            )
                        )

                    def repeated_state_update_dependency_names_bounded(
                        subgraph: Any,
                        graph_output_index: int,
                        state_output_indexes_by_input: dict[str, int] = repeated_state_output_indexes_by_input,
                    ) -> frozenset[str] | None:
                        dependency_names = set(graph_output_dependency_names(subgraph, (graph_output_index,)))
                        if dependency_collection_limit_marker in dependency_names:
                            return None
                        pending_inputs = [
                            input_name for input_name in dependency_names if input_name in state_output_indexes_by_input
                        ]
                        visited_inputs: set[str] = set()
                        work_remaining = _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK
                        while pending_inputs:
                            input_name = pending_inputs.pop()
                            if input_name in visited_inputs:
                                continue
                            visited_inputs.add(input_name)
                            work_remaining -= 1
                            if work_remaining < 0:
                                return None
                            sibling_output_index = state_output_indexes_by_input[input_name]
                            sibling_dependency_names = graph_output_dependency_names(
                                subgraph,
                                (sibling_output_index,),
                            )
                            if dependency_names_exceeded_limit(sibling_dependency_names):
                                return None
                            before_count = len(dependency_names)
                            if merge_dependency_names(dependency_names, sibling_dependency_names):
                                return None
                            if len(dependency_names) == before_count:
                                continue
                            pending_inputs.extend(
                                sibling_input_name
                                for sibling_input_name in sibling_dependency_names
                                if (
                                    sibling_input_name in state_output_indexes_by_input
                                    and sibling_input_name not in visited_inputs
                                )
                            )
                        return frozenset(dependency_names)

                    def is_repeated_control_flow_state_input(
                        pair_index: int,
                        *,
                        current_node: Any = node,
                        current_scan_input_start: int = scan_input_start,
                        current_scan_input_axes: tuple[int, ...] = scan_input_axes,
                        current_scan_input_offset: int = scan_input_offset,
                        current_scan_num_inputs: int = scan_num_inputs,
                    ) -> bool:
                        if current_node.op_type == "Loop":
                            return pair_index >= 2 and loop_may_repeat_body(current_node, constants, graph_input_names)
                        if current_node.op_type == "Scan":
                            return pair_index < current_scan_input_start and scan_may_repeat_body(
                                current_node,
                                constants,
                                graph_input_names,
                                known_value_shapes,
                                proven_value_ranks,
                                {
                                    name
                                    for name in graph_input_names & set(value_lineages)
                                    if name not in proven_value_ranks
                                },
                                scan_input_axes=current_scan_input_axes,
                                scan_input_offset=current_scan_input_offset,
                                num_scan_inputs=current_scan_num_inputs,
                            )
                        return False

                    trusted_repeated_context_candidates: list[tuple[int, str, tuple[int, ...]]] = []
                    for pair_index, (parent_input, graph_input) in enumerate(
                        input_pairs,
                        start=input_pair_index_start,
                    ):
                        parent_name = str(parent_input)
                        graph_input_name = _onnx_value_name(graph_input)
                        trusted_parent_shape = trusted_bound_context_shape(parent_name, pair_index)
                        if not graph_input_name or trusted_parent_shape is None:
                            continue
                        if is_repeated_control_flow_state_input(pair_index):
                            trusted_repeated_context_candidates.append(
                                (pair_index, graph_input_name, trusted_parent_shape)
                            )
                            continue
                        subgraph_trusted_context_shapes[graph_input_name] = trusted_parent_shape
                    related_repeated_state_shapes: dict[str, tuple[int, ...] | None] = {}
                    for pair_index, (parent_input, graph_input) in enumerate(
                        input_pairs,
                        start=input_pair_index_start,
                    ):
                        graph_input_name = _onnx_value_name(graph_input)
                        if not graph_input_name or not is_repeated_control_flow_state_input(pair_index):
                            continue
                        parent_name = str(parent_input)
                        related_parent_shape = known_value_shapes.get(parent_name)
                        if related_parent_shape is None:
                            related_parent_shape = constant_initializer_shape(constants, parent_name)
                        if related_parent_shape is None and parent_name in value_lineages:
                            lineage_shapes = {lineage.shape for lineage in value_lineages[parent_name].values()}
                            if len(lineage_shapes) == 1 and None not in lineage_shapes:
                                related_parent_shape = next(iter(lineage_shapes))  # type: ignore[assignment]
                        if node.op_type == "Scan":
                            related_parent_shape, _related_parent_rank = _onnx_scan_bound_subgraph_input_shape(
                                related_parent_shape,
                                known_value_ranks.get(parent_name),
                                pair_index=pair_index,
                                scan_input_start=scan_input_start,
                                scan_input_offset=scan_input_offset,
                                scan_input_axes=scan_input_axes,
                            )
                        related_repeated_state_shapes[graph_input_name] = related_parent_shape
                    related_repeated_state_shapes_cache_key = tuple(sorted(related_repeated_state_shapes.items()))
                    remaining_trusted_repeated_context_candidates = list(trusted_repeated_context_candidates)
                    repeated_context_proof_budget = min(
                        _ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK,
                        max(
                            len(remaining_trusted_repeated_context_candidates),
                            len(remaining_trusted_repeated_context_candidates)
                            * len(remaining_trusted_repeated_context_candidates),
                        ),
                    )
                    while remaining_trusted_repeated_context_candidates and repeated_context_proof_budget > 0:
                        unresolved_repeated_context_candidates: list[tuple[int, str, tuple[int, ...]]] = []
                        trusted_count_before = len(subgraph_trusted_context_shapes)
                        for (
                            pair_index,
                            graph_input_name,
                            trusted_parent_shape,
                        ) in remaining_trusted_repeated_context_candidates:
                            if repeated_context_proof_budget <= 0:
                                unresolved_repeated_context_candidates.append(
                                    (pair_index, graph_input_name, trusted_parent_shape)
                                )
                                continue
                            repeated_context_proof_budget -= 1
                            graph_output_index = control_flow_subgraph_state_output_index(
                                node,
                                pair_index,
                                opset_versions,
                            )
                            output_shapes: dict[int, tuple[int, ...]] = {}
                            if (
                                not subgraph_reenters_state_with_rank_promotion(
                                    subgraph,
                                    graph_input_name,
                                    graph_output_index,
                                    constants,
                                    opset_versions,
                                    trusted_parent_shape,
                                    trusted_context_shapes=subgraph_trusted_context_shapes,
                                    output_shapes_out=output_shapes,
                                    related_graph_input_shapes=related_repeated_state_shapes,
                                    related_graph_input_shapes_cache_key=related_repeated_state_shapes_cache_key,
                                )
                                and output_shapes.get(graph_output_index) == trusted_parent_shape
                            ):
                                subgraph_trusted_context_shapes[graph_input_name] = trusted_parent_shape
                                continue
                            unresolved_repeated_context_candidates.append(
                                (pair_index, graph_input_name, trusted_parent_shape)
                            )
                        if len(subgraph_trusted_context_shapes) == trusted_count_before:
                            break
                        remaining_trusted_repeated_context_candidates = unresolved_repeated_context_candidates
                    for pair_index, (parent_input, graph_input) in enumerate(input_pairs, start=input_pair_index_start):
                        parent_name = str(parent_input)
                        graph_input_name = _onnx_value_name(graph_input)
                        parent_shape = known_value_shapes.get(parent_name)
                        if parent_shape is None:
                            parent_shape = constant_initializer_shape(constants, parent_name)
                        if parent_shape is None and parent_name in value_lineages:
                            lineage_shapes = {lineage.shape for lineage in value_lineages[parent_name].values()}
                            if len(lineage_shapes) == 1 and None not in lineage_shapes:
                                parent_shape = next(iter(lineage_shapes))  # type: ignore[assignment]
                        parent_rank = known_value_ranks.get(parent_name)
                        repeated_control_flow_state_input = is_repeated_control_flow_state_input(pair_index)
                        repeated_state_reenters_with_rank_promotion = False
                        repeated_state_exact_loop_inconclusive = False
                        repeated_state_output_shapes: dict[int, tuple[int, ...]] = {}
                        graph_output_index = control_flow_subgraph_state_output_index(node, pair_index, opset_versions)
                        if repeated_control_flow_state_input:
                            repeated_state_reenters_with_rank_promotion = subgraph_reenters_state_with_rank_promotion(
                                subgraph,
                                graph_input_name,
                                graph_output_index,
                                constants,
                                opset_versions,
                                parent_shape,
                                trusted_context_shapes=subgraph_trusted_context_shapes,
                                output_shapes_out=repeated_state_output_shapes,
                                related_graph_input_shapes=related_repeated_state_shapes,
                                related_graph_input_shapes_cache_key=related_repeated_state_shapes_cache_key,
                            )
                        parent_rank_for_repeated_state = len(parent_shape) if parent_shape is not None else parent_rank
                        finite_repeated_state_consumes_weight_rank = True
                        if (
                            repeated_control_flow_state_input
                            and node.op_type == "Loop"
                            and (
                                exact_loop_iterations := loop_exact_iteration_count(
                                    max_count=_ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK,
                                )
                            )
                            is not None
                        ):
                            exact_loop_replay_work_exhausted = False
                            exact_rank_bounds = exact_loop_repeated_state_weight_rank_bounds(
                                subgraph,
                                graph_input_name,
                                graph_output_index,
                                parent_shape,
                                parent_rank_for_repeated_state,
                                exact_loop_iterations,
                                subgraph_trusted_context_shapes,
                                related_repeated_state_shapes,
                                len(getattr(node, "input", ())),
                            )
                            if exact_rank_bounds is not None:
                                finite_repeated_state_consumes_weight_rank = exact_rank_bounds[0]
                            else:
                                repeated_state_exact_loop_inconclusive = True
                                if not exact_loop_replay_work_exhausted:
                                    one_iteration_output_shape = repeated_state_output_shapes.get(graph_output_index)
                                    one_iteration_output_rank = (
                                        len(one_iteration_output_shape)
                                        if one_iteration_output_shape is not None
                                        else None
                                    )
                                    if (
                                        parent_rank_for_repeated_state is not None
                                        and one_iteration_output_rank is not None
                                    ):
                                        rank_delta = max(one_iteration_output_rank - parent_rank_for_repeated_state, 0)
                                        max_consumed_rank = (
                                            parent_rank_for_repeated_state
                                            + max(exact_loop_iterations - 1, 0) * rank_delta
                                        )
                                        finite_repeated_state_consumes_weight_rank = max_consumed_rank >= 2
                                elif (
                                    parent_name in value_lineage_limit_gap_counts
                                    and repeated_state_input_reaches_output_bounded(
                                        subgraph,
                                        graph_input_name,
                                        graph_output_index,
                                    )
                                    is not False
                                ):
                                    plan.record_coverage_gap(
                                        "lineages_per_value_limit",
                                        value_lineage_limit_gap_counts[parent_name],
                                    )
                        sibling_state_rank_promotion_may_affect_weight = False
                        if (
                            repeated_control_flow_state_input
                            and node.op_type == "Loop"
                            and len(getattr(node, "input", ())) > 3
                            and subgraph_state_input_can_reach_weight_consumer(
                                subgraph,
                                graph_input_name,
                                opset_versions,
                            )
                        ):
                            current_update_dependency_names = repeated_state_update_dependency_names_bounded(
                                subgraph,
                                graph_output_index,
                            )
                            current_weight_consumer_dependency_names = state_weight_consumer_dependency_names_bounded(
                                subgraph,
                                graph_input_name,
                            )
                            for sibling_output_index, sibling_parent_input in enumerate(
                                getattr(node, "input", ())[2 : 2 + len(getattr(node, "output", ()))]
                            ):
                                sibling_graph_output_index = sibling_output_index + control_flow_output_offset(node)
                                if sibling_graph_output_index == graph_output_index or not sibling_parent_input:
                                    continue
                                sibling_subgraph_input_index = sibling_output_index + 2
                                sibling_graph_input_name = (
                                    _onnx_value_name(subgraph.input[sibling_subgraph_input_index])
                                    if sibling_subgraph_input_index < len(getattr(subgraph, "input", ()))
                                    else ""
                                )
                                if not sibling_graph_input_name:
                                    continue
                                if not subgraph_state_input_can_reach_weight_consumer(
                                    subgraph,
                                    sibling_graph_input_name,
                                    opset_versions,
                                ):
                                    continue
                                if (
                                    current_update_dependency_names is not None
                                    and sibling_graph_input_name not in current_update_dependency_names
                                    and current_weight_consumer_dependency_names is not None
                                    and sibling_graph_input_name not in current_weight_consumer_dependency_names
                                ):
                                    continue
                                sibling_parent_name = str(sibling_parent_input)
                                sibling_parent_shape = known_value_shapes.get(sibling_parent_name)
                                if sibling_parent_shape is None:
                                    sibling_parent_shape = constant_initializer_shape(constants, sibling_parent_name)
                                if sibling_parent_shape is None:
                                    sibling_parent_rank = known_value_ranks.get(sibling_parent_name)
                                    if sibling_parent_rank is None:
                                        continue
                                    sibling_parent_shape = tuple(-1 for _ in range(sibling_parent_rank))
                                if subgraph_reenters_state_with_rank_promotion(
                                    subgraph,
                                    sibling_graph_input_name,
                                    sibling_graph_output_index,
                                    constants,
                                    opset_versions,
                                    sibling_parent_shape,
                                    trusted_context_shapes=subgraph_trusted_context_shapes,
                                    related_graph_input_shapes=related_repeated_state_shapes,
                                    related_graph_input_shapes_cache_key=related_repeated_state_shapes_cache_key,
                                ):
                                    sibling_state_rank_promotion_may_affect_weight = True
                                    break
                        repeated_state_rank_gap_may_affect_weight = repeated_control_flow_state_input and (
                            (repeated_state_reenters_with_rank_promotion and finite_repeated_state_consumes_weight_rank)
                            or sibling_state_rank_promotion_may_affect_weight
                            or parent_rank_for_repeated_state is None
                            or parent_rank_for_repeated_state != 1
                        )
                        repeated_state_reaches_output: bool | None = None
                        if repeated_control_flow_state_input:
                            repeated_state_reaches_output = repeated_state_input_reaches_output_bounded(
                                subgraph,
                                graph_input_name,
                                graph_output_index,
                            )
                        repeated_state_gap_may_feed_weight = (
                            not repeated_control_flow_state_input
                            or repeated_state_rank_gap_may_affect_weight
                            or repeated_state_exact_loop_inconclusive
                            or node.op_type == "Scan"
                        )
                        if repeated_state_gap_may_feed_weight and repeated_state_reaches_output is False:
                            repeated_state_gap_may_feed_weight = False
                        if parent_name in value_lineages:
                            subgraph_bound_lineages[graph_input_name] = value_lineages[parent_name]
                            if (
                                (
                                    repeated_state_reenters_with_rank_promotion
                                    and finite_repeated_state_consumes_weight_rank
                                )
                                or sibling_state_rank_promotion_may_affect_weight
                            ) and repeated_state_reaches_output is not False:
                                repeated_state_body_reaches_weight_consumer = (
                                    subgraph_state_input_can_reach_weight_consumer(
                                        subgraph,
                                        graph_input_name,
                                        opset_versions,
                                    )
                                )
                                retained_rank_summary = rank_gap_weight_summary_after_repeated_rank_increase(
                                    summarize_rank_promotable_lineage_gap(value_lineages[parent_name].values()),
                                    len(value_lineages[parent_name]),
                                )
                                if retained_rank_summary != empty_weight_gap_summary:
                                    if repeated_state_body_reaches_weight_consumer:
                                        plan.record_coverage_gap(
                                            "lineages_per_value_limit",
                                            len(retained_rank_summary.lineages),
                                        )
                                    subgraph_bound_weight_lineage_gaps[graph_input_name] = (
                                        _bounded_onnx_weight_lineage_gap_count(
                                            subgraph_bound_weight_lineage_gaps.get(graph_input_name, 0),
                                            len(retained_rank_summary.lineages),
                                        )
                                    )
                                    subgraph_bound_weight_lineage_gap_summaries[graph_input_name] = (
                                        merge_weight_lineage_gap_summaries(
                                            subgraph_bound_weight_lineage_gap_summaries.get(
                                                graph_input_name, empty_weight_gap_summary
                                            ),
                                            retained_rank_summary,
                                        )
                                    )
                        if parent_name in constants and not repeated_control_flow_state_input:
                            subgraph_bound_constants[graph_input_name] = constants[parent_name]
                        if parent_name in dynamic_values:
                            subgraph_bound_dynamic.add(graph_input_name)
                        if node.op_type == "Scan":
                            parent_shape, parent_rank = _onnx_scan_bound_subgraph_input_shape(
                                parent_shape,
                                parent_rank,
                                pair_index=pair_index,
                                scan_input_start=scan_input_start,
                                scan_input_offset=scan_input_offset,
                                scan_input_axes=scan_input_axes,
                            )
                        if parent_shape is not None:
                            subgraph_bound_value_shapes[graph_input_name] = parent_shape
                            if parent_name in proven_value_ranks:
                                subgraph_bound_proven_value_ranks.add(graph_input_name)
                        elif parent_rank is not None:
                            subgraph_bound_value_ranks[graph_input_name] = parent_rank
                            if parent_name in proven_value_ranks:
                                subgraph_bound_proven_value_ranks.add(graph_input_name)
                        elif parent_name in dynamic_values or parent_name not in constants:
                            subgraph_bound_unknown_value_ranks.add(graph_input_name)
                        if parent_name in value_lineage_limit_gap_counts:
                            subgraph_bound_lineage_gaps[graph_input_name] = value_lineage_limit_gap_counts[parent_name]
                            inherited_gap_summary = known_weight_gap_summary(
                                None,
                                value_lineage_limit_gap_counts[parent_name],
                            )
                            if repeated_state_rank_gap_may_affect_weight and repeated_state_reaches_output is not False:
                                subgraph_bound_rank_promotable_lineage_gaps[graph_input_name] = (
                                    _bounded_onnx_weight_lineage_gap_count(
                                        subgraph_bound_rank_promotable_lineage_gaps.get(graph_input_name, 0),
                                        value_lineage_limit_gap_counts[parent_name],
                                    )
                                )
                                subgraph_bound_rank_promotable_lineage_gap_summaries[graph_input_name] = (
                                    merge_weight_lineage_gap_summaries(
                                        subgraph_bound_rank_promotable_lineage_gap_summaries.get(
                                            graph_input_name, empty_weight_gap_summary
                                        ),
                                        inherited_gap_summary,
                                    )
                                )
                            if repeated_state_gap_may_feed_weight:
                                subgraph_bound_weight_lineage_gaps[graph_input_name] = (
                                    _bounded_onnx_weight_lineage_gap_count(
                                        subgraph_bound_weight_lineage_gaps.get(graph_input_name, 0),
                                        value_lineage_limit_gap_counts[parent_name],
                                    )
                                )
                                subgraph_bound_weight_lineage_gap_summaries[graph_input_name] = (
                                    merge_weight_lineage_gap_summaries(
                                        subgraph_bound_weight_lineage_gap_summaries.get(
                                            graph_input_name, empty_weight_gap_summary
                                        ),
                                        inherited_gap_summary,
                                    )
                                )
                        if parent_name in value_non_shape_lineage_limit_gap_counts:
                            subgraph_bound_non_shape_lineage_gaps[graph_input_name] = (
                                value_non_shape_lineage_limit_gap_counts[parent_name]
                            )
                            subgraph_bound_non_shape_lineage_gap_summaries[graph_input_name] = known_weight_gap_summary(
                                value_non_shape_lineage_limit_gap_summaries.get(parent_name),
                                value_non_shape_lineage_limit_gap_counts[parent_name],
                            )
                        if parent_name in value_weight_lineage_limit_gap_counts and repeated_state_gap_may_feed_weight:
                            subgraph_bound_weight_lineage_gaps[graph_input_name] = (
                                value_weight_lineage_limit_gap_counts[parent_name]
                            )
                            subgraph_bound_weight_lineage_gap_summaries[graph_input_name] = known_weight_gap_summary(
                                value_weight_lineage_limit_gap_summaries.get(parent_name),
                                value_weight_lineage_limit_gap_counts[parent_name],
                            )
                        if parent_name in value_rank_promotable_lineage_limit_gap_counts:
                            subgraph_bound_rank_promotable_lineage_gaps[graph_input_name] = (
                                value_rank_promotable_lineage_limit_gap_counts[parent_name]
                            )
                            rank_promotable_summary = known_weight_gap_summary(
                                value_rank_promotable_lineage_limit_gap_summaries.get(parent_name),
                                value_rank_promotable_lineage_limit_gap_counts[parent_name],
                            )
                            subgraph_bound_rank_promotable_lineage_gap_summaries[graph_input_name] = (
                                rank_promotable_summary
                            )
                            if repeated_state_gap_may_feed_weight:
                                subgraph_bound_weight_lineage_gaps[graph_input_name] = (
                                    _bounded_onnx_weight_lineage_gap_count(
                                        subgraph_bound_weight_lineage_gaps.get(graph_input_name, 0),
                                        value_rank_promotable_lineage_limit_gap_counts[parent_name],
                                    )
                                )
                                subgraph_bound_weight_lineage_gap_summaries[graph_input_name] = (
                                    merge_weight_lineage_gap_summaries(
                                        subgraph_bound_weight_lineage_gap_summaries.get(
                                            graph_input_name, empty_weight_gap_summary
                                        ),
                                        rank_promotable_summary,
                                    )
                                )
                    for captured_name in graph_external_reference_names(subgraph):
                        if captured_name in subgraph_input_names:
                            continue
                        if captured_name in known_value_shapes and captured_name not in subgraph_bound_value_shapes:
                            subgraph_bound_value_shapes[captured_name] = known_value_shapes[captured_name]
                            if captured_name in proven_value_ranks:
                                subgraph_bound_proven_value_ranks.add(captured_name)
                        elif captured_name in known_value_ranks and captured_name not in subgraph_bound_value_ranks:
                            subgraph_bound_value_ranks[captured_name] = known_value_ranks[captured_name]
                            if captured_name in proven_value_ranks:
                                subgraph_bound_proven_value_ranks.add(captured_name)
                    subgraph_results.append(
                        walk_graph(
                            subgraph,
                            value_lineages,
                            constants,
                            dynamic_values,
                            inherited_lineage_limit_gap_counts=value_lineage_limit_gap_counts,
                            inherited_non_shape_lineage_limit_gap_counts=value_non_shape_lineage_limit_gap_counts,
                            inherited_non_shape_lineage_limit_gap_summaries=(
                                value_non_shape_lineage_limit_gap_summaries
                            ),
                            inherited_weight_lineage_limit_gap_counts=value_weight_lineage_limit_gap_counts,
                            inherited_weight_lineage_limit_gap_summaries=value_weight_lineage_limit_gap_summaries,
                            inherited_rank_promotable_lineage_limit_gap_counts=(
                                value_rank_promotable_lineage_limit_gap_counts
                            ),
                            inherited_rank_promotable_lineage_limit_gap_summaries=(
                                value_rank_promotable_lineage_limit_gap_summaries
                            ),
                            root_graph=False,
                            source_scope=(*resolved_attribute_key, "graph", subgraph_position),
                            opset_versions=opset_versions,
                            bound_lineages=subgraph_bound_lineages,
                            bound_constants=subgraph_bound_constants,
                            bound_dynamic_values=subgraph_bound_dynamic,
                            bound_lineage_limit_gap_counts=subgraph_bound_lineage_gaps,
                            bound_non_shape_lineage_limit_gap_counts=subgraph_bound_non_shape_lineage_gaps,
                            bound_non_shape_lineage_limit_gap_summaries=(
                                subgraph_bound_non_shape_lineage_gap_summaries
                            ),
                            bound_weight_lineage_limit_gap_counts=subgraph_bound_weight_lineage_gaps,
                            bound_weight_lineage_limit_gap_summaries=subgraph_bound_weight_lineage_gap_summaries,
                            bound_rank_promotable_lineage_limit_gap_counts=(
                                subgraph_bound_rank_promotable_lineage_gaps
                            ),
                            bound_rank_promotable_lineage_limit_gap_summaries=(
                                subgraph_bound_rank_promotable_lineage_gap_summaries
                            ),
                            bound_value_shapes=subgraph_bound_value_shapes,
                            bound_value_ranks=subgraph_bound_value_ranks,
                            bound_unknown_value_ranks=subgraph_bound_unknown_value_ranks,
                            bound_proven_value_ranks=subgraph_bound_proven_value_ranks,
                            bound_attributes=attribute_bindings,
                            bound_attribute_keys=attribute_binding_keys,
                            function_depth=function_depth,
                            fail_on_unbound_inputs=fail_on_unbound_inputs,
                        ),
                    )

            function = functions.get(function_key)
            if function is not None and function_depth >= _ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT:
                plan.record_coverage_gap("function_call_depth_limit")
                for input_index, input_name in enumerate(node.input):
                    for initializer_index, lineage in value_lineages.get(str(input_name), {}).items():
                        record_unresolved_lineage(
                            _OnnxWeightLineage(
                                initializer_index=initializer_index,
                                shape=None,
                                data_type=lineage.data_type,
                                transforms=lineage.transforms,
                                unresolved_reason="function_call_depth_limit",
                            ),
                            node,
                            current_node_index,
                            input_index,
                        )
                function = None
            if function is not None:
                function_bound_lineages: dict[str, dict[int, _OnnxWeightLineage]] = {}
                function_bound_constants: dict[str, Any] = {}
                function_bound_dynamic: set[str] = set()
                function_bound_lineage_gaps: dict[str, int] = {}
                function_bound_non_shape_lineage_gaps: dict[str, int] = {}
                function_bound_non_shape_lineage_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
                function_bound_weight_lineage_gaps: dict[str, int] = {}
                function_bound_weight_lineage_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
                function_bound_rank_promotable_lineage_gaps: dict[str, int] = {}
                function_bound_rank_promotable_lineage_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
                function_bound_value_shapes: dict[str, tuple[int, ...]] = {}
                function_bound_value_ranks: dict[str, int] = {}
                function_bound_unknown_value_ranks: set[str] = set()
                function_bound_proven_value_ranks: set[str] = set()
                function_source_scope = ("function", *function_key)
                function_bound_attributes: dict[str, Any] = {}
                function_bound_attribute_keys: dict[str, tuple[Any, ...]] = {}
                for default_position, attribute in enumerate(getattr(function, "attribute_proto", ())):
                    attribute_name = str(attribute.name)
                    function_bound_attributes[attribute_name] = attribute
                    function_bound_attribute_keys[attribute_name] = (
                        *function_source_scope,
                        "default_attribute",
                        default_position,
                    )
                for attribute_position, attribute in enumerate(getattr(node, "attribute", ())):
                    resolved_attribute = resolve_attribute(attribute)
                    if resolved_attribute is not None:
                        attribute_name = str(attribute.name)
                        function_bound_attributes[attribute_name] = resolved_attribute
                        function_bound_attribute_keys[attribute_name] = attribute_source_key(
                            attribute,
                            local_node_index,
                            attribute_position,
                        )
                for parent_input, function_input in zip(node.input, function.input, strict=False):
                    parent_name = str(parent_input)
                    function_input_name = _onnx_value_name(function_input)
                    if parent_name in value_lineages:
                        function_bound_lineages[function_input_name] = value_lineages[parent_name]
                    if parent_name in constants:
                        function_bound_constants[function_input_name] = constants[parent_name]
                    if parent_name in dynamic_values:
                        function_bound_dynamic.add(function_input_name)
                    if parent_name in known_value_shapes:
                        function_bound_value_shapes[function_input_name] = known_value_shapes[parent_name]
                        if parent_name in proven_value_ranks:
                            function_bound_proven_value_ranks.add(function_input_name)
                    elif parent_name in known_value_ranks:
                        function_bound_value_ranks[function_input_name] = known_value_ranks[parent_name]
                        if parent_name in proven_value_ranks:
                            function_bound_proven_value_ranks.add(function_input_name)
                    elif parent_name in dynamic_values or parent_name not in constants:
                        function_bound_unknown_value_ranks.add(function_input_name)
                    if parent_name in value_lineage_limit_gap_counts:
                        function_bound_lineage_gaps[function_input_name] = value_lineage_limit_gap_counts[parent_name]
                    if parent_name in value_non_shape_lineage_limit_gap_counts:
                        function_bound_non_shape_lineage_gaps[function_input_name] = (
                            value_non_shape_lineage_limit_gap_counts[parent_name]
                        )
                        function_bound_non_shape_lineage_gap_summaries[function_input_name] = known_weight_gap_summary(
                            value_non_shape_lineage_limit_gap_summaries.get(parent_name),
                            value_non_shape_lineage_limit_gap_counts[parent_name],
                        )
                    if parent_name in value_weight_lineage_limit_gap_counts:
                        function_bound_weight_lineage_gaps[function_input_name] = value_weight_lineage_limit_gap_counts[
                            parent_name
                        ]
                        function_bound_weight_lineage_gap_summaries[function_input_name] = known_weight_gap_summary(
                            value_weight_lineage_limit_gap_summaries.get(parent_name),
                            value_weight_lineage_limit_gap_counts[parent_name],
                        )
                    if parent_name in value_rank_promotable_lineage_limit_gap_counts:
                        function_bound_rank_promotable_lineage_gaps[function_input_name] = (
                            value_rank_promotable_lineage_limit_gap_counts[parent_name]
                        )
                        function_bound_rank_promotable_lineage_gap_summaries[function_input_name] = (
                            known_weight_gap_summary(
                                value_rank_promotable_lineage_limit_gap_summaries.get(parent_name),
                                value_rank_promotable_lineage_limit_gap_counts[parent_name],
                            )
                        )
                subgraph_results.append(
                    walk_graph(
                        function,
                        value_lineages,
                        constants,
                        dynamic_values,
                        root_graph=False,
                        source_scope=function_source_scope,
                        opset_versions={
                            str(getattr(opset, "domain", "") or ""): int(opset.version)
                            for opset in getattr(function, "opset_import", ())
                        }
                        or opset_versions,
                        bound_lineages=function_bound_lineages,
                        bound_constants=function_bound_constants,
                        bound_dynamic_values=function_bound_dynamic,
                        bound_lineage_limit_gap_counts=function_bound_lineage_gaps,
                        bound_non_shape_lineage_limit_gap_counts=function_bound_non_shape_lineage_gaps,
                        bound_non_shape_lineage_limit_gap_summaries=function_bound_non_shape_lineage_gap_summaries,
                        bound_weight_lineage_limit_gap_counts=function_bound_weight_lineage_gaps,
                        bound_weight_lineage_limit_gap_summaries=function_bound_weight_lineage_gap_summaries,
                        bound_rank_promotable_lineage_limit_gap_counts=(function_bound_rank_promotable_lineage_gaps),
                        bound_rank_promotable_lineage_limit_gap_summaries=(
                            function_bound_rank_promotable_lineage_gap_summaries
                        ),
                        bound_value_shapes=function_bound_value_shapes,
                        bound_value_ranks=function_bound_value_ranks,
                        bound_unknown_value_ranks=function_bound_unknown_value_ranks,
                        bound_proven_value_ranks=function_bound_proven_value_ranks,
                        bound_attributes=function_bound_attributes,
                        bound_attribute_keys=function_bound_attribute_keys,
                        function_depth=function_depth + 1,
                        fail_on_unbound_inputs=fail_on_unbound_inputs,
                    ),
                )

            # Keep dimension provenance: a later Cast can turn dimensions into weights.
            is_shape_query = (
                is_registered_standard_operator
                and not is_model_local_function
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type in {"Shape", "Size"}
            )
            output_lineages: dict[int, _OnnxWeightLineage] = {}
            broadcast_operator_promotes_deferred_gap = False
            elementwise_output_shape: tuple[int, ...] | None = None
            elementwise_output_rank: int | None = None
            same_type_elementwise = (
                is_registered_standard_operator
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type in _SAME_TYPE_ELEMENTWISE_OPERATORS
            )
            same_type_unary_elementwise = (
                is_registered_standard_operator
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type in _SAME_TYPE_UNARY_ELEMENTWISE_OPERATORS
                and len(input_names) == 1
            )
            clip_operator = (
                is_registered_standard_operator
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type == "Clip"
            )
            pow_operator = (
                is_registered_standard_operator
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type == "Pow"
            )
            size_operator = is_shape_query and node.op_type == "Size" and not all_input_lineages
            elementwise_has_unknown_dynamic_rank = False
            elementwise_output_rank_proven = True
            if same_type_elementwise or same_type_unary_elementwise or pow_operator:
                elementwise_output_shape = broadcast_shapes(
                    known_value_shapes.get(input_name) for input_name in input_names
                )
                elementwise_input_ranks = [known_value_ranks.get(input_name) for input_name in input_names]
                elementwise_output_rank = (
                    len(elementwise_output_shape)
                    if elementwise_output_shape is not None
                    else broadcast_rank_from_input_ranks(elementwise_input_ranks)
                )
                elementwise_has_unknown_dynamic_rank = any(
                    value_has_unknown_dynamic_rank(input_name) for input_name in input_names
                )
                if elementwise_has_unknown_dynamic_rank:
                    elementwise_output_shape = None
                    elementwise_output_rank = None
                elementwise_output_rank_proven = all(
                    value_rank_is_proven_or_unknown(input_name) for input_name in input_names
                )
            elif clip_operator and input_names:
                elementwise_output_shape = known_value_shapes.get(input_names[0])
                elementwise_output_rank = (
                    len(elementwise_output_shape)
                    if elementwise_output_shape is not None
                    else known_value_ranks.get(input_names[0])
                )
                elementwise_output_rank_proven = value_rank_is_proven_or_unknown(input_names[0])
            elif size_operator:
                elementwise_output_shape = ()
                elementwise_output_rank = 0
            resolved_cast_target_data_type = (
                cast_output_data_type(node, resolve_attribute)
                if supported_transform and node.op_type == "Cast"
                else None
            )
            if supported_transform:
                data_lineages = value_lineages.get(str(node.input[0]), {}) if node.input else {}
                for initializer_index, lineage in data_lineages.items():
                    transform_counts[initializer_index] += 1
                    output_lineages[initializer_index] = transformed_lineage(
                        lineage,
                        node,
                        constants,
                        cast_target_data_type=resolved_cast_target_data_type,
                        resolve_attribute=resolve_attribute,
                    )
                merge_lineages(
                    output_lineages,
                    shape_control_input_lineages,
                    ambiguous_reason="ambiguous_operator_input_lineage",
                )
            elif is_shape_query:
                for initializer_index, lineage in all_input_lineages.items():
                    output_lineages[initializer_index] = _OnnxWeightLineage(
                        initializer_index=initializer_index,
                        shape=None,
                        data_type=onnx.TensorProto.INT64,
                        transforms=lineage.transforms,
                        unresolved_reason="shape_dimensions_lineage",
                    )
            elif (
                all_input_lineages
                and node.op_type not in _QUANTIZED_WEIGHT_OPERATORS
                and function is None
                and not subgraph_results
            ):
                prelu_data_is_activation = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and node.op_type == "PRelu"
                    and bool(input_names)
                    and (
                        input_names[0] in dynamic_values
                        or (
                            bool(value_lineages.get(input_names[0]))
                            and all(
                                lineage.unresolved_reason == "dynamic_activation_lineage"
                                for lineage in value_lineages[input_names[0]].values()
                            )
                        )
                    )
                )
                broadcast_operator_promotes_deferred_gap = (
                    (same_type_elementwise or pow_operator)
                    and all_input_rank_promotable_lineage_limit_gap_count > 0
                    and (elementwise_output_rank is None or elementwise_output_rank >= 2)
                )
                carries_dynamic_activation = bool(terminal_weight_lineages) and has_dynamic_input
                carries_dynamic_activation |= prelu_data_is_activation
                carries_dynamic_activation |= any(
                    lineage.unresolved_reason == "dynamic_activation_lineage" for lineage in all_input_lineages.values()
                )
                preserves_shape_control = (
                    is_registered_standard_operator
                    and not is_model_local_function
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and (
                        same_type_elementwise
                        or (
                            same_type_unary_elementwise
                            and node.op_type not in {"Hardmax", "LogSoftmax", "LpNormalization", "Softmax"}
                        )
                        or clip_operator
                        or pow_operator
                        or node.op_type
                        in {
                            "AveragePool",
                            "BatchNormalization",
                            "Concat",
                            "Conv",
                            "ConvTranspose",
                            "GlobalAveragePool",
                            "GlobalMaxPool",
                            "MaxPool",
                        }
                        or node.op_type in {"Expand", "Gather", "GatherElements", "GatherND", "Slice", "Tile"}
                    )
                )
                preserves_data_type = (
                    same_type_elementwise
                    or same_type_unary_elementwise
                    or clip_operator
                    or (
                        is_registered_standard_operator
                        and not is_model_local_function
                        and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                        and node.op_type
                        in {"Concat", "Expand", "Gather", "GatherElements", "GatherND", "Slice", "Tile"}
                    )
                )
                for initializer_index, lineage in all_input_lineages.items():
                    lineage_output_shape = elementwise_output_shape if elementwise_output_rank_proven else None
                    if initializer_index in activation_input_lineages:
                        continue
                    unresolved_reason = lineage.unresolved_reason
                    if unresolved_reason == "shape_control_lineage" and not preserves_shape_control:
                        # Reductions, normalization and unknown operators can turn extents into data values.
                        unresolved_reason = "shape_dimensions_lineage"
                    if unresolved_reason is None:
                        if (
                            initializer_index in batch_normalization_activation_parameter_lineages
                            or carries_dynamic_activation
                        ):
                            unresolved_reason = "dynamic_activation_lineage"
                        else:
                            unresolved_reason = (
                                "dynamic_input_lineage" if has_dynamic_input else "unsupported_lineage_operator"
                            )
                    output_lineages[initializer_index] = _OnnxWeightLineage(
                        initializer_index=initializer_index,
                        shape=lineage_output_shape,
                        data_type=lineage.data_type if preserves_data_type else None,
                        transforms=lineage.transforms,
                        unresolved_reason=unresolved_reason,
                    )

            (
                output_lineages,
                output_lineage_limit_gap_count,
                output_non_shape_lineage_limit_gap_count,
                output_non_shape_lineage_gap_summary,
                output_weight_lineage_limit_gap_count,
                output_rank_promotable_lineage_limit_gap_count,
                output_weight_lineage_gap_summary,
                output_rank_promotable_lineage_gap_summary,
            ) = bounded_lineages(output_lineages)
            all_input_output_weight_lineage_limit_gap_count = all_input_weight_lineage_limit_gap_count
            all_input_output_weight_lineage_gap_summary = all_input_weight_lineage_limit_gap_summary
            all_input_output_rank_promotable_lineage_limit_gap_count = all_input_rank_promotable_lineage_limit_gap_count
            all_input_output_rank_promotable_lineage_gap_summary = all_input_rank_promotable_lineage_limit_gap_summary
            if elementwise_has_unknown_dynamic_rank and all_input_lineage_limit_gap_count:
                all_input_output_weight_lineage_limit_gap_count = max(
                    all_input_output_weight_lineage_limit_gap_count,
                    min(all_input_lineage_limit_gap_count, _ONNX_WEIGHT_LINEAGE_GAP_COUNT_LIMIT),
                )
                all_input_output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                    all_input_output_weight_lineage_gap_summary,
                    known_weight_gap_summary(None, all_input_lineage_limit_gap_count),
                )
            if elementwise_has_unknown_dynamic_rank and output_rank_promotable_lineage_limit_gap_count:
                promoted_output_rank_gap_summary = rank_gap_weight_summary_after_rank_increase(
                    known_weight_gap_summary(
                        output_rank_promotable_lineage_gap_summary,
                        output_rank_promotable_lineage_limit_gap_count,
                    ),
                    output_rank_promotable_lineage_limit_gap_count,
                )
                if promoted_output_rank_gap_summary != empty_weight_gap_summary or elementwise_output_rank is None:
                    output_weight_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        output_weight_lineage_limit_gap_count,
                        output_rank_promotable_lineage_limit_gap_count,
                    )
                    output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        output_weight_lineage_gap_summary,
                        known_weight_gap_summary(
                            promoted_output_rank_gap_summary,
                            output_rank_promotable_lineage_limit_gap_count,
                        ),
                    )
                    output_rank_promotable_lineage_limit_gap_count = 0
                    output_rank_promotable_lineage_gap_summary = empty_weight_gap_summary
            if is_shape_query:
                all_input_output_weight_lineage_limit_gap_count = 0
                all_input_output_weight_lineage_gap_summary = empty_weight_gap_summary
                all_input_output_rank_promotable_lineage_limit_gap_count = 0
                all_input_output_rank_promotable_lineage_gap_summary = empty_weight_gap_summary
                output_weight_lineage_limit_gap_count = 0
                output_weight_lineage_gap_summary = empty_weight_gap_summary
                output_rank_promotable_lineage_limit_gap_count = 0
                output_rank_promotable_lineage_gap_summary = empty_weight_gap_summary
            pre_promotion_weight_lineage_limit_gap_count = all_input_output_weight_lineage_limit_gap_count
            pre_promotion_weight_lineage_gap_summary = all_input_output_weight_lineage_gap_summary
            transformed_input_output_non_shape_lineage_gap_summary = all_input_non_shape_lineage_gap_summary
            transformed_input_output_weight_lineage_gap_summary = all_input_output_weight_lineage_gap_summary
            transformed_input_output_rank_promotable_lineage_gap_summary = (
                all_input_output_rank_promotable_lineage_gap_summary
            )
            cast_promoted_non_shape_weight_lineage_gap_summary = empty_weight_gap_summary
            promoted_rank_lineage_limit_gap_count = 0
            promoted_rank_lineage_gap_summary = empty_weight_gap_summary
            rank_gap_control_input_is_overridable = (
                node.op_type in {"Expand", "Gather", "GatherND", "Reshape", "Squeeze", "Unsqueeze"}
                and len(node.input) > 1
                and (
                    graph_input_is_runtime_overridable(str(node.input[1]), graph_input_names, constants)
                    or str(node.input[1]) in dynamic_values
                )
            )
            if (
                rank_gap_promoting_operator
                and transform_data_input_rank_promotable_lineage_limit_gap_count
                and rank_gap_control_input_is_overridable
            ):
                promoted_rank_lineage_limit_gap_count = transform_data_input_rank_promotable_lineage_limit_gap_count
                promoted_rank_lineage_gap_summary = known_weight_gap_summary(
                    None,
                    promoted_rank_lineage_limit_gap_count,
                )
            elif rank_gap_promoting_operator and transform_data_input_rank_promotable_lineage_limit_gap_count:
                candidate_promoted_summary = promoted_rank_gap_weight_summary(
                    transform_data_input_rank_promotable_lineage_limit_gap_summary,
                    node,
                    constants,
                    transform_data_input_rank_promotable_lineage_limit_gap_count,
                    resolve_attribute=resolve_attribute,
                )
                rank_gap_promotion_known_not_weight = (
                    transform_data_input_rank_promotable_lineage_limit_gap_summary.lineages
                    and not transform_data_input_rank_promotable_lineage_limit_gap_summary.truncated
                    and candidate_promoted_summary == empty_weight_gap_summary
                )
                if candidate_promoted_summary != empty_weight_gap_summary or (
                    not rank_gap_promotion_known_not_weight
                    and operator_output_may_have_weight_rank(
                        node,
                        input_shape=known_value_shapes.get(input_names[0]) if input_names else None,
                        index_shape=known_value_shapes.get(input_names[1]) if len(input_names) > 1 else None,
                        constants=constants,
                        resolve_attribute=resolve_attribute,
                    )
                ):
                    promoted_rank_lineage_limit_gap_count = transform_data_input_rank_promotable_lineage_limit_gap_count
                    promoted_rank_lineage_gap_summary = known_weight_gap_summary(
                        candidate_promoted_summary,
                        promoted_rank_lineage_limit_gap_count,
                    )
            if broadcast_operator_promotes_deferred_gap:
                broadcast_promoted_summary = rank_gap_weight_summary_after_rank_increase(
                    all_input_rank_promotable_lineage_limit_gap_summary,
                    all_input_rank_promotable_lineage_limit_gap_count,
                    output_shape=elementwise_output_shape,
                    output_rank=elementwise_output_rank,
                )
                if broadcast_promoted_summary != empty_weight_gap_summary:
                    promoted_rank_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        promoted_rank_lineage_limit_gap_count,
                        all_input_rank_promotable_lineage_limit_gap_count,
                    )
                    promoted_rank_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        promoted_rank_lineage_gap_summary,
                        broadcast_promoted_summary,
                    )
            rank_operator_promotes_deferred_gap = promoted_rank_lineage_limit_gap_count > 0
            if rank_operator_promotes_deferred_gap:
                all_input_output_weight_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                    all_input_output_weight_lineage_limit_gap_count,
                    promoted_rank_lineage_limit_gap_count,
                )
                all_input_output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                    all_input_output_weight_lineage_gap_summary,
                    promoted_rank_lineage_gap_summary,
                )
                if promoted_rank_lineage_limit_gap_count == all_input_output_rank_promotable_lineage_limit_gap_count:
                    all_input_output_rank_promotable_lineage_limit_gap_count = 0
                    all_input_output_rank_promotable_lineage_gap_summary = empty_weight_gap_summary
                    transformed_input_output_rank_promotable_lineage_gap_summary = empty_weight_gap_summary
            if (
                supported_transform
                and node.op_type == "Cast"
                and cast_output_may_be_floating(node, resolve_attribute)
                and all_input_non_shape_lineage_limit_gap_count > all_input_output_weight_lineage_limit_gap_count
            ):
                cast_non_shape_gap_summary = known_weight_gap_summary(
                    all_input_non_shape_lineage_gap_summary,
                    all_input_non_shape_lineage_limit_gap_count,
                )
                cast_output_may_have_weight_rank = not output_lineages or any(
                    lineage.shape is None or len(lineage.shape) >= 2 for lineage in output_lineages.values()
                )
                if cast_output_may_have_weight_rank or floating_cast_non_shape_gap_may_be_weight(
                    cast_non_shape_gap_summary,
                    node,
                    constants,
                    cast_target_data_type=resolved_cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                ):
                    all_input_output_weight_lineage_limit_gap_count = all_input_non_shape_lineage_limit_gap_count
                    cast_promoted_non_shape_weight_lineage_gap_summary = transform_weight_gap_summary(
                        cast_non_shape_gap_summary,
                        node,
                        constants,
                        cast_target_data_type=resolved_cast_target_data_type,
                        resolve_attribute=resolve_attribute,
                    )
                    all_input_output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        all_input_output_weight_lineage_gap_summary,
                        cast_promoted_non_shape_weight_lineage_gap_summary,
                    )
                else:
                    all_input_output_rank_promotable_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        all_input_output_rank_promotable_lineage_limit_gap_count,
                        all_input_non_shape_lineage_limit_gap_count,
                    )
                    all_input_output_rank_promotable_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        all_input_output_rank_promotable_lineage_gap_summary,
                        cast_non_shape_gap_summary,
                    )
                    transformed_input_output_rank_promotable_lineage_gap_summary = (
                        all_input_output_rank_promotable_lineage_gap_summary
                    )
            if (
                supported_transform
                and node.op_type == "Cast"
                and cast_output_may_be_floating(node, resolve_attribute)
                and output_non_shape_lineage_limit_gap_count > output_weight_lineage_limit_gap_count
            ):
                cast_output_non_shape_gap_summary = known_weight_gap_summary(
                    output_non_shape_lineage_gap_summary,
                    output_non_shape_lineage_limit_gap_count,
                )
                cast_output_may_have_weight_rank = not output_lineages or any(
                    lineage.shape is None or len(lineage.shape) >= 2 for lineage in output_lineages.values()
                )
                if cast_output_may_have_weight_rank or floating_cast_non_shape_gap_may_be_weight(
                    cast_output_non_shape_gap_summary,
                    node,
                    constants,
                    cast_target_data_type=resolved_cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                ):
                    output_weight_lineage_limit_gap_count = output_non_shape_lineage_limit_gap_count
                    output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        output_weight_lineage_gap_summary,
                        transform_weight_gap_summary(
                            cast_output_non_shape_gap_summary,
                            node,
                            constants,
                            cast_target_data_type=resolved_cast_target_data_type,
                            resolve_attribute=resolve_attribute,
                        ),
                    )
                else:
                    output_rank_promotable_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        output_rank_promotable_lineage_limit_gap_count,
                        output_non_shape_lineage_limit_gap_count,
                    )
                    output_rank_promotable_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        output_rank_promotable_lineage_gap_summary,
                        transform_rank_promotable_gap_summary(
                            cast_output_non_shape_gap_summary,
                            node,
                            constants,
                            cast_target_data_type=resolved_cast_target_data_type,
                            resolve_attribute=resolve_attribute,
                        ),
                    )
            cast_output_is_nonfloating_transform = (
                supported_transform
                and node.op_type == "Cast"
                and not cast_output_may_be_floating(node, resolve_attribute)
            )
            transform_control_input_is_overridable = rank_gap_control_input_is_overridable
            transform_can_demote_weight_gap = not transform_control_input_is_overridable
            transform_output_demotes_weight_gap = (
                supported_transform
                and transform_can_demote_weight_gap
                and all_input_output_weight_lineage_limit_gap_count > 0
                and weight_gap_summary_demotes_after_transform(
                    all_input_output_weight_lineage_gap_summary,
                    node,
                    constants,
                    cast_target_data_type=resolved_cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                )
                and not any(lineage_could_be_weight(lineage) for lineage in output_lineages.values())
                and any(lineage_could_be_weight_after_rank_increase(lineage) for lineage in output_lineages.values())
            )
            if supported_transform and all_input_output_weight_lineage_limit_gap_count > 0:
                transformed_input_output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                    transform_weight_gap_summary(
                        pre_promotion_weight_lineage_gap_summary,
                        node,
                        constants,
                        cast_target_data_type=resolved_cast_target_data_type,
                        resolve_attribute=resolve_attribute,
                    )
                    if pre_promotion_weight_lineage_limit_gap_count
                    else empty_weight_gap_summary,
                    cast_promoted_non_shape_weight_lineage_gap_summary,
                    promoted_rank_lineage_gap_summary
                    if rank_operator_promotes_deferred_gap
                    else empty_weight_gap_summary,
                )
            if supported_transform and all_input_non_shape_lineage_limit_gap_count > 0:
                transformed_input_output_non_shape_lineage_gap_summary = transform_non_shape_gap_summary(
                    all_input_non_shape_lineage_gap_summary,
                    node,
                    constants,
                    cast_target_data_type=resolved_cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                )
            if supported_transform and all_input_output_rank_promotable_lineage_limit_gap_count > 0:
                transformed_input_output_rank_promotable_lineage_gap_summary = transform_rank_promotable_gap_summary(
                    all_input_output_rank_promotable_lineage_gap_summary,
                    node,
                    constants,
                    cast_target_data_type=resolved_cast_target_data_type,
                    resolve_attribute=resolve_attribute,
                )
            if (
                rank_operator_promotes_deferred_gap
                and output_rank_promotable_lineage_limit_gap_count > output_weight_lineage_limit_gap_count
            ):
                output_rank_promoted_summary = rank_gap_weight_summary_after_rank_increase(
                    output_rank_promotable_lineage_gap_summary,
                    output_rank_promotable_lineage_limit_gap_count,
                    output_shape=next(
                        (lineage.shape for lineage in output_lineages.values() if lineage.shape is not None),
                        None,
                    ),
                )
                if output_rank_promoted_summary != empty_weight_gap_summary:
                    output_weight_lineage_limit_gap_count = output_rank_promotable_lineage_limit_gap_count
                    output_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        output_weight_lineage_gap_summary,
                        output_rank_promoted_summary,
                    )
            constant_output_names: set[str] = set()
            constant_output_lineages: dict[str, dict[int, _OnnxWeightLineage]] = {}
            if getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS and node.op_type == "Constant":
                constant_tensor = None
                sparse_constant = None
                unresolved_constant_attribute = False
                constant_source_key: tuple[Any, ...] | None = None
                for attribute_position, attribute in enumerate(node.attribute):
                    resolved_attribute = resolve_attribute(attribute)
                    if resolved_attribute is None:
                        unresolved_constant_attribute = True
                        continue
                    if attribute.name == "value":
                        if _onnx_has_singular_field(resolved_attribute, "t"):
                            constant_tensor = resolved_attribute.t
                    elif attribute.name == "value_ints":
                        constant_tensor = onnx.helper.make_tensor(
                            "",
                            onnx.TensorProto.INT64,
                            [len(resolved_attribute.ints)],
                            list(resolved_attribute.ints),
                        )
                    elif attribute.name == "value_int":
                        constant_tensor = onnx.helper.make_tensor(
                            "",
                            onnx.TensorProto.INT64,
                            [],
                            [resolved_attribute.i],
                        )
                    elif attribute.name == "value_floats":
                        constant_tensor = onnx.helper.make_tensor(
                            "",
                            onnx.TensorProto.FLOAT,
                            [len(resolved_attribute.floats)],
                            list(resolved_attribute.floats),
                        )
                    elif attribute.name == "value_float":
                        constant_tensor = onnx.helper.make_tensor(
                            "",
                            onnx.TensorProto.FLOAT,
                            [],
                            [resolved_attribute.f],
                        )
                    elif attribute.name == "sparse_value" and _onnx_has_singular_field(
                        resolved_attribute,
                        "sparse_tensor",
                    ):
                        sparse_constant = resolved_attribute.sparse_tensor
                    if constant_tensor is not None or sparse_constant is not None:
                        constant_source_key = (
                            "constant_value",
                            *attribute_source_key(attribute, local_node_index, attribute_position),
                        )
                        break
                output_names = [str(output_name) for output_name in node.output if output_name]
                if len(output_names) != 1:
                    plan.record_coverage_gap("invalid_constant_outputs")
                elif constant_tensor is not None:
                    name = output_names[0]
                    constant_tensor.name = name
                    lineage = register_initializer(
                        constant_tensor,
                        current_graph_index,
                        source_key=constant_source_key,
                        constant_output=True,
                    )
                    constants[name] = constant_tensor
                    constant_output_lineages[name] = {lineage.initializer_index: lineage}
                    constant_output_names.add(name)
                    clear_value_gap_state(name)
                elif sparse_constant is not None:
                    name = output_names[0]
                    sparse_constant.values.name = name
                    lineage = register_initializer(
                        sparse_constant.values,
                        current_graph_index,
                        shape=tuple(int(dimension) for dimension in sparse_constant.dims),
                        unresolved_reason="sparse_constant_unsupported",
                        source_key=constant_source_key,
                        constant_output=True,
                    )
                    constant_output_lineages[name] = {lineage.initializer_index: lineage}
                    constant_output_names.add(name)
                    clear_value_gap_state(name)
                elif unresolved_constant_attribute:
                    name = output_names[0]
                    unresolved_tensor = onnx.TensorProto()
                    unresolved_tensor.name = name
                    lineage = register_initializer(
                        unresolved_tensor,
                        current_graph_index,
                        unresolved_reason="unresolved_constant_attribute",
                        source_key=(*source_scope, "node", local_node_index, "unresolved_constant"),
                        constant_output=True,
                    )
                    constant_output_lineages[name] = {lineage.initializer_index: lineage}
                    constant_output_names.add(name)
                    clear_value_gap_state(name)

            subgraph_output_lineages: list[dict[int, _OnnxWeightLineage]] = [{} for _ in node.output]
            subgraph_output_dynamic = [False for _ in node.output]
            subgraph_output_lineage_gap_counts = [0 for _ in node.output]
            subgraph_output_non_shape_lineage_gap_counts = [0 for _ in node.output]
            subgraph_output_non_shape_lineage_gap_summaries = [empty_weight_gap_summary for _ in node.output]
            subgraph_output_weight_lineage_gap_counts = [0 for _ in node.output]
            subgraph_output_weight_lineage_gap_summaries = [empty_weight_gap_summary for _ in node.output]
            subgraph_output_rank_promotable_lineage_gap_counts = [0 for _ in node.output]
            subgraph_output_rank_promotable_lineage_gap_summaries = [empty_weight_gap_summary for _ in node.output]
            subgraph_output_shapes: list[tuple[int, ...] | None] = [None for _ in node.output]
            subgraph_output_ranks: list[int | None] = [None for _ in node.output]
            subgraph_output_proven_ranks = [False for _ in node.output]
            subgraph_output_rank_seen = [False for _ in node.output]
            subgraph_output_rank_unknown = [False for _ in node.output]

            def merge_subgraph_output_gap_state(
                output_index: int,
                parent_name: str,
                *,
                output_dynamic: list[bool] = subgraph_output_dynamic,
                output_lineage_gap_counts: list[int] = subgraph_output_lineage_gap_counts,
                output_non_shape_gap_counts: list[int] = subgraph_output_non_shape_lineage_gap_counts,
                output_non_shape_gap_summaries: list[_OnnxWeightLineageGapSummary] = (
                    subgraph_output_non_shape_lineage_gap_summaries
                ),
                output_weight_gap_counts: list[int] = subgraph_output_weight_lineage_gap_counts,
                output_weight_gap_summaries: list[_OnnxWeightLineageGapSummary] = (
                    subgraph_output_weight_lineage_gap_summaries
                ),
                output_rank_promotable_gap_counts: list[int] = subgraph_output_rank_promotable_lineage_gap_counts,
                output_rank_promotable_gap_summaries: list[_OnnxWeightLineageGapSummary] = (
                    subgraph_output_rank_promotable_lineage_gap_summaries
                ),
            ) -> None:
                output_dynamic[output_index] |= parent_name in dynamic_values
                output_lineage_gap_counts[output_index] = _bounded_onnx_weight_lineage_gap_count(
                    output_lineage_gap_counts[output_index],
                    value_lineage_limit_gap_counts.get(parent_name, 0),
                )
                output_non_shape_gap_counts[output_index] = _bounded_onnx_weight_lineage_gap_count(
                    output_non_shape_gap_counts[output_index],
                    value_non_shape_lineage_limit_gap_counts.get(parent_name, 0),
                )
                output_non_shape_gap_summaries[output_index] = merge_weight_lineage_gap_summaries(
                    output_non_shape_gap_summaries[output_index],
                    known_weight_gap_summary(
                        value_non_shape_lineage_limit_gap_summaries.get(parent_name),
                        value_non_shape_lineage_limit_gap_counts.get(parent_name, 0),
                    ),
                )
                parent_weight_gap_count = value_weight_lineage_limit_gap_counts.get(parent_name, 0)
                output_weight_gap_counts[output_index] = _bounded_onnx_weight_lineage_gap_count(
                    output_weight_gap_counts[output_index],
                    parent_weight_gap_count,
                )
                output_weight_gap_summaries[output_index] = merge_weight_lineage_gap_summaries(
                    output_weight_gap_summaries[output_index],
                    known_weight_gap_summary(
                        value_weight_lineage_limit_gap_summaries.get(parent_name),
                        parent_weight_gap_count,
                    ),
                )
                output_rank_promotable_gap_counts[output_index] = _bounded_onnx_weight_lineage_gap_count(
                    output_rank_promotable_gap_counts[output_index],
                    value_rank_promotable_lineage_limit_gap_counts.get(parent_name, 0),
                )
                output_rank_promotable_gap_summaries[output_index] = merge_weight_lineage_gap_summaries(
                    output_rank_promotable_gap_summaries[output_index],
                    known_weight_gap_summary(
                        value_rank_promotable_lineage_limit_gap_summaries.get(parent_name),
                        value_rank_promotable_lineage_limit_gap_counts.get(parent_name, 0),
                    ),
                )

            def merge_subgraph_output_rank(
                output_index: int,
                output_shape: tuple[int, ...] | None,
                output_rank: int | None,
                output_rank_proven: bool,
                *,
                output_shapes: list[tuple[int, ...] | None] = subgraph_output_shapes,
                output_ranks: list[int | None] = subgraph_output_ranks,
                output_proven_ranks: list[bool] = subgraph_output_proven_ranks,
                output_rank_seen: list[bool] = subgraph_output_rank_seen,
                output_rank_unknown: list[bool] = subgraph_output_rank_unknown,
            ) -> None:
                if output_shape is not None:
                    if not output_rank_seen[output_index]:
                        output_shapes[output_index] = output_shape
                        output_ranks[output_index] = len(output_shape)
                        output_proven_ranks[output_index] = output_rank_proven
                    elif output_shapes[output_index] != output_shape:
                        current_rank = output_ranks[output_index]
                        candidate_rank = len(output_shape)
                        output_shapes[output_index] = None
                        output_proven_ranks[output_index] &= output_rank_proven
                        if current_rank == candidate_rank:
                            output_ranks[output_index] = candidate_rank
                        else:
                            output_ranks[output_index] = None
                            output_proven_ranks[output_index] = False
                            output_rank_unknown[output_index] = True
                    output_rank_seen[output_index] = True
                elif output_rank is not None:
                    if not output_rank_seen[output_index]:
                        output_ranks[output_index] = output_rank
                        output_proven_ranks[output_index] = output_rank_proven
                    elif output_ranks[output_index] == output_rank:
                        output_shapes[output_index] = None
                        output_proven_ranks[output_index] &= output_rank_proven
                    else:
                        output_shapes[output_index] = None
                        output_ranks[output_index] = None
                        output_proven_ranks[output_index] = False
                        output_rank_unknown[output_index] = True
                    output_rank_seen[output_index] = True
                else:
                    output_shapes[output_index] = None
                    output_ranks[output_index] = None
                    output_proven_ranks[output_index] = False
                    output_rank_seen[output_index] = True
                    output_rank_unknown[output_index] = True

            def control_flow_state_input_name(output_index: int, *, current_node: Any = node) -> str:
                if current_node.op_type == "Loop":
                    input_offset = 2
                elif current_node.op_type == "Scan":
                    input_offset = scan_sequence_lens_input_offset(current_node, opset_versions)
                else:
                    input_offset = 0
                state_input_index = output_index + input_offset
                if state_input_index >= len(current_node.input) or not current_node.input[state_input_index]:
                    return ""
                return str(current_node.input[state_input_index])

            def control_flow_state_input_rank(output_index: int) -> int | None:
                state_input_name = control_flow_state_input_name(output_index)
                state_input_shape = known_value_shapes.get(state_input_name)
                return (
                    len(state_input_shape) if state_input_shape is not None else known_value_ranks.get(state_input_name)
                )

            standard_control_flow_operator = (
                is_registered_standard_operator
                and not is_model_local_function
                and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
            )
            scan_output_axes = (
                resolved_int_sequence_attribute(node, "scan_output_axes") or ()
                if standard_control_flow_operator and node.op_type == "Scan"
                else ()
            )
            resolved_scan_input_axes = (
                resolved_int_sequence_attribute(node, "scan_input_axes") or ()
                if standard_control_flow_operator and node.op_type == "Scan"
                else ()
            )
            resolved_scan_input_offset = (
                scan_sequence_lens_input_offset(node, opset_versions)
                if standard_control_flow_operator and node.op_type == "Scan"
                else 0
            )
            resolved_scan_input_count = (
                resolved_int_attribute(node, "num_scan_inputs", 1)
                if standard_control_flow_operator and node.op_type == "Scan"
                else 0
            )
            trusted_scan_shape_names = proven_value_ranks
            untrusted_scan_shape_names = {
                name for name in graph_input_names & set(value_lineages) if name not in proven_value_ranks
            }

            def scan8_batch_extent(
                output_index: int,
                *,
                stacked_output: bool,
                current_node: Any = node,
                input_offset: int = resolved_scan_input_offset,
            ) -> int:
                if stacked_output:
                    num_scan_inputs = resolved_int_attribute(current_node, "num_scan_inputs", 1)
                    scan_input_start = max(len(current_node.input) - max(num_scan_inputs, 0), input_offset)
                    scan_output_index = output_index - max(len(current_node.input) - input_offset - num_scan_inputs, 0)
                    scan_input_index = min(max(scan_output_index, 0), max(num_scan_inputs - 1, 0))
                    value_index = scan_input_start + scan_input_index
                    value_name = str(current_node.input[value_index]) if value_index < len(current_node.input) else ""
                else:
                    value_name = control_flow_state_input_name(output_index)
                value_shape = known_value_shapes.get(value_name) if value_name in proven_value_ranks else None
                if value_shape:
                    return value_shape[0]
                initializer_shape = constant_initializer_shape(constants, value_name)
                if initializer_shape:
                    return initializer_shape[0]
                return -1

            def scan_stacked_output_extent(
                current_node: Any,
                output_index: int,
                *,
                trusted_shape_names: set[str] = trusted_scan_shape_names,
                untrusted_shape_names: set[str] = untrusted_scan_shape_names,
            ) -> int:
                num_scan_inputs = resolved_int_attribute(current_node, "num_scan_inputs", 1)
                if num_scan_inputs <= 0:
                    return -1
                input_offset = scan_sequence_lens_input_offset(current_node, opset_versions)
                scan_input_start = max(len(current_node.input) - num_scan_inputs, input_offset)
                scan_output_index = output_index - max(len(current_node.input) - input_offset - num_scan_inputs, 0)
                scan_input_index = min(max(scan_output_index, 0), max(num_scan_inputs - 1, 0))
                value_index = scan_input_start + scan_input_index
                value_name = str(current_node.input[value_index]) if value_index < len(current_node.input) else ""
                if input_offset and current_node.input:
                    sequence_lens_input = str(current_node.input[0] or "")
                    if graph_input_is_runtime_overridable(sequence_lens_input, graph_input_names, constants):
                        return -1
                    sequence_lens = constant_int64_vector_values(constants.get(sequence_lens_input))
                    if sequence_lens is not None and sequence_lens and all(length >= 0 for length in sequence_lens):
                        return max(sequence_lens)
                    return -1
                if value_name not in trusted_shape_names or value_name in untrusted_shape_names:
                    return -1
                value_shape = known_value_shapes.get(value_name)
                if not value_shape:
                    return -1
                scan_input_axes = resolved_int_sequence_attribute(current_node, "scan_input_axes") or ()
                default_axis = 1 if input_offset else 0
                raw_axis = (
                    scan_input_axes[scan_input_index] if scan_input_index < len(scan_input_axes) else default_axis
                )
                axis = raw_axis if raw_axis >= 0 else len(value_shape) + raw_axis
                if axis < 0 or axis >= len(value_shape):
                    return -1
                return value_shape[axis]

            subgraph_output_offset = 1 if standard_control_flow_operator and node.op_type == "Loop" else 0
            for (
                graph_output_lineages,
                graph_output_dynamic,
                graph_output_lineage_gap_counts,
                graph_output_non_shape_lineage_gap_counts,
                graph_output_non_shape_lineage_gap_summaries,
                graph_output_weight_lineage_gap_counts,
                graph_output_weight_lineage_gap_summaries,
                graph_output_rank_promotable_lineage_gap_counts,
                graph_output_rank_promotable_lineage_gap_summaries,
                graph_output_shapes,
                graph_output_ranks,
                graph_output_proven_ranks,
            ) in subgraph_results:
                stacked_scan_output_start = len(node.output)
                if standard_control_flow_operator and node.op_type == "Loop":
                    stacked_scan_output_start = max(len(node.input) - 2, 0)
                elif standard_control_flow_operator and node.op_type == "Scan":
                    stacked_scan_output_start = scan_stacked_output_start(
                        node,
                        opset_versions,
                        resolve_attribute=resolve_attribute,
                    )
                for output_index in range(len(node.output)):
                    graph_output_index = output_index + subgraph_output_offset
                    if graph_output_index >= len(graph_output_lineages):
                        continue
                    graph_output_rank_promotable_gap_count = graph_output_rank_promotable_lineage_gap_counts[
                        graph_output_index
                    ]
                    stacked_scan_output = standard_control_flow_operator and output_index >= stacked_scan_output_start
                    graph_output_parent_lineages = graph_output_lineages[graph_output_index]
                    graph_output_shape = graph_output_shapes[graph_output_index]
                    graph_output_rank = graph_output_ranks[graph_output_index]
                    graph_output_rank_proven = graph_output_proven_ranks[graph_output_index]
                    repeated_carried_state_rank_may_increase = False
                    repeated_carried_state_input_may_feed_weight = False
                    scan_output_insert_axis = stacked_scan_output_insert_axis(
                        scan_output_axes,
                        stacked_scan_output_start,
                        output_index,
                    )
                    scan_output_extent = -1
                    if stacked_scan_output and standard_control_flow_operator:
                        if (
                            node.op_type == "Loop"
                            and (exact_loop_iterations := loop_exact_iteration_count()) is not None
                        ):
                            scan_output_extent = exact_loop_iterations
                        elif node.op_type == "Scan":
                            scan_output_extent = scan_stacked_output_extent(node, output_index)
                    if stacked_scan_output:
                        if graph_output_shape is not None:
                            graph_output_shape = insert_shape_axis(
                                graph_output_shape,
                                scan_output_insert_axis,
                                scan_output_extent,
                            )
                            graph_output_rank_proven = graph_output_rank_proven and scan_output_extent >= 0
                            if graph_output_shape is not None and resolved_scan_input_offset:
                                graph_output_shape = insert_shape_axis(
                                    graph_output_shape,
                                    0,
                                    scan8_batch_extent(output_index, stacked_output=True),
                                )
                                graph_output_rank_proven = graph_output_rank_proven and graph_output_shape is not None
                            graph_output_rank = len(graph_output_shape) if graph_output_shape is not None else None
                        elif graph_output_rank is not None:
                            graph_output_rank = insert_rank_axis(graph_output_rank, scan_output_insert_axis)
                            graph_output_rank_proven = False
                            if graph_output_rank is not None and resolved_scan_input_offset:
                                graph_output_rank = insert_rank_axis(graph_output_rank, 0)
                    elif standard_control_flow_operator and node.op_type == "Scan" and resolved_scan_input_offset:
                        if graph_output_shape is not None:
                            graph_output_shape = insert_shape_axis(
                                graph_output_shape,
                                0,
                                scan8_batch_extent(output_index, stacked_output=False),
                            )
                            graph_output_rank_proven = graph_output_rank_proven and graph_output_shape is not None
                            graph_output_rank = len(graph_output_shape) if graph_output_shape is not None else None
                        elif graph_output_rank is not None:
                            graph_output_rank = insert_rank_axis(graph_output_rank, 0)
                            graph_output_rank_proven = False
                    repeated_carried_state = (
                        standard_control_flow_operator
                        and not stacked_scan_output
                        and (
                            (node.op_type == "Loop" and loop_may_repeat_body(node, constants, graph_input_names))
                            or (
                                node.op_type == "Scan"
                                and scan_may_repeat_body(
                                    node,
                                    constants,
                                    graph_input_names,
                                    known_value_shapes,
                                    trusted_scan_shape_names,
                                    untrusted_scan_shape_names,
                                    scan_input_axes=resolved_scan_input_axes,
                                    scan_input_offset=resolved_scan_input_offset,
                                    num_scan_inputs=resolved_scan_input_count,
                                )
                            )
                        )
                    )
                    subgraph_state_input_name = ""
                    if standard_control_flow_operator and node.op_type == "Loop" and not stacked_scan_output:
                        subgraph_state_input_index = output_index + 2
                        subgraph_state_input_name = (
                            _onnx_value_name(subgraph.input[subgraph_state_input_index])
                            if subgraph_state_input_index < len(subgraph.input)
                            else ""
                        )
                    elif standard_control_flow_operator and node.op_type == "Scan" and not stacked_scan_output:
                        subgraph_state_input_name = (
                            _onnx_value_name(subgraph.input[output_index]) if output_index < len(subgraph.input) else ""
                        )
                    graph_output_shape_before_reentry_reset = graph_output_shape
                    graph_output_rank_before_reentry_reset = graph_output_rank
                    if repeated_carried_state:
                        state_input_name = control_flow_state_input_name(output_index)
                        repeated_carried_state_input_may_feed_weight = subgraph_state_input_can_reach_weight_consumer(
                            subgraph,
                            subgraph_state_input_name,
                            opset_versions,
                        )
                        state_input_shape = known_value_shapes.get(state_input_name)
                        state_input_rank = (
                            len(state_input_shape)
                            if state_input_shape is not None
                            else known_value_ranks.get(state_input_name)
                        )
                        if graph_output_rank != state_input_rank:
                            repeated_carried_state_rank_may_increase = (
                                graph_output_rank is None
                                or state_input_rank is None
                                or graph_output_rank > state_input_rank
                            )
                            graph_output_shape = None
                            graph_output_rank = None
                            graph_output_rank_proven = False
                        elif graph_output_shape != state_input_shape:
                            graph_output_shape = None
                            graph_output_rank_proven = (
                                graph_output_rank_proven and state_input_name in proven_value_ranks
                            )
                    if graph_output_parent_lineages and (
                        stacked_scan_output
                        or (
                            standard_control_flow_operator
                            and node.op_type == "Scan"
                            and resolved_scan_input_offset
                            and not stacked_scan_output
                        )
                    ):
                        graph_output_parent_lineages = lineages_after_control_flow_rank_increase(
                            graph_output_parent_lineages,
                            output_shape=graph_output_shape,
                            output_rank=graph_output_rank,
                            insert_axis=scan_output_insert_axis if stacked_scan_output else 0,
                        )
                    merge_lineages(
                        subgraph_output_lineages[output_index],
                        graph_output_parent_lineages,
                        ambiguous_reason="ambiguous_subgraph_output_lineage",
                    )
                    merge_subgraph_output_rank(
                        output_index,
                        graph_output_shape,
                        graph_output_rank,
                        graph_output_rank_proven,
                    )
                    subgraph_output_dynamic[output_index] |= graph_output_dynamic[graph_output_index]
                    subgraph_output_lineage_gap_counts[output_index] = _bounded_onnx_weight_lineage_gap_count(
                        subgraph_output_lineage_gap_counts[output_index],
                        graph_output_lineage_gap_counts[graph_output_index],
                    )
                    subgraph_output_non_shape_lineage_gap_counts[output_index] = _bounded_onnx_weight_lineage_gap_count(
                        subgraph_output_non_shape_lineage_gap_counts[output_index],
                        graph_output_non_shape_lineage_gap_counts[graph_output_index],
                    )
                    graph_output_non_shape_gap_summary = known_weight_gap_summary(
                        graph_output_non_shape_lineage_gap_summaries[graph_output_index],
                        graph_output_non_shape_lineage_gap_counts[graph_output_index],
                    )
                    if stacked_scan_output and graph_output_non_shape_lineage_gap_counts[graph_output_index]:
                        graph_output_non_shape_gap_summary = non_shape_gap_summary_after_rank_increase(
                            graph_output_non_shape_gap_summary,
                            graph_output_non_shape_lineage_gap_counts[graph_output_index],
                            insert_axis=scan_output_insert_axis,
                        )
                    elif (
                        standard_control_flow_operator
                        and node.op_type in {"Loop", "Scan"}
                        and not stacked_scan_output
                        and graph_output_non_shape_lineage_gap_counts[graph_output_index]
                        and (
                            (node.op_type == "Loop" and loop_may_repeat_body(node, constants, graph_input_names))
                            or (
                                node.op_type == "Scan"
                                and scan_may_repeat_body(
                                    node,
                                    constants,
                                    graph_input_names,
                                    known_value_shapes,
                                    trusted_scan_shape_names,
                                    untrusted_scan_shape_names,
                                    scan_input_axes=resolved_scan_input_axes,
                                    scan_input_offset=resolved_scan_input_offset,
                                    num_scan_inputs=resolved_scan_input_count,
                                )
                            )
                        )
                    ):
                        state_input_name = control_flow_state_input_name(output_index)
                        if gap_summary_may_exceed_input_rank(
                            graph_output_non_shape_gap_summary,
                            known_value_ranks.get(state_input_name),
                        ):
                            graph_output_non_shape_gap_summary = non_shape_gap_summary_after_rank_increase(
                                graph_output_non_shape_gap_summary,
                                graph_output_non_shape_lineage_gap_counts[graph_output_index],
                            )
                    subgraph_output_non_shape_lineage_gap_summaries[output_index] = merge_weight_lineage_gap_summaries(
                        subgraph_output_non_shape_lineage_gap_summaries[output_index],
                        graph_output_non_shape_gap_summary,
                    )
                    graph_output_weight_gap_summary = known_weight_gap_summary(
                        graph_output_weight_lineage_gap_summaries[graph_output_index],
                        graph_output_weight_lineage_gap_counts[graph_output_index],
                    )
                    finite_loop_rank_bounds: tuple[bool, bool, tuple[int, ...]] | None = None
                    finite_loop_body_consumes_output_weight_gap = True
                    if (
                        (
                            repeated_carried_state_rank_may_increase
                            or graph_output_weight_lineage_gap_counts[graph_output_index]
                        )
                        and subgraph_state_input_name
                        and node.op_type == "Loop"
                        and (
                            exact_loop_iterations := loop_exact_iteration_count(
                                max_count=_ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK,
                            )
                        )
                        is not None
                    ):
                        state_input_name = control_flow_state_input_name(output_index)
                        state_input_rank = control_flow_state_input_rank(output_index)
                        finite_loop_rank_bounds = exact_loop_repeated_state_weight_rank_bounds(
                            subgraph,
                            subgraph_state_input_name,
                            graph_output_index,
                            known_value_shapes.get(state_input_name),
                            state_input_rank,
                            exact_loop_iterations,
                            subgraph_trusted_context_shapes,
                            related_repeated_state_shapes,
                            len(getattr(node, "input", ())),
                        )
                        if finite_loop_rank_bounds is not None:
                            finite_loop_body_consumes_output_weight_gap = finite_loop_rank_bounds[0]
                            finite_loop_output_shape = finite_loop_rank_bounds[2]
                            finite_loop_output_rank = len(finite_loop_output_shape)
                            if len(getattr(node, "input", ())) <= 3:
                                graph_output_shape = finite_loop_output_shape
                                graph_output_rank = finite_loop_output_rank
                                subgraph_output_shapes[output_index] = finite_loop_output_shape
                                subgraph_output_ranks[output_index] = finite_loop_output_rank
                                subgraph_output_rank_seen[output_index] = True
                                subgraph_output_rank_unknown[output_index] = False
                        else:
                            one_iteration_output_rank = (
                                len(graph_output_shape_before_reentry_reset)
                                if graph_output_shape_before_reentry_reset is not None
                                else graph_output_rank_before_reentry_reset
                            )
                            if state_input_rank is not None and one_iteration_output_rank is not None:
                                rank_delta = max(one_iteration_output_rank - state_input_rank, 0)
                                max_body_consumed_rank = (
                                    state_input_rank + max(exact_loop_iterations - 1, 0) * rank_delta
                                )
                                finite_loop_body_consumes_output_weight_gap = max_body_consumed_rank >= 2
                    if (
                        repeated_carried_state_input_may_feed_weight
                        and graph_output_weight_lineage_gap_counts[graph_output_index]
                        and finite_loop_body_consumes_output_weight_gap
                    ):
                        plan.record_coverage_gap(
                            "lineages_per_value_limit",
                            graph_output_weight_lineage_gap_counts[graph_output_index],
                        )
                    if stacked_scan_output and graph_output_weight_lineage_gap_counts[graph_output_index]:
                        graph_output_weight_gap_summary = rank_gap_weight_summary_after_rank_increase(
                            graph_output_weight_gap_summary,
                            graph_output_weight_lineage_gap_counts[graph_output_index],
                            output_shape=graph_output_shape,
                            output_rank=graph_output_rank,
                            insert_axis=scan_output_insert_axis,
                        )
                    finite_loop_output_stays_below_weight_rank = (
                        finite_loop_rank_bounds is not None and not finite_loop_rank_bounds[1]
                    )
                    suppress_finite_loop_output_weight_gap = (
                        finite_loop_output_stays_below_weight_rank
                        and not finite_loop_body_consumes_output_weight_gap
                        and len(related_repeated_state_shapes) <= 1
                        and len(getattr(node, "input", ())) <= 3
                    )
                    if not suppress_finite_loop_output_weight_gap:
                        subgraph_output_weight_lineage_gap_counts[output_index] = (
                            _bounded_onnx_weight_lineage_gap_count(
                                subgraph_output_weight_lineage_gap_counts[output_index],
                                graph_output_weight_lineage_gap_counts[graph_output_index],
                            )
                        )
                        subgraph_output_weight_lineage_gap_summaries[output_index] = merge_weight_lineage_gap_summaries(
                            subgraph_output_weight_lineage_gap_summaries[output_index],
                            graph_output_weight_gap_summary,
                        )
                    rank_promotable_gap_promoted = False
                    if (
                        standard_control_flow_operator
                        and node.op_type in {"Loop", "Scan"}
                        and not stacked_scan_output
                        and graph_output_rank_promotable_gap_count
                        and repeated_carried_state_input_may_feed_weight
                        and (
                            (node.op_type == "Loop" and loop_may_repeat_body(node, constants, graph_input_names))
                            or (
                                node.op_type == "Scan"
                                and scan_may_repeat_body(
                                    node,
                                    constants,
                                    graph_input_names,
                                    known_value_shapes,
                                    trusted_scan_shape_names,
                                    untrusted_scan_shape_names,
                                    scan_input_axes=resolved_scan_input_axes,
                                    scan_input_offset=resolved_scan_input_offset,
                                    num_scan_inputs=resolved_scan_input_count,
                                )
                            )
                        )
                    ):
                        state_rank_gap_summary = known_weight_gap_summary(
                            graph_output_rank_promotable_lineage_gap_summaries[graph_output_index],
                            graph_output_rank_promotable_gap_count,
                        )
                        repeated_state_weight_gap_summary = empty_weight_gap_summary
                        finite_loop_body_consumes_weight_rank = True
                        finite_loop_output_reaches_weight_rank = True
                        if (
                            node.op_type == "Loop"
                            and (
                                exact_loop_iterations := loop_exact_iteration_count(
                                    max_count=_ONNX_REENTRY_ANALYSIS_MAX_GRAPH_WORK,
                                )
                            )
                            is not None
                        ):
                            state_input_rank = control_flow_state_input_rank(output_index)
                            if finite_loop_rank_bounds is None:
                                state_input_name = control_flow_state_input_name(output_index)
                                finite_loop_rank_bounds = exact_loop_repeated_state_weight_rank_bounds(
                                    subgraph,
                                    subgraph_state_input_name,
                                    graph_output_index,
                                    known_value_shapes.get(state_input_name),
                                    state_input_rank,
                                    exact_loop_iterations,
                                    subgraph_trusted_context_shapes,
                                    related_repeated_state_shapes,
                                    len(getattr(node, "input", ())),
                                )
                            if finite_loop_rank_bounds is not None:
                                finite_loop_body_consumes_weight_rank = finite_loop_rank_bounds[0]
                                finite_loop_output_reaches_weight_rank = finite_loop_rank_bounds[1]
                                finite_loop_output_shape = finite_loop_rank_bounds[2]
                                finite_loop_output_rank = len(finite_loop_output_shape)
                                if len(getattr(node, "input", ())) <= 3:
                                    graph_output_shape = finite_loop_output_shape
                                    graph_output_rank = finite_loop_output_rank
                                    subgraph_output_shapes[output_index] = finite_loop_output_shape
                                    subgraph_output_ranks[output_index] = finite_loop_output_rank
                                    subgraph_output_rank_seen[output_index] = True
                                    subgraph_output_rank_unknown[output_index] = False
                            elif len(getattr(node, "input", ())) <= 3:
                                one_iteration_output_rank = (
                                    len(graph_output_shape_before_reentry_reset)
                                    if graph_output_shape_before_reentry_reset is not None
                                    else graph_output_rank_before_reentry_reset
                                )
                                if state_input_rank is not None and one_iteration_output_rank is not None:
                                    rank_delta = max(one_iteration_output_rank - state_input_rank, 0)
                                    max_body_consumed_rank = (
                                        state_input_rank + max(exact_loop_iterations - 1, 0) * rank_delta
                                    )
                                    max_output_rank = state_input_rank + exact_loop_iterations * rank_delta
                                    finite_loop_body_consumes_weight_rank = max_body_consumed_rank >= 2
                                    finite_loop_output_reaches_weight_rank = max_output_rank >= 2
                        if repeated_carried_state_rank_may_increase and finite_loop_output_reaches_weight_rank:
                            repeated_state_weight_gap_summary = rank_gap_weight_summary_after_repeated_rank_increase(
                                state_rank_gap_summary,
                                graph_output_rank_promotable_gap_count,
                            )
                        elif (
                            not repeated_carried_state_rank_may_increase or finite_loop_output_reaches_weight_rank
                        ) and gap_summary_may_exceed_input_rank(
                            state_rank_gap_summary,
                            control_flow_state_input_rank(output_index),
                        ):
                            repeated_state_weight_gap_summary = rank_gap_weight_summary_after_rank_increase(
                                state_rank_gap_summary,
                                graph_output_rank_promotable_gap_count,
                                output_shape=graph_output_shape,
                                output_rank=graph_output_rank,
                            )
                        if repeated_state_weight_gap_summary != empty_weight_gap_summary:
                            if finite_loop_body_consumes_weight_rank:
                                plan.record_coverage_gap(
                                    "lineages_per_value_limit",
                                    graph_output_rank_promotable_gap_count,
                                )
                            subgraph_output_weight_lineage_gap_counts[output_index] = (
                                _bounded_onnx_weight_lineage_gap_count(
                                    subgraph_output_weight_lineage_gap_counts[output_index],
                                    graph_output_rank_promotable_gap_count,
                                )
                            )
                            subgraph_output_weight_lineage_gap_summaries[output_index] = (
                                merge_weight_lineage_gap_summaries(
                                    subgraph_output_weight_lineage_gap_summaries[output_index],
                                    repeated_state_weight_gap_summary,
                                )
                            )
                            rank_promotable_gap_promoted = True
                    if (
                        standard_control_flow_operator
                        and node.op_type == "Scan"
                        and resolved_scan_input_offset
                        and not stacked_scan_output
                        and graph_output_rank_promotable_gap_count
                        and not rank_promotable_gap_promoted
                    ):
                        state_rank_gap_summary = known_weight_gap_summary(
                            graph_output_rank_promotable_lineage_gap_summaries[graph_output_index],
                            graph_output_rank_promotable_gap_count,
                        )
                        batched_state_weight_gap_summary = rank_gap_weight_summary_after_rank_increase(
                            state_rank_gap_summary,
                            graph_output_rank_promotable_gap_count,
                            output_shape=graph_output_shape,
                            output_rank=graph_output_rank,
                        )
                        if batched_state_weight_gap_summary != empty_weight_gap_summary:
                            subgraph_output_weight_lineage_gap_counts[output_index] = (
                                _bounded_onnx_weight_lineage_gap_count(
                                    subgraph_output_weight_lineage_gap_counts[output_index],
                                    graph_output_rank_promotable_gap_count,
                                )
                            )
                            subgraph_output_weight_lineage_gap_summaries[output_index] = (
                                merge_weight_lineage_gap_summaries(
                                    subgraph_output_weight_lineage_gap_summaries[output_index],
                                    batched_state_weight_gap_summary,
                                )
                            )
                            rank_promotable_gap_promoted = True
                    if rank_promotable_gap_promoted:
                        continue
                    if stacked_scan_output and graph_output_rank_promotable_gap_count:
                        stacked_scan_weight_gap_summary = rank_gap_weight_summary_after_rank_increase(
                            known_weight_gap_summary(
                                graph_output_rank_promotable_lineage_gap_summaries[graph_output_index],
                                graph_output_rank_promotable_gap_count,
                            ),
                            graph_output_rank_promotable_gap_count,
                            output_shape=graph_output_shape,
                            output_rank=graph_output_rank,
                            insert_axis=scan_output_insert_axis,
                        )
                        if stacked_scan_weight_gap_summary != empty_weight_gap_summary:
                            subgraph_output_weight_lineage_gap_counts[output_index] = (
                                _bounded_onnx_weight_lineage_gap_count(
                                    subgraph_output_weight_lineage_gap_counts[output_index],
                                    graph_output_rank_promotable_gap_count,
                                )
                            )
                            subgraph_output_weight_lineage_gap_summaries[output_index] = (
                                merge_weight_lineage_gap_summaries(
                                    subgraph_output_weight_lineage_gap_summaries[output_index],
                                    stacked_scan_weight_gap_summary,
                                )
                            )
                        else:
                            subgraph_output_rank_promotable_lineage_gap_counts[output_index] = (
                                _bounded_onnx_weight_lineage_gap_count(
                                    subgraph_output_rank_promotable_lineage_gap_counts[output_index],
                                    graph_output_rank_promotable_gap_count,
                                )
                            )
                            subgraph_output_rank_promotable_lineage_gap_summaries[output_index] = (
                                merge_weight_lineage_gap_summaries(
                                    subgraph_output_rank_promotable_lineage_gap_summaries[output_index],
                                    known_weight_gap_summary(
                                        graph_output_rank_promotable_lineage_gap_summaries[graph_output_index],
                                        graph_output_rank_promotable_gap_count,
                                    ),
                                )
                            )
                    else:
                        subgraph_output_rank_promotable_lineage_gap_counts[output_index] = (
                            _bounded_onnx_weight_lineage_gap_count(
                                subgraph_output_rank_promotable_lineage_gap_counts[output_index],
                                graph_output_rank_promotable_gap_count,
                            )
                        )
                        subgraph_output_rank_promotable_lineage_gap_summaries[output_index] = (
                            merge_weight_lineage_gap_summaries(
                                subgraph_output_rank_promotable_lineage_gap_summaries[output_index],
                                known_weight_gap_summary(
                                    graph_output_rank_promotable_lineage_gap_summaries[graph_output_index],
                                    graph_output_rank_promotable_gap_count,
                                ),
                            )
                        )

            if (
                standard_control_flow_operator
                and node.op_type == "Loop"
                and loop_may_skip_body(node, constants, graph_input_names)
            ):
                for output_index, parent_input in enumerate(node.input[2 : 2 + len(node.output)]):
                    if not parent_input:
                        continue
                    parent_name = str(parent_input)
                    merge_lineages(
                        subgraph_output_lineages[output_index],
                        value_lineages.get(parent_name, {}),
                        ambiguous_reason="ambiguous_subgraph_output_lineage",
                    )
                    merge_subgraph_output_gap_state(output_index, parent_name)
                    merge_subgraph_output_rank(
                        output_index,
                        known_value_shapes.get(parent_name),
                        known_value_ranks.get(parent_name),
                        parent_name in proven_value_ranks,
                    )
            if (
                standard_control_flow_operator
                and node.op_type == "Scan"
                and scan_may_skip_body(
                    node,
                    constants,
                    graph_input_names,
                    known_value_shapes,
                    trusted_scan_shape_names,
                    untrusted_scan_shape_names,
                    scan_input_axes=resolved_scan_input_axes,
                    scan_input_offset=resolved_scan_input_offset,
                    num_scan_inputs=resolved_scan_input_count,
                )
            ):
                scan_state_input_count = max(
                    len(node.input) - resolved_scan_input_offset - max(resolved_scan_input_count, 0), 0
                )
                state_inputs = node.input[
                    resolved_scan_input_offset : resolved_scan_input_offset
                    + min(scan_state_input_count, len(node.output))
                ]
                for output_index, parent_input in enumerate(state_inputs):
                    if not parent_input:
                        continue
                    parent_name = str(parent_input)
                    merge_lineages(
                        subgraph_output_lineages[output_index],
                        value_lineages.get(parent_name, {}),
                        ambiguous_reason="ambiguous_subgraph_output_lineage",
                    )
                    merge_subgraph_output_gap_state(output_index, parent_name)
                    merge_subgraph_output_rank(
                        output_index,
                        known_value_shapes.get(parent_name),
                        known_value_ranks.get(parent_name),
                        parent_name in proven_value_ranks,
                    )

            if elementwise_output_shape is None and elementwise_output_rank is None and input_names:
                common_output_rank_operator = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and node.op_type in _SHAPE_PRESERVING_UNARY_RANK_OPERATORS
                    and (len(input_names) == 1 or node.op_type in {"Clip", "Dropout"})
                )
                rank_preserving_variadic_operator = (
                    is_registered_standard_operator
                    and not is_model_local_function
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and node.op_type in _RANK_PRESERVING_VARIADIC_OPERATORS
                )
                if common_output_rank_operator:
                    if value_has_unknown_dynamic_rank(input_names[0]):
                        elementwise_has_unknown_dynamic_rank = True
                    else:
                        elementwise_output_shape = known_value_shapes.get(input_names[0])
                        elementwise_output_rank = (
                            len(elementwise_output_shape)
                            if elementwise_output_shape is not None
                            else known_value_ranks.get(input_names[0])
                        )
                        elementwise_output_rank_proven = value_rank_is_proven_or_unknown(input_names[0])
                elif rank_preserving_variadic_operator:
                    elementwise_output_shape = _onnx_concat_output_shape(
                        node,
                        (known_value_shapes.get(input_name) for input_name in input_names),
                        axis=resolved_int_attribute(node, "axis", 0),
                    )
                    elementwise_output_rank_proven = all(
                        value_rank_is_proven_or_unknown(input_name) for input_name in input_names
                    )
                    if elementwise_output_shape is not None:
                        elementwise_output_rank = len(elementwise_output_shape)
                    else:
                        input_ranks = [known_value_ranks.get(input_name) for input_name in input_names]
                        known_ranks = {rank for rank in input_ranks if rank is not None}
                        if len(known_ranks) == 1 and all(rank is not None for rank in input_ranks):
                            elementwise_output_rank = next(iter(known_ranks))

            transform_output_shape: tuple[int, ...] | None = None
            transform_output_rank: int | None = None
            transform_output_rank_proven = True
            clear_transform_output_rank = False
            if supported_transform and input_names:
                transform_input_shape = known_value_shapes.get(input_names[0])
                transform_input_rank = known_value_ranks.get(input_names[0])
                transform_input_rank_proven = value_rank_is_proven_or_unknown(input_names[0])
                if node.op_type in {"Identity", "Cast"}:
                    if value_has_unknown_dynamic_rank(input_names[0]):
                        clear_transform_output_rank = True
                    else:
                        transform_output_shape = transform_input_shape
                        transform_output_rank = (
                            len(transform_output_shape) if transform_output_shape is not None else transform_input_rank
                        )
                        transform_output_rank_proven = transform_input_rank_proven
                elif node.op_type == "Transpose":
                    transform_output_rank_proven = transform_input_rank_proven
                    if transform_input_shape is not None:
                        permutation = resolved_int_sequence_attribute(node, "perm") or tuple(
                            reversed(range(len(transform_input_shape)))
                        )
                        if sorted(permutation) == list(range(len(transform_input_shape))):
                            transform_output_shape = tuple(transform_input_shape[index] for index in permutation)
                            transform_output_rank = len(transform_output_shape)
                    elif transform_input_rank is not None:
                        permutation = resolved_int_sequence_attribute(node, "perm") or tuple(
                            reversed(range(transform_input_rank))
                        )
                        if sorted(permutation) == list(range(transform_input_rank)):
                            transform_output_rank = transform_input_rank
                elif node.op_type == "Flatten" and transform_input_rank is not None:
                    transform_output_rank_proven = transform_input_rank_proven
                    axis = resolved_int_attribute(node, "axis", 1)
                    axis = axis if axis >= 0 else transform_input_rank + axis
                    if 0 <= axis <= transform_input_rank:
                        transform_output_rank = 2
                        if transform_input_shape is not None:
                            transform_output_shape = (
                                flattened_shape_extent(transform_input_shape[:axis]),
                                flattened_shape_extent(transform_input_shape[axis:]),
                            )
                elif node.op_type == "Reshape" and len(input_names) > 1:
                    shape_initializer = constants.get(input_names[1])
                    target_shape = constant_int64_vector_values(shape_initializer)
                    if (
                        target_shape is not None
                        and all(value >= -1 for value in target_shape)
                        and target_shape.count(-1) <= 1
                        and not (
                            bool(resolved_int_attribute(node, "allowzero")) and -1 in target_shape and 0 in target_shape
                        )
                    ):
                        transform_output_rank = len(target_shape)
                        if transform_input_shape is not None and shape_initializer is not None:
                            transform_output_shape = _resolve_onnx_reshape_shape(
                                transform_input_shape,
                                shape_initializer,
                                allowzero=bool(resolved_int_attribute(node, "allowzero")),
                                onnx=onnx,
                            )
                            if transform_output_shape is None:
                                transform_output_rank = None
                elif node.op_type == "Squeeze" and transform_input_rank is not None:
                    transform_output_rank_proven = transform_input_rank_proven
                    axes = _resolve_onnx_axes(node, constants, onnx=onnx, resolve_attribute=resolve_attribute)
                    if axes is not None:
                        if not axes:
                            if squeeze_with_empty_axes_is_noop(node, axes, resolve_attribute):
                                transform_output_shape = transform_input_shape
                                transform_output_rank = (
                                    len(transform_output_shape)
                                    if transform_output_shape is not None
                                    else transform_input_rank
                                )
                            elif transform_input_shape is not None:
                                transform_output_shape = tuple(
                                    dimension for dimension in transform_input_shape if dimension != 1
                                )
                                transform_output_rank = len(transform_output_shape)
                            else:
                                clear_transform_output_rank = True
                        else:
                            normalized_axes = tuple(axis if axis >= 0 else transform_input_rank + axis for axis in axes)
                            if len(set(normalized_axes)) == len(normalized_axes) and all(
                                0 <= axis < transform_input_rank for axis in normalized_axes
                            ):
                                transform_output_rank = transform_input_rank - len(normalized_axes)
                                if transform_input_shape is not None:
                                    squeeze_axes = set(normalized_axes)
                                    transform_output_shape = tuple(
                                        dimension
                                        for index, dimension in enumerate(transform_input_shape)
                                        if index not in squeeze_axes
                                    )
                elif node.op_type == "Unsqueeze" and transform_input_rank is not None:
                    transform_output_rank_proven = transform_input_rank_proven
                    axes = _resolve_onnx_axes(node, constants, onnx=onnx, resolve_attribute=resolve_attribute)
                    if axes is not None:
                        output_rank = transform_input_rank + len(axes)
                        normalized_axes = tuple(axis if axis >= 0 else output_rank + axis for axis in axes)
                        if (
                            normalized_axes
                            and len(set(normalized_axes)) == len(normalized_axes)
                            and all(0 <= axis < output_rank for axis in normalized_axes)
                        ):
                            transform_output_rank = output_rank
                            if transform_input_shape is not None:
                                source_dimensions = iter(transform_input_shape)
                                transform_output_shape = tuple(
                                    1 if index in normalized_axes else next(source_dimensions)
                                    for index in range(output_rank)
                                )

            for output_index, output_name in enumerate(node.output):
                if not output_name:
                    continue
                name = str(output_name)
                inferred_output_shape = None
                inferred_output_rank = None
                inferred_output_rank_proven = True
                if output_index == 0 or (node.op_type == "Dropout" and output_index == 1):
                    inferred_output_shape = (
                        elementwise_output_shape if elementwise_output_shape is not None else transform_output_shape
                    )
                    if elementwise_output_rank is not None:
                        inferred_output_rank = elementwise_output_rank
                        inferred_output_rank_proven = elementwise_output_rank_proven
                    else:
                        inferred_output_rank = transform_output_rank
                        inferred_output_rank_proven = transform_output_rank_proven
                if output_index < len(subgraph_output_shapes):
                    subgraph_output_shape = subgraph_output_shapes[output_index]
                    if subgraph_output_shape is not None:
                        inferred_output_shape = subgraph_output_shape
                        inferred_output_rank = len(subgraph_output_shape)
                        inferred_output_rank_proven = subgraph_output_proven_ranks[output_index]
                    elif subgraph_output_ranks[output_index] is not None and inferred_output_shape is None:
                        inferred_output_rank = subgraph_output_ranks[output_index]
                        inferred_output_rank_proven = subgraph_output_proven_ranks[output_index]
                    elif subgraph_output_rank_unknown[output_index]:
                        inferred_output_shape = None
                        inferred_output_rank = None
                subgraph_clears_output_rank = (
                    output_index < len(subgraph_output_rank_unknown) and subgraph_output_rank_unknown[output_index]
                )
                elementwise_clears_output_rank = elementwise_has_unknown_dynamic_rank and output_index == 0
                clear_output_rank = (
                    (
                        (clear_transform_output_rank and output_index == 0)
                        or subgraph_clears_output_rank
                        or elementwise_clears_output_rank
                    )
                    and inferred_output_shape is None
                    and inferred_output_rank is None
                )
                per_output_lineages = dict(output_lineages)
                if (
                    recurrent_state_lineages
                    and is_registered_standard_operator
                    and not is_model_local_function
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and node.op_type in _RECURRENT_WEIGHT_OPERATORS
                ):
                    for initializer_index in recurrent_state_lineages:
                        per_output_lineages.pop(initializer_index, None)
                    if output_index == 0:
                        state_lineages = {
                            initializer_index: _OnnxWeightLineage(
                                initializer_index=initializer_index,
                                shape=lineage.shape,
                                data_type=lineage.data_type,
                                transforms=lineage.transforms,
                                unresolved_reason="recurrent_sequence_state_lineage",
                            )
                            for initializer_index, lineage in recurrent_state_lineages.items()
                        }
                    else:
                        state_lineages = {
                            initializer_index: _OnnxWeightLineage(
                                initializer_index=initializer_index,
                                shape=lineage.shape,
                                data_type=lineage.data_type,
                                transforms=append_transform_marker(
                                    lineage.transforms,
                                    _OnnxWeightTransform("recurrent_state_output"),
                                ),
                                unresolved_reason=(
                                    lineage.unresolved_reason
                                    if lineage.unresolved_reason is not None
                                    else "recurrent_state_lineage"
                                ),
                            )
                            for initializer_index, lineage in recurrent_state_lineages.items()
                        }
                    merge_lineages(
                        per_output_lineages,
                        state_lineages,
                        ambiguous_reason="ambiguous_operator_input_lineage",
                    )
                merge_lineages(
                    per_output_lineages,
                    constant_output_lineages.get(name, {}),
                    ambiguous_reason="ambiguous_constant_output_lineage",
                )
                merge_lineages(
                    per_output_lineages,
                    subgraph_output_lineages[output_index],
                    ambiguous_reason="ambiguous_subgraph_output_lineage",
                )
                if subgraph_output_dynamic[output_index] and per_output_lineages:
                    per_output_lineages = {
                        initializer_index: _OnnxWeightLineage(
                            initializer_index=initializer_index,
                            shape=None,
                            data_type=None,
                            transforms=lineage.transforms,
                            unresolved_reason=lineage.unresolved_reason or "dynamic_subgraph_output_lineage",
                        )
                        for initializer_index, lineage in per_output_lineages.items()
                    }
                (
                    per_output_lineages,
                    per_output_lineage_limit_gap_count,
                    per_output_non_shape_lineage_limit_gap_count,
                    per_output_non_shape_lineage_gap_summary,
                    per_output_weight_lineage_limit_gap_count,
                    per_output_rank_promotable_lineage_limit_gap_count,
                    per_output_weight_lineage_gap_summary,
                    per_output_rank_promotable_lineage_gap_summary,
                ) = bounded_lineages(per_output_lineages)
                if per_output_lineages:
                    value_lineages[name] = per_output_lineages
                    input_lineage_limit_gap_count_for_output = (
                        0 if subgraph_results else all_input_lineage_limit_gap_count
                    )
                    input_weight_lineage_limit_gap_count_for_output = (
                        0
                        if subgraph_results
                        or transform_output_demotes_weight_gap
                        or cast_output_is_nonfloating_transform
                        else all_input_output_weight_lineage_limit_gap_count
                    )
                    input_weight_lineage_gap_summary_for_output = (
                        empty_weight_gap_summary
                        if input_weight_lineage_limit_gap_count_for_output == 0
                        else transformed_input_output_weight_lineage_gap_summary
                    )
                    input_non_shape_lineage_limit_gap_count_for_output = (
                        0 if subgraph_results else all_input_non_shape_lineage_limit_gap_count
                    )
                    input_non_shape_lineage_gap_summary_for_output = (
                        empty_weight_gap_summary
                        if input_non_shape_lineage_limit_gap_count_for_output == 0
                        else transformed_input_output_non_shape_lineage_gap_summary
                    )
                    input_rank_promotable_lineage_limit_gap_count_for_output = (
                        0
                        if subgraph_results
                        or rank_operator_promotes_deferred_gap
                        or cast_output_is_nonfloating_transform
                        else all_input_output_rank_promotable_lineage_limit_gap_count
                    )
                    if transform_output_demotes_weight_gap:
                        input_rank_promotable_lineage_limit_gap_count_for_output = (
                            _bounded_onnx_weight_lineage_gap_count(
                                input_rank_promotable_lineage_limit_gap_count_for_output,
                                all_input_output_weight_lineage_limit_gap_count,
                            )
                        )
                        input_rank_promotable_lineage_gap_summary_for_output = merge_weight_lineage_gap_summaries(
                            transformed_input_output_rank_promotable_lineage_gap_summary,
                            transformed_input_output_weight_lineage_gap_summary,
                        )
                    else:
                        input_rank_promotable_lineage_gap_summary_for_output = (
                            empty_weight_gap_summary
                            if input_rank_promotable_lineage_limit_gap_count_for_output == 0
                            else transformed_input_output_rank_promotable_lineage_gap_summary
                        )
                    propagated_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        input_lineage_limit_gap_count_for_output,
                        output_lineage_limit_gap_count,
                        per_output_lineage_limit_gap_count,
                        subgraph_output_lineage_gap_counts[output_index],
                    )
                    propagated_non_shape_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        input_non_shape_lineage_limit_gap_count_for_output,
                        output_non_shape_lineage_limit_gap_count,
                        per_output_non_shape_lineage_limit_gap_count,
                        subgraph_output_non_shape_lineage_gap_counts[output_index],
                    )
                    propagated_non_shape_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        known_weight_gap_summary(
                            input_non_shape_lineage_gap_summary_for_output,
                            input_non_shape_lineage_limit_gap_count_for_output,
                        ),
                        known_weight_gap_summary(
                            output_non_shape_lineage_gap_summary,
                            output_non_shape_lineage_limit_gap_count,
                        ),
                        known_weight_gap_summary(
                            per_output_non_shape_lineage_gap_summary,
                            per_output_non_shape_lineage_limit_gap_count,
                        ),
                        known_weight_gap_summary(
                            subgraph_output_non_shape_lineage_gap_summaries[output_index],
                            subgraph_output_non_shape_lineage_gap_counts[output_index],
                        ),
                    )
                    propagated_weight_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        input_weight_lineage_limit_gap_count_for_output,
                        output_weight_lineage_limit_gap_count,
                        per_output_weight_lineage_limit_gap_count,
                        subgraph_output_weight_lineage_gap_counts[output_index],
                    )
                    propagated_weight_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        known_weight_gap_summary(
                            input_weight_lineage_gap_summary_for_output,
                            input_weight_lineage_limit_gap_count_for_output,
                        ),
                        known_weight_gap_summary(
                            output_weight_lineage_gap_summary,
                            output_weight_lineage_limit_gap_count,
                        ),
                        known_weight_gap_summary(
                            per_output_weight_lineage_gap_summary,
                            per_output_weight_lineage_limit_gap_count,
                        ),
                        known_weight_gap_summary(
                            subgraph_output_weight_lineage_gap_summaries[output_index],
                            subgraph_output_weight_lineage_gap_counts[output_index],
                        ),
                    )
                    propagated_rank_promotable_lineage_limit_gap_count = _bounded_onnx_weight_lineage_gap_count(
                        input_rank_promotable_lineage_limit_gap_count_for_output,
                        output_rank_promotable_lineage_limit_gap_count,
                        per_output_rank_promotable_lineage_limit_gap_count,
                        subgraph_output_rank_promotable_lineage_gap_counts[output_index],
                    )
                    propagated_rank_promotable_lineage_gap_summary = merge_weight_lineage_gap_summaries(
                        known_weight_gap_summary(
                            input_rank_promotable_lineage_gap_summary_for_output,
                            input_rank_promotable_lineage_limit_gap_count_for_output,
                        ),
                        known_weight_gap_summary(
                            output_rank_promotable_lineage_gap_summary,
                            output_rank_promotable_lineage_limit_gap_count,
                        ),
                        known_weight_gap_summary(
                            per_output_rank_promotable_lineage_gap_summary,
                            per_output_rank_promotable_lineage_limit_gap_count,
                        ),
                        known_weight_gap_summary(
                            subgraph_output_rank_promotable_lineage_gap_summaries[output_index],
                            subgraph_output_rank_promotable_lineage_gap_counts[output_index],
                        ),
                    )
                    if propagated_lineage_limit_gap_count:
                        value_lineage_limit_gap_counts[name] = propagated_lineage_limit_gap_count
                    else:
                        value_lineage_limit_gap_counts.pop(name, None)
                    if propagated_non_shape_lineage_limit_gap_count:
                        value_non_shape_lineage_limit_gap_counts[name] = propagated_non_shape_lineage_limit_gap_count
                        value_non_shape_lineage_limit_gap_summaries[name] = propagated_non_shape_lineage_gap_summary
                    else:
                        value_non_shape_lineage_limit_gap_counts.pop(name, None)
                        value_non_shape_lineage_limit_gap_summaries.pop(name, None)
                    if propagated_weight_lineage_limit_gap_count:
                        value_weight_lineage_limit_gap_counts[name] = propagated_weight_lineage_limit_gap_count
                        value_weight_lineage_limit_gap_summaries[name] = propagated_weight_lineage_gap_summary
                    else:
                        value_weight_lineage_limit_gap_counts.pop(name, None)
                        value_weight_lineage_limit_gap_summaries.pop(name, None)
                    if propagated_rank_promotable_lineage_limit_gap_count:
                        value_rank_promotable_lineage_limit_gap_counts[name] = (
                            propagated_rank_promotable_lineage_limit_gap_count
                        )
                        value_rank_promotable_lineage_limit_gap_summaries[name] = (
                            propagated_rank_promotable_lineage_gap_summary
                        )
                    else:
                        value_rank_promotable_lineage_limit_gap_counts.pop(name, None)
                        value_rank_promotable_lineage_limit_gap_summaries.pop(name, None)
                    lineage_shapes = {lineage.shape for lineage in per_output_lineages.values()}
                    if inferred_output_shape is not None:
                        set_known_value_shape(name, inferred_output_shape, proven=inferred_output_rank_proven)
                    elif inferred_output_rank is not None:
                        set_known_value_rank(name, inferred_output_rank, proven=inferred_output_rank_proven)
                    elif clear_output_rank:
                        clear_known_value_rank(name)
                    elif len(lineage_shapes) == 1 and None not in lineage_shapes:
                        set_known_value_shape(name, next(iter(lineage_shapes)), proven=True)  # type: ignore[arg-type]
                else:
                    value_lineages.pop(name, None)
                    value_lineage_limit_gap_counts.pop(name, None)
                    value_non_shape_lineage_limit_gap_counts.pop(name, None)
                    value_non_shape_lineage_limit_gap_summaries.pop(name, None)
                    value_weight_lineage_limit_gap_counts.pop(name, None)
                    value_weight_lineage_limit_gap_summaries.pop(name, None)
                    value_rank_promotable_lineage_limit_gap_counts.pop(name, None)
                    value_rank_promotable_lineage_limit_gap_summaries.pop(name, None)
                    if name in constants and name not in graph_input_names:
                        with suppress(AttributeError, TypeError, ValueError):
                            set_known_value_shape(
                                name,
                                tuple(int(dimension) for dimension in constants[name].dims),
                                proven=True,
                            )
                    if inferred_output_shape is not None:
                        set_known_value_shape(name, inferred_output_shape, proven=inferred_output_rank_proven)
                    elif inferred_output_rank is not None:
                        set_known_value_rank(name, inferred_output_rank, proven=inferred_output_rank_proven)
                    elif clear_output_rank:
                        clear_known_value_rank(name)

                mapped_subgraph_output = bool(subgraph_results) and output_index < len(subgraph_output_dynamic)
                output_is_dynamic = (
                    subgraph_output_dynamic[output_index]
                    if mapped_subgraph_output and per_output_lineages
                    else has_dynamic_input or (not per_output_lineages and name not in constant_output_names)
                )
                if output_is_dynamic:
                    dynamic_values.add(name)
                else:
                    dynamic_values.discard(name)

        if captured_state is not None:
            captured_state[0].clear()
            captured_state[0].update(value_lineages)
            captured_state[1].clear()
            captured_state[1].update(constants)
            captured_state[2].clear()
            captured_state[2].update(dynamic_values)
            captured_state[3].clear()
            captured_state[3].update(value_lineage_limit_gap_counts)
            captured_state[4].clear()
            captured_state[4].update(value_non_shape_lineage_limit_gap_counts)
            captured_state[5].clear()
            captured_state[5].update(value_non_shape_lineage_limit_gap_summaries)
            captured_state[6].clear()
            captured_state[6].update(value_weight_lineage_limit_gap_counts)
            captured_state[7].clear()
            captured_state[7].update(value_weight_lineage_limit_gap_summaries)
            captured_state[8].clear()
            captured_state[8].update(value_rank_promotable_lineage_limit_gap_counts)
            captured_state[9].clear()
            captured_state[9].update(value_rank_promotable_lineage_limit_gap_summaries)

        output_names = [_onnx_value_name(graph_output) for graph_output in current_graph.output]
        return (
            [dict(value_lineages.get(output_name, {})) for output_name in output_names],
            [output_name in dynamic_values for output_name in output_names],
            [value_lineage_limit_gap_counts.get(output_name, 0) for output_name in output_names],
            [value_non_shape_lineage_limit_gap_counts.get(output_name, 0) for output_name in output_names],
            [
                known_weight_gap_summary(
                    value_non_shape_lineage_limit_gap_summaries.get(output_name),
                    value_non_shape_lineage_limit_gap_counts.get(output_name, 0),
                )
                for output_name in output_names
            ],
            [value_weight_lineage_limit_gap_counts.get(output_name, 0) for output_name in output_names],
            [
                known_weight_gap_summary(
                    value_weight_lineage_limit_gap_summaries.get(output_name),
                    value_weight_lineage_limit_gap_counts.get(output_name, 0),
                )
                for output_name in output_names
            ],
            [value_rank_promotable_lineage_limit_gap_counts.get(output_name, 0) for output_name in output_names],
            [
                known_weight_gap_summary(
                    value_rank_promotable_lineage_limit_gap_summaries.get(output_name),
                    value_rank_promotable_lineage_limit_gap_counts.get(output_name, 0),
                )
                for output_name in output_names
            ],
            [known_value_shapes.get(output_name) for output_name in output_names],
            [
                len(known_value_shapes[output_name])
                if output_name in known_value_shapes
                else known_value_ranks.get(output_name)
                for output_name in output_names
            ],
            [output_name in proven_value_ranks for output_name in output_names],
        )

    root_state_lineages: dict[str, dict[int, _OnnxWeightLineage]] = {}
    root_state_constants: dict[str, Any] = {}
    root_state_dynamic: set[str] = set()
    root_state_lineage_limit_gap_counts: dict[str, int] = {}
    root_state_non_shape_lineage_limit_gap_counts: dict[str, int] = {}
    root_state_non_shape_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
    root_state_weight_lineage_limit_gap_counts: dict[str, int] = {}
    root_state_weight_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
    root_state_rank_promotable_lineage_limit_gap_counts: dict[str, int] = {}
    root_state_rank_promotable_lineage_limit_gap_summaries: dict[str, _OnnxWeightLineageGapSummary] = {}
    (
        root_output_lineages,
        _root_output_dynamic,
        _root_output_lineage_gaps,
        _root_output_non_shape_lineage_gaps,
        _root_output_non_shape_lineage_gap_summaries,
        _root_output_weight_lineage_gaps,
        _root_output_weight_lineage_gap_summaries,
        _root_output_rank_promotable_lineage_gaps,
        _root_output_rank_promotable_lineage_gap_summaries,
        _root_output_shapes,
        _root_output_ranks,
        _root_output_proven_ranks,
    ) = walk_graph(
        graph,
        {},
        {},
        set(),
        root_graph=True,
        source_scope=("root_graph",),
        opset_versions=model_opset_versions,
        captured_state=(
            root_state_lineages,
            root_state_constants,
            root_state_dynamic,
            root_state_lineage_limit_gap_counts,
            root_state_non_shape_lineage_limit_gap_counts,
            root_state_non_shape_lineage_limit_gap_summaries,
            root_state_weight_lineage_limit_gap_counts,
            root_state_weight_lineage_limit_gap_summaries,
            root_state_rank_promotable_lineage_limit_gap_counts,
            root_state_rank_promotable_lineage_limit_gap_summaries,
        ),
    )

    main_initializer_lineages: dict[str, dict[int, _OnnxWeightLineage]] = {}
    for initializer_position, initializer in enumerate(getattr(graph, "initializer", ())):
        source_key = ("root_graph", "initializer", initializer_position)
        initializer_index = initializer_source_indexes.get(source_key)
        if initializer_index is None or not initializer.name:
            continue
        name = str(initializer.name)
        main_initializer_lineages[name] = {
            initializer_index: _OnnxWeightLineage(
                initializer_index=initializer_index,
                shape=tuple(int(dimension) for dimension in initializer.dims),
                data_type=int(initializer.data_type),
            )
        }
    for sparse_position, sparse_initializer in enumerate(getattr(graph, "sparse_initializer", ())):
        source_key = ("root_graph", "sparse_initializer", sparse_position)
        initializer_index = initializer_source_indexes.get(source_key)
        if initializer_index is None or not sparse_initializer.values.name:
            continue
        name = str(sparse_initializer.values.name)
        main_initializer_lineages[name] = {
            initializer_index: _OnnxWeightLineage(
                initializer_index=initializer_index,
                shape=tuple(int(dimension) for dimension in sparse_initializer.dims),
                data_type=int(sparse_initializer.values.data_type),
                unresolved_reason="sparse_initializer_unsupported",
            )
        }

    root_output_lineages_by_name = {
        _onnx_value_name(graph_output): lineages
        for graph_output, lineages in zip(graph.output, root_output_lineages, strict=False)
    }
    training_graph_results: dict[
        tuple[Any, ...],
        tuple[
            Any,
            list[dict[int, _OnnxWeightLineage]],
            list[bool],
            list[int],
            list[int],
            list[_OnnxWeightLineageGapSummary],
            list[int],
            list[_OnnxWeightLineageGapSummary],
            list[int],
            list[_OnnxWeightLineageGapSummary],
            list[tuple[int, ...] | None],
            list[int | None],
            list[bool],
        ],
    ] = {}
    algorithm_initializer_lineages: dict[int, dict[str, dict[int, _OnnxWeightLineage]]] = {}
    for source_scope, training_graph in analysis_graph_roots[1:]:
        is_algorithm = source_scope[2] == "algorithm"
        (
            output_lineages,
            output_dynamic,
            output_lineage_gaps,
            output_non_shape_lineage_gaps,
            output_non_shape_lineage_gap_summaries,
            output_weight_lineage_gaps,
            output_weight_lineage_gap_summaries,
            output_rank_promotable_lineage_gaps,
            output_rank_promotable_lineage_gap_summaries,
            output_shapes,
            output_ranks,
            output_proven_ranks,
        ) = walk_graph(
            training_graph,
            root_state_lineages if is_algorithm else {},
            root_state_constants if is_algorithm else {},
            root_state_dynamic if is_algorithm else set(),
            inherited_lineage_limit_gap_counts=root_state_lineage_limit_gap_counts if is_algorithm else {},
            inherited_non_shape_lineage_limit_gap_counts=(
                root_state_non_shape_lineage_limit_gap_counts if is_algorithm else {}
            ),
            inherited_non_shape_lineage_limit_gap_summaries=(
                root_state_non_shape_lineage_limit_gap_summaries if is_algorithm else {}
            ),
            inherited_weight_lineage_limit_gap_counts=(
                root_state_weight_lineage_limit_gap_counts if is_algorithm else {}
            ),
            inherited_weight_lineage_limit_gap_summaries=(
                root_state_weight_lineage_limit_gap_summaries if is_algorithm else {}
            ),
            inherited_rank_promotable_lineage_limit_gap_counts=(
                root_state_rank_promotable_lineage_limit_gap_counts if is_algorithm else {}
            ),
            inherited_rank_promotable_lineage_limit_gap_summaries=(
                root_state_rank_promotable_lineage_limit_gap_summaries if is_algorithm else {}
            ),
            root_graph=True,
            source_scope=source_scope,
            opset_versions=model_opset_versions,
            fail_on_unbound_inputs=True,
        )
        training_graph_results[source_scope] = (
            training_graph,
            output_lineages,
            output_dynamic,
            output_lineage_gaps,
            output_non_shape_lineage_gaps,
            output_non_shape_lineage_gap_summaries,
            output_weight_lineage_gaps,
            output_weight_lineage_gap_summaries,
            output_rank_promotable_lineage_gaps,
            output_rank_promotable_lineage_gap_summaries,
            output_shapes,
            output_ranks,
            output_proven_ranks,
        )
        if not is_algorithm:
            continue
        training_index = int(source_scope[1])
        local_initializers: dict[str, dict[int, _OnnxWeightLineage]] = {}
        for initializer_position, initializer in enumerate(getattr(training_graph, "initializer", ())):
            source_key = (*source_scope, "initializer", initializer_position)
            initializer_index = initializer_source_indexes.get(source_key)
            if initializer_index is None or not initializer.name:
                continue
            lineage = _OnnxWeightLineage(
                initializer_index=initializer_index,
                shape=tuple(int(dimension) for dimension in initializer.dims),
                data_type=int(initializer.data_type),
            )
            local_initializers[str(initializer.name)] = {initializer_index: lineage}
        for sparse_position, sparse_initializer in enumerate(getattr(training_graph, "sparse_initializer", ())):
            source_key = (*source_scope, "sparse_initializer", sparse_position)
            initializer_index = initializer_source_indexes.get(source_key)
            if initializer_index is None or not sparse_initializer.values.name:
                continue
            lineage = _OnnxWeightLineage(
                initializer_index=initializer_index,
                shape=tuple(int(dimension) for dimension in sparse_initializer.dims),
                data_type=int(sparse_initializer.values.data_type),
                unresolved_reason="sparse_initializer_unsupported",
            )
            local_initializers[str(sparse_initializer.values.name)] = {initializer_index: lineage}
        algorithm_initializer_lineages[training_index] = local_initializers

    for training_index, training_info in enumerate(training_infos):
        for binding_kind, graph_field, bindings in (
            ("initialization", "initialization", training_info.initialization_binding),
            ("update", "algorithm", training_info.update_binding),
        ):
            source_scope = ("training_info", training_index, graph_field)
            graph_result = training_graph_results.get(source_scope)
            output_lineages_by_name: dict[str, dict[int, _OnnxWeightLineage]] = {}
            if graph_result is not None:
                (
                    training_graph,
                    output_lineages,
                    _output_dynamic,
                    _output_lineage_gaps,
                    _output_non_shape_lineage_gaps,
                    _output_non_shape_lineage_gap_summaries,
                    _output_weight_lineage_gaps,
                    _output_weight_lineage_gap_summaries,
                    _output_rank_promotable_lineage_gaps,
                    _output_rank_promotable_lineage_gap_summaries,
                    _output_shapes,
                    _output_ranks,
                    _output_proven_ranks,
                ) = graph_result
                output_lineages_by_name = {
                    _onnx_value_name(graph_output): lineages
                    for graph_output, lineages in zip(training_graph.output, output_lineages, strict=False)
                }
            target_lineages_by_name = dict(main_initializer_lineages)
            target_lineages_by_name.update(algorithm_initializer_lineages.get(training_index, {}))
            for binding in bindings:
                state_name = str(binding.key)
                source_name = str(binding.value)
                source_lineages = output_lineages_by_name.get(source_name, {})
                if binding_kind == "update" and not source_lineages:
                    source_lineages = root_output_lineages_by_name.get(source_name, {})
                target_lineages = target_lineages_by_name.get(state_name, {})
                if not target_lineages:
                    plan.record_coverage_gap("unresolved_training_binding")
                target_has_weight_role = any(
                    lineage_could_be_weight(lineage)
                    or initializer_index in eligible_initializer_indexes
                    or bool(groups[initializer_index])
                    for initializer_index, lineage in target_lineages.items()
                )
                consumed_lineages = dict(target_lineages)
                consumed_lineages.update(source_lineages)
                for initializer_index, _lineage in consumed_lineages.items():
                    terminal_consumer_counts[initializer_index] += 1
                    total_consumer_count += 1
                gap_lineages = (
                    source_lineages
                    if target_has_weight_role and source_lineages
                    else {
                        initializer_index: lineage
                        for initializer_index, lineage in source_lineages.items()
                        if lineage_could_be_weight(lineage)
                    }
                )
                if target_has_weight_role and not source_lineages:
                    gap_lineages = target_lineages
                if gap_lineages:
                    for lineage in gap_lineages.values():
                        record_training_binding_gap(
                            lineage,
                            binding_kind=binding_kind,
                            state_name=state_name,
                        )
                else:
                    for initializer_index in consumed_lineages:
                        record_exclusion(initializer_index, "non_weight_training_binding")

    for initializer_index, _initializer in enumerate(initializers):
        if terminal_consumer_counts[initializer_index] == 0 and not groups[initializer_index]:
            reason = (
                "unconsumed_transformed_initializer" if transform_counts[initializer_index] else "unused_initializer"
            )
            record_exclusion(initializer_index, reason)

    analyzed_initializer_indexes: set[int] = set()
    eligible_metadata: list[dict[str, Any]] = []
    analysis_id = 0
    for initializer_index in sorted(eligible_initializer_indexes):
        initializer = initializers[initializer_index]
        initializer_groups = groups[initializer_index]
        if not initializer_groups:
            continue
        if _onnx_tensor_uses_external_storage(initializer, onnx=onnx):
            plan.external_initializers_skipped += 1
            continue

        try:
            numel = math.prod(int(dimension) for dimension in initializer.dims)
            itemsize = int(_tensor_data_type_to_np_dtype(initializer.data_type).itemsize)
            estimated_bytes = numel * itemsize
            if estimated_bytes < 0 or (
                max_array_size is not None and max_array_size > 0 and estimated_bytes > max_array_size
            ):
                plan.oversized_initializers_skipped += 1
                continue
            bounded_name, _, _ = _bounded_onnx_metadata_text(plan, initializer.name)
            if pre_materialization_check is not None and not pre_materialization_check(
                initializer,
                bounded_name,
                estimated_bytes,
            ):
                plan.oversized_initializers_skipped += 1
                continue

            array = onnx.numpy_helper.to_array(initializer)
            if retain_array_check is not None and not retain_array_check(bounded_name, int(array.nbytes)):
                plan.oversized_initializers_skipped += 1
                continue

            transformed_views: dict[tuple[_OnnxWeightTransform, ...], Any] = {(): array}
            for consumer_group in initializer_groups.values():
                transformed = transformed_views.get(consumer_group.lineage.transforms)
                if transformed is None:
                    transformed = array
                    for transform in consumer_group.lineage.transforms:
                        if transform.kind == "Identity":
                            continue
                        if transform.kind == "Transpose":
                            transformed = np.transpose(transformed, axes=transform.parameters)
                        elif transform.kind == "Reshape":
                            transformed = np.reshape(transformed, transform.parameters)
                        if transformed.size and not np.shares_memory(array, transformed):
                            raise RuntimeError("ONNX weight lineage transform requires a full-tensor copy")
                    transformed_views[consumer_group.lineage.transforms] = transformed

                output_axes = consumer_group.output_axes
                tensor_weights = transformed
                conceptual_output_axes = output_axes
                if consumer_group.node.op_type == "ConvTranspose":
                    group_value = consumer_group.group
                    if group_value <= 0 or int(transformed.shape[0]) % group_value != 0:
                        raise ValueError("ConvTranspose initializer has an incompatible group")
                    tensor_weights = transformed.reshape(
                        group_value,
                        int(transformed.shape[0]) // group_value,
                        *transformed.shape[1:],
                    )
                    conceptual_output_axes = (0, 2)
                if tensor_weights.size and not np.shares_memory(array, tensor_weights):
                    raise RuntimeError("ONNX weight analysis requires a full-tensor copy")

                matrix_analysis = consumer_group.analysis_kind == "matrix"
                analysis_weights = tensor_weights
                if matrix_analysis:
                    if len(output_axes) != 1 or transformed.ndim != 2:
                        raise ValueError("Matrix weight analysis requires exactly one output axis")
                    analysis_weights = np.moveaxis(transformed, output_axes[0], -1)
                    conceptual_output_axes = (analysis_weights.ndim - 1,)
                input_axes = tuple(axis for axis in range(analysis_weights.ndim) if axis not in conceptual_output_axes)
                analysis_shape = [
                    math.prod(int(analysis_weights.shape[axis]) for axis in input_axes),
                    math.prod(int(analysis_weights.shape[axis]) for axis in conceptual_output_axes),
                ]
                first_consumer = consumer_group.consumers[0]
                context = {
                    "analysis_id": analysis_id,
                    **_bounded_onnx_metadata_fields(plan, "initializer", initializer.name),
                    "initializer_graph_index": initializer_graph_indexes[initializer_index],
                    "consumer_op": first_consumer["op"],
                    "consumer_op_length": first_consumer["op_length"],
                    "consumer_op_truncated": first_consumer["op_truncated"],
                    "consumer_node": first_consumer["node"],
                    "consumer_node_length": first_consumer["node_length"],
                    "consumer_node_truncated": first_consumer["node_truncated"],
                    "consumer_node_index": consumer_group.node_index,
                    "consumer_input_index": consumer_group.input_index,
                    "output_axis": output_axes[-1],
                    **_bounded_onnx_integer_sequence("output_axes", output_axes),
                    "analysis_kind": consumer_group.analysis_kind,
                    "group": consumer_group.group,
                    **_bounded_onnx_integer_sequence("stored_shape", initializer.dims),
                    **_bounded_onnx_integer_sequence("transformed_shape", transformed.shape),
                    "analysis_shape": analysis_shape,
                    **_bounded_onnx_integer_sequence("conceptual_output_axes", conceptual_output_axes),
                    "analysis_storage_shares_memory": bool(
                        array.size == 0 or np.shares_memory(array, analysis_weights)
                    ),
                    "analysis_materialization": "zero_copy_view_chunked_reduction",
                    "lineage": [transform.kind for transform in consumer_group.lineage.transforms],
                    "lineage_transform_count": len(consumer_group.lineage.transforms),
                    "consumer_count": consumer_group.consumer_count,
                    "consumers": consumer_group.consumers,
                    "consumers_truncated": consumer_group.consumer_count > len(consumer_group.consumers),
                }
                plan.specs.append(
                    _OnnxWeightAnalysisSpec(
                        initializer_index=initializer_index,
                        analysis_id=analysis_id,
                        weights=analysis_weights,
                        output_axes=conceptual_output_axes,
                        matrix_analysis=matrix_analysis,
                        context=context,
                    ),
                )
                analysis_id += 1
                analyzed_initializer_indexes.add(initializer_index)
                if len(eligible_metadata) < _ONNX_WEIGHT_METADATA_SAMPLE_LIMIT:
                    eligible_metadata.append(context)
        except Exception as exc:
            plan.extraction_failures += 1
            bounded_name, _, _ = _bounded_onnx_metadata_text(plan, initializer.name)
            logger.warning(
                "Failed to prepare ONNX initializer '%s' for distribution analysis (%s)",
                bounded_name,
                type(exc).__name__,
            )

    plan.eligible_initializer_count = len(eligible_initializer_indexes)
    plan.analyzed_initializer_count = len(analyzed_initializer_indexes)
    plan.metadata = {
        "eligible_initializer_count": plan.eligible_initializer_count,
        "analyzed_layer_count": len(plan.specs),
        "eligible": eligible_metadata,
        "eligible_metadata_truncated": len(plan.specs) > len(eligible_metadata),
        "exclusion_counts": plan.exclusion_counts,
        "exclusion_samples": plan.exclusion_samples,
        "exclusion_metadata_truncated": sum(plan.exclusion_counts.values()) > len(plan.exclusion_samples),
        "consumer_count": total_consumer_count,
        "consumer_metadata_sample_count": consumer_sample_count,
        "consumer_metadata_truncated": total_consumer_count > consumer_sample_count,
        "unresolved_lineage_samples": plan.unresolved_lineage_samples,
        "unresolved_lineage_metadata_truncated": plan.coverage_gaps.get("unresolved_initializer_lineage", 0)
        > len(plan.unresolved_lineage_samples),
        "coverage_gaps": dict(plan.coverage_gaps),
        "metadata_string_truncation_count": plan.string_truncation_count,
        "metadata_strings_truncated": plan.string_truncation_count > 0,
        "initializer_name_validation": {
            "empty_name_count": 0,
            "duplicate_name_count": 0,
            "samples": [],
            "samples_truncated": False,
        },
    }
    return plan


def _parse_external_data_extent(info: dict[str, str], key: str) -> int | None:
    """Parse an optional non-negative integer from external_data metadata."""
    value = info.get(key)
    if value is None:
        return None

    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{key} must be non-negative, got {parsed}")
    return parsed


class _OnnxStructureParseError(ValueError):
    """Raised when bounded ONNX structural parsing cannot safely continue."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _is_onnx_structure_safety_budget_reason(reason: str) -> bool:
    """Return whether a parser failure is an implementation resource bound."""
    return reason.endswith(("_limit_exceeded", "_budget_exceeded"))


class _OnnxOmittedBytes:
    """Length-only stand-in for ONNX tensor payload bytes skipped from disk."""

    def __init__(self, length: int):
        self._length = max(int(length), 0)

    def __len__(self) -> int:
        return self._length


class _OnnxLengthOnlySequence:
    """Sequence facade used when only a tensor-data count and byte total are needed."""

    def __init__(self, count: int, total_bytes: int = 0):
        self._count = max(int(count), 0)
        self._total_bytes = max(int(total_bytes), 0)

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Any:
        if self._total_bytes <= 0:
            return iter(())
        return iter((_OnnxOmittedBytes(self._total_bytes),))


_ONNX_MESSAGE_CLASS_BY_FULL_NAME: dict[str, str] = {
    "onnx.StringStringEntryProto": "StringStringEntryProto",
    "onnx.TensorProto": "TensorProto",
    "onnx.SparseTensorProto": "SparseTensorProto",
    "onnx.AttributeProto": "AttributeProto",
    "onnx.NodeProto": "NodeProto",
    "onnx.ValueInfoProto": "ValueInfoProto",
    "onnx.GraphProto": "GraphProto",
    "onnx.OperatorSetIdProto": "OperatorSetIdProto",
    "onnx.FunctionProto": "FunctionProto",
    "onnx.TrainingInfoProto": "TrainingInfoProto",
    "onnx.ModelProto": "ModelProto",
}
_FALLBACK_ONNX_KNOWN_FIELD_NUMBERS: dict[str, frozenset[int]] = {
    "onnx.StringStringEntryProto": frozenset({1, 2}),
    "onnx.TensorProto": frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16}),
    "onnx.SparseTensorProto": frozenset({1, 2, 3}),
    "onnx.AttributeProto": frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 20, 21, 22, 23}),
    "onnx.NodeProto": frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
    "onnx.ValueInfoProto": frozenset({1, 2, 3, 4}),
    "onnx.GraphProto": frozenset({1, 2, 5, 10, 11, 12, 13, 14, 15, 16}),
    "onnx.OperatorSetIdProto": frozenset({1, 2}),
    "onnx.FunctionProto": frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}),
    "onnx.TrainingInfoProto": frozenset({1, 2, 3, 4}),
    "onnx.ModelProto": frozenset({1, 2, 3, 4, 5, 6, 7, 8, 14, 20, 25, 26}),
}
_ONNX_KNOWN_FIELD_NUMBERS: dict[str, frozenset[int]] | None = None


def _onnx_known_field_numbers(message_name: str) -> frozenset[int]:
    global _ONNX_KNOWN_FIELD_NUMBERS
    if _ONNX_KNOWN_FIELD_NUMBERS is None:
        known_fields = dict(_FALLBACK_ONNX_KNOWN_FIELD_NUMBERS)
        try:
            import onnx

            for full_name, class_name in _ONNX_MESSAGE_CLASS_BY_FULL_NAME.items():
                proto_type = getattr(onnx, class_name, None)
                descriptor = getattr(proto_type, "DESCRIPTOR", None)
                fields = getattr(descriptor, "fields", None)
                if fields is not None:
                    known_fields[full_name] = frozenset(int(field.number) for field in fields)
        except Exception:
            logger.debug("Unable to derive installed ONNX protobuf field map", exc_info=True)
        _ONNX_KNOWN_FIELD_NUMBERS = known_fields
    return _ONNX_KNOWN_FIELD_NUMBERS.get(message_name, frozenset())


def _discard_onnx_unknown_field_bytes(message: Any) -> int:
    byte_size = getattr(message, "ByteSize", None)
    discard_unknown_fields = getattr(message, "DiscardUnknownFields", None)
    if not callable(byte_size) or not callable(discard_unknown_fields):
        return 0
    before = int(byte_size())
    discard_unknown_fields()
    after = int(byte_size())
    return max(0, before - after)


@dataclass
class _OnnxLiteStringEntry:
    key: str = ""
    value: str = ""


@dataclass
class _OnnxLiteTensor:
    name: str = ""
    data_type: int = 0
    dims: list[int] = field(default_factory=list)
    data_location: int = 0
    external_data: list[_OnnxLiteStringEntry] = field(default_factory=list)
    raw_data: Any = b""
    float_data: Any = field(default_factory=lambda: _OnnxLengthOnlySequence(0))
    int32_data: Any = field(default_factory=lambda: _OnnxLengthOnlySequence(0))
    int64_data: Any = field(default_factory=lambda: _OnnxLengthOnlySequence(0))
    double_data: Any = field(default_factory=lambda: _OnnxLengthOnlySequence(0))
    uint64_data: Any = field(default_factory=lambda: _OnnxLengthOnlySequence(0))
    string_data: Any = field(default_factory=list)


@dataclass
class _OnnxLiteSparseTensor:
    values: _OnnxLiteTensor = field(default_factory=_OnnxLiteTensor)
    indices: _OnnxLiteTensor = field(default_factory=_OnnxLiteTensor)
    dims: list[int] = field(default_factory=list)


@dataclass
class _OnnxLiteValueInfo:
    name: str = ""


@dataclass
class _OnnxLiteAttribute:
    name: str = ""
    ref_attr_name: str = ""
    i: int = 0
    ints: list[int] = field(default_factory=list)
    t: _OnnxLiteTensor | None = None
    g: "_OnnxLiteGraph | None" = None
    sparse_tensor: _OnnxLiteSparseTensor | None = None
    tensors: list[_OnnxLiteTensor] = field(default_factory=list)
    graphs: list["_OnnxLiteGraph"] = field(default_factory=list)
    sparse_tensors: list[_OnnxLiteSparseTensor] = field(default_factory=list)

    def HasField(self, name: str) -> bool:
        if name in {"t", "g", "sparse_tensor"}:
            return getattr(self, name) is not None
        raise ValueError(f"Unknown ONNX attribute field: {name}")


@dataclass
class _OnnxLiteNode:
    input: list[str] = field(default_factory=list)
    output: list[str] = field(default_factory=list)
    name: str = ""
    op_type: str = ""
    domain: str = ""
    overload: str = ""
    attribute: list[_OnnxLiteAttribute] = field(default_factory=list)


@dataclass
class _OnnxLiteGraph:
    node: list[_OnnxLiteNode] = field(default_factory=list)
    name: str = ""
    initializer: list[_OnnxLiteTensor] = field(default_factory=list)
    sparse_initializer: list[_OnnxLiteSparseTensor] = field(default_factory=list)
    input: list[_OnnxLiteValueInfo] = field(default_factory=list)
    output: list[_OnnxLiteValueInfo] = field(default_factory=list)
    value_info: list[_OnnxLiteValueInfo] = field(default_factory=list)


@dataclass
class _OnnxLiteOpsetImport:
    domain: str = ""
    version: int = 0


@dataclass
class _OnnxLiteFunction:
    node: list[_OnnxLiteNode] = field(default_factory=list)
    name: str = ""
    domain: str = ""
    overload: str = ""
    input: list[str] = field(default_factory=list)
    output: list[str] = field(default_factory=list)
    attribute: list[str] = field(default_factory=list)
    opset_import: list[_OnnxLiteOpsetImport] = field(default_factory=list)
    attribute_proto: list[_OnnxLiteAttribute] = field(default_factory=list)
    value_info: list[_OnnxLiteValueInfo] = field(default_factory=list)


@dataclass
class _OnnxLiteTrainingInfo:
    initialization: _OnnxLiteGraph = field(default_factory=_OnnxLiteGraph)
    algorithm: _OnnxLiteGraph = field(default_factory=_OnnxLiteGraph)
    initialization_binding: list[_OnnxLiteStringEntry] = field(default_factory=list)
    update_binding: list[_OnnxLiteStringEntry] = field(default_factory=list)


@dataclass
class _OnnxLiteModel:
    ir_version: int = 0
    producer_name: str = ""
    opset_import: list[_OnnxLiteOpsetImport] = field(default_factory=list)
    functions: list[_OnnxLiteFunction] = field(default_factory=list)
    training_info: list[_OnnxLiteTrainingInfo] = field(default_factory=list)
    _graph: _OnnxLiteGraph | None = None

    @property
    def graph(self) -> _OnnxLiteGraph:
        return self._graph if self._graph is not None else _OnnxLiteGraph()

    def HasField(self, name: str) -> bool:
        if name == "graph":
            return self._graph is not None
        raise ValueError(f"Unknown ONNX model field: {name}")


@dataclass
class _OnnxStructureParseState:
    interrupt_check: Callable[[], None] | None = field(default=None, repr=False, compare=False)
    omitted_raw_data_fields: int = 0
    omitted_raw_data_bytes: int = 0
    omitted_packed_varint_fields: int = 0
    omitted_packed_varint_bytes: int = 0
    node_count: int = 0
    tensor_count: int = 0
    graph_count: int = 0
    retained_object_count: int = 0
    retained_sequence_entries: int = 0
    retained_string_bytes: int = 0
    retained_allocation_bytes: int = 0
    string_fields_skipped: int = 0
    unknown_field_count: int = 0
    unknown_field_samples: list[dict[str, Any]] = field(default_factory=list)
    fields_seen: int = 0
    parse_steps: int = 0
    coverage_gaps: dict[str, int] = field(default_factory=dict)

    def check_interrupted(self) -> None:
        if self.interrupt_check is not None:
            self.interrupt_check()
        if self.parse_steps >= _ONNX_STRUCTURE_MAX_PARSE_STEPS:
            reason = "protobuf_parse_step_limit_exceeded"
            self.record_gap(reason)
            raise _OnnxStructureParseError(
                reason,
                f"ONNX structural parser work exceeds limit ({_ONNX_STRUCTURE_MAX_PARSE_STEPS})",
            )
        self.parse_steps += 1

    def record_gap(self, reason: str, count: int = 1) -> None:
        self.coverage_gaps[reason] = self.coverage_gaps.get(reason, 0) + count

    def record_unknown_field(self, message_name: str, field_number: int, wire_type: int) -> None:
        self.unknown_field_count += 1
        self.record_gap("unknown_protobuf_fields")
        if len(self.unknown_field_samples) >= _ONNX_STRUCTURE_MAX_UNKNOWN_FIELD_SAMPLES:
            return
        self.unknown_field_samples.append(
            {
                "message": message_name,
                "field_number": field_number,
                "wire_type": wire_type,
            }
        )

    def record_retained_allocation(self, amount: int) -> None:
        if amount < 0 or amount > _ONNX_STRUCTURE_MAX_RETAINED_ALLOCATION_BYTES - self.retained_allocation_bytes:
            reason = "retained_allocation_budget_exceeded"
            self.record_gap(reason)
            raise _OnnxStructureParseError(
                reason,
                (
                    "ONNX structural parser retained allocation estimate exceeds limit "
                    f"({_ONNX_STRUCTURE_MAX_RETAINED_ALLOCATION_BYTES})"
                ),
            )
        self.retained_allocation_bytes += amount

    def record_retained_object(self, amount: int = 1, reason: str = "retained_object_limit_exceeded") -> None:
        if amount < 0 or amount > _ONNX_STRUCTURE_MAX_RETAINED_OBJECTS - self.retained_object_count:
            self.record_gap(reason)
            raise _OnnxStructureParseError(
                reason,
                f"ONNX structural parser retained object count exceeds limit ({_ONNX_STRUCTURE_MAX_RETAINED_OBJECTS})",
            )
        self.retained_object_count += amount
        self.record_retained_allocation(amount * _ONNX_STRUCTURE_RETAINED_OBJECT_BYTES)

    def record_retained_sequence_entry(self, reason: str = "retained_sequence_entries_limit_exceeded") -> None:
        if self.retained_sequence_entries >= _ONNX_STRUCTURE_MAX_RETAINED_SEQUENCE_ENTRIES:
            self.record_gap(reason)
            raise _OnnxStructureParseError(
                reason,
                (
                    "ONNX structural parser retained sequence entries exceed aggregate limit "
                    f"({_ONNX_STRUCTURE_MAX_RETAINED_SEQUENCE_ENTRIES})"
                ),
            )
        self.retained_sequence_entries += 1
        self.record_retained_allocation(_ONNX_STRUCTURE_RETAINED_SEQUENCE_ENTRY_BYTES)

    def record_retained_string(self, length: int, field_name: str) -> None:
        if length < 0 or length > _ONNX_STRUCTURE_MAX_RETAINED_STRING_BYTES - self.retained_string_bytes:
            reason = "retained_string_bytes_limit_exceeded"
            self.record_gap(reason)
            raise _OnnxStructureParseError(
                reason,
                (
                    "ONNX structural parser retained string bytes exceed aggregate limit "
                    f"({_ONNX_STRUCTURE_MAX_RETAINED_STRING_BYTES}) at {field_name}"
                ),
            )
        self.retained_string_bytes += length
        self.record_retained_allocation((2 * length) + _ONNX_STRUCTURE_RETAINED_STRING_OVERHEAD_BYTES)

    def metadata(self) -> dict[str, Any]:
        return {
            "parse_mode": "file_backed_structure",
            "omitted_raw_data_fields": self.omitted_raw_data_fields,
            "omitted_raw_data_bytes": self.omitted_raw_data_bytes,
            "omitted_packed_varint_fields": self.omitted_packed_varint_fields,
            "omitted_packed_varint_bytes": self.omitted_packed_varint_bytes,
            "node_count": self.node_count,
            "tensor_count": self.tensor_count,
            "graph_count": self.graph_count,
            "retained_object_count": self.retained_object_count,
            "retained_sequence_entries": self.retained_sequence_entries,
            "retained_string_bytes": self.retained_string_bytes,
            "retained_allocation_bytes": self.retained_allocation_bytes,
            "string_fields_skipped": self.string_fields_skipped,
            "unknown_field_count": self.unknown_field_count,
            "unknown_field_samples": list(self.unknown_field_samples),
            "unknown_field_samples_truncated": (self.unknown_field_count > len(self.unknown_field_samples)),
            "fields_seen": self.fields_seen,
            "parse_steps": self.parse_steps,
            "coverage_gaps": dict(self.coverage_gaps),
        }


def _decode_int64_varint(value: int) -> int:
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= (1 << 63) else value


def _decode_int32_varint(value: int) -> int:
    value &= (1 << 32) - 1
    return value - (1 << 32) if value >= (1 << 31) else value


def _ensure_onnx_parse_depth(depth: int) -> None:
    if depth > _ONNX_STRUCTURE_MAX_DEPTH:
        raise _OnnxStructureParseError(
            "protobuf_nesting_limit_exceeded",
            f"ONNX protobuf nesting exceeds limit ({_ONNX_STRUCTURE_MAX_DEPTH})",
        )


def _read_onnx_varint(handle: BinaryIO, end: int) -> int:
    shift = 0
    value = 0
    for _ in range(10):
        if handle.tell() >= end:
            raise _OnnxStructureParseError("truncated_varint", "ONNX protobuf varint is truncated")
        chunk = handle.read(1)
        if len(chunk) != 1:
            raise _OnnxStructureParseError("truncated_varint", "ONNX protobuf varint is truncated")
        byte = chunk[0]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value
        shift += 7
    raise _OnnxStructureParseError("varint_too_long", "ONNX protobuf varint exceeds 10 bytes")


def _read_onnx_key(handle: BinaryIO, end: int, state: _OnnxStructureParseState) -> tuple[int, int]:
    state.check_interrupted()
    state.fields_seen += 1
    key = _read_onnx_varint(handle, end)
    field_number = key >> 3
    if field_number == 0:
        raise _OnnxStructureParseError("invalid_field_number_zero", "ONNX protobuf field number 0 is invalid")
    if field_number > _ONNX_STRUCTURE_MAX_FIELD_NUMBER:
        raise _OnnxStructureParseError(
            "field_number_out_of_range",
            f"ONNX protobuf field number exceeds maximum ({_ONNX_STRUCTURE_MAX_FIELD_NUMBER})",
        )
    return field_number, key & 0x07


def _read_onnx_message_key(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    message_name: str,
) -> tuple[int, int]:
    field_number, wire_type = _read_onnx_key(handle, end, state)
    if field_number not in _onnx_known_field_numbers(message_name):
        state.record_unknown_field(message_name, field_number, wire_type)
    return field_number, wire_type


def _read_onnx_exact(handle: BinaryIO, length: int, end: int) -> bytes:
    if length < 0 or handle.tell() + length > end:
        raise _OnnxStructureParseError("declared_length_out_of_bounds", "ONNX protobuf field length exceeds input")
    data = handle.read(length)
    if len(data) != length:
        raise _OnnxStructureParseError("truncated_field", "ONNX protobuf field is truncated")
    return data


def _skip_onnx_bytes(handle: BinaryIO, length: int, end: int) -> None:
    if length < 0 or handle.tell() + length > end:
        raise _OnnxStructureParseError("declared_length_out_of_bounds", "ONNX protobuf field length exceeds input")
    handle.seek(length, os.SEEK_CUR)


def _read_onnx_length_bounds(handle: BinaryIO, end: int) -> tuple[int, int]:
    length = _read_onnx_varint(handle, end)
    payload_end = handle.tell() + length
    if payload_end > end:
        raise _OnnxStructureParseError("declared_length_out_of_bounds", "ONNX protobuf field length exceeds input")
    return length, payload_end


def _skip_onnx_unknown_field(handle: BinaryIO, wire_type: int, end: int) -> None:
    if wire_type == 0:
        _read_onnx_varint(handle, end)
    elif wire_type == 1:
        _skip_onnx_bytes(handle, 8, end)
    elif wire_type == 2:
        length, payload_end = _read_onnx_length_bounds(handle, end)
        _skip_onnx_bytes(handle, length, payload_end)
    elif wire_type == 5:
        _skip_onnx_bytes(handle, 4, end)
    else:
        raise _OnnxStructureParseError(
            "unsupported_wire_type",
            f"ONNX protobuf uses unsupported wire type {wire_type}",
        )


def _read_onnx_string(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    *,
    field_name: str,
) -> str:
    length, payload_end = _read_onnx_length_bounds(handle, end)
    if length > _ONNX_STRUCTURE_STRING_MAX_BYTES:
        state.string_fields_skipped += 1
        state.record_gap(f"{field_name}_string_too_large")
        handle.seek(payload_end)
        return ""
    raw = _read_onnx_exact(handle, length, payload_end)
    state.record_retained_string(length, field_name)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        state.record_gap(f"{field_name}_invalid_utf8")
        return raw.decode("utf-8", errors="replace")


def _append_onnx_sequence_value(
    values: list[Any],
    value: Any,
    state: _OnnxStructureParseState,
    *,
    reason: str,
    limit: int = _ONNX_STRUCTURE_MAX_SEQUENCE_VALUES,
) -> None:
    _ensure_onnx_sequence_capacity(values, state, reason=reason, limit=limit)
    values.append(value)


def _ensure_onnx_sequence_capacity(
    values: list[Any],
    state: _OnnxStructureParseState,
    *,
    reason: str,
    limit: int = _ONNX_STRUCTURE_MAX_SEQUENCE_VALUES,
) -> None:
    if len(values) >= limit:
        state.record_gap(reason)
        raise _OnnxStructureParseError(reason, f"ONNX protobuf repeated field exceeds limit ({limit})")
    state.record_retained_sequence_entry()


def _append_onnx_string_value(
    values: list[str],
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    *,
    field_name: str,
    reason: str,
    limit: int = _ONNX_STRUCTURE_MAX_SEQUENCE_VALUES,
) -> None:
    _ensure_onnx_sequence_capacity(values, state, reason=reason, limit=limit)
    values.append(_read_onnx_string(handle, end, state, field_name=field_name))


def _append_onnx_submessage_value(
    values: list[Any],
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
    parser: Callable[[BinaryIO, int, _OnnxStructureParseState, int], Any],
    *,
    reason: str,
    limit: int = _ONNX_STRUCTURE_MAX_SEQUENCE_VALUES,
) -> None:
    _ensure_onnx_sequence_capacity(values, state, reason=reason, limit=limit)
    values.append(_read_onnx_submessage(handle, end, state, depth, parser))


def _append_onnx_dimension(values: list[int], value: int, state: _OnnxStructureParseState) -> None:
    _append_onnx_sequence_value(
        values,
        value,
        state,
        reason="tensor_rank_limit_exceeded",
        limit=_ONNX_STRUCTURE_MAX_TENSOR_RANK,
    )


def _raise_duplicate_onnx_singular_message(field_name: str) -> NoReturn:
    raise _OnnxStructureParseError(
        "duplicate_singular_message",
        f"ONNX protobuf singular message field is repeated: {field_name}",
    )


def _increment_onnx_count(
    current: int,
    amount: int,
    *,
    reason: str,
    limit: int = _ONNX_STRUCTURE_MAX_SEQUENCE_VALUES,
) -> int:
    if amount < 0 or amount > limit - current:
        raise _OnnxStructureParseError(reason, f"ONNX protobuf repeated field exceeds limit ({limit})")
    return current + amount


def _read_onnx_packed_varints(
    handle: BinaryIO,
    payload_end: int,
    values: list[int],
    state: _OnnxStructureParseState,
    *,
    signed: bool = False,
    reason: str = "packed_varint_sequence_limit_exceeded",
    limit: int = _ONNX_STRUCTURE_MAX_SEQUENCE_VALUES,
) -> None:
    while handle.tell() < payload_end:
        state.check_interrupted()
        raw_value = _read_onnx_varint(handle, payload_end)
        value = _decode_int64_varint(raw_value) if signed else raw_value
        _append_onnx_sequence_value(values, value, state, reason=reason, limit=limit)


def _read_onnx_submessage(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
    parser: Callable[[BinaryIO, int, _OnnxStructureParseState, int], Any],
) -> Any:
    _ensure_onnx_parse_depth(depth + 1)
    _length, payload_end = _read_onnx_length_bounds(handle, end)
    value = parser(handle, payload_end, state, depth + 1)
    handle.seek(payload_end)
    return value


def _parse_onnx_string_entry(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteStringEntry:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    entry = _OnnxLiteStringEntry()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.StringStringEntryProto")
        if field_number == 1 and wire_type == 2:
            entry.key = _read_onnx_string(handle, end, state, field_name="external_data_key")
        elif field_number == 2 and wire_type == 2:
            entry.value = _read_onnx_string(handle, end, state, field_name="external_data_value")
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return entry


def _parse_onnx_tensor(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteTensor:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    state.tensor_count += 1
    if state.tensor_count > _ONNX_STRUCTURE_MAX_TENSORS:
        raise _OnnxStructureParseError(
            "tensor_count_limit_exceeded",
            f"ONNX tensor count exceeds limit ({_ONNX_STRUCTURE_MAX_TENSORS})",
        )
    tensor = _OnnxLiteTensor()
    counts = {
        "float_data": 0,
        "int32_data": 0,
        "int64_data": 0,
        "double_data": 0,
        "uint64_data": 0,
    }
    string_data_count = 0
    string_data_bytes = 0
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.TensorProto")
        if field_number == 1:
            if wire_type == 0:
                _append_onnx_dimension(tensor.dims, _decode_int64_varint(_read_onnx_varint(handle, end)), state)
            elif wire_type == 2:
                _length, payload_end = _read_onnx_length_bounds(handle, end)
                while handle.tell() < payload_end:
                    state.check_interrupted()
                    _append_onnx_dimension(
                        tensor.dims,
                        _decode_int64_varint(_read_onnx_varint(handle, payload_end)),
                        state,
                    )
                handle.seek(payload_end)
            else:
                _skip_onnx_unknown_field(handle, wire_type, end)
        elif field_number == 2 and wire_type == 0:
            tensor.data_type = _decode_int32_varint(_read_onnx_varint(handle, end))
        elif field_number == 4:
            if wire_type == 5:
                _skip_onnx_bytes(handle, 4, end)
                counts["float_data"] += 1
            elif wire_type == 2:
                length, payload_end = _read_onnx_length_bounds(handle, end)
                if length % 4:
                    raise _OnnxStructureParseError("malformed_packed_float_data", "Packed float_data length is invalid")
                counts["float_data"] += length // 4
                handle.seek(payload_end)
            else:
                _skip_onnx_unknown_field(handle, wire_type, end)
        elif field_number in {5, 7, 11}:
            key_name = {5: "int32_data", 7: "int64_data", 11: "uint64_data"}[field_number]
            if wire_type == 0:
                _read_onnx_varint(handle, end)
                counts[key_name] += 1
            elif wire_type == 2:
                length, payload_end = _read_onnx_length_bounds(handle, end)
                # Packed integer values are tensor payload. The serialized byte
                # length is a conservative upper bound on element count and lets
                # file-backed scans skip multi-GB payloads in constant work.
                counts[key_name] += length
                state.omitted_packed_varint_fields += 1
                state.omitted_packed_varint_bytes += length
                handle.seek(payload_end)
            else:
                _skip_onnx_unknown_field(handle, wire_type, end)
        elif field_number == 6 and wire_type == 2:
            length, payload_end = _read_onnx_length_bounds(handle, end)
            string_data_count = _increment_onnx_count(
                string_data_count,
                1,
                reason="tensor_string_data_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_STRING_DATA_FIELDS,
            )
            string_data_bytes += length
            handle.seek(payload_end)
        elif field_number == 8 and wire_type == 2:
            tensor.name = _read_onnx_string(handle, end, state, field_name="tensor_name")
        elif field_number == 9 and wire_type == 2:
            length, payload_end = _read_onnx_length_bounds(handle, end)
            tensor.raw_data = _OnnxOmittedBytes(length)
            state.omitted_raw_data_fields += 1
            state.omitted_raw_data_bytes += length
            handle.seek(payload_end)
        elif field_number == 10:
            if wire_type == 1:
                _skip_onnx_bytes(handle, 8, end)
                counts["double_data"] += 1
            elif wire_type == 2:
                length, payload_end = _read_onnx_length_bounds(handle, end)
                if length % 8:
                    raise _OnnxStructureParseError(
                        "malformed_packed_double_data",
                        "Packed double_data length is invalid",
                    )
                counts["double_data"] += length // 8
                handle.seek(payload_end)
            else:
                _skip_onnx_unknown_field(handle, wire_type, end)
        elif field_number == 13 and wire_type == 2:
            _append_onnx_submessage_value(
                tensor.external_data,
                handle,
                end,
                state,
                depth,
                _parse_onnx_string_entry,
                reason="external_data_entry_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_EXTERNAL_DATA_ENTRIES,
            )
        elif field_number == 14 and wire_type == 0:
            data_location = _decode_int32_varint(_read_onnx_varint(handle, end))
            # TensorProto.data_location is a proto2 enum. Unknown values are
            # retained as unknown fields by protobuf and must not overwrite a
            # previously recognized value.
            if data_location in {0, 1}:
                tensor.data_location = data_location
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    tensor.float_data = _OnnxLengthOnlySequence(counts["float_data"])
    tensor.int32_data = _OnnxLengthOnlySequence(counts["int32_data"])
    tensor.int64_data = _OnnxLengthOnlySequence(counts["int64_data"])
    tensor.double_data = _OnnxLengthOnlySequence(counts["double_data"])
    tensor.uint64_data = _OnnxLengthOnlySequence(counts["uint64_data"])
    tensor.string_data = _OnnxLengthOnlySequence(string_data_count, string_data_bytes)
    return tensor


def _parse_onnx_sparse_tensor(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteSparseTensor:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object(3)
    sparse = _OnnxLiteSparseTensor()
    seen_values = False
    seen_indices = False
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.SparseTensorProto")
        if field_number == 1 and wire_type == 2:
            if seen_values:
                _raise_duplicate_onnx_singular_message("SparseTensorProto.values")
            seen_values = True
            sparse.values = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_tensor)
        elif field_number == 2 and wire_type == 2:
            if seen_indices:
                _raise_duplicate_onnx_singular_message("SparseTensorProto.indices")
            seen_indices = True
            sparse.indices = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_tensor)
        elif field_number == 3:
            if wire_type == 0:
                _append_onnx_dimension(sparse.dims, _decode_int64_varint(_read_onnx_varint(handle, end)), state)
            elif wire_type == 2:
                _length, payload_end = _read_onnx_length_bounds(handle, end)
                while handle.tell() < payload_end:
                    state.check_interrupted()
                    _append_onnx_dimension(
                        sparse.dims,
                        _decode_int64_varint(_read_onnx_varint(handle, payload_end)),
                        state,
                    )
                handle.seek(payload_end)
            else:
                _skip_onnx_unknown_field(handle, wire_type, end)
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return sparse


def _parse_onnx_attribute(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteAttribute:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    attribute = _OnnxLiteAttribute()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.AttributeProto")
        if field_number == 1 and wire_type == 2:
            attribute.name = _read_onnx_string(handle, end, state, field_name="attribute_name")
        elif field_number == 21 and wire_type == 2:
            attribute.ref_attr_name = _read_onnx_string(handle, end, state, field_name="attribute_ref_name")
        elif field_number == 3 and wire_type == 0:
            attribute.i = _decode_int64_varint(_read_onnx_varint(handle, end))
        elif field_number == 5 and wire_type == 2:
            if attribute.t is not None:
                _raise_duplicate_onnx_singular_message("AttributeProto.t")
            attribute.t = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_tensor)
        elif field_number == 6 and wire_type == 2:
            if attribute.g is not None:
                _raise_duplicate_onnx_singular_message("AttributeProto.g")
            attribute.g = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_graph)
        elif field_number == 8:
            if wire_type == 0:
                _append_onnx_sequence_value(
                    attribute.ints,
                    _decode_int64_varint(_read_onnx_varint(handle, end)),
                    state,
                    reason="attribute_ints_limit_exceeded",
                )
            elif wire_type == 2:
                _length, payload_end = _read_onnx_length_bounds(handle, end)
                _read_onnx_packed_varints(
                    handle,
                    payload_end,
                    attribute.ints,
                    state,
                    signed=True,
                    reason="attribute_ints_limit_exceeded",
                )
                handle.seek(payload_end)
            else:
                _skip_onnx_unknown_field(handle, wire_type, end)
        elif field_number == 10 and wire_type == 2:
            _append_onnx_submessage_value(
                attribute.tensors,
                handle,
                end,
                state,
                depth,
                _parse_onnx_tensor,
                reason="attribute_tensors_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 11 and wire_type == 2:
            _append_onnx_submessage_value(
                attribute.graphs,
                handle,
                end,
                state,
                depth,
                _parse_onnx_graph,
                reason="attribute_graphs_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 22 and wire_type == 2:
            if attribute.sparse_tensor is not None:
                _raise_duplicate_onnx_singular_message("AttributeProto.sparse_tensor")
            attribute.sparse_tensor = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_sparse_tensor)
        elif field_number == 23 and wire_type == 2:
            _append_onnx_submessage_value(
                attribute.sparse_tensors,
                handle,
                end,
                state,
                depth,
                _parse_onnx_sparse_tensor,
                reason="attribute_sparse_tensors_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return attribute


def _parse_onnx_node(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteNode:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    state.node_count += 1
    if state.node_count > _ONNX_STRUCTURE_MAX_NODES:
        raise _OnnxStructureParseError(
            "node_count_limit_exceeded",
            f"ONNX node count exceeds limit ({_ONNX_STRUCTURE_MAX_NODES})",
        )
    node = _OnnxLiteNode()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.NodeProto")
        if field_number == 1 and wire_type == 2:
            _append_onnx_string_value(
                node.input,
                handle,
                end,
                state,
                field_name="node_input",
                reason="node_input_limit_exceeded",
            )
        elif field_number == 2 and wire_type == 2:
            _append_onnx_string_value(
                node.output,
                handle,
                end,
                state,
                field_name="node_output",
                reason="node_output_limit_exceeded",
            )
        elif field_number == 3 and wire_type == 2:
            node.name = _read_onnx_string(handle, end, state, field_name="node_name")
        elif field_number == 4 and wire_type == 2:
            node.op_type = _read_onnx_string(handle, end, state, field_name="node_op_type")
        elif field_number == 5 and wire_type == 2:
            _append_onnx_submessage_value(
                node.attribute,
                handle,
                end,
                state,
                depth,
                _parse_onnx_attribute,
                reason="node_attribute_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_NODE_ATTRIBUTES,
            )
        elif field_number == 7 and wire_type == 2:
            node.domain = _read_onnx_string(handle, end, state, field_name="node_domain")
        elif field_number == 8 and wire_type == 2:
            node.overload = _read_onnx_string(handle, end, state, field_name="node_overload")
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return node


def _parse_onnx_value_info(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteValueInfo:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    value_info = _OnnxLiteValueInfo()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.ValueInfoProto")
        if field_number == 1 and wire_type == 2:
            value_info.name = _read_onnx_string(handle, end, state, field_name="value_info_name")
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return value_info


def _parse_onnx_graph(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteGraph:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    state.graph_count += 1
    if state.graph_count > _ONNX_STRUCTURE_MAX_GRAPHS:
        raise _OnnxStructureParseError(
            "graph_count_limit_exceeded",
            f"ONNX graph count exceeds limit ({_ONNX_STRUCTURE_MAX_GRAPHS})",
        )
    graph = _OnnxLiteGraph()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.GraphProto")
        if field_number == 1 and wire_type == 2:
            _append_onnx_submessage_value(
                graph.node,
                handle,
                end,
                state,
                depth,
                _parse_onnx_node,
                reason="graph_node_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_NODES,
            )
        elif field_number == 2 and wire_type == 2:
            graph.name = _read_onnx_string(handle, end, state, field_name="graph_name")
        elif field_number == 5 and wire_type == 2:
            _append_onnx_submessage_value(
                graph.initializer,
                handle,
                end,
                state,
                depth,
                _parse_onnx_tensor,
                reason="graph_initializer_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_TENSORS,
            )
        elif field_number == 15 and wire_type == 2:
            _append_onnx_submessage_value(
                graph.sparse_initializer,
                handle,
                end,
                state,
                depth,
                _parse_onnx_sparse_tensor,
                reason="graph_sparse_initializer_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_TENSORS,
            )
        elif field_number == 11 and wire_type == 2:
            _append_onnx_submessage_value(
                graph.input,
                handle,
                end,
                state,
                depth,
                _parse_onnx_value_info,
                reason="graph_input_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 12 and wire_type == 2:
            _append_onnx_submessage_value(
                graph.output,
                handle,
                end,
                state,
                depth,
                _parse_onnx_value_info,
                reason="graph_output_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 13 and wire_type == 2:
            _append_onnx_submessage_value(
                graph.value_info,
                handle,
                end,
                state,
                depth,
                _parse_onnx_value_info,
                reason="graph_value_info_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return graph


def _parse_onnx_opset_import(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteOpsetImport:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    opset = _OnnxLiteOpsetImport()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.OperatorSetIdProto")
        if field_number == 1 and wire_type == 2:
            opset.domain = _read_onnx_string(handle, end, state, field_name="opset_domain")
        elif field_number == 2 and wire_type == 0:
            opset.version = _decode_int64_varint(_read_onnx_varint(handle, end))
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return opset


def _parse_onnx_function(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteFunction:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    function = _OnnxLiteFunction()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.FunctionProto")
        if field_number == 1 and wire_type == 2:
            function.name = _read_onnx_string(handle, end, state, field_name="function_name")
        elif field_number == 4 and wire_type == 2:
            _append_onnx_string_value(
                function.input,
                handle,
                end,
                state,
                field_name="function_input",
                reason="function_input_limit_exceeded",
            )
        elif field_number == 5 and wire_type == 2:
            _append_onnx_string_value(
                function.output,
                handle,
                end,
                state,
                field_name="function_output",
                reason="function_output_limit_exceeded",
            )
        elif field_number == 6 and wire_type == 2:
            _append_onnx_string_value(
                function.attribute,
                handle,
                end,
                state,
                field_name="function_attribute",
                reason="function_attribute_limit_exceeded",
            )
        elif field_number == 7 and wire_type == 2:
            _append_onnx_submessage_value(
                function.node,
                handle,
                end,
                state,
                depth,
                _parse_onnx_node,
                reason="function_node_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_NODES,
            )
        elif field_number == 9 and wire_type == 2:
            _append_onnx_submessage_value(
                function.opset_import,
                handle,
                end,
                state,
                depth,
                _parse_onnx_opset_import,
                reason="function_opset_import_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 10 and wire_type == 2:
            function.domain = _read_onnx_string(handle, end, state, field_name="function_domain")
        elif field_number == 11 and wire_type == 2:
            _append_onnx_submessage_value(
                function.attribute_proto,
                handle,
                end,
                state,
                depth,
                _parse_onnx_attribute,
                reason="function_attribute_proto_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_NODE_ATTRIBUTES,
            )
        elif field_number == 12 and wire_type == 2:
            _append_onnx_submessage_value(
                function.value_info,
                handle,
                end,
                state,
                depth,
                _parse_onnx_value_info,
                reason="function_value_info_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 13 and wire_type == 2:
            function.overload = _read_onnx_string(handle, end, state, field_name="function_overload")
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return function


def _parse_onnx_training_info(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteTrainingInfo:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object(3)
    training_info = _OnnxLiteTrainingInfo()
    seen_initialization = False
    seen_algorithm = False
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.TrainingInfoProto")
        if field_number == 1 and wire_type == 2:
            if seen_initialization:
                _raise_duplicate_onnx_singular_message("TrainingInfoProto.initialization")
            seen_initialization = True
            training_info.initialization = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_graph)
        elif field_number == 2 and wire_type == 2:
            if seen_algorithm:
                _raise_duplicate_onnx_singular_message("TrainingInfoProto.algorithm")
            seen_algorithm = True
            training_info.algorithm = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_graph)
        elif field_number == 3 and wire_type == 2:
            _append_onnx_submessage_value(
                training_info.initialization_binding,
                handle,
                end,
                state,
                depth,
                _parse_onnx_string_entry,
                reason="training_initialization_binding_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 4 and wire_type == 2:
            _append_onnx_submessage_value(
                training_info.update_binding,
                handle,
                end,
                state,
                depth,
                _parse_onnx_string_entry,
                reason="training_update_binding_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return training_info


def _parse_onnx_model(
    handle: BinaryIO,
    end: int,
    state: _OnnxStructureParseState,
    depth: int,
) -> _OnnxLiteModel:
    _ensure_onnx_parse_depth(depth)
    state.record_retained_object()
    model = _OnnxLiteModel()
    while handle.tell() < end:
        field_number, wire_type = _read_onnx_message_key(handle, end, state, "onnx.ModelProto")
        if field_number == 1 and wire_type == 0:
            model.ir_version = _decode_int64_varint(_read_onnx_varint(handle, end))
        elif field_number == 2 and wire_type == 2:
            model.producer_name = _read_onnx_string(handle, end, state, field_name="producer_name")
        elif field_number == 7 and wire_type == 2:
            if model._graph is not None:
                _raise_duplicate_onnx_singular_message("ModelProto.graph")
            model._graph = _read_onnx_submessage(handle, end, state, depth, _parse_onnx_graph)
        elif field_number == 8 and wire_type == 2:
            _append_onnx_submessage_value(
                model.opset_import,
                handle,
                end,
                state,
                depth,
                _parse_onnx_opset_import,
                reason="model_opset_import_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 20 and wire_type == 2:
            _append_onnx_submessage_value(
                model.training_info,
                handle,
                end,
                state,
                depth,
                _parse_onnx_training_info,
                reason="model_training_info_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        elif field_number == 25 and wire_type == 2:
            _append_onnx_submessage_value(
                model.functions,
                handle,
                end,
                state,
                depth,
                _parse_onnx_function,
                reason="model_functions_limit_exceeded",
                limit=_ONNX_STRUCTURE_MAX_REPEATED_SUBMESSAGES,
            )
        else:
            _skip_onnx_unknown_field(handle, wire_type, end)
    return model


def _load_onnx_structure_file_backed(
    path: str,
    file_size: int,
    interrupt_check: Callable[[], None] | None = None,
    *,
    expected_stat: os.stat_result | None = None,
) -> tuple[_OnnxLiteModel, _OnnxStructureParseState]:
    identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")

    def identity_matches(left: os.stat_result, right: os.stat_result) -> bool:
        return all(getattr(left, field_name) == getattr(right, field_name) for field_name in identity_fields)

    state = _OnnxStructureParseState(interrupt_check=interrupt_check)
    try:
        path_stat = os.stat(path)
    except OSError as exc:
        raise _OnnxStructureParseError(
            "source_identity_unavailable",
            f"Unable to stat ONNX source before structural parsing: {exc}",
        ) from exc
    expected = expected_stat if expected_stat is not None else path_stat
    if file_size != expected.st_size or not identity_matches(path_stat, expected):
        raise _OnnxStructureParseError(
            "source_changed_before_parse",
            "ONNX source identity changed before structural parsing",
        )

    open_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, open_flags)
    except OSError as exc:
        raise _OnnxStructureParseError(
            "source_changed_before_parse",
            f"Unable to open expected ONNX source for structural parsing: {exc}",
        ) from exc
    with os.fdopen(descriptor, "rb") as handle:
        opened_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened_stat.st_mode) or not identity_matches(opened_stat, expected):
            raise _OnnxStructureParseError(
                "source_changed_before_parse",
                "Opened ONNX source does not match the expected regular file identity",
            )
        opened_size = opened_stat.st_size

        def ensure_source_unchanged() -> None:
            final_descriptor_stat = os.fstat(handle.fileno())
            try:
                final_path_stat = os.stat(path)
            except OSError as exc:
                raise _OnnxStructureParseError(
                    "source_changed_during_parse",
                    f"ONNX source became unavailable during structural parsing: {exc}",
                ) from exc
            if not identity_matches(final_descriptor_stat, opened_stat) or not identity_matches(
                final_path_stat,
                opened_stat,
            ):
                raise _OnnxStructureParseError(
                    "source_changed_during_parse",
                    "ONNX source identity changed during structural parsing",
                )

        try:
            model = _parse_onnx_model(handle, opened_size, state, 0)
            if handle.tell() != opened_size:
                raise _OnnxStructureParseError(
                    "trailing_parse_mismatch",
                    "ONNX structural parser did not consume input",
                )
        except Exception:
            ensure_source_unchanged()
            raise
        ensure_source_unchanged()
    return model, state


def _mark_inconclusive_scan_result(result: ScanResult, reason: str) -> None:
    """Mark the ONNX scan inconclusive when structure validation cannot complete."""
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    reasons = result.metadata.get("scan_outcome_reasons")
    if not isinstance(reasons, list):
        reasons = []
    if reason not in reasons:
        reasons.append(reason)
    result.metadata["scan_outcome_reasons"] = reasons


def _finish_scan_result(result: ScanResult) -> None:
    """Finalize success so incomplete ONNX validation fails closed."""
    success = not result.has_errors
    if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
        success = False
    result.finish(success=success)


def _onnx_format_integrity_validated(result: ScanResult) -> bool:
    """Return True once ONNX ownership is structurally validated."""
    incomplete_reasons = result.metadata.get("scan_outcome_reasons", [])
    if isinstance(incomplete_reasons, list) and any(
        reason in {ONNX_STRUCTURE_INCONCLUSIVE_REASON, ONNX_SCHEMA_INCONCLUSIVE_REASON} for reason in incomplete_reasons
    ):
        return False
    if _suppressed_onnx_format_integrity_failure(result):
        return False
    return not any(
        check.status == CheckStatus.FAILED and check.name in _ONNX_FORMAT_INTEGRITY_CHECK_NAMES
        for check in result.checks
    )


def _suppressed_onnx_format_integrity_failure(result: ScanResult) -> bool:
    suppressed_checks = result._private_metadata.get(SUPPRESSED_FAILED_CHECKS_METADATA_KEY)
    if not isinstance(suppressed_checks, list):
        return False
    return any(
        isinstance(check, dict) and check.get("name") in _ONNX_FORMAT_INTEGRITY_CHECK_NAMES
        for check in suppressed_checks
    )


def _mark_onnx_schema_incomplete(
    result: ScanResult,
    path: str,
    *,
    message: str,
    details: dict[str, Any],
) -> None:
    _mark_inconclusive_scan_result(result, ONNX_SCHEMA_INCONCLUSIVE_REASON)
    result.add_check(
        name="ONNX Schema Validation",
        passed=False,
        message=message,
        severity=IssueSeverity.INFO,
        location=path,
        rule_code="S902",
        details={
            "schema_validation_reason": ONNX_SCHEMA_INCONCLUSIVE_REASON,
            **details,
        },
    )


def _mark_onnx_result_reporting_incomplete(
    result: ScanResult,
    path: str,
    *,
    section: str,
    omitted_count: int,
) -> None:
    """Fail closed when bounded result aggregation omits attacker-controlled groups."""
    if omitted_count <= 0:
        return
    _mark_inconclusive_scan_result(result, ONNX_RESULT_REPORTING_INCONCLUSIVE_REASON)
    result.add_check(
        name="ONNX Result Reporting Coverage",
        passed=False,
        message=f"ONNX {section} results exceeded the bounded reporting budget; analysis incomplete",
        severity=IssueSeverity.INFO,
        location=path,
        rule_code="S902",
        details={
            "scan_outcome_reason": ONNX_RESULT_REPORTING_INCONCLUSIVE_REASON,
            "section": section,
            "omitted_count": omitted_count,
            "max_distinct_groups": _ONNX_RESULT_MAX_DISTINCT_GROUPS,
            "analysis_incomplete": True,
        },
    )


class OnnxScanner(BaseScanner):
    """Scanner for ONNX model files."""

    name = "onnx"
    description = "Scans ONNX models for custom operators and integrity issues"
    supported_extensions: ClassVar[list[str]] = [".onnx"]
    default_max_file_read_size: ClassVar[int] = 0

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        return os.path.splitext(path)[1].lower() in cls.supported_extensions

    def _is_tentative_protobuf_route(self) -> bool:
        format_validation = self.config.get(FORMAT_VALIDATION_CONFIG_KEY)
        return isinstance(format_validation, dict) and (
            format_validation.get("routed_format") == PROTOBUF_MODEL_CANDIDATE_FORMAT
        )

    def _read_onnx_raw_detector_input(self, path: str, file_size: int, max_bytes: int) -> bytes | None:
        if file_size > max_bytes:
            return None
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
        if len(data) > max_bytes:
            return None
        return data

    def _add_onnx_file_integrity_check(
        self,
        path: str,
        result: ScanResult,
        *,
        file_size: int,
        max_hash_bytes: int,
    ) -> None:
        if file_size <= max_hash_bytes:
            self.add_file_integrity_check(path, result)
            return

        hashes: dict[str, str | None] = {"md5": None, "sha256": None, "sha512": None}
        result.add_check(
            name="File Integrity Hash",
            passed=True,
            message="File integrity hash calculation skipped for oversized ONNX file",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "md5": None,
                "sha256": None,
                "sha512": None,
                "file_size": file_size,
                "hash_calculation_skipped": True,
                "max_hash_bytes": max_hash_bytes,
                "reason": "file_exceeds_onnx_hash_budget",
            },
        )
        result.metadata["file_hashes"] = hashes
        result.metadata["file_size"] = file_size

    def _mark_structure_parse_coverage_gaps(
        self,
        result: ScanResult,
        path: str,
        *,
        state: _OnnxStructureParseState,
    ) -> None:
        if not state.coverage_gaps:
            return
        _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
        result.add_check(
            name="ONNX Structure Parse Coverage",
            passed=False,
            message="ONNX structural parser skipped or encountered protobuf fields outside complete coverage",
            severity=IssueSeverity.INFO,
            location=path,
            rule_code="S902",
            details={
                "scan_outcome_reason": ONNX_STRUCTURE_INCONCLUSIVE_REASON,
                **state.metadata(),
            },
        )

    def _mark_in_memory_unknown_fields(
        self,
        result: ScanResult,
        path: str,
        *,
        unknown_field_bytes_discarded: int,
    ) -> None:
        _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
        result.add_check(
            name="ONNX Structure Parse Coverage",
            passed=False,
            message="ONNX protobuf contains fields outside the installed schema; analysis incomplete",
            severity=IssueSeverity.INFO,
            location=path,
            rule_code="S902",
            details={
                "scan_outcome_reason": ONNX_STRUCTURE_INCONCLUSIVE_REASON,
                "parse_mode": "in_memory_model_proto",
                "coverage_gaps": {"unknown_protobuf_fields": 1},
                "unknown_field_count": 1,
                "unknown_field_bytes_discarded": unknown_field_bytes_discarded,
                "unknown_field_detection": "discard_unknown_fields_byte_size",
            },
        )

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        try:
            source_stat = os.stat(path)
        except OSError as e:
            _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
            result.add_check(
                name="ONNX File Stability",
                passed=False,
                message=f"Unable to stat ONNX source before scanning; analysis incomplete: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S902",
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": ONNX_STRUCTURE_INCONCLUSIVE_REASON,
                    "coverage_gap": "source_identity_unavailable",
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
            )
            _finish_scan_result(result)
            return result
        file_size = source_stat.st_size
        result.metadata["file_size"] = file_size
        raw_detector_max_bytes = resolve_onnx_raw_detector_max_bytes(self.config)

        # Add file integrity check for compliance
        self._add_onnx_file_integrity_check(
            path,
            result,
            file_size=file_size,
            max_hash_bytes=raw_detector_max_bytes,
        )
        self.current_file_path = path

        if not _check_onnx():
            if self._is_tentative_protobuf_route():
                result.bytes_scanned = file_size
                result.scanner_name = "unknown"
                result.metadata["tentative_protobuf_candidate_unanalyzed"] = "onnx_dependency_unavailable"
                _mark_inconclusive_scan_result(result, ONNX_TENTATIVE_CANDIDATE_UNAVAILABLE_REASON)
                result.add_check(
                    name="ONNX Candidate Analysis",
                    passed=False,
                    message="ONNX analysis dependency is unavailable for an ambiguous protobuf model candidate",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "required_package": "onnx",
                        "analysis_incomplete": True,
                        "scan_outcome_reason": ONNX_TENTATIVE_CANDIDATE_UNAVAILABLE_REASON,
                    },
                    rule_code="S902",
                )
                _finish_scan_result(result)
                return result
            result.add_check(
                name="ONNX Capability Check",
                passed=False,
                message="ONNX analysis dependency is unavailable; ONNX scan coverage is incomplete.",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "required_package": "onnx",
                    "analysis_incomplete": True,
                    "scan_outcome_reason": ONNX_DEPENDENCY_UNAVAILABLE_REASON,
                    "operational_error": True,
                },
            )
            result.bytes_scanned = file_size
            result.metadata["analysis_incomplete"] = True
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = ONNX_DEPENDENCY_UNAVAILABLE_REASON
            result.metadata["missing_dependency"] = "onnx"
            _mark_inconclusive_scan_result(result, ONNX_DEPENDENCY_UNAVAILABLE_REASON)
            _finish_scan_result(result)
            return result

        # Read raw bytes only when bounded. Oversized ONNX files are parsed
        # structurally from the file descriptor so tensor payloads can be
        # skipped rather than materialized.
        model_data: bytes | None = None
        check_jit = self._get_bool_config("check_jit_script", True)
        check_net = self._get_bool_config("check_network_comm", True)
        raw_detectors_enabled = check_jit or check_net
        if not check_jit or not check_net:
            disabled_checks = result.metadata.setdefault("disabled_checks", [])
            if not check_jit:
                disabled_checks.append("JIT/Script Code Execution Detection")
            if not check_net:
                disabled_checks.append("Network Communication Detection")
        try:
            self.check_interrupted()
            model_data = self._read_onnx_raw_detector_input(path, file_size, raw_detector_max_bytes)
            self.check_interrupted()
            if model_data is None and raw_detectors_enabled:
                self._mark_raw_detection_incomplete(
                    result,
                    path,
                    detector="raw_file_read",
                    reason="raw_detector_budget_exceeded",
                    message=(
                        "Raw ONNX detector input exceeds bounded read budget; "
                        "continuing with file-backed structural analysis"
                    ),
                    details={
                        "file_size": file_size,
                        "max_raw_detector_bytes": raw_detector_max_bytes,
                    },
                )
        except Exception as e:
            logger.warning("Raw ONNX detector input read failed: %s", e)
            if raw_detectors_enabled:
                self._mark_raw_detection_incomplete(
                    result,
                    path,
                    detector="raw_file_read",
                    reason="file_read_failed",
                    message=f"Raw ONNX detector input read failed: {e!s}",
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )

        try:
            import onnx

            # Check for interrupts before starting the potentially long-running load.
            self.check_interrupted()
            file_backed_parse_state: _OnnxStructureParseState | None = None
            in_memory_unknown_field_bytes_discarded = 0
            model: Any
            if model_data is None:
                model, file_backed_parse_state = _load_onnx_structure_file_backed(
                    path,
                    file_size,
                    self.check_interrupted,
                    expected_stat=source_stat,
                )
                result.metadata["onnx_structure_parse"] = file_backed_parse_state.metadata()
            else:
                model = onnx.load_model_from_string(model_data)
                result.metadata["onnx_structure_parse"] = {"parse_mode": "in_memory_model_proto"}
                in_memory_unknown_field_bytes_discarded = _discard_onnx_unknown_field_bytes(model)
            # Check for interrupts after loading completes.
            self.check_interrupted()
            result.bytes_scanned = file_size
        except KeyboardInterrupt:
            # Re-raise keyboard interrupt for graceful shutdown
            raise
        except Exception as e:  # pragma: no cover - unexpected parse errors
            result.bytes_scanned = file_size
            parse_error_details = {"exception": str(e), "exception_type": type(e).__name__}
            if isinstance(e, _OnnxStructureParseError):
                parse_error_details["coverage_gap"] = e.reason
            if self._is_tentative_protobuf_route():
                result.scanner_name = "unknown"
                result.metadata["tentative_protobuf_candidate_unanalyzed"] = "onnx_parse_failed"
                _mark_inconclusive_scan_result(result, ONNX_TENTATIVE_CANDIDATE_PARSE_INCOMPLETE_REASON)
                result.add_check(
                    name="ONNX Candidate Analysis",
                    passed=False,
                    message=f"ONNX tentative candidate parsing failed; analysis incomplete: {e}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        **parse_error_details,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": ONNX_TENTATIVE_CANDIDATE_PARSE_INCOMPLETE_REASON,
                    },
                    rule_code="S902",
                )
                _finish_scan_result(result)
                return result
            parse_error_reason = e.reason if isinstance(e, _OnnxStructureParseError) else None
            safety_budget_exhausted = parse_error_reason is not None and _is_onnx_structure_safety_budget_reason(
                parse_error_reason
            )
            source_identity_incomplete = parse_error_reason in {
                "source_changed_before_parse",
                "source_changed_during_parse",
                "source_identity_unavailable",
            }
            if safety_budget_exhausted or source_identity_incomplete:
                _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
                result.add_check(
                    name="ONNX Structure Parse Coverage",
                    passed=False,
                    message=f"ONNX structural parsing stopped before completion; analysis incomplete: {e}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    rule_code="S902",
                    details={
                        **parse_error_details,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": ONNX_STRUCTURE_INCONCLUSIVE_REASON,
                        "safety_budget_exhausted": safety_budget_exhausted,
                        "source_changed": (parse_error_reason or "").startswith("source_changed_"),
                    },
                )
                _finish_scan_result(result)
                return result
            result.add_check(
                name="ONNX Model Parsing",
                passed=False,
                message=f"Error parsing ONNX model: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details=parse_error_details,
            )
            result.finish(success=False)
            return result

        has_graph = _onnx_has_singular_field(model, "graph")
        if model.ir_version <= 0 or not has_graph:
            if self._is_tentative_protobuf_route() and not has_graph:
                result.scanner_name = "unknown"
                result.metadata["tentative_protobuf_candidate_rejected"] = True
                result.finish(success=True)
                return result
            if file_backed_parse_state is not None:
                self._mark_structure_parse_coverage_gaps(result, path, state=file_backed_parse_state)
            elif in_memory_unknown_field_bytes_discarded:
                result.metadata["onnx_structure_parse"] = {
                    "parse_mode": "in_memory_model_proto",
                    "coverage_gaps": {"unknown_protobuf_fields": 1},
                    "unknown_field_count": 1,
                    "unknown_field_bytes_discarded": in_memory_unknown_field_bytes_discarded,
                    "unknown_field_detection": "discard_unknown_fields_byte_size",
                }
                self._mark_in_memory_unknown_fields(
                    result,
                    path,
                    unknown_field_bytes_discarded=in_memory_unknown_field_bytes_discarded,
                )
            _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
            result.add_check(
                name="ONNX Structure Validation",
                passed=False,
                message="Parsed ONNX payload is missing required model structure; analysis incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S902",
                details={
                    "scan_outcome_reason": ONNX_STRUCTURE_INCONCLUSIVE_REASON,
                    "ir_version": model.ir_version,
                    "has_graph": has_graph,
                },
            )
        elif file_backed_parse_state is not None:
            self._mark_structure_parse_coverage_gaps(result, path, state=file_backed_parse_state)
        elif in_memory_unknown_field_bytes_discarded:
            result.metadata["onnx_structure_parse"] = {
                "parse_mode": "in_memory_model_proto",
                "coverage_gaps": {"unknown_protobuf_fields": 1},
                "unknown_field_count": 1,
                "unknown_field_bytes_discarded": in_memory_unknown_field_bytes_discarded,
                "unknown_field_detection": "discard_unknown_fields_byte_size",
            }
            self._mark_in_memory_unknown_fields(
                result,
                path,
                unknown_field_bytes_discarded=in_memory_unknown_field_bytes_discarded,
            )

        if model.ir_version > 0 and has_graph:
            checker = getattr(onnx, "checker", None)
            check_model = getattr(checker, "check_model", None)
            if not callable(check_model):
                _mark_onnx_schema_incomplete(
                    result,
                    path,
                    message="ONNX schema checker is unavailable; analysis incomplete",
                    details={"checker_available": False},
                )
            elif model_data is None:
                _mark_onnx_schema_incomplete(
                    result,
                    path,
                    message="ONNX schema validation unavailable for bounded file-backed structure; analysis incomplete",
                    details={
                        "checker_available": True,
                        "file_backed_structure": True,
                        "parse_mode": "file_backed_structure",
                        "external_data_present": _model_has_external_data(model, self.check_interrupted),
                        "reason": "file_backed_structure_not_full_model_proto",
                    },
                )
            elif _model_has_external_data(model, self.check_interrupted):
                _mark_onnx_schema_incomplete(
                    result,
                    path,
                    message="ONNX schema validation skipped for external-data model; analysis incomplete",
                    details={
                        "checker_available": True,
                        "external_data_present": True,
                    },
                )
            else:
                try:
                    self.check_interrupted()
                    check_model(model)
                    self.check_interrupted()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    redacted_error = redact_untrusted_error_message(e)
                    _mark_onnx_schema_incomplete(
                        result,
                        path,
                        message=f"ONNX schema validation failed; analysis incomplete: {redacted_error}",
                        details={
                            "checker_available": True,
                            "exception": redacted_error,
                            "exception_type": type(e).__name__,
                        },
                    )
                else:
                    result.add_check(
                        name="ONNX Schema Validation",
                        passed=True,
                        message="ONNX schema validation passed",
                        location=path,
                    )

        result.metadata.update(
            {
                "ir_version": model.ir_version,
                "producer_name": model.producer_name,
                "node_count": len(model.graph.node),
            },
        )

        if model_data is not None:
            if check_jit:
                try:
                    jit_findings = self.collect_jit_script_findings(
                        model_data,
                        model_type="onnx",
                        context=path,
                        raise_on_error=True,
                    )
                except Exception as e:
                    redacted_error = redact_untrusted_error_message(e)
                    logger.warning("ONNX JIT/script detector analysis failed: %s", redacted_error)
                    self._mark_raw_detection_incomplete(
                        result,
                        path,
                        detector="jit_script",
                        reason="analysis_failed",
                        message=f"ONNX JIT/script detector analysis failed: {redacted_error}",
                        details={"exception": redacted_error, "exception_type": type(e).__name__},
                    )
                else:
                    self.add_jit_script_findings(
                        _confirmed_onnx_operator_findings(jit_findings, model),
                        result,
                        model_type="onnx",
                        context=path,
                    )

            if check_net:
                network_findings: list[dict[str, Any]] = []
                network_detector_input: _OnnxNetworkDetectorInput | None = None
                network_detector_failed = False
                try:
                    network_detector_input = _collect_onnx_network_detector_input(
                        model,
                        check_interrupted=self.check_interrupted,
                    )
                    result.metadata["onnx_network_detector_input"] = _onnx_network_detector_input_metadata(
                        network_detector_input
                    )
                    if network_detector_input.truncated:
                        self._mark_network_text_input_incomplete(result, path, network_detector_input)
                    max_network_findings = _network_communication_max_findings(self.config)
                    emitted_network_findings = 0
                    for section_index, section in enumerate(network_detector_input.sections):
                        detector_context = path
                        limit_already_reached = (
                            max_network_findings is not None and emitted_network_findings >= max_network_findings
                        )
                        remaining_findings = None
                        if max_network_findings is not None:
                            remaining_findings = (
                                1 if limit_already_reached else max_network_findings - emitted_network_findings
                            )
                        section_findings = self.collect_network_communication_findings(
                            section.data,
                            context=detector_context,
                            raise_on_error=True,
                            max_findings=remaining_findings,
                            onnx_metadata_context=section.metadata_owned,
                        )
                        if limit_already_reached:
                            assert max_network_findings is not None
                            limit_findings = [
                                finding
                                for finding in section_findings
                                if finding.get("type") == "detector_finding_limit"
                            ]
                            if limit_findings:
                                self._mark_network_finding_limit(
                                    result, path, section, section_index, network_detector_input
                                )
                                for finding in limit_findings:
                                    annotated_finding = dict(finding)
                                    annotated_finding.update(
                                        {
                                            "onnx_detector_input": section.name,
                                            "onnx_detector_context": detector_context,
                                            "onnx_detector_field_count": section.field_count,
                                            "onnx_metadata_owned": section.metadata_owned,
                                        }
                                    )
                                    if section.metadata_owned:
                                        annotated_finding["context"] = f"{path}:metadata_props"
                                    network_findings.append(annotated_finding)
                                break
                            if section_findings:
                                self._mark_network_finding_limit(
                                    result, path, section, section_index, network_detector_input
                                )
                                network_findings.append(
                                    _network_finding_limit_payload(
                                        section,
                                        detector_context,
                                        max_findings=max_network_findings,
                                    )
                                )
                                break
                            continue
                        section_truncated = False
                        section_redaction_work_limited = False
                        section_finding_limited = False
                        section_redaction_work_limit: dict[str, Any] | None = None
                        for finding in section_findings:
                            annotated_finding = dict(finding)
                            if annotated_finding.get("type") == "detector_finding_limit":
                                section_truncated = True
                                if _is_network_redaction_work_limit(annotated_finding):
                                    section_redaction_work_limited = True
                                    section_redaction_work_limit = annotated_finding
                                else:
                                    section_finding_limited = True
                            else:
                                emitted_network_findings += 1
                            annotated_finding.update(
                                {
                                    "onnx_detector_input": section.name,
                                    "onnx_detector_context": detector_context,
                                    "onnx_detector_field_count": section.field_count,
                                    "onnx_metadata_owned": section.metadata_owned,
                                }
                            )
                            if section.metadata_owned:
                                annotated_finding["context"] = f"{path}:metadata_props"
                            network_findings.append(annotated_finding)
                        if section_truncated:
                            if section_redaction_work_limited:
                                self._mark_network_redaction_work_limit(
                                    result,
                                    path,
                                    section,
                                    section_redaction_work_limit,
                                )
                            if section_finding_limited:
                                self._mark_network_finding_limit(
                                    result, path, section, section_index, network_detector_input
                                )
                                break
                except Exception as e:
                    network_detector_failed = True
                    redacted_error = redact_untrusted_error_message(e)
                    logger.warning("ONNX network detector analysis failed: %s", redacted_error)
                    self._mark_raw_detection_incomplete(
                        result,
                        path,
                        detector="network_communication",
                        reason="analysis_failed",
                        message=f"ONNX network detector analysis failed: {redacted_error}",
                        details={"exception": redacted_error, "exception_type": type(e).__name__},
                    )
                if network_findings or (
                    network_detector_input is not None
                    and not network_detector_input.truncated
                    and not network_detector_failed
                ):
                    self.add_network_communication_findings(
                        network_findings,
                        result,
                        context=path,
                    )

        if model_data is None and check_net:
            try:
                network_detector_input = _collect_onnx_network_detector_input(
                    model,
                    check_interrupted=self.check_interrupted,
                )
                result.metadata["onnx_network_detector_input"] = _onnx_network_detector_input_metadata(
                    network_detector_input
                )
                if network_detector_input.truncated:
                    self._mark_network_text_input_incomplete(result, path, network_detector_input)
            except Exception as e:
                redacted_error = redact_untrusted_error_message(e)
                logger.warning("ONNX network detector analysis failed: %s", redacted_error)
                self._mark_raw_detection_incomplete(
                    result,
                    path,
                    detector="network_communication",
                    reason="analysis_failed",
                    message=f"ONNX network detector analysis failed: {redacted_error}",
                    details={"exception": redacted_error, "exception_type": type(e).__name__},
                )

        self._check_custom_ops(model, path, result)
        self._check_external_data(model, path, result)
        self._check_tensor_sizes(model, path, result)
        if _onnx_format_integrity_validated(result):
            result.metadata[VALIDATED_FORMAT_METADATA_KEY] = self.name
        if model_data is None:
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason="file_backed_structural_parse",
                message="Weight distribution analysis requires tensor materialization and was skipped",
                details={
                    "parse_mode": "file_backed_structure",
                    "omitted_raw_data_fields": result.metadata.get("onnx_structure_parse", {}).get(
                        "omitted_raw_data_fields",
                    ),
                    "omitted_raw_data_bytes": result.metadata.get("onnx_structure_parse", {}).get(
                        "omitted_raw_data_bytes",
                    ),
                },
            )
        else:
            self._check_weight_distribution(model, path, result)

        _finish_scan_result(result)
        return result

    def _mark_network_redaction_work_limit(
        self,
        result: ScanResult,
        path: str,
        section: _OnnxNetworkDetectorSection,
        finding: dict[str, Any] | None,
    ) -> None:
        self._mark_raw_detection_incomplete(
            result,
            path,
            detector="network_communication",
            reason="detector_finding_limit",
            message="ONNX network detector redaction work limit reached; analysis incomplete",
            details={
                "max_classifications": (finding or {}).get("max_classifications"),
                "truncated_section": section.name,
                "truncated_section_metadata_owned": section.metadata_owned,
            },
        )

    def _mark_network_finding_limit(
        self,
        result: ScanResult,
        path: str,
        section: _OnnxNetworkDetectorSection,
        section_index: int,
        network_detector_input: _OnnxNetworkDetectorInput,
    ) -> None:
        remaining_sections = network_detector_input.sections[section_index + 1 :]
        self._mark_raw_detection_incomplete(
            result,
            path,
            detector="network_communication",
            reason="detector_finding_limit",
            message="ONNX network detector findings reached the configured reporting limit; analysis incomplete",
            details={
                "max_findings": _network_communication_max_findings(self.config),
                "truncated_section": section.name,
                "truncated_section_metadata_owned": section.metadata_owned,
                "skipped_section_count": len(remaining_sections),
                "skipped_sections": [item.name for item in remaining_sections[:10]],
            },
        )

    def _mark_network_text_input_incomplete(
        self,
        result: ScanResult,
        path: str,
        network_detector_input: _OnnxNetworkDetectorInput,
    ) -> None:
        truncation_reason = network_detector_input.truncation_reason or "text_field_budget_exceeded"
        truncation_message = "ONNX network detector text input exceeded bounded extraction budget; analysis incomplete"
        if truncation_reason == "structured_text_unavailable":
            truncation_message = (
                "ONNX network detector text input unavailable for bounded file-backed structure; analysis incomplete"
            )
        self._mark_raw_detection_incomplete(
            result,
            path,
            detector="network_communication",
            reason=truncation_reason,
            message=truncation_message,
            details={
                "field_count": network_detector_input.field_count,
                "omitted_field_count": network_detector_input.omitted_field_count,
                "truncation_reason": truncation_reason,
                "max_bytes": _ONNX_NETWORK_TEXT_MAX_BYTES,
                "max_fields": _ONNX_NETWORK_TEXT_MAX_FIELDS,
            },
        )

    def _mark_raw_detection_incomplete(
        self,
        result: ScanResult,
        path: str,
        *,
        detector: str,
        reason: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        _mark_inconclusive_scan_result(result, ONNX_RAW_DETECTION_INCONCLUSIVE_REASON)
        result.add_check(
            name="Raw Detector Analysis Coverage",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=path,
            rule_code="S902",
            details={
                "scan_outcome_reason": ONNX_RAW_DETECTION_INCONCLUSIVE_REASON,
                "coverage_gap": reason,
                "detector": detector,
                **(details or {}),
            },
        )

    def _check_custom_ops(self, model: Any, path: str, result: ScanResult) -> None:
        local_function_identifiers = _model_local_function_identifiers(model)
        custom_domain_findings: dict[str, _CustomOperatorAggregate] = {}
        explicit_custom_operator_findings: dict[tuple[str, str, str], _CustomOperatorAggregate] = {}
        python_operator_finding = _CustomOperatorAggregate()
        omitted_custom_groups = 0
        custom_operators_found = 0
        python_ops_found = False
        safe_nodes = 0
        nodes_checked = 0
        custom_operator_security_note = (
            "Custom operators may depend on external operator implementations. "
            "ONNX files cannot execute code - risk is in runtime environment if malicious "
            "operators are installed. Verify operator packages before installation."
        )

        for graph, opset_versions in _iter_model_graphs_with_opsets(model):
            for node in _iter_graph_nodes(graph):
                nodes_checked += 1
                # Check for interrupts periodically during node processing.
                self.check_interrupted()
                is_python_operator = _is_python_operator(node.op_type or "")
                is_external_custom_operator = _is_external_custom_operator(
                    node,
                    local_function_identifiers,
                    opset_versions,
                )
                is_explicit_custom_operator = _is_explicit_custom_operator(node, local_function_identifiers)
                if is_external_custom_operator or is_explicit_custom_operator:
                    custom_operators_found += 1
                    retained_group_count = len(custom_domain_findings) + len(explicit_custom_operator_findings)
                    if is_external_custom_operator:
                        domain = str(node.domain or "")
                        finding = custom_domain_findings.get(domain)
                        if finding is None and retained_group_count < _ONNX_RESULT_MAX_DISTINCT_GROUPS:
                            finding = _CustomOperatorAggregate()
                            custom_domain_findings[domain] = finding
                        if finding is None:
                            omitted_custom_groups += 1
                        else:
                            finding.add_node(node)
                    else:
                        identifier = _operator_identifier(node)
                        finding = explicit_custom_operator_findings.get(identifier)
                        if finding is None and retained_group_count < _ONNX_RESULT_MAX_DISTINCT_GROUPS:
                            finding = _CustomOperatorAggregate()
                            explicit_custom_operator_findings[identifier] = finding
                        if finding is None:
                            omitted_custom_groups += 1
                        else:
                            finding.add_node(node)

                if is_python_operator:
                    python_ops_found = True
                    python_operator_finding.add_node(node)
                elif not is_external_custom_operator and not is_explicit_custom_operator:
                    safe_nodes += 1

        if python_ops_found:
            representative = python_operator_finding.representative_nodes[0]
            result.add_check(
                name="Python Operator Detection",
                passed=False,
                message=(
                    f"Model uses Python operator '{representative['op_type']}' "
                    f"in {python_operator_finding.occurrence_count} node(s)"
                ),
                severity=IssueSeverity.CRITICAL,
                location=path,
                rule_code="S902",
                details={
                    "op_type": representative["op_type"],
                    "domain": representative["domain"],
                    "occurrence_count": python_operator_finding.occurrence_count,
                    "representative_nodes": python_operator_finding.representative_nodes,
                    "representative_nodes_truncated": (
                        python_operator_finding.occurrence_count > len(python_operator_finding.representative_nodes)
                    ),
                },
            )

        # All custom operators are INFO - they're metadata, not executable code.
        # Security risk is in runtime environment (installing malicious operators)
        # not in the ONNX file itself. Emit one bounded aggregate per domain/file.
        for domain, finding in sorted(custom_domain_findings.items()):
            domain_display = _bounded_custom_operator_value(domain)
            domain_hash = _custom_operator_domain_hash(domain)
            check_consolidation_key = f"onnx_custom_operator_domain:{domain_hash}"
            details = finding.details(
                domain=domain,
                security_note=custom_operator_security_note,
                check_consolidation_key=check_consolidation_key,
            )
            details["domain_hash"] = domain_hash
            result.add_check(
                name="Custom Operator Domain Check",
                passed=False,
                message=(
                    f"Model references custom operator domain '{domain_display}' "
                    f"(domain identity {domain_hash}) in "
                    f"{finding.occurrence_count} node(s). This is metadata only - ensure operators are "
                    "from trusted sources before installation."
                ),
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S1111",
                details=details,
            )

        for (domain, op_type, overload), finding in sorted(explicit_custom_operator_findings.items()):
            domain_display = _custom_operator_identity_display(domain)
            op_type_display = _bounded_custom_operator_value(op_type)
            overload_display = _custom_operator_identity_display(overload)
            identity_hash = _custom_operator_identity_hash(domain, op_type, overload)
            check_consolidation_key = f"onnx_custom_operator_identity:{identity_hash}"
            details = finding.details(
                domain=domain,
                security_note=custom_operator_security_note,
                check_consolidation_key=check_consolidation_key,
            )
            details.update(
                {
                    "op_type": op_type,
                    "overload": overload,
                    "operator_identity_hash": identity_hash,
                    "operator_identity": {
                        "domain": domain,
                        "op_type": op_type,
                        "overload": overload,
                    },
                }
            )
            result.add_check(
                name="Custom Operator Domain Check",
                passed=False,
                message=(
                    f"Model references custom operator '{op_type_display}' in ONNX domain '{domain_display}' "
                    f"with overload '{overload_display}' (identity {identity_hash}) in "
                    f"{finding.occurrence_count} node(s). Ensure its implementation is from a trusted source "
                    "before installation."
                ),
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S1111",
                details=details,
            )

        # Record successful checks for safe operators
        if safe_nodes > 0 and custom_operators_found == 0:
            result.add_check(
                name="Custom Operator Domain Check",
                passed=True,
                message=(
                    "All operators use standard ONNX domains, model-local function implementations, "
                    "or known low-noise vendor runtime operators"
                ),
                location=path,
                details={"safe_nodes": safe_nodes},
                rule_code=None,  # Passing check
            )

        if not python_ops_found:
            result.add_check(
                name="Python Operator Detection",
                passed=True,
                message="No Python operators detected",
                location=path,
                details={"nodes_checked": nodes_checked},
            )

        if custom_domain_findings:
            result.metadata["custom_domains"] = sorted(custom_domain_findings)
        _mark_onnx_result_reporting_incomplete(
            result,
            path,
            section="custom operator",
            omitted_count=omitted_custom_groups,
        )

    def _check_external_data(self, model: Any, path: str, result: ScanResult) -> None:
        model_path = Path(path).absolute()
        model_dir = model_path.parent
        try:
            resolved_model_dir = model_dir.resolve()
        except (OSError, RuntimeError):
            resolved_model_dir = model_dir
        import onnx

        # Track per-file status to avoid flooding the result with one check
        # per tensor when many tensors share the same external data file.
        missing_files: dict[str, _OnnxExternalLocationAggregate] = {}
        traversal_files: dict[str, _OnnxExternalLocationAggregate] = {}
        symlink_traversal_files: dict[str, _OnnxExternalLocationAggregate] = {}
        safe_files: set[str] = set()
        tracked_locations: set[str] = set()
        tracked_unsafe_locations: set[str] = set()
        omitted_external_results = 0
        external_size_validations: dict[
            str,
            tuple[_OnnxExternalSizeValidation, _OnnxExternalLocationAggregate],
        ] = {}
        missing_location = _OnnxExternalLocationAggregate()

        def aggregate_location(
            groups: dict[str, _OnnxExternalLocationAggregate],
            location: str,
            tensor_name: str,
            *,
            preserve_security_finding: bool = False,
        ) -> None:
            nonlocal omitted_external_results
            aggregate = groups.get(location)
            if aggregate is None:
                tracked_group = tracked_unsafe_locations if preserve_security_finding else tracked_locations
                if location not in tracked_group:
                    if len(tracked_group) >= _ONNX_RESULT_MAX_DISTINCT_GROUPS:
                        omitted_external_results += 1
                        return
                    tracked_group.add(location)
                aggregate = _OnnxExternalLocationAggregate()
                groups[location] = aggregate
            aggregate.add(tensor_name)

        for tensors in _iter_model_external_data_tensor_groups(model, self.check_interrupted):
            for tensor in tensors:
                if tensor.data_location != onnx.TensorProto.EXTERNAL:
                    continue
                info = {entry.key: entry.value for entry in tensor.external_data}
                location = info.get("location")
                if not location:
                    missing_location.add(tensor.name)
                    continue
                has_windows_absolute_path = _is_windows_absolute_path(location)
                lexical_external_path = _resolve_external_location_lexically(model_dir, location)
                external_path = _resolve_external_location(model_dir, location)
                lexical_in_model_dir = not has_windows_absolute_path and _is_contained_in(
                    lexical_external_path, model_dir
                )
                has_symlink_component = lexical_in_model_dir and _has_symlink_component(
                    lexical_external_path,
                    model_dir,
                )
                trusted_hf_cache_alias = has_symlink_component and _is_trusted_huggingface_cache_external_alias(
                    model_path,
                    lexical_external_path,
                    external_path,
                )
                symlink_escapes_model_dir = (
                    has_symlink_component
                    and not trusted_hf_cache_alias
                    and not _is_contained_in(external_path, resolved_model_dir)
                )
                escapes_model_dir = has_windows_absolute_path or (
                    not trusted_hf_cache_alias and not _is_contained_in(external_path, resolved_model_dir)
                )
                if symlink_escapes_model_dir:
                    aggregate_location(
                        symlink_traversal_files,
                        location,
                        tensor.name,
                        preserve_security_finding=True,
                    )
                elif has_symlink_component and not external_path.exists():
                    aggregate_location(missing_files, location, tensor.name)
                elif escapes_model_dir:
                    # Track for per-file CVE-2025-51480 (write direction) reporting
                    aggregate_location(
                        traversal_files,
                        location,
                        tensor.name,
                        preserve_security_finding=True,
                    )
                elif not external_path.exists():
                    aggregate_location(missing_files, location, tensor.name)
                else:
                    if location not in safe_files and location not in tracked_locations:
                        if len(tracked_locations) >= _ONNX_RESULT_MAX_DISTINCT_GROUPS:
                            omitted_external_results += 1
                        else:
                            tracked_locations.add(location)
                    if location in tracked_locations and location not in safe_files:
                        safe_files.add(location)
                        result.add_check(
                            name="External Data Reference Check",
                            passed=True,
                            message=f"External data reference resolved successfully: {location}",
                            severity=IssueSeverity.INFO,
                            location=str(external_path),
                            details={"file": location},
                        )
                    validation = self._validate_external_size(tensor, info, external_path, result)
                    validation_group = external_size_validations.get(validation.category)
                    if validation_group is None:
                        validation_group = (validation, _OnnxExternalLocationAggregate())
                        external_size_validations[validation.category] = validation_group
                    validation_group[1].add(tensor.name)

        for validation, aggregate in external_size_validations.values():
            result.add_check(
                name="External Data Size Validation",
                passed=validation.passed,
                message=validation.message,
                severity=validation.severity,
                location=validation.location,
                rule_code=validation.rule_code,
                details={
                    **validation.details,
                    "affected_tensor_count": aggregate.occurrence_count,
                    "sample_tensors": aggregate.tensor_samples,
                },
            )

        if missing_location.occurrence_count:
            result.add_check(
                name="External Data Location Check",
                passed=False,
                message=(f"{missing_location.occurrence_count} tensor(s) use external data without a location"),
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "affected_tensor_count": missing_location.occurrence_count,
                    "sample_tensors": missing_location.tensor_samples,
                },
                rule_code="S703",
            )

        for location, aggregate in symlink_traversal_files.items():
            lexical_external_path = _resolve_external_location_lexically(model_dir, location)
            external_path = _resolve_external_location(model_dir, location)
            result.add_check(
                name="CVE-2026-34447: External Data Symlink Traversal",
                passed=False,
                message=(
                    f"CVE-2026-34447: External data path '{location}' for "
                    f"{aggregate.occurrence_count} tensor(s) resolves through a symlink outside the model directory"
                ),
                severity=IssueSeverity.CRITICAL,
                location=str(lexical_external_path),
                details={
                    "tensor": aggregate.tensor_samples[0],
                    "file": location,
                    "affected_tensor_count": aggregate.occurrence_count,
                    "sample_tensors": aggregate.tensor_samples,
                    "symlink_path": str(lexical_external_path),
                    "resolved_path": str(external_path),
                    "cve_id": "CVE-2026-34447",
                    "cvss": 5.5,
                    "cwe": "CWE-22",
                    "description": (
                        "ONNX external_data loading can follow symlinks that escape the model directory "
                        "and disclose local files."
                    ),
                    "remediation": (
                        "Reject external_data entries that traverse symlinks outside the model directory "
                        "and update ONNX to a version containing the symlink traversal fix."
                    ),
                },
                why=(
                    "The external_data location is lexically inside the model directory, but a symlink component "
                    "resolves outside that directory. Loading external data may read a file the model archive "
                    "should not be able to reference."
                ),
            )

        # Report missing files once per file (not per tensor)
        for location, aggregate in missing_files.items():
            external_path = _resolve_external_location(model_dir, location)
            result.add_check(
                name="External Data Reference Check",
                passed=False,
                message=(
                    f"External data reference found (file may not be present): '{location}' "
                    f"({aggregate.occurrence_count} tensor"
                    f"{'s' if aggregate.occurrence_count != 1 else ''} affected)"
                ),
                severity=IssueSeverity.WARNING,
                location=str(external_path),
                details={
                    "tensor": aggregate.tensor_samples[0],
                    "file": location,
                    "affected_tensor_count": aggregate.occurrence_count,
                    "sample_tensors": aggregate.tensor_samples,
                },
            )

        # Path traversal is a genuine security issue -- keep CRITICAL
        for location, aggregate in traversal_files.items():
            external_path = _resolve_external_location(model_dir, location)
            normalized_parts = [part for part in location.replace("\\", "/").split("/") if part]
            starts_with_parent = bool(normalized_parts and normalized_parts[0] == "..")
            has_traversal_raw = ".." in normalized_parts
            if has_traversal_raw and not starts_with_parent:
                cve_id = "CVE-2024-27318"
                cve_desc = (
                    "ONNX external_data path contains nested traversal sequences that bypass naive "
                    "sanitization (lstrip fix for CVE-2022-25882)"
                )
            else:
                cve_id = "CVE-2022-25882"
                cve_desc = "ONNX external_data location uses path traversal to access files outside the model directory"
            result.add_check(
                name=f"{cve_id}: External Data Path Traversal",
                passed=False,
                message=(
                    f"{cve_id}: External data path traversal '{location}' affects "
                    f"{aggregate.occurrence_count} tensor(s) and resolves outside the model directory"
                ),
                severity=IssueSeverity.CRITICAL,
                location=str(external_path),
                details={
                    "tensor": aggregate.tensor_samples[0],
                    "file": location,
                    "affected_tensor_count": aggregate.occurrence_count,
                    "sample_tensors": aggregate.tensor_samples,
                    "cve_id": cve_id,
                    "cvss": 7.5,
                    "cwe": "CWE-22",
                    "description": cve_desc,
                    "remediation": (
                        "Validate that external_data paths do not contain '..' or resolve outside the model "
                        "directory before loading. Update to ONNX >= 1.16.0."
                    ),
                },
                why=(
                    f"This ONNX model references external data via path '{location}' which escapes the model "
                    f"directory and can read arbitrary files ({cve_id})."
                ),
            )
            result.add_check(
                name="CVE-2025-51480: External Data Write Path Traversal",
                passed=False,
                message=(
                    f"CVE-2025-51480: External data path traversal for "
                    f"'{location}' ({aggregate.occurrence_count} tensor"
                    f"{'s' if aggregate.occurrence_count != 1 else ''} affected) can enable "
                    "arbitrary file overwrite when saving"
                ),
                severity=IssueSeverity.CRITICAL,
                location=str(external_path),
                details={
                    "file": location,
                    "affected_tensor_count": aggregate.occurrence_count,
                    "sample_tensors": aggregate.tensor_samples,
                    "cve_id": "CVE-2025-51480",
                    "cvss": 8.8,
                    "cwe": "CWE-22",
                    "description": (
                        "ONNX save_external_data writes tensor data to paths "
                        "from external_data location fields. Path traversal "
                        "can overwrite arbitrary files."
                    ),
                    "remediation": (
                        "Validate external_data paths before onnx.save(). "
                        "Update ONNX to a patched version and run model "
                        "processing with minimal filesystem privileges."
                    ),
                },
                why=(
                    "The model contains an external_data path that resolves "
                    "outside the model directory. If this model is saved with "
                    "external data, ONNX may overwrite arbitrary files "
                    "(CVE-2025-51480)."
                ),
            )

        _mark_onnx_result_reporting_incomplete(
            result,
            path,
            section="external data",
            omitted_count=omitted_external_results,
        )

    def _validate_external_size(
        self,
        tensor: Any,
        info: dict[str, str],
        external_path: Path,
        result: ScanResult,
    ) -> _OnnxExternalSizeValidation:
        try:
            offset = _parse_external_data_extent(info, "offset") or 0
            declared_length = _parse_external_data_extent(info, "length")
        except ValueError as e:
            return _OnnxExternalSizeValidation(
                category="invalid_metadata",
                passed=False,
                message=f"External data metadata is invalid: {e}",
                severity=IssueSeverity.CRITICAL,
                location=str(external_path),
                rule_code="S902",
                details={
                    "tensor": tensor.name,
                    "offset": info.get("offset"),
                    "length": info.get("length"),
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
            )

        try:
            dtype = _tensor_data_type_to_np_dtype(tensor.data_type)
            num_elem = 1
            for d in tensor.dims:
                num_elem *= d
            expected_size = int(num_elem) * int(dtype.itemsize)
            required_end = offset + (declared_length if declared_length is not None else expected_size)
            actual_size = external_path.stat().st_size
            if (
                offset > actual_size
                or required_end > actual_size
                or (declared_length is not None and declared_length < expected_size)
            ):
                return _OnnxExternalSizeValidation(
                    category="size_mismatch",
                    passed=False,
                    message="External data file size mismatch",
                    severity=IssueSeverity.CRITICAL,
                    location=str(external_path),
                    rule_code="S902",
                    details={
                        "tensor": tensor.name,
                        "expected_size": expected_size,
                        "actual_size": actual_size,
                        "offset": offset,
                        "length": declared_length,
                        "required_end": required_end,
                    },
                )
            return _OnnxExternalSizeValidation(
                category="size_match",
                passed=True,
                message="External data file size matches expected",
                severity=None,
                location=str(external_path),
                details={
                    "tensor": tensor.name,
                    "size": actual_size,
                    "offset": offset,
                    "length": declared_length,
                },
            )
        except Exception as e:
            _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
            return _OnnxExternalSizeValidation(
                category="validation_incomplete",
                passed=False,
                message=f"Failed to validate external data size: {e}",
                severity=IssueSeverity.INFO,
                location=str(external_path),
                rule_code="S902",
                details={
                    "tensor": tensor.name,
                    "data_type": int(tensor.data_type),
                    "exception": str(e),
                    "exception_type": type(e).__name__,
                },
            )

    def _check_tensor_sizes(self, model: Any, path: str, result: ScanResult) -> None:
        valid_count = 0
        valid_samples: list[dict[str, Any]] = []
        truncated_count = 0
        truncated_samples: list[dict[str, Any]] = []
        failure_count = 0
        failure_samples: list[dict[str, Any]] = []
        for tensor in model.graph.initializer:
            # Check for interrupts during tensor size validation
            self.check_interrupted()
            import onnx

            if tensor.data_location == onnx.TensorProto.EXTERNAL:
                continue
            if tensor.raw_data:
                try:
                    dtype = _tensor_data_type_to_np_dtype(tensor.data_type)
                    num_elem = 1
                    for d in tensor.dims:
                        num_elem *= d
                    expected_size = int(num_elem) * int(dtype.itemsize)
                    actual_size = len(tensor.raw_data)
                    if actual_size < expected_size:
                        truncated_count += 1
                        if len(truncated_samples) < 5:
                            truncated_samples.append(
                                {
                                    "tensor": tensor.name,
                                    "expected_size": expected_size,
                                    "actual_size": actual_size,
                                }
                            )
                    else:
                        valid_count += 1
                        if len(valid_samples) < 5:
                            valid_samples.append({"tensor": tensor.name, "size": actual_size})
                except Exception as e:
                    _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
                    failure_count += 1
                    if len(failure_samples) < 5:
                        failure_samples.append(
                            {
                                "tensor": tensor.name,
                                "data_type": int(tensor.data_type),
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                            }
                        )

        if truncated_count:
            result.add_check(
                name="Tensor Size Validation",
                passed=False,
                message=f"{truncated_count} ONNX tensor payload(s) appear truncated",
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S703",
                details={
                    "affected_tensor_count": truncated_count,
                    "sample_tensors": truncated_samples,
                    "samples_truncated": truncated_count > len(truncated_samples),
                },
            )
        if valid_count:
            result.add_check(
                name="Tensor Size Validation",
                passed=True,
                message=f"{valid_count} ONNX tensor payload size(s) are valid",
                location=path,
                details={
                    "validated_tensor_count": valid_count,
                    "sample_tensors": valid_samples,
                    "samples_truncated": valid_count > len(valid_samples),
                },
            )
        if failure_count:
            result.add_check(
                name="Tensor Validation",
                passed=False,
                message=f"Failed to validate {failure_count} ONNX tensor(s); analysis incomplete",
                severity=IssueSeverity.INFO,
                location=path,
                rule_code="S703",
                details={
                    "failed_tensor_count": failure_count,
                    "sample_failures": failure_samples,
                    "samples_truncated": failure_count > len(failure_samples),
                },
            )

    def _check_weight_distribution(self, model: Any, path: str, result: ScanResult) -> None:
        """Run bounded semantic weight analysis over eligible ONNX initializers."""
        try:
            import numpy as np
            import onnx
        except Exception as e:
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason="missing_dependency",
                message=f"Weight distribution analysis dependency unavailable: {e!s}",
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            return

        configured_max_array_size = self.config.get("max_array_size", _ONNX_WEIGHT_DEFAULT_MAX_ARRAY_SIZE)
        max_array_size = _configured_onnx_weight_array_limit(configured_max_array_size)

        def inline_storage_fits_budget(initializer: Any, _name: str, _estimated_bytes: int) -> bool:
            return max_array_size is None or _onnx_inline_storage_nbytes(initializer) <= max_array_size

        plan = _build_onnx_weight_analysis_plan(
            model,
            onnx=onnx,
            np=np,
            max_array_size=max_array_size,
            pre_materialization_check=inline_storage_fits_budget,
        )
        result.metadata["onnx_weight_distribution_semantics"] = plan.metadata

        coverage_incomplete = bool(
            plan.coverage_gaps
            or plan.external_initializers_skipped
            or plan.oversized_initializers_skipped
            or plan.extraction_failures
        )
        if coverage_incomplete:
            reason = "partial_initializer_coverage"
            if plan.coverage_gaps and not (
                plan.external_initializers_skipped or plan.oversized_initializers_skipped or plan.extraction_failures
            ):
                reason = next(iter(plan.coverage_gaps)) if len(plan.coverage_gaps) == 1 else "multiple_coverage_gaps"
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason=reason,
                message="Weight distribution analysis skipped one or more eligible ONNX initializers",
                details={
                    "eligible_initializers": plan.eligible_initializer_count,
                    "analyzed_initializers": plan.analyzed_initializer_count,
                    "external_initializers_skipped": plan.external_initializers_skipped,
                    "oversized_initializers_skipped": plan.oversized_initializers_skipped,
                    "extraction_failures": plan.extraction_failures,
                    "coverage_gaps": plan.coverage_gaps,
                    "unresolved_lineage_samples": plan.unresolved_lineage_samples,
                    "max_array_size": max_array_size,
                },
            )

        if not plan.specs:
            return

        try:
            if any(spec.matrix_analysis for spec in plan.specs):
                from scipy import stats as _stats  # noqa: F401

            # Lazy-import the weight distribution scanner to avoid circular deps
            # and heavy library loads when the scanner is not needed.
            from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner
        except Exception as e:
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason="missing_dependency",
                message=f"Weight distribution analysis dependency unavailable: {e!s}",
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            return

        try:
            wd_scanner = WeightDistributionScanner(self.config)
            analyzed = wd_scanner._analyze_onnx_weight_specs(plan.specs)
            for anomaly, spec in analyzed:
                details = dict(anomaly["details"])
                details.update(spec.context)
                result.add_check(
                    name="Weight Distribution Anomaly Detection",
                    passed=False,
                    message=anomaly["description"],
                    severity=anomaly["severity"],
                    location=path,
                    details=details,
                    why=anomaly.get("why"),
                )

            result.metadata["layers_analyzed"] = len(plan.specs)
            result.metadata["anomalies_found"] = len(analyzed)
            if plan.extraction_failures > 0:
                result.metadata["weight_extraction_failures"] = plan.extraction_failures
        except Exception as e:
            logger.warning("Weight distribution analysis failed (%s)", type(e).__name__)
            result.add_check(
                name="Weight Distribution Analysis",
                passed=False,
                message=f"Weight distribution analysis failed ({type(e).__name__})",
                severity=IssueSeverity.DEBUG,
                location=path,
                details={"exception_type": type(e).__name__},
            )
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason="analysis_failed",
                message=f"Weight distribution analysis failed ({type(e).__name__})",
                details={"exception_type": type(e).__name__},
            )

    def _mark_weight_distribution_incomplete(
        self,
        result: ScanResult,
        path: str,
        *,
        reason: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        _mark_inconclusive_scan_result(result, ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON)
        result.add_check(
            name="Weight Distribution Analysis Coverage",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=path,
            rule_code="S902",
            details={
                "scan_outcome_reason": ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON,
                "coverage_gap": reason,
                **(details or {}),
            },
        )

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract ONNX model metadata."""
        metadata = super().extract_metadata(file_path)

        if not _check_onnx():
            metadata["extraction_error"] = "ONNX library not available"
            return metadata

        try:
            import onnx

            model = onnx.load(file_path, load_external_data=False)

            # Basic model info
            metadata.update(
                {
                    "ir_version": model.ir_version,
                    "producer_name": model.producer_name,
                    "producer_version": model.producer_version,
                    "model_version": model.model_version,
                    "domain": model.domain,
                    "node_count": len(model.graph.node),
                }
            )

            # Opsets
            metadata["opset_imports"] = [
                {"domain": op.domain or "ai.onnx", "version": op.version} for op in model.opset_import
            ]

            # Inputs/outputs
            metadata["inputs"] = [
                {"name": inp.name, "type": onnx.helper.printable_type(inp.type)} for inp in model.graph.input
            ]
            metadata["outputs"] = [
                {"name": out.name, "type": onnx.helper.printable_type(out.type)} for out in model.graph.output
            ]

            # Operators used
            operators = sorted({node.op_type for node in model.graph.node})
            metadata["operators"] = operators

            # Custom domains
            local_function_identifiers = _model_local_function_identifiers(model)
            custom_domains = sorted(
                {
                    node.domain
                    for graph, opset_versions in _iter_model_graphs_with_opsets(model)
                    for node in _iter_graph_nodes(graph)
                    if _is_external_custom_operator(
                        node,
                        local_function_identifiers,
                        opset_versions,
                    )
                }
            )
            if custom_domains:
                metadata["custom_domains"] = custom_domains

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
