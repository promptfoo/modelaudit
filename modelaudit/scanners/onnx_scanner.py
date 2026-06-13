"""Scanner for ONNX model files (.onnx)."""

import hashlib
import logging
import math
import ntpath
import numbers
import os
import re
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

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
_ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT = 32
_ONNX_WEIGHT_NODE_VISIT_LIMIT = 200_000
_ONNX_WEIGHT_EDGE_VISIT_LIMIT = 1_000_000
_ONNX_INTEGER_SCALE_TRACE_DEPTH_LIMIT = 4
_ONNX_INTEGER_SCALE_TRACE_NODE_LIMIT = 32
_ONNX_WEIGHT_RETAINED_ARRAY_BUDGET_MULTIPLIER = 8
_ONNX_WEIGHT_RESHAPE_RANK_LIMIT = 64
_ONNX_WEIGHT_METADATA_TEXT_LIMIT = 256
_ONNX_WEIGHT_METADATA_SEQUENCE_LIMIT = 64
_ONNX_CUSTOM_OPERATOR_REPRESENTATIVE_LIMIT = 5
_ONNX_CUSTOM_OPERATOR_SAMPLE_LIMIT = 20
_ONNX_CUSTOM_OPERATOR_TEXT_LIMIT = 256
_ONNX_WEIGHT_DEFAULT_MAX_ARRAY_SIZE = 100 * 1024 * 1024
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
_QUANTIZED_WEIGHT_INPUT_METADATA: dict[tuple[str, int], tuple[int | None, int | None]] = {
    ("ConvInteger", 1): (None, 3),
    ("MatMulInteger", 0): (None, 2),
    ("MatMulInteger", 1): (None, 3),
    ("QLinearConv", 3): (4, 5),
    ("QLinearMatMul", 0): (1, 2),
    ("QLinearMatMul", 3): (4, 5),
}
_RECURRENT_WEIGHT_OPERATORS: frozenset[str] = frozenset({"GRU", "LSTM", "RNN"})
_WEIGHT_COMPUTING_LINEAGE_OPERATORS: frozenset[str] = frozenset(
    {
        "Conv",
        "ConvTranspose",
        "Einsum",
        "Gemm",
        "MatMul",
        "RandomNormalLike",
        "RandomUniformLike",
        *_RECURRENT_WEIGHT_OPERATORS,
    }
)


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


def _onnx_quantized_weight_input(node: Any, input_index: int) -> bool:
    if getattr(node, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS:
        return False
    return (str(getattr(node, "op_type", "")), input_index) in _QUANTIZED_WEIGHT_INPUT_METADATA


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

    if op_type in {"MatMulInteger", "QLinearMatMul"}:
        if not _onnx_quantized_weight_input(node, input_index):
            return None, "non_weight_input"
        if rank < 2:
            return None, "unsupported_weight_rank"
        batch_axes = tuple(range(rank - 2))
        if input_index == 0:
            return (*batch_axes, rank - 2), f"eligible_{op_type.lower()}_left_weight"
        return (*batch_axes, rank - 1), f"eligible_{op_type.lower()}_weight"

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

    if op_type in {"ConvInteger", "QLinearConv"}:
        if not _onnx_quantized_weight_input(node, input_index):
            return None, "non_weight_input"
        if rank < 3:
            return None, "unsupported_weight_rank"
        return (0,), f"eligible_{op_type.lower()}_weight"

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


def _iter_attribute_graphs(attribute: Any) -> Any:
    """Yield graph values declared by an ONNX attribute."""
    yield from attribute.graphs
    try:
        if attribute.HasField("g"):
            yield attribute.g
    except (ValueError, AttributeError):  # pragma: no cover - proto edge case
        pass


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


def _iter_graph_and_subgraphs(graph: Any) -> Any:
    """Yield an ONNX graph and every graph nested below node attributes."""
    yield graph
    for node in getattr(graph, "node", []):
        for attribute in getattr(node, "attribute", []):
            for subgraph in _iter_attribute_graphs(attribute):
                yield from _iter_graph_and_subgraphs(subgraph)


def _iter_model_initializer_graphs(model: Any) -> Any:
    """Yield every ONNX graph that can carry tensor initializers."""
    yield from _iter_graph_and_subgraphs(model.graph)
    for function in getattr(model, "functions", []):
        yield from _iter_graph_and_subgraphs(function)
        for attribute in getattr(function, "attribute_proto", []):
            for subgraph in _iter_attribute_graphs(attribute):
                yield from _iter_graph_and_subgraphs(subgraph)
    for training_info in getattr(model, "training_info", []):
        yield from _iter_graph_and_subgraphs(training_info.initialization)
        yield from _iter_graph_and_subgraphs(training_info.algorithm)


def _iter_attribute_external_data_tensors(attribute: Any) -> Any:
    """Yield tensor values declared by an ONNX attribute."""
    yield from getattr(attribute, "tensors", [])
    for sparse_tensor in getattr(attribute, "sparse_tensors", []):
        yield sparse_tensor.values
        yield sparse_tensor.indices
    try:
        if attribute.HasField("t"):
            yield attribute.t
        if attribute.HasField("sparse_tensor"):
            yield attribute.sparse_tensor.values
            yield attribute.sparse_tensor.indices
    except (ValueError, AttributeError):  # pragma: no cover - proto edge case
        pass


def _iter_graph_external_data_tensors(graph: Any) -> Any:
    """Yield graph-owned tensors that can carry external_data references."""
    yield from getattr(graph, "initializer", [])
    for sparse_tensor in getattr(graph, "sparse_initializer", []):
        yield sparse_tensor.values
        yield sparse_tensor.indices
    for node in getattr(graph, "node", []):
        for attribute in getattr(node, "attribute", []):
            yield from _iter_attribute_external_data_tensors(attribute)


def _iter_model_external_data_tensor_groups(model: Any) -> Any:
    """Yield model tensor groups that can declare external_data."""
    for graph in _iter_model_initializer_graphs(model):
        yield _iter_graph_external_data_tensors(graph)
    for function in getattr(model, "functions", []):
        for attribute in getattr(function, "attribute_proto", []):
            yield _iter_attribute_external_data_tensors(attribute)


def _model_has_external_data(model: Any) -> bool:
    """Return True when an ONNX model declares tensors stored in external_data."""
    for tensors in _iter_model_external_data_tensor_groups(model):
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
        if hasattr(model, "HasField") and not model.HasField("graph"):
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


def _onnx_tensor_expected_storage_nbytes(tensor: Any, *, onnx: Any) -> int:
    num_elements = math.prod(int(dimension) for dimension in tensor.dims)
    data_type = int(tensor.data_type)
    packed_bits = {
        int(getattr(onnx.TensorProto, name)): bits
        for name, bits in (
            ("INT2", 2),
            ("UINT2", 2),
            ("INT4", 4),
            ("UINT4", 4),
            ("FLOAT4E2M1", 4),
        )
        if hasattr(onnx.TensorProto, name)
    }.get(data_type)
    if packed_bits is not None:
        return (num_elements * packed_bits + 7) // 8
    return num_elements * int(_tensor_data_type_to_np_dtype(data_type).itemsize)


@dataclass(frozen=True)
class _OnnxWeightTransform:
    kind: str
    parameters: tuple[int, ...] = ()


@dataclass(frozen=True)
class _OnnxWeightQuantization:
    kind: str
    input_data_type: int | None = None
    scale_name: str | None = None
    zero_point_name: str | None = None
    axis: int | None = None
    scale_initializer_index: int | None = None
    zero_point_initializer_index: int | None = None
    output_data_type: int | None = None
    scale_factor_names: tuple[str, ...] = ()
    scale_factor_initializer_indexes: tuple[int, ...] = ()


@dataclass(frozen=True)
class _OnnxWeightLineage:
    initializer_index: int
    shape: tuple[int, ...] | None
    data_type: int | None
    transforms: tuple[_OnnxWeightTransform, ...] = ()
    unresolved_reason: str | None = None
    quantization: _OnnxWeightQuantization | None = None


@dataclass
class _OnnxWeightConsumerGroup:
    lineage: _OnnxWeightLineage
    node: Any
    node_index: int
    input_index: int
    output_axes: tuple[int, ...]
    analysis_kind: str
    group: int
    quantization: _OnnxWeightQuantization | None = None
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
        self.coverage_gaps[reason] = self.coverage_gaps.get(reason, 0) + count


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


def _resolve_onnx_axes(node: Any, constants: dict[str, Any], *, onnx: Any) -> tuple[int, ...] | None:
    for attribute in getattr(node, "attribute", ()):
        if attribute.name == "axes":
            return tuple(int(value) for value in attribute.ints)
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
    if _onnx_quantized_weight_input(node, input_index):
        return True
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
    if node.op_type in {"Einsum", "Gemm", "MatMul", "MatMulInteger", "QLinearMatMul"}:
        return True
    if node.op_type in {"Conv", "ConvTranspose", "ConvInteger", "QLinearConv"}:
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
    initializer_object_indexes: dict[int, int] = {}
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
            "analyzed_initializer_count": 0,
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
            "node_visit_count": 0,
            "node_visit_limit": _ONNX_WEIGHT_NODE_VISIT_LIMIT,
            "edge_visit_count": 0,
            "edge_visit_limit": _ONNX_WEIGHT_EDGE_VISIT_LIMIT,
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
    quantized_integer_types = {
        int(getattr(onnx.TensorProto, name))
        for name in (
            "INT2",
            "UINT2",
            "INT4",
            "UINT4",
            "INT8",
            "UINT8",
            "INT16",
            "UINT16",
            "INT32",
            "UINT32",
        )
        if hasattr(onnx.TensorProto, name)
    }

    def lineage_could_be_weight(lineage: _OnnxWeightLineage) -> bool:
        return (lineage.data_type is None or lineage.data_type in floating_types) and (
            lineage.shape is None or len(lineage.shape) >= 2
        )

    def lineage_could_be_quantized_weight(lineage: _OnnxWeightLineage) -> bool:
        return (lineage.data_type is None or lineage.data_type in quantized_integer_types) and (
            lineage.shape is None or len(lineage.shape) >= 2
        )

    def lineage_could_reach_weight_input(node: Any, input_index: int, lineage: _OnnxWeightLineage) -> bool:
        if _onnx_quantized_weight_input(node, input_index):
            return lineage_could_be_quantized_weight(lineage)
        return lineage_could_be_weight(lineage)

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

    groups: list[dict[tuple[Any, ...], _OnnxWeightConsumerGroup]] = []
    eligible_initializer_indexes: set[int] = set()
    terminal_consumer_counts: list[int] = []
    transform_counts: list[int] = []
    total_consumer_count = 0
    consumer_sample_count = 0
    node_counter = 0
    edge_counter = 0
    graph_counter = 0
    schema_cache: dict[tuple[str, str, int], bool] = {}

    def register_initializer(
        initializer: Any,
        graph_index: int,
        *,
        shape: tuple[int, ...] | None = None,
        unresolved_reason: str | None = None,
        source_key: tuple[Any, ...] | None = None,
    ) -> _OnnxWeightLineage:
        resolved_shape = shape if shape is not None else tuple(int(dimension) for dimension in initializer.dims)
        if source_key is not None and source_key in initializer_source_indexes:
            initializer_object_indexes[id(initializer)] = initializer_source_indexes[source_key]
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
        initializer_object_indexes[id(initializer)] = initializer_index
        if source_key is not None:
            initializer_source_indexes[source_key] = initializer_index
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
            **_bounded_onnx_metadata_fields(plan, "domain", getattr(node, "domain", "")),
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

    def infer_quantized_consumer_metadata(
        lineage: _OnnxWeightLineage,
        node: Any,
        input_index: int,
        output_axes: tuple[int, ...],
        constants: dict[str, Any],
        consumers_by_value: dict[str, list[Any]],
        producers_by_value: dict[str, Any],
        live_values: set[str],
        graph_output_names: set[str],
    ) -> tuple[_OnnxWeightQuantization | None, str | None]:
        if lineage.quantization is not None:
            return lineage.quantization, None
        if not _onnx_quantized_weight_input(node, input_index):
            return None, None

        scale_index, zero_point_index = _QUANTIZED_WEIGHT_INPUT_METADATA[(str(node.op_type), input_index)]
        scale_name: str | None = None
        zero_point_name: str | None = None
        scale_initializer_index: int | None = None
        scale_factor_names: tuple[str, ...] = ()
        scale_factor_initializer_indexes: tuple[int, ...] = ()
        output_data_type = int(onnx.TensorProto.FLOAT)

        def scale_initializer_names_in_expression(
            value_name: str,
            *,
            depth: int = 0,
            visited: frozenset[str] = frozenset(),
        ) -> tuple[str, ...] | None:
            if not value_name or value_name in visited or depth > _ONNX_INTEGER_SCALE_TRACE_DEPTH_LIMIT:
                return None
            if value_name in constants:
                tensor = constants[value_name]
                try:
                    return (value_name,) if int(tensor.data_type) in floating_types else None
                except (AttributeError, TypeError, ValueError):
                    return None
            producer = producers_by_value.get(value_name)
            if (
                producer is not None
                and getattr(producer, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and producer.op_type == "DynamicQuantizeLinear"
                and len(producer.output) > 1
                and str(producer.output[1]) == value_name
            ):
                return ()
            if (
                producer is None
                or getattr(producer, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS
                or producer.op_type not in {"Identity", "Mul"}
            ):
                return None
            discovered: list[str] = []
            discovered_by_source: list[tuple[str, ...]] = []
            next_visited = frozenset((*visited, value_name))
            for source_name in (str(source) for source in getattr(producer, "input", ()) if source):
                source_names = scale_initializer_names_in_expression(
                    source_name,
                    depth=depth + 1,
                    visited=next_visited,
                )
                if source_names is None:
                    return None
                discovered_by_source.append(source_names)
                discovered.extend(source_names)
            if producer.op_type == "Mul" and sum(bool(names) for names in discovered_by_source) != 1:
                return None
            return tuple(discovered)

        def infer_authoritative_integer_scale_name() -> tuple[str | None, str | None]:
            nonlocal output_data_type, scale_factor_names
            live_outputs = [
                str(output_name)
                for output_name in getattr(node, "output", ())
                if output_name and str(output_name) in live_values
            ]
            if not live_outputs or all(not consumers_by_value.get(output_name) for output_name in live_outputs):
                return None, None
            queue = [(output_name, 0) for output_name in live_outputs]
            visited_values: set[str] = set()
            visited_nodes = 0
            scale_names: list[str] = []
            reached_terminal = False
            current_data_type = int(onnx.TensorProto.FLOAT)
            scale_data_type: int | None = None
            while queue:
                value_name, depth = queue.pop(0)
                if not value_name or value_name in visited_values:
                    return None, "unresolved_quantized_weight_scale"
                visited_values.add(value_name)
                if depth > _ONNX_INTEGER_SCALE_TRACE_DEPTH_LIMIT:
                    return None, "unresolved_quantized_weight_scale"
                live_consumers = [
                    consumer
                    for consumer in consumers_by_value.get(value_name, [])
                    if any(str(output_name) in live_values for output_name in consumer.output if output_name)
                ]
                if value_name in graph_output_names:
                    if live_consumers:
                        return None, "unresolved_quantized_weight_scale"
                    reached_terminal = True
                    continue
                if len(live_consumers) != 1:
                    return None, "unresolved_quantized_weight_scale"
                consumer = live_consumers[0]
                visited_nodes += 1
                if (
                    visited_nodes > _ONNX_INTEGER_SCALE_TRACE_NODE_LIMIT
                    or getattr(consumer, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS
                ):
                    return None, "unresolved_quantized_weight_scale"
                next_values = [
                    str(output_name)
                    for output_name in consumer.output
                    if output_name and str(output_name) in live_values
                ]
                if not next_values:
                    return None, "unresolved_quantized_weight_scale"
                if consumer.op_type in {"Add", "Cast", "Identity"}:
                    if consumer.op_type == "Add":
                        add_inputs = [str(source) for source in consumer.input if source]
                        bias_names = [source for source in add_inputs if source != value_name]
                        expected_bias_type = (
                            int(onnx.TensorProto.INT32) if scale_data_type is None else current_data_type
                        )
                        if (
                            add_inputs.count(value_name) != 1
                            or len(bias_names) != 1
                            or bias_names[0] not in constants
                            or int(constants[bias_names[0]].data_type) != expected_bias_type
                        ):
                            return None, "unresolved_quantized_weight_scale"
                    elif consumer.op_type == "Cast":
                        cast_data_type = _onnx_int_attribute(consumer, "to", -1)
                        if cast_data_type not in floating_types:
                            return None, "unresolved_quantized_weight_scale"
                        current_data_type = cast_data_type
                        if scale_data_type is not None:
                            try:
                                current_itemsize = int(_tensor_data_type_to_np_dtype(current_data_type).itemsize)
                                output_itemsize = int(_tensor_data_type_to_np_dtype(output_data_type).itemsize)
                            except (KeyError, TypeError, ValueError):
                                return None, "unresolved_quantized_weight_scale"
                            if current_itemsize < output_itemsize:
                                output_data_type = current_data_type
                            elif current_itemsize == output_itemsize and current_data_type != output_data_type:
                                return None, "unresolved_quantized_weight_scale"
                    queue.extend((output_name, depth + 1) for output_name in next_values)
                    continue
                if consumer.op_type != "Mul":
                    return None, "unresolved_quantized_weight_scale"
                if scale_data_type is not None and scale_data_type != current_data_type:
                    return None, "unresolved_quantized_weight_scale"
                scale_data_type = current_data_type
                output_data_type = current_data_type
                for source_name in (str(source) for source in consumer.input if source and str(source) != value_name):
                    source_scale_names = scale_initializer_names_in_expression(source_name)
                    if source_scale_names is None:
                        return None, "unresolved_quantized_weight_scale"
                    scale_names.extend(source_scale_names)
                queue.extend((output_name, depth + 1) for output_name in next_values)

            if not reached_terminal:
                return None, "unresolved_quantized_weight_scale"

            axis = output_axes[-1] if output_axes else None
            non_scalar_names: list[str] = []
            scale_factor_names = tuple(scale_names)
            for candidate_name in scale_factor_names:
                tensor = constants.get(candidate_name)
                if tensor is None:
                    continue
                try:
                    shape = tuple(int(dimension) for dimension in tensor.dims)
                except (AttributeError, TypeError, ValueError):
                    return None, "unresolved_quantized_weight_scale"
                if math.prod(shape) == 1:
                    continue
                if lineage.shape is None or axis is None or not 0 <= axis < len(lineage.shape):
                    return None, "unresolved_quantized_weight_scale"
                if node.op_type == "ConvInteger":
                    channel_count = int(lineage.shape[0])
                    spatial_rank = max(len(lineage.shape) - 2, 0)
                    valid_shapes = {
                        (channel_count, *([1] * spatial_rank)),
                        (1, channel_count, *([1] * spatial_rank)),
                    }
                    if tuple(shape) in valid_shapes:
                        non_scalar_names.append(candidate_name)
                        continue
                    return None, "unresolved_quantized_weight_scale"
                if node.op_type != "MatMulInteger":
                    return None, "unresolved_quantized_weight_scale"
                expected_shape = list(lineage.shape)
                contraction_axis = len(expected_shape) - 1 if input_index == 0 else len(expected_shape) - 2
                expected_shape[contraction_axis] = 1
                if tuple(shape) == tuple(expected_shape) or (
                    input_index == 1 and len(shape) == 1 and int(shape[0]) == int(lineage.shape[axis])
                ):
                    non_scalar_names.append(candidate_name)
                    continue
                return None, "unresolved_quantized_weight_scale"
            unique_non_scalar_names = tuple(dict.fromkeys(non_scalar_names))
            if len(unique_non_scalar_names) > 1:
                return None, "unresolved_quantized_weight_scale"
            return (unique_non_scalar_names[0] if unique_non_scalar_names else None), None

        if scale_index is not None:
            if scale_index >= len(node.input) or not node.input[scale_index]:
                return None, "missing_quantized_weight_scale"
            scale_name = str(node.input[scale_index])
            if scale_name not in constants:
                return None, "missing_quantized_weight_scale"
            scale_initializer = constants[scale_name]
            scale_initializer_index = initializer_object_indexes.get(id(scale_initializer))
            if scale_initializer_index is None:
                return None, "missing_quantized_weight_scale"
            output_data_type = int(onnx.TensorProto.FLOAT)
        else:
            scale_name, scale_gap = infer_authoritative_integer_scale_name()
            if scale_gap is not None:
                return None, scale_gap
            resolved_scale_factor_indexes: list[int] = []
            for factor_name in scale_factor_names:
                factor = constants.get(factor_name)
                factor_index = initializer_object_indexes.get(id(factor)) if factor is not None else None
                if factor_index is None:
                    return None, "missing_quantized_weight_scale"
                resolved_scale_factor_indexes.append(factor_index)
            scale_factor_initializer_indexes = tuple(resolved_scale_factor_indexes)
            if scale_name is not None:
                scale_initializer = constants[scale_name]
                scale_initializer_index = initializer_object_indexes.get(id(scale_initializer))
                if scale_initializer_index is None:
                    return None, "missing_quantized_weight_scale"

        zero_point_initializer_index: int | None = None
        if zero_point_index is not None and zero_point_index < len(node.input) and node.input[zero_point_index]:
            zero_point_name = str(node.input[zero_point_index])
            if zero_point_name not in constants:
                return None, "missing_quantized_weight_zero_point"
            zero_point_initializer_index = initializer_object_indexes.get(id(constants[zero_point_name]))
            if zero_point_initializer_index is None:
                return None, "missing_quantized_weight_zero_point"

        axis = output_axes[-1] if output_axes else None
        return (
            _OnnxWeightQuantization(
                kind=node.op_type,
                input_data_type=lineage.data_type,
                scale_name=scale_name,
                zero_point_name=zero_point_name,
                axis=axis,
                scale_initializer_index=scale_initializer_index,
                zero_point_initializer_index=zero_point_initializer_index,
                output_data_type=output_data_type,
                scale_factor_names=scale_factor_names,
                scale_factor_initializer_indexes=scale_factor_initializer_indexes,
            ),
            None,
        )

    def add_consumer_group(
        lineage: _OnnxWeightLineage,
        node: Any,
        node_index: int,
        input_index: int,
        output_axes: tuple[int, ...],
        quantization: _OnnxWeightQuantization | None = None,
    ) -> None:
        nonlocal consumer_sample_count
        initializer = initializers[lineage.initializer_index]
        if int(initializer.data_type) not in floating_types and not (
            quantization is not None and int(initializer.data_type) in quantized_integer_types
        ):
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
            quantization,
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
                quantization=quantization,
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
    ) -> _OnnxWeightLineage:
        if any(getattr(attribute, "ref_attr_name", "") for attribute in getattr(node, "attribute", ())):
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=None,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "referenced_function_attribute",
                quantization=lineage.quantization,
            )
        if node.op_type == "Identity":
            return lineage
        if node.op_type == "Cast":
            target_data_type = _onnx_int_attribute(node, "to", -1)
            if target_data_type == lineage.data_type:
                return lineage
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=lineage.shape,
                data_type=target_data_type if target_data_type >= 0 else None,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "dtype_changing_cast_lineage",
                quantization=lineage.quantization,
            )
        if len(lineage.transforms) >= _ONNX_WEIGHT_TRANSFORM_DEPTH_LIMIT:
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=None,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "lineage_transform_depth_limit",
                quantization=lineage.quantization,
            )
        if lineage.shape is None:
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=None,
                data_type=lineage.data_type,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason or "lineage_shape_unavailable",
                quantization=lineage.quantization,
            )

        output_shape: tuple[int, ...]
        transform: _OnnxWeightTransform
        quantization = lineage.quantization
        output_data_type = lineage.data_type
        if node.op_type == "DequantizeLinear":
            scale_name = str(node.input[1]) if len(node.input) > 1 and node.input[1] else ""
            zero_point_name = str(node.input[2]) if len(node.input) > 2 and node.input[2] else None
            if not scale_name or scale_name not in constants:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=lineage.shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "missing_dequantize_scale",
                    quantization=lineage.quantization,
                )
            scale_initializer_index = initializer_object_indexes.get(id(constants[scale_name]))
            if scale_initializer_index is None:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=lineage.shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "missing_dequantize_scale",
                    quantization=lineage.quantization,
                )
            zero_point_initializer_index: int | None = None
            if zero_point_name is not None and zero_point_name not in constants:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=lineage.shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "missing_dequantize_zero_point",
                    quantization=lineage.quantization,
                )
            if zero_point_name is not None:
                zero_point_initializer_index = initializer_object_indexes.get(id(constants[zero_point_name]))
                if zero_point_initializer_index is None:
                    return _OnnxWeightLineage(
                        initializer_index=lineage.initializer_index,
                        shape=lineage.shape,
                        data_type=lineage.data_type,
                        transforms=lineage.transforms,
                        unresolved_reason=lineage.unresolved_reason or "missing_dequantize_zero_point",
                        quantization=lineage.quantization,
                    )
            if _onnx_int_attribute(node, "block_size", 0):
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=lineage.shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "blocked_dequantize_lineage_unsupported",
                    quantization=lineage.quantization,
                )
            scale_is_scalar = math.prod(int(dimension) for dimension in constants[scale_name].dims) == 1
            zero_point_is_scalar = zero_point_name is None or (
                math.prod(int(dimension) for dimension in constants[zero_point_name].dims) == 1
            )
            axis: int | None = None
            if not (scale_is_scalar and zero_point_is_scalar):
                axis = _onnx_int_attribute(node, "axis", 1)
                axis = axis if axis >= 0 else len(lineage.shape) + axis
                if axis < 0 or axis >= len(lineage.shape):
                    return _OnnxWeightLineage(
                        initializer_index=lineage.initializer_index,
                        shape=lineage.shape,
                        data_type=lineage.data_type,
                        transforms=lineage.transforms,
                        unresolved_reason=lineage.unresolved_reason or "invalid_dequantize_axis",
                        quantization=lineage.quantization,
                    )
            output_shape = lineage.shape
            transform = _OnnxWeightTransform("DequantizeLinear", () if axis is None else (axis,))
            output_data_type = _onnx_int_attribute(node, "output_dtype", 0) or int(constants[scale_name].data_type)
            if output_data_type not in floating_types:
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=lineage.shape,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "unsupported_dequantize_output_dtype",
                    quantization=lineage.quantization,
                )
            quantization = _OnnxWeightQuantization(
                kind="DequantizeLinear",
                input_data_type=lineage.data_type,
                scale_name=scale_name,
                zero_point_name=zero_point_name,
                axis=axis,
                scale_initializer_index=scale_initializer_index,
                zero_point_initializer_index=zero_point_initializer_index,
                output_data_type=output_data_type,
            )
        elif node.op_type in {"DynamicQuantizeLinear", "QuantizeLinear"}:
            return _OnnxWeightLineage(
                initializer_index=lineage.initializer_index,
                shape=lineage.shape,
                data_type=None,
                transforms=lineage.transforms,
                unresolved_reason=lineage.unresolved_reason
                or (
                    "dynamic_quantize_linear_lineage_unsupported"
                    if node.op_type == "DynamicQuantizeLinear"
                    else "quantize_linear_lineage_unsupported"
                ),
                quantization=lineage.quantization,
            )
        elif node.op_type == "Flatten":
            axis = _onnx_int_attribute(node, "axis", 1)
            axis = axis if axis >= 0 else len(lineage.shape) + axis
            if axis < 0 or axis > len(lineage.shape):
                return _OnnxWeightLineage(
                    initializer_index=lineage.initializer_index,
                    shape=None,
                    data_type=lineage.data_type,
                    transforms=lineage.transforms,
                    unresolved_reason=lineage.unresolved_reason or "invalid_flatten_lineage",
                    quantization=lineage.quantization,
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
                    quantization=lineage.quantization,
                )
            if node.op_type == "Squeeze":
                normalized_axes = tuple(axis if axis >= 0 else len(lineage.shape) + axis for axis in axes)
                if not normalized_axes:
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
                        quantization=lineage.quantization,
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
                        quantization=lineage.quantization,
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
                    quantization=lineage.quantization,
                )
            if permutation == tuple(range(len(lineage.shape))):
                return lineage
            transform = _OnnxWeightTransform("Transpose", permutation)
            output_shape = tuple(lineage.shape[index] for index in permutation)
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
                    quantization=lineage.quantization,
                )
            output_shape = resolved_shape
            transform = _OnnxWeightTransform("Reshape", output_shape)

        if (
            output_shape == lineage.shape
            and output_data_type == lineage.data_type
            and quantization == lineage.quantization
        ):
            return lineage

        return _OnnxWeightLineage(
            initializer_index=lineage.initializer_index,
            shape=output_shape,
            data_type=output_data_type,
            transforms=(*lineage.transforms, transform),
            unresolved_reason=lineage.unresolved_reason,
            quantization=quantization,
        )

    def bounded_lineages(lineages: dict[int, _OnnxWeightLineage]) -> dict[int, _OnnxWeightLineage]:
        if len(lineages) <= _ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT:
            return lineages
        plan.record_coverage_gap(
            "lineages_per_value_limit",
            len(lineages) - _ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT,
        )
        return dict(sorted(lineages.items())[:_ONNX_WEIGHT_LINEAGES_PER_VALUE_LIMIT])

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
                transforms=existing.transforms,
                unresolved_reason=unresolved_reason,
                quantization=existing.quantization if existing.quantization == lineage.quantization else None,
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
        bound_attributes: dict[str, Any] | None = None,
        bound_attribute_keys: dict[str, tuple[Any, ...]] | None = None,
        function_depth: int = 0,
        fail_on_unbound_inputs: bool = False,
        captured_state: tuple[
            dict[str, dict[int, _OnnxWeightLineage]],
            dict[str, Any],
            set[str],
        ]
        | None = None,
    ) -> tuple[list[dict[int, _OnnxWeightLineage]], list[bool]]:
        nonlocal edge_counter, graph_counter, node_counter, total_consumer_count
        current_graph_index = graph_counter
        graph_counter += 1
        if root_graph:
            value_lineages = dict(inherited_lineages)
            constants = dict(inherited_constants)
            dynamic_values = set(inherited_dynamic_values)
        else:
            declared_names = _graph_declared_value_names(current_graph)
            value_lineages = {
                name: lineages for name, lineages in inherited_lineages.items() if name not in declared_names
            }
            constants = {name: value for name, value in inherited_constants.items() if name not in declared_names}
            dynamic_values = {name for name in inherited_dynamic_values if name not in declared_names}

        value_lineages.update(bound_lineages or {})
        constants.update(bound_constants or {})
        dynamic_values.update(bound_dynamic_values or set())
        attribute_bindings = bound_attributes or {}
        attribute_binding_keys = bound_attribute_keys or {}
        known_value_shapes: dict[str, tuple[int, ...]] = {}
        for value_info in (
            *getattr(current_graph, "input", ()),
            *getattr(current_graph, "value_info", ()),
            *getattr(current_graph, "output", ()),
        ):
            name = _onnx_value_name(value_info)
            shape = value_info_shape(value_info)
            if name and shape is not None:
                known_value_shapes[name] = shape
        for name, lineages in value_lineages.items():
            lineage_shapes = {lineage.shape for lineage in lineages.values()}
            if len(lineage_shapes) == 1 and None not in lineage_shapes:
                known_value_shapes[name] = next(iter(lineage_shapes))  # type: ignore[arg-type]
        for name, constant in constants.items():
            try:
                known_value_shapes[name] = tuple(int(dimension) for dimension in constant.dims)
            except (AttributeError, TypeError, ValueError):
                continue
        graph_nodes = tuple(getattr(current_graph, "node", ()))
        if len(graph_nodes) > _ONNX_WEIGHT_NODE_VISIT_LIMIT - node_counter:
            plan.record_coverage_gap("node_visit_limit")
            return [], []
        consumers_by_value: dict[str, list[Any]] = {}
        producers_by_value: dict[str, Any] = {}
        indexed_edge_count = 0
        for graph_node in graph_nodes:
            indexed_edge_count += sum(1 for input_name in graph_node.input if input_name)
            indexed_edge_count += sum(1 for output_name in graph_node.output if output_name)
            if indexed_edge_count > _ONNX_WEIGHT_EDGE_VISIT_LIMIT - edge_counter:
                plan.record_coverage_gap("edge_visit_limit")
                return [], []
            for input_name in graph_node.input:
                if input_name:
                    consumers_by_value.setdefault(str(input_name), []).append(graph_node)
            for output_name in graph_node.output:
                if output_name:
                    producers_by_value[str(output_name)] = graph_node
        graph_output_names = {
            name for output in getattr(current_graph, "output", ()) if (name := _onnx_value_name(output))
        }
        live_values = set(graph_output_names)
        live_queue = list(graph_output_names)
        while live_queue:
            live_value = live_queue.pop()
            producer = producers_by_value.get(live_value)
            if producer is None:
                continue
            for input_name in (str(input_name) for input_name in producer.input if input_name):
                if input_name not in live_values:
                    live_values.add(input_name)
                    live_queue.append(input_name)

        def resolve_attribute(attribute: Any) -> Any | None:
            reference_name = str(getattr(attribute, "ref_attr_name", ""))
            return attribute_bindings.get(reference_name) if reference_name else attribute

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
                lineage = register_initializer(
                    initializer,
                    current_graph_index,
                    source_key=(*source_scope, "initializer", initializer_position),
                )
                value_lineages[name] = {lineage.initializer_index: lineage}
                constants[name] = initializer
                dynamic_values.discard(name)
                known_value_shapes[name] = lineage.shape or ()
        for sparse_position, sparse_initializer in enumerate(getattr(current_graph, "sparse_initializer", ())):
            if sparse_initializer.values.name:
                name = str(sparse_initializer.values.name)
                lineage = register_initializer(
                    sparse_initializer.values,
                    current_graph_index,
                    shape=tuple(int(dimension) for dimension in sparse_initializer.dims),
                    unresolved_reason="sparse_initializer_unsupported",
                    source_key=(*source_scope, "sparse_initializer", sparse_position),
                )
                value_lineages[name] = {lineage.initializer_index: lineage}
                dynamic_values.discard(name)
                known_value_shapes[name] = lineage.shape or ()

        for graph_input in getattr(current_graph, "input", ()):
            name = _onnx_value_name(graph_input)
            if name and name not in value_lineages and name not in constants:
                dynamic_values.add(name)

        for local_node_index, node in enumerate(graph_nodes):
            if node_counter >= _ONNX_WEIGHT_NODE_VISIT_LIMIT:
                plan.record_coverage_gap("node_visit_limit")
                break
            current_node_index = node_counter
            node_counter += 1
            edge_counter += len([input_name for input_name in node.input if input_name])
            edge_counter += len([output_name for output_name in node.output if output_name])
            if edge_counter > _ONNX_WEIGHT_EDGE_VISIT_LIMIT:
                plan.record_coverage_gap("edge_visit_limit")
                break
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
                "DequantizeLinear",
                "DynamicQuantizeLinear",
                "Flatten",
                "Identity",
                "QuantizeLinear",
                "Reshape",
                "Squeeze",
                "Transpose",
                "Unsqueeze",
            }
            all_input_lineages: dict[int, _OnnxWeightLineage] = {}
            terminal_weight_lineages: set[int] = set()
            activation_input_lineages: set[int] = set()
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
            all_lineage_inputs_are_activation_contraction = (
                getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                and node.op_type in {"Einsum", "MatMul"}
                and len(lineage_input_indexes) >= 2
                and lineage_input_indexes == dynamic_activation_input_indexes
            )

            for input_index, input_name in enumerate(node.input):
                input_lineages = value_lineages.get(str(input_name), {})
                is_array_feature_selector = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") == "ai.onnx.ml"
                    and node.op_type == "ArrayFeatureExtractor"
                    and input_index == 1
                )
                is_non_data_standard_input = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and ((node.op_type == "Clip" and input_index > 0) or (node.op_type == "Where" and input_index == 0))
                )
                if not is_array_feature_selector and not is_non_data_standard_input:
                    merge_lineages(
                        all_input_lineages,
                        input_lineages,
                        ambiguous_reason="ambiguous_operator_input_lineage",
                    )
                for initializer_index, lineage in input_lineages.items():
                    invalid_clip_bound = (
                        is_registered_standard_operator
                        and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                        and node.op_type == "Clip"
                        and input_index > 0
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
                                quantization=lineage.quantization,
                            ),
                            node,
                            current_node_index,
                            input_index,
                        )
                    potential_weight_input = _onnx_potential_weight_input(
                        node,
                        input_index,
                        is_model_local_function=is_model_local_function,
                        is_registered_standard_operator=is_registered_standard_operator,
                    ) and lineage_could_reach_weight_input(node, input_index, lineage)
                    if supported_transform and input_index == 0:
                        continue
                    if potential_weight_input:
                        terminal_weight_lineages.add(initializer_index)
                    terminal_consumer_counts[initializer_index] += 1
                    total_consumer_count += 1
                    if lineage.unresolved_reason is not None:
                        opposite_resolved_weight = any(
                            resolved_index != input_index for resolved_index in resolved_weight_input_indexes
                        )
                        prior_layer_activation = lineage.unresolved_reason == "dynamic_activation_lineage"
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
                        if recognized_activation_input:
                            if opposite_resolved_weight:
                                activation_input_lineages.add(initializer_index)
                            record_exclusion(initializer_index, "dynamic_activation_input", node, input_index)
                        elif potential_weight_input:
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
                                    quantization=lineage.quantization,
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
                                    quantization=lineage.quantization,
                                ),
                                node,
                                current_node_index,
                                input_index,
                            )
                        else:
                            record_exclusion(initializer_index, reason, node, input_index)
                        continue
                    quantization, quantization_gap = infer_quantized_consumer_metadata(
                        lineage,
                        node,
                        input_index,
                        output_axes,
                        constants,
                        consumers_by_value,
                        producers_by_value,
                        live_values,
                        graph_output_names,
                    )
                    if quantization_gap is not None:
                        record_unresolved_lineage(
                            _OnnxWeightLineage(
                                initializer_index=initializer_index,
                                shape=lineage.shape,
                                data_type=lineage.data_type,
                                transforms=lineage.transforms,
                                unresolved_reason=quantization_gap,
                                quantization=lineage.quantization,
                            ),
                            node,
                            current_node_index,
                            input_index,
                        )
                        continue
                    add_consumer_group(
                        lineage,
                        node,
                        current_node_index,
                        input_index,
                        output_axes,
                        quantization=quantization,
                    )
                    if node.op_type == "Gather":
                        gather_axis = _onnx_gather_axis(node, len(lineage.shape or ()))
                        if gather_axis is not None and (gather_axis,) != output_axes:
                            add_consumer_group(
                                lineage,
                                node,
                                current_node_index,
                                input_index,
                                (gather_axis,),
                                quantization=quantization,
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
                                    quantization=quantization,
                                )

            subgraph_results: list[tuple[list[dict[int, _OnnxWeightLineage]], list[bool]]] = []
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
                    input_pairs: Iterable[tuple[Any, Any]]
                    if node.op_type == "Loop":
                        input_pairs = zip(node.input[2:], subgraph.input[2:], strict=False)
                    elif node.op_type == "Scan":
                        input_pairs = zip(node.input, subgraph.input, strict=False)
                    else:
                        input_pairs = ()
                    for parent_input, graph_input in input_pairs:
                        parent_name = str(parent_input)
                        graph_input_name = _onnx_value_name(graph_input)
                        if parent_name in value_lineages:
                            subgraph_bound_lineages[graph_input_name] = value_lineages[parent_name]
                        if parent_name in constants:
                            subgraph_bound_constants[graph_input_name] = constants[parent_name]
                        if parent_name in dynamic_values:
                            subgraph_bound_dynamic.add(graph_input_name)
                    subgraph_results.append(
                        walk_graph(
                            subgraph,
                            value_lineages,
                            constants,
                            dynamic_values,
                            root_graph=False,
                            source_scope=(*resolved_attribute_key, "graph", subgraph_position),
                            opset_versions=opset_versions,
                            bound_lineages=subgraph_bound_lineages,
                            bound_constants=subgraph_bound_constants,
                            bound_dynamic_values=subgraph_bound_dynamic,
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
                                quantization=lineage.quantization,
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
                        bound_attributes=function_bound_attributes,
                        bound_attribute_keys=function_bound_attribute_keys,
                        function_depth=function_depth + 1,
                        fail_on_unbound_inputs=fail_on_unbound_inputs,
                    ),
                )

            output_lineages: dict[int, _OnnxWeightLineage] = {}
            if supported_transform:
                data_lineages = value_lineages.get(str(node.input[0]), {}) if node.input else {}
                for initializer_index, lineage in data_lineages.items():
                    transform_counts[initializer_index] += 1
                    output_lineages[initializer_index] = transformed_lineage(lineage, node, constants)
            elif all_input_lineages and function is None and not subgraph_results:
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
                weight_computing_lineage = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and node.op_type in _WEIGHT_COMPUTING_LINEAGE_OPERATORS
                )
                unmodeled_standard_operator_lineage = (
                    is_registered_standard_operator
                    and getattr(node, "domain", "") in _STANDARD_NEURAL_NETWORK_DOMAINS
                    and not (
                        same_type_elementwise
                        or same_type_unary_elementwise
                        or clip_operator
                        or pow_operator
                        or prelu_data_is_activation
                        or weight_computing_lineage
                    )
                )
                unknown_operator_lineage = (
                    not is_registered_standard_operator
                    or getattr(node, "domain", "") not in _STANDARD_NEURAL_NETWORK_DOMAINS
                )
                propagates_lineage = (
                    same_type_elementwise
                    or same_type_unary_elementwise
                    or clip_operator
                    or pow_operator
                    or prelu_data_is_activation
                    or weight_computing_lineage
                    or unknown_operator_lineage
                    or unmodeled_standard_operator_lineage
                )
                if propagates_lineage:
                    elementwise_output_shape = (
                        broadcast_shapes(known_value_shapes.get(input_name) for input_name in input_names)
                        if same_type_elementwise or same_type_unary_elementwise or pow_operator
                        else known_value_shapes.get(input_names[0])
                        if clip_operator and input_names
                        else None
                    )
                    carries_dynamic_activation = bool(terminal_weight_lineages) and has_dynamic_input
                    carries_dynamic_activation |= prelu_data_is_activation
                    carries_dynamic_activation |= any(
                        lineage.unresolved_reason == "dynamic_activation_lineage"
                        for lineage in all_input_lineages.values()
                    )
                    for initializer_index, lineage in all_input_lineages.items():
                        if initializer_index in activation_input_lineages:
                            continue
                        unresolved_reason = lineage.unresolved_reason
                        if unresolved_reason is None:
                            if carries_dynamic_activation:
                                unresolved_reason = "dynamic_activation_lineage"
                            else:
                                unresolved_reason = (
                                    "dynamic_input_lineage" if has_dynamic_input else "unsupported_lineage_operator"
                                )
                        output_lineages[initializer_index] = _OnnxWeightLineage(
                            initializer_index=initializer_index,
                            shape=elementwise_output_shape,
                            data_type=(
                                lineage.data_type
                                if same_type_elementwise or same_type_unary_elementwise or clip_operator
                                else None
                            ),
                            transforms=lineage.transforms,
                            unresolved_reason=unresolved_reason,
                            quantization=lineage.quantization,
                        )

            output_lineages = bounded_lineages(output_lineages)
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
                        try:
                            if resolved_attribute.HasField("t"):
                                constant_tensor = resolved_attribute.t
                        except (AttributeError, ValueError):
                            constant_tensor = None
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
                    elif attribute.name == "sparse_value":
                        try:
                            if resolved_attribute.HasField("sparse_tensor"):
                                sparse_constant = resolved_attribute.sparse_tensor
                        except (AttributeError, ValueError):
                            sparse_constant = None
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
                    )
                    constants[name] = constant_tensor
                    constant_output_lineages[name] = {lineage.initializer_index: lineage}
                    constant_output_names.add(name)
                elif sparse_constant is not None:
                    name = output_names[0]
                    sparse_constant.values.name = name
                    lineage = register_initializer(
                        sparse_constant.values,
                        current_graph_index,
                        shape=tuple(int(dimension) for dimension in sparse_constant.dims),
                        unresolved_reason="sparse_constant_unsupported",
                        source_key=constant_source_key,
                    )
                    constant_output_lineages[name] = {lineage.initializer_index: lineage}
                    constant_output_names.add(name)
                elif unresolved_constant_attribute:
                    name = output_names[0]
                    unresolved_tensor = onnx.TensorProto()
                    unresolved_tensor.name = name
                    lineage = register_initializer(
                        unresolved_tensor,
                        current_graph_index,
                        unresolved_reason="unresolved_constant_attribute",
                        source_key=(*source_scope, "node", local_node_index, "unresolved_constant"),
                    )
                    constant_output_lineages[name] = {lineage.initializer_index: lineage}
                    constant_output_names.add(name)

            subgraph_output_lineages: list[dict[int, _OnnxWeightLineage]] = [{} for _ in node.output]
            subgraph_output_dynamic = [False for _ in node.output]
            subgraph_output_offset = 1 if node.op_type == "Loop" else 0
            for graph_output_lineages, graph_output_dynamic in subgraph_results:
                for output_index in range(len(node.output)):
                    graph_output_index = output_index + subgraph_output_offset
                    if graph_output_index >= len(graph_output_lineages):
                        continue
                    merge_lineages(
                        subgraph_output_lineages[output_index],
                        graph_output_lineages[graph_output_index],
                        ambiguous_reason="ambiguous_subgraph_output_lineage",
                    )
                    subgraph_output_dynamic[output_index] |= graph_output_dynamic[graph_output_index]

            for output_index, output_name in enumerate(node.output):
                if not output_name:
                    continue
                name = str(output_name)
                per_output_lineages = (
                    {}
                    if supported_transform and node.op_type == "DynamicQuantizeLinear" and output_index != 0
                    else dict(output_lineages)
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
                            quantization=lineage.quantization,
                        )
                        for initializer_index, lineage in per_output_lineages.items()
                    }
                per_output_lineages = bounded_lineages(per_output_lineages)
                if per_output_lineages:
                    value_lineages[name] = per_output_lineages
                    lineage_shapes = {lineage.shape for lineage in per_output_lineages.values()}
                    if len(lineage_shapes) == 1 and None not in lineage_shapes:
                        known_value_shapes[name] = next(iter(lineage_shapes))  # type: ignore[arg-type]
                else:
                    value_lineages.pop(name, None)
                    if name in constants:
                        with suppress(AttributeError, TypeError, ValueError):
                            known_value_shapes[name] = tuple(int(dimension) for dimension in constants[name].dims)

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

        return (
            [dict(value_lineages.get(_onnx_value_name(graph_output), {})) for graph_output in current_graph.output],
            [_onnx_value_name(graph_output) in dynamic_values for graph_output in current_graph.output],
        )

    root_state_lineages: dict[str, dict[int, _OnnxWeightLineage]] = {}
    root_state_constants: dict[str, Any] = {}
    root_state_dynamic: set[str] = set()
    root_output_lineages, _root_output_dynamic = walk_graph(
        graph,
        {},
        {},
        set(),
        root_graph=True,
        source_scope=("root_graph",),
        opset_versions=model_opset_versions,
        captured_state=(root_state_lineages, root_state_constants, root_state_dynamic),
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
        tuple[Any, list[dict[int, _OnnxWeightLineage]], list[bool]],
    ] = {}
    algorithm_initializer_lineages: dict[int, dict[str, dict[int, _OnnxWeightLineage]]] = {}
    for source_scope, training_graph in analysis_graph_roots[1:]:
        is_algorithm = source_scope[2] == "algorithm"
        output_lineages, output_dynamic = walk_graph(
            training_graph,
            root_state_lineages if is_algorithm else {},
            root_state_constants if is_algorithm else {},
            root_state_dynamic if is_algorithm else set(),
            root_graph=True,
            source_scope=source_scope,
            opset_versions=model_opset_versions,
            fail_on_unbound_inputs=True,
        )
        training_graph_results[source_scope] = (training_graph, output_lineages, output_dynamic)
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
                training_graph, output_lineages, _output_dynamic = graph_result
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
                    or lineage_could_be_quantized_weight(lineage)
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

    def load_quantization_parameter(
        initializer_index: int | None,
        *,
        name: str | None,
        role: str,
    ) -> Any:
        if initializer_index is None:
            raise ValueError(f"Quantized weight {role} initializer is unavailable")
        parameter = initializers[initializer_index]
        if _onnx_tensor_uses_external_storage(parameter, onnx=onnx):
            raise ValueError(f"Quantized weight {role} initializer uses external data")
        numel = math.prod(int(dimension) for dimension in parameter.dims)
        itemsize = int(_tensor_data_type_to_np_dtype(parameter.data_type).itemsize)
        estimated_bytes = numel * itemsize
        bounded_name, _, _ = _bounded_onnx_metadata_text(plan, name or parameter.name)
        if (
            estimated_bytes < 0
            or (max_array_size is not None and max_array_size > 0 and estimated_bytes > max_array_size)
            or (
                pre_materialization_check is not None
                and not pre_materialization_check(parameter, bounded_name, estimated_bytes)
            )
        ):
            raise ValueError(f"Quantized weight {role} initializer exceeds analysis budget")
        return onnx.numpy_helper.to_array(parameter)

    def reshape_quantization_parameter(
        parameter: Any,
        *,
        axis: int | None,
        target_shape: tuple[int, ...],
        role: str,
        analysis_dtype: Any,
        allow_multidirectional_broadcast: bool,
    ) -> Any:
        parameter = np.asarray(parameter, dtype=analysis_dtype)
        if role == "scale" and (not np.all(np.isfinite(parameter)) or bool(np.any(parameter <= 0))):
            raise ValueError("Quantized weight scale must be finite and positive")
        if parameter.size == 1:
            return parameter.reshape(())
        if axis is None or axis < 0 or axis >= len(target_shape):
            raise ValueError(f"Quantized weight {role} axis is invalid")
        if parameter.ndim > 1:
            if not allow_multidirectional_broadcast:
                raise ValueError(f"Quantized weight {role} must be scalar or one-dimensional")
            if parameter.ndim != len(target_shape) or axis not in {len(target_shape) - 2, len(target_shape) - 1}:
                raise ValueError(f"Quantized weight {role} shape is incompatible with weight shape")
            contraction_axis = len(target_shape) - 1 if axis == len(target_shape) - 2 else len(target_shape) - 2
            expected_shape = list(target_shape)
            expected_shape[contraction_axis] = 1
            if tuple(int(dimension) for dimension in parameter.shape) != tuple(expected_shape):
                raise ValueError(f"Quantized weight {role} shape is incompatible with weight shape")
            return parameter
        if parameter.ndim != 1 or int(parameter.shape[0]) != int(target_shape[axis]):
            raise ValueError(f"Quantized weight {role} shape is incompatible with weight axis")
        broadcast_shape = [1] * len(target_shape)
        broadcast_shape[axis] = int(target_shape[axis])
        return parameter.reshape(tuple(broadcast_shape))

    def materialize_quantized_weights(weights: Any, quantization: _OnnxWeightQuantization) -> Any:
        if quantization.scale_name is None and quantization.kind not in {"ConvInteger", "MatMulInteger"}:
            raise ValueError("Quantized weight scale initializer is unavailable")
        target_shape = tuple(int(dimension) for dimension in weights.shape)
        analysis_dtype = np.dtype(
            _tensor_data_type_to_np_dtype(quantization.output_data_type or int(onnx.TensorProto.FLOAT))
        )
        allow_multidirectional_broadcast = quantization.kind in {"MatMulInteger", "QLinearMatMul"}
        scale_factor_pairs = (
            list(zip(quantization.scale_factor_names, quantization.scale_factor_initializer_indexes, strict=True))
            if quantization.scale_factor_names
            else [(quantization.scale_name, quantization.scale_initializer_index)]
            if quantization.scale_name is not None
            else []
        )
        raw_scales = [
            load_quantization_parameter(initializer_index, name=name, role="scale")
            for name, initializer_index in scale_factor_pairs
        ]
        if quantization.kind == "ConvInteger":
            channel_count = int(target_shape[0])
            spatial_rank = max(len(target_shape) - 2, 0)
            valid_scale_shapes = {
                (channel_count, *([1] * spatial_rank)),
                (1, channel_count, *([1] * spatial_rank)),
            }
            raw_scales = [
                np.asarray(raw_scale).reshape((channel_count,))
                if np.asarray(raw_scale).shape in valid_scale_shapes
                else raw_scale
                for raw_scale in raw_scales
            ]
        raw_zero_point = (
            load_quantization_parameter(
                quantization.zero_point_initializer_index,
                name=quantization.zero_point_name,
                role="zero_point",
            )
            if quantization.zero_point_name is not None
            else None
        )
        for _, scale_initializer_index in scale_factor_pairs:
            if scale_initializer_index is None:
                raise ValueError("Quantized weight scale initializer is unavailable")
            scale_initializer = initializers[scale_initializer_index]
            if int(scale_initializer.data_type) not in floating_types:
                raise ValueError("Quantized weight scale must use a floating-point data type")
        if quantization.zero_point_initializer_index is not None and quantization.input_data_type is not None:
            zero_point_initializer = initializers[quantization.zero_point_initializer_index]
            if int(zero_point_initializer.data_type) != int(quantization.input_data_type):
                raise ValueError("Quantized weight zero point must match the weight data type")
        if (
            quantization.kind in {"DequantizeLinear", "QLinearConv", "QLinearMatMul"}
            and raw_scales
            and raw_zero_point is not None
            and np.asarray(raw_scales[0]).shape != np.asarray(raw_zero_point).shape
        ):
            raise ValueError("Quantized weight scale and zero point must have matching shapes")
        scales = [
            reshape_quantization_parameter(
                raw_scale,
                axis=quantization.axis,
                target_shape=target_shape,
                role="scale",
                analysis_dtype=analysis_dtype,
                allow_multidirectional_broadcast=allow_multidirectional_broadcast,
            )
            for raw_scale in raw_scales
        ]
        dequantized = weights.astype(analysis_dtype, copy=True)
        if raw_zero_point is not None:
            zero_point = reshape_quantization_parameter(
                raw_zero_point,
                axis=quantization.axis,
                target_shape=target_shape,
                role="zero_point",
                analysis_dtype=analysis_dtype,
                allow_multidirectional_broadcast=allow_multidirectional_broadcast,
            )
            np.subtract(dequantized, zero_point, out=dequantized, casting="unsafe")
        for scale in scales:
            with np.errstate(over="ignore", invalid="ignore"):
                np.multiply(dequantized, scale, out=dequantized, casting="unsafe")
        return dequantized

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
            quantized_item_sizes = [
                int(
                    np.dtype(
                        _tensor_data_type_to_np_dtype(
                            consumer_group.quantization.output_data_type or int(onnx.TensorProto.FLOAT)
                        )
                    ).itemsize
                )
                for consumer_group in initializer_groups.values()
                if consumer_group.quantization is not None
            ]
            analysis_itemsize = max([itemsize, *quantized_item_sizes])
            estimated_bytes = numel * analysis_itemsize
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
            quantized_views: dict[tuple[tuple[_OnnxWeightTransform, ...], _OnnxWeightQuantization], Any] = {}
            for consumer_group in initializer_groups.values():
                analysis_materialization = "zero_copy_view_chunked_reduction"
                if consumer_group.quantization is not None:
                    quantized_key = (consumer_group.lineage.transforms, consumer_group.quantization)
                    transformed = quantized_views.get(quantized_key)
                    if transformed is None:
                        transformed = array
                        quantization_applied = False
                        for transform in consumer_group.lineage.transforms:
                            if transform.kind == "Identity":
                                continue
                            if transform.kind == "DequantizeLinear":
                                transformed = materialize_quantized_weights(transformed, consumer_group.quantization)
                                if retain_array_check is not None and not retain_array_check(
                                    bounded_name,
                                    int(transformed.nbytes),
                                ):
                                    raise ValueError("Quantized weight dequantization exceeds retained array budget")
                                quantization_applied = True
                                continue
                            transform_input = transformed
                            if transform.kind == "Transpose":
                                transformed = np.transpose(transformed, axes=transform.parameters)
                            elif transform.kind == "Reshape":
                                transformed = np.reshape(transformed, transform.parameters)
                            if transformed.size and not np.shares_memory(transform_input, transformed):
                                if not quantization_applied:
                                    raise RuntimeError("ONNX weight lineage transform requires a full-tensor copy")
                                if retain_array_check is not None and not retain_array_check(
                                    bounded_name,
                                    int(transformed.nbytes),
                                ):
                                    raise ValueError("Post-dequantization transform exceeds retained array budget")
                        if not quantization_applied:
                            transformed = materialize_quantized_weights(transformed, consumer_group.quantization)
                            if retain_array_check is not None and not retain_array_check(
                                bounded_name,
                                int(transformed.nbytes),
                            ):
                                raise ValueError("Quantized weight dequantization exceeds retained array budget")
                        quantized_views[quantized_key] = transformed
                    analysis_materialization = "bounded_quantized_dequantize_copy"
                    analysis_storage_shares_memory = False
                else:
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
                    analysis_storage_shares_memory = bool(array.size == 0 or np.shares_memory(array, transformed))

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
                if (
                    consumer_group.quantization is None
                    and tensor_weights.size
                    and not np.shares_memory(array, tensor_weights)
                ):
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
                quantization_context = (
                    {
                        "quantization_kind": consumer_group.quantization.kind,
                        "quantization_scale": consumer_group.quantization.scale_name,
                        "quantization_zero_point": consumer_group.quantization.zero_point_name,
                        "quantization_axis": consumer_group.quantization.axis,
                        "quantization_scale_initializer_index": consumer_group.quantization.scale_initializer_index,
                        "quantization_scale_factor_names": list(consumer_group.quantization.scale_factor_names),
                        "quantization_scale_factor_initializer_indexes": list(
                            consumer_group.quantization.scale_factor_initializer_indexes
                        ),
                        "quantization_zero_point_initializer_index": (
                            consumer_group.quantization.zero_point_initializer_index
                        ),
                        "quantization_output_data_type": consumer_group.quantization.output_data_type,
                    }
                    if consumer_group.quantization is not None
                    else {}
                )
                context = {
                    "analysis_id": analysis_id,
                    **_bounded_onnx_metadata_fields(plan, "initializer", initializer.name),
                    "initializer_graph_index": initializer_graph_indexes[initializer_index],
                    "consumer_domain": first_consumer["domain"],
                    "consumer_domain_length": first_consumer["domain_length"],
                    "consumer_domain_truncated": first_consumer["domain_truncated"],
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
                    "analysis_storage_shares_memory": analysis_storage_shares_memory,
                    "analysis_materialization": analysis_materialization,
                    "quantized_weight": consumer_group.quantization is not None,
                    **quantization_context,
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
        "analyzed_initializer_count": plan.analyzed_initializer_count,
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
        "node_visit_count": node_counter,
        "node_visit_limit": _ONNX_WEIGHT_NODE_VISIT_LIMIT,
        "edge_visit_count": edge_counter,
        "edge_visit_limit": _ONNX_WEIGHT_EDGE_VISIT_LIMIT,
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
    if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME:
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


class OnnxScanner(BaseScanner):
    """Scanner for ONNX model files."""

    name = "onnx"
    description = "Scans ONNX models for custom operators and integrity issues"
    supported_extensions: ClassVar[list[str]] = [".onnx"]

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

        # Read raw bytes first so successful scans can parse and run raw
        # detectors from the same buffer. If this read fails, fall back to
        # ONNX's path-based loader so structural analysis still has a chance
        # to complete while raw detector coverage stays explicitly incomplete.
        model_data: bytes | None = None
        try:
            self.check_interrupted()
            with open(path, "rb") as f:
                model_data = f.read()
            self.check_interrupted()
        except Exception as e:
            logger.warning("Raw ONNX detector input read failed: %s", e)
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
            model = (
                onnx.load(path, load_external_data=False)
                if model_data is None
                else onnx.load_model_from_string(model_data)
            )
            # Check for interrupts after loading completes.
            self.check_interrupted()
            result.bytes_scanned = file_size
        except KeyboardInterrupt:
            # Re-raise keyboard interrupt for graceful shutdown
            raise
        except Exception as e:  # pragma: no cover - unexpected parse errors
            result.bytes_scanned = file_size
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
                        "exception": str(e),
                        "exception_type": type(e).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": ONNX_TENTATIVE_CANDIDATE_PARSE_INCOMPLETE_REASON,
                    },
                    rule_code="S902",
                )
                _finish_scan_result(result)
                return result
            result.add_check(
                name="ONNX Model Parsing",
                passed=False,
                message=f"Error parsing ONNX model: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        has_graph = model.HasField("graph")
        if model.ir_version <= 0 or not has_graph:
            if self._is_tentative_protobuf_route() and not has_graph:
                result.scanner_name = "unknown"
                result.metadata["tentative_protobuf_candidate_rejected"] = True
                result.finish(success=True)
                return result
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
            elif _model_has_external_data(model):
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
            check_jit = self._get_bool_config("check_jit_script", True)
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
            else:
                result.metadata.setdefault("disabled_checks", []).append("JIT/Script Code Execution Detection")

            check_net = self._get_bool_config("check_network_comm", True)
            if check_net:
                try:
                    network_findings = self.collect_network_communication_findings(
                        model_data,
                        context=path,
                        raise_on_error=True,
                    )
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
                else:
                    self.add_network_communication_findings(
                        network_findings,
                        result,
                        context=path,
                    )
            else:
                result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")

        self._check_custom_ops(model, path, result)
        self._check_external_data(model, path, result)
        self._check_tensor_sizes(model, path, result)
        if _onnx_format_integrity_validated(result):
            result.metadata[VALIDATED_FORMAT_METADATA_KEY] = self.name
        self._check_weight_distribution(model, path, result)

        _finish_scan_result(result)
        return result

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
        custom_domains = set()
        local_function_identifiers = _model_local_function_identifiers(model)
        custom_domain_findings: dict[str, _CustomOperatorAggregate] = {}
        explicit_custom_operator_findings: dict[tuple[str, str, str], _CustomOperatorAggregate] = {}
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
                    if is_external_custom_operator:
                        domain = str(node.domain or "")
                        custom_domains.add(domain)
                        custom_domain_findings.setdefault(domain, _CustomOperatorAggregate()).add_node(node)
                    else:
                        explicit_custom_operator_findings.setdefault(
                            _operator_identifier(node),
                            _CustomOperatorAggregate(),
                        ).add_node(node)

                if is_python_operator:
                    python_ops_found = True
                    result.add_check(
                        name="Python Operator Detection",
                        passed=False,
                        message=f"Model uses Python operator '{node.op_type}'",
                        severity=IssueSeverity.CRITICAL,
                        location=f"{path} (node: {node.name})",
                        rule_code="S902",
                        details={"op_type": node.op_type, "domain": node.domain},
                    )
                elif not is_external_custom_operator and not is_explicit_custom_operator:
                    safe_nodes += 1

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

        if custom_domains:
            result.metadata["custom_domains"] = sorted(custom_domains)

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
        missing_files: dict[str, list[str]] = {}  # file -> [tensor_names]
        traversal_files: dict[str, list[str]] = {}  # file -> [tensor_names]
        safe_files: set[str] = set()

        for tensors in _iter_model_external_data_tensor_groups(model):
            for tensor in tensors:
                self.check_interrupted()

                if tensor.data_location != onnx.TensorProto.EXTERNAL:
                    continue
                info = {entry.key: entry.value for entry in tensor.external_data}
                location = info.get("location")
                if not location:
                    result.add_check(
                        name="External Data Location Check",
                        passed=False,
                        message=f"Tensor '{tensor.name}' uses external data without location",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"tensor": tensor.name},
                        rule_code="S703",
                    )
                    continue
                has_windows_absolute_path = _is_windows_absolute_path(location)
                lexical_external_path = _resolve_external_location_lexically(model_dir, location)
                external_path = _resolve_external_location(model_dir, location)
                # CVE-2024-27318: Detect nested path traversal (e.g.
                # "subdir/../../etc/passwd") which bypasses naive lstrip
                # sanitization.  Check the raw location for ".." BEFORE
                # the existence check so traversal attempts against
                # non-existent targets are still flagged.
                has_traversal_raw = ".." in location.replace("\\", "/").split("/")
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
                    result.add_check(
                        name="CVE-2026-34447: External Data Symlink Traversal",
                        passed=False,
                        message=(
                            "CVE-2026-34447: External data path "
                            f"'{location}' for tensor '{tensor.name}' resolves through a symlink outside "
                            "the model directory"
                        ),
                        severity=IssueSeverity.CRITICAL,
                        location=str(lexical_external_path),
                        details={
                            "tensor": tensor.name,
                            "file": location,
                            "symlink_path": str(lexical_external_path),
                            "resolved_path": str(external_path),
                            "cve_id": "CVE-2026-34447",
                            "cvss": 5.5,
                            "cwe": "CWE-22",
                            "description": (
                                "ONNX external_data loading can follow symlinks that escape the model "
                                "directory and disclose local files."
                            ),
                            "remediation": (
                                "Reject external_data entries that traverse symlinks outside the model "
                                "directory and update ONNX to a version containing the symlink traversal fix."
                            ),
                        },
                        why=(
                            "The external_data location is lexically inside the model directory, but a symlink "
                            "component resolves outside that directory. Loading external data may read a file "
                            "the model archive should not be able to reference."
                        ),
                    )
                elif has_symlink_component and not external_path.exists():
                    missing_files.setdefault(location, []).append(tensor.name)
                elif escapes_model_dir:
                    # Track for per-file CVE-2025-51480 (write direction) reporting
                    traversal_files.setdefault(location, []).append(tensor.name)
                    # Determine specific CVE attribution
                    normalized_parts = [p for p in location.replace("\\", "/").split("/") if p]
                    starts_with_parent = bool(normalized_parts and normalized_parts[0] == "..")
                    if has_traversal_raw and not starts_with_parent:
                        # Nested traversal (subdir/../../) - CVE-2024-27318
                        cve_id = "CVE-2024-27318"
                        cve_desc = (
                            "ONNX external_data path contains nested "
                            "traversal sequences that bypass naive "
                            "sanitization (lstrip fix for CVE-2022-25882)"
                        )
                        cvss = 7.5
                    else:
                        # Direct traversal (../../) - CVE-2022-25882
                        cve_id = "CVE-2022-25882"
                        cve_desc = (
                            "ONNX external_data location uses path "
                            "traversal to access files outside the "
                            "model directory"
                        )
                        cvss = 7.5
                    result.add_check(
                        name=f"{cve_id}: External Data Path Traversal",
                        passed=False,
                        message=(
                            f"{cve_id}: External data path traversal "
                            f"for tensor '{tensor.name}' - path "
                            f"'{location}' resolves outside model "
                            f"directory"
                        ),
                        severity=IssueSeverity.CRITICAL,
                        location=str(external_path),
                        details={
                            "tensor": tensor.name,
                            "file": location,
                            "cve_id": cve_id,
                            "cvss": cvss,
                            "cwe": "CWE-22",
                            "description": cve_desc,
                            "remediation": (
                                "Validate that external_data paths do "
                                "not contain '..' or resolve outside "
                                "the model directory before loading. "
                                "Update to ONNX >= 1.16.0."
                            ),
                        },
                        why=(
                            f"This ONNX model references external data "
                            f"via path '{location}' which contains "
                            f"directory traversal sequences. An "
                            f"attacker can craft an ONNX model that "
                            f"reads arbitrary files ({cve_id})."
                        ),
                    )
                elif not external_path.exists():
                    missing_files.setdefault(location, []).append(tensor.name)
                else:
                    if location not in safe_files:
                        safe_files.add(location)
                        result.add_check(
                            name="External Data Reference Check",
                            passed=True,
                            message=f"External data reference resolved successfully: {location}",
                            severity=IssueSeverity.INFO,
                            location=str(external_path),
                            details={"file": location},
                        )
                    self._validate_external_size(tensor, info, external_path, result)

        # Report missing files once per file (not per tensor)
        for location, tensors in missing_files.items():
            external_path = _resolve_external_location(model_dir, location)
            result.add_check(
                name="External Data Reference Check",
                passed=False,
                message=(
                    f"External data reference found (file may not be present): '{location}' "
                    f"({len(tensors)} tensor{'s' if len(tensors) != 1 else ''} affected)"
                ),
                severity=IssueSeverity.WARNING,
                location=str(external_path),
                details={
                    "file": location,
                    "affected_tensor_count": len(tensors),
                    "sample_tensors": tensors[:5],
                },
            )

        # Path traversal is a genuine security issue -- keep CRITICAL
        for location, tensors in traversal_files.items():
            external_path = _resolve_external_location(model_dir, location)
            result.add_check(
                name="CVE-2025-51480: External Data Write Path Traversal",
                passed=False,
                message=(
                    f"CVE-2025-51480: External data path traversal for "
                    f"'{location}' ({len(tensors)} tensor"
                    f"{'s' if len(tensors) != 1 else ''} affected) can enable "
                    "arbitrary file overwrite when saving"
                ),
                severity=IssueSeverity.CRITICAL,
                location=str(external_path),
                details={
                    "file": location,
                    "affected_tensor_count": len(tensors),
                    "sample_tensors": tensors[:5],
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

    def _validate_external_size(
        self,
        tensor: Any,
        info: dict[str, str],
        external_path: Path,
        result: ScanResult,
    ) -> None:
        try:
            offset = _parse_external_data_extent(info, "offset") or 0
            declared_length = _parse_external_data_extent(info, "length")
        except ValueError as e:
            result.add_check(
                name="External Data Size Validation",
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
            return

        try:
            import onnx

            expected_size = _onnx_tensor_expected_storage_nbytes(tensor, onnx=onnx)
            required_end = offset + (declared_length if declared_length is not None else expected_size)
            actual_size = external_path.stat().st_size
            if (
                offset > actual_size
                or required_end > actual_size
                or (declared_length is not None and declared_length < expected_size)
            ):
                result.add_check(
                    name="External Data Size Validation",
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
            else:
                result.add_check(
                    name="External Data Size Validation",
                    passed=True,
                    message="External data file size matches expected",
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
            result.add_check(
                name="External Data Size Validation",
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
        for tensor in model.graph.initializer:
            # Check for interrupts during tensor size validation
            self.check_interrupted()
            import onnx

            if tensor.data_location == onnx.TensorProto.EXTERNAL:
                continue
            if tensor.raw_data:
                try:
                    expected_size = _onnx_tensor_expected_storage_nbytes(tensor, onnx=onnx)
                    actual_size = len(tensor.raw_data)
                    if actual_size < expected_size:
                        result.add_check(
                            name="Tensor Size Validation",
                            passed=False,
                            message=f"Tensor '{tensor.name}' data appears truncated",
                            severity=IssueSeverity.INFO,
                            location=f"{path} (tensor: {tensor.name})",
                            rule_code="S703",
                            details={
                                "expected_size": expected_size,
                                "actual_size": actual_size,
                            },
                        )
                    else:
                        result.add_check(
                            name="Tensor Size Validation",
                            passed=True,
                            message=f"Tensor '{tensor.name}' size is valid",
                            location=f"{path} (tensor: {tensor.name})",
                            details={
                                "size": actual_size,
                            },
                            rule_code=None,  # Passing check
                        )
                except Exception as e:
                    _mark_inconclusive_scan_result(result, ONNX_STRUCTURE_INCONCLUSIVE_REASON)
                    result.add_check(
                        name="Tensor Validation",
                        passed=False,
                        message=f"Failed to validate tensor '{tensor.name}': {e}",
                        severity=IssueSeverity.INFO,
                        location=path,
                        rule_code="S703",
                        details={
                            "tensor": tensor.name,
                            "data_type": int(tensor.data_type),
                            "exception": str(e),
                            "exception_type": type(e).__name__,
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

        def inline_storage_fits_budget(initializer: Any, _name: str, estimated_bytes: int) -> bool:
            return (
                max_array_size is None
                or max(
                    _onnx_inline_storage_nbytes(initializer),
                    estimated_bytes,
                )
                <= max_array_size
            )

        retained_array_budget = (
            None if max_array_size is None else max_array_size * _ONNX_WEIGHT_RETAINED_ARRAY_BUDGET_MULTIPLIER
        )
        retained_array_bytes = 0

        def retained_array_fits_budget(_name: str, retained_bytes: int) -> bool:
            nonlocal retained_array_bytes
            if retained_array_budget is not None and retained_array_bytes + retained_bytes > retained_array_budget:
                return False
            retained_array_bytes += retained_bytes
            return True

        plan = _build_onnx_weight_analysis_plan(
            model,
            onnx=onnx,
            np=np,
            max_array_size=max_array_size,
            pre_materialization_check=inline_storage_fits_budget,
            retain_array_check=retained_array_fits_budget,
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
