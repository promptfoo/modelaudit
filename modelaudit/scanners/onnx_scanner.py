"""Scanner for ONNX model files (.onnx)."""

import logging
import math
import ntpath
import os
import re
from pathlib import Path
from typing import Any, ClassVar

from ..utils.file.detection import PROTOBUF_MODEL_CANDIDATE_FORMAT
from ._evidence_redaction import redact_untrusted_error_message
from .base import FORMAT_VALIDATION_CONFIG_KEY, INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult

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
ONNX_STRUCTURE_INCONCLUSIVE_REASON = "onnx_structure_validation_failed"
ONNX_RAW_DETECTION_INCONCLUSIVE_REASON = "onnx_raw_detection_analysis_incomplete"
ONNX_WEIGHT_DISTRIBUTION_INCONCLUSIVE_REASON = "onnx_weight_distribution_analysis_incomplete"
ONNX_TENTATIVE_CANDIDATE_UNAVAILABLE_REASON = "onnx_tentative_candidate_analysis_unavailable"
ONNX_TENTATIVE_CANDIDATE_PARSE_INCOMPLETE_REASON = "onnx_tentative_candidate_parse_incomplete"
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


def _iter_model_graphs(model: Any) -> Any:
    """Yield graph-bearing ONNX model fields that may declare operators."""
    for graph, _opset_versions in _iter_model_graphs_with_opsets(model):
        yield graph


def _iter_model_graphs_with_opsets(model: Any) -> Any:
    """Yield model graphs with the operator-set versions governing each graph."""
    model_opset_versions = {opset.domain or "": int(opset.version) for opset in getattr(model, "opset_import", [])}
    yield model.graph, model_opset_versions
    for function in getattr(model, "functions", []):
        function_opset_versions = {
            opset.domain or "": int(opset.version) for opset in getattr(function, "opset_import", [])
        }
        yield function, function_opset_versions
        for attribute in getattr(function, "attribute_proto", []):
            for graph in _iter_attribute_graphs(attribute):
                yield graph, function_opset_versions
    for training_info in getattr(model, "training_info", []):
        yield training_info.initialization, model_opset_versions
        yield training_info.algorithm, model_opset_versions


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
                name="ONNX Library Check",
                passed=False,
                message="onnx package not installed, cannot scan ONNX files.",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"required_package": "onnx"},
                rule_code="S902",
            )
            result.finish(success=False)
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
        custom_operators_found = 0
        python_ops_found = False
        safe_nodes = 0
        nodes_checked = 0

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
                        custom_domains.add(node.domain)
                        message = (
                            f"Model references custom operator domain '{node.domain}'. "
                            "This is metadata only - ensure operators are from trusted sources before installation."
                        )
                    else:
                        message = (
                            f"Model references custom operator '{node.op_type}' in the standard ONNX domain. "
                            "Ensure its implementation is from a trusted source before installation."
                        )

                    # All custom operators are INFO - they're metadata, not executable code
                    # Security risk is in runtime environment (installing malicious operators)
                    # not in the ONNX file itself
                    result.add_check(
                        name="Custom Operator Domain Check",
                        passed=False,
                        message=message,
                        severity=IssueSeverity.INFO,
                        location=f"{path} (node: {node.name})",
                        rule_code="S1111",
                        details={
                            "op_type": node.op_type,
                            "domain": node.domain,
                            "security_note": (
                                "Custom operators may depend on external operator implementations. "
                                "ONNX files cannot execute code - risk is in runtime environment if malicious "
                                "operators are installed. Verify operator packages before installation."
                            ),
                        },
                    )

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

        # Record successful checks for safe operators
        if safe_nodes > 0 and custom_operators_found == 0:
            result.add_check(
                name="Custom Operator Domain Check",
                passed=True,
                message="All operators use standard ONNX domains or model-local function implementations",
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
        model_dir = Path(path).resolve().parent
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
                symlink_escapes_model_dir = has_symlink_component and not _is_contained_in(external_path, model_dir)
                escapes_model_dir = has_windows_absolute_path or not _is_contained_in(external_path, model_dir)
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
                    dtype = _tensor_data_type_to_np_dtype(tensor.data_type)
                    num_elem = 1
                    for d in tensor.dims:
                        num_elem *= d
                    expected_size = int(num_elem) * int(dtype.itemsize)
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
        """Extract weights from ONNX initializers and run weight distribution analysis.

        The model is already loaded with load_external_data=False, so external-data
        tensors have no raw bytes and must be skipped.  Only inline 2-D+ tensors
        (conv kernels, linear layers, embeddings) are relevant for distribution
        analysis; 1-D tensors (biases, batch-norm params) are excluded.
        """
        try:
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

        # Max in-memory array size (default 100 MB)
        max_array_size = self.config.get("max_array_size", 100 * 1024 * 1024)

        eligible_initializers = 0
        external_initializers_skipped = 0
        oversized_initializers_skipped = 0
        extraction_failures = 0
        weights_info: dict[str, Any] = {}
        for initializer in model.graph.initializer:
            try:
                self.check_interrupted()

                # Only 2-D+ tensors are interesting for distribution analysis.
                if len(initializer.dims) < 2:
                    continue
                eligible_initializers += 1

                # Skip external-data tensors — their bytes were not loaded.
                if initializer.data_location == onnx.TensorProto.EXTERNAL:
                    external_initializers_skipped += 1
                    continue

                # Pre-check estimated size before materializing the array.
                # Use math.prod for arbitrary-precision arithmetic (np.prod
                # can silently overflow for very large dimension products).
                numel = math.prod(int(dim) for dim in initializer.dims)
                itemsize = int(_tensor_data_type_to_np_dtype(initializer.data_type).itemsize)
                estimated_bytes = numel * itemsize
                if max_array_size and max_array_size > 0 and estimated_bytes > max_array_size:
                    oversized_initializers_skipped += 1
                    continue

                array = onnx.numpy_helper.to_array(initializer)

                weights_info[initializer.name] = array
            except Exception as e:
                extraction_failures += 1
                logger.warning(
                    "Failed to extract ONNX initializer '%s' for distribution analysis: %s",
                    initializer.name,
                    e,
                )
                continue

        if external_initializers_skipped or oversized_initializers_skipped or extraction_failures:
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason="partial_initializer_coverage",
                message="Weight distribution analysis skipped one or more eligible ONNX initializers",
                details={
                    "eligible_initializers": eligible_initializers,
                    "analyzed_initializers": len(weights_info),
                    "external_initializers_skipped": external_initializers_skipped,
                    "oversized_initializers_skipped": oversized_initializers_skipped,
                    "extraction_failures": extraction_failures,
                    "max_array_size": max_array_size,
                },
            )

        if not weights_info:
            # Nothing to analyse (external-only model, or all tensors too small / too large).
            return

        try:
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

        # Delegate the actual statistical analysis to WeightDistributionScanner.
        try:
            wd_scanner = WeightDistributionScanner(self.config)
            anomalies = wd_scanner._analyze_weight_distributions(weights_info)

            for anomaly in anomalies:
                result.add_check(
                    name="Weight Distribution Anomaly Detection",
                    passed=False,
                    message=anomaly["description"],
                    severity=anomaly["severity"],
                    location=path,
                    details=anomaly["details"],
                    why=anomaly.get("why"),
                )

            result.metadata["layers_analyzed"] = len(weights_info)
            result.metadata["anomalies_found"] = len(anomalies)
            if extraction_failures > 0:
                result.metadata["weight_extraction_failures"] = extraction_failures
        except Exception as e:
            logger.warning(f"Weight distribution analysis failed: {e}")
            result.add_check(
                name="Weight Distribution Analysis",
                passed=False,
                message=f"Weight distribution analysis failed: {e!s}",
                severity=IssueSeverity.DEBUG,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            self._mark_weight_distribution_incomplete(
                result,
                path,
                reason="analysis_failed",
                message=f"Weight distribution analysis failed: {e!s}",
                details={"exception": str(e), "exception_type": type(e).__name__},
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
