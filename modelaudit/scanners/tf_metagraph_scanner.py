"""Scanner for TensorFlow MetaGraph (`.meta`) checkpoint graph definitions."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, ClassVar

from modelaudit.config.explanations import get_tf_op_explanation
from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_OPS, TENSORFLOW_DANGEROUS_OPS

from .base import BaseScanner, IssueSeverity, ScanResult

# Discovery assumptions for `.meta` support:
# 1) TensorFlow MetaGraph artifacts are protobuf-encoded `MetaGraphDef` payloads
#    (`tensorflow/core/protobuf/meta_graph.proto`).
# 2) Parsing relies on vendored TensorFlow protobuf stubs (`modelaudit.protos`) so
#    a TensorFlow runtime install is not required.
# 3) High-severity string findings require executable op context to reduce
#    token-only false positives from inert metadata.
DISCOVERY_ASSUMPTIONS = [
    "TensorFlow .meta files are parsed as MetaGraphDef protobuf messages.",
    "Scanner uses vendored TensorFlow protobuf stubs and does not require TensorFlow runtime imports.",
    "High-severity command/network/path findings require executable op context.",
]

HAS_PROTOS: bool | None = None

_MAX_PARSE_BYTES = 20 * 1024 * 1024
_MIN_PARSE_BYTES = 8
_MAX_GRAPH_NODES = 200_000
_MAX_FUNCTION_NODES = 100_000
_MAX_ATTR_VALUE_BYTES = 32 * 1024
_MAX_COLLECTION_VALUE_BYTES = 256 * 1024
_MAX_SIGNAL_EXAMPLES = 8

# Align dangerous operation severity with SavedModel scanner behavior.
_EXCLUDE_GENERIC_DANGEROUS = {"DecodeRaw", "DecodeJpeg", "DecodePng"}
_DANGEROUS_TF_OPS = {
    op: IssueSeverity.CRITICAL for op in TENSORFLOW_DANGEROUS_OPS if op not in _EXCLUDE_GENERIC_DANGEROUS
}

_EXECUTABLE_CONTEXT_OPS = frozenset(
    {
        "PyFunc",
        "PyFuncStateless",
        "PyCall",
        "EagerPyFunc",
        "StatefulPartitionedCall",
        "PartitionedCall",
        "ExecuteOp",
        "ShellExecute",
        "LoadLibrary",
        "LoadLibraryV2",
    }
)

_COLLECTION_EXEC_HINTS = (
    "script",
    "command",
    "entrypoint",
    "hook",
    "callback",
    "runtime",
    "plugin",
    "library",
)

_LIBRARY_OR_PATH_RE = re.compile(
    r"(?i)(?:\b[a-z]:\\[^\s\"']+|\.\.[/\\][^\s\"']+|(?:/[^\s\"']+){2,}|[^\s\"']+\.(?:dll|so|dylib)\b)"
)
_COMMAND_RE = re.compile(
    r"(?i)(?:\bos\.system\b|\bsubprocess\.(?:run|popen|call|check_call|check_output)\b|"
    r"\b(?:bash|sh|zsh|powershell(?:\.exe)?|cmd(?:\.exe)?)\b|\b(?:curl|wget)\b\s+https?://|"
    r"\bpython\s+-c\b|/bin/(?:sh|bash))"
)
_NETWORK_RE = re.compile(r"(?i)(?:https?://|wss?://|ftp://|tcp://|udp://|\bsocket\b|\b(?:\d{1,3}\.){3}\d{1,3}\b)")
_ENCODED_PAYLOAD_RE = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")
_DECODE_HINT_RE = re.compile(r"(?i)(?:base64|b64decode|frombase64string|decode\(|eval\(|exec\()")


def _check_protos() -> bool:
    """Check if TensorFlow protobuf stubs are available (vendored or native)."""
    global HAS_PROTOS
    if HAS_PROTOS is None:
        import modelaudit.protos

        HAS_PROTOS = modelaudit.protos._check_vendored_protos()
    return HAS_PROTOS


def _read_bounded(path: str, max_bytes: int) -> tuple[bytes, bool]:
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    return data[:max_bytes], len(data) > max_bytes


def _parse_metagraph(data: bytes) -> Any:
    # Import vendored protos module (sets up sys.path for tensorflow.* imports)
    # Order matters: modelaudit.protos must be imported first to set up sys.path
    import modelaudit.protos  # noqa: F401, I001

    from tensorflow.core.protobuf.meta_graph_pb2 import MetaGraphDef

    metagraph = MetaGraphDef()
    metagraph.ParseFromString(data)
    return metagraph


@dataclass(frozen=True)
class _NodeContext:
    node_name: str
    op: str
    location_suffix: str
    attrs: Any


@dataclass(frozen=True)
class _MetaGraphStructure:
    valid: bool
    reason: str
    graph_node_count: int
    function_count: int
    function_node_count: int
    collection_count: int


def _collect_structure(metagraph: Any) -> _MetaGraphStructure:
    has_graph = metagraph.HasField("graph_def")
    graph_node_count = len(metagraph.graph_def.node)
    function_count = len(metagraph.graph_def.library.function)
    function_node_count = sum(len(function.node_def) for function in metagraph.graph_def.library.function)
    collection_count = len(metagraph.collection_def)

    if not has_graph:
        return _MetaGraphStructure(
            valid=False,
            reason="missing_graph_def",
            graph_node_count=graph_node_count,
            function_count=function_count,
            function_node_count=function_node_count,
            collection_count=collection_count,
        )

    if graph_node_count == 0 and function_node_count == 0 and collection_count == 0:
        return _MetaGraphStructure(
            valid=False,
            reason="no_graph_nodes_functions_or_collections",
            graph_node_count=graph_node_count,
            function_count=function_count,
            function_node_count=function_node_count,
            collection_count=collection_count,
        )

    if graph_node_count > _MAX_GRAPH_NODES:
        return _MetaGraphStructure(
            valid=False,
            reason="graph_node_limit_exceeded",
            graph_node_count=graph_node_count,
            function_count=function_count,
            function_node_count=function_node_count,
            collection_count=collection_count,
        )

    if function_node_count > _MAX_FUNCTION_NODES:
        return _MetaGraphStructure(
            valid=False,
            reason="function_node_limit_exceeded",
            graph_node_count=graph_node_count,
            function_count=function_count,
            function_node_count=function_node_count,
            collection_count=collection_count,
        )

    return _MetaGraphStructure(
        valid=True,
        reason="ok",
        graph_node_count=graph_node_count,
        function_count=function_count,
        function_node_count=function_node_count,
        collection_count=collection_count,
    )


def _iter_nodes(metagraph: Any) -> Iterable[_NodeContext]:
    for node in metagraph.graph_def.node:
        yield _NodeContext(node_name=node.name, op=node.op, location_suffix=f"node: {node.name}", attrs=node.attr)

    for function in metagraph.graph_def.library.function:
        function_name = function.signature.name or "unknown_function"
        for node in function.node_def:
            yield _NodeContext(
                node_name=node.name,
                op=node.op,
                location_suffix=f"function: {function_name}, node: {node.name}",
                attrs=node.attr,
            )


def _extract_attr_strings(attrs: Any) -> list[tuple[str, str]]:
    strings: list[tuple[str, str]] = []

    for attr_name, attr_value in attrs.items():
        if hasattr(attr_value, "s") and attr_value.s:
            decoded = attr_value.s[:_MAX_ATTR_VALUE_BYTES].decode("utf-8", errors="ignore").strip()
            if decoded:
                strings.append((attr_name, decoded))

        if hasattr(attr_value, "list") and hasattr(attr_value.list, "s"):
            for item in attr_value.list.s:
                decoded = item[:_MAX_ATTR_VALUE_BYTES].decode("utf-8", errors="ignore").strip()
                if decoded:
                    strings.append((attr_name, decoded))

    return strings


class TensorFlowMetaGraphScanner(BaseScanner):
    """Scanner for TensorFlow MetaGraph protobuf files (.meta)."""

    name = "tf_metagraph"
    description = "Scans TensorFlow .meta graph definitions for unsafe operations and executable payload indicators"
    supported_extensions: ClassVar[list[str]] = [".meta"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if os.path.splitext(path)[1].lower() not in cls.supported_extensions:
            return False
        if not _check_protos():
            return False

        file_size = os.path.getsize(path)
        if file_size < _MIN_PARSE_BYTES or file_size > _MAX_PARSE_BYTES:
            return False

        try:
            content, truncated = _read_bounded(path, _MAX_PARSE_BYTES)
            if truncated:
                return False
            metagraph = _parse_metagraph(content)
        except Exception:
            return False

        structure = _collect_structure(metagraph)
        return structure.valid

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)
        result.metadata["scan_byte_limit"] = _MAX_PARSE_BYTES
        result.metadata["max_graph_nodes"] = _MAX_GRAPH_NODES
        result.metadata["max_function_nodes"] = _MAX_FUNCTION_NODES
        result.metadata["discovery_assumptions"] = DISCOVERY_ASSUMPTIONS

        if not _check_protos():
            result.add_check(
                name="TensorFlow Protobuf Availability",
                passed=False,
                message="TensorFlow protobuf stubs are unavailable; cannot parse .meta file",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"path": path},
            )
            result.finish(success=False)
            return result

        try:
            content, truncated = _read_bounded(path, _MAX_PARSE_BYTES)
        except OSError as e:
            result.add_check(
                name="MetaGraph File Read",
                passed=False,
                message=f"Unable to read .meta file: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.bytes_scanned = len(content)
        result.metadata["scan_truncated"] = truncated

        if truncated:
            result.add_check(
                name="MetaGraph Parse Budget",
                passed=False,
                message="MetaGraph exceeds bounded parse budget",
                severity=IssueSeverity.INFO,
                location=path,
                details={"max_parse_bytes": _MAX_PARSE_BYTES},
            )
            result.finish(success=False)
            return result

        try:
            metagraph = _parse_metagraph(content)
        except Exception as e:
            result.add_check(
                name="MetaGraph Protobuf Parsing",
                passed=False,
                message=f"Invalid or corrupt TensorFlow MetaGraph protobuf: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        structure = _collect_structure(metagraph)
        result.metadata["graph_node_count"] = structure.graph_node_count
        result.metadata["function_count"] = structure.function_count
        result.metadata["function_node_count"] = structure.function_node_count
        result.metadata["collection_count"] = structure.collection_count

        if not structure.valid:
            result.add_check(
                name="MetaGraph Structural Validation",
                passed=False,
                message="MetaGraph structure failed strict validation",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "reason": structure.reason,
                    "graph_node_count": structure.graph_node_count,
                    "function_node_count": structure.function_node_count,
                    "collection_count": structure.collection_count,
                },
            )
            result.finish(success=False)
            return result

        suspicious_signal_categories: set[str] = set()
        suspicious_signal_examples: dict[str, list[str]] = {
            "dynamic_library_or_path": [],
            "command_or_network": [],
            "encoded_payload": [],
        }

        for ctx in _iter_nodes(metagraph):
            if ctx.op in _DANGEROUS_TF_OPS:
                result.add_check(
                    name="TensorFlow MetaGraph Operation Security Check",
                    passed=False,
                    message=f"Dangerous TensorFlow operation: {ctx.op}",
                    severity=_DANGEROUS_TF_OPS[ctx.op],
                    location=f"{path} ({ctx.location_suffix})",
                    details={"op_type": ctx.op, "node_name": ctx.node_name},
                    why=get_tf_op_explanation(ctx.op),
                )
            elif ctx.op in SUSPICIOUS_OPS:
                result.add_check(
                    name="TensorFlow MetaGraph Operation Security Check",
                    passed=False,
                    message=f"Suspicious TensorFlow operation: {ctx.op}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} ({ctx.location_suffix})",
                    details={"op_type": ctx.op, "node_name": ctx.node_name},
                    why=get_tf_op_explanation(ctx.op),
                )

            if ctx.op not in _EXECUTABLE_CONTEXT_OPS:
                continue

            for attr_name, attr_val in _extract_attr_strings(ctx.attrs):
                attr_lower = attr_val.lower()

                if _LIBRARY_OR_PATH_RE.search(attr_val):
                    suspicious_signal_categories.add("dynamic_library_or_path")
                    if len(suspicious_signal_examples["dynamic_library_or_path"]) < _MAX_SIGNAL_EXAMPLES:
                        suspicious_signal_examples["dynamic_library_or_path"].append(
                            f"{ctx.op}:{attr_name}:{attr_val[:120]}"
                        )
                    result.add_check(
                        name="MetaGraph External Reference Check",
                        passed=False,
                        message="External library/path reference found in executable TensorFlow op context",
                        severity=IssueSeverity.WARNING,
                        location=f"{path} ({ctx.location_suffix})",
                        details={
                            "op_type": ctx.op,
                            "node_name": ctx.node_name,
                            "attribute": attr_name,
                            "value_preview": attr_val[:200],
                        },
                    )

                command_match = _COMMAND_RE.search(attr_val)
                network_match = _NETWORK_RE.search(attr_val)
                if command_match or network_match:
                    suspicious_signal_categories.add("command_or_network")
                    if len(suspicious_signal_examples["command_or_network"]) < _MAX_SIGNAL_EXAMPLES:
                        suspicious_signal_examples["command_or_network"].append(
                            f"{ctx.op}:{attr_name}:{attr_val[:120]}"
                        )

                    severity = IssueSeverity.CRITICAL if command_match and network_match else IssueSeverity.WARNING
                    result.add_check(
                        name="MetaGraph Executable String Check",
                        passed=False,
                        message="Suspicious command/network string found in executable TensorFlow op attribute",
                        severity=severity,
                        location=f"{path} ({ctx.location_suffix})",
                        details={
                            "op_type": ctx.op,
                            "node_name": ctx.node_name,
                            "attribute": attr_name,
                            "command_pattern": bool(command_match),
                            "network_pattern": bool(network_match),
                            "value_preview": attr_val[:200],
                        },
                    )

                if _ENCODED_PAYLOAD_RE.search(attr_val) and _DECODE_HINT_RE.search(attr_lower):
                    suspicious_signal_categories.add("encoded_payload")
                    if len(suspicious_signal_examples["encoded_payload"]) < _MAX_SIGNAL_EXAMPLES:
                        suspicious_signal_examples["encoded_payload"].append(f"{ctx.op}:{attr_name}:{attr_val[:120]}")
                    result.add_check(
                        name="MetaGraph Encoded Payload Check",
                        passed=False,
                        message="Encoded payload indicator found in executable TensorFlow op attribute",
                        severity=IssueSeverity.WARNING,
                        location=f"{path} ({ctx.location_suffix})",
                        details={
                            "op_type": ctx.op,
                            "node_name": ctx.node_name,
                            "attribute": attr_name,
                            "value_preview": attr_val[:200],
                        },
                    )

                if len(attr_val) > _MAX_ATTR_VALUE_BYTES:
                    result.add_check(
                        name="MetaGraph Attribute Size Anomaly",
                        passed=False,
                        message="Large executable-context attribute detected (possible payload stuffing)",
                        severity=IssueSeverity.WARNING,
                        location=f"{path} ({ctx.location_suffix})",
                        details={
                            "op_type": ctx.op,
                            "node_name": ctx.node_name,
                            "attribute": attr_name,
                            "attribute_length": len(attr_val),
                            "max_expected": _MAX_ATTR_VALUE_BYTES,
                        },
                    )

        for key, collection in metagraph.collection_def.items():
            key_lower = key.lower()

            if hasattr(collection, "bytes_list"):
                for idx, value in enumerate(collection.bytes_list.value):
                    if len(value) > _MAX_COLLECTION_VALUE_BYTES:
                        result.add_check(
                            name="MetaGraph Collection Size Anomaly",
                            passed=False,
                            message="Large collection bytes entry detected (possible payload stuffing)",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={
                                "collection_key": key,
                                "index": idx,
                                "entry_size": len(value),
                                "max_expected": _MAX_COLLECTION_VALUE_BYTES,
                            },
                        )

                    if any(hint in key_lower for hint in _COLLECTION_EXEC_HINTS):
                        decoded = value[:_MAX_ATTR_VALUE_BYTES].decode("utf-8", errors="ignore")
                        if _COMMAND_RE.search(decoded) and _NETWORK_RE.search(decoded):
                            result.add_check(
                                name="MetaGraph Collection Executable Pattern",
                                passed=False,
                                message=(
                                    "Collection metadata contains command+network pattern in executable key context"
                                ),
                                severity=IssueSeverity.WARNING,
                                location=path,
                                details={
                                    "collection_key": key,
                                    "index": idx,
                                    "value_preview": decoded[:200],
                                },
                            )

        if len(suspicious_signal_categories) >= 2:
            result.add_check(
                name="MetaGraph Multi-Signal Correlation",
                passed=False,
                message="Multiple independent executable-context risk indicators detected in MetaGraph",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "signals": sorted(suspicious_signal_categories),
                    "examples": {k: v for k, v in suspicious_signal_examples.items() if v},
                },
            )

        if not result.issues:
            result.add_check(
                name="TensorFlow MetaGraph Static Security Analysis",
                passed=True,
                message="No suspicious executable MetaGraph patterns detected",
                location=path,
                details={
                    "graph_node_count": structure.graph_node_count,
                    "function_node_count": structure.function_node_count,
                },
            )

        result.finish(success=not result.has_errors)
        return result
