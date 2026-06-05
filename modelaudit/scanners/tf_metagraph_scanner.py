"""Scanner for TensorFlow MetaGraph (`.meta`) checkpoint graph definitions."""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, ClassVar

from modelaudit.config.explanations import get_tf_op_explanation
from modelaudit.core_results import mark_operational_scan_error
from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_OPS, TENSORFLOW_DANGEROUS_OPS
from modelaudit.scanner_results import mark_inconclusive_scan_result
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs

from ._evidence_redaction import (
    REDACTED_EVIDENCE_VALUE,
    REDACTION_LOOKAHEAD_CHARS,
    STANDALONE_SECRET_RE,
    is_sensitive_evidence_key,
    redact_evidence_string,
)
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

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

_MAX_PARSE_BYTES = 20 * 1024 * 1024
_MIN_PARSE_BYTES = 8
_MAX_GRAPH_NODES = 200_000
_MAX_FUNCTION_NODES = 100_000
_MAX_ATTR_VALUE_BYTES = 32 * 1024
_MAX_COLLECTION_VALUE_BYTES = 256 * 1024
_MAX_SIGNAL_EXAMPLES = 8

# Align dangerous operation severity with SavedModel scanner behavior.
# Save/Restore ops are common in benign checkpoints and are not direct
# code-execution primitives in MetaGraph context.
_EXCLUDE_GENERIC_DANGEROUS = {"DecodeRaw", "DecodeJpeg", "DecodePng", "SaveV2", "RestoreV2"}
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
_ENCODED_PAYLOAD_RE = re.compile(r"(?<![A-Za-z0-9+_-])[A-Za-z0-9+_-][A-Za-z0-9+/_-]{119,}={0,2}(?![A-Za-z0-9+/_=-])")
_URL_AUTHORITY_PREFIX_RE = re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^\s\"'<>]*\Z")
_DECODE_HINT_RE = re.compile(r"(?i)(?:base64|b64decode|frombase64string|decode\(|eval\(|exec\()")
_BENIGN_CHECKPOINT_IO_OPS = frozenset({"SaveV2", "RestoreV2"})
_FUNCTION_ATTRIBUTE_SUFFIX = ".func.name"
_ESCAPED_EVIDENCE_ASCII_RE = re.compile(
    r"\\(?:"
    r"(?P<continuation>\r\n|\r|\n)|"
    r"(?P<mnemonic>[abfnrtv])(?=\Z|[^A-Za-z0-9_])|"
    r"u00(?P<unicode>[0-7][0-9A-Fa-f])|"
    r"U000000(?P<long_unicode>[0-7][0-9A-Fa-f])|"
    r"u\{0{0,4}(?P<braced_unicode>[2-7][0-9A-Fa-f])\}|"
    r"N\{(?P<named_unicode>[A-Za-z0-9 -]{1,64})\}|"
    r"x(?P<hex>[2-7][0-9A-Fa-f])|"
    r"(?P<octal>[0-7]{1,3})|"
    r"(?P<literal>[\\/:=?&#@])"
    r")"
)
_UNRESOLVED_ESCAPED_EVIDENCE_RE = re.compile(r"\\(?:u(?:[0-9A-Fa-f]|\{)|U[0-9A-Fa-f]|N\{|x[0-9A-Fa-f]|[0-7])")
_WINDOWS_PATH_EVIDENCE_RE = re.compile(r"(?i)\A[a-z]:\\[^\r\n]*\Z")
_MAX_ESCAPED_EVIDENCE_DECODE_PASSES = 8
_MAX_ESCAPED_EVIDENCE_SEQUENCE_CHARS = 68
_PLAIN_EVIDENCE_IDENTIFIER_RE = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")
_SENSITIVE_IDENTIFIER_HINT_RE = re.compile(
    r"(?i)(?:access|api|auth|cookie|credential|key|pass|private|secret|session|signature|token)"
)


def _normalize_metagraph_evidence_escapes(text: str) -> str:
    """Expose bounded printable-ASCII escapes before evidence redaction."""

    def decode_escape(match: re.Match[str]) -> str:
        if match.group("continuation") is not None:
            return ""
        if match.group("mnemonic") is not None:
            return " "
        if match.group("unicode") is not None:
            decoded = chr(int(match.group("unicode"), 16))
        elif match.group("long_unicode") is not None:
            decoded = chr(int(match.group("long_unicode"), 16))
        elif match.group("braced_unicode") is not None:
            decoded = chr(int(match.group("braced_unicode"), 16))
        elif match.group("named_unicode") is not None:
            try:
                decoded = unicodedata.lookup(match.group("named_unicode").upper())
            except KeyError:
                return match.group(0)
        elif match.group("hex") is not None:
            decoded = chr(int(match.group("hex"), 16))
        elif match.group("octal") is not None:
            decoded = chr(int(match.group("octal"), 8))
        else:
            literal = match.group("literal")
            assert literal is not None
            decoded = literal
        return decoded if decoded.isascii() and decoded.isprintable() else match.group(0)

    normalized = text
    for _ in range(_MAX_ESCAPED_EVIDENCE_DECODE_PASSES):
        next_value = _ESCAPED_EVIDENCE_ASCII_RE.sub(decode_escape, normalized)
        if next_value == normalized:
            return REDACTED_EVIDENCE_VALUE if _UNRESOLVED_ESCAPED_EVIDENCE_RE.search(normalized) else normalized
        normalized = next_value

    if _UNRESOLVED_ESCAPED_EVIDENCE_RE.search(normalized):
        return REDACTED_EVIDENCE_VALUE
    return normalized


def _is_plain_metagraph_evidence(text: str) -> bool:
    """Recognize small generated-style identifiers that cannot contain credentials."""

    def is_plain_identifier(identifier: str) -> bool:
        return bool(
            _PLAIN_EVIDENCE_IDENTIFIER_RE.fullmatch(identifier)
            and not _SENSITIVE_IDENTIFIER_HINT_RE.search(identifier)
            and not STANDALONE_SECRET_RE.search(identifier)
        )

    if is_plain_identifier(text):
        return True
    if text.startswith("node: "):
        return is_plain_identifier(text.removeprefix("node: "))
    if text.startswith("function: "):
        function_name, separator, node_name = text.removeprefix("function: ").partition(", node: ")
        return bool(separator and is_plain_identifier(function_name) and is_plain_identifier(node_name))
    return False


def _redact_encoded_payload_match(match: re.Match[str]) -> str:
    raw_value = match.group(0)
    url_prefix_match = _URL_AUTHORITY_PREFIX_RE.search(match.string[: match.start()])
    if url_prefix_match is not None:
        authority_prefix = url_prefix_match.group(0).partition("://")[2]
        authority_tail, separator, _path = raw_value.partition("/")
        if (
            separator
            and "/" not in authority_prefix
            and len(authority_tail) <= 63
            and _ENCODED_PAYLOAD_RE.fullmatch(authority_tail) is None
        ):
            trailing_separator = "/" if raw_value.endswith("/") else ""
            return f"{authority_tail}/{REDACTED_EVIDENCE_VALUE}{trailing_separator}"
    return REDACTED_EVIDENCE_VALUE


def _redact_metagraph_evidence(text: str, max_chars: int) -> str:
    """Redact stored MetaGraph evidence without changing detection input."""
    normalization_limit = max(0, max_chars) + (2 * REDACTION_LOOKAHEAD_CHARS) + _MAX_ESCAPED_EVIDENCE_SEQUENCE_CHARS
    source_text = text[:normalization_limit]
    normalized_text = _normalize_metagraph_evidence_escapes(source_text)
    if normalized_text == REDACTED_EVIDENCE_VALUE:
        return normalized_text
    if _is_plain_metagraph_evidence(normalized_text):
        return normalized_text[:max_chars]
    secret_redacted = redact_evidence_string(normalized_text, max_chars=max_chars + REDACTION_LOOKAHEAD_CHARS)
    payload_redacted = _ENCODED_PAYLOAD_RE.sub(_redact_encoded_payload_match, secret_redacted)
    if (
        normalized_text != source_text
        and payload_redacted == normalized_text
        and _WINDOWS_PATH_EVIDENCE_RE.fullmatch(source_text) is not None
    ):
        secret_redacted = redact_evidence_string(source_text, max_chars=max_chars + REDACTION_LOOKAHEAD_CHARS)
        payload_redacted = _ENCODED_PAYLOAD_RE.sub(_redact_encoded_payload_match, secret_redacted)
    if payload_redacted == f"{REDACTED_EVIDENCE_VALUE}...":
        return REDACTED_EVIDENCE_VALUE
    if len(payload_redacted) <= max_chars:
        return payload_redacted
    if max_chars <= 3:
        return payload_redacted[:max_chars]
    return f"{payload_redacted[: max_chars - 3]}..."


def _attribute_context_name(attr_name: str) -> str:
    """Strip generated function metadata suffixes for conservative key classification."""
    end = len(attr_name)
    suffix_length = len(_FUNCTION_ATTRIBUTE_SUFFIX)
    while attr_name.endswith(_FUNCTION_ATTRIBUTE_SUFFIX, 0, end):
        end -= suffix_length
    return attr_name[:end]


def _is_sensitive_metagraph_evidence_key(key: str) -> bool:
    """Classify bounded escaped key spellings before storing their values."""
    if is_sensitive_evidence_key(key):
        return True
    normalized_key = _normalize_metagraph_evidence_escapes(key)
    return normalized_key == REDACTED_EVIDENCE_VALUE or is_sensitive_evidence_key(normalized_key)


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
class _AttrString:
    attr_name: str
    attr_value: str
    byte_length: int
    sensitive_context_name: str | None = None


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

    if not has_graph and collection_count == 0:
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


def _append_attr_string(
    strings: list[_AttrString],
    attr_name: str,
    raw_value: bytes,
    *,
    sensitive_context_name: str | None = None,
) -> None:
    decoded = raw_value[:_MAX_ATTR_VALUE_BYTES].decode("utf-8", errors="ignore").strip()
    if decoded or len(raw_value) > _MAX_ATTR_VALUE_BYTES:
        strings.append(
            _AttrString(
                attr_name=attr_name,
                attr_value=decoded,
                byte_length=len(raw_value),
                sensitive_context_name=sensitive_context_name,
            )
        )


def _extract_attr_strings(attrs: Any) -> list[_AttrString]:
    strings: list[_AttrString] = []

    for attr_name, attr_value in attrs.items():
        if hasattr(attr_value, "s") and attr_value.s:
            _append_attr_string(strings, attr_name, attr_value.s)

        if hasattr(attr_value, "func") and attr_value.func.name:
            _append_attr_string(
                strings,
                f"{attr_name}{_FUNCTION_ATTRIBUTE_SUFFIX}",
                attr_value.func.name.encode("utf-8"),
                sensitive_context_name=_attribute_context_name(attr_name),
            )

        if hasattr(attr_value, "list") and hasattr(attr_value.list, "s"):
            for item in attr_value.list.s:
                _append_attr_string(strings, attr_name, item)

        if hasattr(attr_value, "list") and hasattr(attr_value.list, "func"):
            for function_attr in attr_value.list.func:
                if function_attr.name:
                    _append_attr_string(
                        strings,
                        f"{attr_name}{_FUNCTION_ATTRIBUTE_SUFFIX}",
                        function_attr.name.encode("utf-8"),
                        sensitive_context_name=_attribute_context_name(attr_name),
                    )

    return strings


def _attr_strings_with_lowered_values(attr_strings: Iterable[_AttrString]) -> tuple[tuple[_AttrString, str], ...]:
    return tuple((attr_string, attr_string.attr_value.lower()) for attr_string in attr_strings)


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
        if not has_tensorflow_protobuf_stubs():
            return False

        try:
            file_size = os.path.getsize(path)
            if file_size < _MIN_PARSE_BYTES:
                return False
            if file_size > _MAX_PARSE_BYTES:
                return True

            content, truncated = _read_bounded(path, _MAX_PARSE_BYTES)
            if truncated:
                return False
            metagraph = _parse_metagraph(content)
        except OSError:
            return True
        except Exception:
            return False

        structure = _collect_structure(metagraph)
        return structure.valid

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _finish_read_failure(result: ScanResult, path: str, error: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, "metagraph_read_failed")
        mark_operational_scan_error(result, "metagraph_read_failed")
        result.add_check(
            name="MetaGraph File Read",
            passed=False,
            message=f"Unable to read .meta file: {error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "metagraph_read_failed",
                "operational_error_reason": "metagraph_read_failed",
            },
        )
        result.finish(success=False)
        return result

    def scan(self, path: str) -> ScanResult:
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
        result.metadata["file_size"] = self.get_file_size(path)
        result.metadata["scan_byte_limit"] = _MAX_PARSE_BYTES
        result.metadata["max_graph_nodes"] = _MAX_GRAPH_NODES
        result.metadata["max_function_nodes"] = _MAX_FUNCTION_NODES
        result.metadata["discovery_assumptions"] = DISCOVERY_ASSUMPTIONS

        if not has_tensorflow_protobuf_stubs():
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
            return self._finish_read_failure(result, path, e)

        result.bytes_scanned = len(content)
        result.metadata["scan_truncated"] = truncated

        if truncated:
            result.metadata["operational_error"] = True
            result.metadata["operational_error_reason"] = "metagraph_parse_budget_exceeded"
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
            if ctx.op in _BENIGN_CHECKPOINT_IO_OPS:
                continue

            evidence_context: tuple[str, str] | None = None

            def get_evidence_context(node_context: _NodeContext = ctx) -> tuple[str, str]:
                nonlocal evidence_context
                if evidence_context is None:
                    evidence_context = (
                        f"{path} ({_redact_metagraph_evidence(node_context.location_suffix, max_chars=240)})",
                        _redact_metagraph_evidence(node_context.node_name, max_chars=200),
                    )
                return evidence_context

            if ctx.op in _DANGEROUS_TF_OPS:
                evidence_location, evidence_node_name = get_evidence_context()
                result.add_check(
                    name="TensorFlow MetaGraph Operation Security Check",
                    passed=False,
                    message=f"Dangerous TensorFlow operation: {ctx.op}",
                    severity=_DANGEROUS_TF_OPS[ctx.op],
                    location=evidence_location,
                    details={"op_type": ctx.op, "node_name": evidence_node_name},
                    why=get_tf_op_explanation(ctx.op),
                )
            elif ctx.op in SUSPICIOUS_OPS:
                evidence_location, evidence_node_name = get_evidence_context()
                result.add_check(
                    name="TensorFlow MetaGraph Operation Security Check",
                    passed=False,
                    message=f"Suspicious TensorFlow operation: {ctx.op}",
                    severity=IssueSeverity.WARNING,
                    location=evidence_location,
                    details={"op_type": ctx.op, "node_name": evidence_node_name},
                    why=get_tf_op_explanation(ctx.op),
                )

            if ctx.op not in _EXECUTABLE_CONTEXT_OPS:
                continue

            attr_strings = _extract_attr_strings(ctx.attrs)
            attr_strings_with_lowered_values = _attr_strings_with_lowered_values(attr_strings)
            has_decode_hint = any(
                _DECODE_HINT_RE.search(attr_lower) for _attr_string, attr_lower in attr_strings_with_lowered_values
            )

            for attr_string, attr_lower in attr_strings_with_lowered_values:
                attr_name = attr_string.attr_name
                attr_val = attr_string.attr_value
                library_match = _LIBRARY_OR_PATH_RE.search(attr_val)
                command_match = _COMMAND_RE.search(attr_val)
                network_match = _NETWORK_RE.search(attr_val)
                encoded_payload_match = _ENCODED_PAYLOAD_RE.search(attr_val) and (
                    has_decode_hint or _DECODE_HINT_RE.search(attr_lower)
                )
                oversized_attribute = attr_string.byte_length > _MAX_ATTR_VALUE_BYTES

                if not any((library_match, command_match, network_match, encoded_payload_match, oversized_attribute)):
                    continue

                evidence_location, evidence_node_name = get_evidence_context()
                evidence_attr_name = _redact_metagraph_evidence(attr_name, max_chars=200)
                sensitive_attr_value = _is_sensitive_metagraph_evidence_key(
                    attr_string.sensitive_context_name or _attribute_context_name(attr_name)
                )
                needs_value_preview = bool(library_match or command_match or network_match or encoded_payload_match)
                evidence_value_preview = (
                    (
                        REDACTED_EVIDENCE_VALUE
                        if sensitive_attr_value
                        else _redact_metagraph_evidence(attr_val, max_chars=200)
                    )
                    if needs_value_preview
                    else None
                )
                needs_example_preview = (
                    (
                        bool(library_match)
                        and len(suspicious_signal_examples["dynamic_library_or_path"]) < _MAX_SIGNAL_EXAMPLES
                    )
                    or (
                        bool(command_match or network_match)
                        and len(suspicious_signal_examples["command_or_network"]) < _MAX_SIGNAL_EXAMPLES
                    )
                    or (
                        bool(encoded_payload_match)
                        and len(suspicious_signal_examples["encoded_payload"]) < _MAX_SIGNAL_EXAMPLES
                    )
                )
                evidence_example_preview = (
                    (
                        REDACTED_EVIDENCE_VALUE
                        if sensitive_attr_value
                        else _redact_metagraph_evidence(attr_val, max_chars=120)
                    )
                    if needs_example_preview
                    else None
                )

                if library_match:
                    suspicious_signal_categories.add("dynamic_library_or_path")
                    if len(suspicious_signal_examples["dynamic_library_or_path"]) < _MAX_SIGNAL_EXAMPLES:
                        assert evidence_example_preview is not None
                        suspicious_signal_examples["dynamic_library_or_path"].append(
                            f"{ctx.op}:{evidence_attr_name}:{evidence_example_preview}"
                        )
                    result.add_check(
                        name="MetaGraph External Reference Check",
                        passed=False,
                        message="External library/path reference found in executable TensorFlow op context",
                        severity=IssueSeverity.WARNING,
                        location=evidence_location,
                        details={
                            "op_type": ctx.op,
                            "node_name": evidence_node_name,
                            "attribute": evidence_attr_name,
                            "value_preview": evidence_value_preview,
                        },
                    )

                if command_match or network_match:
                    suspicious_signal_categories.add("command_or_network")
                    if len(suspicious_signal_examples["command_or_network"]) < _MAX_SIGNAL_EXAMPLES:
                        assert evidence_example_preview is not None
                        suspicious_signal_examples["command_or_network"].append(
                            f"{ctx.op}:{evidence_attr_name}:{evidence_example_preview}"
                        )

                    is_function_reference = attr_name.endswith(".func.name")
                    severity = (
                        IssueSeverity.CRITICAL
                        if command_match and (network_match or is_function_reference)
                        else IssueSeverity.WARNING
                    )
                    result.add_check(
                        name="MetaGraph Executable String Check",
                        passed=False,
                        message="Suspicious command/network string found in executable TensorFlow op attribute",
                        severity=severity,
                        location=evidence_location,
                        details={
                            "op_type": ctx.op,
                            "node_name": evidence_node_name,
                            "attribute": evidence_attr_name,
                            "command_pattern": bool(command_match),
                            "network_pattern": bool(network_match),
                            "value_preview": evidence_value_preview,
                        },
                    )

                if encoded_payload_match:
                    suspicious_signal_categories.add("encoded_payload")
                    if len(suspicious_signal_examples["encoded_payload"]) < _MAX_SIGNAL_EXAMPLES:
                        assert evidence_example_preview is not None
                        suspicious_signal_examples["encoded_payload"].append(
                            f"{ctx.op}:{evidence_attr_name}:{evidence_example_preview}"
                        )
                    result.add_check(
                        name="MetaGraph Encoded Payload Check",
                        passed=False,
                        message="Encoded payload indicator found in executable TensorFlow op attribute",
                        severity=IssueSeverity.WARNING,
                        location=evidence_location,
                        details={
                            "op_type": ctx.op,
                            "node_name": evidence_node_name,
                            "attribute": evidence_attr_name,
                            "value_preview": evidence_value_preview,
                        },
                    )

                if oversized_attribute:
                    result.add_check(
                        name="MetaGraph Attribute Size Anomaly",
                        passed=False,
                        message="Large executable-context attribute detected (possible payload stuffing)",
                        severity=IssueSeverity.WARNING,
                        location=evidence_location,
                        details={
                            "op_type": ctx.op,
                            "node_name": evidence_node_name,
                            "attribute": evidence_attr_name,
                            "attribute_length": attr_string.byte_length,
                            "max_expected": _MAX_ATTR_VALUE_BYTES,
                        },
                    )

        for key, collection in metagraph.collection_def.items():
            key_lower = key.lower()
            evidence_key: str | None = None
            sensitive_collection_value = _is_sensitive_metagraph_evidence_key(key)

            if hasattr(collection, "bytes_list"):
                for idx, value in enumerate(collection.bytes_list.value):
                    if len(value) > _MAX_COLLECTION_VALUE_BYTES:
                        if evidence_key is None:
                            evidence_key = _redact_metagraph_evidence(key, max_chars=200)
                        result.add_check(
                            name="MetaGraph Collection Size Anomaly",
                            passed=False,
                            message="Large collection bytes entry detected (possible payload stuffing)",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={
                                "collection_key": evidence_key,
                                "index": idx,
                                "entry_size": len(value),
                                "max_expected": _MAX_COLLECTION_VALUE_BYTES,
                            },
                        )

                    if any(hint in key_lower for hint in _COLLECTION_EXEC_HINTS):
                        decoded = value[:_MAX_COLLECTION_VALUE_BYTES].decode("utf-8", errors="ignore")
                        if _COMMAND_RE.search(decoded) and _NETWORK_RE.search(decoded):
                            if evidence_key is None:
                                evidence_key = _redact_metagraph_evidence(key, max_chars=200)
                            result.add_check(
                                name="MetaGraph Collection Executable Pattern",
                                passed=False,
                                message=(
                                    "Collection metadata contains command+network pattern in executable key context"
                                ),
                                severity=IssueSeverity.WARNING,
                                location=path,
                                details={
                                    "collection_key": evidence_key,
                                    "index": idx,
                                    "value_preview": (
                                        REDACTED_EVIDENCE_VALUE
                                        if sensitive_collection_value
                                        else _redact_metagraph_evidence(decoded, max_chars=200)
                                    ),
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
