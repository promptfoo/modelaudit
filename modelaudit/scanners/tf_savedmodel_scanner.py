"""Scanner for TensorFlow SavedModel directories and files."""

import base64
import contextlib
import hashlib
import logging
import os
import pickletools
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError, Message

from modelaudit.config.explanations import get_tf_op_explanation
from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_OPS, TENSORFLOW_DANGEROUS_OPS
from modelaudit.utils.file.detection import (
    PROTO0_1_MAX_PROBE_BYTES,
    PROTO0_1_MAX_PROBE_OPCODES,
    PROTO0_1_TRIVIAL_LEADING_OPCODES,
    _looks_like_proto0_or_1_pickle,
)
from modelaudit.utils.helpers.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)
from modelaudit.utils.tensorflow_compat import has_tensorflow_protobuf_stubs

from ..core_results import mark_operational_scan_error
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ._evidence_redaction import (
    REDACTED_URL_CREDENTIALS,
    redact_evidence_mapping_key,
    redact_evidence_string,
    redact_evidence_value,
    redact_untrusted_error_message,
)
from .base import BaseScanner, CheckStatus, IssueSeverity, ScanResult
from .keras_utils import find_case_insensitive_substrings, find_lambda_dangerous_patterns

logger = logging.getLogger(__name__)


def _add_keras_metadata_field(
    message: Any,
    *,
    name: str,
    number: int,
    field_type: int,
    label: int = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    type_name: str | None = None,
) -> None:
    field = message.field.add()
    field.name = name
    field.number = number
    field.type = field_type
    field.label = label
    if type_name is not None:
        field.type_name = type_name


def _build_keras_saved_metadata_message_type() -> type[Message]:
    """Build the small Keras metadata schema missing from the vendored TensorFlow stubs."""
    package = "third_party.tensorflow.python.keras.protobuf"
    file_descriptor = descriptor_pb2.FileDescriptorProto(
        name="modelaudit/keras_saved_metadata.proto",
        package=package,
        syntax="proto3",
    )

    version_def = file_descriptor.message_type.add()
    version_def.name = "VersionDef"
    _add_keras_metadata_field(
        version_def, name="producer", number=1, field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32
    )
    _add_keras_metadata_field(
        version_def,
        name="min_consumer",
        number=2,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32,
    )
    _add_keras_metadata_field(
        version_def,
        name="bad_consumers",
        number=3,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
    )

    saved_object = file_descriptor.message_type.add()
    saved_object.name = "SavedObject"
    reserved_range = saved_object.reserved_range.add()
    reserved_range.start = 1
    reserved_range.end = 2
    _add_keras_metadata_field(
        saved_object, name="node_id", number=2, field_type=descriptor_pb2.FieldDescriptorProto.TYPE_INT32
    )
    _add_keras_metadata_field(
        saved_object, name="node_path", number=3, field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    )
    _add_keras_metadata_field(
        saved_object, name="identifier", number=4, field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    )
    _add_keras_metadata_field(
        saved_object, name="metadata", number=5, field_type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    )
    _add_keras_metadata_field(
        saved_object,
        name="version",
        number=6,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        type_name=f".{package}.VersionDef",
    )

    saved_metadata = file_descriptor.message_type.add()
    saved_metadata.name = "SavedMetadata"
    _add_keras_metadata_field(
        saved_metadata,
        name="nodes",
        number=1,
        field_type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
        type_name=f".{package}.SavedObject",
    )

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_descriptor)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{package}.SavedMetadata"))


_KERAS_SAVED_METADATA_MESSAGE_TYPE = _build_keras_saved_metadata_message_type()

# Derive from centralized list; keep severities unified here
# Exclude Python ops (handled elsewhere) and pure decode ops from the generic pass
_EXCLUDE_FROM_GENERIC = {"DecodeRaw", "DecodeJpeg", "DecodePng"}
DANGEROUS_TF_OPERATIONS = {
    op: IssueSeverity.CRITICAL for op in TENSORFLOW_DANGEROUS_OPS if op not in _EXCLUDE_FROM_GENERIC
}

# Python operations that require special handling
PYTHON_OPS = ("PyFunc", "PyCall", "PyFuncStateless", "EagerPyFunc")

_ASSET_SCRIPT_SHEBANG = b"#!"
_ASSET_ELF_HEADER = b"\x7fELF"
_ASSET_MACHO_HEADERS = (
    b"\xfe\xed\xfa\xce",  # MH_MAGIC
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
)
_ASSET_PE_HEADER = b"MZ"  # Windows PE executables
_ASSET_PICKLE_PREFIXES = tuple(bytes([0x80, protocol]) for protocol in range(2, 6))
_ASSET_PROBE_BYTES = max(8192, PROTO0_1_MAX_PROBE_BYTES)
_ASSET_TRIVIAL_PADDING_COMPLETE_BYTES = 2 * _ASSET_PROBE_BYTES
_MAX_PROTOBUF_PARSE_BYTES = 20 * 1024 * 1024
_MAX_SAVEDMODEL_META_GRAPHS = 64
_MAX_SAVEDMODEL_GRAPH_NODES = 200_000
_MAX_SAVEDMODEL_FUNCTIONS = 50_000
_MAX_SAVEDMODEL_FUNCTION_NODES = 100_000
_MAX_SAVEDMODEL_NODE_ATTRIBUTES = 1_000_000
_MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES = 100_000
_MAX_SAVEDMODEL_COLLECTIONS = 50_000
_MAX_SAVEDMODEL_COLLECTION_VALUES = 100_000
_MAX_KERAS_METADATA_PARSE_BYTES = _MAX_PROTOBUF_PARSE_BYTES
_MAX_COLLECTION_VALUE_BYTES = 256 * 1024
_PROTOBUF_STRING_LENGTH_CHECK_THRESHOLD = 10_000
_MAX_PROTOBUF_STRING_FULL_SCAN_CHARS = 32 * 1024
_PROTOBUF_STRING_SCAN_WINDOW_CHARS = 16 * 1024
_PROTOBUF_STRING_INCOMPLETE_REASON = "savedmodel_protobuf_string_scan_incomplete"
_CORE_ROOT_MODEL_FILES = frozenset({"saved_model.pb", "keras_metadata.pb", "fingerprint.pb"})
_CORE_ROOT_MODEL_DIRS = frozenset({"assets", "assets.extra", "variables"})
_CORE_ROOT_ASSET_DIRS = frozenset({"assets", "assets.extra"})
_ASSET_PYTHON_PATTERN = re.compile(
    r"(?m)(^\s*(?:"
    r"from\s+[A-Za-z_][\w.]*\s+import\s+"
    r"|import\s+[A-Za-z_][\w.]*"
    r"|def\s+[A-Za-z_]\w*\s*\("
    r"|class\s+[A-Za-z_]\w*\s*[:(]"
    r"))"
)


def _is_trivial_proto0_padding_prefix(sample: bytes) -> bool:
    """Return whether a bounded prefix is entirely harmless protocol-0 padding."""
    opcode_count = 0
    try:
        for opcode, _argument, _position in pickletools.genops(sample):
            opcode_count += 1
            if opcode.name not in PROTO0_1_TRIVIAL_LEADING_OPCODES:
                return False
            if opcode_count >= PROTO0_1_MAX_PROBE_OPCODES:
                return False
    except ValueError as error:
        return opcode_count >= 2 and str(error).startswith("pickle exhausted before seeing STOP")
    except Exception:
        return False
    return False


_PYFUNC_DANGEROUS_REFERENCE_TOKENS = frozenset(
    {
        "__builtin__",
        "__builtins__",
        "builtins",
        "compile",
        "ctypes",
        "eval",
        "exec",
        "importlib",
        "marshal",
        "nt",
        "open",
        "os",
        "pickle",
        "popen",
        "posix",
        "runpy",
        "socket",
        "spawn",
        "subprocess",
        "sys",
        "system",
        "webbrowser",
    }
)
_SUSPICIOUS_FUNCTION_NAME_PATTERNS = (
    ("eval", re.compile(r"(?:^|[^a-z0-9])eval(?:[^a-z0-9]|$)")),
    ("exec", re.compile(r"(?:^|[^a-z0-9])exec(?:[^a-z0-9]|$)")),
    ("compile", re.compile(r"(?:^|[^a-z0-9])compile(?:[^a-z0-9]|$)")),
    ("__import__", re.compile(r"(?:^|[^a-z0-9])__import__(?:[^a-z0-9]|$)")),
    ("system", re.compile(r"(?:^|[^a-z0-9])system(?:[^a-z0-9]|$)")),
    ("popen", re.compile(r"(?:^|[^a-z0-9])popen(?:[^a-z0-9]|$)")),
    ("subprocess", re.compile(r"(?:^|[^a-z0-9])subprocess(?:[^a-z0-9]|$)")),
    ("pickle", re.compile(r"(?:^|[^a-z0-9])pickle(?:[^a-z0-9]|$)")),
    ("marshal", re.compile(r"(?:^|[^a-z0-9])marshal(?:[^a-z0-9]|$)")),
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
_COLLECTION_COMMAND_RE = re.compile(
    r"(?i)(?:\bos\.system\b|\bsubprocess\.(?:run|popen|call|check_call|check_output)\b|"
    r"\b(?:bash|sh|zsh|powershell(?:\.exe)?|cmd(?:\.exe)?)\b|\b(?:curl|wget)\b\s+https?://|"
    r"\bpython\s+-c\b|/bin/(?:sh|bash))"
)
_COLLECTION_NETWORK_RE = re.compile(
    r"(?i)(?:https?://|wss?://|ftp://|tcp://|udp://|\bsocket\b|\b(?:\d{1,3}\.){3}\d{1,3}\b)"
)
_STANDALONE_KEY_SECRET_RE = re.compile(
    r"\b(?:"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[ps]_[A-Za-z0-9]{36}|"
    r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|"
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*|"
    r"sk-(?:proj-)?[A-Za-z0-9]{24,}|"
    r"xox[baprs]-[0-9A-Za-z-]{20,}"
    r")\b"
)
_PREVIEW_TOKEN_LOOKAHEAD_CHARS = 512
_PREVIEW_TOKEN_SUFFIX_RE = re.compile(r"([A-Za-z0-9._~+-]+)\Z")
_PREVIEW_TOKEN_CONTINUATION_RE = re.compile(r"[A-Za-z0-9._~+=-]*")
_PREVIEW_URL_SUFFIX_RE = re.compile(
    r"(?i)(?P<scheme>(?:https?|ftp|ftps|ssh|telnet|wss?|tcp|udp|s3|gs|az|wasbs?|abfss?|file)://)"
    r"[^\s\"'<>]*\Z"
)
_PREVIEW_URL_CONTINUATION_RE = re.compile(r"[^\s\"'<>]*")
_URL_AUTHORITY_TERMINATOR_RE = re.compile(r"[/?#]")


def _redact_sensitive_preview_text(text: str) -> str:
    """Redact secret-shaped values from attacker-controlled evidence previews."""
    redacted = redact_evidence_string(text, max_chars=None)
    return _STANDALONE_KEY_SECRET_RE.sub("<redacted>", redacted)


def _url_authority_contains_userinfo(url_text: str) -> bool:
    rest = url_text.split("://", 1)[1]
    authority = _URL_AUTHORITY_TERMINATOR_RE.split(rest, maxsplit=1)[0]
    return "@" in authority


def _redact_preview_boundary_url_userinfo_prefix(text: str, limit: int) -> str:
    preview_source = text[:limit]
    suffix_match = _PREVIEW_URL_SUFFIX_RE.search(preview_source)
    if suffix_match is None:
        return preview_source

    lookahead = text[limit : limit + _PREVIEW_TOKEN_LOOKAHEAD_CHARS]
    continuation_match = _PREVIEW_URL_CONTINUATION_RE.match(lookahead)
    candidate = suffix_match.group(0) + (continuation_match.group(0) if continuation_match else "")
    if not _url_authority_contains_userinfo(candidate) or _url_authority_contains_userinfo(suffix_match.group(0)):
        return preview_source

    return f"{preview_source[: suffix_match.start()]}{suffix_match.group('scheme')}{REDACTED_URL_CREDENTIALS}"


def _redact_preview_boundary_secret_prefix(text: str, limit: int) -> str:
    preview_source = text[:limit]
    url_redacted = _redact_preview_boundary_url_userinfo_prefix(text, limit)
    if url_redacted != preview_source:
        return url_redacted

    suffix_match = _PREVIEW_TOKEN_SUFFIX_RE.search(preview_source)
    if suffix_match is None:
        return preview_source

    lookahead = text[limit : limit + _PREVIEW_TOKEN_LOOKAHEAD_CHARS]
    continuation_match = _PREVIEW_TOKEN_CONTINUATION_RE.match(lookahead)
    candidate = suffix_match.group(1) + (continuation_match.group(0) if continuation_match else "")
    if not _STANDALONE_KEY_SECRET_RE.fullmatch(candidate):
        return preview_source

    return f"{preview_source[: suffix_match.start(1)]}<redacted>"


def _safe_decoded_preview(text: str, limit: int) -> str:
    """Return a bounded decoded preview safe for serialized findings."""
    preview_source = _redact_preview_boundary_secret_prefix(text, limit) if len(text) > limit else text
    redacted = _redact_sensitive_preview_text(preview_source)
    if len(text) <= limit and len(redacted) <= limit:
        return redacted
    return f"{redacted[:limit]}..."


def _redact_savedmodel_detail_string(value: Any, max_chars: int = 200) -> str:
    return redact_evidence_string(str(value), max_chars=max_chars)


def _redact_savedmodel_detail_value(value: Any, max_string_chars: int = 200) -> Any:
    return redact_evidence_value(value, max_string_chars=max_string_chars)


def _redact_savedmodel_relative_path(file_path: Path, model_root: Path) -> str:
    try:
        relative_path = file_path.relative_to(model_root)
    except ValueError:
        relative_path = Path(file_path.name)
    return str(Path(*(_redact_savedmodel_detail_string(part) for part in relative_path.parts)))


def _redact_savedmodel_file_location(file_path: Path, model_root: Path) -> str:
    return str(model_root / _redact_savedmodel_relative_path(file_path, model_root))


def _looks_like_pe_executable(content_head: bytes) -> bool:
    """Return True for a minimally valid PE/COFF executable prefix."""
    if not content_head.startswith(_ASSET_PE_HEADER) or len(content_head) < 0x40:
        return False

    pe_offset = int.from_bytes(content_head[0x3C:0x40], "little", signed=False)
    if pe_offset < 0x40 or pe_offset + 4 > len(content_head):
        return False
    return content_head[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _strip_leading_comment_lines(content: bytes) -> bytes:
    """Remove leading comment/blank lines before protocol 0/1 pickle probing."""
    offset = 0
    content_len = len(content)

    while offset < content_len:
        line_start = offset
        while offset < content_len and content[offset] not in (0x0A, 0x0D):
            offset += 1
        line = content[line_start:offset].lstrip()
        while offset < content_len and content[offset] in (0x0A, 0x0D):
            offset += 1

        if not line or line.startswith(b"#"):
            continue
        return content[line_start:]

    return b""


# Create a placeholder for type hints when TensorFlow is not available
class SavedModel:  # type: ignore[no-redef]
    """Placeholder for SavedModel when TensorFlow is not installed"""

    meta_graphs: ClassVar[list] = []


SavedModelType = SavedModel


@dataclass(frozen=True)
class SavedModelNodeContext:
    """Context for a node stored in a graph body or function definition."""

    node: Any
    meta_graph_tag: str
    node_scope: str
    function_name: str | None = None


@dataclass(frozen=True)
class SavedModelGraphBudget:
    """Bounded structure summary collected before graph traversal."""

    meta_graph_count: int
    graph_node_count: int
    function_count: int
    function_node_count: int
    node_attribute_count: int
    attribute_string_value_count: int
    collection_count: int
    collection_value_count: int
    limit_reason: str | None = None
    limit_name: str | None = None

    @property
    def exceeded(self) -> bool:
        return self.limit_reason is not None


class TensorFlowSavedModelScanner(BaseScanner):
    """Scanner for TensorFlow SavedModel format"""

    name = "tf_savedmodel"
    description = "Scans TensorFlow SavedModel for suspicious operations"
    supported_extensions: ClassVar[list[str]] = [".pb", ""]  # Empty string for directories

    @classmethod
    def directory_owner_source_in_scope(cls, relative_parts: tuple[str, ...]) -> bool:
        """Bind files whose contents can be read by SavedModel directory analysis."""
        if not relative_parts:
            return False
        root_name = relative_parts[0]
        if root_name in _CORE_ROOT_ASSET_DIRS:
            return True
        if root_name == "variables":
            return (
                relative_parts[-1].lower().endswith((".txt", ".md", ".json", ".yaml", ".yml", ".py", ".cfg", ".conf"))
            )
        if len(relative_parts) == 1 and root_name in {"saved_model.pb", "keras_metadata.pb"}:
            return True
        return not (len(relative_parts) == 1 and root_name == "fingerprint.pb")

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Additional scanner-specific configuration
        suspicious_ops = self.config.get("suspicious_ops", SUSPICIOUS_OPS)
        self.suspicious_ops = set(SUSPICIOUS_OPS if suspicious_ops is None else suspicious_ops)
        self.blacklist_patterns = [
            pattern for pattern in (self.config.get("blacklist_patterns") or []) if isinstance(pattern, str) and pattern
        ]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not has_tensorflow_protobuf_stubs():
            return False

        if os.path.isfile(path):
            # Handle any .pb file (protobuf format)
            ext = os.path.splitext(path)[1].lower()
            return ext == ".pb"
        if os.path.isdir(path):
            # For directory, check if saved_model.pb exists
            return os.path.exists(os.path.join(path, "saved_model.pb"))
        return False

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _finish_read_failure(result: ScanResult, path: str, error: OSError) -> ScanResult:
        redacted_error = redact_untrusted_error_message(error)
        mark_inconclusive_scan_result(result, "savedmodel_read_failed")
        mark_operational_scan_error(result, "savedmodel_read_failed")
        result.add_check(
            name="SavedModel File Read",
            passed=False,
            message=f"Unable to read TF SavedModel file: {redacted_error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": redacted_error,
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "savedmodel_read_failed",
            },
        )
        result.finish(success=False)
        return result

    @staticmethod
    def _collect_graph_budget(saved_model: Any) -> SavedModelGraphBudget:
        meta_graphs = getattr(saved_model, "meta_graphs", [])
        meta_graph_count = len(meta_graphs)
        graph_node_count = 0
        function_count = 0
        function_node_count = 0
        node_attribute_count = 0
        attribute_string_value_count = 0
        collection_count = 0
        collection_value_count = 0

        def budget(
            limit_reason: str | None = None,
            limit_name: str | None = None,
        ) -> SavedModelGraphBudget:
            return SavedModelGraphBudget(
                meta_graph_count=meta_graph_count,
                graph_node_count=graph_node_count,
                function_count=function_count,
                function_node_count=function_node_count,
                node_attribute_count=node_attribute_count,
                attribute_string_value_count=attribute_string_value_count,
                collection_count=collection_count,
                collection_value_count=collection_value_count,
                limit_reason=limit_reason,
                limit_name=limit_name,
            )

        def collect_node_attributes(nodes: Any) -> SavedModelGraphBudget | None:
            nonlocal node_attribute_count, attribute_string_value_count

            for node in nodes:
                attributes = getattr(node, "attr", {})
                node_attribute_count += len(attributes)
                if node_attribute_count > _MAX_SAVEDMODEL_NODE_ATTRIBUTES:
                    return budget("node_attribute_limit_exceeded", "node_attribute_count")

                for attribute in attributes.values():
                    value_kind = attribute.WhichOneof("value")
                    if value_kind == "s":
                        attribute_string_value_count += 1
                    elif value_kind == "list":
                        attribute_string_value_count += len(attribute.list.s)
                    if attribute_string_value_count > _MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES:
                        return budget("attribute_string_value_limit_exceeded", "attribute_string_value_count")

            return None

        if meta_graph_count > _MAX_SAVEDMODEL_META_GRAPHS:
            return budget("meta_graph_limit_exceeded", "meta_graph_count")

        for meta_graph in meta_graphs:
            graph_def = meta_graph.graph_def
            graph_node_count += len(graph_def.node)
            if graph_node_count > _MAX_SAVEDMODEL_GRAPH_NODES:
                return budget("graph_node_limit_exceeded", "graph_node_count")
            if node_budget := collect_node_attributes(graph_def.node):
                return node_budget

            collections = getattr(meta_graph, "collection_def", {})
            collection_count += len(collections)
            if collection_count > _MAX_SAVEDMODEL_COLLECTIONS:
                return budget("collection_limit_exceeded", "collection_count")
            for collection in collections.values():
                collection_value_count += len(collection.bytes_list.value)
                if collection_value_count > _MAX_SAVEDMODEL_COLLECTION_VALUES:
                    return budget("collection_value_limit_exceeded", "collection_value_count")

            function_library = getattr(graph_def, "library", None)
            if function_library is None:
                continue

            functions = getattr(function_library, "function", [])
            function_count += len(functions)
            if function_count > _MAX_SAVEDMODEL_FUNCTIONS:
                return budget("function_limit_exceeded", "function_count")

            for function_def in functions:
                function_node_count += len(function_def.node_def)
                if function_node_count > _MAX_SAVEDMODEL_FUNCTION_NODES:
                    return budget("function_node_limit_exceeded", "function_node_count")
                if node_budget := collect_node_attributes(function_def.node_def):
                    return node_budget

        return budget()

    def _record_graph_budget_metadata(self, result: ScanResult, budget: SavedModelGraphBudget) -> None:
        result.metadata.update(
            {
                "meta_graph_count": budget.meta_graph_count,
                "graph_node_count": budget.graph_node_count,
                "function_count": budget.function_count,
                "function_node_count": budget.function_node_count,
                "node_attribute_count": budget.node_attribute_count,
                "attribute_string_value_count": budget.attribute_string_value_count,
                "collection_count": budget.collection_count,
                "collection_value_count": budget.collection_value_count,
                "max_meta_graphs": _MAX_SAVEDMODEL_META_GRAPHS,
                "max_graph_nodes": _MAX_SAVEDMODEL_GRAPH_NODES,
                "max_functions": _MAX_SAVEDMODEL_FUNCTIONS,
                "max_function_nodes": _MAX_SAVEDMODEL_FUNCTION_NODES,
                "max_node_attributes": _MAX_SAVEDMODEL_NODE_ATTRIBUTES,
                "max_attribute_string_values": _MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES,
                "max_collections": _MAX_SAVEDMODEL_COLLECTIONS,
                "max_collection_values": _MAX_SAVEDMODEL_COLLECTION_VALUES,
            }
        )

    def _finish_graph_budget_failure(
        self,
        result: ScanResult,
        path: str,
        budget: SavedModelGraphBudget,
    ) -> ScanResult:
        reason = "savedmodel_graph_traversal_budget_exceeded"
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        self._record_graph_budget_metadata(result, budget)
        result.add_check(
            name="SavedModel Graph Traversal Budget",
            passed=False,
            message="SavedModel graph structure exceeds bounded traversal budget",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "limit_reason": budget.limit_reason,
                "limit_name": budget.limit_name,
                "meta_graph_count": budget.meta_graph_count,
                "graph_node_count": budget.graph_node_count,
                "function_count": budget.function_count,
                "function_node_count": budget.function_node_count,
                "node_attribute_count": budget.node_attribute_count,
                "attribute_string_value_count": budget.attribute_string_value_count,
                "collection_count": budget.collection_count,
                "collection_value_count": budget.collection_value_count,
                "max_meta_graphs": _MAX_SAVEDMODEL_META_GRAPHS,
                "max_graph_nodes": _MAX_SAVEDMODEL_GRAPH_NODES,
                "max_functions": _MAX_SAVEDMODEL_FUNCTIONS,
                "max_function_nodes": _MAX_SAVEDMODEL_FUNCTION_NODES,
                "max_node_attributes": _MAX_SAVEDMODEL_NODE_ATTRIBUTES,
                "max_attribute_string_values": _MAX_SAVEDMODEL_ATTRIBUTE_STRING_VALUES,
                "max_collections": _MAX_SAVEDMODEL_COLLECTIONS,
                "max_collection_values": _MAX_SAVEDMODEL_COLLECTION_VALUES,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )
        result.finish(success=False)
        return result

    @staticmethod
    def _mark_keras_metadata_scan_failure(result: ScanResult, path: str, error: Exception) -> None:
        redacted_error = redact_untrusted_error_message(error)
        reason = "keras_metadata_parse_failed"
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        result.add_check(
            name="Keras Metadata Parsing",
            passed=False,
            message=f"Unable to parse keras_metadata.pb: {redacted_error}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": redacted_error,
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    @staticmethod
    def _mark_keras_metadata_parse_budget_exceeded(result: ScanResult, path: str) -> None:
        reason = "keras_metadata_parse_budget_exceeded"
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        result.add_check(
            name="Keras Metadata Parse Budget",
            passed=False,
            message="keras_metadata.pb exceeds bounded parse budget",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "max_parse_bytes": _MAX_KERAS_METADATA_PARSE_BYTES,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    @staticmethod
    def _add_bounded_file_integrity_check(path: str, result: ScanResult, content: bytes) -> None:
        """Record hashes for the same bounded metadata bytes used by security analysis."""
        hashes: dict[str, str | None] = {"md5": None, "sha256": None, "sha512": None}
        try:
            hashes["md5"] = hashlib.md5(content, usedforsecurity=False).hexdigest()
        except Exception as exc:
            logger.warning("Failed to calculate MD5 hash for %s: %s", path, exc)
        try:
            hashes["sha256"] = hashlib.sha256(content).hexdigest()
        except Exception as exc:
            logger.warning("Failed to calculate SHA256 hash for %s: %s", path, exc)
        try:
            hashes["sha512"] = hashlib.sha512(content).hexdigest()
        except Exception as exc:
            logger.warning("Failed to calculate SHA512 hash for %s: %s", path, exc)

        result.add_check(
            name="File Integrity Hash",
            passed=True,
            message="File integrity hashes calculated",
            location=path,
            details={**hashes, "file_size": len(content)},
        )
        result.metadata["file_hashes"] = hashes
        result.metadata["file_size"] = len(content)

    def scan(self, path: str) -> ScanResult:
        """Scan a TensorFlow SavedModel file or directory"""
        # Check if path is valid
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

        # Store the file path for use in issue locations
        self.current_file_path = path

        # Check if TensorFlow protos are available (vendored or from TensorFlow)
        if not has_tensorflow_protobuf_stubs():
            result = self._create_result()
            result.add_check(
                name="TensorFlow Protos Check",
                passed=False,
                message="TensorFlow protos unavailable. Vendored protos may be missing or corrupted.",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "path": path,
                    "required_package": "tensorflow",
                    "note": "Vendored protos should be bundled; reinstall if missing",
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        # Determine if path is file or directory
        if os.path.isfile(path):
            return self._scan_saved_model_file(path)
        if os.path.isdir(path):
            return self._scan_saved_model_directory(path)
        result = self._create_result()
        result.add_check(
            name="Path Type Validation",
            passed=False,
            message=f"Path is neither a file nor a directory: {path}",
            severity=IssueSeverity.CRITICAL,
            location=path,
            details={"path": path},
            rule_code="S902",
        )
        result.finish(success=False)
        return result

    def _scan_saved_model_file(self, path: str) -> ScanResult:
        """Scan a single SavedModel protobuf file"""
        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        result.metadata["scan_byte_limit"] = _MAX_PROTOBUF_PARSE_BYTES

        if path.endswith("keras_metadata.pb") and file_size > _MAX_KERAS_METADATA_PARSE_BYTES:
            self._mark_keras_metadata_parse_budget_exceeded(result, path)
            result.finish(success=False)
            return result

        self.current_file_path = path

        # Check if this is a keras_metadata.pb file
        if path.endswith("keras_metadata.pb"):
            # Scan it for Lambda layers
            try:
                self._scan_keras_metadata(path, result, add_integrity_check=True)
            except OSError as e:
                return self._finish_read_failure(result, path, e)
            result.finish(
                success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
            )
            return result

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            # Import vendored protos module (sets up sys.path for tensorflow.* imports)
            # Order matters: modelaudit.protos must be imported first to set up sys.path
            import modelaudit.protos  # noqa: F401, I001

            from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

            with open(path, "rb") as f:
                content = f.read(_MAX_PROTOBUF_PARSE_BYTES + 1)
                result.bytes_scanned = min(len(content), _MAX_PROTOBUF_PARSE_BYTES)

                if len(content) > _MAX_PROTOBUF_PARSE_BYTES:
                    result.metadata["operational_error"] = True
                    result.metadata["operational_error_reason"] = "savedmodel_parse_budget_exceeded"
                    result.add_check(
                        name="SavedModel Parse Budget",
                        passed=False,
                        message="SavedModel exceeds bounded parse budget",
                        severity=IssueSeverity.INFO,
                        location=path,
                        details={"max_parse_bytes": _MAX_PROTOBUF_PARSE_BYTES},
                    )
                    result.finish(success=False)
                    return result

                saved_model = SavedModel()
                saved_model.ParseFromString(content)
                graph_budget = self._collect_graph_budget(saved_model)
                if graph_budget.exceeded:
                    return self._finish_graph_budget_failure(result, path, graph_budget)
                self._record_graph_budget_metadata(result, graph_budget)

                for op_info in self._scan_tf_operations(saved_model):
                    result.add_check(
                        name="TensorFlow Operation Security Check",
                        passed=False,
                        message=f"Dangerous TensorFlow operation: {op_info['operation']}",
                        severity=op_info["severity"],
                        location=op_info["location"],
                        details=op_info["details"],
                        why=get_tf_op_explanation(op_info["operation"]),
                    )

                self._analyze_saved_model(saved_model, result)

        except OSError as e:
            return self._finish_read_failure(result, path, e)
        except Exception as e:
            redacted_error = redact_untrusted_error_message(e)
            result.add_check(
                name="SavedModel Parsing",
                passed=False,
                message=f"Error scanning TF SavedModel file: {redacted_error}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": redacted_error, "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
        )
        return result

    def _scan_saved_model_directory(self, dir_path: str) -> ScanResult:
        """Scan a SavedModel directory"""
        result = self._create_result()
        model_root = Path(dir_path)

        # Look for saved_model.pb in the directory
        saved_model_path = model_root / "saved_model.pb"
        if not saved_model_path.exists():
            result.add_check(
                name="SavedModel Structure Check",
                passed=False,
                message="No saved_model.pb found in directory.",
                severity=IssueSeverity.CRITICAL,
                location=dir_path,
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        # Scan the saved_model.pb file
        file_scan_result = self._scan_saved_model_file(str(saved_model_path))
        result.merge(file_scan_result)

        # Check for keras_metadata.pb which contains Lambda layer definitions
        keras_metadata_path = model_root / "keras_metadata.pb"
        if keras_metadata_path.exists():
            try:
                self._scan_keras_metadata(str(keras_metadata_path), result)
            except OSError as e:
                result.merge(self._finish_read_failure(self._create_result(), str(keras_metadata_path), e))

        self._scan_saved_model_assets(model_root, result)
        self._scan_saved_model_root_siblings(model_root, result)

        # Check for other suspicious files in the directory
        for root, _dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                redacted_file = _redact_savedmodel_detail_string(file)
                redacted_location = _redact_savedmodel_file_location(file_path, model_root)
                redacted_directory = str(Path(redacted_location).parent)
                if (
                    any(
                        file_path.is_relative_to(model_root / asset_dir_name)
                        for asset_dir_name in ("assets", "assets.extra")
                    )
                    and file_path.is_symlink()
                ):
                    continue
                # Look for potentially suspicious Python files
                if file.endswith(".py"):
                    result.add_check(
                        name="Python File Detection",
                        passed=False,
                        message=f"Python file found in SavedModel: {redacted_file}",
                        severity=IssueSeverity.INFO,
                        location=redacted_location,
                        rule_code="S902",
                        details={"file": redacted_file, "directory": redacted_directory},
                    )

                # Check for blacklist patterns in text files
                if self.blacklist_patterns:
                    try:
                        # Only check text files
                        if file.endswith(
                            (
                                ".txt",
                                ".md",
                                ".json",
                                ".yaml",
                                ".yml",
                                ".py",
                                ".cfg",
                                ".conf",
                            ),
                        ):
                            with Path(file_path).open(
                                encoding="utf-8",
                                errors="ignore",
                            ) as f:
                                content = f.read()
                                for pattern in self.blacklist_patterns:
                                    if pattern in content:
                                        result.add_check(
                                            name="Blacklist Pattern Check",
                                            passed=False,
                                            message=f"Blacklisted pattern '{pattern}' found in file {redacted_file}",
                                            severity=IssueSeverity.CRITICAL,
                                            location=redacted_location,
                                            rule_code="S902",
                                            details={"pattern": pattern, "file": redacted_file},
                                        )
                    except Exception as e:
                        redacted_error = redact_untrusted_error_message(e)
                        result.add_check(
                            name="File Read Check",
                            passed=False,
                            message=f"Error reading file {redacted_file}: {redacted_error}",
                            severity=IssueSeverity.DEBUG,
                            location=redacted_location,
                            rule_code="S902",
                            details={
                                "file": redacted_file,
                                "exception": redacted_error,
                                "exception_type": type(e).__name__,
                            },
                        )

        result.finish(
            success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
        )
        return result

    def _scan_saved_model_assets(self, model_root: Path, result: ScanResult) -> None:
        """Scan SavedModel asset directories for suspicious executable content."""
        for assets_dir_name in ("assets", "assets.extra"):
            assets_dir = model_root / assets_dir_name
            if not assets_dir.exists() and not assets_dir.is_symlink():
                continue

            try:
                assets_dir_stat = assets_dir.lstat()
            except OSError as exc:
                redacted_error = redact_untrusted_error_message(exc)
                result.add_check(
                    name="SavedModel Assets Security Check",
                    passed=False,
                    message=(
                        f"Cannot inspect asset directory for security analysis: {assets_dir_name}: {redacted_error}"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=str(assets_dir),
                    details={
                        "file_name": assets_dir_name,
                        "detected_content_type": "unscannable_asset_dir",
                        "asset_kind": "stat_error",
                        "exception": redacted_error,
                        "exception_type": type(exc).__name__,
                    },
                    rule_code="S902",
                )
                continue

            if stat.S_ISLNK(assets_dir_stat.st_mode):
                result.add_check(
                    name="SavedModel Assets Security Check",
                    passed=False,
                    message=f"Symlinked asset directory is not traversed during security analysis: {assets_dir_name}",
                    severity=IssueSeverity.WARNING,
                    location=str(assets_dir),
                    details={
                        "file_name": assets_dir_name,
                        "detected_content_type": "unscannable_asset_dir",
                        "asset_kind": "symlink_directory",
                    },
                    rule_code="S902",
                )
                continue

            if not stat.S_ISDIR(assets_dir_stat.st_mode):
                continue

            for root, dir_names, files in os.walk(assets_dir):
                retained_dirs: list[str] = []
                for dir_name in dir_names:
                    child_dir = Path(root) / dir_name
                    redacted_dir_name = _redact_savedmodel_detail_string(dir_name)
                    redacted_relative_dir = _redact_savedmodel_relative_path(child_dir, model_root)
                    redacted_dir_location = _redact_savedmodel_file_location(child_dir, model_root)
                    try:
                        child_stat = child_dir.lstat()
                    except OSError as exc:
                        redacted_error = redact_untrusted_error_message(exc)
                        result.add_check(
                            name="SavedModel Assets Security Check",
                            passed=False,
                            message=(
                                "Cannot inspect nested asset directory for security analysis: "
                                f"{redacted_relative_dir}: {redacted_error}"
                            ),
                            severity=IssueSeverity.WARNING,
                            location=redacted_dir_location,
                            details={
                                "file_name": redacted_dir_name,
                                "detected_content_type": "unscannable_asset_dir",
                                "asset_kind": "stat_error",
                                "exception": redacted_error,
                                "exception_type": type(exc).__name__,
                            },
                            rule_code="S902",
                        )
                        continue

                    if stat.S_ISLNK(child_stat.st_mode):
                        result.add_check(
                            name="SavedModel Assets Security Check",
                            passed=False,
                            message=(
                                "Symlinked nested asset directory is not traversed during security analysis: "
                                f"{redacted_relative_dir}"
                            ),
                            severity=IssueSeverity.WARNING,
                            location=redacted_dir_location,
                            details={
                                "file_name": redacted_dir_name,
                                "detected_content_type": "unscannable_asset_dir",
                                "asset_kind": "symlink_directory",
                            },
                            rule_code="S902",
                        )
                        continue

                    if stat.S_ISDIR(child_stat.st_mode):
                        retained_dirs.append(dir_name)

                dir_names[:] = retained_dirs

                for file_name in files:
                    file_path = Path(root) / file_name
                    detected_types = self._detect_suspicious_asset_content(file_path, result, model_root=model_root)
                    if not detected_types:
                        continue

                    file_size = self.get_file_size(str(file_path))
                    redacted_file_name = _redact_savedmodel_detail_string(file_name)
                    redacted_relative_path = _redact_savedmodel_relative_path(file_path, model_root)
                    result.add_check(
                        name="SavedModel Assets Security Check",
                        passed=False,
                        message=(
                            "Suspicious executable-like content detected in SavedModel assets: "
                            f"{redacted_relative_path}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=_redact_savedmodel_file_location(file_path, model_root),
                        details={
                            "file_name": redacted_file_name,
                            "detected_content_type": ", ".join(detected_types),
                            "size": file_size,
                        },
                        rule_code="S902",
                    )

    def _scan_saved_model_root_siblings(self, model_root: Path, result: ScanResult) -> None:
        """Scan non-canonical root entries that can accompany a SavedModel."""
        for child_path in model_root.iterdir():
            redacted_child_name = _redact_savedmodel_detail_string(child_path.name)
            redacted_child_location = _redact_savedmodel_file_location(child_path, model_root)
            try:
                child_stat = child_path.lstat()
            except OSError as exc:
                redacted_error = redact_untrusted_error_message(exc)
                result.add_check(
                    name="SavedModel Supplemental Directory Security Check",
                    passed=False,
                    message=f"Cannot inspect SavedModel supplemental entry: {redacted_child_name}: {redacted_error}",
                    severity=IssueSeverity.WARNING,
                    location=redacted_child_location,
                    details={
                        "file_name": redacted_child_name,
                        "detected_content_type": "unscannable_supplemental_entry",
                        "entry_kind": "stat_error",
                        "exception": redacted_error,
                        "exception_type": type(exc).__name__,
                    },
                    rule_code="S902",
                )
                continue

            if child_path.name in _CORE_ROOT_MODEL_FILES and stat.S_ISREG(child_stat.st_mode):
                continue
            if child_path.name in _CORE_ROOT_ASSET_DIRS and (
                stat.S_ISDIR(child_stat.st_mode) or stat.S_ISLNK(child_stat.st_mode)
            ):
                continue
            if child_path.name in _CORE_ROOT_MODEL_DIRS and stat.S_ISDIR(child_stat.st_mode):
                continue
            if stat.S_ISDIR(child_stat.st_mode):
                self._scan_saved_model_supplemental_directory(model_root, child_path, result)
                continue

            self._scan_saved_model_supplemental_file(model_root, child_path, result)

    def _scan_saved_model_supplemental_directory(
        self,
        model_root: Path,
        directory_path: Path,
        result: ScanResult,
    ) -> None:
        """Scan a non-canonical SavedModel sibling directory without following symlinks."""
        for root, dir_names, files in os.walk(directory_path):
            retained_dirs: list[str] = []
            for dir_name in dir_names:
                child_dir = Path(root) / dir_name
                redacted_dir_name = _redact_savedmodel_detail_string(dir_name)
                redacted_relative_dir = _redact_savedmodel_relative_path(child_dir, model_root)
                redacted_dir_location = _redact_savedmodel_file_location(child_dir, model_root)
                try:
                    child_stat = child_dir.lstat()
                except OSError as exc:
                    redacted_error = redact_untrusted_error_message(exc)
                    result.add_check(
                        name="SavedModel Supplemental Directory Security Check",
                        passed=False,
                        message=(
                            "Cannot inspect nested SavedModel supplemental directory: "
                            f"{redacted_relative_dir}: {redacted_error}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=redacted_dir_location,
                        details={
                            "file_name": redacted_dir_name,
                            "detected_content_type": "unscannable_supplemental_dir",
                            "entry_kind": "stat_error",
                            "exception": redacted_error,
                            "exception_type": type(exc).__name__,
                        },
                        rule_code="S902",
                    )
                    continue

                if stat.S_ISLNK(child_stat.st_mode):
                    result.add_check(
                        name="SavedModel Supplemental Directory Security Check",
                        passed=False,
                        message=(
                            "Symlinked SavedModel supplemental directory is not traversed during security analysis: "
                            f"{redacted_relative_dir}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=redacted_dir_location,
                        details={
                            "file_name": redacted_dir_name,
                            "detected_content_type": "unscannable_supplemental_dir",
                            "entry_kind": "symlink_directory",
                        },
                        rule_code="S902",
                    )
                    continue

                if stat.S_ISDIR(child_stat.st_mode):
                    retained_dirs.append(dir_name)

            dir_names[:] = retained_dirs

            for file_name in files:
                self._scan_saved_model_supplemental_file(model_root, Path(root) / file_name, result)

    def _scan_saved_model_supplemental_file(
        self,
        model_root: Path,
        file_path: Path,
        result: ScanResult,
    ) -> None:
        """Scan one supplemental SavedModel file-like entry."""
        detected_types = self._detect_suspicious_asset_content(
            file_path,
            result,
            model_root=model_root,
            check_name="SavedModel Supplemental File Security Check",
            file_label="supplemental file",
        )
        if not detected_types:
            return

        file_size = self.get_file_size(str(file_path))
        redacted_file_name = _redact_savedmodel_detail_string(file_path.name)
        result.add_check(
            name="SavedModel Supplemental File Security Check",
            passed=False,
            message=(
                f"Suspicious executable-like content detected in SavedModel supplemental file: {redacted_file_name}"
            ),
            severity=IssueSeverity.WARNING,
            location=_redact_savedmodel_file_location(file_path, model_root),
            details={
                "file_name": redacted_file_name,
                "detected_content_type": ", ".join(detected_types),
                "size": file_size,
            },
            rule_code="S902",
        )

    def _detect_suspicious_asset_content(
        self,
        file_path: Path,
        result: ScanResult,
        *,
        model_root: Path,
        check_name: str = "SavedModel Assets Security Check",
        file_label: str = "asset file",
    ) -> list[str]:
        """Return suspicious content types found in a SavedModel asset file."""
        redacted_file_name = _redact_savedmodel_detail_string(file_path.name)
        redacted_location = _redact_savedmodel_file_location(file_path, model_root)
        try:
            file_stat = file_path.lstat()
        except OSError as exc:
            redacted_error = redact_untrusted_error_message(exc)
            result.add_check(
                name=check_name,
                passed=False,
                message=f"Cannot inspect {file_label} for security analysis: {redacted_file_name}: {redacted_error}",
                severity=IssueSeverity.WARNING,
                location=redacted_location,
                details={
                    "file_name": redacted_file_name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "stat_error",
                    "exception": redacted_error,
                    "exception_type": type(exc).__name__,
                },
                rule_code="S902",
            )
            return []
        if stat.S_ISLNK(file_stat.st_mode):
            result.add_check(
                name=check_name,
                passed=False,
                message=f"Symlink {file_label} is not followed during security analysis: {redacted_file_name}",
                severity=IssueSeverity.WARNING,
                location=redacted_location,
                details={
                    "file_name": redacted_file_name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "symlink",
                    "size": file_stat.st_size,
                },
                rule_code="S902",
            )
            return []
        if not stat.S_ISREG(file_stat.st_mode):
            result.add_check(
                name=check_name,
                passed=False,
                message=f"Non-regular {file_label} is not scanned during security analysis: {redacted_file_name}",
                severity=IssueSeverity.WARNING,
                location=redacted_location,
                details={
                    "file_name": redacted_file_name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "non_regular",
                    "size": file_stat.st_size,
                },
                rule_code="S902",
            )
            return []

        source_changed = False
        try:
            with file_path.open("rb") as file_obj:
                opened_stat = os.fstat(file_obj.fileno())
                content_sample = file_obj.read(_ASSET_PROBE_BYTES + 1)
                content_head = content_sample[:_ASSET_PROBE_BYTES]
                if (
                    opened_stat.st_size > len(content_head)
                    and opened_stat.st_size <= _ASSET_TRIVIAL_PADDING_COMPLETE_BYTES
                    and _is_trivial_proto0_padding_prefix(content_head)
                ):
                    # Resolve the narrow boundary case where a harmless opcode
                    # prefix crosses the normal probe limit. This read remains
                    # bounded and also exposes a payload immediately after the
                    # otherwise-trivial padding.
                    file_obj.seek(0)
                    content_sample = file_obj.read(_ASSET_TRIVIAL_PADDING_COMPLETE_BYTES + 1)
                    content_head = content_sample[:_ASSET_TRIVIAL_PADDING_COMPLETE_BYTES]
                final_stat = os.fstat(file_obj.fileno())
                final_file_size = final_stat.st_size
                initial_identity = (
                    file_stat.st_dev,
                    file_stat.st_ino,
                    file_stat.st_size,
                    file_stat.st_mtime_ns,
                    file_stat.st_ctime_ns,
                )
                opened_identity = (
                    opened_stat.st_dev,
                    opened_stat.st_ino,
                    opened_stat.st_size,
                    opened_stat.st_mtime_ns,
                    opened_stat.st_ctime_ns,
                )
                final_identity = (
                    final_stat.st_dev,
                    final_stat.st_ino,
                    final_stat.st_size,
                    final_stat.st_mtime_ns,
                    final_stat.st_ctime_ns,
                )
                source_changed = initial_identity != opened_identity or opened_identity != final_identity
        except OSError as exc:
            redacted_error = redact_untrusted_error_message(exc)
            result.add_check(
                name=check_name,
                passed=False,
                message=f"Cannot read {file_label} for security analysis: {redacted_file_name}: {redacted_error}",
                severity=IssueSeverity.WARNING,
                location=redacted_location,
                details={
                    "file_name": redacted_file_name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "unreadable",
                    "size": file_stat.st_size,
                    "exception": redacted_error,
                    "exception_type": type(exc).__name__,
                },
                rule_code="S902",
            )
            return []
        if source_changed:
            mark_inconclusive_scan_result(result, "savedmodel_asset_source_changed")
            mark_operational_scan_error(result, "savedmodel_asset_source_changed")
            result.add_check(
                name="SavedModel Asset Source Stability",
                passed=False,
                message=f"Asset changed during bounded security analysis: {redacted_file_name}",
                severity=IssueSeverity.INFO,
                location=redacted_location,
                details={
                    "file_name": redacted_file_name,
                    "initial_size": file_stat.st_size,
                    "final_size": final_file_size,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "savedmodel_asset_source_changed",
                },
            )
            return []
        content_head_is_prefix = len(content_sample) > len(content_head) or final_file_size > len(content_head)

        detected_types: list[str] = []

        def _record_detected_type(content_type: str) -> None:
            if content_type not in detected_types:
                detected_types.append(content_type)

        if content_head.startswith(_ASSET_SCRIPT_SHEBANG):
            _record_detected_type("script_shebang")
        if content_head.startswith(_ASSET_ELF_HEADER):
            _record_detected_type("elf_binary")
        if _looks_like_pe_executable(content_head):
            _record_detected_type("pe_executable")
        if any(content_head.startswith(header) for header in _ASSET_MACHO_HEADERS):
            _record_detected_type("macho_binary")
        if any(content_head.startswith(prefix) for prefix in _ASSET_PICKLE_PREFIXES):
            _record_detected_type("pickle_payload")
        proto0_probe = _strip_leading_comment_lines(content_head)
        if _looks_like_proto0_or_1_pickle(
            content_head,
            sample_is_prefix=content_head_is_prefix,
        ) or (
            proto0_probe
            and _looks_like_proto0_or_1_pickle(
                proto0_probe,
                sample_is_prefix=content_head_is_prefix,
            )
        ):
            _record_detected_type("pickle_payload")

        decoded_head = content_head.decode("utf-8", errors="ignore")
        if decoded_head and _ASSET_PYTHON_PATTERN.search(decoded_head):
            _record_detected_type("python_source_pattern")

        if content_head_is_prefix and not detected_types:
            mark_inconclusive_scan_result(result, "savedmodel_asset_probe_incomplete")
            result.add_check(
                name="SavedModel Asset Probe Limit",
                passed=False,
                message=f"Asset exceeds bounded security probe window: {redacted_file_name}",
                severity=IssueSeverity.INFO,
                location=redacted_location,
                details={
                    "file_name": redacted_file_name,
                    "asset_size": final_file_size,
                    "probe_bytes": len(content_head),
                    "analysis_incomplete": True,
                },
            )

        return detected_types

    def _get_meta_graph_tag(self, meta_graph: Any) -> str:
        """Return a stable label for a MetaGraphDef."""
        return meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"

    def _iter_meta_graph_node_contexts(self, meta_graph: Any) -> Iterator[SavedModelNodeContext]:
        """Yield node contexts for top-level graph nodes and nested functions."""
        graph_def = meta_graph.graph_def
        meta_graph_tag = self._get_meta_graph_tag(meta_graph)

        for node in graph_def.node:
            yield SavedModelNodeContext(
                node=node,
                meta_graph_tag=meta_graph_tag,
                node_scope="graph_def",
            )

        function_library = getattr(graph_def, "library", None)
        if function_library is None:
            return

        for function_def in getattr(function_library, "function", []):
            function_name = function_def.signature.name or "unknown"
            for node in function_def.node_def:
                yield SavedModelNodeContext(
                    node=node,
                    meta_graph_tag=meta_graph_tag,
                    node_scope="function_def",
                    function_name=function_name,
                )

    def _iter_saved_model_node_contexts(self, saved_model: Any) -> Iterator[SavedModelNodeContext]:
        """Yield node contexts across every MetaGraphDef in the SavedModel."""
        for meta_graph in saved_model.meta_graphs:
            yield from self._iter_meta_graph_node_contexts(meta_graph)

    def _scan_collection_defs(self, saved_model: Any, result: ScanResult) -> None:
        """Scan MetaGraph collection payloads embedded in SavedModel files."""
        for meta_graph in saved_model.meta_graphs:
            meta_graph_tag = self._get_meta_graph_tag(meta_graph)
            redacted_meta_graph_tag = _redact_savedmodel_detail_string(meta_graph_tag)
            for key, collection in meta_graph.collection_def.items():
                key_lower = key.lower()
                redacted_key = _redact_savedmodel_detail_string(key)
                if not hasattr(collection, "bytes_list"):
                    continue

                for index, value in enumerate(collection.bytes_list.value):
                    if len(value) > _MAX_COLLECTION_VALUE_BYTES:
                        result.add_check(
                            name="SavedModel Collection Size Anomaly",
                            passed=False,
                            message="Large collection bytes entry detected (possible payload stuffing)",
                            severity=IssueSeverity.WARNING,
                            location=self.current_file_path,
                            details={
                                "collection_key": redacted_key,
                                "index": index,
                                "entry_size": len(value),
                                "max_expected": _MAX_COLLECTION_VALUE_BYTES,
                                "meta_graph": redacted_meta_graph_tag,
                            },
                        )

                    if not any(hint in key_lower for hint in _COLLECTION_EXEC_HINTS):
                        continue

                    decoded = value[:_MAX_COLLECTION_VALUE_BYTES].decode("utf-8", errors="ignore")
                    if _COLLECTION_COMMAND_RE.search(decoded) and _COLLECTION_NETWORK_RE.search(decoded):
                        result.add_check(
                            name="SavedModel Collection Executable Pattern",
                            passed=False,
                            message="Collection metadata contains command+network pattern in executable key context",
                            severity=IssueSeverity.WARNING,
                            location=self.current_file_path,
                            details={
                                "collection_key": redacted_key,
                                "index": index,
                                "value_preview": _safe_decoded_preview(decoded, 200),
                                "meta_graph": redacted_meta_graph_tag,
                            },
                        )

    def _build_node_location(
        self,
        node_context: SavedModelNodeContext,
        *,
        attr_name: str | None = None,
    ) -> str:
        """Format a finding location for a graph node."""
        location_parts = []
        if node_context.function_name:
            location_parts.append(f"function: {_redact_savedmodel_detail_string(node_context.function_name)}")
        location_parts.append(f"node: {_redact_savedmodel_detail_string(node_context.node.name)}")
        if attr_name:
            location_parts.append(f"attr: {_redact_savedmodel_detail_string(attr_name)}")
        return f"{self.current_file_path} ({', '.join(location_parts)})"

    def _build_node_details(
        self,
        node_context: SavedModelNodeContext,
        extra_details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build consistent finding details for a graph node."""
        details: dict[str, Any] = {
            "node_name": _redact_savedmodel_detail_string(node_context.node.name),
            "meta_graph": _redact_savedmodel_detail_string(node_context.meta_graph_tag),
            "node_scope": node_context.node_scope,
        }
        if node_context.function_name:
            details["function_name"] = _redact_savedmodel_detail_string(node_context.function_name)
        if extra_details:
            redacted_extra_details = _redact_savedmodel_detail_value(extra_details)
            if isinstance(redacted_extra_details, dict):
                details.update(redacted_extra_details)
        return details

    def _scan_tf_operations(self, saved_model: Any) -> list[dict[str, Any]]:
        """Scan TensorFlow graph for dangerous operations (generic pass)"""
        dangerous_ops: list[dict[str, Any]] = []
        try:
            for node_context in self._iter_saved_model_node_contexts(saved_model):
                node = node_context.node
                # Skip Python ops here; they are handled by _check_python_op
                if node.op in PYTHON_OPS:
                    continue
                if node.op in DANGEROUS_TF_OPERATIONS:
                    dangerous_ops.append(
                        {
                            "operation": node.op,
                            "severity": DANGEROUS_TF_OPERATIONS[node.op],
                            "location": self._build_node_location(node_context),
                            "details": self._build_node_details(
                                node_context,
                                {"op_type": node.op},
                            ),
                        }
                    )
        except Exception as e:  # pragma: no cover
            logger.warning("Failed to iterate TensorFlow graph: %s", redact_untrusted_error_message(e))
        return dangerous_ops

    def _analyze_saved_model(self, saved_model: Any, result: ScanResult) -> None:
        """Analyze the saved model for suspicious operations"""
        suspicious_op_found = False
        op_counts: dict[str, int] = {}
        op_count_display_keys: dict[str, str] = {}
        op_count_next_occurrences: dict[str, int] = {}

        # Regex to detect Lambda-layer node names in the graph.
        # Matches node names that start with "lambda" (case-insensitive)
        # followed by "/" or "_<digit>" which is the standard Keras naming
        # convention for Lambda layers (e.g. "lambda/StatefulPartitionedCall",
        # "lambda_1/PartitionedCall").  This is intentionally stricter than
        # the plain substring check that was previously used in
        # suspicious_func_patterns, which caused false positives on standard
        # Keras preprocessing layers whose *function* names also contain
        # "lambda" (e.g. "__inference_lambda_layer_call_fn_123").
        _lambda_node_re = re.compile(r"^(?:lambda(?:_\d+)?)(?:/|$)", re.IGNORECASE)
        _reported_lambda_layers: set[str] = set()

        for node_context in self._iter_saved_model_node_contexts(saved_model):
            node = node_context.node

            # Count all operation types
            redacted_op = op_count_display_keys.get(node.op)
            if redacted_op is None:
                redacted_op = redact_evidence_mapping_key(
                    node.op,
                    op_counts,
                    next_occurrences=op_count_next_occurrences,
                )
                op_count_display_keys[node.op] = redacted_op
            op_counts[redacted_op] = op_counts.get(redacted_op, 0) + 1

            if node.op in self.suspicious_ops:
                suspicious_op_found = True

                # Special handling for PyFunc/PyCall - try to extract and validate Python code
                if node.op in PYTHON_OPS:
                    self._check_python_op(node_context, result)
                elif node.op not in DANGEROUS_TF_OPERATIONS:
                    result.add_check(
                        name="TensorFlow Operation Security Check",
                        passed=False,
                        message=f"Suspicious TensorFlow operation: {redacted_op}",
                        severity=IssueSeverity.CRITICAL,
                        location=self._build_node_location(node_context),
                        rule_code="S703",
                        details=self._build_node_details(
                            node_context,
                            {"op_type": node.op},
                        ),
                        why=get_tf_op_explanation(node.op),
                    )
                # else: already reported by generic dangerous-op pass

            # Check for StatefulPartitionedCall which can contain custom functions
            if node.op == "StatefulPartitionedCall" and hasattr(node, "attr") and "f" in node.attr:
                # These operations can contain arbitrary functions
                # Check the function name for suspicious patterns
                func_attr = node.attr["f"]
                if hasattr(func_attr, "func") and hasattr(func_attr.func, "name"):
                    func_name = func_attr.func.name

                    # Check for suspicious function names.
                    # NOTE: "lambda" is intentionally excluded because
                    # standard Keras preprocessing layers generate
                    # StatefulPartitionedCall nodes whose function names
                    # contain "lambda" as part of normal TF internal
                    # naming (e.g. "__inference_lambda_layer_call_fn_123").
                    # Lambda layers are already detected separately via
                    # _scan_keras_metadata.
                    matched_pattern = self._match_suspicious_function_name(func_name)
                    if matched_pattern is not None:
                        redacted_func_name = _redact_savedmodel_detail_string(func_name)
                        result.add_check(
                            name="StatefulPartitionedCall Security Check",
                            passed=False,
                            message=f"StatefulPartitionedCall with suspicious function: {redacted_func_name}",
                            severity=IssueSeverity.WARNING,
                            location=self._build_node_location(node_context),
                            details=self._build_node_details(
                                node_context,
                                {
                                    "op_type": node.op,
                                    "stateful_call_target": func_name,
                                    "suspicious_pattern": matched_pattern,
                                },
                            ),
                            why=(
                                "StatefulPartitionedCall can execute custom functions that may contain arbitrary code."
                            ),
                        )

            # Detect Lambda layers by node name at the top-level graph only.
            # FunctionDef node names are internal graph implementation details
            # and can legitimately reuse "lambda/<op>"-like prefixes without
            # representing a user-authored Keras Lambda layer.
            if node_context.node_scope == "graph_def":
                m = _lambda_node_re.match(node.name)
                if m:
                    layer_prefix = m.group(0).rstrip("/")
                    if layer_prefix not in _reported_lambda_layers:
                        _reported_lambda_layers.add(layer_prefix)
                        result.add_check(
                            name="Lambda Layer Detection",
                            passed=False,
                            message="Lambda layer detected in graph",
                            severity=IssueSeverity.WARNING,
                            location=self._build_node_location(node_context),
                            details=self._build_node_details(
                                node_context,
                                {
                                    "op_type": node.op,
                                    "layer_prefix": layer_prefix,
                                },
                            ),
                            why=(
                                "Lambda layers can execute arbitrary Python code during "
                                "model inference, which poses a security risk."
                            ),
                        )

        self._scan_collection_defs(saved_model, result)

        # Add operation counts to metadata
        result.metadata["op_counts"] = op_counts
        result.metadata["suspicious_op_found"] = suspicious_op_found

        # Enhanced protobuf vulnerability scanning
        self._scan_protobuf_vulnerabilities(saved_model, result)

    @staticmethod
    def _match_suspicious_function_name(func_name: str) -> str | None:
        """Return the suspicious token matched in a function name, if any."""
        lowered_func_name = func_name.lower()
        for pattern_name, pattern in _SUSPICIOUS_FUNCTION_NAME_PATTERNS:
            if pattern.search(lowered_func_name):
                return pattern_name
        return None

    @classmethod
    def _match_pyfunc_reference_token(cls, func_name: str) -> str | None:
        """Return the suspicious module/function token in a PyFunc reference, if any."""
        matched_pattern = cls._match_suspicious_function_name(func_name)
        if matched_pattern is not None:
            return matched_pattern

        tokens = [token for token in re.split(r"[^0-9A-Za-z_]+", func_name.lower()) if token]
        if not tokens:
            return None

        for token in (tokens[0], tokens[-1]):
            if token in _PYFUNC_DANGEROUS_REFERENCE_TOKENS:
                return token
        return None

    def _check_python_op(self, node_context: SavedModelNodeContext, result: ScanResult) -> None:
        """Check PyFunc/PyCall operations for embedded Python code"""
        node = node_context.node
        # PyFunc and PyCall can embed Python code in various ways:
        # 1. As a string attribute containing Python code
        # 2. As a reference to a Python function
        # 3. As serialized bytecode

        code_found = False
        python_code = None

        # Try to extract Python code from node attributes
        if hasattr(node, "attr"):
            # Check for 'func' attribute which might contain Python code
            if "func" in node.attr:
                func_attr = node.attr["func"]
                # The function might be stored as a string
                if hasattr(func_attr, "s") and func_attr.s:
                    python_code = func_attr.s.decode("utf-8", errors="ignore")
                    code_found = True

            # Check for 'body' attribute (some ops store code here)
            if not code_found and "body" in node.attr:
                body_attr = node.attr["body"]
                if hasattr(body_attr, "s") and body_attr.s:
                    python_code = body_attr.s.decode("utf-8", errors="ignore")
                    code_found = True

            # Check for function name references
            if not code_found:
                for attr_name in ["function_name", "f", "fn"]:
                    if attr_name in node.attr:
                        attr = node.attr[attr_name]
                        if hasattr(attr, "s") and attr.s:
                            func_name = attr.s.decode("utf-8", errors="ignore")
                            matched_reference = self._match_pyfunc_reference_token(func_name)
                            if matched_reference is not None:
                                redacted_func_name = _redact_savedmodel_detail_string(func_name)
                                result.add_check(
                                    name="PyFunc Function Reference Check",
                                    passed=False,
                                    message=f"{node.op} operation references dangerous function: {redacted_func_name}",
                                    severity=IssueSeverity.CRITICAL,
                                    location=self._build_node_location(node_context),
                                    rule_code="S902",
                                    details=self._build_node_details(
                                        node_context,
                                        {
                                            "op_type": node.op,
                                            "function_reference": func_name,
                                            "suspicious_pattern": matched_reference,
                                        },
                                    ),
                                    why=get_tf_op_explanation(node.op),
                                )
                                return

        if code_found and python_code:
            # Validate the Python code
            is_valid, error = validate_python_syntax(python_code)

            if is_valid:
                # Check if the code is dangerous
                is_dangerous, risk_desc = is_code_potentially_dangerous(python_code, "low")

                severity = IssueSeverity.CRITICAL
                issue_msg = f"{node.op} operation contains {'dangerous' if is_dangerous else 'executable'} Python code"

                result.add_check(
                    name="PyFunc Python Code Analysis",
                    passed=False,
                    message=issue_msg,
                    severity=severity,
                    location=self._build_node_location(node_context),
                    rule_code="S902",
                    details=self._build_node_details(
                        node_context,
                        {
                            "op_type": node.op,
                            "code_analysis": risk_desc if is_dangerous else "Contains executable code",
                            "code_preview": _safe_decoded_preview(python_code, 200),
                            "validation_status": "valid_python",
                        },
                    ),
                    why=get_tf_op_explanation(node.op),
                )
            else:
                # Code found but not valid Python
                result.add_check(
                    name="PyFunc Code Validation",
                    passed=False,
                    message=f"{node.op} operation contains suspicious data (possibly obfuscated code)",
                    rule_code="S902",
                    severity=IssueSeverity.CRITICAL,
                    location=self._build_node_location(node_context),
                    details=self._build_node_details(
                        node_context,
                        {
                            "op_type": node.op,
                            "validation_error": error,
                            "data_preview": _safe_decoded_preview(python_code, 100),
                        },
                    ),
                    why=get_tf_op_explanation(node.op),
                )
        else:
            # PyFunc/PyCall without analyzable code - still dangerous
            result.add_check(
                name="PyFunc Code Extraction Check",
                passed=False,
                message=f"{node.op} operation detected (unable to extract Python code)",
                rule_code="S902",
                severity=IssueSeverity.CRITICAL,
                location=self._build_node_location(node_context),
                details=self._build_node_details(
                    node_context,
                    {"op_type": node.op},
                ),
                why=get_tf_op_explanation(node.op),
            )

    def _scan_keras_metadata(self, path: str, result: ScanResult, *, add_integrity_check: bool = False) -> None:
        """Scan keras_metadata.pb for Lambda layers and unsafe patterns"""
        try:
            with open(path, "rb") as f:
                content = f.read(_MAX_KERAS_METADATA_PARSE_BYTES + 1)
                result.bytes_scanned += min(len(content), _MAX_KERAS_METADATA_PARSE_BYTES)
                if len(content) > _MAX_KERAS_METADATA_PARSE_BYTES:
                    self._mark_keras_metadata_parse_budget_exceeded(result, path)
                    return
                if add_integrity_check:
                    self._add_bounded_file_integrity_check(path, result, content)
                try:
                    _KERAS_SAVED_METADATA_MESSAGE_TYPE().ParseFromString(content)
                except DecodeError as e:
                    self._mark_keras_metadata_scan_failure(result, path, e)

                # Convert to string for pattern matching
                content_str = content.decode("utf-8", errors="ignore")

                # Look for Lambda layers in the metadata
                lambda_pattern = re.compile(r'"class_name":\s*"Lambda"', re.IGNORECASE)
                lambda_matches = lambda_pattern.findall(content_str)

                if lambda_matches:
                    # Found Lambda layers, now look for the function definition
                    # Lambda functions are often base64 encoded in the metadata

                    # Pattern to find base64 encoded functions in Lambda configs
                    # Look for the function field with base64 data
                    # The pattern needs to handle newlines in the base64 string
                    func_pattern = re.compile(
                        r'"function":\s*\{[^}]*"items":\s*\[\s*"([A-Za-z0-9+/=\s\\n]+)"', re.DOTALL
                    )

                    for match in func_pattern.finditer(content_str):
                        base64_code = match.group(1)

                        try:
                            # Clean the base64 string (remove newlines and spaces)
                            base64_code = base64_code.replace("\\n", "").replace(" ", "").strip()

                            # Try to decode the base64
                            decoded = base64.b64decode(base64_code)
                            decoded_str = decoded.decode("utf-8", errors="ignore")

                            # Check for dangerous patterns in the decoded content
                            dangerous_patterns = [
                                "exec",
                                "eval",
                                "__import__",
                                "compile",
                                "open",
                                "subprocess",
                                "os.system",
                                "os.popen",
                                "pickle",
                                "marshal",
                                "importlib",
                                "runpy",
                                "webbrowser",
                            ]

                            found_patterns = find_lambda_dangerous_patterns(decoded_str, dangerous_patterns)

                            if found_patterns:
                                result.add_check(
                                    name="Lambda Layer Security Check",
                                    passed=False,
                                    message=f"Lambda layer contains dangerous code: {', '.join(found_patterns)}",
                                    severity=IssueSeverity.CRITICAL,
                                    location=path,
                                    details={
                                        "layer_type": "Lambda",
                                        "dangerous_patterns": found_patterns,
                                        "code_preview": _safe_decoded_preview(decoded_str, 200),
                                        "encoding": "base64",
                                    },
                                    why=(
                                        "Lambda layers can execute arbitrary Python code during model inference, "
                                        "which poses a severe security risk."
                                    ),
                                )
                            else:
                                # Lambda layer found but no obvious dangerous patterns
                                result.add_check(
                                    name="Lambda Layer Detection",
                                    passed=False,
                                    message="Lambda layer detected with custom code",
                                    severity=IssueSeverity.WARNING,
                                    location=path,
                                    details={
                                        "layer_type": "Lambda",
                                        "code_preview": _safe_decoded_preview(decoded_str, 100),
                                    },
                                    why=(
                                        "Lambda layers can execute arbitrary Python code. "
                                        "Review the code to ensure it's safe."
                                    ),
                                )

                        except Exception as decode_error:
                            # Couldn't decode the function, but Lambda layer is still present
                            result.add_check(
                                name="Lambda Layer Detection",
                                passed=False,
                                message="Lambda layer detected (unable to decode function)",
                                severity=IssueSeverity.WARNING,
                                location=path,
                                details={
                                    "layer_type": "Lambda",
                                    "decode_error": redact_untrusted_error_message(decode_error),
                                },
                                why=(
                                    "Lambda layers can execute arbitrary code. "
                                    "Unable to inspect the code for security analysis."
                                ),
                            )

                    # If we found Lambda layers but no function definitions
                    if not func_pattern.search(content_str):
                        result.add_check(
                            name="Lambda Layer Detection",
                            passed=False,
                            message=f"Found {len(lambda_matches)} Lambda layer(s) in model",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={
                                "layer_count": len(lambda_matches),
                            },
                            why="Lambda layers can execute arbitrary Python code during model inference.",
                        )

                # Also check for other suspicious patterns directly in the metadata
                suspicious_patterns = {
                    "eval": "Code evaluation",
                    "exec": "Code execution",
                    "__import__": "Dynamic imports",
                    "os.system": "System command execution",
                    "subprocess": "Process spawning",
                    "pickle": "Unsafe deserialization",
                    "marshal": "Unsafe deserialization",
                }

                present_patterns = set(find_case_insensitive_substrings(content_str, suspicious_patterns))
                for pattern, description in suspicious_patterns.items():
                    if pattern in present_patterns:
                        result.add_check(
                            name="Keras Metadata Pattern Check",
                            passed=False,
                            message=f"Suspicious pattern '{pattern}' found in keras metadata",
                            severity=IssueSeverity.WARNING,
                            location=path,
                            details={
                                "pattern": pattern,
                                "description": description,
                            },
                            why=f"The pattern '{pattern}' suggests {description} capability in the model.",
                        )

        except OSError:
            raise
        except Exception as e:
            self._mark_keras_metadata_scan_failure(result, path, e)

    def _scan_protobuf_vulnerabilities(self, saved_model: Any, result: ScanResult) -> None:
        """Enhanced protobuf vulnerability scanning for TensorFlow SavedModels"""

        # Check for malicious string data in protobuf fields
        self._check_protobuf_string_injection(saved_model, result)
        # NOTE: _check_protobuf_buffer_overflow() and
        # _check_protobuf_field_bomb() are intentionally not enabled yet.
        # Their thresholds are heuristic and currently lack regression
        # coverage, so wiring them in would expand SavedModel findings beyond
        # the narrowly-scoped function-definition fix until they are validated.

    @staticmethod
    def _protobuf_string_scan_windows(string_val: str) -> tuple[list[tuple[int, int, str]], bool]:
        """Return bounded merged scan regions and whether they cover the whole string."""
        string_length = len(string_val)
        if string_length <= _MAX_PROTOBUF_STRING_FULL_SCAN_CHARS:
            return [(0, string_length, string_val)], True

        window_size = min(_PROTOBUF_STRING_SCAN_WINDOW_CHARS, string_length)
        starts = [
            0,
            max(0, _PROTOBUF_STRING_LENGTH_CHECK_THRESHOLD - window_size // 4),
            min(_PROTOBUF_STRING_LENGTH_CHECK_THRESHOLD, max(0, string_length - window_size)),
            max(0, string_length // 2 - window_size // 2),
            max(0, string_length - window_size),
        ]
        seen: set[tuple[int, int]] = set()
        for start in starts:
            end = min(string_length, start + window_size)
            seen.add((start, end))

        merged_intervals: list[tuple[int, int]] = []
        for start, end in sorted(seen):
            if not merged_intervals or start > merged_intervals[-1][1]:
                merged_intervals.append((start, end))
                continue

            previous_start, previous_end = merged_intervals[-1]
            merged_intervals[-1] = (previous_start, max(previous_end, end))

        windows = [(start, end, string_val[start:end]) for start, end in merged_intervals]
        scanned_entire_string = len(windows) == 1 and windows[0][0] == 0 and windows[0][1] >= string_length
        return windows, scanned_entire_string

    def _check_protobuf_string_injection(self, saved_model: Any, result: ScanResult) -> None:
        """Check for string injection attacks in protobuf fields"""

        # Patterns that indicate potential injection attacks
        injection_patterns = [
            # Code injection patterns
            (r"eval\s*\(", "code_injection", "eval function call"),
            (r"exec\s*\(", "code_injection", "exec function call"),
            (r"__import__\s*\(", "code_injection", "import function call"),
            (r"compile\s*\(", "code_injection", "compile function call"),
            (r"os\.system\s*\(", "system_command", "OS system call"),
            (r"subprocess\.[a-zA-Z_]+\s*\(", "system_command", "subprocess call"),
            # Path traversal patterns
            (r"\.\./+", "path_traversal", "directory traversal"),
            (r"\.\.\\+", "path_traversal", "Windows directory traversal"),
            (r"/etc/passwd", "path_traversal", "system file access"),
            (r"/proc/", "path_traversal", "proc filesystem access"),
            # Encoding bypass attempts
            (r"\\x[0-9a-fA-F]{2}", "encoding_bypass", "hex encoding"),
            (r"\\u[0-9a-fA-F]{4}", "encoding_bypass", "unicode escape"),
            (r"%[0-9a-fA-F]{2}", "encoding_bypass", "URL encoding"),
            # Script injection
            (r"<script[^>]*>", "script_injection", "HTML script tag"),
            (r"javascript:", "script_injection", "JavaScript URI"),
            (r"vbscript:", "script_injection", "VBScript URI"),
            # Base64 encoded payloads — require at least one trailing '=' pad
            # character to avoid matching normal TF node names that use '/'
            # as a hierarchical separator (e.g. "bidirectional/forward_lstm",
            # "Adam/embedding/embeddings"). Boundaries also prevent quadratic
            # backtracking on long unpadded alphanumeric runs.
            (
                r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={1,2}(?![A-Za-z0-9+/=])",
                "encoded_payload",
                "potential base64 payload",
            ),
        ]

        for node_context in self._iter_saved_model_node_contexts(saved_model):
            node = node_context.node

            # Check string values in node attributes
            if hasattr(node, "attr"):
                for attr_name, attr_value in node.attr.items():
                    string_vals_to_check: list[str] = []

                    value_kind = attr_value.WhichOneof("value")
                    if value_kind == "s":
                        encoded_values = (attr_value.s,)
                    elif value_kind == "list":
                        encoded_values = attr_value.list.s
                    else:
                        continue

                    for encoded_value in encoded_values:
                        try:
                            string_vals_to_check.append(encoded_value.decode("utf-8", errors="ignore"))
                        except (UnicodeDecodeError, AttributeError):
                            continue

                    # Check each string value against injection patterns
                    for string_val in string_vals_to_check:
                        scan_windows, scanned_entire_string = self._protobuf_string_scan_windows(string_val)
                        matched_injection: tuple[str, str, str, list[Any], int, int] | None = None
                        for pattern, attack_type, description in injection_patterns:
                            for window_start, window_end, scan_text in scan_windows:
                                matches = re.findall(pattern, scan_text, re.IGNORECASE)
                                if matches:
                                    matched_injection = (
                                        pattern,
                                        attack_type,
                                        description,
                                        matches,
                                        window_start,
                                        window_end,
                                    )
                                    break
                            if matched_injection is not None:
                                break

                        if len(string_val) > _PROTOBUF_STRING_LENGTH_CHECK_THRESHOLD:
                            string_details = self._build_node_details(
                                node_context,
                                {
                                    "attribute_name": attr_name,
                                    "string_length": len(string_val),
                                    "attack_type": "protobuf_string_bomb",
                                    "string_scan_strategy": "full" if scanned_entire_string else "windowed",
                                    "string_scan_window_count": len(scan_windows),
                                    "max_full_scan_chars": _MAX_PROTOBUF_STRING_FULL_SCAN_CHARS,
                                },
                            )
                            if not scanned_entire_string:
                                mark_inconclusive_scan_result(result, _PROTOBUF_STRING_INCOMPLETE_REASON)
                                mark_operational_scan_error(result, _PROTOBUF_STRING_INCOMPLETE_REASON)
                                string_details.update(
                                    {
                                        "analysis_incomplete": True,
                                        "scan_outcome_reason": _PROTOBUF_STRING_INCOMPLETE_REASON,
                                        "window_size_chars": _PROTOBUF_STRING_SCAN_WINDOW_CHARS,
                                    }
                                )
                            result.add_check(
                                name="Protobuf String Length Check",
                                passed=False,
                                message=f"Abnormally long string in node attribute (length: {len(string_val)})",
                                severity=IssueSeverity.INFO,
                                location=self._build_node_location(node_context, attr_name=attr_name),
                                details=string_details,
                            )

                        if matched_injection is None:
                            continue

                        pattern, attack_type, description, matches, window_start, window_end = matched_injection
                        result.add_check(
                            name="Protobuf String Injection Check",
                            passed=False,
                            message=f"Potential {description} detected in protobuf string",
                            severity=IssueSeverity.CRITICAL
                            if attack_type in ["code_injection", "system_command"]
                            else IssueSeverity.WARNING,
                            location=self._build_node_location(node_context, attr_name=attr_name),
                            details=self._build_node_details(
                                node_context,
                                {
                                    "attribute_name": attr_name,
                                    "pattern_matched": pattern,
                                    "matches": matches[:5],  # Limit to first 5 matches
                                    "attack_type": attack_type,
                                    "description": description,
                                    "total_matches": len(matches),
                                    "string_length": len(string_val),
                                    "string_scan_strategy": "full" if scanned_entire_string else "windowed",
                                    "matched_window_start": window_start,
                                    "matched_window_end": window_end,
                                },
                            ),
                        )

    def _check_protobuf_buffer_overflow(self, saved_model: Any, result: ScanResult) -> None:
        """Check for potential buffer overflow patterns in protobuf data"""

        for node_context in self._iter_saved_model_node_contexts(saved_model):
            node = node_context.node
            if len(node.name) > 2048:  # 2KB threshold for node names
                result.add_check(
                    name="Protobuf Node Name Length Check",
                    passed=False,
                    message=(
                        f"Abnormally long node name (length: {len(node.name)}) may indicate buffer overflow attempt"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=self._build_node_location(node_context),
                    details=self._build_node_details(
                        node_context,
                        {
                            "node_name_length": len(node.name),
                            "name_threshold": 2048,
                            "attack_type": "protobuf_buffer_overflow",
                            "node_name_preview": _redact_savedmodel_detail_string(node.name[:200]),
                        },
                    ),
                )

            # Check input names for excessive length
            for input_name in node.input:
                if len(input_name) > 2048:
                    result.add_check(
                        name="Protobuf Input Name Length Check",
                        passed=False,
                        message=(
                            f"Abnormally long input name (length: {len(input_name)}) in node "
                            f"{_redact_savedmodel_detail_string(node.name)}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=self._build_node_location(node_context),
                        details=self._build_node_details(
                            node_context,
                            {
                                "input_name_length": len(input_name),
                                "name_threshold": 2048,
                                "attack_type": "protobuf_buffer_overflow",
                            },
                        ),
                    )

    def _check_protobuf_field_bomb(self, saved_model: Any, result: ScanResult) -> None:
        """Check for protobuf field bombs (DoS via excessive fields)"""

        total_nodes = 0
        total_attrs = 0

        for meta_graph in saved_model.meta_graphs:
            meta_graph_nodes = 0
            meta_graph_attrs = 0

            for node_context in self._iter_meta_graph_node_contexts(meta_graph):
                meta_graph_nodes += 1
                node = node_context.node
                meta_graph_attrs += len(node.attr) if hasattr(node, "attr") else 0

            total_nodes += meta_graph_nodes
            total_attrs += meta_graph_attrs

            # Check for excessive nodes in single meta graph
            if meta_graph_nodes > 50000:  # 50k nodes threshold
                result.add_check(
                    name="Protobuf Node Count Bomb Check",
                    passed=False,
                    message=f"Meta graph contains excessive nodes ({meta_graph_nodes:,}) - potential DoS attack",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "node_count": meta_graph_nodes,
                        "node_threshold": 50000,
                        "attack_type": "protobuf_node_bomb",
                    },
                )

        # Check total model complexity
        if total_nodes > 100000:  # 100k total nodes
            result.add_check(
                name="Protobuf Total Complexity Check",
                passed=False,
                message=f"Model has excessive total complexity ({total_nodes:,} nodes, {total_attrs:,} attributes)",
                severity=IssueSeverity.WARNING,
                location=self.current_file_path,
                details={
                    "total_nodes": total_nodes,
                    "total_attributes": total_attrs,
                    "node_threshold": 100000,
                    "attack_type": "protobuf_complexity_bomb",
                },
            )

    def extract_metadata(self, file_path: str) -> dict[str, Any]:
        """Extract TensorFlow SavedModel metadata."""
        metadata = super().extract_metadata(file_path)

        allow_deserialization = bool(self.config.get("allow_metadata_deserialization"))

        if not allow_deserialization:
            metadata["deserialization_skipped"] = True
            metadata["reason"] = "Deserialization disabled for metadata extraction"
            return metadata

        if not has_tensorflow_protobuf_stubs():
            metadata["extraction_error"] = "TensorFlow protobuf stubs unavailable for metadata extraction"
            return metadata

        try:
            import modelaudit.protos  # noqa: F401, I001
            from importlib.metadata import PackageNotFoundError, version

            from tensorflow.core.framework.types_pb2 import DataType
            from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

            def _tensor_info_to_dict(tensor_info: Any) -> dict[str, Any]:
                try:
                    dtype_name = DataType.Name(tensor_info.dtype)
                except ValueError:
                    dtype_name = str(tensor_info.dtype)
                return {
                    "tensor_name": tensor_info.name,
                    "dtype": dtype_name,
                    "shape": [int(dim.size) for dim in tensor_info.tensor_shape.dim],
                }

            path_obj = Path(file_path)
            export_dir = path_obj if path_obj.is_dir() else path_obj.parent

            saved_model_pb = export_dir / "saved_model.pb"
            if not saved_model_pb.exists():
                redacted_export_dir = _redact_savedmodel_detail_string(export_dir, max_chars=500)
                metadata["extraction_error"] = f"saved_model.pb not found in export directory: {redacted_export_dir}"
                return metadata

            with open(saved_model_pb, "rb") as f:
                content = f.read()

            saved_model = SavedModel()
            saved_model.ParseFromString(content)

            signature_details: dict[str, dict[str, Any]] = {}
            tag_sets: list[list[str]] = []
            trackable_objects = 0

            for meta_graph_index, meta_graph in enumerate(saved_model.meta_graphs):
                tags = list(meta_graph.meta_info_def.tags)
                if tags:
                    tag_sets.append(tags)
                trackable_objects += len(meta_graph.object_graph_def.nodes)

                for signature_name, signature_def in sorted(meta_graph.signature_def.items()):
                    detail_key = signature_name
                    if detail_key in signature_details:
                        suffix = ",".join(tags) if tags else str(meta_graph_index)
                        detail_key = f"{signature_name}@{suffix}"

                    input_items = sorted(signature_def.inputs.items())
                    output_items = sorted(signature_def.outputs.items())
                    signature_details[detail_key] = {
                        "inputs": [name for name, _ in input_items],
                        "outputs": [name for name, _ in output_items],
                        "method_name": signature_def.method_name,
                        "input_tensors": {name: _tensor_info_to_dict(tensor_info) for name, tensor_info in input_items},
                        "output_tensors": {
                            name: _tensor_info_to_dict(tensor_info) for name, tensor_info in output_items
                        },
                    }

            with contextlib.suppress(PackageNotFoundError, Exception):
                metadata["tensorflow_version"] = version("tensorflow")

            redacted_signature_details = _redact_savedmodel_detail_value(signature_details)
            metadata.update(
                {
                    "meta_graph_count": len(saved_model.meta_graphs),
                    "saved_model_pb_size": len(content),
                    "signatures": (
                        sorted(redacted_signature_details.keys())
                        if isinstance(redacted_signature_details, dict)
                        else []
                    ),
                    "signature_details": redacted_signature_details,
                    "trackable_objects": trackable_objects,
                }
            )
            if tag_sets:
                metadata["tag_sets"] = _redact_savedmodel_detail_value(tag_sets)

        except Exception as e:
            metadata["extraction_error"] = redact_untrusted_error_message(e)

        return metadata
