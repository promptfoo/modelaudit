"""Scanner for TensorFlow SavedModel directories and files."""

import contextlib
import logging
import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from modelaudit.config.explanations import get_tf_op_explanation
from modelaudit.detectors.suspicious_symbols import SUSPICIOUS_OPS, TENSORFLOW_DANGEROUS_OPS
from modelaudit.utils.file.detection import PROTO0_1_MAX_PROBE_BYTES, _looks_like_proto0_or_1_pickle
from modelaudit.utils.helpers.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)

from .base import BaseScanner, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)

# Derive from centralized list; keep severities unified here
# Exclude Python ops (handled elsewhere) and pure decode ops from the generic pass
_EXCLUDE_FROM_GENERIC = {"DecodeRaw", "DecodeJpeg", "DecodePng"}
DANGEROUS_TF_OPERATIONS = {
    op: IssueSeverity.CRITICAL for op in TENSORFLOW_DANGEROUS_OPS if op not in _EXCLUDE_FROM_GENERIC
}

# Python operations that require special handling
PYTHON_OPS = ("PyFunc", "PyCall", "PyFuncStateless", "EagerPyFunc")

# Defer protobuf availability check to avoid module-level imports
HAS_PROTOS: bool | None = None
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
_ASSET_PYTHON_PATTERN = re.compile(
    r"(?m)(^\s*(?:"
    r"from\s+[A-Za-z_][\w.]*\s+import\s+"
    r"|import\s+[A-Za-z_][\w.]*"
    r"|def\s+[A-Za-z_]\w*\s*\("
    r"|class\s+[A-Za-z_]\w*\s*[:(]"
    r"))"
)


def _looks_like_pe_executable(content_head: bytes) -> bool:
    """Return True for a minimally valid PE/COFF executable prefix."""
    if not content_head.startswith(_ASSET_PE_HEADER) or len(content_head) < 0x40:
        return False

    pe_offset = int.from_bytes(content_head[0x3C:0x40], "little", signed=False)
    if pe_offset < 0x40 or pe_offset + 4 > len(content_head):
        return False
    return content_head[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _check_protos() -> bool:
    """Check if TensorFlow protobuf stubs are available (vendored or from TensorFlow)."""
    global HAS_PROTOS
    if HAS_PROTOS is None:
        import modelaudit.protos

        HAS_PROTOS = modelaudit.protos._check_vendored_protos()
    return HAS_PROTOS


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


class TensorFlowSavedModelScanner(BaseScanner):
    """Scanner for TensorFlow SavedModel format"""

    name = "tf_savedmodel"
    description = "Scans TensorFlow SavedModel for suspicious operations"
    supported_extensions: ClassVar[list[str]] = [".pb", ""]  # Empty string for directories

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Additional scanner-specific configuration
        self.suspicious_ops = set(self.config.get("suspicious_ops", SUSPICIOUS_OPS))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not _check_protos():
            return False

        if os.path.isfile(path):
            # Handle any .pb file (protobuf format)
            ext = os.path.splitext(path)[1].lower()
            return ext == ".pb"
        if os.path.isdir(path):
            # For directory, check if saved_model.pb exists
            return os.path.exists(os.path.join(path, "saved_model.pb"))
        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a TensorFlow SavedModel file or directory"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        # Store the file path for use in issue locations
        self.current_file_path = path

        # Check if TensorFlow protos are available (vendored or from TensorFlow)
        if not _check_protos():
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

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)
        self.current_file_path = path

        # Check if this is a keras_metadata.pb file
        if path.endswith("keras_metadata.pb"):
            # Scan it for Lambda layers
            self._scan_keras_metadata(path, result)
            result.finish(success=True)
            return result

        try:
            # Import vendored protos module (sets up sys.path for tensorflow.* imports)
            # Order matters: modelaudit.protos must be imported first to set up sys.path
            import modelaudit.protos  # noqa: F401, I001

            from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

            with open(path, "rb") as f:
                content = f.read()
                result.bytes_scanned = len(content)

                saved_model = SavedModel()
                saved_model.ParseFromString(content)
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

        except Exception as e:
            result.add_check(
                name="SavedModel Parsing",
                passed=False,
                message=f"Error scanning TF SavedModel file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
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
            self._scan_keras_metadata(str(keras_metadata_path), result)

        self._scan_saved_model_assets(model_root, result)

        # Check for other suspicious files in the directory
        for root, _dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                if any(
                    file_path.is_relative_to(model_root / asset_dir_name)
                    for asset_dir_name in ("assets", "assets.extra")
                ) and file_path.is_symlink():
                    continue
                # Look for potentially suspicious Python files
                if file.endswith(".py"):
                    result.add_check(
                        name="Python File Detection",
                        passed=False,
                        message=f"Python file found in SavedModel: {file}",
                        severity=IssueSeverity.INFO,
                        location=str(file_path),
                        rule_code="S902",
                        details={"file": file, "directory": root},
                    )

                # Check for blacklist patterns in text files
                if hasattr(self, "config") and self.config and "blacklist_patterns" in self.config:
                    blacklist_patterns = self.config["blacklist_patterns"]
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
                                for pattern in blacklist_patterns:
                                    if pattern in content:
                                        result.add_check(
                                            name="Blacklist Pattern Check",
                                            passed=False,
                                            message=f"Blacklisted pattern '{pattern}' found in file {file}",
                                            severity=IssueSeverity.CRITICAL,
                                            location=str(file_path),
                                            rule_code="S902",
                                            details={"pattern": pattern, "file": file},
                                        )
                    except Exception as e:
                        result.add_check(
                            name="File Read Check",
                            passed=False,
                            message=f"Error reading file {file}: {e!s}",
                            severity=IssueSeverity.DEBUG,
                            location=str(file_path),
                            rule_code="S902",
                            details={
                                "file": file,
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                            },
                        )

        result.finish(success=True)
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
                result.add_check(
                    name="SavedModel Assets Security Check",
                    passed=False,
                    message=f"Cannot inspect asset directory for security analysis: {assets_dir_name}: {exc}",
                    severity=IssueSeverity.WARNING,
                    location=str(assets_dir),
                    details={
                        "file_name": assets_dir_name,
                        "detected_content_type": "unscannable_asset_dir",
                        "asset_kind": "stat_error",
                        "exception": str(exc),
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
                    try:
                        child_stat = child_dir.lstat()
                    except OSError as exc:
                        result.add_check(
                            name="SavedModel Assets Security Check",
                            passed=False,
                            message=(
                                "Cannot inspect nested asset directory for security analysis: "
                                f"{child_dir.relative_to(model_root)}: {exc}"
                            ),
                            severity=IssueSeverity.WARNING,
                            location=str(child_dir),
                            details={
                                "file_name": dir_name,
                                "detected_content_type": "unscannable_asset_dir",
                                "asset_kind": "stat_error",
                                "exception": str(exc),
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
                                f"{child_dir.relative_to(model_root)}"
                            ),
                            severity=IssueSeverity.WARNING,
                            location=str(child_dir),
                            details={
                                "file_name": dir_name,
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
                    detected_types = self._detect_suspicious_asset_content(file_path, result)
                    if not detected_types:
                        continue

                    file_size = self.get_file_size(str(file_path))
                    result.add_check(
                        name="SavedModel Assets Security Check",
                        passed=False,
                        message=(
                            "Suspicious executable-like content detected in SavedModel assets: "
                            f"{file_path.relative_to(model_root)}"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=str(file_path),
                        details={
                            "file_name": file_name,
                            "detected_content_type": ", ".join(detected_types),
                            "size": file_size,
                        },
                        rule_code="S902",
                    )

    def _detect_suspicious_asset_content(self, file_path: Path, result: ScanResult) -> list[str]:
        """Return suspicious content types found in a SavedModel asset file."""
        try:
            file_stat = file_path.lstat()
        except OSError as exc:
            result.add_check(
                name="SavedModel Assets Security Check",
                passed=False,
                message=f"Cannot inspect asset file for security analysis: {file_path.name}: {exc}",
                severity=IssueSeverity.WARNING,
                location=str(file_path),
                details={
                    "file_name": file_path.name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "stat_error",
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                },
                rule_code="S902",
            )
            return []
        if stat.S_ISLNK(file_stat.st_mode):
            result.add_check(
                name="SavedModel Assets Security Check",
                passed=False,
                message=f"Symlink asset is not followed during security analysis: {file_path.name}",
                severity=IssueSeverity.WARNING,
                location=str(file_path),
                details={
                    "file_name": file_path.name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "symlink",
                    "size": file_stat.st_size,
                },
                rule_code="S902",
            )
            return []
        if not stat.S_ISREG(file_stat.st_mode):
            result.add_check(
                name="SavedModel Assets Security Check",
                passed=False,
                message=f"Non-regular asset file is not scanned during security analysis: {file_path.name}",
                severity=IssueSeverity.WARNING,
                location=str(file_path),
                details={
                    "file_name": file_path.name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "non_regular",
                    "size": file_stat.st_size,
                },
                rule_code="S902",
            )
            return []

        try:
            with file_path.open("rb") as file_obj:
                content_head = file_obj.read(_ASSET_PROBE_BYTES)
        except OSError as exc:
            result.add_check(
                name="SavedModel Assets Security Check",
                passed=False,
                message=f"Cannot read asset file for security analysis: {file_path.name}: {exc}",
                severity=IssueSeverity.WARNING,
                location=str(file_path),
                details={
                    "file_name": file_path.name,
                    "detected_content_type": "unscannable_asset",
                    "asset_kind": "unreadable",
                    "size": file_stat.st_size,
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                },
                rule_code="S902",
            )
            return []

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
        if _looks_like_proto0_or_1_pickle(content_head) or (
            proto0_probe and _looks_like_proto0_or_1_pickle(proto0_probe)
        ):
            _record_detected_type("pickle_payload")

        decoded_head = content_head.decode("utf-8", errors="ignore")
        if decoded_head and _ASSET_PYTHON_PATTERN.search(decoded_head):
            _record_detected_type("python_source_pattern")

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

    def _build_node_location(
        self,
        node_context: SavedModelNodeContext,
        *,
        attr_name: str | None = None,
    ) -> str:
        """Format a finding location for a graph node."""
        location_parts = []
        if node_context.function_name:
            location_parts.append(f"function: {node_context.function_name}")
        location_parts.append(f"node: {node_context.node.name}")
        if attr_name:
            location_parts.append(f"attr: {attr_name}")
        return f"{self.current_file_path} ({', '.join(location_parts)})"

    def _build_node_details(
        self,
        node_context: SavedModelNodeContext,
        extra_details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build consistent finding details for a graph node."""
        details: dict[str, Any] = {
            "node_name": node_context.node.name,
            "meta_graph": node_context.meta_graph_tag,
            "node_scope": node_context.node_scope,
        }
        if node_context.function_name:
            details["function_name"] = node_context.function_name
        if extra_details:
            details.update(extra_details)
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
            logger.warning(f"Failed to iterate TensorFlow graph: {e}")
        return dangerous_ops

    def _analyze_saved_model(self, saved_model: Any, result: ScanResult) -> None:
        """Analyze the saved model for suspicious operations"""
        suspicious_op_found = False
        op_counts: dict[str, int] = {}

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
            op_counts[node.op] = op_counts.get(node.op, 0) + 1

            if node.op in self.suspicious_ops:
                suspicious_op_found = True

                # Special handling for PyFunc/PyCall - try to extract and validate Python code
                if node.op in PYTHON_OPS:
                    self._check_python_op(node_context, result)
                elif node.op not in DANGEROUS_TF_OPERATIONS:
                    result.add_check(
                        name="TensorFlow Operation Security Check",
                        passed=False,
                        message=f"Suspicious TensorFlow operation: {node.op}",
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
                        result.add_check(
                            name="StatefulPartitionedCall Security Check",
                            passed=False,
                            message=f"StatefulPartitionedCall with suspicious function: {func_name}",
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

        # Add operation counts to metadata
        result.metadata["op_counts"] = op_counts
        result.metadata["suspicious_op_found"] = suspicious_op_found

        # Enhanced protobuf vulnerability scanning
        self._scan_protobuf_vulnerabilities(saved_model, result)

    @staticmethod
    def _match_suspicious_function_name(func_name: str) -> str | None:
        """Return the suspicious token matched in a function name, if any."""
        suspicious_patterns = (
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

        lowered_func_name = func_name.lower()
        for pattern_name, pattern in suspicious_patterns:
            if pattern.search(lowered_func_name):
                return pattern_name
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
                            # Check if it references dangerous modules
                            dangerous_modules = ["os", "sys", "subprocess", "eval", "exec", "__builtins__"]
                            if any(dangerous in func_name for dangerous in dangerous_modules):
                                result.add_check(
                                    name="PyFunc Function Reference Check",
                                    passed=False,
                                    message=f"{node.op} operation references dangerous function: {func_name}",
                                    severity=IssueSeverity.CRITICAL,
                                    location=self._build_node_location(node_context),
                                    rule_code="S902",
                                    details=self._build_node_details(
                                        node_context,
                                        {
                                            "op_type": node.op,
                                            "function_reference": func_name,
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
                            "code_preview": python_code[:200] + "..." if len(python_code) > 200 else python_code,
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
                            "data_preview": python_code[:100] + "..." if len(python_code) > 100 else python_code,
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

    def _scan_keras_metadata(self, path: str, result: ScanResult) -> None:
        """Scan keras_metadata.pb for Lambda layers and unsafe patterns"""
        import base64
        import re

        try:
            with open(path, "rb") as f:
                content = f.read()
                result.bytes_scanned += len(content)

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

                            found_patterns = []
                            for pattern in dangerous_patterns:
                                if pattern in decoded_str.lower():
                                    found_patterns.append(pattern)

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
                                        "code_preview": decoded_str[:200] + "..."
                                        if len(decoded_str) > 200
                                        else decoded_str,
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
                                        "code_preview": decoded_str[:100] + "..."
                                        if len(decoded_str) > 100
                                        else decoded_str,
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
                                    "decode_error": str(decode_error),
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

                for pattern, description in suspicious_patterns.items():
                    if pattern in content_str.lower():
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

        except Exception as e:
            result.add_check(
                name="Keras Metadata Scan",
                passed=False,
                message=f"Error scanning keras_metadata.pb: {e!s}",
                severity=IssueSeverity.DEBUG,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

    def _scan_protobuf_vulnerabilities(self, saved_model: Any, result: ScanResult) -> None:
        """Enhanced protobuf vulnerability scanning for TensorFlow SavedModels"""

        # Check for malicious string data in protobuf fields
        self._check_protobuf_string_injection(saved_model, result)
        # NOTE: _check_protobuf_buffer_overflow() and
        # _check_protobuf_field_bomb() are intentionally not enabled yet.
        # Their thresholds are heuristic and currently lack regression
        # coverage, so wiring them in would expand SavedModel findings beyond
        # the narrowly-scoped function-definition fix until they are validated.

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
            # "Adam/embedding/embeddings").
            (r"[A-Za-z0-9+/]{20,}={1,2}", "encoded_payload", "potential base64 payload"),
        ]

        import re

        for node_context in self._iter_saved_model_node_contexts(saved_model):
            node = node_context.node

            # Check string values in node attributes
            if hasattr(node, "attr"):
                for attr_name, attr_value in node.attr.items():
                    string_vals_to_check = []

                    # Extract string values from different attribute types
                    if hasattr(attr_value, "s"):  # String attribute
                        try:
                            string_vals_to_check.append(attr_value.s.decode("utf-8", errors="ignore"))
                        except (UnicodeDecodeError, AttributeError):
                            continue

                    elif hasattr(attr_value, "list") and hasattr(attr_value.list, "s"):  # String list
                        for s_val in attr_value.list.s:
                            try:
                                string_vals_to_check.append(s_val.decode("utf-8", errors="ignore"))
                            except (UnicodeDecodeError, AttributeError):
                                continue

                    # Check each string value against injection patterns
                    for string_val in string_vals_to_check:
                        if len(string_val) > 10000:  # Skip extremely long strings to avoid performance issues
                            result.add_check(
                                name="Protobuf String Length Check",
                                passed=False,
                                message=f"Abnormally long string in node attribute (length: {len(string_val)})",
                                severity=IssueSeverity.INFO,
                                location=self._build_node_location(node_context, attr_name=attr_name),
                                details=self._build_node_details(
                                    node_context,
                                    {
                                        "attribute_name": attr_name,
                                        "string_length": len(string_val),
                                        "attack_type": "protobuf_string_bomb",
                                    },
                                ),
                            )
                            continue

                        for pattern, attack_type, description in injection_patterns:
                            matches = re.findall(pattern, string_val, re.IGNORECASE)
                            if matches:
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
                                        },
                                    ),
                                )
                                break  # Only report first match per string to avoid spam

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
                            "node_name_preview": node.name[:200],  # First 200 chars
                        },
                    ),
                )

            # Check input names for excessive length
            for input_name in node.input:
                if len(input_name) > 2048:
                    result.add_check(
                        name="Protobuf Input Name Length Check",
                        passed=False,
                        message=f"Abnormally long input name (length: {len(input_name)}) in node {node.name}",
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

        if not _check_protos():
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
                metadata["extraction_error"] = f"saved_model.pb not found in export directory: {export_dir}"
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

            metadata.update(
                {
                    "meta_graph_count": len(saved_model.meta_graphs),
                    "saved_model_pb_size": len(content),
                    "signatures": sorted(signature_details.keys()),
                    "signature_details": signature_details,
                    "trackable_objects": trackable_objects,
                }
            )
            if tag_sets:
                metadata["tag_sets"] = tag_sets

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata
