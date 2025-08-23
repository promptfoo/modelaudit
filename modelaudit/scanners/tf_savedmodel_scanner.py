import logging
import os
from pathlib import Path
from typing import Any, ClassVar, Optional

from modelaudit.explanations import get_tf_op_explanation
from modelaudit.suspicious_symbols import SUSPICIOUS_OPS, TENSORFLOW_DANGEROUS_OPS
from modelaudit.utils.code_validation import (
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

# Try to import TensorFlow, but handle the case where it's not installed
try:
    import tensorflow as tf  # noqa: F401
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    HAS_TENSORFLOW = True
    SavedModelType: type = SavedModel
except ImportError:
    HAS_TENSORFLOW = False

    # Create a placeholder for type hints when TensorFlow is not available
    class SavedModel:  # type: ignore[no-redef]
        """Placeholder for SavedModel when TensorFlow is not installed"""

        meta_graphs: ClassVar[list] = []

    SavedModelType = SavedModel


class TensorFlowSavedModelScanner(BaseScanner):
    """Scanner for TensorFlow SavedModel format"""

    name = "tf_savedmodel"
    description = "Scans TensorFlow SavedModel for suspicious operations"
    supported_extensions: ClassVar[list[str]] = [".pb", ""]  # Empty string for directories

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Additional scanner-specific configuration
        self.suspicious_ops = set(self.config.get("suspicious_ops", SUSPICIOUS_OPS))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not HAS_TENSORFLOW:
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

        # Check if TensorFlow is installed
        if not HAS_TENSORFLOW:
            result = self._create_result()
            result.add_check(
                name="TensorFlow Library Check",
                passed=False,
                message="TensorFlow not installed, cannot scan SavedModel. Install modelaudit[tensorflow].",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"path": path, "required_package": "tensorflow"},
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
            with open(path, "rb") as f:
                content = f.read()
                result.bytes_scanned = len(content)

                saved_model = SavedModelType()
                saved_model.ParseFromString(content)
                for op_info in self._scan_tf_operations(saved_model):
                    result.add_check(
                        name="TensorFlow Operation Security Check",
                        passed=False,
                        message=f"Dangerous TensorFlow operation: {op_info['operation']}",
                        severity=op_info["severity"],
                        location=f"{self.current_file_path} (node: {op_info['node_name']})",
                        details={
                            "op_type": op_info["operation"],
                            "node_name": op_info["node_name"],
                            "meta_graph": op_info.get("meta_graph", "unknown"),
                        },
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

        # Look for saved_model.pb in the directory
        saved_model_path = Path(dir_path) / "saved_model.pb"
        if not saved_model_path.exists():
            result.add_check(
                name="SavedModel Structure Check",
                passed=False,
                message="No saved_model.pb found in directory.",
                severity=IssueSeverity.CRITICAL,
                location=dir_path,
            )
            result.finish(success=False)
            return result

        # Scan the saved_model.pb file
        file_scan_result = self._scan_saved_model_file(str(saved_model_path))
        result.merge(file_scan_result)

        # Check for keras_metadata.pb which contains Lambda layer definitions
        keras_metadata_path = Path(dir_path) / "keras_metadata.pb"
        if keras_metadata_path.exists():
            self._scan_keras_metadata(str(keras_metadata_path), result)

        # Check for other suspicious files in the directory
        for root, _dirs, files in os.walk(dir_path):
            for file in files:
                file_path = Path(root) / file
                # Look for potentially suspicious Python files
                if file.endswith(".py"):
                    result.add_check(
                        name="Python File Detection",
                        passed=False,
                        message=f"Python file found in SavedModel: {file}",
                        severity=IssueSeverity.INFO,
                        location=str(file_path),
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
                                            details={"pattern": pattern, "file": file},
                                        )
                    except Exception as e:
                        result.add_check(
                            name="File Read Check",
                            passed=False,
                            message=f"Error reading file {file}: {e!s}",
                            severity=IssueSeverity.DEBUG,
                            location=str(file_path),
                            details={
                                "file": file,
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                            },
                        )

        result.finish(success=True)
        return result

    def _scan_tf_operations(self, saved_model: Any) -> list[dict[str, Any]]:
        """Scan TensorFlow graph for dangerous operations (generic pass)"""
        dangerous_ops: list[dict[str, Any]] = []
        try:
            for meta_graph in saved_model.meta_graphs:
                graph_def = meta_graph.graph_def
                for node in graph_def.node:
                    # Skip Python ops here; they are handled by _check_python_op
                    if node.op in PYTHON_OPS:
                        continue
                    if node.op in DANGEROUS_TF_OPERATIONS:
                        dangerous_ops.append(
                            {
                                "operation": node.op,
                                "node_name": node.name,
                                "severity": DANGEROUS_TF_OPERATIONS[node.op],
                                "meta_graph": (
                                    meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"
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

        for meta_graph in saved_model.meta_graphs:
            graph_def = meta_graph.graph_def

            # Scan all nodes in the graph for suspicious operations
            for node in graph_def.node:
                # Count all operation types
                op_counts[node.op] = op_counts.get(node.op, 0) + 1

                if node.op in self.suspicious_ops:
                    suspicious_op_found = True

                    # Special handling for PyFunc/PyCall - try to extract and validate Python code
                    if node.op in PYTHON_OPS:
                        self._check_python_op(node, result, meta_graph)
                    elif node.op not in DANGEROUS_TF_OPERATIONS:
                        result.add_check(
                            name="TensorFlow Operation Security Check",
                            passed=False,
                            message=f"Suspicious TensorFlow operation: {node.op}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} (node: {node.name})",
                            details={
                                "op_type": node.op,
                                "node_name": node.name,
                                "meta_graph": (
                                    meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"
                                ),
                            },
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

                        # Check for suspicious function names
                        suspicious_func_patterns = [
                            "lambda",
                            "eval",
                            "exec",
                            "compile",
                            "__import__",
                            "system",
                            "popen",
                            "subprocess",
                            "pickle",
                            "marshal",
                        ]

                        for pattern in suspicious_func_patterns:
                            if pattern in func_name.lower():
                                result.add_check(
                                    name="StatefulPartitionedCall Security Check",
                                    passed=False,
                                    message=f"StatefulPartitionedCall with suspicious function: {func_name}",
                                    severity=IssueSeverity.WARNING,
                                    location=f"{self.current_file_path} (node: {node.name})",
                                    details={
                                        "op_type": node.op,
                                        "node_name": node.name,
                                        "function_name": func_name,
                                        "suspicious_pattern": pattern,
                                    },
                                    why=(
                                        "StatefulPartitionedCall can execute custom functions "
                                        "that may contain arbitrary code."
                                    ),
                                )
                                break

        # Add operation counts to metadata
        result.metadata["op_counts"] = op_counts
        result.metadata["suspicious_op_found"] = suspicious_op_found

        # Enhanced protobuf vulnerability scanning
        self._scan_protobuf_vulnerabilities(saved_model, result)

    def _check_python_op(self, node: Any, result: ScanResult, meta_graph: Any) -> None:
        """Check PyFunc/PyCall operations for embedded Python code"""
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
                                    location=f"{self.current_file_path} (node: {node.name})",
                                    details={
                                        "op_type": node.op,
                                        "node_name": node.name,
                                        "function_reference": func_name,
                                        "meta_graph": (
                                            meta_graph.meta_info_def.tags[0]
                                            if meta_graph.meta_info_def.tags
                                            else "unknown"
                                        ),
                                    },
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
                    location=f"{self.current_file_path} (node: {node.name})",
                    details={
                        "op_type": node.op,
                        "node_name": node.name,
                        "code_analysis": risk_desc if is_dangerous else "Contains executable code",
                        "code_preview": python_code[:200] + "..." if len(python_code) > 200 else python_code,
                        "validation_status": "valid_python",
                        "meta_graph": (
                            meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"
                        ),
                    },
                    why=get_tf_op_explanation(node.op),
                )
            else:
                # Code found but not valid Python
                result.add_check(
                    name="PyFunc Code Validation",
                    passed=False,
                    message=f"{node.op} operation contains suspicious data (possibly obfuscated code)",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{self.current_file_path} (node: {node.name})",
                    details={
                        "op_type": node.op,
                        "node_name": node.name,
                        "validation_error": error,
                        "data_preview": python_code[:100] + "..." if len(python_code) > 100 else python_code,
                        "meta_graph": (
                            meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"
                        ),
                    },
                    why=get_tf_op_explanation(node.op),
                )
        else:
            # PyFunc/PyCall without analyzable code - still dangerous
            result.add_check(
                name="PyFunc Code Extraction Check",
                passed=False,
                message=f"{node.op} operation detected (unable to extract Python code)",
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} (node: {node.name})",
                details={
                    "op_type": node.op,
                    "node_name": node.name,
                    "meta_graph": (meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"),
                },
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
                                result.add_issue(
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

        # Check for protobuf schema validation bypasses
        self._check_protobuf_schema_attacks(saved_model, result)

        # Check for malicious string data in protobuf fields
        self._check_protobuf_string_injection(saved_model, result)

        # Check for buffer overflow patterns
        self._check_protobuf_buffer_overflow(saved_model, result)

        # Check for large field counts (DoS via memory exhaustion)
        self._check_protobuf_field_bomb(saved_model, result)

    def _check_protobuf_schema_attacks(self, saved_model: Any, result: ScanResult) -> None:
        """Check for protobuf schema validation bypass attempts"""

        for meta_graph in saved_model.meta_graphs:
            # Check for unknown/unexpected fields in the meta graph
            if hasattr(meta_graph, "ListFields"):
                fields = meta_graph.ListFields()

                # Look for fields with unusually large sizes
                for field_desc, field_value in fields:
                    if hasattr(field_value, "__len__"):
                        try:
                            field_size = len(field_value)
                            # Check for abnormally large repeated fields
                            if field_size > 10000:  # 10k threshold
                                result.add_check(
                                    name="Protobuf Field Size Check",
                                    passed=False,
                                    message=(
                                        f"Abnormally large protobuf field '{field_desc.name}' "
                                        f"with {field_size} elements"
                                    ),
                                    severity=IssueSeverity.WARNING,
                                    location=self.current_file_path,
                                    details={
                                        "field_name": field_desc.name,
                                        "field_size": field_size,
                                        "size_threshold": 10000,
                                        "potential_attack": "protobuf_field_bomb",
                                    },
                                )
                        except (AttributeError, TypeError):
                            continue

            # Check the graph definition for schema bypass attempts
            graph_def = meta_graph.graph_def

            # Look for nodes with excessive attributes (potential DoS)
            for node in graph_def.node:
                if hasattr(node, "attr") and len(node.attr) > 1000:
                    result.add_check(
                        name="Protobuf Node Attribute Bomb Check",
                        passed=False,
                        message=f"Node '{node.name}' has excessive attributes ({len(node.attr)})",
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (node: {node.name})",
                        details={
                            "node_name": node.name,
                            "attribute_count": len(node.attr),
                            "threshold": 1000,
                            "attack_type": "protobuf_attribute_bomb",
                        },
                    )

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
            # Base64 encoded payloads
            (r"[A-Za-z0-9+/]{20,}={0,2}", "encoded_payload", "potential base64 payload"),
        ]

        import re

        for meta_graph in saved_model.meta_graphs:
            graph_def = meta_graph.graph_def

            for node in graph_def.node:
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
                                    severity=IssueSeverity.WARNING,
                                    location=f"{self.current_file_path} (node: {node.name}, attr: {attr_name})",
                                    details={
                                        "node_name": node.name,
                                        "attribute_name": attr_name,
                                        "string_length": len(string_val),
                                        "attack_type": "protobuf_string_bomb",
                                    },
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
                                        location=f"{self.current_file_path} (node: {node.name}, attr: {attr_name})",
                                        details={
                                            "node_name": node.name,
                                            "attribute_name": attr_name,
                                            "pattern_matched": pattern,
                                            "matches": matches[:5],  # Limit to first 5 matches
                                            "attack_type": attack_type,
                                            "description": description,
                                            "total_matches": len(matches),
                                        },
                                    )
                                    break  # Only report first match per string to avoid spam

    def _check_protobuf_buffer_overflow(self, saved_model: Any, result: ScanResult) -> None:
        """Check for potential buffer overflow patterns in protobuf data"""

        for meta_graph in saved_model.meta_graphs:
            graph_def = meta_graph.graph_def

            # Check for nodes with extremely long names (potential buffer overflow)
            for node in graph_def.node:
                if len(node.name) > 2048:  # 2KB threshold for node names
                    result.add_check(
                        name="Protobuf Node Name Length Check",
                        passed=False,
                        message=(
                            f"Abnormally long node name (length: {len(node.name)}) may indicate buffer overflow attempt"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=f"{self.current_file_path} (node: {node.name[:100]}...)",
                        details={
                            "node_name_length": len(node.name),
                            "name_threshold": 2048,
                            "attack_type": "protobuf_buffer_overflow",
                            "node_name_preview": node.name[:200],  # First 200 chars
                        },
                    )

                # Check input names for excessive length
                for input_name in node.input:
                    if len(input_name) > 2048:
                        result.add_check(
                            name="Protobuf Input Name Length Check",
                            passed=False,
                            message=f"Abnormally long input name (length: {len(input_name)}) in node {node.name}",
                            severity=IssueSeverity.WARNING,
                            location=f"{self.current_file_path} (node: {node.name})",
                            details={
                                "node_name": node.name,
                                "input_name_length": len(input_name),
                                "name_threshold": 2048,
                                "attack_type": "protobuf_buffer_overflow",
                            },
                        )

    def _check_protobuf_field_bomb(self, saved_model: Any, result: ScanResult) -> None:
        """Check for protobuf field bombs (DoS via excessive fields)"""

        total_nodes = 0
        total_attrs = 0

        for meta_graph in saved_model.meta_graphs:
            graph_def = meta_graph.graph_def
            meta_graph_nodes = len(graph_def.node)
            total_nodes += meta_graph_nodes

            # Count total attributes across all nodes
            meta_graph_attrs = sum(len(node.attr) if hasattr(node, "attr") else 0 for node in graph_def.node)
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
