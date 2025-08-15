import os
from pathlib import Path
from typing import Any, ClassVar, Optional

from modelaudit.explanations import get_tf_op_explanation
from modelaudit.suspicious_symbols import SUSPICIOUS_OPS
from modelaudit.utils.code_validation import (
    is_code_potentially_dangerous,
    validate_python_syntax,
)

from .base import BaseScanner, IssueSeverity, ScanResult

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
                details={"path": path, "required_package": "tensorflow"}, rule_code="S902",)
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
            details={"path": path}, rule_code="S902",)
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

        try:
            with open(path, "rb") as f:
                content = f.read()
                result.bytes_scanned = len(content)

                saved_model = SavedModelType()
                saved_model.ParseFromString(content)

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
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        # Scan the saved_model.pb file
        file_scan_result = self._scan_saved_model_file(str(saved_model_path))
        result.merge(file_scan_result)

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
                        location=str(file_path), rule_code="S902",
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
                                            location=str(file_path,
                rule_code="S902",
            ),
                                            details={"pattern": pattern, "file": file},
                                        )
                    except Exception as e:
                        result.add_check(
                            name="File Read Check",
                            passed=False,
                            message=f"Error reading file {file}: {e!s}",
                            severity=IssueSeverity.DEBUG,
                            location=str(file_path), rule_code="S902",
                            details={
                                "file": file,
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                            },
                        )

        result.finish(success=True)
        return result

    def _analyze_saved_model(self, saved_model: Any, result: ScanResult) -> None:
        """Analyze the saved model for suspicious operations"""
        suspicious_op_found = False
        op_counts: dict[str, int] = {}

        for meta_graph in saved_model.meta_graphs:
            graph_def = meta_graph.graph_def

            # Scan all nodes in the graph for suspicious operations
            for node in graph_def.node:
                # Count all operation types
                if node.op in op_counts:
                    op_counts[node.op] += 1
                else:
                    op_counts[node.op] = 1

                # Check if the operation is suspicious
                if node.op in self.suspicious_ops:
                    suspicious_op_found = True

                    # Special handling for PyFunc/PyCall - try to extract and validate Python code
                    if node.op in ["PyFunc", "PyCall"]:
                        self._check_python_op(node, result, meta_graph)
                    else:
                        result.add_check(
                            name="TensorFlow Operation Security Check",
                            passed=False,
                            message=f"Suspicious TensorFlow operation: {node.op}",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{self.current_file_path} (node: {node.name})",
                rule_code="S703"",
                            details={
                                "op_type": node.op,
                                "node_name": node.name,
                                "meta_graph": (
                                    meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"
                                ),
                            },
                            why=get_tf_op_explanation(node.op),
                        )

        # Add operation counts to metadata
        result.metadata["op_counts"] = op_counts
        result.metadata["suspicious_op_found"] = suspicious_op_found

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
                rule_code="S902"",
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
                    location=f"{self.current_file_path} (node: {node.name})", rule_code="S902"",
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
                    message=f"{node.op} operation contains suspicious data (possibly obfuscated code")",
                rule_code="S902"",
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
                message=f"{node.op} operation detected (unable to extract Python code")",
                rule_code="S902"",
                severity=IssueSeverity.CRITICAL,
                location=f"{self.current_file_path} (node: {node.name})",
                details={
                    "op_type": node.op,
                    "node_name": node.name,
                    "meta_graph": (meta_graph.meta_info_def.tags[0] if meta_graph.meta_info_def.tags else "unknown"),
                },
                why=get_tf_op_explanation(node.op),
            )
