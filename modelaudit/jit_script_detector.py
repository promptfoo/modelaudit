"""
JIT/Script Code Execution Detection for ML Models
==================================================

Detects potentially dangerous JIT-compiled code and script execution patterns
in TorchScript, TensorFlow SavedFunction, and ONNX models that could lead to
arbitrary code execution.

Part of ModelAudit's critical security validation suite.
"""

import ast
import re
from typing import Any, Optional

# Dangerous TorchScript operations that can execute arbitrary code
DANGEROUS_TORCH_OPS = [
    # System operations
    "torch.ops.aten.system",
    "torch.ops.aten.popen",
    "torch.ops.aten.exec",
    "torch.ops.aten.eval",
    # File operations that could be exploited
    "torch.ops.aten.open",
    "torch.ops.aten.write",
    "torch.ops.aten.remove",
    # Dynamic compilation
    "torch.jit._script",
    "torch.jit.compile",
    "torch.compile",
    # Process/subprocess operations
    "torch.ops.aten.fork",
    "torch.ops.aten.spawn",
    "torch.ops.aten.subprocess",
    # Network operations
    "torch.ops.aten.socket",
    "torch.ops.aten.connect",
    "torch.ops.aten.send",
    # Import operations
    "torch.ops.aten.__import__",
    "torch.ops.aten.importlib",
]

# Dangerous TensorFlow operations
DANGEROUS_TF_OPS = [
    # Arbitrary Python execution
    "tf.py_func",
    "tf.py_function",
    "tf.numpy_function",
    "tf.py_func_with_gradient",
    # Dynamic compilation
    "tf.function",
    "tf.autograph.to_graph",
    "tf.autograph.to_code",
    # System operations
    "tf.io.gfile.GFile",
    "tf.io.gfile.makedirs",
    "tf.io.gfile.remove",
    # Subprocess operations
    "tf.sysconfig.get_compile_flags",
    "tf.sysconfig.get_link_flags",
]

# Dangerous Python builtins that might be embedded
DANGEROUS_BUILTINS = [
    "__import__",
    "compile",
    "eval",
    "exec",
    "execfile",
    "open",
    "input",
    "raw_input",
    "reload",
    "file",
]

# Dangerous module imports
DANGEROUS_IMPORTS = [
    "os",
    "sys",
    "subprocess",
    "socket",
    "urllib",
    "urllib2",
    "urllib3",
    "requests",
    "httplib",
    "http.client",
    "ftplib",
    "telnetlib",
    "smtplib",
    "pickle",
    "cPickle",
    "dill",
    "marshal",
    "shelve",
    "importlib",
    "__builtin__",
    "__builtins__",
]

# Patterns that indicate code execution attempts
CODE_EXECUTION_PATTERNS = [
    # Direct execution patterns
    (rb"exec\s*\(", "exec() call detected"),
    (rb"eval\s*\(", "eval() call detected"),
    (rb"compile\s*\(", "compile() call detected"),
    (rb"__import__\s*\(", "__import__() call detected"),
    # Subprocess patterns
    (rb"subprocess\.(call|run|Popen|check_output)", "Subprocess execution detected"),
    (rb"os\.(system|popen|exec\w*|spawn\w*)", "OS command execution detected"),
    # Network patterns
    (rb"socket\.(socket|create_connection)", "Socket creation detected"),
    (rb"urllib\.(request|urlopen)", "URL request detected"),
    (rb"requests\.(get|post|put|delete)", "HTTP request detected"),
    # File operations
    (rb"open\s*\([^)]*['\"]w", "File write operation detected"),
    (rb"os\.(remove|unlink|rmdir)", "File deletion detected"),
    # Code generation
    (rb"lambda\s+.*:\s*exec", "Lambda with exec detected"),
    (rb"type\s*\(\s*['\"].*['\"],.*exec", "Dynamic type creation with exec"),
]


class JITScriptDetector:
    """Detects dangerous JIT/Script code execution patterns in ML models."""

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize the JIT/Script detector.

        Args:
            config: Optional configuration dictionary with settings like:
                - strict_mode: If True, flag any JIT/script usage (default: False)
                - check_ast: If True, parse and check embedded Python AST (default: True)
                - custom_dangerous_ops: Additional operations to flag
        """
        self.config = config or {}
        self.strict_mode = self.config.get("strict_mode", False)
        self.check_ast = self.config.get("check_ast", True)

        # Combine default dangerous ops with custom ones
        self.dangerous_torch_ops = DANGEROUS_TORCH_OPS.copy()
        self.dangerous_tf_ops = DANGEROUS_TF_OPS.copy()

        if "custom_dangerous_ops" in self.config:
            custom_ops = self.config["custom_dangerous_ops"]
            if "torch" in custom_ops:
                self.dangerous_torch_ops.extend(custom_ops["torch"])
            if "tf" in custom_ops:
                self.dangerous_tf_ops.extend(custom_ops["tf"])

    def scan_torchscript(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan TorchScript model data for dangerous operations.

        Args:
            data: Binary model data
            context: Context string for reporting

        Returns:
            List of findings with details
        """
        findings = []

        # Convert to string for pattern matching
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except Exception:
            text_data = str(data)

        # Check for dangerous Torch operations
        for op in self.dangerous_torch_ops:
            if op in text_data:
                findings.append(
                    {
                        "type": "dangerous_operation",
                        "severity": "CRITICAL",
                        "operation": op,
                        "framework": "TorchScript",
                        "message": f"Dangerous TorchScript operation found: {op}",
                        "context": context,
                        "recommendation": "Review the model source - this operation can execute arbitrary code",
                    }
                )

        # Check for TorchScript markers
        if b"TorchScript" in data or b"torch.jit" in data:
            if self.strict_mode:
                findings.append(
                    {
                        "type": "jit_usage",
                        "severity": "WARNING",
                        "framework": "TorchScript",
                        "message": "TorchScript JIT compilation detected",
                        "context": context,
                        "recommendation": "JIT-compiled models can contain arbitrary code - verify source",
                    }
                )

            # Look for embedded Python code
            if b"def " in data or b"class " in data:
                # Try to extract and parse Python code
                code_findings = self._extract_and_check_python_code(data, "TorchScript", context)
                findings.extend(code_findings)

        # Check for pickle within TorchScript (common attack vector)
        if b"GLOBAL" in data and b"torch" in data:
            findings.append(
                {
                    "type": "embedded_pickle",
                    "severity": "WARNING",
                    "framework": "TorchScript",
                    "message": "Embedded pickle data in TorchScript model",
                    "context": context,
                    "recommendation": "TorchScript with pickle can execute arbitrary code during loading",
                }
            )

        return findings

    def scan_tensorflow(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan TensorFlow SavedModel for dangerous operations.

        Args:
            data: Binary model data or protobuf
            context: Context string for reporting

        Returns:
            List of findings with details
        """
        findings = []

        # Convert to string for pattern matching
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except Exception:
            text_data = str(data)

        # Check for dangerous TF operations
        for op in self.dangerous_tf_ops:
            if op in text_data:
                findings.append(
                    {
                        "type": "dangerous_operation",
                        "severity": "CRITICAL",
                        "operation": op,
                        "framework": "TensorFlow",
                        "message": f"Dangerous TensorFlow operation found: {op}",
                        "context": context,
                        "recommendation": "This operation can execute arbitrary Python code",
                    }
                )

        # Check for SavedFunction markers
        if b"SavedFunction" in data or b"saved_model.pb" in data:
            if b"py_func" in data or b"numpy_function" in data:
                findings.append(
                    {
                        "type": "py_func_usage",
                        "severity": "CRITICAL",
                        "framework": "TensorFlow",
                        "message": "TensorFlow py_func/numpy_function allows arbitrary code execution",
                        "context": context,
                        "recommendation": "Remove py_func operations or verify their implementation",
                    }
                )

            # Check for embedded Python code in SavedFunction
            if b"python_function" in data or b"function_spec" in data:
                code_findings = self._extract_and_check_python_code(data, "TensorFlow", context)
                findings.extend(code_findings)

        # Check for Keras Lambda layers (can contain arbitrary code)
        if b"Lambda" in data and (b"keras" in data or b"tensorflow.keras" in data):
            findings.append(
                {
                    "type": "lambda_layer",
                    "severity": "WARNING",
                    "framework": "TensorFlow/Keras",
                    "message": "Keras Lambda layer detected - may contain arbitrary code",
                    "context": context,
                    "recommendation": "Lambda layers can execute arbitrary Python - verify implementation",
                }
            )

        return findings

    def scan_onnx(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan ONNX model for custom operators and dangerous patterns.

        Args:
            data: Binary ONNX model data
            context: Context string for reporting

        Returns:
            List of findings with details
        """
        findings = []

        # Check for custom operators (potential security risk)
        if b"custom_op" in data or b"ai.onnx.contrib" in data:
            findings.append(
                {
                    "type": "custom_operator",
                    "severity": "WARNING",
                    "framework": "ONNX",
                    "message": "Custom ONNX operator detected",
                    "context": context,
                    "recommendation": "Custom operators can contain native code - verify implementation",
                }
            )

        # Check for Python operators (ONNX-Script)
        if b"PythonOp" in data or b"PyOp" in data:
            findings.append(
                {
                    "type": "python_operator",
                    "severity": "CRITICAL",
                    "framework": "ONNX",
                    "message": "Python operator in ONNX model - can execute arbitrary code",
                    "context": context,
                    "recommendation": "Remove Python operators or thoroughly audit their code",
                }
            )

        # Check for function extensions
        if b"onnx.function" in data:
            findings.append(
                {
                    "type": "function_extension",
                    "severity": "INFO",
                    "framework": "ONNX",
                    "message": "ONNX function extension detected",
                    "context": context,
                    "recommendation": "Review function implementations for security",
                }
            )

        return findings

    def _extract_and_check_python_code(self, data: bytes, framework: str, context: str) -> list[dict[str, Any]]:
        """Extract and analyze embedded Python code.

        Args:
            data: Binary data potentially containing Python code
            framework: The ML framework (for reporting)
            context: Context string

        Returns:
            List of findings from code analysis
        """
        findings: list[dict[str, Any]] = []

        if not self.check_ast:
            return findings

        # Try to extract Python code snippets
        python_code_pattern = rb"def\s+\w+\s*\([^)]*\):[^}]+|class\s+\w+[^}]+"
        matches = re.findall(python_code_pattern, data[:1000000])  # Limit search size

        for match in matches[:10]:  # Analyze first 10 code snippets
            try:
                code_str = match.decode("utf-8", errors="ignore")

                # Check for dangerous imports
                for dangerous_import in DANGEROUS_IMPORTS:
                    if f"import {dangerous_import}" in code_str or f"from {dangerous_import}" in code_str:
                        findings.append(
                            {
                                "type": "dangerous_import",
                                "severity": "CRITICAL",
                                "import": dangerous_import,
                                "framework": framework,
                                "message": f"Dangerous import '{dangerous_import}' in embedded code",
                                "context": context,
                                "code_snippet": code_str[:200],
                                "recommendation": f"Remove {dangerous_import} import - it can be used maliciously",
                            }
                        )

                # Check for dangerous builtins
                for builtin in DANGEROUS_BUILTINS:
                    if builtin in code_str:
                        findings.append(
                            {
                                "type": "dangerous_builtin",
                                "severity": "CRITICAL",
                                "builtin": builtin,
                                "framework": framework,
                                "message": f"Dangerous builtin '{builtin}' used in embedded code",
                                "context": context,
                                "code_snippet": code_str[:200],
                                "recommendation": f"Remove {builtin} usage - it can execute arbitrary code",
                            }
                        )

                # Try to parse as AST for deeper analysis
                try:
                    tree = ast.parse(code_str)
                    ast_findings = self._analyze_ast(tree, framework, context)
                    findings.extend(ast_findings)
                except SyntaxError:
                    # Not valid Python, might be partial or corrupted
                    pass

            except Exception:
                # Failed to process this code snippet
                continue

        # Check for common code execution patterns in binary
        for pattern, description in CODE_EXECUTION_PATTERNS:
            if re.search(pattern, data[:1000000]):  # Limit search size
                findings.append(
                    {
                        "type": "code_execution_pattern",
                        "severity": "CRITICAL",
                        "pattern": description,
                        "framework": framework,
                        "message": description,
                        "context": context,
                        "recommendation": "This pattern indicates potential code execution - review carefully",
                    }
                )

        return findings

    def _analyze_ast(self, tree: ast.AST, framework: str, context: str) -> list[dict[str, Any]]:
        """Analyze Python AST for dangerous patterns.

        Args:
            tree: Python AST tree
            framework: The ML framework
            context: Context string

        Returns:
            List of findings from AST analysis
        """
        findings: list[dict[str, Any]] = []

        class DangerousNodeVisitor(ast.NodeVisitor):
            def __init__(self):
                self.findings: list[dict[str, Any]] = []

            def visit_Import(self, node):
                for alias in node.names:
                    if alias.name in DANGEROUS_IMPORTS:
                        self.findings.append(
                            {
                                "type": "ast_dangerous_import",
                                "severity": "CRITICAL",
                                "import": alias.name,
                                "framework": framework,
                                "message": f"AST analysis: Dangerous import '{alias.name}'",
                                "context": context,
                            }
                        )
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                if node.module in DANGEROUS_IMPORTS:
                    self.findings.append(
                        {
                            "type": "ast_dangerous_import",
                            "severity": "CRITICAL",
                            "import": node.module,
                            "framework": framework,
                            "message": f"AST analysis: Dangerous import from '{node.module}'",
                            "context": context,
                        }
                    )
                self.generic_visit(node)

            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
                    self.findings.append(
                        {
                            "type": "ast_dangerous_call",
                            "severity": "CRITICAL",
                            "function": node.func.id,
                            "framework": framework,
                            "message": f"AST analysis: Dangerous function call '{node.func.id}'",
                            "context": context,
                        }
                    )
                self.generic_visit(node)

        visitor = DangerousNodeVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)

        return findings

    def scan_model(self, data: bytes, model_type: str = "unknown", context: str = "") -> list[dict[str, Any]]:
        """Main entry point to scan a model for JIT/Script code execution risks.

        Args:
            data: Binary model data
            model_type: Type of model (pytorch, tensorflow, onnx, etc.)
            context: Context string for reporting

        Returns:
            List of all findings
        """
        findings = []

        # Auto-detect model type if unknown
        if model_type == "unknown":
            if b"TorchScript" in data or b"torch.jit" in data or b"pytorch" in data:
                model_type = "pytorch"
            elif b"tensorflow" in data or b"saved_model.pb" in data:
                model_type = "tensorflow"
            elif b"onnx" in data or b"ai.onnx" in data:
                model_type = "onnx"

        # Scan based on model type
        if model_type in ["pytorch", "torchscript"]:
            findings.extend(self.scan_torchscript(data, context))

        if model_type in ["tensorflow", "tf", "keras"]:
            findings.extend(self.scan_tensorflow(data, context))

        if model_type == "onnx":
            findings.extend(self.scan_onnx(data, context))

        # Always check for generic dangerous patterns
        if model_type == "unknown" or not findings:
            # Check all frameworks if type is unknown
            findings.extend(self.scan_torchscript(data, context))
            findings.extend(self.scan_tensorflow(data, context))
            findings.extend(self.scan_onnx(data, context))

        return findings


def detect_jit_script_risks(file_path: str, max_size: int = 500 * 1024 * 1024) -> list[dict[str, Any]]:
    """Convenience function to scan a file for JIT/Script execution risks.

    Args:
        file_path: Path to the model file to scan
        max_size: Maximum file size to scan (default 500MB)

    Returns:
        List of detected risks
    """
    import os

    if not os.path.exists(file_path):
        return [{"type": "error", "message": f"File not found: {file_path}"}]

    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        return [{"type": "error", "message": f"File too large: {file_size} bytes (max: {max_size})"}]

    # Detect model type from extension
    ext = os.path.splitext(file_path)[1].lower()
    model_type = "unknown"
    if ext in [".pt", ".pth", ".pts", ".torchscript"]:
        model_type = "pytorch"
    elif ext in [".pb", ".h5", ".keras", ".savedmodel"]:
        model_type = "tensorflow"
    elif ext in [".onnx"]:
        model_type = "onnx"

    detector = JITScriptDetector()

    with open(file_path, "rb") as f:
        data = f.read()

    return detector.scan_model(data, model_type, file_path)
