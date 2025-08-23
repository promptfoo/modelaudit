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
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from modelaudit.models import JITScriptFinding


def create_jit_finding(**kwargs) -> "JITScriptFinding":
    """Helper to create JITScriptFinding with proper field handling."""
    from modelaudit.models import JITScriptFinding

    # Handle the import field alias properly
    if "import_" in kwargs:
        kwargs["import"] = kwargs.pop("import_")
    return JITScriptFinding(**kwargs)


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
            config: Configuration dictionary with settings like:
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

    def scan_torchscript(self, data: bytes, context: str = "") -> list["JITScriptFinding"]:
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
                    create_jit_finding(
                        message=f"Dangerous TorchScript operation found: {op}",
                        severity="CRITICAL",
                        context=context,
                        pattern=op,
                        recommendation="Review the model source - this operation can execute arbitrary code",
                        confidence=1.0,
                        framework="TorchScript",
                        code_snippet=None,
                        type="dangerous_operation",
                        operation=op,
                        builtin=None,
                        import_=None,
                    )
                )

        # Check for TorchScript markers
        if b"TorchScript" in data or b"torch.jit" in data:
            if self.strict_mode:
                finding_data = {
                    "message": "TorchScript JIT compilation detected",
                    "severity": "WARNING",
                    "context": context,
                    "pattern": None,
                    "recommendation": "JIT-compiled models can contain arbitrary code - verify source",
                    "confidence": 0.8,
                    "framework": "TorchScript",
                    "code_snippet": None,
                    "type": "jit_usage",
                    "operation": None,
                    "builtin": None,
                    "import": None,
                }
                findings.append(create_jit_finding(**finding_data))

            # Look for embedded Python code
            if b"def " in data or b"class " in data:
                # Try to extract and parse Python code
                code_findings = self._extract_and_check_python_code(data, "TorchScript", context)
                findings.extend(code_findings)

        # Check for pickle within TorchScript (common attack vector)
        if b"GLOBAL" in data and b"torch" in data:
            findings.append(
                create_jit_finding(
                    message="Embedded pickle data in TorchScript model",
                    severity="WARNING",
                    context=context,
                    pattern=None,
                    recommendation="TorchScript with pickle can execute arbitrary code during loading",
                    confidence=0.9,
                    framework="TorchScript",
                    code_snippet=None,
                    type="embedded_pickle",
                    operation=None,
                    builtin=None,
                    import_=None,
                )
            )

        return findings

    def scan_tensorflow(self, data: bytes, context: str = "") -> list["JITScriptFinding"]:
        """Scan TensorFlow SavedModel for dangerous operations.

        Args:
            data: Binary model data or protobuf
            context: Context string for reporting

        Returns:
            List of findings with details
        """
        findings: list[JITScriptFinding] = []

        # Convert to string for pattern matching
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except Exception:
            text_data = str(data)

        # Check for dangerous TF operations
        for op in self.dangerous_tf_ops:
            if op in text_data:
                findings.append(
                    create_jit_finding(
                        message=f"Dangerous TensorFlow operation found: {op}",
                        severity="CRITICAL",
                        context=context,
                        pattern=None,
                        recommendation="This operation can execute arbitrary Python code",
                        confidence=0.9,
                        framework="TensorFlow",
                        code_snippet=None,
                        type="dangerous_operation",
                        operation=op,
                        builtin=None,
                        import_=None,
                    )
                )

        # Check for SavedFunction markers
        if b"SavedFunction" in data or b"saved_model.pb" in data:
            if b"py_func" in data or b"numpy_function" in data:
                findings.append(
                    create_jit_finding(
                        message="TensorFlow py_func/numpy_function allows arbitrary code execution",
                        severity="CRITICAL",
                        context=context,
                        pattern=None,
                        recommendation="Remove py_func operations or verify their implementation",
                        confidence=0.9,
                        framework="TensorFlow",
                        code_snippet=None,
                        type="py_func_usage",
                        operation=None,
                        builtin=None,
                        import_=None,
                    )
                )

            # Check for embedded Python code in SavedFunction
            if b"python_function" in data or b"function_spec" in data:
                code_findings = self._extract_and_check_python_code(data, "TensorFlow", context)
                findings.extend(code_findings)

        # Check for Keras Lambda layers (can contain arbitrary code)
        if b"Lambda" in data and (b"keras" in data or b"tensorflow.keras" in data):
            findings.append(
                create_jit_finding(
                    message="Keras Lambda layer detected - may contain arbitrary code",
                    severity="WARNING",
                    context=context,
                    pattern=None,
                    recommendation="Lambda layers can execute arbitrary Python - verify implementation",
                    confidence=0.8,
                    framework="TensorFlow/Keras",
                    code_snippet=None,
                    type="lambda_layer",
                    operation=None,
                    builtin=None,
                    import_=None,
                )
            )

        return findings

    def scan_onnx(self, data: bytes, context: str = "") -> list["JITScriptFinding"]:
        """Scan ONNX model for custom operators and dangerous patterns.

        Args:
            data: Binary ONNX model data
            context: Context string for reporting

        Returns:
            List of findings with details
        """
        from modelaudit.models import JITScriptFinding

        findings: list[JITScriptFinding] = []

        # Check for custom operators (potential security risk)
        if b"custom_op" in data or b"ai.onnx.contrib" in data:
            findings.append(
                create_jit_finding(
                    message="Custom ONNX operator detected",
                    severity="WARNING",
                    context=context,
                    pattern=None,
                    recommendation="Custom operators can contain native code - verify implementation",
                    confidence=0.7,
                    framework="ONNX",
                    code_snippet=None,
                    type="custom_operator",
                    operation=None,
                    builtin=None,
                    import_=None,
                )
            )

        # Check for Python operators (ONNX-Script)
        if b"PythonOp" in data or b"PyOp" in data:
            findings.append(
                create_jit_finding(
                    message="Python operator in ONNX model - can execute arbitrary code",
                    severity="CRITICAL",
                    context=context,
                    pattern=None,
                    recommendation="Remove Python operators or thoroughly audit their code",
                    confidence=0.9,
                    framework="ONNX",
                    code_snippet=None,
                    type="python_operator",
                    operation=None,
                    builtin=None,
                    import_=None,
                )
            )

        # Check for function extensions
        if b"onnx.function" in data:
            findings.append(
                create_jit_finding(
                    message="ONNX function extension detected",
                    severity="INFO",
                    context=context,
                    pattern=None,
                    recommendation="Review function implementations for security",
                    confidence=0.5,
                    framework="ONNX",
                    code_snippet=None,
                    type="function_extension",
                    operation=None,
                    builtin=None,
                    import_=None,
                )
            )

        return findings

    def _extract_and_check_python_code(self, data: bytes, framework: str, context: str) -> list["JITScriptFinding"]:
        """Extract and analyze embedded Python code.

        Args:
            data: Binary data potentially containing Python code
            framework: The ML framework (for reporting)
            context: Context string

        Returns:
            List of findings from code analysis
        """
        from modelaudit.models import JITScriptFinding

        findings: list[JITScriptFinding] = []

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
                            create_jit_finding(
                                message=f"Dangerous import '{dangerous_import}' in embedded code",
                                severity="CRITICAL",
                                context=context,
                                pattern=None,
                                recommendation=f"Remove {dangerous_import} import - it can be used maliciously",
                                confidence=0.9,
                                framework=framework,
                                code_snippet=code_str[:200],
                                type="dangerous_import",
                                operation=None,
                                builtin=None,
                                import_=dangerous_import,
                            )
                        )

                # Check for dangerous builtins
                for builtin in DANGEROUS_BUILTINS:
                    if builtin in code_str:
                        findings.append(
                            create_jit_finding(
                                message=f"Dangerous builtin '{builtin}' used in embedded code",
                                severity="CRITICAL",
                                context=context,
                                pattern=None,
                                recommendation=f"Remove {builtin} usage - it can execute arbitrary code",
                                confidence=0.9,
                                framework=framework,
                                code_snippet=code_str[:200],
                                type="dangerous_builtin",
                                operation=None,
                                builtin=builtin,
                                import_=None,
                            )
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
                    create_jit_finding(
                        message=description,
                        severity="CRITICAL",
                        context=context,
                        pattern=description,
                        recommendation="This pattern indicates potential code execution - review carefully",
                        confidence=0.8,
                        framework=framework,
                        code_snippet=None,
                        type="code_execution_pattern",
                        operation=None,
                        builtin=None,
                        import_=None,
                    )
                )

        return findings

    def _analyze_ast(self, tree: ast.AST, framework: str, context: str) -> list["JITScriptFinding"]:
        """Analyze Python AST for dangerous patterns.

        Args:
            tree: Python AST tree
            framework: The ML framework
            context: Context string

        Returns:
            List of findings from AST analysis
        """
        from modelaudit.models import JITScriptFinding

        findings: list[JITScriptFinding] = []

        class DangerousNodeVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.findings: list[JITScriptFinding] = []

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    if alias.name in DANGEROUS_IMPORTS:
                        self.findings.append(
                            create_jit_finding(
                                message=f"AST analysis: Dangerous import '{alias.name}'",
                                severity="CRITICAL",
                                context=context,
                                pattern=None,
                                recommendation="Remove dangerous imports to prevent code execution",
                                confidence=0.9,
                                framework=framework,
                                code_snippet=None,
                                type="ast_dangerous_import",
                                operation=None,
                                builtin=None,
                                import_=alias.name,
                            )
                        )
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if node.module and node.module in DANGEROUS_IMPORTS:
                    self.findings.append(
                        create_jit_finding(
                            message=f"AST analysis: Dangerous import from '{node.module}'",
                            severity="CRITICAL",
                            context=context,
                            pattern=None,
                            recommendation="Remove dangerous imports to prevent code execution",
                            confidence=0.9,
                            framework=framework,
                            code_snippet=None,
                            type="ast_dangerous_import",
                            operation=None,
                            builtin=None,
                            import_=node.module,
                        )
                    )
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
                    self.findings.append(
                        create_jit_finding(
                            message=f"AST analysis: Dangerous function call '{node.func.id}'",
                            severity="CRITICAL",
                            context=context,
                            pattern=None,
                            recommendation="Remove dangerous function calls to prevent code execution",
                            confidence=0.9,
                            framework=framework,
                            code_snippet=None,
                            type="ast_dangerous_call",
                            operation=None,
                            builtin=node.func.id,
                            import_=None,
                        )
                    )
                self.generic_visit(node)

        visitor = DangerousNodeVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)

        return findings

    def scan_advanced_torchscript_vulnerabilities(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Advanced TorchScript vulnerability scanning for sophisticated attacks"""
        findings: list[dict[str, Any]] = []

        try:
            text_data = data.decode("utf-8", errors="ignore")
        except Exception:
            text_data = str(data)

        # 1. TorchScript serialization injection attacks
        serialization_injection_patterns = [
            (r"torch\.jit\.save.*exec\s*\(", "TorchScript save with exec injection"),
            (r"torch\.jit\.load.*eval\s*\(", "TorchScript load with eval injection"),
            (r"torch\.save.*__reduce__", "PyTorch save with reduce injection"),
            (r"torch\.load.*weights_only\s*=\s*False", "Unsafe torch.load without weights_only protection"),
            (r"pickle\.loads.*torch", "Unsafe pickle deserialization with torch"),
        ]

        for pattern, description in serialization_injection_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_serialization_injection",
                        "severity": "CRITICAL",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"TorchScript serialization vulnerability: {description}",
                        "context": context,
                        "recommendation": "Use safe serialization methods and validate all model sources",
                    }
                )

        # 2. TorchScript module manipulation attacks
        module_manipulation_patterns = [
            (r"torch\.jit\.script\s*\(\s*lambda", "Lambda script compilation"),
            (r"torch\.jit\.trace.*exec", "Trace with exec injection"),
            (r"torch\.nn\.Module.*__getattr__.*exec", "Module attribute injection"),
            (r"torch\.jit\.CompilationUnit.*exec", "Compilation unit injection"),
            (r"torch\.jit\.script_method.*eval", "Script method with eval"),
            (r"torch\.jit\.unused.*__import__", "Unused decorator bypass"),
        ]

        for pattern, description in module_manipulation_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_module_manipulation",
                        "severity": "HIGH",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"TorchScript module manipulation: {description}",
                        "context": context,
                        "recommendation": "Review model architecture for unauthorized module modifications",
                    }
                )

        # 3. TorchScript graph manipulation
        graph_manipulation_patterns = [
            (r"torch\.jit\.freeze.*add_module", "Graph freeze with module injection"),
            (r"torch\.jit\.optimize_for_inference.*exec", "Inference optimization with exec"),
            (r"torch\.fx\.symbolic_trace.*eval", "FX tracing with eval injection"),
            (r"torch\.fx\.replace_pattern.*__import__", "FX pattern replacement with import"),
            (r"torch\.jit\.fuse.*system", "JIT fusion with system call"),
        ]

        for pattern, description in graph_manipulation_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_graph_manipulation",
                        "severity": "HIGH",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"TorchScript graph manipulation: {description}",
                        "context": context,
                        "recommendation": "Validate model graph integrity and compilation process",
                    }
                )

        # 4. TorchScript bytecode injection
        bytecode_injection_patterns = [
            (r"torch\.jit\.get_jit_operator.*exec", "JIT operator with exec"),
            (r"torch\.ops\.aten\..*exec", "ATEN operator with exec"),
            (r"torch\.ops\.torchscript\..*eval", "TorchScript op with eval"),
            (r"torch\.jit\.ScriptFunction.*compile", "Script function with compile"),
            (r"torch\.jit\.mobile\..*exec", "Mobile JIT with exec"),
        ]

        for pattern, description in bytecode_injection_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_bytecode_injection",
                        "severity": "CRITICAL",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"TorchScript bytecode injection: {description}",
                        "context": context,
                        "recommendation": "This indicates potential code injection at the bytecode level",
                    }
                )

        # 5. TorchScript CUDA/backend exploitation
        backend_exploitation_patterns = [
            (r"torch\.cuda\..*exec", "CUDA operations with exec"),
            (r"torch\.backends\..*eval", "Backend configuration with eval"),
            (r"torch\.distributed\..*system", "Distributed operations with system calls"),
            (r"torch\.multiprocessing\..*exec", "Multiprocessing with exec"),
            (r"torch\.profiler\..*eval", "Profiler with eval injection"),
        ]

        for pattern, description in backend_exploitation_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_backend_exploitation",
                        "severity": "HIGH",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"TorchScript backend exploitation: {description}",
                        "context": context,
                        "recommendation": "Review backend operations for security vulnerabilities",
                    }
                )

        # 6. TorchScript hook and callback injection
        hook_injection_patterns = [
            (r"torch\.nn\.utils\.hooks\..*exec", "Hook with exec injection"),
            (r"register_.*_hook.*eval", "Hook registration with eval"),
            (r"register_forward_hook.*__import__", "Forward hook with import"),
            (r"register_backward_hook.*system", "Backward hook with system call"),
            (r"register_module_.*_hook.*exec", "Module hook with exec"),
        ]

        for pattern, description in hook_injection_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_hook_injection",
                        "severity": "CRITICAL",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"TorchScript hook injection: {description}",
                        "context": context,
                        "recommendation": "Hooks can execute arbitrary code - review all hook registrations",
                    }
                )

        # 7. Check for obfuscated TorchScript code
        obfuscation_patterns = [
            (r"\\x[0-9a-fA-F]{2}.*torch", "Hex-encoded TorchScript references"),
            (r"base64.*decode.*torch", "Base64-encoded TorchScript code"),
            (r"chr\(.*\).*torch", "Character-encoded TorchScript strings"),
            (r"eval\(.*compile.*torch", "Double-encoded TorchScript execution"),
        ]

        for pattern, description in obfuscation_patterns:
            matches = re.findall(pattern, text_data, re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_obfuscation",
                        "severity": "WARNING",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"Obfuscated TorchScript code: {description}",
                        "context": context,
                        "recommendation": "Obfuscated code may hide malicious functionality",
                    }
                )

        # 8. TorchScript version-specific vulnerability patterns
        version_vulnerabilities = [
            (r"torch\.jit\.load.*weights_only\s*=\s*True", "CVE-2025-32434: weights_only=True bypass pattern"),
            (r"torch\.load.*map_location.*exec", "Map location with code execution"),
            (r"torch\.serialization\..*exec", "Serialization with exec pattern"),
            (r"torch\._C\..*eval", "Internal C++ interface with eval"),
        ]

        for pattern, description in version_vulnerabilities:
            matches = re.findall(pattern, text_data, re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append(
                    {
                        "type": "torchscript_version_vulnerability",
                        "severity": "CRITICAL",
                        "pattern": pattern,
                        "description": description,
                        "matches": len(matches),
                        "framework": "TorchScript",
                        "message": f"Version-specific vulnerability: {description}",
                        "context": context,
                        "recommendation": "Update PyTorch version and review loading patterns",
                    }
                )

        return findings

    def scan_model(self, data: bytes, model_type: str = "unknown", context: str = "") -> list["JITScriptFinding"]:
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
            # TODO: Fix return type mismatch in scan_advanced_torchscript_vulnerabilities
            # findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))

        if model_type in ["tensorflow", "tf", "keras"]:
            findings.extend(self.scan_tensorflow(data, context))

        if model_type == "onnx":
            findings.extend(self.scan_onnx(data, context))

        # Always check for generic dangerous patterns
        if model_type == "unknown" or not findings:
            # Check all frameworks if type is unknown
            findings.extend(self.scan_torchscript(data, context))
            # TODO: Fix return type mismatch in scan_advanced_torchscript_vulnerabilities
            # findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))
            findings.extend(self.scan_tensorflow(data, context))
            findings.extend(self.scan_onnx(data, context))

        return findings


def detect_jit_script_risks(file_path: str, max_size: int = 500 * 1024 * 1024) -> list["JITScriptFinding"]:
    """Convenience function to scan a file for JIT/Script execution risks.

    Args:
        file_path: Path to the model file to scan
        max_size: Maximum file size to scan (default 500MB)

    Returns:
        List of detected risks
    """
    import os

    if not os.path.exists(file_path):
        return [
            create_jit_finding(
                message=f"File not found: {file_path}",
                severity="WARNING",
                context=file_path,
                pattern=None,
                recommendation="Verify the file path is correct",
                confidence=1.0,
                framework=None,
                code_snippet=None,
                type="error",
                operation=None,
                builtin=None,
                import_=None,
            )
        ]

    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        return [
            create_jit_finding(
                message=f"File too large: {file_size} bytes (max: {max_size})",
                severity="WARNING",
                context=file_path,
                pattern=None,
                recommendation="Use a smaller file for analysis",
                confidence=1.0,
                framework=None,
                code_snippet=None,
                type="error",
                operation=None,
                builtin=None,
                import_=None,
            )
        ]

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
