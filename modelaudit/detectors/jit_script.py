"""
JIT/Script Code Execution Detection for ML Models
==================================================

Detects potentially dangerous JIT-compiled code and script execution patterns
in TorchScript, TensorFlow SavedFunction, and ONNX models that could lead to
arbitrary code execution.

Part of ModelAudit's critical security validation suite.
"""

import ast
import contextlib
import re
import textwrap
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from modelaudit.models import JITScriptFinding


def create_jit_finding(**kwargs: Any) -> "JITScriptFinding":
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
_BUILTIN_NAMESPACE_PREFIXES = ("__builtin__.", "__builtins__.", "builtins.")
_JIT_DANGEROUS_BUILTIN_CALL_NAMES = frozenset(DANGEROUS_BUILTINS).union(
    f"{prefix}{builtin}" for prefix in _BUILTIN_NAMESPACE_PREFIXES for builtin in DANGEROUS_BUILTINS
)

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


def _compile_dangerous_import_patterns(dangerous_import: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Compile exact import/from-import regexes for one dangerous module name."""
    escaped = re.escape(dangerous_import)
    return (
        re.compile(rf"(?m)^\s*import\s+{escaped}(?:[.\s,]|$)"),
        re.compile(rf"(?m)^\s*from\s+{escaped}(?:[.\s]|$)"),
    )


_DANGEROUS_IMPORT_PATTERNS = {
    dangerous_import: _compile_dangerous_import_patterns(dangerous_import) for dangerous_import in DANGEROUS_IMPORTS
}
_SNIPPET_IMPORT_CONTEXT_LINES = 50


def _extract_nearby_python_prelude_line(line: bytes) -> bytes | None:
    stripped = line.lstrip()
    if stripped.startswith((b"import ", b"from ")):
        return stripped
    import_fragment = re.search(rb"(?a)(?:^|[^A-Za-z0-9_])((?:from|import)\s+[^\r\n]+)$", stripped)
    if import_fragment is not None:
        return import_fragment.group(1)
    if re.match(rb"(?a)^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
        return stripped
    return None


def _prepend_nearby_imports(bounded: bytes, match: re.Match[bytes]) -> bytes:
    """Carry nearby module-scope aliases into extracted functions without parsing the whole blob."""
    prelude_lines = [
        prelude_line
        for line in bounded[: match.start()].splitlines()[-_SNIPPET_IMPORT_CONTEXT_LINES:]
        if (prelude_line := _extract_nearby_python_prelude_line(line)) is not None
    ]
    if not prelude_lines:
        return match.group(0)
    return b"\n".join([*prelude_lines, match.group(0)])


def _resolve_alias_aware_dangerous_builtins(tree: ast.AST) -> set[str]:
    """Return dangerous builtins reached through shared bounded source resolution."""
    from modelaudit.scanners.archive_member_security import statically_resolved_python_call_names_in_tree

    dangerous_builtins: set[str] = set()
    for call_name in statically_resolved_python_call_names_in_tree(tree, _JIT_DANGEROUS_BUILTIN_CALL_NAMES):
        if call_name in DANGEROUS_BUILTINS:
            dangerous_builtins.add(call_name)
            continue
        for prefix in _BUILTIN_NAMESPACE_PREFIXES:
            if call_name.startswith(prefix):
                builtin_name = call_name.removeprefix(prefix)
                if builtin_name in DANGEROUS_BUILTINS:
                    dangerous_builtins.add(builtin_name)
                break
    return dangerous_builtins


def _resolve_alias_aware_execution_calls(
    tree: ast.AST,
) -> tuple[set[str], set[str], set[str], set[str], set[str], set[str]]:
    """Return modeled process and dynamic-module execution calls reached through static resolution."""
    from modelaudit.scanners.archive_member_security import high_risk_python_calls_in_tree

    calls = high_risk_python_calls_in_tree(tree)
    return (
        {call.name for call in calls if call.rule_code == "S101"},
        {call.name for call in calls if call.rule_code == "S103"},
        {call.name for call in calls if call.rule_code == "S111"},
        {call.name for call in calls if call.rule_code == "S108"},
        {call.name for call in calls if call.rule_code == "S109"},
        {call.name for call in calls if call.rule_code == "S110"},
    )


# Patterns that indicate code execution attempts
_SUBPROCESS_CODE_EXECUTION_DESCRIPTION = "Subprocess execution detected"
_OS_CODE_EXECUTION_DESCRIPTION = "OS command execution detected"
_PTY_CODE_EXECUTION_DESCRIPTION = "Pseudo-terminal process execution detected"
_RUNPY_CODE_EXECUTION_DESCRIPTION = "Dynamic module execution detected"
_WEBBROWSER_LAUNCH_DESCRIPTION = "Web browser launch detected"
_CTYPES_NATIVE_LOADING_DESCRIPTION = "Native library loading detected"
CODE_EXECUTION_PATTERNS = [
    # Direct execution patterns
    (rb"exec\s*\(", "exec() call detected"),
    (rb"eval\s*\(", "eval() call detected"),
    (rb"compile\s*\(", "compile() call detected"),
    (rb"__import__\s*\(", "__import__() call detected"),
    # Subprocess patterns
    (
        rb"subprocess\.(call|run|Popen|check_call|check_output|getoutput|getstatusoutput)",
        _SUBPROCESS_CODE_EXECUTION_DESCRIPTION,
    ),
    (rb"asyncio\.create_subprocess_(?:exec|shell)", _SUBPROCESS_CODE_EXECUTION_DESCRIPTION),
    (rb"os\.(system|popen|exec\w*|spawn\w*|posix_spawnp?|startfile)", _OS_CODE_EXECUTION_DESCRIPTION),
    (rb"pty\.spawn", _PTY_CODE_EXECUTION_DESCRIPTION),
    (rb"runpy\.(?:run_module|run_path)", _RUNPY_CODE_EXECUTION_DESCRIPTION),
    (rb"webbrowser\.open(?:_new(?:_tab)?)?\s*\(", _WEBBROWSER_LAUNCH_DESCRIPTION),
    (
        rb"(?:_ctypes\.dlopen\s*\(|ctypes\.(?:(?:CDLL|OleDLL|PyDLL|WinDLL)\s*\(|"
        rb"LibraryLoader\s*\([^)]*\)\.LoadLibrary\s*\(|"
        rb"(?:cdll|oledll|pydll|windll)\.(?:LoadLibrary\s*\(|(?!LoadLibrary\b)[A-Za-z_]\w*\b)))",
        _CTYPES_NATIVE_LOADING_DESCRIPTION,
    ),
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
_BUILTIN_CODE_EXECUTION_PATTERN_NAMES = {
    "exec() call detected": "exec",
    "eval() call detected": "eval",
    "compile() call detected": "compile",
    "__import__() call detected": "__import__",
    "File write operation detected": "open",
}


class JITScriptDetector:
    """Detects dangerous JIT/Script code execution patterns in ML models."""

    def __init__(self, config: dict[str, Any] | None = None):
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

    @staticmethod
    def _looks_like_dangerous_python_source(data: bytes) -> bool:
        """Return whether marker-free bytes look like dangerous embedded Python source."""
        try:
            source = textwrap.dedent(data.decode("utf-8"))
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            return False

        return JITScriptDetector._ast_contains_dangerous_python(tree)

    @staticmethod
    def _ast_contains_dangerous_python(tree: ast.AST) -> bool:
        """Return whether parsed Python contains modeled dangerous operations."""
        if _resolve_alias_aware_dangerous_builtins(tree):
            return True
        (
            os_process_calls,
            subprocess_calls,
            pty_process_calls,
            runpy_execution_calls,
            webbrowser_launch_calls,
            ctypes_native_loading_calls,
        ) = _resolve_alias_aware_execution_calls(tree)
        if (
            os_process_calls
            or subprocess_calls
            or pty_process_calls
            or runpy_execution_calls
            or webbrowser_launch_calls
            or ctypes_native_loading_calls
        ):
            return True

        def is_dangerous_import(module_name: str) -> bool:
            return any(
                module_name == dangerous_import or module_name.startswith(f"{dangerous_import}.")
                for dangerous_import in DANGEROUS_IMPORTS
            )

        def dotted_name(node: ast.AST) -> str | None:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                parent = dotted_name(node.value)
                return f"{parent}.{node.attr}" if parent else None
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(is_dangerous_import(alias.name) for alias in node.names):
                    return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and is_dangerous_import(node.module):
                    return True
            elif isinstance(node, ast.Call):
                operation = dotted_name(node.func)
                if operation is None:
                    continue
                if operation in {
                    "socket.socket",
                    "socket.create_connection",
                    "urllib.urlopen",
                    "urllib.request.urlopen",
                    "requests.get",
                    "requests.post",
                    "requests.put",
                    "requests.delete",
                }:
                    return True
        return False

    @staticmethod
    def _contains_dangerous_import(source: str, dangerous_import: str) -> bool:
        """Return whether source imports the exact dangerous module or one of its submodules."""
        patterns = _DANGEROUS_IMPORT_PATTERNS.get(dangerous_import)
        import_pattern, from_pattern = patterns or _compile_dangerous_import_patterns(dangerous_import)
        return import_pattern.search(source) is not None or from_pattern.search(source) is not None

    def scan_torchscript(
        self, data: bytes, context: str = "", *, scan_embedded_python: bool = True
    ) -> list["JITScriptFinding"]:
        """Scan TorchScript model data for dangerous operations.

        Args:
            data: Binary model data
            context: Context string for reporting
            scan_embedded_python: Whether to inspect embedded Python snippets in this pass.

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
        if self.strict_mode and (b"TorchScript" in data or b"torch.jit" in data):
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

        # Look for embedded Python code even when framework markers are absent.
        # Scanner callers can hand us raw code-bearing blobs, and an attacker can
        # remove marker strings without removing the executable payload.
        if scan_embedded_python and (b"def " in data or b"class " in data):
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

    def scan_tensorflow(
        self, data: bytes, context: str = "", *, scan_embedded_python: bool = True
    ) -> list["JITScriptFinding"]:
        """Scan TensorFlow SavedModel for dangerous operations.

        Args:
            data: Binary model data or protobuf
            context: Context string for reporting
            scan_embedded_python: Whether to inspect embedded Python snippets in this pass.

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
            if scan_embedded_python and (b"python_function" in data or b"function_spec" in data):
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
        python_op_pattern = re.compile(
            rb"(?<![A-Za-z0-9_])(?:PyFunc(?:Stateless)?|EagerPyFunc|PythonOp|PyOp)(?:V[0-9]+)?(?![A-Za-z0-9_])",
            re.IGNORECASE,
        )
        if python_op_pattern.search(data):
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

    def _extract_and_check_python_code(
        self,
        data: bytes,
        framework: str,
        context: str,
        *,
        include_full_source: bool = False,
    ) -> list["JITScriptFinding"]:
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

        bounded = data if include_full_source else data[:1000000]
        python_code_pattern = rb"def\s+\w+\s*\([^)]*\):[^}]+|class\s+\w+[^}]+"
        matches = (
            [bounded]
            if include_full_source
            else [_prepend_nearby_imports(bounded, match) for match in re.finditer(python_code_pattern, bounded)]
        )
        bounded_dangerous_builtins: set[str] | None = None
        bounded_os_process_calls: set[str] | None = None
        bounded_subprocess_calls: set[str] | None = None
        bounded_pty_process_calls: set[str] | None = None
        bounded_runpy_execution_calls: set[str] | None = None
        bounded_webbrowser_launch_calls: set[str] | None = None
        bounded_ctypes_native_loading_calls: set[str] | None = None
        snippet_os_process_calls: set[str] = set()
        snippet_subprocess_calls: set[str] = set()
        snippet_pty_process_calls: set[str] = set()
        snippet_runpy_execution_calls: set[str] = set()
        snippet_webbrowser_launch_calls: set[str] = set()
        snippet_ctypes_native_loading_calls: set[str] = set()
        saw_snippet_ast = False
        try:
            bounded_tree = ast.parse(textwrap.dedent(bounded.decode("utf-8")))
            bounded_dangerous_builtins = _resolve_alias_aware_dangerous_builtins(bounded_tree)
            (
                bounded_os_process_calls,
                bounded_subprocess_calls,
                bounded_pty_process_calls,
                bounded_runpy_execution_calls,
                bounded_webbrowser_launch_calls,
                bounded_ctypes_native_loading_calls,
            ) = _resolve_alias_aware_execution_calls(bounded_tree)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            pass

        for match in matches[:10]:  # Analyze first 10 code snippets
            try:
                code_str = textwrap.dedent(match.decode("utf-8", errors="ignore"))
                tree: ast.AST | None = None
                with contextlib.suppress(SyntaxError):
                    tree = ast.parse(code_str)

                # Check for dangerous imports
                for dangerous_import in DANGEROUS_IMPORTS:
                    if self._contains_dangerous_import(code_str, dangerous_import):
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
                dangerous_builtins = (
                    _resolve_alias_aware_dangerous_builtins(tree)
                    if tree is not None
                    else {builtin for builtin in DANGEROUS_BUILTINS if builtin in code_str}
                )
                for builtin in sorted(dangerous_builtins):
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
                if tree is not None:
                    saw_snippet_ast = True
                    (
                        snippet_os_calls,
                        snippet_subprocess,
                        snippet_pty_calls,
                        snippet_runpy_calls,
                        snippet_webbrowser_calls,
                        snippet_ctypes_calls,
                    ) = _resolve_alias_aware_execution_calls(tree)
                    snippet_os_process_calls.update(snippet_os_calls)
                    snippet_subprocess_calls.update(snippet_subprocess)
                    snippet_pty_process_calls.update(snippet_pty_calls)
                    snippet_runpy_execution_calls.update(snippet_runpy_calls)
                    snippet_webbrowser_launch_calls.update(snippet_webbrowser_calls)
                    snippet_ctypes_native_loading_calls.update(snippet_ctypes_calls)
                    ast_findings = self._analyze_ast(tree, framework, context)
                    findings.extend(ast_findings)

            except Exception:
                # Failed to process this code snippet
                continue

        if saw_snippet_ast:
            if bounded_os_process_calls is None:
                bounded_os_process_calls = snippet_os_process_calls
            if bounded_subprocess_calls is None:
                bounded_subprocess_calls = snippet_subprocess_calls
            if bounded_pty_process_calls is None:
                bounded_pty_process_calls = snippet_pty_process_calls
            if bounded_runpy_execution_calls is None:
                bounded_runpy_execution_calls = snippet_runpy_execution_calls
            if bounded_webbrowser_launch_calls is None:
                bounded_webbrowser_launch_calls = snippet_webbrowser_launch_calls
            if bounded_ctypes_native_loading_calls is None:
                bounded_ctypes_native_loading_calls = snippet_ctypes_native_loading_calls

        def add_code_execution_pattern_finding(description: str) -> None:
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

        # Check for common code execution patterns in binary
        for pattern, description in CODE_EXECUTION_PATTERNS:
            builtin_name = _BUILTIN_CODE_EXECUTION_PATTERN_NAMES.get(description)
            if (
                builtin_name is not None
                and bounded_dangerous_builtins is not None
                and builtin_name not in bounded_dangerous_builtins
            ):
                continue
            if (
                description == _SUBPROCESS_CODE_EXECUTION_DESCRIPTION
                and bounded_subprocess_calls is not None
                and not bounded_subprocess_calls
            ):
                continue
            if (
                description == _OS_CODE_EXECUTION_DESCRIPTION
                and bounded_os_process_calls is not None
                and not bounded_os_process_calls
            ):
                continue
            if (
                description == _PTY_CODE_EXECUTION_DESCRIPTION
                and bounded_pty_process_calls is not None
                and not bounded_pty_process_calls
            ):
                continue
            if (
                description == _RUNPY_CODE_EXECUTION_DESCRIPTION
                and bounded_runpy_execution_calls is not None
                and not bounded_runpy_execution_calls
            ):
                continue
            if (
                description == _WEBBROWSER_LAUNCH_DESCRIPTION
                and bounded_webbrowser_launch_calls is not None
                and not bounded_webbrowser_launch_calls
            ):
                continue
            if (
                description == _CTYPES_NATIVE_LOADING_DESCRIPTION
                and bounded_ctypes_native_loading_calls is not None
                and not bounded_ctypes_native_loading_calls
            ):
                continue
            if re.search(pattern, bounded):  # Limit search size
                add_code_execution_pattern_finding(description)

        reported_patterns = {finding.pattern for finding in findings if finding.type == "code_execution_pattern"}
        for calls, description in (
            (bounded_os_process_calls, _OS_CODE_EXECUTION_DESCRIPTION),
            (bounded_subprocess_calls, _SUBPROCESS_CODE_EXECUTION_DESCRIPTION),
            (bounded_pty_process_calls, _PTY_CODE_EXECUTION_DESCRIPTION),
            (bounded_runpy_execution_calls, _RUNPY_CODE_EXECUTION_DESCRIPTION),
            (bounded_webbrowser_launch_calls, _WEBBROWSER_LAUNCH_DESCRIPTION),
            (bounded_ctypes_native_loading_calls, _CTYPES_NATIVE_LOADING_DESCRIPTION),
        ):
            if calls and description not in reported_patterns:
                add_code_execution_pattern_finding(description)
                reported_patterns.add(description)

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
                self.generic_visit(node)

        visitor = DangerousNodeVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)

        reported_builtins = {
            finding.builtin
            for finding in findings
            if finding.type == "ast_dangerous_call" and finding.builtin is not None
        }
        for dangerous_builtin in sorted(_resolve_alias_aware_dangerous_builtins(tree) - reported_builtins):
            findings.append(
                create_jit_finding(
                    message=f"AST analysis: Dangerous function call '{dangerous_builtin}'",
                    severity="CRITICAL",
                    context=context,
                    pattern=None,
                    recommendation="Remove dangerous function calls to prevent code execution",
                    confidence=0.9,
                    framework=framework,
                    code_snippet=None,
                    type="ast_dangerous_call",
                    operation=None,
                    builtin=dangerous_builtin,
                    import_=None,
                )
            )

        return findings

    def scan_advanced_torchscript_vulnerabilities(self, data: bytes, context: str = "") -> list["JITScriptFinding"]:
        """Advanced TorchScript vulnerability scanning for sophisticated attacks"""
        findings: list[JITScriptFinding] = []

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
                    create_jit_finding(
                        type="torchscript_serialization_injection",
                        severity="CRITICAL",
                        pattern=pattern,
                        message=f"TorchScript serialization vulnerability: {description}",
                        context=context,
                        recommendation="Use safe serialization methods and validate all model sources",
                        confidence=0.9,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                        builtin=None,
                        import_=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_module_manipulation",
                        severity="HIGH",
                        pattern=pattern,
                        message=f"TorchScript module manipulation: {description}",
                        context=context,
                        recommendation="Review model architecture for unauthorized module modifications",
                        confidence=0.8,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                        builtin=None,
                        import_=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_graph_manipulation",
                        severity="HIGH",
                        message=f"TorchScript graph manipulation: {description}",
                        pattern=pattern,
                        context=context,
                        recommendation="Validate model graph integrity and compilation process",
                        confidence=0.8,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_bytecode_injection",
                        severity="CRITICAL",
                        message=f"TorchScript bytecode injection: {description}",
                        pattern=pattern,
                        context=context,
                        recommendation="This indicates potential code injection at the bytecode level",
                        confidence=0.9,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_backend_exploitation",
                        severity="HIGH",
                        message=f"TorchScript backend exploitation: {description}",
                        pattern=pattern,
                        context=context,
                        recommendation="Review backend operations for security vulnerabilities",
                        confidence=0.8,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_hook_injection",
                        severity="CRITICAL",
                        message=f"TorchScript hook injection: {description}",
                        pattern=pattern,
                        context=context,
                        recommendation="Hooks can execute arbitrary code - review all hook registrations",
                        confidence=0.9,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_obfuscation",
                        severity="WARNING",
                        message=f"Obfuscated TorchScript code: {description}",
                        pattern=pattern,
                        context=context,
                        recommendation="Obfuscated code may hide malicious functionality",
                        confidence=0.7,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                    )
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
                    create_jit_finding(
                        type="torchscript_version_vulnerability",
                        severity="CRITICAL",
                        message=f"Version-specific vulnerability: {description}",
                        pattern=pattern,
                        context=context,
                        recommendation="Update PyTorch version and review loading patterns",
                        confidence=0.9,
                        framework="TorchScript",
                        code_snippet=None,
                        operation=None,
                    )
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

        dangerous_python_source = self._looks_like_dangerous_python_source(data)

        # Scan based on model type
        if model_type in ["pytorch", "torchscript"]:
            findings.extend(self.scan_torchscript(data, context, scan_embedded_python=not dangerous_python_source))
            findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))

        if model_type in ["tensorflow", "tf", "keras"]:
            findings.extend(self.scan_tensorflow(data, context, scan_embedded_python=not dangerous_python_source))

        if model_type == "onnx":
            findings.extend(self.scan_onnx(data, context))

        if model_type == "pickle" and not dangerous_python_source and (b"def " in data or b"class " in data):
            findings.extend(self._extract_and_check_python_code(data, "Generic Python", context))

        # Always check for generic dangerous patterns
        # Only run fallback scanners if model type is truly unknown
        # Don't run fallback on known types (pytorch, tensorflow, onnx) even if they have no findings
        # because that causes false positives (e.g. TorchScript patterns matching ONNX metadata)
        if model_type == "unknown":
            # Check all frameworks if type is unknown
            findings.extend(self.scan_torchscript(data, context, scan_embedded_python=not dangerous_python_source))
            findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))
            findings.extend(self.scan_tensorflow(data, context, scan_embedded_python=not dangerous_python_source))
            findings.extend(self.scan_onnx(data, context))

        if dangerous_python_source:
            findings.extend(
                self._extract_and_check_python_code(
                    data,
                    "Generic Python",
                    context,
                    include_full_source=True,
                )
            )

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
                severity="INFO",
                context=file_path,
                pattern=None,
                recommendation="Consider increasing the max_size parameter for large model files",
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
