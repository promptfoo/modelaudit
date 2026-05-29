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
_MAX_SNIPPET_PARSE_TRIM_ATTEMPTS = 8
_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES = 1_000_000
_EMBEDDED_PYTHON_START_MARKERS = (b"def ", b"async def ", b"class ", b"import ", b"from ")
_EMBEDDED_PYTHON_BLOCK_PATTERN = re.compile(rb"def\s+\w+\s*\([^)]*\):[^}]+|class\s+\w+[^}]+")
_EMBEDDED_PYTHON_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])"
    rb"(?:(?:async\s+)?def\s+\w+|class\s+\w+|import\s+[A-Za-z_][\w.]*|from\s+[A-Za-z_][\w.]*\s+import)"
)


def _resolve_alias_aware_high_risk_calls(tree: ast.AST) -> set[tuple[str, str]]:
    """Return high-risk calls reached through shared static resolution."""
    from modelaudit.scanners.archive_member_security import high_risk_python_calls_in_tree

    return {(call.name, call.rule_code) for call in high_risk_python_calls_in_tree(tree)}


def _parse_embedded_python_snippet(code_str: str) -> tuple[ast.AST, int] | None:
    """Parse an extracted Python snippet, trimming trailing binary framing when needed."""
    try:
        return ast.parse(code_str), len(code_str)
    except (SyntaxError, ValueError) as exc:
        initial_error = exc

    lines = code_str.splitlines(keepends=True)
    candidate_lengths: list[int] = []
    null_offset = code_str.find("\x00")
    if null_offset > 0:
        candidate_lengths.append(null_offset)

    candidate_ends: list[int] = []
    if isinstance(initial_error, SyntaxError) and initial_error.lineno is not None:
        candidate_ends.append(max(1, initial_error.lineno - 1))
    candidate_ends.extend(range(len(lines) - 1, max(0, len(lines) - _MAX_SNIPPET_PARSE_TRIM_ATTEMPTS - 1), -1))

    for end in candidate_ends:
        candidate_lengths.append(sum(len(line) for line in lines[:end]))

    seen_lengths: set[int] = set()
    for length in candidate_lengths:
        if length <= 0 or length in seen_lengths:
            continue
        seen_lengths.add(length)
        candidate = code_str[:length]
        if candidate.strip() == "":
            continue
        try:
            return ast.parse(f"{candidate}\n"), length
        except (SyntaxError, ValueError):
            continue
    return None


def _candidate_embedded_python_snippets(
    bounded: bytes,
    *,
    include_full_source: bool = False,
) -> list[tuple[bytes, tuple[int, int]]]:
    candidates: list[tuple[bytes, tuple[int, int]]] = []
    block_spans: list[tuple[int, int]] = []
    if include_full_source:
        candidates.append((bounded, (0, len(bounded))))

    for match in _EMBEDDED_PYTHON_BLOCK_PATTERN.finditer(bounded):
        span = match.span()
        if include_full_source and span[0] == 0:
            continue
        block_spans.append(span)
        candidates.append((match.group(0), span))

    for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(bounded):
        start = match.start()
        if include_full_source and start == 0:
            continue
        if any(block_start <= start < block_end for block_start, block_end in block_spans):
            continue
        candidates.append((bounded[start:], (start, len(bounded))))

    return candidates


def _embedded_python_scan_windows(data: bytes) -> list[bytes]:
    if len(data) <= _EMBEDDED_PYTHON_SCAN_WINDOW_BYTES:
        return [data]
    return [data[:_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES], data[-_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES:]]


def _has_raw_match_outside_parsed_spans(raw_spans: list[tuple[int, int]], parsed_spans: list[tuple[int, int]]) -> bool:
    """Return whether any raw regex hit sits outside AST-validated source."""
    for raw_start, raw_end in raw_spans:
        if not any(parsed_start <= raw_start and raw_end <= parsed_end for parsed_start, parsed_end in parsed_spans):
            return True
    return False


def _decode_utf8_with_byte_offsets(data: bytes) -> tuple[str, list[int]]:
    """Decode UTF-8 like errors='ignore' while mapping decoded character offsets to byte offsets."""
    chars: list[str] = []
    byte_offsets = [0]
    index = 0
    while index < len(data):
        byte = data[index]
        if byte < 0x80:
            chars.append(chr(byte))
            index += 1
            byte_offsets.append(index)
            continue

        if 0xC2 <= byte <= 0xDF:
            length = 2
        elif 0xE0 <= byte <= 0xEF:
            length = 3
        elif 0xF0 <= byte <= 0xF4:
            length = 4
        else:
            index += 1
            continue

        chunk = data[index : index + length]
        if len(chunk) != length or any((continuation & 0xC0) != 0x80 for continuation in chunk[1:]):
            index += 1
            continue
        try:
            chars.append(chunk.decode("utf-8"))
        except UnicodeDecodeError:
            index += 1
            continue
        index += length
        byte_offsets.append(index)

    return "".join(chars), byte_offsets


# Patterns that indicate code execution attempts
_SUBPROCESS_CODE_EXECUTION_DESCRIPTION = "Subprocess execution detected"
_OS_CODE_EXECUTION_DESCRIPTION = "OS command execution detected"
_RUNPY_CODE_EXECUTION_DESCRIPTION = "Dynamic module execution detected"
CODE_EXECUTION_PATTERNS = [
    # Direct execution patterns
    (rb"exec\s*\(", "exec() call detected"),
    (rb"eval\s*\(", "eval() call detected"),
    (rb"compile\s*\(", "compile() call detected"),
    (rb"__import__\s*\(", "__import__() call detected"),
    # Process and dynamic execution patterns
    (
        rb"(?:subprocess\.(?:call|run|Popen|check_call|check_output|getoutput|getstatusoutput)"
        rb"|asyncio\.(?:subprocess\.)?create_subprocess_(?:exec|shell))",
        _SUBPROCESS_CODE_EXECUTION_DESCRIPTION,
    ),
    (rb"os\.(system|popen|exec\w*|spawn\w*|posix_spawnp?|startfile)", _OS_CODE_EXECUTION_DESCRIPTION),
    (rb"runpy\.(?:_run_module_as_main|run_module|run_path)", _RUNPY_CODE_EXECUTION_DESCRIPTION),
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
        bounded = data
        try:
            source = textwrap.dedent(bounded.decode("utf-8"))
            full_tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            return False

        return JITScriptDetector._ast_contains_dangerous_python(full_tree)

    @staticmethod
    def _looks_like_framed_dangerous_python_source(data: bytes) -> bool:
        """Return whether a bounded binary blob has parseable dangerous Python framing."""
        if not any(marker in data for marker in _EMBEDDED_PYTHON_START_MARKERS):
            return False
        for window in _embedded_python_scan_windows(data):
            for candidate, _span in _candidate_embedded_python_snippets(window):
                code_str, _byte_offsets = _decode_utf8_with_byte_offsets(candidate)
                parsed_snippet = _parse_embedded_python_snippet(code_str)
                if parsed_snippet is None:
                    continue
                snippet_tree, _parsed_chars = parsed_snippet
                if JITScriptDetector._ast_contains_dangerous_python(snippet_tree):
                    return True
        return False

    @staticmethod
    def _ast_contains_dangerous_python(tree: ast.AST) -> bool:
        """Return whether parsed Python contains modeled dangerous operations."""
        if _resolve_alias_aware_high_risk_calls(tree):
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
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
                    return True

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
                    "subprocess.call",
                    "subprocess.run",
                    "subprocess.Popen",
                    "subprocess.check_output",
                }:
                    return True
        return False

    @staticmethod
    def _contains_dangerous_import(source: str, dangerous_import: str) -> bool:
        """Return whether source imports the exact dangerous module or one of its submodules."""
        patterns = _DANGEROUS_IMPORT_PATTERNS.get(dangerous_import)
        import_pattern, from_pattern = patterns or _compile_dangerous_import_patterns(dangerous_import)
        return import_pattern.search(source) is not None or from_pattern.search(source) is not None

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
        if b"def " in data or b"class " in data:
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
        matches = _candidate_embedded_python_snippets(bounded, include_full_source=include_full_source)
        bounded_high_risk_calls: set[tuple[str, str]] | None = None
        snippet_high_risk_calls: set[tuple[str, str]] = set()
        parsed_snippet_spans: list[tuple[int, int]] = []
        try:
            bounded_tree = ast.parse(textwrap.dedent(bounded.decode("utf-8")))
            bounded_high_risk_calls = _resolve_alias_aware_high_risk_calls(bounded_tree)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            # Binary model blobs commonly contain non-Python framing bytes; keep
            # raw pattern detection active and fall back to extracted snippets.
            bounded_high_risk_calls = None

        for match, span in matches[:10]:  # Analyze first 10 code snippets
            try:
                code_str, byte_offsets = _decode_utf8_with_byte_offsets(match)

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

                # Try to parse as AST for deeper analysis.
                parsed_snippet = _parse_embedded_python_snippet(code_str)
                if parsed_snippet is not None:
                    tree, parsed_chars = parsed_snippet
                    parsed_byte_length = byte_offsets[parsed_chars]
                    parsed_snippet_spans.append((span[0], min(span[1], span[0] + parsed_byte_length)))
                    snippet_high_risk_calls.update(_resolve_alias_aware_high_risk_calls(tree))
                    ast_findings = self._analyze_ast(tree, framework, context)
                    findings.extend(ast_findings)

            except Exception:
                # Failed to process this code snippet
                continue

        # Check for common code execution patterns in binary
        resolved_high_risk_calls = (bounded_high_risk_calls or set()) | snippet_high_risk_calls
        for pattern, description in CODE_EXECUTION_PATTERNS:
            raw_pattern_spans = [match.span() for match in re.finditer(pattern, bounded)]
            pattern_match = len(raw_pattern_spans) > 0
            if description == _SUBPROCESS_CODE_EXECUTION_DESCRIPTION:
                resolved_subprocess_call = any(code == "S103" for _, code in resolved_high_risk_calls)
                raw_match_only_in_parsed_snippets = bool(
                    parsed_snippet_spans
                ) and not _has_raw_match_outside_parsed_spans(raw_pattern_spans, parsed_snippet_spans)
                if resolved_subprocess_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
            if description == _OS_CODE_EXECUTION_DESCRIPTION:
                resolved_os_process_call = any(code == "S101" for _, code in resolved_high_risk_calls)
                if resolved_os_process_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None:
                    continue
            if description == _RUNPY_CODE_EXECUTION_DESCRIPTION:
                resolved_runpy_call = any(code == "S108" for _, code in resolved_high_risk_calls)
                raw_match_only_in_parsed_snippets = bool(
                    parsed_snippet_spans
                ) and not _has_raw_match_outside_parsed_spans(raw_pattern_spans, parsed_snippet_spans)
                if resolved_runpy_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
            if pattern_match:  # Limit search size
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

        # Scan based on model type
        if model_type in ["pytorch", "torchscript"]:
            findings.extend(self.scan_torchscript(data, context))
            findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))

        if model_type in ["tensorflow", "tf", "keras"]:
            findings.extend(self.scan_tensorflow(data, context))

        if model_type == "onnx":
            findings.extend(self.scan_onnx(data, context))

        if model_type == "pickle" and (b"def " in data or b"class " in data):
            findings.extend(self._extract_and_check_python_code(data, "Generic Python", context))

        # Always check for generic dangerous patterns
        # Only run fallback scanners if model type is truly unknown
        # Don't run fallback on known types (pytorch, tensorflow, onnx) even if they have no findings
        # because that causes false positives (e.g. TorchScript patterns matching ONNX metadata)
        if model_type == "unknown":
            # Check all frameworks if type is unknown
            findings.extend(self.scan_torchscript(data, context))
            findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))
            findings.extend(self.scan_tensorflow(data, context))
            findings.extend(self.scan_onnx(data, context))

        if self._looks_like_dangerous_python_source(data):
            findings.extend(
                self._extract_and_check_python_code(
                    data,
                    "Generic Python",
                    context,
                    include_full_source=True,
                )
            )
        elif self._looks_like_framed_dangerous_python_source(data):
            findings.extend(self._extract_and_check_python_code(data, "Generic Python", context))

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
