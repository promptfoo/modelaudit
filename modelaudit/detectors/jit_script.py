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
from bisect import bisect_left, bisect_right
from collections.abc import Iterator
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
_MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS = 10
_MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS = 16
_MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES = 16_384
_MAX_PRIORITY_ALIAS_USAGE_LINES = 8
# Each indirect-alias probe re-parses and re-resolves the whole (<=16 KiB) snippet,
# so an unbounded loop is quadratic in the assignment count. Cap the expensive
# probes; the cheap direct-reference fast path still runs for every assignment.
_MAX_PRIORITY_ASSIGNMENT_PROBES = 48
# Bound nested ``:``-header recursion when extracting an embedded statement so a
# crafted deeply-indented blob cannot exhaust the interpreter stack.
_MAX_BODY_STATEMENT_NESTING = 100
_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES = 1_000_000
_MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES = 16_384
_EMBEDDED_PYTHON_START_MARKERS = (b"def ", b"async def ", b"class ", b"import ", b"from ")
_PRIORITY_EMBEDDED_PYTHON_MODULES = tuple(
    sorted(
        {marker.lower() for marker in (*DANGEROUS_IMPORTS, "asyncio", "ctypes", "runpy", "subprocess", "webbrowser")},
        key=len,
        reverse=True,
    )
)
_PRIORITY_EMBEDDED_PYTHON_MODULE_PATTERN = b"|".join(
    re.escape(marker.encode("utf-8")) for marker in _PRIORITY_EMBEDDED_PYTHON_MODULES
)
_PRIORITY_WILDCARD_IMPORT_ALIASES = {
    "asyncio": ("create_subprocess_exec", "create_subprocess_shell"),
    "ctypes": ("CDLL", "LoadLibrary", "LibraryLoader", "cdll", "pydll", "windll"),
    "os": ("popen", "spawnl", "spawnle", "spawnv", "spawnve", "system"),
    "runpy": ("_run_module_as_main", "run_module", "run_path"),
    "subprocess": ("Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput", "run"),
    "webbrowser": ("get", "open", "open_new", "open_new_tab"),
}
_PRIORITY_EMBEDDED_PYTHON_IMPORT_PATTERN = re.compile(
    rb"(?m)^\s*(?:"
    rb"import\s+(?:[a-z_][\w.]*(?:\s+as\s+[a-z_]\w*)?\s*,(?:\s|\\\r?\n)*)*(?:"
    + _PRIORITY_EMBEDDED_PYTHON_MODULE_PATTERN
    + rb")(?:[.\s,]|$)|"
    rb"from\s+(?:" + _PRIORITY_EMBEDDED_PYTHON_MODULE_PATTERN + rb")(?:[.\s]|\\\r?\n|$)"
    rb")"
)
_EMBEDDED_PYTHON_CONTEXT_ASSIGNMENT_LHS_PATTERN = rb"(?:[A-Za-z_]\w*(?:\s*:[^=\n#]+)?|[\(\[][A-Za-z_][^=\n#]*[\)\]])"
_EMBEDDED_PYTHON_BLOCK_PATTERN = re.compile(rb"def\s+\w+\s*\([^)]*\):[^}\x00]+|class\s+\w+[^}\x00]+")
_EMBEDDED_PYTHON_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])"
    rb"(?:(?:async\s+)?def\s+\w+|class\s+\w+|import\s+[A-Za-z_][\w.]*|"
    rb"from\s+[A-Za-z_][\w.]*(?:\s|\\\r?\n)+import)"
)
_EMBEDDED_PYTHON_CONTEXT_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])(?:if\s+True\s*:|import\s+[A-Za-z_][\w.]*|from\s+[A-Za-z_][\w.]*|"
    + _EMBEDDED_PYTHON_CONTEXT_ASSIGNMENT_LHS_PATTERN
    + rb"\s*=)"
)
_EMBEDDED_PYTHON_COMPOUND_CONTEXT_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])if\s+(?:True|1)\s*:\s*(?:import|from)\s+"
)
_COMPOUND_HEADER_MATCH_PATTERN = re.compile(
    rb"\b(?:async\s+def|if|elif|else|for|while|try|except|finally|with|class|def)\b"
)
_EmbeddedPythonCandidate = tuple[bytes, tuple[int, int], tuple[tuple[int, int], ...]]


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
) -> list[_EmbeddedPythonCandidate]:
    candidates: list[_EmbeddedPythonCandidate] = []
    block_spans: list[tuple[int, int]] = []
    start_offsets = [match.start() for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(bounded)]
    priority_starts: set[int] = set()
    for priority_offset in _priority_import_offsets(bounded):
        insertion_index = bisect_right(start_offsets, priority_offset)
        if insertion_index == 0:
            continue
        priority_starts.add(start_offsets[insertion_index - 1])
        if insertion_index >= 2:
            priority_starts.add(start_offsets[insertion_index - 2])

    if include_full_source:
        span = (0, len(bounded))
        candidates.append((bounded, span, (span,)))

    for match in _EMBEDDED_PYTHON_BLOCK_PATTERN.finditer(bounded):
        span = match.span()
        if include_full_source and span[0] == 0:
            continue
        block_spans.append(span)
        candidates.append((match.group(0), span, (span,)))

    for start in start_offsets:
        if include_full_source and start == 0:
            continue
        if any(block_start < start < block_end for block_start, block_end in block_spans):
            continue
        if any(block_start == start for block_start, _block_end in block_spans) and start not in priority_starts:
            continue
        candidate_start = _candidate_start_with_enclosing_header(bounded, start)
        span = (candidate_start, len(bounded))
        candidates.append((bounded[candidate_start:], span, (span,)))

    return candidates


def _priority_import_offsets(bounded: bytes) -> list[int]:
    lowered = bounded.lower()
    return [
        match.start()
        for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(lowered)
        if _PRIORITY_EMBEDDED_PYTHON_IMPORT_PATTERN.match(lowered[match.start() :]) is not None
    ]


def _span_contains_priority_offset(span: tuple[int, int], priority_offsets: list[int]) -> bool:
    index = bisect_left(priority_offsets, span[0])
    return index < len(priority_offsets) and priority_offsets[index] < span[1]


def _bounded_priority_embedded_python_candidate(
    candidate: bytes,
    span: tuple[int, int],
    priority_offsets: list[int],
) -> _EmbeddedPythonCandidate:
    index = bisect_left(priority_offsets, span[0])
    if index >= len(priority_offsets) or priority_offsets[index] >= span[1]:
        return candidate, span, (span,)
    fallback_candidate: _EmbeddedPythonCandidate | None = None
    for priority_offset in priority_offsets[index:]:
        if priority_offset >= span[1]:
            break
        (
            compact_candidate,
            compact_span,
            compact_real_ranges,
            has_usage_lines,
        ) = _bounded_priority_embedded_python_candidate_at_offset(candidate, span, priority_offset - span[0])
        if has_usage_lines:
            return compact_candidate, compact_span, compact_real_ranges
        if fallback_candidate is None:
            fallback_candidate = (compact_candidate, compact_span, compact_real_ranges)
    return fallback_candidate or (candidate, span, (span,))


def _bounded_priority_embedded_python_candidate_at_offset(
    candidate: bytes,
    span: tuple[int, int],
    priority_relative_offset: int,
) -> tuple[bytes, tuple[int, int], tuple[tuple[int, int], ...], bool]:
    if priority_relative_offset >= _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        line_start = candidate.rfind(b"\n", 0, priority_relative_offset) + 1
    else:
        line_start = 0
    bounded_end = min(len(candidate), line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES)
    segment_ranges: list[tuple[int, int]] = []

    def add_segment(start: int, end: int) -> None:
        segment = (start, end)
        if end > start and segment not in segment_ranges:
            segment_ranges.append(segment)

    block_header_end = candidate.find(b"\n")
    if (
        block_header_end != -1
        and line_start > block_header_end
        and candidate[:block_header_end].lstrip().startswith((b"def ", b"async def ", b"class "))
    ):
        add_segment(0, block_header_end + 1)
    for header_start, header_end in _enclosing_compound_header_segments(candidate, line_start):
        add_segment(header_start, header_end)
    add_segment(line_start, bounded_end)

    aliases = _priority_import_aliases(_compact_candidate_segments(candidate, segment_ranges))
    usage_lines = _priority_alias_usage_lines(candidate, aliases, bounded_end) if aliases else []
    for usage_line in usage_lines:
        add_segment(*usage_line)

    tail_start = max(bounded_end, len(candidate) - _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES)
    tail_start = candidate.rfind(b"\n", 0, tail_start) + 1
    if bounded_end < tail_start < len(candidate):
        add_segment(tail_start, len(candidate))

    merged_ranges = _merge_candidate_segment_ranges(segment_ranges)
    compact_candidate = _compact_candidate_segments(candidate, merged_ranges)
    if not merged_ranges:
        return compact_candidate, span, (span,), bool(usage_lines)

    span_start = span[0] + merged_ranges[0][0]
    span_end = span[0] + max(end for _start, end in merged_ranges)
    real_ranges = tuple((span[0] + start, span[0] + end) for start, end in merged_ranges)
    return compact_candidate, (span_start, span_end), real_ranges, bool(usage_lines)


def _is_priority_module_name(module_name: str) -> bool:
    module_name = module_name.lower()
    return any(
        module_name == priority_module or module_name.startswith(f"{priority_module}.")
        for priority_module in _PRIORITY_EMBEDDED_PYTHON_MODULES
    )


def _priority_import_aliases(candidate: bytes) -> frozenset[bytes]:
    try:
        source, _byte_offsets = _decode_utf8_with_byte_offsets(candidate)
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return frozenset()

    aliases: set[bytes] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if _is_priority_module_name(alias.name):
                    root_name = alias.name.split(".", maxsplit=1)[0]
                    aliases.add((alias.asname or root_name).encode("utf-8"))
        elif isinstance(statement, ast.ImportFrom) and statement.module is not None:
            root_name = statement.module.split(".", maxsplit=1)[0]
            if _is_priority_module_name(statement.module):
                for alias in statement.names:
                    if alias.name == "*":
                        aliases.update(
                            name.encode("utf-8") for name in _PRIORITY_WILDCARD_IMPORT_ALIASES.get(root_name, ())
                        )
                    else:
                        aliases.add((alias.asname or alias.name).encode("utf-8"))
    aliases.update(_priority_assignment_aliases(source, tree, {alias.decode("utf-8") for alias in aliases}))
    return frozenset(aliases)


def _priority_assignment_aliases(source: str, tree: ast.AST, priority_aliases: set[str]) -> set[bytes]:
    aliases: set[bytes] = set()
    discovered_aliases = set(priority_aliases)
    expensive_probes = 0
    for target, value in _assignment_targets_and_values_in_tree(tree):
        if _expression_is_priority_alias_reference(value, discovered_aliases):
            aliases.add(target.encode("utf-8"))
            discovered_aliases.add(target)
            continue
        if expensive_probes >= _MAX_PRIORITY_ASSIGNMENT_PROBES:
            continue
        expensive_probes += 1
        probe = f"{source}\n" + "\n".join(_priority_assignment_probe_calls(target))
        try:
            probe_tree = ast.parse(probe)
        except (SyntaxError, ValueError):
            continue
        if _resolve_alias_aware_high_risk_calls(probe_tree):
            aliases.add(target.encode("utf-8"))
            discovered_aliases.add(target)
    return aliases


def _assignment_targets_and_values_in_tree(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    targets_and_values: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                targets_and_values.extend((name, node.value) for name in _assignment_target_names(target))
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            targets_and_values.extend((name, node.value) for name in _assignment_target_names(node.target))
    return targets_and_values


def _expression_is_priority_alias_reference(node: ast.AST, aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases
    if isinstance(node, ast.Attribute):
        return _expression_is_priority_alias_reference(node.value, aliases)
    if isinstance(node, ast.Subscript):
        return _expression_is_priority_alias_reference(node.value, aliases)
    if isinstance(node, ast.Call):
        call_name = _simple_reference_name(node.func)
        if call_name in {"getattr", "builtins.getattr"} and len(node.args) >= 2 and not node.keywords:
            return _expression_is_priority_alias_reference(node.args[0], aliases)
    return False


def _simple_reference_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _simple_reference_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def _priority_assignment_probe_calls(target: str) -> list[str]:
    return [
        f"{target}()",
        f"{target}.run_path('payload.py')",
        f"{target}.run_module('payload')",
        f"{target}._run_module_as_main('payload')",
        f"{target}.system('id')",
        f"{target}.popen('id')",
        f"{target}.run(['id'])",
        f"{target}.Popen(['id'])",
        f"{target}.call(['id'])",
        f"{target}.check_call(['id'])",
        f"{target}.check_output(['id'])",
        f"{target}.getoutput('id')",
        f"{target}.getstatusoutput('id')",
        f"{target}.open('https://example.invalid')",
        f"{target}.open_new('https://example.invalid')",
        f"{target}.open_new_tab('https://example.invalid')",
        f"{target}.CDLL('payload')",
        f"{target}.LoadLibrary('payload')",
        f"{target}.__getitem__('payload')",
    ]


def _priority_alias_usage_lines(
    candidate: bytes, aliases: frozenset[bytes], search_start: int
) -> list[tuple[int, int]]:
    usage_lines: list[tuple[int, int]] = []
    pending_shadow_lines: dict[bytes, tuple[int, int]] = {}
    line_start = search_start
    multiline_quote: bytes | None = _multiline_string_state_after_line(candidate[:search_start], None)
    while line_start < len(candidate):
        line_end = candidate.find(b"\n", line_start)
        if line_end == -1:
            line_end = len(candidate)
        else:
            line_end += 1
        line = candidate[line_start:line_end]
        if multiline_quote is not None:
            multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
            line_start = line_end
            continue
        code_line = _python_structural_line_bytes(line)
        shadowed_aliases = _line_shadowed_priority_aliases(code_line, aliases)
        if shadowed_aliases:
            shadow_line = (
                line_start,
                min(
                    _priority_alias_shadow_segment_end(candidate, line, line_end),
                    line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES,
                ),
            )
            for alias in shadowed_aliases:
                pending_shadow_lines[alias] = shadow_line
        if used_aliases := _line_used_priority_aliases(code_line, aliases):
            live_aliases = _line_live_priority_aliases(code_line, aliases)
            active_used_aliases = (used_aliases - shadowed_aliases) | live_aliases
            if not active_used_aliases:
                multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                line_start = line_end
                continue
            for shadow_line in sorted(
                {shadow_line for alias, shadow_line in pending_shadow_lines.items() if alias in used_aliases}
            ):
                if shadow_line not in usage_lines:
                    usage_lines.append(shadow_line)
            usage_line = (line_start, min(line_end, line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES))
            if usage_line not in usage_lines:
                usage_lines.append(usage_line)
            called_aliases = _line_called_priority_aliases(code_line, aliases)
            if (called_aliases & active_used_aliases) or len(usage_lines) >= _MAX_PRIORITY_ALIAS_USAGE_LINES:
                return usage_lines
        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
        line_start = line_end
    return usage_lines


def _priority_alias_shadow_segment_end(candidate: bytes, line: bytes, line_end: int) -> int:
    structural_line = _python_structural_line_bytes(line)
    if not structural_line.rstrip().endswith(b":"):
        return line_end
    header_indent = _line_indent_width(line)
    segment_end = line_end
    body_seen = False
    next_line_start = line_end
    while next_line_start < len(candidate):
        next_line_end = candidate.find(b"\n", next_line_start)
        if next_line_end == -1:
            next_line_end = len(candidate)
        else:
            next_line_end += 1
        next_line = candidate[next_line_start:next_line_end]
        next_structural_line = _python_structural_line_bytes(next_line)
        next_stripped = next_structural_line.strip()
        next_indent = _line_indent_width(next_line)
        if next_stripped and next_indent <= header_indent:
            break
        segment_end = next_line_end
        if next_stripped:
            body_seen = True
        next_line_start = next_line_end
    return segment_end if body_seen else line_end


def _line_used_priority_aliases(code_line: bytes, aliases: frozenset[bytes]) -> frozenset[bytes]:
    return frozenset(
        alias
        for alias in aliases
        if re.search(rb"(?<![A-Za-z0-9_])" + re.escape(alias) + rb"\s*(?:\.|\()", code_line)
        or re.search(
            rb"(?<![A-Za-z0-9_.])(?:builtins\.)?getattr\s*\(\s*" + re.escape(alias) + rb"\s*,",
            code_line,
        )
    )


def _line_called_priority_aliases(code_line: bytes, aliases: frozenset[bytes]) -> frozenset[bytes]:
    return frozenset(
        alias
        for alias in aliases
        if re.search(rb"(?<![A-Za-z0-9_])" + re.escape(alias) + rb"\s*(?:\(|\.[A-Za-z_]\w*\s*\()", code_line)
        or re.search(
            rb"(?<![A-Za-z0-9_.])(?:builtins\.)?getattr\s*\(\s*"
            + re.escape(alias)
            + rb"\s*,\s*['\"][A-Za-z_]\w*['\"]\s*\)\s*\(",
            code_line,
        )
    )


def _line_live_priority_aliases(code_line: bytes, aliases: frozenset[bytes]) -> frozenset[bytes]:
    try:
        tree = ast.parse(textwrap.dedent(code_line.decode("utf-8", errors="ignore")))
    except SyntaxError:
        return frozenset()

    live_aliases: set[bytes] = set()
    shadowed_aliases: set[bytes] = set()
    for statement in tree.body:
        for event, event_aliases in _statement_priority_alias_runtime_events(statement, aliases):
            if event == "use":
                live_aliases.update(event_aliases - shadowed_aliases)
            else:
                shadowed_aliases.update(event_aliases)
    return frozenset(live_aliases)


def _statement_priority_alias_runtime_events(
    statement: ast.stmt,
    aliases: frozenset[bytes],
) -> Iterator[tuple[str, frozenset[bytes]]]:
    if isinstance(statement, ast.Assign):
        yield from _node_priority_alias_use_events(statement.value, aliases)
        yield (
            "bind",
            frozenset(
                alias for target in statement.targets for alias in _target_bound_priority_aliases(target, aliases)
            ),
        )
        return
    if isinstance(statement, ast.AnnAssign):
        if statement.value is not None:
            yield from _node_priority_alias_use_events(statement.value, aliases)
        yield "bind", _target_bound_priority_aliases(statement.target, aliases)
        return
    if isinstance(statement, ast.AugAssign):
        yield from _node_priority_alias_use_events(statement.target, aliases)
        yield from _node_priority_alias_use_events(statement.value, aliases)
        yield "bind", _target_bound_priority_aliases(statement.target, aliases)
        return
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        yield "bind", _statement_bound_priority_aliases(statement, aliases)
        return
    if isinstance(statement, ast.If):
        yield from _node_priority_alias_use_events(statement.test, aliases)
        for child_statement in [*statement.body, *statement.orelse]:
            yield from _statement_priority_alias_runtime_events(child_statement, aliases)
        return
    yield from _node_priority_alias_use_events(statement, aliases)
    if bound_aliases := _statement_bound_priority_aliases(statement, aliases):
        yield "bind", bound_aliases


def _node_priority_alias_use_events(node: ast.AST, aliases: frozenset[bytes]) -> Iterator[tuple[str, frozenset[bytes]]]:
    alias_names = {alias.decode("utf-8", errors="ignore"): alias for alias in aliases}
    pending = [node]
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, ast.Call):
            called_aliases = _call_priority_aliases(child, alias_names)
            if called_aliases:
                yield "use", called_aliases
                continue
        expression_aliases = _expression_priority_aliases(child, alias_names)
        if expression_aliases:
            yield "use", expression_aliases
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(child))))


def _call_priority_aliases(call: ast.Call, alias_names: dict[str, bytes]) -> frozenset[bytes]:
    if isinstance(call.func, ast.Name):
        alias = alias_names.get(call.func.id)
        return frozenset({alias}) if alias is not None else frozenset()
    if isinstance(call.func, ast.Attribute):
        return _expression_priority_aliases(call.func.value, alias_names)
    if (
        isinstance(call.func, ast.Call)
        and _simple_reference_name(call.func.func) in {"getattr", "builtins.getattr"}
        and call.func.args
    ):
        return _expression_priority_aliases(call.func.args[0], alias_names)
    return frozenset()


def _expression_priority_aliases(node: ast.AST, alias_names: dict[str, bytes]) -> frozenset[bytes]:
    if isinstance(node, ast.Name):
        alias = alias_names.get(node.id)
        return frozenset({alias}) if alias is not None else frozenset()
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _expression_priority_aliases(node.value, alias_names)
    if (
        isinstance(node, ast.Call)
        and _simple_reference_name(node.func) in {"getattr", "builtins.getattr"}
        and node.args
    ):
        return _expression_priority_aliases(node.args[0], alias_names)
    return frozenset()


def _target_bound_priority_aliases(target: ast.AST, aliases: frozenset[bytes]) -> frozenset[bytes]:
    if isinstance(target, ast.Name):
        name = target.id.encode()
        return frozenset({name}) if name in aliases else frozenset()
    if isinstance(target, ast.Starred):
        return _target_bound_priority_aliases(target.value, aliases)
    if isinstance(target, (ast.Tuple, ast.List)):
        return frozenset(alias for element in target.elts for alias in _target_bound_priority_aliases(element, aliases))
    return frozenset()


def _statement_bound_priority_aliases(statement: ast.stmt, aliases: frozenset[bytes]) -> frozenset[bytes]:
    if isinstance(statement, ast.Assign):
        return frozenset(
            alias for target in statement.targets for alias in _target_bound_priority_aliases(target, aliases)
        )
    if isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        return _target_bound_priority_aliases(statement.target, aliases)
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return _target_bound_priority_aliases(statement.target, aliases)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return frozenset(
            alias
            for item in statement.items
            if item.optional_vars is not None
            for alias in _target_bound_priority_aliases(item.optional_vars, aliases)
        )
    if isinstance(statement, ast.Import):
        return frozenset(
            name
            for alias in statement.names
            for name in ((alias.asname or alias.name.split(".", maxsplit=1)[0]).encode(),)
            if name in aliases
        )
    if isinstance(statement, ast.ImportFrom):
        return frozenset(
            name for alias in statement.names for name in ((alias.asname or alias.name).encode(),) if name in aliases
        )
    if isinstance(statement, ast.Delete):
        return frozenset(
            alias for target in statement.targets for alias in _target_bound_priority_aliases(target, aliases)
        )
    return frozenset()


def _line_shadowed_priority_aliases(code_line: bytes, aliases: frozenset[bytes]) -> frozenset[bytes]:
    shadowed_aliases = set(_line_assigned_priority_aliases(code_line, aliases))
    shadowed_aliases.update(
        alias
        for alias in aliases
        if re.search(rb"^\s*(?:async\s+)?def\s+" + re.escape(alias) + rb"\b", code_line)
        or re.search(rb"^\s*class\s+" + re.escape(alias) + rb"\b", code_line)
    )
    return frozenset(shadowed_aliases)


def _line_assigned_priority_aliases(code_line: bytes, aliases: frozenset[bytes]) -> frozenset[bytes]:
    decoded_line = textwrap.dedent(code_line.decode("utf-8", errors="ignore"))
    try:
        tree = ast.parse(decoded_line)
    except SyntaxError:
        if not decoded_line.rstrip().endswith(":"):
            return frozenset()
        try:
            tree = ast.parse(f"{decoded_line.rstrip()}\n    pass\n")
        except (SyntaxError, ValueError):
            return frozenset()
    except ValueError:
        return frozenset()

    pending = list(reversed(tree.body))
    assigned_aliases: set[bytes] = set()
    while pending:
        statement = pending.pop()
        assigned_aliases.update(_statement_bound_priority_aliases(statement, aliases))
        assigned_aliases.update(_named_expression_bound_priority_aliases(statement, aliases))
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        pending.extend(
            child for child in reversed(list(ast.iter_child_nodes(statement))) if isinstance(child, ast.stmt)
        )
    return frozenset(assigned_aliases)


def _named_expression_bound_priority_aliases(node: ast.AST, aliases: frozenset[bytes]) -> frozenset[bytes]:
    assigned_aliases: set[bytes] = set()
    pending = [node]
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, ast.NamedExpr):
            assigned_aliases.update(_target_bound_priority_aliases(child.target, aliases))
        pending.extend(reversed(list(ast.iter_child_nodes(child))))
    return frozenset(assigned_aliases)


def _line_indent_width(line: bytes) -> int:
    return len(line) - len(line.lstrip(b" \t"))


def _compound_header_keyword(structural_line: bytes) -> bytes | None:
    stripped = structural_line.lstrip()
    for keyword in (b"async def", b"elif", b"else", b"except", b"finally", b"if", b"for", b"while", b"try"):
        if stripped == keyword + b":" or stripped.startswith(keyword + b" ") or stripped.startswith(keyword + b":"):
            return keyword
    return None


def _line_end_offset(candidate: bytes, line_start: int) -> int:
    line_end = candidate.find(b"\n", line_start)
    return len(candidate) if line_end == -1 else line_end + 1


def _compound_header_start(line_start: int, structural_line: bytes) -> int:
    header_match = _COMPOUND_HEADER_MATCH_PATTERN.search(structural_line)
    if header_match is None:
        return line_start
    prefix = structural_line[: header_match.start()]
    if _is_embedded_top_level_prefix(prefix):
        return line_start + header_match.start()
    return line_start


def _first_body_statement_segment(
    candidate: bytes, header_line_end: int, header_indent: int, _depth: int = 0
) -> tuple[int, int] | None:
    line_start = header_line_end
    while line_start < len(candidate):
        line_end = _line_end_offset(candidate, line_start)
        line = candidate[line_start:line_end]
        structural_line = _python_structural_line_bytes(line).rstrip()
        if not structural_line:
            line_start = line_end
            continue
        if _line_indent_width(line) <= header_indent:
            return None

        statement_end = line_end
        paren_depth = _line_parenthesis_delta(line)
        while (
            _line_has_explicit_continuation(candidate[line_start:statement_end]) or paren_depth > 0
        ) and statement_end < len(candidate):
            continuation_start = statement_end
            statement_end = _line_end_offset(candidate, continuation_start)
            paren_depth += _line_parenthesis_delta(candidate[continuation_start:statement_end])

        if structural_line.endswith(b":") and _depth < _MAX_BODY_STATEMENT_NESTING:
            nested_segment = _first_body_statement_segment(
                candidate, statement_end, _line_indent_width(line), _depth + 1
            )
            if nested_segment is not None:
                statement_end = nested_segment[1]
        return line_start, statement_end
    return None


def _previous_header_context_segments(
    candidate: bytes,
    before_line_start: int,
    indent: int,
    keywords: set[bytes],
) -> list[tuple[int, int]]:
    search_end = before_line_start
    while search_end > 0:
        previous_line_end = search_end - 1
        previous_line_start = candidate.rfind(b"\n", 0, previous_line_end) + 1
        previous_line = candidate[previous_line_start:search_end]
        search_end = previous_line_start
        structural_line = _python_structural_line_bytes(previous_line).rstrip()
        if not structural_line:
            continue
        previous_indent = _line_indent_width(previous_line)
        if previous_indent < indent:
            return []
        if previous_indent != indent:
            continue
        keyword = _compound_header_keyword(structural_line)
        if keyword not in keywords or not structural_line.endswith(b":"):
            continue
        header_start = _compound_header_start(previous_line_start, structural_line)
        header_segment = (header_start, previous_line_start + len(previous_line))
        body_segment = _first_body_statement_segment(candidate, previous_line_start + len(previous_line), indent)
        if body_segment is None:
            return [header_segment]
        return [header_segment, body_segment]
    return []


def _try_else_context_segments(candidate: bytes, clause_line_start: int, indent: int) -> list[tuple[int, int]]:
    except_context = _previous_header_context_segments(candidate, clause_line_start, indent, {b"except"})
    try_context = _previous_header_context_segments(candidate, clause_line_start, indent, {b"try"})
    if try_context and except_context:
        return [*try_context, *except_context]
    return []


def _matching_clause_context_segments(
    candidate: bytes,
    clause_line_start: int,
    indent: int,
    clause_keyword: bytes | None,
) -> list[tuple[int, int]]:
    if clause_keyword in {b"else", b"elif"}:
        context = _previous_header_context_segments(candidate, clause_line_start, indent, {b"if", b"for", b"while"})
        if context:
            return context
        if clause_keyword == b"else":
            return _try_else_context_segments(candidate, clause_line_start, indent)
    if clause_keyword in {b"except", b"finally"}:
        return _previous_header_context_segments(candidate, clause_line_start, indent, {b"try"})
    return []


def _enclosing_compound_header_segments(candidate: bytes, line_start: int) -> list[tuple[int, int]]:
    line_end = candidate.find(b"\n", line_start)
    if line_end == -1:
        line_end = len(candidate)
    current_indent = _line_indent_width(candidate[line_start:line_end])
    if current_indent == 0:
        return []

    segments: list[tuple[int, int]] = []
    search_end = line_start
    while current_indent > 0 and search_end > 0:
        previous_line_end = search_end - 1
        previous_line_start = candidate.rfind(b"\n", 0, previous_line_end) + 1
        previous_line = candidate[previous_line_start:search_end]
        search_end = previous_line_start
        structural_line = _python_structural_line_bytes(previous_line).rstrip()
        if not structural_line:
            continue
        previous_indent = _line_indent_width(previous_line)
        if previous_indent < current_indent and structural_line.endswith(b":"):
            header_start = _compound_header_start(previous_line_start, structural_line)
            header_segment = (header_start, previous_line_start + len(previous_line))
            clause_context = _matching_clause_context_segments(
                candidate,
                previous_line_start,
                previous_indent,
                _compound_header_keyword(structural_line),
            )
            segments.append(header_segment)
            segments.extend(reversed(clause_context))
            current_indent = previous_indent
    return list(reversed(segments))


def _candidate_start_with_enclosing_header(candidate: bytes, start: int) -> int:
    line_start = candidate.rfind(b"\n", 0, start) + 1
    line_end = candidate.find(b"\n", start)
    if line_end == -1:
        line_end = len(candidate)
    if _line_indent_width(candidate[line_start:line_end]) == 0:
        return start
    header_segments = _enclosing_compound_header_segments(candidate, line_start)
    return header_segments[0][0] if header_segments else start


def _merge_candidate_segment_ranges(segment_ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(segment_ranges):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        previous_start, previous_end = merged[-1]
        merged[-1] = (previous_start, max(previous_end, end))
    return merged


def _compact_candidate_segments(candidate: bytes, segment_ranges: list[tuple[int, int]]) -> bytes:
    if len(segment_ranges) == 1:
        start, end = segment_ranges[0]
        return candidate[start:end]
    return b"\n".join(candidate[start:end].rstrip(b"\n") for start, end in segment_ranges)


def _prioritized_embedded_python_snippets(
    candidates: list[_EmbeddedPythonCandidate],
    bounded: bytes | None = None,
) -> list[_EmbeddedPythonCandidate]:
    selected: list[_EmbeddedPythonCandidate] = []
    selected_spans: set[tuple[int, int]] = set()
    priority_offsets = _priority_import_offsets(bounded) if bounded is not None else []
    selected_priority_candidates = 0
    for index, (candidate, span, real_ranges) in enumerate(candidates):
        has_priority_marker = (
            _span_contains_priority_offset(span, priority_offsets)
            if bounded is not None
            else _PRIORITY_EMBEDDED_PYTHON_IMPORT_PATTERN.search(candidate.lower()) is not None
        )
        if index >= _MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS:
            if not has_priority_marker:
                continue
            if selected_priority_candidates >= _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS:
                continue
            if bounded is not None:
                candidate, span, real_ranges = _bounded_priority_embedded_python_candidate(
                    candidate, span, priority_offsets
                )
            else:
                candidate = candidate[:_MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES]
                span = (span[0], span[0] + len(candidate))
                real_ranges = (span,)
            selected_priority_candidates += 1
        if span in selected_spans:
            continue
        selected_spans.add(span)
        selected.append((candidate, span, real_ranges))
    return selected


def _complete_brace_truncated_line_candidate(
    bounded: bytes,
    span: tuple[int, int],
) -> tuple[bytes, tuple[int, int]] | None:
    """Extend a failed block candidate through a same-line closing brace."""
    if span[1] >= len(bounded) or bounded[span[1] : span[1] + 1] != b"}":
        return None
    line_end = bounded.find(b"\n", span[1])
    end = len(bounded) if line_end < 0 else line_end + 1
    if end <= span[1]:
        return None
    return bounded[span[0] : end], (span[0], end)


def _embedded_python_scan_windows(data: bytes) -> list[bytes]:
    if len(data) <= _EMBEDDED_PYTHON_SCAN_WINDOW_BYTES:
        return [data]
    return [data[:_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES], data[-_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES:]]


def _python_structural_line_bytes(line: bytes) -> bytes:
    structural = bytearray()
    quote_marker: bytes | None = None
    escaped = False
    index = 0
    while index < len(line):
        if quote_marker is not None:
            if escaped:
                escaped = False
                index += 1
                continue
            if len(quote_marker) == 1 and line[index] == ord("\\"):
                escaped = True
                index += 1
                continue
            if line.startswith(quote_marker, index):
                index += len(quote_marker)
                quote_marker = None
                continue
            index += 1
            continue

        byte = line[index]
        if byte == ord("#"):
            break
        if line.startswith(b'"""', index) or line.startswith(b"'''", index):
            quote_marker = line[index : index + 3]
            index += 3
            continue
        if byte in {ord("'"), ord('"')}:
            quote_marker = bytes([byte])
            index += 1
            continue
        structural.append(byte)
        index += 1
    return bytes(structural)


def _triple_quote_state_after_line(line: bytes, quote: bytes | None) -> bytes | None:
    index = 0
    while index < len(line):
        if quote is not None:
            end = _find_unescaped_marker(line, quote, index)
            if end == -1:
                return quote
            index = end + len(quote)
            quote = None
            continue

        byte = line[index]
        if byte == ord("#"):
            return None
        if (line.startswith(b'"""', index) or line.startswith(b"'''", index)) and not _is_escaped_marker(line, index):
            quote = line[index : index + 3]
            index += 3
            continue
        if byte in {ord("'"), ord('"')}:
            single_quote = byte
            index += 1
            escaped = False
            while index < len(line):
                current = line[index]
                if escaped:
                    escaped = False
                elif current == ord("\\"):
                    escaped = True
                elif current == single_quote:
                    index += 1
                    break
                index += 1
            continue
        index += 1
    return quote


def _find_unescaped_marker(line: bytes, marker: bytes, start: int) -> int:
    index = line.find(marker, start)
    while index != -1:
        if not _is_escaped_marker(line, index):
            return index
        index = line.find(marker, index + 1)
    return -1


def _is_escaped_marker(line: bytes, index: int) -> bool:
    backslashes = 0
    position = index - 1
    while position >= 0 and line[position] == ord("\\"):
        backslashes += 1
        position -= 1
    return backslashes % 2 == 1


def _line_has_explicit_continuation(line: bytes) -> bool:
    return _python_structural_line_bytes(line).rstrip().endswith(b"\\")


def _line_parenthesis_delta(line: bytes) -> int:
    structural = _python_structural_line_bytes(line)
    return structural.count(b"(") - structural.count(b")")


def _multiline_string_state_after_line(line: bytes, quote: bytes | None) -> bytes | None:
    return _triple_quote_state_after_line(line, quote)


def _is_embedded_top_level_prefix(prefix: bytes) -> bool:
    if not prefix:
        return True
    stripped_prefix = prefix.strip()
    if stripped_prefix == b"":
        return False
    return not any(0x20 <= byte < 0x7F for byte in stripped_prefix)


def _context_statement_start(line: bytes) -> int | None:
    for match in _EMBEDDED_PYTHON_CONTEXT_START_PATTERN.finditer(line):
        if _is_embedded_top_level_prefix(line[: match.start()]):
            return match.start()
    structural_line = _python_structural_line_bytes(line)
    for match in _EMBEDDED_PYTHON_COMPOUND_CONTEXT_START_PATTERN.finditer(structural_line):
        if _is_embedded_top_level_prefix(structural_line[: match.start()]):
            return match.start()
    return None


def _assignment_targets(tree: ast.AST) -> list[str]:
    targets: list[str] = []
    for statement in getattr(tree, "body", []):
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                targets.extend(_assignment_target_names(target))
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            targets.extend(_assignment_target_names(statement.target))
    return targets


def _assignment_target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Starred):
        return _assignment_target_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _assignment_target_names(element)]
    return []


def _is_priority_assignment_context(context: bytes, statement: bytes) -> bool:
    code_str, _byte_offsets = _decode_utf8_with_byte_offsets(context + statement)
    statement_str, _statement_byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        statement_tree = ast.parse(statement_str)
    except (SyntaxError, ValueError):
        return False

    targets = _assignment_targets(statement_tree)
    if not targets:
        return False

    probe = code_str + "\n" + "\n".join(call for target in targets for call in _priority_assignment_probe_calls(target))
    try:
        probe_tree = ast.parse(probe)
    except (SyntaxError, ValueError):
        return False
    return bool(_resolve_alias_aware_high_risk_calls(probe_tree))


def _tree_imports_priority_module(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(_is_priority_module_name(alias.name) for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module is not None and _is_priority_module_name(node.module):
            return True
    return False


def _is_priority_prefix_context_statement(context: bytes, statement: bytes) -> bool:
    code_str, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(code_str)
    except (SyntaxError, ValueError):
        return False
    if _tree_imports_priority_module(tree):
        return True
    return _is_priority_assignment_context(context, statement)


def _is_prefix_context_shadow_statement(context: bytes, statement: bytes) -> bool:
    if not context:
        return False
    context_names = _prefix_context_binding_names(context)
    if not context_names:
        return False
    return not _statement_defined_names(statement).isdisjoint(context_names)


def _statement_defined_names(statement: bytes) -> set[str]:
    statement_str, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(statement_str)
    except (SyntaxError, ValueError):
        return set()

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                names.update(_assignment_target_names(target))
    return names


def _statement_referenced_names(statement: bytes) -> set[str]:
    statement_str, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(statement_str)
    except (SyntaxError, ValueError):
        return set()
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}


def _drop_context_statement_index(context: list[bytes]) -> int:
    later_references: set[str] = set()
    for index in range(len(context) - 1, -1, -1):
        defined_names = _statement_defined_names(context[index])
        if defined_names.isdisjoint(later_references):
            return index
        later_references.difference_update(defined_names)
        later_references.update(_statement_referenced_names(context[index]))
    return 0


def _prefix_context_binding_names(context: bytes) -> set[str]:
    code_str, _byte_offsets = _decode_utf8_with_byte_offsets(context)
    try:
        tree = ast.parse(code_str)
    except (SyntaxError, ValueError):
        return set()

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                names.update(_assignment_target_names(target))
    return names


def _extract_priority_prefix_context(data: bytes) -> bytes:
    """Return bounded top-level dangerous imports and aliases from a prefix window."""
    context: list[bytes] = []
    context_size = 0
    lines = data.splitlines(keepends=True)
    index = 0
    multiline_quote: bytes | None = None
    while index < len(lines):
        start = _context_statement_start(lines[index])
        if start is None:
            multiline_quote = _multiline_string_state_after_line(lines[index], multiline_quote)
            index += 1
            continue
        if multiline_quote is not None:
            multiline_quote = _multiline_string_state_after_line(lines[index], multiline_quote)
            index += 1
            continue

        statement_line_quote = _multiline_string_state_after_line(lines[index], None)
        statement_lines = [lines[index][start:]]
        paren_depth = _line_parenthesis_delta(statement_lines[0])
        while (_line_has_explicit_continuation(statement_lines[-1]) or paren_depth > 0) and index + 1 < len(lines):
            index += 1
            continuation = lines[index]
            statement_lines.append(continuation)
            paren_depth += _line_parenthesis_delta(continuation)

        statement = b"".join(statement_lines).rstrip() + b"\n"
        current_context = b"".join(context)
        if not _is_priority_prefix_context_statement(
            current_context, statement
        ) and not _is_prefix_context_shadow_statement(current_context, statement):
            multiline_quote = statement_line_quote
            index += 1
            continue
        if len(statement) > _MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES:
            index += 1
            continue
        while context and context_size + len(statement) > _MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES:
            drop_index = _drop_context_statement_index([*context, statement])
            if drop_index >= len(context):
                break
            context_size -= len(context.pop(drop_index))
        context.append(statement)
        context_size += len(statement)
        index += 1

    return b"".join(context)


def _embedded_python_extraction_windows(data: bytes) -> list[tuple[bytes, bool]]:
    windows = _embedded_python_scan_windows(data)
    if len(windows) == 1:
        return [(windows[0], False)]

    prefix, tail = windows
    extraction_windows = [(prefix, False), (tail, False)]
    import_context = _extract_priority_prefix_context(prefix)
    if import_context:
        extraction_windows.append((import_context + b"\n" + tail, True))
        tail_starts = [match.start() for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(tail) if match.start() > 0]
        context_aliases = _priority_import_aliases(import_context)
        priority_tail_starts = set(_tail_starts_for_priority_alias_uses(tail, tail_starts, context_aliases))
        for priority_offset in _priority_import_offsets(tail):
            insertion_index = bisect_right(tail_starts, priority_offset)
            if insertion_index:
                priority_tail_starts.add(tail_starts[insertion_index - 1])
        priority_tail_start_list = _bounded_priority_tail_starts(sorted(priority_tail_starts))
        selected_starts = [
            *tail_starts[:_MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS],
            *priority_tail_start_list,
            *tail_starts[-_MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS:],
        ]
        for start in dict.fromkeys(selected_starts):
            extraction_windows.append((import_context + b"\n" + tail[start:], True))
    return extraction_windows


def _bounded_priority_tail_starts(tail_starts: list[int]) -> list[int]:
    if len(tail_starts) <= _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS:
        return tail_starts
    head_count = _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS // 2
    tail_count = _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS - head_count
    return [*tail_starts[:head_count], *tail_starts[-tail_count:]]


def _tail_starts_for_priority_alias_uses(
    tail: bytes,
    tail_starts: list[int],
    aliases: frozenset[bytes],
) -> list[int]:
    selected_starts: list[int] = []
    if not tail_starts or not aliases:
        return selected_starts
    for usage_start, _usage_end in _priority_alias_usage_lines(tail, aliases, 0):
        start_index = bisect_right(tail_starts, usage_start) - 1
        if start_index >= 0:
            selected_starts.append(tail_starts[start_index])
    return selected_starts


def _has_raw_match_outside_parsed_spans(raw_spans: list[tuple[int, int]], parsed_spans: list[tuple[int, int]]) -> bool:
    """Return whether any raw regex hit sits outside AST-validated source."""
    for raw_start, raw_end in raw_spans:
        if not any(parsed_start <= raw_start and raw_end <= parsed_end for parsed_start, parsed_end in parsed_spans):
            return True
    return False


def _parsed_real_spans(
    real_ranges: tuple[tuple[int, int], ...],
    parsed_byte_length: int,
    compact_length: int,
) -> list[tuple[int, int]]:
    if parsed_byte_length >= compact_length:
        return list(real_ranges)

    remaining = parsed_byte_length
    parsed_spans: list[tuple[int, int]] = []
    for start, end in real_ranges:
        if remaining <= 0:
            break
        segment_length = end - start
        consumed = min(segment_length, remaining)
        if consumed > 0:
            parsed_spans.append((start, start + consumed))
            remaining -= consumed
        if remaining > 0:
            remaining -= 1
    return parsed_spans


def _is_span_inside_parsed_spans(span: tuple[int, int], parsed_spans: list[tuple[int, int]]) -> bool:
    return any(parsed_start <= span[0] and span[1] <= parsed_end for parsed_start, parsed_end in parsed_spans)


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
_WEBBROWSER_LAUNCH_DESCRIPTION = "Web browser launch detected"
_CTYPES_NATIVE_LOADING_DESCRIPTION = "Native library loading detected"
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
    (rb"webbrowser\.(?:get|open|open_new|open_new_tab)", _WEBBROWSER_LAUNCH_DESCRIPTION),
    (
        rb"ctypes\.(?:CDLL|OleDLL|PyDLL|WinDLL|LibraryLoader|cdll|oledll|pydll|windll)",
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
        for window, include_full_source in _embedded_python_extraction_windows(data):
            for candidate, _span, _real_ranges in _candidate_embedded_python_snippets(
                window, include_full_source=include_full_source
            ):
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

    @staticmethod
    def _dangerous_imports_in_tree(tree: ast.AST) -> set[str]:
        dangerous_imports: set[str] = set()
        for node in ast.walk(tree):
            imported_modules: list[str] = []
            if isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_modules.append(node.module)
            for module_name in imported_modules:
                dangerous_imports.update(
                    dangerous_import
                    for dangerous_import in DANGEROUS_IMPORTS
                    if module_name == dangerous_import or module_name.startswith(f"{dangerous_import}.")
                )
        return dangerous_imports

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

        for match, span, real_ranges in _prioritized_embedded_python_snippets(matches, bounded=bounded):
            try:
                if _is_span_inside_parsed_spans(span, parsed_snippet_spans):
                    continue
                code_str, byte_offsets = _decode_utf8_with_byte_offsets(match)
                parsed_snippet = _parse_embedded_python_snippet(code_str)
                if parsed_snippet is None or parsed_snippet[1] < len(code_str):
                    completed_candidate = _complete_brace_truncated_line_candidate(bounded, span)
                    if completed_candidate is not None:
                        completed_match, completed_span = completed_candidate
                        completed_code_str, completed_byte_offsets = _decode_utf8_with_byte_offsets(completed_match)
                        completed_parsed_snippet = _parse_embedded_python_snippet(completed_code_str)
                        if completed_parsed_snippet is not None:
                            code_str = completed_code_str
                            byte_offsets = completed_byte_offsets
                            parsed_snippet = completed_parsed_snippet
                            span = completed_span
                            real_ranges = (completed_span,)

                parsed_imports = (
                    self._dangerous_imports_in_tree(parsed_snippet[0]) if parsed_snippet is not None else None
                )
                # Check for dangerous imports
                for dangerous_import in DANGEROUS_IMPORTS:
                    if self._contains_dangerous_import(code_str, dangerous_import) and (
                        parsed_imports is None or dangerous_import in parsed_imports
                    ):
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

                # Use the parsed source, including a completed same-line candidate when applicable.
                if parsed_snippet is not None:
                    tree, parsed_chars = parsed_snippet
                    parsed_byte_length = byte_offsets[parsed_chars]
                    parsed_snippet_spans.extend(_parsed_real_spans(real_ranges, parsed_byte_length, len(match)))
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
            raw_match_only_in_parsed_snippets = bool(parsed_snippet_spans) and not _has_raw_match_outside_parsed_spans(
                raw_pattern_spans, parsed_snippet_spans
            )
            if description == _SUBPROCESS_CODE_EXECUTION_DESCRIPTION:
                resolved_subprocess_call = any(code == "S103" for _, code in resolved_high_risk_calls)
                if resolved_subprocess_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
            if description == _OS_CODE_EXECUTION_DESCRIPTION:
                resolved_os_process_call = any(code == "S101" for _, code in resolved_high_risk_calls)
                if resolved_os_process_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
            if description == _RUNPY_CODE_EXECUTION_DESCRIPTION:
                resolved_runpy_call = any(code == "S108" for _, code in resolved_high_risk_calls)
                if resolved_runpy_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
            if description == _WEBBROWSER_LAUNCH_DESCRIPTION:
                resolved_webbrowser_call = any(code == "S109" for _, code in resolved_high_risk_calls)
                if resolved_webbrowser_call:
                    pattern_match = True
                elif bounded_high_risk_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
            if description == _CTYPES_NATIVE_LOADING_DESCRIPTION:
                resolved_ctypes_call = any(code == "S110" for _, code in resolved_high_risk_calls)
                if resolved_ctypes_call:
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
            for window, include_full_source in _embedded_python_extraction_windows(data):
                findings.extend(
                    self._extract_and_check_python_code(
                        window,
                        "Generic Python",
                        context,
                        include_full_source=include_full_source,
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
