"""
JIT/Script Code Execution Detection for ML Models
==================================================

Detects potentially dangerous JIT-compiled code and script execution patterns
in TorchScript, TensorFlow SavedFunction, and ONNX models that could lead to
arbitrary code execution.

Part of ModelAudit's critical security validation suite.
"""

import ast
import builtins as python_builtins
import json
import re
import textwrap
from bisect import bisect_left, bisect_right
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from modelaudit.models import JITScriptFinding

_BuiltinAliasBinding = tuple[
    str | None,
    bool,
    dict[tuple[object, ...], str | None],
    set[str],
    dict[tuple[str, ...], str | None],
    str | None,
    str | None,
    tuple[tuple[str, int], ...],
]
_FunctionAliasSummary = tuple[
    list[tuple[str, str, _BuiltinAliasBinding]],
    _BuiltinAliasBinding | None,
    tuple[tuple[str, int], ...],
]


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
_BUILTINS_MODULE_NAMES = frozenset({"builtins", "__builtin__", "__builtins__"})
_PYTHON_BUILTIN_NAMES = frozenset(dir(python_builtins))
_BUILTIN_ALIAS_CONTEXT_MARKERS = tuple(
    name.encode("utf-8") for name in sorted({*DANGEROUS_BUILTINS, *_BUILTINS_MODULE_NAMES, "globals", "locals"})
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
_MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES = 64
_EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT = 1_000_000
_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES = 1_000_000
_MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES = 16_384
_EMBEDDED_PYTHON_BYTE_LIMIT_REASON = "jit_embedded_python_byte_limit"
_EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON = "jit_embedded_python_snippet_limit"
_EMBEDDED_PYTHON_START_MARKERS = (
    b"def ",
    b"async def ",
    b"class ",
    b"import ",
    b"from ",
    b"globals(",
    b"locals(",
)
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
_EMBEDDED_PYTHON_CONTEXT_ASSIGNMENT_LHS_PATTERN = (
    rb"(?:[A-Za-z_]\w*(?:\s*:[^=\n#]+)?|"
    rb"[A-Za-z_]\w*(?:(?:\s*\[[^\]\n#]+\])|(?:\.[A-Za-z_]\w*))+|"
    rb"[\(\[][A-Za-z_][^=\n#]*[\)\]])"
)
_EMBEDDED_PYTHON_BLOCK_PATTERN = re.compile(rb"def\s+\w+\s*\([^)]*\):[^}\x00]+|class\s+\w+[^}\x00]+")
_EMBEDDED_PYTHON_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])"
    rb"(?:(?:async\s+)?def\s+\w+|class\s+\w+|import\s+[A-Za-z_][\w.]*|"
    rb"from\s+[A-Za-z_][\w.]*(?:\s|\\\r?\n)+import|(?:globals|locals)\s*\()"
)
_UNAMBIGUOUS_EMBEDDED_PYTHON_START_PATTERN = re.compile(
    rb"(?:(?:async\s+)?def\s+\w+\s*[\[(]|"
    rb"class\s+\w+\s*[\[(:]|"
    rb"import\s+[A-Za-z_][\w.]*(?:\s*(?:,|as\b|\\\r?\n|\r?\n|$))|"
    rb"from\s+[A-Za-z_][\w.]*(?:\s|\\\r?\n)+import(?:\s|\\\r?\n)+(?:\(|[A-Za-z_*])|"
    rb"(?:globals|locals)\s*\()"
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


def _has_source_like_embedded_python_start(data: bytes, *, start_offset: int = 0) -> bool:
    """Return whether a Python start marker follows source indentation or binary framing."""
    source_start_probes = 0
    for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(data, start_offset):
        cursor = match.start()
        while cursor > 0 and data[cursor - 1] in b" \t\r":
            cursor -= 1
        if cursor > 0 and data[cursor - 1] != 0x0A and 0x20 <= data[cursor - 1] < 0x7F:
            continue
        source_start_probes += 1
        if source_start_probes > _MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES:
            return True
        candidate = data[match.start() : match.start() + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES]
        code_str, _byte_offsets = _decode_utf8_with_byte_offsets(candidate)
        if _parse_embedded_python_snippet(code_str) is not None:
            return True
        if _UNAMBIGUOUS_EMBEDDED_PYTHON_START_PATTERN.match(candidate):
            return True
    return False


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
        matching_block = next(
            ((block_start, block_end) for block_start, block_end in block_spans if block_start == start),
            None,
        )
        if matching_block is not None and start not in priority_starts:
            block_start, block_end = matching_block
            if not any(marker in bounded[block_start:block_end] for marker in _BUILTIN_ALIAS_CONTEXT_MARKERS):
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
        return node.id in aliases or node.id in DANGEROUS_BUILTINS
    if isinstance(node, ast.Attribute):
        return _expression_is_priority_alias_reference(node.value, aliases)
    if isinstance(node, ast.Subscript):
        return _expression_is_priority_alias_reference(node.value, aliases)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_expression_is_priority_alias_reference(element, aliases) for element in node.elts)
    if isinstance(node, ast.Dict):
        return any(
            _expression_is_priority_alias_reference(candidate, aliases)
            for candidate in [*node.keys, *node.values]
            if candidate is not None
        )
    if isinstance(node, ast.IfExp):
        return _expression_is_priority_alias_reference(node.body, aliases) or _expression_is_priority_alias_reference(
            node.orelse, aliases
        )
    if isinstance(node, ast.BoolOp):
        return any(_expression_is_priority_alias_reference(value, aliases) for value in node.values)
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
        f"{target}.eval('1+1')",
        f"{target}['eval']('1+1')",
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


def _select_prioritized_embedded_python_snippets(
    candidates: list[_EmbeddedPythonCandidate],
    bounded: bytes | None = None,
) -> tuple[list[_EmbeddedPythonCandidate], list[tuple[int, int]]]:
    selected: list[_EmbeddedPythonCandidate] = []
    selected_spans: set[tuple[int, int]] = set()
    priority_offsets = _priority_import_offsets(bounded) if bounded is not None else []
    selected_default_candidates = 0
    selected_priority_candidates = 0
    omitted_budgeted_spans: list[tuple[int, int]] = []
    for candidate, span, real_ranges in candidates:
        if span in selected_spans:
            continue
        has_priority_marker = (
            _span_contains_priority_offset(span, priority_offsets)
            if bounded is not None
            else _PRIORITY_EMBEDDED_PYTHON_IMPORT_PATTERN.search(candidate.lower()) is not None
        )
        if selected_default_candidates >= _MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS:
            if not has_priority_marker:
                omitted_budgeted_spans.append(span)
                continue
            if selected_priority_candidates >= _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS:
                omitted_budgeted_spans.append(span)
                continue
            if bounded is not None:
                candidate, span, real_ranges = _bounded_priority_embedded_python_candidate(
                    candidate, span, priority_offsets
                )
            else:
                candidate = candidate[:_MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES]
                span = (span[0], span[0] + len(candidate))
                real_ranges = (span,)
            if span in selected_spans:
                continue
            selected_priority_candidates += 1
        else:
            selected_default_candidates += 1
        selected_spans.add(span)
        selected.append((candidate, span, real_ranges))
    return selected, omitted_budgeted_spans


def _prioritized_embedded_python_snippets(
    candidates: list[_EmbeddedPythonCandidate],
    bounded: bytes | None = None,
) -> list[_EmbeddedPythonCandidate]:
    selected, _omitted_budgeted_spans = _select_prioritized_embedded_python_snippets(candidates, bounded)
    return selected


def _complete_brace_truncated_line_candidate(
    bounded: bytes,
    span: tuple[int, int],
) -> tuple[bytes, tuple[int, int]] | None:
    """Extend a failed block candidate through its remaining indented lines."""
    if span[1] >= len(bounded) or bounded[span[1] : span[1] + 1] != b"}":
        return None
    line_end = bounded.find(b"\n", span[1])
    end = len(bounded) if line_end < 0 else line_end + 1
    if end <= span[1]:
        return None

    header_end = bounded.find(b"\n", span[0], span[1])
    if header_end < 0:
        return bounded[span[0] : end], (span[0], end)
    header_indent = _line_indent_width(bounded[span[0] : header_end + 1])
    byte_limit = min(len(bounded), span[0] + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES)
    while end < byte_limit:
        next_line_end = bounded.find(b"\n", end, byte_limit)
        next_end = byte_limit if next_line_end < 0 else next_line_end + 1
        line = bounded[end:next_end]
        null_offset = line.find(b"\x00")
        if null_offset >= 0:
            break
        structural_line = _python_structural_line_bytes(line)
        if structural_line.strip() and _line_indent_width(line) <= header_indent:
            break
        end = next_end
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


def _assignment_target_root_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Starred):
        return _assignment_target_root_names(target.value)
    if isinstance(target, (ast.Attribute, ast.Subscript)):
        return _assignment_target_root_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _assignment_target_root_names(element)]
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
    if any(
        _expression_is_priority_alias_reference(value, set())
        for _target, value in _assignment_targets_and_values_in_tree(statement_tree)
    ):
        return True

    probe = code_str + "\n" + "\n".join(call for target in targets for call in _priority_assignment_probe_calls(target))
    try:
        probe_tree = ast.parse(probe)
    except (SyntaxError, ValueError):
        return False
    return bool(
        _resolve_alias_aware_high_risk_calls(probe_tree)
        or JITScriptDetector._dangerous_builtin_calls_in_tree(probe_tree)
    )


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
                names.update(_assignment_target_root_names(target))
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


def _priority_prefix_contexts_at_offsets(data: bytes, offsets: list[int]) -> dict[int, bytes]:
    """Return top-level dangerous import and alias context at bounded offsets."""
    requested_offsets = sorted({offset for offset in offsets if 0 <= offset <= len(data)})
    if not requested_offsets:
        return {}

    contexts: dict[int, bytes] = {}
    context: list[bytes] = []
    context_size = 0
    lines = data.splitlines(keepends=True)
    line_offsets: list[int] = []
    current_offset = 0
    for line in lines:
        line_offsets.append(current_offset)
        current_offset += len(line)

    index = 0
    requested_index = 0
    multiline_quote: bytes | None = None

    def capture_offsets_before(end: int) -> None:
        nonlocal requested_index
        snapshot: bytes | None = None
        while requested_index < len(requested_offsets) and requested_offsets[requested_index] < end:
            if snapshot is None:
                snapshot = b"".join(context)
            contexts[requested_offsets[requested_index]] = snapshot
            requested_index += 1

    while index < len(lines):
        capture_offsets_before(line_offsets[index] + len(lines[index]))
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
            capture_offsets_before(line_offsets[index] + len(lines[index]))
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

    final_context = b"".join(context)
    for offset in requested_offsets[requested_index:]:
        contexts[offset] = final_context
    return contexts


def _extract_priority_prefix_context(data: bytes) -> bytes:
    """Return bounded top-level dangerous imports and aliases from a prefix window."""
    return _priority_prefix_contexts_at_offsets(data, [len(data)]).get(len(data), b"")


def _append_single_window_prefix_context_windows(
    extraction_windows: list[tuple[bytes, bool]],
    bounded: bytes,
) -> None:
    if not any(marker in bounded for marker in _BUILTIN_ALIAS_CONTEXT_MARKERS):
        return
    starts = [match.start() for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(bounded) if match.start() > 0]
    selected_starts = [
        *starts[:_MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS],
        *starts[-_MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS:],
    ]
    selected_starts = list(dict.fromkeys(selected_starts))
    contexts = _priority_prefix_contexts_at_offsets(bounded, selected_starts)
    for start in selected_starts:
        context = contexts.get(start, b"")
        if context:
            extraction_windows.append((context + b"\n" + bounded[start:], True))


def _embedded_python_extraction_windows(data: bytes) -> list[tuple[bytes, bool]]:
    windows = _embedded_python_scan_windows(data)
    if len(windows) == 1:
        extraction_windows = [(windows[0], False)]
        _append_single_window_prefix_context_windows(extraction_windows, windows[0])
        return extraction_windows

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


def _embedded_python_analysis_incomplete_finding(
    *,
    framework: str,
    context: str,
    reason: str,
    message: str,
    max_scan_bytes: int | None = None,
    omitted_snippets: int | None = None,
    candidates_count: int | None = None,
) -> "JITScriptFinding":
    details: dict[str, Any] = {
        "analysis_incomplete": True,
        "reason": reason,
    }
    if max_scan_bytes is not None:
        details["max_scan_bytes"] = max_scan_bytes
    if omitted_snippets is not None:
        details["omitted_snippets"] = omitted_snippets
    if candidates_count is not None:
        details["candidate_snippets"] = candidates_count

    return create_jit_finding(
        message=message,
        severity="INFO",
        context=context,
        pattern=None,
        recommendation="Treat JIT/embedded Python coverage as inconclusive and review the model source.",
        confidence=1.0,
        details=details,
        framework=framework,
        code_snippet=None,
        type="analysis_incomplete",
        operation=None,
        builtin=None,
        import_=None,
    )


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
_CODE_EXECUTION_PATTERN_BUILTINS = {
    "exec() call detected": "exec",
    "eval() call detected": "eval",
    "compile() call detected": "compile",
    "__import__() call detected": "__import__",
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
        if JITScriptDetector._dangerous_builtin_calls_in_tree(tree):
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
    def _dangerous_builtin_calls_in_tree(tree: ast.AST) -> set[str]:
        dangerous_builtins = set(DANGEROUS_BUILTINS)

        class DangerousBuiltinCallVisitor(ast.NodeVisitor):
            _SEQUENCE_INDEX_MARKER = "__modelaudit_sequence_index__"
            # Store import identities with scoped aliases so branch snapshots preserve them.
            _FUNCTOOLS_MODULE_MARKER = "__modelaudit_functools_module__:"
            _FUNCTOOLS_PARTIAL_MARKER = "__modelaudit_functools_partial__:"
            _CONSTANT_STRING_MARKER = "__modelaudit_constant_string__:"
            _FUNCTION_EFFECT_MARKER = "__modelaudit_function_effect__:"
            _CALLBACK_INVOKER_MARKER = "__modelaudit_callback_invoker__:"
            _BUILTIN_HELPER_MARKER = "__modelaudit_builtin_helper__:"
            _ATTRIBUTE_CONTAINER_MARKER = "__modelaudit_attribute_container__:"
            _ATTRIBUTE_FUNCTION_MARKER = "__modelaudit_attribute_function__:"
            _CLASS_MARKER = "__modelaudit_class__:"
            _CONTAINER_FUNCTION_MARKER = "__modelaudit_container_function__:"
            _GLOBAL_DELETE_MARKER = "__modelaudit_global_delete__:"
            _MAX_CONSTANT_STRING_CANDIDATES = 16

            def __init__(self) -> None:
                self.findings: set[str] = set()
                self.alias_scopes: list[dict[str, str | None]] = [{}]
                self.builtins_module_aliases: list[set[str]] = [set()]
                self.defined_names: list[set[str]] = [set()]
                self.container_alias_scopes: list[dict[str, dict[tuple[object, ...], str | None]]] = [{}]
                self.container_identity_scopes: list[dict[str, int | None]] = [{}]
                self.attribute_alias_scopes: list[dict[tuple[str, ...], str | None]] = [{}]
                self.scope_kinds = ["module"]
                self.global_name_scopes: list[set[str]] = [set()]
                self.next_container_identity = 1
                self.return_binding_stack: list[list[_BuiltinAliasBinding]] = []
                self.active_function_calls: set[str] = set()
                self.function_nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda] = {}
                self.lambda_summaries: dict[int, _FunctionAliasSummary] = {}
                self.constructor_call_bindings: dict[
                    int,
                    tuple[
                        dict[tuple[str, ...], str | None],
                        dict[tuple[str, ...], dict[tuple[object, ...], str | None]],
                    ],
                ] = {}

            def _push_scope(
                self,
                arguments: ast.arguments | None = None,
                default_bindings: dict[
                    str,
                    tuple[
                        str | None,
                        bool,
                        dict[tuple[object, ...], str | None],
                        int | None,
                        set[str],
                    ],
                ]
                | None = None,
                local_names: set[str] | None = None,
                *,
                kind: str = "function",
                global_names: set[str] | None = None,
            ) -> None:
                self.alias_scopes.append({})
                self.builtins_module_aliases.append(set())
                self.defined_names.append(set())
                self.container_alias_scopes.append({})
                self.container_identity_scopes.append({})
                self.attribute_alias_scopes.append({})
                self.scope_kinds.append(kind)
                self.global_name_scopes.append(set(global_names or set()))
                for name in local_names or set():
                    self._bind_name(name, None, defined=False)
                if arguments is None:
                    return
                for arg in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]:
                    self._bind_name(arg.arg, None)
                if arguments.vararg is not None:
                    self._bind_name(arguments.vararg.arg, None)
                if arguments.kwarg is not None:
                    self._bind_name(arguments.kwarg.arg, None)
                for name, (
                    builtin,
                    builtins_module,
                    container_aliases,
                    container_identity,
                    constant_strings,
                ) in (default_bindings or {}).items():
                    self._bind_name(
                        name,
                        builtin,
                        builtins_module=builtins_module,
                        container_aliases=container_aliases,
                        container_identity=container_identity,
                        constant_strings=constant_strings,
                    )

            def _pop_scope(self) -> None:
                self.alias_scopes.pop()
                self.builtins_module_aliases.pop()
                self.defined_names.pop()
                self.container_alias_scopes.pop()
                self.container_identity_scopes.pop()
                self.attribute_alias_scopes.pop()
                self.scope_kinds.pop()
                self.global_name_scopes.pop()

            def _visible_scope_indexes(self) -> Iterator[int]:
                skip_class_scopes = False
                for index in range(len(self.alias_scopes) - 1, -1, -1):
                    if skip_class_scopes and self.scope_kinds[index] == "class":
                        continue
                    yield index
                    if self.scope_kinds[index] in {"class", "comprehension", "function"}:
                        skip_class_scopes = True

            def _lookup_alias(self, name: str) -> str | None:
                for index in self._visible_scope_indexes():
                    scope = self.alias_scopes[index]
                    if name in scope:
                        return scope[name]
                return name if name in dangerous_builtins else None

            def _is_unshadowed_name(self, name: str) -> bool:
                return all(name not in self.alias_scopes[index] for index in self._visible_scope_indexes())

            def _is_guaranteed_resolvable_name(self, name: str) -> bool:
                for index in self._visible_scope_indexes():
                    scope = self.alias_scopes[index]
                    if name in scope:
                        return name in self.defined_names[index]
                return name in _PYTHON_BUILTIN_NAMES

            def _known_truth(self, node: ast.AST) -> bool | None:
                truth = self._constant_truth(node)
                if truth is not None:
                    return truth
                if self._resolve_builtin(node) is not None:
                    return True
                if (
                    isinstance(node, ast.Name)
                    and self._is_unshadowed_name(node.id)
                    and node.id in _PYTHON_BUILTIN_NAMES
                ):
                    return True
                return None

            def _is_builtins_module_name(self, name: str) -> bool:
                for index in self._visible_scope_indexes():
                    scope = self.alias_scopes[index]
                    if name in scope:
                        return name in self.builtins_module_aliases[index]
                return name in _BUILTINS_MODULE_NAMES

            def _has_binding_marker(self, name: str, marker: str) -> bool:
                for index in self._visible_scope_indexes():
                    if name in self.alias_scopes[index]:
                        return f"{marker}{name}" in self.builtins_module_aliases[index]
                return False

            @classmethod
            def _constant_string_marker_prefix(cls, name: str) -> str:
                return f"{cls._CONSTANT_STRING_MARKER}{name}\0"

            @classmethod
            def _function_effect_marker_prefix(cls, name: str) -> str:
                return f"{cls._FUNCTION_EFFECT_MARKER}{name}\0"

            @classmethod
            def _callback_invoker_marker_prefix(cls, name: str) -> str:
                return f"{cls._CALLBACK_INVOKER_MARKER}{name}\0"

            @classmethod
            def _builtin_helper_marker_prefix(cls, name: str) -> str:
                return f"{cls._BUILTIN_HELPER_MARKER}{name}\0"

            @classmethod
            def _class_marker(cls, name: str) -> str:
                return f"{cls._CLASS_MARKER}{name}"

            @classmethod
            def _global_delete_marker(cls, name: str) -> str:
                return f"{cls._GLOBAL_DELETE_MARKER}{name}"

            @classmethod
            def _container_function_marker_prefix(cls, name: str) -> str:
                return f"{cls._CONTAINER_FUNCTION_MARKER}{name}\0"

            @classmethod
            def _attribute_container_name(cls, key: tuple[str, ...]) -> str:
                return f"{cls._ATTRIBUTE_CONTAINER_MARKER}{chr(0).join(key)}"

            @classmethod
            def _attribute_container_key(cls, name: str) -> tuple[str, ...] | None:
                if not name.startswith(cls._ATTRIBUTE_CONTAINER_MARKER):
                    return None
                return tuple(name.removeprefix(cls._ATTRIBUTE_CONTAINER_MARKER).split(chr(0)))

            @classmethod
            def _attribute_function_name(cls, key: tuple[str, ...]) -> str:
                return f"{cls._ATTRIBUTE_FUNCTION_MARKER}{chr(0).join(key)}"

            @classmethod
            def _attribute_function_key(cls, name: str) -> tuple[str, ...] | None:
                if not name.startswith(cls._ATTRIBUTE_FUNCTION_MARKER):
                    return None
                return tuple(name.removeprefix(cls._ATTRIBUTE_FUNCTION_MARKER).split(chr(0)))

            def _lookup_constant_strings(self, name: str) -> set[str]:
                marker_prefix = self._constant_string_marker_prefix(name)
                for index in self._visible_scope_indexes():
                    if name in self.alias_scopes[index]:
                        return {
                            marker.removeprefix(marker_prefix)
                            for marker in self.builtins_module_aliases[index]
                            if marker.startswith(marker_prefix)
                        }
                return set()

            def _lookup_callback_invoker(self, name: str) -> str | None:
                marker_prefix = self._callback_invoker_marker_prefix(name)
                for index in self._visible_scope_indexes():
                    if name in self.alias_scopes[index]:
                        return next(
                            (
                                marker.removeprefix(marker_prefix)
                                for marker in self.builtins_module_aliases[index]
                                if marker.startswith(marker_prefix)
                            ),
                            None,
                        )
                return None

            def _resolve_callback_invoker(self, node: ast.AST) -> str | None:
                if return_binding := self._function_return_binding(node):
                    return return_binding[6]
                if not isinstance(node, ast.Name):
                    return None
                helper = self._resolve_builtin_helper(node)
                if helper in {"filter", "map", "max", "min", "sorted"}:
                    return helper
                return self._lookup_callback_invoker(node.id)

            def _resolve_builtin_helper(self, node: ast.AST) -> str | None:
                if return_binding := self._function_return_binding(node):
                    return return_binding[5]
                if not isinstance(node, ast.Name):
                    return None
                marker_prefix = self._builtin_helper_marker_prefix(node.id)
                for index in self._visible_scope_indexes():
                    if node.id not in self.alias_scopes[index]:
                        continue
                    return next(
                        (
                            marker.removeprefix(marker_prefix)
                            for marker in self.builtins_module_aliases[index]
                            if marker.startswith(marker_prefix)
                        ),
                        None,
                    )
                return node.id if node.id in _PYTHON_BUILTIN_NAMES else None

            def _is_builtin_helper(self, node: ast.AST, name: str) -> bool:
                return self._resolve_builtin_helper(node) == name

            def _is_class_name(self, node: ast.AST) -> bool:
                if not isinstance(node, ast.Name):
                    return False
                for index in self._visible_scope_indexes():
                    if node.id in self.alias_scopes[index]:
                        return self._class_marker(node.id) in self.builtins_module_aliases[index]
                return False

            @staticmethod
            def _has_named_decorator(
                node: ast.FunctionDef | ast.AsyncFunctionDef,
                name: str,
            ) -> bool:
                return any(
                    (isinstance(decorator, ast.Name) and decorator.id == name)
                    or (isinstance(decorator, ast.Attribute) and decorator.attr == name)
                    for decorator in node.decorator_list
                )

            @classmethod
            def _json_value_payload(cls, value: object) -> object:
                if isinstance(value, bytes):
                    return {"type": "bytes", "value": value.hex()}
                if value is Ellipsis:
                    return {"type": "ellipsis"}
                if isinstance(value, complex):
                    return {"type": "complex", "real": value.real, "imag": value.imag}
                if isinstance(value, tuple):
                    return {"type": "tuple", "items": [cls._json_value_payload(item) for item in value]}
                return value

            @classmethod
            def _json_value_from_payload(cls, value: object) -> object:
                if isinstance(value, list):
                    return tuple(cls._json_value_from_payload(item) for item in value)
                if not isinstance(value, dict):
                    return value
                value_type = value.get("type")
                if value_type == "bytes":
                    return bytes.fromhex(str(value["value"]))
                if value_type == "ellipsis":
                    return Ellipsis
                if value_type == "complex":
                    return complex(float(value["real"]), float(value["imag"]))
                if value_type == "tuple":
                    return tuple(cls._json_value_from_payload(item) for item in value["items"])
                return value

            def _register_container_functions(
                self,
                name: str,
                functions: dict[tuple[object, ...], tuple[tuple[str, int], ...]],
                *,
                scope_index: int = -1,
            ) -> None:
                prefix = self._container_function_marker_prefix(name)
                self.builtins_module_aliases[scope_index] = {
                    marker for marker in self.builtins_module_aliases[scope_index] if not marker.startswith(prefix)
                }
                for path, callable_functions in functions.items():
                    payload = {
                        "path": [self._json_value_payload(item) for item in path],
                        "functions": [list(function) for function in callable_functions],
                    }
                    self.builtins_module_aliases[scope_index].add(
                        f"{prefix}{json.dumps(payload, sort_keys=True, separators=(',', ':'))}"
                    )

            def _lookup_container_functions(
                self,
                name: str,
            ) -> dict[tuple[object, ...], tuple[tuple[str, int], ...]]:
                prefix = self._container_function_marker_prefix(name)
                for index in self._visible_scope_indexes():
                    if name not in self.alias_scopes[index]:
                        continue
                    functions: dict[tuple[object, ...], tuple[tuple[str, int], ...]] = {}
                    for marker in self.builtins_module_aliases[index]:
                        if not marker.startswith(prefix):
                            continue
                        payload = json.loads(marker.removeprefix(prefix))
                        path = tuple(self._json_value_from_payload(item) for item in payload["path"])
                        functions[path] = tuple(
                            (str(function_id), int(positional_offset))
                            for function_id, positional_offset in payload["functions"]
                        )
                    return functions
                return {}

            @classmethod
            def _binding_payload(cls, binding: _BuiltinAliasBinding) -> dict[str, Any]:
                (
                    builtin,
                    builtins_module,
                    container_aliases,
                    constant_strings,
                    attribute_aliases,
                    builtin_helper,
                    callback_invoker,
                    callable_functions,
                ) = binding
                return {
                    "builtin": builtin,
                    "builtins_module": builtins_module,
                    "container_aliases": [
                        [[cls._json_value_payload(item) for item in path], nested_builtin]
                        for path, nested_builtin in container_aliases.items()
                    ],
                    "constant_strings": sorted(constant_strings),
                    "attribute_aliases": [
                        [list(path), nested_builtin] for path, nested_builtin in attribute_aliases.items()
                    ],
                    "builtin_helper": builtin_helper,
                    "callback_invoker": callback_invoker,
                    "callable_functions": [list(function) for function in callable_functions],
                }

            @classmethod
            def _binding_from_payload(cls, payload: dict[str, Any]) -> _BuiltinAliasBinding:
                return (
                    payload.get("builtin"),
                    bool(payload.get("builtins_module")),
                    {
                        tuple(cls._json_value_from_payload(item) for item in path): builtin
                        for path, builtin in payload.get("container_aliases", [])
                    },
                    set(payload.get("constant_strings", [])),
                    {
                        tuple(str(item) for item in path): builtin
                        for path, builtin in payload.get("attribute_aliases", [])
                    },
                    payload.get("builtin_helper"),
                    payload.get("callback_invoker"),
                    tuple(
                        (str(function_id), int(positional_offset))
                        for function_id, positional_offset in payload.get("callable_functions", [])
                    ),
                )

            def _register_function_summary(
                self,
                function_name: str,
                summary: _FunctionAliasSummary,
                *,
                scope_index: int = -1,
            ) -> None:
                prefix = self._function_effect_marker_prefix(function_name)
                self.builtins_module_aliases[scope_index] = {
                    marker for marker in self.builtins_module_aliases[scope_index] if not marker.startswith(prefix)
                }
                effects, return_binding, functions = summary
                payload = {
                    "effects": [
                        {
                            "kind": kind,
                            "name": name,
                            "binding": self._binding_payload(binding),
                        }
                        for kind, name, binding in effects
                    ],
                    "return_binding": (self._binding_payload(return_binding) if return_binding is not None else None),
                    "functions": [list(function) for function in functions],
                }
                self.builtins_module_aliases[scope_index].add(
                    f"{prefix}{json.dumps(payload, sort_keys=True, separators=(',', ':'))}"
                )

            def _lookup_function_summary(self, name: str) -> tuple[int, _FunctionAliasSummary | None]:
                prefix = self._function_effect_marker_prefix(name)
                for index in self._visible_scope_indexes():
                    if name not in self.alias_scopes[index]:
                        continue
                    effect_bindings: dict[tuple[str, str], list[_BuiltinAliasBinding]] = {}
                    return_bindings: list[_BuiltinAliasBinding] = []
                    functions: set[tuple[str, int]] = set()
                    for marker in self.builtins_module_aliases[index]:
                        if marker.startswith(prefix):
                            payload = json.loads(marker.removeprefix(prefix))
                            for effect in payload.get("effects", []):
                                effect_bindings.setdefault((effect["kind"], effect["name"]), []).append(
                                    self._binding_from_payload(effect["binding"])
                                )
                            return_payload = payload.get("return_binding")
                            if return_payload is not None:
                                return_bindings.append(self._binding_from_payload(return_payload))
                            functions.update(
                                (str(function_id), int(positional_offset))
                                for function_id, positional_offset in payload.get("functions", [])
                            )
                    if effect_bindings or return_bindings or functions:
                        effects = [
                            (kind, target_name, binding)
                            for (kind, target_name), bindings in effect_bindings.items()
                            if (binding := self._merge_bindings(bindings)) is not None
                        ]
                        return index, (
                            effects,
                            self._merge_bindings(return_bindings),
                            tuple(sorted(functions)),
                        )
                    return index, None
                return -1, None

            def _function_summary_for_node(self, node: ast.AST) -> _FunctionAliasSummary | None:
                if isinstance(node, ast.Name):
                    return self._lookup_function_summary(node.id)[1]
                if isinstance(node, ast.Attribute):
                    attribute_key = self._attribute_alias_key(node)
                    if attribute_key is not None:
                        return self._lookup_function_summary(self._attribute_function_name(attribute_key))[1]
                if isinstance(node, ast.Subscript):
                    key_resolved, key = self._constant_container_key(node.slice)
                    if key_resolved:
                        container = self._resolve_function_container(node.value)
                        functions = {
                            function
                            for prefix in self._container_access_prefixes(container, (key,))
                            for function in container.get(prefix, ())
                        }
                        if functions:
                            return [], None, tuple(sorted(functions))
                if isinstance(node, ast.Lambda):
                    return self.lambda_summaries.get(id(node))
                if isinstance(node, ast.Call):
                    callee_summary = self._function_summary_for_node(node.func)
                    if callee_summary is not None and callee_summary[1] is not None:
                        callable_functions = callee_summary[1][7]
                        if callable_functions:
                            return [], None, callable_functions
                return None

            def _function_return_binding(self, node: ast.AST) -> _BuiltinAliasBinding | None:
                if not isinstance(node, ast.Call):
                    return None
                summary = self._function_summary_for_node(node.func)
                return summary[1] if summary is not None else None

            def _property_return_binding(self, node: ast.AST) -> _BuiltinAliasBinding | None:
                if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Call):
                    return None
                summary = self._function_summary_for_node(node)
                if summary is None:
                    return None
                if any(
                    isinstance(
                        function_node := self.function_nodes.get(function_id),
                        (ast.FunctionDef, ast.AsyncFunctionDef),
                    )
                    and self._has_named_decorator(function_node, "property")
                    for function_id, _positional_offset in summary[2]
                ):
                    return summary[1]
                return None

            def _binding_from_expression(self, node: ast.AST) -> _BuiltinAliasBinding:
                return (
                    self._resolve_builtin(node),
                    self._is_builtins_namespace(node),
                    self._resolve_builtin_container(node),
                    self._constant_strings(node),
                    self._resolve_attribute_aliases(node),
                    self._resolve_builtin_helper(node),
                    self._resolve_callback_invoker(node),
                    (summary[2] if (summary := self._function_summary_for_node(node)) is not None else ()),
                )

            @staticmethod
            def _binding_has_tracked_value(binding: _BuiltinAliasBinding) -> bool:
                return any(
                    (
                        binding[0] is not None,
                        binding[1],
                        bool(binding[2]),
                        bool(binding[3]),
                        bool(binding[4]),
                        binding[5] is not None,
                        binding[6] is not None,
                        bool(binding[7]),
                    )
                )

            def _binding_from_name(self, name: str, scope_index: int) -> _BuiltinAliasBinding:
                marker_prefix = self._constant_string_marker_prefix(name)
                return (
                    self.alias_scopes[scope_index].get(name),
                    name in self.builtins_module_aliases[scope_index],
                    dict(self.container_alias_scopes[scope_index].get(name, {})),
                    {
                        marker.removeprefix(marker_prefix)
                        for marker in self.builtins_module_aliases[scope_index]
                        if marker.startswith(marker_prefix)
                    },
                    {
                        key[1:]: builtin
                        for key, builtin in self.attribute_alias_scopes[scope_index].items()
                        if key and key[0] == name
                    },
                    next(
                        (
                            marker.removeprefix(self._builtin_helper_marker_prefix(name))
                            for marker in self.builtins_module_aliases[scope_index]
                            if marker.startswith(self._builtin_helper_marker_prefix(name))
                        ),
                        None,
                    ),
                    self._lookup_callback_invoker(name),
                    (summary[2] if (summary := self._lookup_function_summary(name)[1]) is not None else ()),
                )

            def _merge_bindings(self, bindings: list[_BuiltinAliasBinding]) -> _BuiltinAliasBinding | None:
                if not bindings:
                    return None
                merged_attributes: dict[tuple[str, ...], str | None] = {}
                for binding in bindings:
                    for path, builtin in binding[4].items():
                        if builtin is not None or path not in merged_attributes:
                            merged_attributes[path] = builtin
                return (
                    next((binding[0] for binding in bindings if binding[0] is not None), None),
                    any(binding[1] for binding in bindings),
                    self._merge_container_aliases(*(binding[2] for binding in bindings)),
                    set().union(*(binding[3] for binding in bindings)),
                    merged_attributes,
                    next((binding[5] for binding in bindings if binding[5] is not None), None),
                    next((binding[6] for binding in bindings if binding[6] is not None), None),
                    tuple(sorted(set().union(*(set(binding[7]) for binding in bindings)))),
                )

            def _apply_binding(self, name: str, binding: _BuiltinAliasBinding, *, scope_index: int) -> None:
                (
                    builtin,
                    builtins_module,
                    container_aliases,
                    constant_strings,
                    attribute_aliases,
                    builtin_helper,
                    callback_invoker,
                    callable_functions,
                ) = binding
                self._bind_name(
                    name,
                    builtin,
                    builtins_module=builtins_module,
                    container_aliases=container_aliases,
                    container_identity=self._new_container_identity() if container_aliases else None,
                    constant_strings=constant_strings,
                    builtin_helper=builtin_helper,
                    callback_invoker=callback_invoker,
                    scope_index=scope_index,
                )
                self.attribute_alias_scopes[scope_index].update(
                    {(name, *path): nested_builtin for path, nested_builtin in attribute_aliases.items()}
                )
                if callable_functions:
                    self._register_function_summary(
                        name,
                        ([], None, callable_functions),
                        scope_index=scope_index,
                    )

            def _apply_function_effects(self, node: ast.AST) -> None:
                if not isinstance(node, ast.Name):
                    return
                owner_index, summary = self._lookup_function_summary(node.id)
                if summary is None:
                    return
                effects, _return_binding, _functions = summary
                for kind, target_name, binding in effects:
                    target_scope = 0 if kind == "global" else owner_index
                    if kind == "global_delete":
                        self._remove_name_binding(target_name, scope_index=0)
                    else:
                        self._apply_binding(target_name, binding, scope_index=target_scope)

            def _is_functools_partial(self, node: ast.AST) -> bool:
                if isinstance(node, ast.Name):
                    return self._has_binding_marker(node.id, self._FUNCTOOLS_PARTIAL_MARKER)
                return (
                    isinstance(node, ast.Attribute)
                    and node.attr == "partial"
                    and isinstance(node.value, ast.Name)
                    and self._has_binding_marker(node.value.id, self._FUNCTOOLS_MODULE_MARKER)
                )

            def _is_builtins_module(self, node: ast.AST) -> bool:
                if isinstance(node, ast.Name):
                    return self._is_builtins_module_name(node.id)
                if isinstance(node, ast.Subscript) and self._is_runtime_namespace(node.value):
                    return "__builtins__" in self._constant_strings(node.slice)
                if (
                    isinstance(node, ast.Call)
                    and node.args
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"get", "__getitem__"}
                    and self._is_runtime_namespace(node.func.value)
                ):
                    return "__builtins__" in self._constant_strings(node.args[0])
                return False

            def _lookup_container_alias(self, name: str) -> dict[tuple[object, ...], str | None]:
                for index in self._visible_scope_indexes():
                    if name in self.alias_scopes[index]:
                        return self.container_alias_scopes[index].get(name, {})
                return {}

            def _lookup_container_identity(self, name: str) -> int | None:
                for index in self._visible_scope_indexes():
                    if name in self.alias_scopes[index]:
                        return self.container_identity_scopes[index].get(name)
                return None

            def _lookup_attribute_container(
                self,
                key: tuple[str, ...],
            ) -> dict[tuple[object, ...], str | None]:
                root_name = key[0]
                synthetic_name = self._attribute_container_name(key)
                for index in self._visible_scope_indexes():
                    container = self.container_alias_scopes[index].get(synthetic_name)
                    if container is not None:
                        return dict(container)
                    if root_name in self.alias_scopes[index]:
                        return {}
                return {}

            def _resolve_attribute_containers(
                self,
                node: ast.AST,
            ) -> dict[tuple[str, ...], dict[tuple[object, ...], str | None]]:
                key = self._attribute_alias_key(node)
                if key is None:
                    return {}
                root_name = key[0]
                for index in self._visible_scope_indexes():
                    containers = {
                        attribute_key[len(key) :]: dict(container)
                        for name, container in self.container_alias_scopes[index].items()
                        if (attribute_key := self._attribute_container_key(name)) is not None
                        and len(attribute_key) > len(key)
                        and attribute_key[: len(key)] == key
                    }
                    if containers:
                        return containers
                    if root_name in self.alias_scopes[index]:
                        return {}
                return {}

            def _resolve_attribute_function_summaries(
                self,
                node: ast.AST,
            ) -> dict[tuple[str, ...], _FunctionAliasSummary]:
                key = self._attribute_alias_key(node)
                if key is None:
                    return {}
                root_name = key[0]
                for index in self._visible_scope_indexes():
                    summaries = {
                        attribute_key[len(key) :]: summary
                        for name in self.alias_scopes[index]
                        if (attribute_key := self._attribute_function_key(name)) is not None
                        and len(attribute_key) > len(key)
                        and attribute_key[: len(key)] == key
                        and (summary := self._lookup_function_summary(name)[1]) is not None
                    }
                    if summaries:
                        return summaries
                    if root_name in self.alias_scopes[index]:
                        return {}
                return {}

            def _new_container_identity(self) -> int:
                identity = self.next_container_identity
                self.next_container_identity += 1
                return identity

            def _container_expression_identity(self, node: ast.AST) -> int | None:
                if isinstance(node, ast.Name):
                    return self._lookup_container_identity(node.id)
                if return_binding := self._function_return_binding(node):
                    return self._new_container_identity() if return_binding[2] else None
                if isinstance(node, ast.NamedExpr):
                    return self._container_expression_identity(node.value)
                if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
                    return self._new_container_identity()
                if isinstance(node, ast.IfExp):
                    truth = self._constant_truth(node.test)
                    if truth is True:
                        return self._container_expression_identity(node.body)
                    if truth is False:
                        return self._container_expression_identity(node.orelse)
                return None

            @classmethod
            def _sequence_index_element(cls, index: int, length: int) -> tuple[str, int, int]:
                return cls._SEQUENCE_INDEX_MARKER, index, length

            @classmethod
            def _container_path_element_matches(cls, element: object, key: object) -> bool:
                if (
                    isinstance(element, tuple)
                    and len(element) == 3
                    and element[0] == cls._SEQUENCE_INDEX_MARKER
                    and isinstance(element[1], int)
                    and isinstance(element[2], int)
                    and isinstance(key, int)
                ):
                    index = key if key >= 0 else element[2] + key
                    return element[1] == index
                return element == key

            @classmethod
            def _container_access_prefixes(
                cls,
                container: Mapping[tuple[object, ...], object],
                keys: tuple[object, ...],
            ) -> tuple[tuple[object, ...], ...]:
                prefixes: set[tuple[object, ...]] = {()}
                for key in keys:
                    next_prefixes = {
                        (*prefix, path[len(prefix)])
                        for prefix in prefixes
                        for path in container
                        if len(path) > len(prefix)
                        and path[: len(prefix)] == prefix
                        and cls._container_path_element_matches(path[len(prefix)], key)
                    }
                    if not next_prefixes:
                        return ()
                    prefixes = next_prefixes
                return tuple(sorted(prefixes, key=repr))

            @staticmethod
            def _merge_container_aliases(
                *containers: dict[tuple[object, ...], str | None],
            ) -> dict[tuple[object, ...], str | None]:
                merged: dict[tuple[object, ...], str | None] = {}
                for container in containers:
                    for path, builtin in container.items():
                        if builtin is not None or path not in merged:
                            merged[path] = builtin
                return merged

            def _constant_container_key(self, node: ast.AST) -> tuple[bool, object]:
                if isinstance(node, ast.Constant):
                    try:
                        hash(node.value)
                    except TypeError:
                        return False, None
                    return True, node.value
                if (
                    isinstance(node, ast.UnaryOp)
                    and isinstance(node.op, (ast.UAdd, ast.USub))
                    and isinstance(node.operand, ast.Constant)
                    and isinstance(node.operand.value, (int, float, complex))
                ):
                    value = node.operand.value
                    return True, value if isinstance(node.op, ast.UAdd) else -value
                constant_strings = self._constant_strings(node)
                if len(constant_strings) == 1:
                    return True, next(iter(constant_strings))
                return False, None

            def _resolve_builtin_container(self, node: ast.AST) -> dict[tuple[object, ...], str | None]:
                if return_binding := self._function_return_binding(node):
                    return dict(return_binding[2])
                if isinstance(node, ast.Name):
                    return dict(self._lookup_container_alias(node.id))
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Call):
                        _attributes, containers = self._constructor_call_instance_bindings(node.value)
                        if (container := containers.get((node.attr,))) is not None:
                            return dict(container)
                    attribute_key = self._attribute_alias_key(node)
                    return self._lookup_attribute_container(attribute_key) if attribute_key is not None else {}
                if isinstance(node, ast.NamedExpr):
                    return self._resolve_builtin_container(node.value)
                if isinstance(node, (ast.List, ast.Tuple)):
                    resolved: dict[tuple[object, ...], str | None] = {}
                    for index, element in enumerate(node.elts):
                        item = self._sequence_index_element(index, len(node.elts))
                        resolved[(item,)] = self._resolve_builtin(element)
                        nested = self._resolve_builtin_container(element)
                        for path, builtin in nested.items():
                            resolved[(item, *path)] = builtin
                    return resolved
                if isinstance(node, ast.Dict):
                    resolved = {}
                    for key_node, value_node in zip(node.keys, node.values, strict=True):
                        if key_node is None:
                            continue
                        key_resolved, key = self._constant_container_key(key_node)
                        builtin = self._resolve_builtin(value_node)
                        if key_resolved:
                            resolved[(key,)] = builtin
                            for path, nested_builtin in self._resolve_builtin_container(value_node).items():
                                resolved[(key, *path)] = nested_builtin
                    return resolved
                if isinstance(node, ast.Subscript):
                    key_resolved, key = self._constant_container_key(node.slice)
                    if not key_resolved:
                        return {}
                    container = self._resolve_builtin_container(node.value)
                    prefixes = self._container_access_prefixes(container, (key,))
                    if not prefixes:
                        return {}
                    nested_containers = [
                        {
                            path[len(prefix) :]: builtin
                            for path, builtin in container.items()
                            if len(path) > len(prefix) and path[: len(prefix)] == prefix
                        }
                        for prefix in prefixes
                    ]
                    return self._merge_container_aliases(*nested_containers)
                if isinstance(node, ast.IfExp):
                    truth = self._constant_truth(node.test)
                    if truth is True:
                        return self._resolve_builtin_container(node.body)
                    if truth is False:
                        return self._resolve_builtin_container(node.orelse)
                    return self._merge_container_aliases(
                        self._resolve_builtin_container(node.orelse),
                        self._resolve_builtin_container(node.body),
                    )
                return {}

            def _resolve_function_container(
                self,
                node: ast.AST,
            ) -> dict[tuple[object, ...], tuple[tuple[str, int], ...]]:
                if isinstance(node, ast.Name):
                    return dict(self._lookup_container_functions(node.id))
                if isinstance(node, ast.NamedExpr):
                    return self._resolve_function_container(node.value)
                if isinstance(node, (ast.List, ast.Tuple)):
                    resolved: dict[tuple[object, ...], tuple[tuple[str, int], ...]] = {}
                    for index, element in enumerate(node.elts):
                        item = self._sequence_index_element(index, len(node.elts))
                        if summary := self._function_summary_for_node(element):
                            resolved[(item,)] = summary[2]
                        for path, functions in self._resolve_function_container(element).items():
                            resolved[(item, *path)] = functions
                    return resolved
                if isinstance(node, ast.Dict):
                    resolved = {}
                    for key_node, value_node in zip(node.keys, node.values, strict=True):
                        if key_node is None:
                            continue
                        key_resolved, key = self._constant_container_key(key_node)
                        if not key_resolved:
                            continue
                        if summary := self._function_summary_for_node(value_node):
                            resolved[(key,)] = summary[2]
                        for path, functions in self._resolve_function_container(value_node).items():
                            resolved[(key, *path)] = functions
                    return resolved
                if isinstance(node, ast.Subscript):
                    key_resolved, key = self._constant_container_key(node.slice)
                    if not key_resolved:
                        return {}
                    container = self._resolve_function_container(node.value)
                    prefixes = self._container_access_prefixes(container, (key,))
                    return {
                        path[len(prefix) :]: functions
                        for prefix in prefixes
                        for path, functions in container.items()
                        if len(path) > len(prefix) and path[: len(prefix)] == prefix
                    }
                if isinstance(node, ast.IfExp):
                    truth = self._constant_truth(node.test)
                    if truth is True:
                        return self._resolve_function_container(node.body)
                    if truth is False:
                        return self._resolve_function_container(node.orelse)
                    return {
                        **self._resolve_function_container(node.orelse),
                        **self._resolve_function_container(node.body),
                    }
                return {}

            @staticmethod
            def _attribute_alias_key(node: ast.AST) -> tuple[str, ...] | None:
                if isinstance(node, ast.Name):
                    return (node.id,)
                if isinstance(node, ast.Attribute):
                    parent = DangerousBuiltinCallVisitor._attribute_alias_key(node.value)
                    return (*parent, node.attr) if parent is not None else None
                if isinstance(node, ast.Call):
                    return DangerousBuiltinCallVisitor._attribute_alias_key(node.func)
                return None

            def _container_target_path(self, node: ast.Subscript) -> tuple[str, tuple[object, ...]] | None:
                path: list[object] = []
                current: ast.AST = node
                while isinstance(current, ast.Subscript):
                    key_resolved, key = self._constant_container_key(current.slice)
                    if not key_resolved:
                        return None
                    path.append(key)
                    current = current.value
                if not isinstance(current, ast.Name):
                    return None
                return current.id, tuple(reversed(path))

            def _lookup_attribute_alias(self, node: ast.Attribute) -> tuple[bool, str | None]:
                key = self._attribute_alias_key(node)
                if key is None:
                    return False, None
                root_name = key[0]
                for index in self._visible_scope_indexes():
                    aliases = self.attribute_alias_scopes[index]
                    if key in aliases:
                        return True, aliases[key]
                    if root_name in self.alias_scopes[index]:
                        return False, None
                return False, None

            def _resolve_attribute_aliases(self, node: ast.AST) -> dict[tuple[str, ...], str | None]:
                if (return_binding := self._function_return_binding(node)) and return_binding[4]:
                    return dict(return_binding[4])
                if isinstance(node, ast.Call):
                    attributes, _containers = self._constructor_call_instance_bindings(node)
                    if attributes:
                        return attributes
                key = self._attribute_alias_key(node)
                if key is None:
                    return {}
                root_name = key[0]
                for index in self._visible_scope_indexes():
                    aliases = {
                        alias_key[len(key) :]: builtin
                        for alias_key, builtin in self.attribute_alias_scopes[index].items()
                        if len(alias_key) > len(key) and alias_key[: len(key)] == key
                    }
                    if aliases:
                        return aliases
                    if root_name in self.alias_scopes[index]:
                        return {}
                return {}

            def _attribute_dictionary_target_key(self, node: ast.Subscript) -> tuple[str, ...] | None:
                attribute_name = self._constant_string(node.slice)
                if attribute_name is None:
                    return None
                target = node.value
                if isinstance(target, ast.Attribute) and target.attr == "__dict__":
                    root = self._attribute_alias_key(target.value)
                    return (*root, attribute_name) if root is not None else None
                if (
                    isinstance(target, ast.Call)
                    and self._is_builtin_helper(target.func, "vars")
                    and len(target.args) == 1
                    and not target.keywords
                ):
                    root = self._attribute_alias_key(target.args[0])
                    return (*root, attribute_name) if root is not None else None
                return None

            def _runtime_global_target_name(self, node: ast.Subscript) -> str | None:
                if (
                    self.scope_kinds[-1] == "module"
                    and isinstance(node.value, ast.Call)
                    and any(self._is_builtin_helper(node.value.func, name) for name in ("globals", "locals"))
                    and not node.value.args
                    and not node.value.keywords
                ):
                    return self._constant_string(node.slice)
                return None

            def _runtime_namespace_binding(self, node: ast.Subscript) -> str | None:
                if not isinstance(node.value, ast.Call):
                    return None
                target_name = self._constant_string(node.slice)
                if target_name is None:
                    return None
                if self._is_builtin_helper(node.value.func, "globals"):
                    return self.alias_scopes[0].get(target_name)
                if self.scope_kinds[-1] == "module" and self._is_builtin_helper(node.value.func, "locals"):
                    return self.alias_scopes[0].get(target_name)
                return None

            def _is_runtime_namespace(self, node: ast.AST) -> bool:
                return (
                    isinstance(node, ast.Call)
                    and any(self._is_builtin_helper(node.func, name) for name in ("globals", "locals"))
                    and not node.args
                    and not node.keywords
                )

            def _is_builtins_namespace(self, node: ast.AST) -> bool:
                if return_binding := self._function_return_binding(node):
                    return return_binding[1]
                if isinstance(node, ast.NamedExpr):
                    return self._is_builtins_namespace(node.value)
                if isinstance(node, ast.IfExp):
                    truth = self._constant_truth(node.test)
                    if truth is True:
                        return self._is_builtins_namespace(node.body)
                    if truth is False:
                        return self._is_builtins_namespace(node.orelse)
                    return self._is_builtins_namespace(node.body) or self._is_builtins_namespace(node.orelse)
                if isinstance(node, ast.BoolOp):
                    if isinstance(node.op, ast.Or):
                        for value in node.values:
                            if self._is_builtins_namespace(value):
                                return True
                            if self._known_truth(value) is True:
                                return False
                        return False
                    for value in node.values[:-1]:
                        if self._known_truth(value) is False:
                            return self._is_builtins_namespace(value)
                    return self._is_builtins_namespace(node.values[-1])
                return (
                    self._is_builtins_module(node)
                    or (
                        isinstance(node, ast.Attribute)
                        and node.attr == "__dict__"
                        and self._is_builtins_module(node.value)
                    )
                    or (
                        isinstance(node, ast.Call)
                        and self._is_builtin_helper(node.func, "vars")
                        and len(node.args) == 1
                        and self._is_builtins_module(node.args[0])
                    )
                    or (
                        isinstance(node, ast.Call)
                        and len(node.args) >= 2
                        and self._is_builtin_helper(node.func, "getattr")
                        and self._is_builtins_module(node.args[0])
                        and "__dict__" in self._constant_strings(node.args[1])
                    )
                )

            def _constant_strings(self, node: ast.AST) -> set[str]:
                if return_binding := self._function_return_binding(node):
                    return set(return_binding[3])
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    return {node.value}
                if isinstance(node, ast.Name):
                    return self._lookup_constant_strings(node.id)
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    combined: set[str] = set()
                    for left in self._constant_strings(node.left):
                        for right in self._constant_strings(node.right):
                            combined.add(left + right)
                            if len(combined) >= self._MAX_CONSTANT_STRING_CANDIDATES:
                                return combined
                    return combined
                if isinstance(node, ast.IfExp):
                    truth = self._constant_truth(node.test)
                    if truth is True:
                        return self._constant_strings(node.body)
                    if truth is False:
                        return self._constant_strings(node.orelse)
                    return {
                        *self._constant_strings(node.body),
                        *self._constant_strings(node.orelse),
                    }
                return set()

            def _constant_string(self, node: ast.AST) -> str | None:
                candidates = self._constant_strings(node)
                return next(iter(candidates)) if len(candidates) == 1 else None

            def _dangerous_constant_string(self, node: ast.AST) -> str | None:
                candidates = self._constant_strings(node)
                return next((name for name in dangerous_builtins if name in candidates), None)

            def _resolve_builtin(self, node: ast.AST) -> str | None:
                if isinstance(node, ast.Name):
                    return self._lookup_alias(node.id)
                if isinstance(node, ast.NamedExpr):
                    return self._resolve_builtin(node.value)
                if isinstance(node, ast.IfExp):
                    truth = self._constant_truth(node.test)
                    if truth is True:
                        return self._resolve_builtin(node.body)
                    if truth is False:
                        return self._resolve_builtin(node.orelse)
                    return self._resolve_builtin(node.body) or self._resolve_builtin(node.orelse)
                if isinstance(node, ast.BoolOp):
                    if isinstance(node.op, ast.Or):
                        for value in node.values:
                            if builtin := self._resolve_builtin(value):
                                return builtin
                            if self._known_truth(value) is True:
                                return None
                        return None
                    for value in node.values[:-1]:
                        if self._known_truth(value) is False:
                            return None
                    return self._resolve_builtin(node.values[-1])
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Call):
                        attributes, _containers = self._constructor_call_instance_bindings(node.value)
                        if (node.attr,) in attributes:
                            return attributes[(node.attr,)]
                    if (property_binding := self._property_return_binding(node)) is not None and property_binding[
                        0
                    ] is not None:
                        return property_binding[0]
                    alias_found, alias = self._lookup_attribute_alias(node)
                    if alias_found:
                        return alias
                    if node.attr in dangerous_builtins and self._is_builtins_namespace(node.value):
                        return node.attr
                    if node.attr == "__call__":
                        return self._resolve_builtin(node.value)
                if isinstance(node, ast.Subscript):
                    if runtime_binding := self._runtime_namespace_binding(node):
                        return runtime_binding
                    if self._is_builtins_namespace(node.value):
                        return self._dangerous_constant_string(node.slice)
                    key_resolved, key = self._constant_container_key(node.slice)
                    if key_resolved:
                        container = self._resolve_builtin_container(node.value)
                        prefixes = self._container_access_prefixes(container, (key,))
                        return next(
                            (builtin for prefix in prefixes if (builtin := container.get(prefix)) is not None),
                            None,
                        )
                if isinstance(node, ast.Call):
                    if (return_binding := self._function_return_binding(node)) and return_binding[0] is not None:
                        return return_binding[0]
                    if self._is_functools_partial(node.func) and node.args:
                        return self._resolve_builtin(node.args[0])
                    if len(node.args) >= 2 and self._is_builtin_helper(node.func, "getattr"):
                        names = self._constant_strings(node.args[1])
                        if "__call__" in names:
                            return self._resolve_builtin(node.args[0])
                        if self._is_builtins_namespace(node.args[0]):
                            return next((name for name in dangerous_builtins if name in names), None)
                    if (
                        node.args
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in {"get", "__getattribute__", "__getitem__", "pop"}
                        and self._is_builtins_namespace(node.func.value)
                    ):
                        return self._dangerous_constant_string(node.args[0])
                    if (
                        node.args
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "__getattribute__"
                        and "__call__" in self._constant_strings(node.args[0])
                    ):
                        return self._resolve_builtin(node.func.value)
                    if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "__getitem__", "pop"}:
                        container = self._resolve_builtin_container(node.func.value)
                        if node.args:
                            key_resolved, key = self._constant_container_key(node.args[0])
                        else:
                            key_resolved = node.func.attr == "pop" and any(
                                path
                                and isinstance(path[0], tuple)
                                and len(path[0]) == 3
                                and path[0][0] == self._SEQUENCE_INDEX_MARKER
                                for path in container
                            )
                            key = -1
                        if key_resolved:
                            prefixes = self._container_access_prefixes(container, (key,))
                            return next(
                                (builtin for prefix in prefixes if (builtin := container.get(prefix)) is not None),
                                None,
                            )
                    if (
                        len(node.args) >= 2
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "__getattribute__"
                        and self._is_builtin_helper(node.func.value, "object")
                    ):
                        if "__call__" in self._constant_strings(node.args[1]):
                            return self._resolve_builtin(node.args[0])
                        if not self._is_builtins_namespace(node.args[0]):
                            return None
                        return self._dangerous_constant_string(node.args[1])
                return None

            def _bind_name(
                self,
                name: str,
                builtin: str | None,
                *,
                builtins_module: bool = False,
                container_aliases: dict[tuple[object, ...], str | None] | None = None,
                container_identity: int | None = None,
                constant_strings: set[str] | None = None,
                callback_invoker: str | None = None,
                builtin_helper: str | None = None,
                container_functions: dict[tuple[object, ...], tuple[tuple[str, int], ...]] | None = None,
                defined: bool = True,
                scope_index: int = -1,
            ) -> None:
                self.alias_scopes[scope_index][name] = builtin
                self.container_alias_scopes[scope_index][name] = dict(container_aliases or {})
                self.container_identity_scopes[scope_index][name] = container_identity
                self.builtins_module_aliases[scope_index].discard(f"{self._FUNCTOOLS_MODULE_MARKER}{name}")
                self.builtins_module_aliases[scope_index].discard(f"{self._FUNCTOOLS_PARTIAL_MARKER}{name}")
                self.builtins_module_aliases[scope_index].discard(self._class_marker(name))
                self.builtins_module_aliases[scope_index].discard(self._global_delete_marker(name))
                constant_string_prefix = self._constant_string_marker_prefix(name)
                function_effect_prefix = self._function_effect_marker_prefix(name)
                callback_invoker_prefix = self._callback_invoker_marker_prefix(name)
                builtin_helper_prefix = self._builtin_helper_marker_prefix(name)
                container_function_prefix = self._container_function_marker_prefix(name)
                self.builtins_module_aliases[scope_index] = {
                    marker
                    for marker in self.builtins_module_aliases[scope_index]
                    if not marker.startswith(constant_string_prefix)
                    and not marker.startswith(function_effect_prefix)
                    and not marker.startswith(callback_invoker_prefix)
                    and not marker.startswith(builtin_helper_prefix)
                    and not marker.startswith(container_function_prefix)
                }
                self.builtins_module_aliases[scope_index].update(
                    f"{constant_string_prefix}{value}" for value in (constant_strings or set())
                )
                if callback_invoker is not None:
                    self.builtins_module_aliases[scope_index].add(f"{callback_invoker_prefix}{callback_invoker}")
                if builtin_helper is not None:
                    self.builtins_module_aliases[scope_index].add(f"{builtin_helper_prefix}{builtin_helper}")
                if container_functions:
                    self._register_container_functions(
                        name,
                        container_functions,
                        scope_index=scope_index,
                    )
                attribute_aliases = self.attribute_alias_scopes[scope_index]
                for key in tuple(attribute_aliases):
                    if key[0] == name:
                        del attribute_aliases[key]
                for container_name in tuple(self.container_alias_scopes[scope_index]):
                    attribute_key = self._attribute_container_key(container_name)
                    if attribute_key is not None and attribute_key[0] == name:
                        del self.container_alias_scopes[scope_index][container_name]
                for alias_name in tuple(self.alias_scopes[scope_index]):
                    attribute_key = self._attribute_function_key(alias_name)
                    if attribute_key is not None and attribute_key[0] == name:
                        self._bind_name(alias_name, None, defined=False, scope_index=scope_index)
                        self.alias_scopes[scope_index].pop(alias_name, None)
                        self.container_alias_scopes[scope_index].pop(alias_name, None)
                        self.container_identity_scopes[scope_index].pop(alias_name, None)
                if defined:
                    self.defined_names[scope_index].add(name)
                else:
                    self.defined_names[scope_index].discard(name)
                if builtins_module:
                    self.builtins_module_aliases[scope_index].add(name)
                else:
                    self.builtins_module_aliases[scope_index].discard(name)

            def _bind_attribute_key(
                self,
                key: tuple[str, ...],
                builtin: str | None,
                *,
                container_aliases: dict[tuple[object, ...], str | None] | None = None,
                attribute_aliases: dict[tuple[str, ...], str | None] | None = None,
                function_summary: _FunctionAliasSummary | None = None,
                scope_index: int = -1,
            ) -> None:
                self.attribute_alias_scopes[scope_index][key] = builtin
                synthetic_name = self._attribute_container_name(key)
                self.container_alias_scopes[scope_index][synthetic_name] = dict(container_aliases or {})
                self.attribute_alias_scopes[scope_index].update(
                    {(*key, *path): nested_builtin for path, nested_builtin in (attribute_aliases or {}).items()}
                )
                function_name = self._attribute_function_name(key)
                self._bind_name(function_name, None, scope_index=scope_index)
                if function_summary is not None:
                    self._register_function_summary(
                        function_name,
                        function_summary,
                        scope_index=scope_index,
                    )

            def _remove_name_binding(self, name: str, *, scope_index: int = -1) -> None:
                self._bind_name(name, None, defined=False, scope_index=scope_index)
                self.alias_scopes[scope_index].pop(name, None)
                self.container_alias_scopes[scope_index].pop(name, None)
                self.container_identity_scopes[scope_index].pop(name, None)

            def _unbind_target(self, target: ast.AST) -> None:
                if isinstance(target, ast.Name):
                    if self.scope_kinds[-1] in {"class", "module"}:
                        self._remove_name_binding(target.id)
                    elif target.id in self.global_name_scopes[-1]:
                        self._bind_name(
                            target.id,
                            target.id if target.id in dangerous_builtins else None,
                            defined=False,
                        )
                        self.builtins_module_aliases[-1].add(self._global_delete_marker(target.id))
                    else:
                        self._bind_name(target.id, None, defined=False)
                elif isinstance(target, ast.Attribute):
                    attribute_key = self._attribute_alias_key(target)
                    if attribute_key is not None:
                        self._bind_attribute_key(attribute_key, None)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for element in target.elts:
                        self._unbind_target(element)

            def _bind_target(
                self,
                target: ast.AST,
                builtin: str | None,
                *,
                builtins_module: bool = False,
                container_aliases: dict[tuple[object, ...], str | None] | None = None,
                container_identity: int | None = None,
                constant_strings: set[str] | None = None,
                attribute_aliases: dict[tuple[str, ...], str | None] | None = None,
                callback_invoker: str | None = None,
                builtin_helper: str | None = None,
                container_functions: dict[tuple[object, ...], tuple[tuple[str, int], ...]] | None = None,
                function_summary: _FunctionAliasSummary | None = None,
                scope_index: int = -1,
            ) -> None:
                if isinstance(target, ast.Name):
                    self._bind_name(
                        target.id,
                        builtin,
                        builtins_module=builtins_module,
                        container_aliases=container_aliases,
                        container_identity=container_identity,
                        constant_strings=constant_strings,
                        callback_invoker=callback_invoker,
                        builtin_helper=builtin_helper,
                        container_functions=container_functions,
                        scope_index=scope_index,
                    )
                    self.attribute_alias_scopes[scope_index].update(
                        {
                            (target.id, *path): nested_builtin
                            for path, nested_builtin in (attribute_aliases or {}).items()
                        }
                    )
                    if function_summary is not None:
                        self._register_function_summary(
                            target.id,
                            function_summary,
                            scope_index=scope_index,
                        )
                elif isinstance(target, ast.Attribute):
                    attribute_key = self._attribute_alias_key(target)
                    if attribute_key is not None:
                        self._bind_attribute_key(
                            attribute_key,
                            builtin,
                            container_aliases=container_aliases,
                            attribute_aliases=attribute_aliases,
                            function_summary=function_summary,
                            scope_index=scope_index,
                        )
                elif isinstance(target, ast.Subscript):
                    attribute_key = self._attribute_dictionary_target_key(target)
                    runtime_global_name = self._runtime_global_target_name(target)
                    if attribute_key is not None:
                        self.attribute_alias_scopes[scope_index][attribute_key] = builtin
                    elif runtime_global_name is not None:
                        self._bind_name(
                            runtime_global_name,
                            builtin,
                            container_aliases=container_aliases,
                            constant_strings=constant_strings,
                            scope_index=0,
                        )
                    elif (target_path := self._container_target_path(target)) is not None:
                        container_name, raw_prefix = target_path
                        container = dict(self._lookup_container_alias(container_name))
                        function_container = dict(self._lookup_container_functions(container_name))
                        container_identity = self._lookup_container_identity(container_name)
                        prefixes = self._container_access_prefixes(container, raw_prefix) or (raw_prefix,)
                        container = {
                            path: value
                            for path, value in container.items()
                            if not any(path[: len(prefix)] == prefix for prefix in prefixes)
                        }
                        for prefix in prefixes:
                            container[prefix] = builtin
                            for path, nested_builtin in (container_aliases or {}).items():
                                container[(*prefix, *path)] = nested_builtin
                        function_prefixes = self._container_access_prefixes(function_container, raw_prefix) or prefixes
                        function_container = {
                            path: functions
                            for path, functions in function_container.items()
                            if not any(path[: len(prefix)] == prefix for prefix in function_prefixes)
                        }
                        if function_summary is not None:
                            for prefix in function_prefixes:
                                function_container[prefix] = function_summary[2]
                        if container_identity is not None:
                            for identity_index, (identity_scope, container_scope) in enumerate(
                                zip(
                                    self.container_identity_scopes,
                                    self.container_alias_scopes,
                                    strict=True,
                                )
                            ):
                                for name, identity in identity_scope.items():
                                    if identity == container_identity:
                                        container_scope[name] = dict(container)
                                        self._register_container_functions(
                                            name,
                                            function_container,
                                            scope_index=identity_index,
                                        )
                        else:
                            for index in self._visible_scope_indexes():
                                if container_name in self.alias_scopes[index]:
                                    self.container_alias_scopes[index][container_name] = container
                                    self._register_container_functions(
                                        container_name,
                                        function_container,
                                        scope_index=index,
                                    )
                                    break
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for element in target.elts:
                        self._bind_target(element, None, scope_index=scope_index)

            def _container_child_binding(
                self,
                container: dict[tuple[object, ...], str | None],
                key: object,
                *,
                sequence_only: bool = False,
            ) -> tuple[bool, str | None, dict[tuple[object, ...], str | None]]:
                prefixes = self._container_access_prefixes(container, (key,))
                if sequence_only:
                    prefixes = tuple(
                        prefix
                        for prefix in prefixes
                        if prefix
                        and isinstance(prefix[0], tuple)
                        and len(prefix[0]) == 3
                        and prefix[0][0] == self._SEQUENCE_INDEX_MARKER
                    )
                if not prefixes:
                    return False, None, {}
                builtin = next(
                    (candidate for prefix in prefixes if (candidate := container.get(prefix)) is not None),
                    None,
                )
                nested = self._merge_container_aliases(
                    *(
                        {
                            path[len(prefix) :]: candidate
                            for path, candidate in container.items()
                            if len(path) > len(prefix) and path[: len(prefix)] == prefix
                        }
                        for prefix in prefixes
                    )
                )
                return True, builtin, nested

            def _bind_destructured_target_from_container(
                self,
                target: ast.Tuple | ast.List,
                container: dict[tuple[object, ...], str | None],
                *,
                scope_index: int = -1,
            ) -> None:
                starred_index = next(
                    (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
                    None,
                )
                if starred_index is not None:
                    bindings: list[_BuiltinAliasBinding] = [
                        (builtin, False, nested, set(), {}, None, None, ())
                        for builtin, nested in self._sequence_container_element_bindings(container)
                    ]
                    trailing_count = len(target.elts) - starred_index - 1
                    for index, element in enumerate(target.elts[:starred_index]):
                        if index < len(bindings):
                            self._apply_binding_to_target(element, bindings[index], scope_index=scope_index)
                    remainder_end = len(bindings) - trailing_count if trailing_count else len(bindings)
                    starred = target.elts[starred_index]
                    assert isinstance(starred, ast.Starred)
                    self._apply_binding_to_target(
                        starred.value,
                        self._sequence_binding(bindings[starred_index:remainder_end]),
                        scope_index=scope_index,
                    )
                    for offset, element in enumerate(target.elts[starred_index + 1 :]):
                        binding_index = remainder_end + offset
                        if binding_index < len(bindings):
                            self._apply_binding_to_target(
                                element,
                                bindings[binding_index],
                                scope_index=scope_index,
                            )
                    return
                for index, element in enumerate(target.elts):
                    found, builtin, nested = self._container_child_binding(
                        container,
                        index,
                        sequence_only=True,
                    )
                    if not found:
                        self._bind_target(element, None, scope_index=scope_index)
                    elif isinstance(element, (ast.Tuple, ast.List)):
                        self._bind_destructured_target_from_container(
                            element,
                            nested,
                            scope_index=scope_index,
                        )
                    else:
                        self._bind_target(
                            element,
                            builtin,
                            container_aliases=nested,
                            scope_index=scope_index,
                        )

            def _apply_binding_to_target(
                self,
                target: ast.AST,
                binding: _BuiltinAliasBinding,
                *,
                scope_index: int = -1,
            ) -> None:
                if isinstance(target, (ast.Tuple, ast.List)):
                    self._bind_destructured_target_from_container(
                        target,
                        binding[2],
                        scope_index=scope_index,
                    )
                    return
                self._bind_target(
                    target,
                    binding[0],
                    builtins_module=binding[1],
                    container_aliases=binding[2],
                    constant_strings=binding[3],
                    attribute_aliases=binding[4],
                    builtin_helper=binding[5],
                    callback_invoker=binding[6],
                    function_summary=(([], None, binding[7]) if binding[7] else None),
                    scope_index=scope_index,
                )

            def _sequence_container_element_bindings(
                self,
                container: dict[tuple[object, ...], str | None],
            ) -> list[tuple[str | None, dict[tuple[object, ...], str | None]]]:
                sequence_indexes = sorted(
                    {
                        element[1]
                        for path in container
                        if path
                        and isinstance((element := path[0]), tuple)
                        and len(element) == 3
                        and element[0] == self._SEQUENCE_INDEX_MARKER
                        and isinstance(element[1], int)
                    }
                )
                bindings = []
                for index in sequence_indexes:
                    found, builtin, nested = self._container_child_binding(
                        container,
                        index,
                        sequence_only=True,
                    )
                    if found:
                        bindings.append((builtin, nested))
                return bindings

            def _bind_target_from_container_candidates(
                self,
                target: ast.AST,
                candidates: list[tuple[str | None, dict[tuple[object, ...], str | None]]],
            ) -> None:
                if isinstance(target, (ast.Tuple, ast.List)):
                    for index, element in enumerate(target.elts):
                        child_candidates = []
                        for _builtin, nested in candidates:
                            found, child_builtin, child_nested = self._container_child_binding(
                                nested,
                                index,
                                sequence_only=True,
                            )
                            if found:
                                child_candidates.append((child_builtin, child_nested))
                        if child_candidates:
                            self._bind_target_from_container_candidates(element, child_candidates)
                        else:
                            self._bind_target(element, None)
                    return
                self._bind_target(
                    target,
                    next((builtin for builtin, _nested in candidates if builtin is not None), None),
                    container_aliases=self._merge_container_aliases(*(nested for _builtin, nested in candidates)),
                )

            def _bind_target_from_value(self, target: ast.AST, value: ast.AST, *, scope_index: int = -1) -> None:
                if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
                    starred_index = next(
                        (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
                        None,
                    )
                    if starred_index is not None:
                        trailing_count = len(target.elts) - starred_index - 1
                        for index, element in enumerate(target.elts[:starred_index]):
                            if index < len(value.elts):
                                self._bind_target_from_value(element, value.elts[index], scope_index=scope_index)
                        remainder_end = len(value.elts) - trailing_count if trailing_count else len(value.elts)
                        starred = target.elts[starred_index]
                        assert isinstance(starred, ast.Starred)
                        self._apply_binding_to_target(
                            starred.value,
                            self._sequence_binding(
                                [
                                    self._binding_from_expression(element)
                                    for element in value.elts[starred_index:remainder_end]
                                ]
                            ),
                            scope_index=scope_index,
                        )
                        for offset, element in enumerate(target.elts[starred_index + 1 :]):
                            value_index = remainder_end + offset
                            if value_index < len(value.elts):
                                self._bind_target_from_value(
                                    element,
                                    value.elts[value_index],
                                    scope_index=scope_index,
                                )
                        return
                    for index, element in enumerate(target.elts):
                        if index < len(value.elts):
                            self._bind_target_from_value(element, value.elts[index], scope_index=scope_index)
                        else:
                            self._bind_target(element, None, scope_index=scope_index)
                    return
                if isinstance(target, (ast.Tuple, ast.List)):
                    container = self._resolve_builtin_container(value)
                    if container:
                        self._bind_destructured_target_from_container(
                            target,
                            container,
                            scope_index=scope_index,
                        )
                    else:
                        self._bind_target(target, None, scope_index=scope_index)
                    return

                class_alias = self._is_class_name(value)
                attribute_function_summaries = self._resolve_attribute_function_summaries(value)
                self._bind_target(
                    target,
                    self._resolve_builtin(value),
                    builtins_module=self._is_builtins_namespace(value),
                    container_aliases=self._resolve_builtin_container(value),
                    container_identity=self._container_expression_identity(value),
                    constant_strings=self._constant_strings(value),
                    attribute_aliases=self._resolve_attribute_aliases(value),
                    callback_invoker=self._resolve_callback_invoker(value),
                    builtin_helper=self._resolve_builtin_helper(value),
                    container_functions=self._resolve_function_container(value),
                    function_summary=self._function_summary_for_node(value),
                    scope_index=scope_index,
                )
                if isinstance(target, ast.Name):
                    if class_alias:
                        self.builtins_module_aliases[scope_index].add(self._class_marker(target.id))
                    for path, summary in attribute_function_summaries.items():
                        key = (target.id, *path)
                        self._bind_attribute_key(
                            key,
                            self.attribute_alias_scopes[scope_index].get(key),
                            function_summary=summary,
                            scope_index=scope_index,
                        )

            def _bind_target_from_values(self, target: ast.AST, values: list[ast.expr]) -> None:
                if isinstance(target, (ast.Tuple, ast.List)):
                    for index, element in enumerate(target.elts):
                        child_values = [
                            value.elts[index]
                            for value in values
                            if isinstance(value, (ast.Tuple, ast.List)) and index < len(value.elts)
                        ]
                        if child_values:
                            self._bind_target_from_values(element, child_values)
                        else:
                            self._bind_target(element, None)
                    return
                self._bind_target(
                    target,
                    next((builtin for value in values if (builtin := self._resolve_builtin(value))), None),
                    builtins_module=any(self._is_builtins_namespace(value) for value in values),
                    container_aliases=self._merge_container_aliases(
                        *(self._resolve_builtin_container(value) for value in values)
                    ),
                    constant_strings=set().union(*(self._constant_strings(value) for value in values)),
                )

            def _bind_loop_target_from_iterable(self, target: ast.AST, iterable: ast.AST) -> None:
                elements = self._literal_iterable_elements(iterable)
                if elements is None:
                    candidates = self._sequence_container_element_bindings(self._resolve_builtin_container(iterable))
                    if candidates:
                        self._bind_target_from_container_candidates(target, candidates)
                        return
                    self._bind_target(target, None)
                    return
                if len(elements) == 1:
                    self._bind_target_from_value(target, elements[0])
                    return
                self._bind_target_from_values(target, elements)

            @staticmethod
            def _literal_iterable_elements(node: ast.AST) -> list[ast.expr] | None:
                if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                    return node.elts
                if isinstance(node, ast.Dict):
                    return [key for key in node.keys if key is not None]
                return None

            @staticmethod
            def _constant_truth(node: ast.AST) -> bool | None:
                if isinstance(node, ast.Constant) and isinstance(node.value, (bool, int, str, bytes, type(None))):
                    return bool(node.value)
                return None

            def _constant_iterable_truth(self, node: ast.AST) -> bool | None:
                if (elements := self._literal_iterable_elements(node)) is not None:
                    return bool(elements)
                if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, tuple, frozenset)):
                    return bool(node.value)
                return None

            @staticmethod
            def _copy_alias_scopes(scopes: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
                return [dict(scope) for scope in scopes]

            @staticmethod
            def _copy_builtins_module_aliases(aliases: list[set[str]]) -> list[set[str]]:
                return [set(scope) for scope in aliases]

            @staticmethod
            def _copy_defined_names(defined_names: list[set[str]]) -> list[set[str]]:
                return [set(scope) for scope in defined_names]

            @staticmethod
            def _copy_container_alias_scopes(
                scopes: list[dict[str, dict[tuple[object, ...], str | None]]],
            ) -> list[dict[str, dict[tuple[object, ...], str | None]]]:
                return [{name: dict(values) for name, values in scope.items()} for scope in scopes]

            @staticmethod
            def _copy_container_identity_scopes(
                scopes: list[dict[str, int | None]],
            ) -> list[dict[str, int | None]]:
                return [dict(scope) for scope in scopes]

            @staticmethod
            def _copy_attribute_alias_scopes(
                scopes: list[dict[tuple[str, ...], str | None]],
            ) -> list[dict[tuple[str, ...], str | None]]:
                return [dict(scope) for scope in scopes]

            def _snapshot_alias_state(
                self,
            ) -> tuple[
                list[dict[str, str | None]],
                list[set[str]],
                list[set[str]],
                list[dict[str, dict[tuple[object, ...], str | None]]],
                list[dict[tuple[str, ...], str | None]],
                list[dict[str, int | None]],
            ]:
                return (
                    self._copy_alias_scopes(self.alias_scopes),
                    self._copy_builtins_module_aliases(self.builtins_module_aliases),
                    self._copy_defined_names(self.defined_names),
                    self._copy_container_alias_scopes(self.container_alias_scopes),
                    self._copy_attribute_alias_scopes(self.attribute_alias_scopes),
                    self._copy_container_identity_scopes(self.container_identity_scopes),
                )

            def _restore_alias_state(
                self,
                state: tuple[
                    list[dict[str, str | None]],
                    list[set[str]],
                    list[set[str]],
                    list[dict[str, dict[tuple[object, ...], str | None]]],
                    list[dict[tuple[str, ...], str | None]],
                    list[dict[str, int | None]],
                ],
            ) -> None:
                self.alias_scopes = self._copy_alias_scopes(state[0])
                self.builtins_module_aliases = self._copy_builtins_module_aliases(state[1])
                self.defined_names = self._copy_defined_names(state[2])
                self.container_alias_scopes = self._copy_container_alias_scopes(state[3])
                self.attribute_alias_scopes = self._copy_attribute_alias_scopes(state[4])
                self.container_identity_scopes = self._copy_container_identity_scopes(state[5])

            def _merge_alias_state_variants(
                self,
                original: tuple[
                    list[dict[str, str | None]],
                    list[set[str]],
                    list[set[str]],
                    list[dict[str, dict[tuple[object, ...], str | None]]],
                    list[dict[tuple[str, ...], str | None]],
                    list[dict[str, int | None]],
                ],
                variants: list[
                    tuple[
                        list[dict[str, str | None]],
                        list[set[str]],
                        list[set[str]],
                        list[dict[str, dict[tuple[object, ...], str | None]]],
                        list[dict[tuple[str, ...], str | None]],
                        list[dict[str, int | None]],
                    ]
                ],
            ) -> None:
                merged_scopes = self._copy_alias_scopes(original[0])
                for index, alias_scope in enumerate(merged_scopes):
                    names = set(alias_scope)
                    for variant_scopes, *_variant_state in variants:
                        names.update(variant_scopes[index])
                    for name in names:
                        candidates = [
                            variant_scopes[index].get(name, original[0][index].get(name))
                            for variant_scopes, *_variant_state in variants
                        ]
                        alias_scope[name] = next((candidate for candidate in candidates if candidate is not None), None)
                self.alias_scopes = merged_scopes
                self.builtins_module_aliases = [
                    set().union(
                        *(variant_modules[index] for _variant_scopes, variant_modules, *_variant_state in variants)
                    )
                    for index in range(len(original[1]))
                ]
                self.defined_names = [
                    set.intersection(
                        *(
                            variant_defined_names[index]
                            for _variant_scopes, _variant_modules, variant_defined_names, *_variant_state in variants
                        )
                    )
                    for index in range(len(original[2]))
                ]
                merged_containers = self._copy_container_alias_scopes(original[3])
                for index, container_scope in enumerate(merged_containers):
                    names = set(container_scope)
                    for *_prefix, variant_containers, _variant_attributes, _variant_identities in variants:
                        names.update(variant_containers[index])
                    for name in names:
                        merged_values: dict[tuple[object, ...], str | None] = {}
                        for *_prefix, variant_containers, _variant_attributes, _variant_identities in variants:
                            merged_values = self._merge_container_aliases(
                                merged_values,
                                variant_containers[index].get(name, original[3][index].get(name, {})),
                            )
                        container_scope[name] = merged_values
                self.container_alias_scopes = merged_containers
                merged_attributes = self._copy_attribute_alias_scopes(original[4])
                for index, attribute_scope in enumerate(merged_attributes):
                    attribute_keys = set(attribute_scope)
                    for *_prefix, variant_attributes, _variant_identities in variants:
                        attribute_keys.update(variant_attributes[index])
                    for attribute_key in attribute_keys:
                        candidates = [
                            variant_attributes[index].get(attribute_key, original[4][index].get(attribute_key))
                            for *_prefix, variant_attributes, _variant_identities in variants
                        ]
                        attribute_scope[attribute_key] = next(
                            (candidate for candidate in candidates if candidate is not None),
                            None,
                        )
                self.attribute_alias_scopes = merged_attributes
                merged_identities = self._copy_container_identity_scopes(original[5])
                for index, identity_scope in enumerate(merged_identities):
                    names = set(identity_scope)
                    for *_prefix, variant_identities in variants:
                        names.update(variant_identities[index])
                    for name in names:
                        identity_candidates = [
                            variant_identities[index].get(name, original[5][index].get(name))
                            for *_prefix, variant_identities in variants
                        ]
                        identity_scope[name] = (
                            identity_candidates[0]
                            if identity_candidates
                            and all(candidate == identity_candidates[0] for candidate in identity_candidates)
                            else None
                        )
                self.container_identity_scopes = merged_identities

            def _visit_statements(self, statements: list[ast.stmt]) -> ast.stmt | None:
                for statement in statements:
                    visit_result = self.visit(statement)
                    if isinstance(statement, (ast.Break, ast.Continue, ast.Raise, ast.Return)):
                        return statement
                    if isinstance(visit_result, (ast.Break, ast.Continue, ast.Raise, ast.Return)):
                        return visit_result
                return None

            def _statement_may_raise_before_completion(self, statement: ast.stmt) -> bool:
                if isinstance(statement, ast.Pass):
                    return False
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                    return False
                if isinstance(statement, ast.Assign):
                    return not (
                        all(isinstance(target, ast.Name) for target in statement.targets)
                        and (
                            isinstance(statement.value, ast.Constant)
                            or (
                                isinstance(statement.value, ast.Name)
                                and self._is_guaranteed_resolvable_name(statement.value.id)
                            )
                        )
                    )
                return True

            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                    self._bind_name(local_name, None, builtins_module=alias.name in _BUILTINS_MODULE_NAMES)
                    if alias.name == "functools":
                        self.builtins_module_aliases[-1].add(f"{self._FUNCTOOLS_MODULE_MARKER}{local_name}")

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                if node.module in _BUILTINS_MODULE_NAMES:
                    for alias in node.names:
                        if alias.name == "*":
                            for builtin in dangerous_builtins:
                                self._bind_name(builtin, builtin)
                        else:
                            local_name = alias.asname or alias.name
                            helper = alias.name if alias.name in _PYTHON_BUILTIN_NAMES else None
                            callback_invoker = (
                                alias.name if alias.name in {"filter", "map", "max", "min", "sorted"} else None
                            )
                            self._bind_name(
                                local_name,
                                alias.name if alias.name in dangerous_builtins else None,
                                callback_invoker=callback_invoker,
                                builtin_helper=helper,
                            )
                else:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        self._bind_name(local_name, None)
                        if node.module == "functools" and alias.name == "partial":
                            self.builtins_module_aliases[-1].add(f"{self._FUNCTOOLS_PARTIAL_MARKER}{local_name}")

            def visit_Assign(self, node: ast.Assign) -> None:
                self.visit(node.value)
                if len(node.targets) > 1 and not any(
                    isinstance(target, (ast.Tuple, ast.List)) for target in node.targets
                ):
                    builtin = self._resolve_builtin(node.value)
                    builtins_module = self._is_builtins_namespace(node.value)
                    container_aliases = self._resolve_builtin_container(node.value)
                    container_identity = self._container_expression_identity(node.value)
                    constant_strings = self._constant_strings(node.value)
                    attribute_aliases = self._resolve_attribute_aliases(node.value)
                    callback_invoker = self._resolve_callback_invoker(node.value)
                    builtin_helper = self._resolve_builtin_helper(node.value)
                    container_functions = self._resolve_function_container(node.value)
                    function_summary = self._function_summary_for_node(node.value)
                    for target in node.targets:
                        self._bind_target(
                            target,
                            builtin,
                            builtins_module=builtins_module,
                            container_aliases=container_aliases,
                            container_identity=container_identity,
                            constant_strings=constant_strings,
                            attribute_aliases=attribute_aliases,
                            callback_invoker=callback_invoker,
                            builtin_helper=builtin_helper,
                            container_functions=container_functions,
                            function_summary=function_summary,
                        )
                    return
                for target in node.targets:
                    self._bind_target_from_value(target, node.value)

            def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                if node.value is not None:
                    self.visit(node.value)
                    self._bind_target_from_value(node.target, node.value)
                else:
                    self._bind_target(node.target, None)

            def visit_AugAssign(self, node: ast.AugAssign) -> None:
                self.visit(node.value)
                self._bind_target(node.target, None)

            def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
                self.visit(node.value)
                scope_index = len(self.scope_kinds) - 1
                while scope_index > 0 and self.scope_kinds[scope_index] == "comprehension":
                    scope_index -= 1
                self._bind_target_from_value(node.target, node.value, scope_index=scope_index)

            def visit_Return(self, node: ast.Return) -> None:
                if node.value is not None:
                    if self.return_binding_stack:
                        self.return_binding_stack[-1].append(self._binding_from_expression(node.value))
                    self.visit(node.value)

            def visit_Delete(self, node: ast.Delete) -> None:
                for target in node.targets:
                    self.visit(target)
                    self._unbind_target(target)

            @staticmethod
            def _local_binding_names(nodes: list[ast.AST]) -> set[str]:
                class LocalBindingVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.local_names: set[str] = set()
                        self.outer_names: set[str] = set()

                    def visit_Name(self, node: ast.Name) -> None:
                        if isinstance(node.ctx, (ast.Store, ast.Del)):
                            self.local_names.add(node.id)

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        self.local_names.add(node.name)
                        for decorator in node.decorator_list:
                            self.visit(decorator)
                        self._visit_function_signature(node)

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        self.local_names.add(node.name)
                        for decorator in node.decorator_list:
                            self.visit(decorator)
                        self._visit_function_signature(node)

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        self.local_names.add(node.name)
                        for base in node.bases:
                            self.visit(base)
                        for keyword in node.keywords:
                            self.visit(keyword.value)
                        for decorator in node.decorator_list:
                            self.visit(decorator)

                    def visit_Lambda(self, node: ast.Lambda) -> None:
                        for default in [*node.args.defaults, *node.args.kw_defaults]:
                            if default is not None:
                                self.visit(default)

                    def _visit_function_signature(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                        for argument in [
                            *node.args.posonlyargs,
                            *node.args.args,
                            *node.args.kwonlyargs,
                            node.args.vararg,
                            node.args.kwarg,
                        ]:
                            if argument is not None and argument.annotation is not None:
                                self.visit(argument.annotation)
                        if node.returns is not None:
                            self.visit(node.returns)
                        for default in [*node.args.defaults, *node.args.kw_defaults]:
                            if default is not None:
                                self.visit(default)

                    def visit_Global(self, node: ast.Global) -> None:
                        self.outer_names.update(node.names)

                    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                        self.outer_names.update(node.names)

                    def visit_Import(self, node: ast.Import) -> None:
                        self.local_names.update(
                            alias.asname or alias.name.split(".", maxsplit=1)[0] for alias in node.names
                        )

                    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                        self.local_names.update(alias.asname or alias.name for alias in node.names)

                    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                        if node.name is not None:
                            self.local_names.add(node.name)
                        self.generic_visit(node)

                    def visit_MatchAs(self, node: ast.MatchAs) -> None:
                        if node.name is not None:
                            self.local_names.add(node.name)
                        self.generic_visit(node)

                    def visit_MatchStar(self, node: ast.MatchStar) -> None:
                        if node.name is not None:
                            self.local_names.add(node.name)

                    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
                        if node.rest is not None:
                            self.local_names.add(node.rest)
                        self.generic_visit(node)

                    def _visit_comprehension(
                        self,
                        generators: list[ast.comprehension],
                        result_nodes: tuple[ast.AST, ...],
                    ) -> None:
                        for generator in generators:
                            self.visit(generator.iter)
                            for condition in generator.ifs:
                                self.visit(condition)
                        for result_node in result_nodes:
                            self.visit(result_node)

                    def visit_ListComp(self, node: ast.ListComp) -> None:
                        self._visit_comprehension(node.generators, (node.elt,))

                    def visit_SetComp(self, node: ast.SetComp) -> None:
                        self._visit_comprehension(node.generators, (node.elt,))

                    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
                        self._visit_comprehension(node.generators, (node.elt,))

                    def visit_DictComp(self, node: ast.DictComp) -> None:
                        self._visit_comprehension(node.generators, (node.key, node.value))

                visitor = LocalBindingVisitor()
                for node in nodes:
                    visitor.visit(node)
                return visitor.local_names - visitor.outer_names

            @staticmethod
            def _outer_binding_declarations(nodes: list[ast.AST]) -> tuple[set[str], set[str]]:
                class OuterBindingVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.global_names: set[str] = set()
                        self.nonlocal_names: set[str] = set()

                    def visit_Global(self, node: ast.Global) -> None:
                        self.global_names.update(node.names)

                    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
                        self.nonlocal_names.update(node.names)

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        return

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        return

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        return

                    def visit_Lambda(self, node: ast.Lambda) -> None:
                        return

                visitor = OuterBindingVisitor()
                for node in nodes:
                    visitor.visit(node)
                return visitor.global_names, visitor.nonlocal_names

            def _argument_default_bindings(
                self,
                arguments: ast.arguments,
            ) -> dict[
                str,
                tuple[
                    str | None,
                    bool,
                    dict[tuple[object, ...], str | None],
                    int | None,
                    set[str],
                ],
            ]:
                bindings: dict[
                    str,
                    tuple[
                        str | None,
                        bool,
                        dict[tuple[object, ...], str | None],
                        int | None,
                        set[str],
                    ],
                ] = {}
                positional_arguments = [*arguments.posonlyargs, *arguments.args]
                if arguments.defaults:
                    for argument, default in zip(
                        positional_arguments[-len(arguments.defaults) :],
                        arguments.defaults,
                        strict=True,
                    ):
                        bindings[argument.arg] = (
                            self._resolve_builtin(default),
                            self._is_builtins_namespace(default),
                            self._resolve_builtin_container(default),
                            self._container_expression_identity(default),
                            self._constant_strings(default),
                        )
                for argument, kw_default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
                    if kw_default is not None:
                        bindings[argument.arg] = (
                            self._resolve_builtin(kw_default),
                            self._is_builtins_namespace(kw_default),
                            self._resolve_builtin_container(kw_default),
                            self._container_expression_identity(kw_default),
                            self._constant_strings(kw_default),
                        )
                return bindings

            def _visit_argument_annotations(self, arguments: ast.arguments, returns: ast.expr | None = None) -> None:
                for argument in [
                    *arguments.posonlyargs,
                    *arguments.args,
                    *arguments.kwonlyargs,
                    arguments.vararg,
                    arguments.kwarg,
                ]:
                    if argument is not None and argument.annotation is not None:
                        self.visit(argument.annotation)
                if returns is not None:
                    self.visit(returns)

            def _visit_function_node(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                for decorator in node.decorator_list:
                    self.visit(decorator)
                self._visit_argument_annotations(node.args, node.returns)
                default_bindings = self._argument_default_bindings(node.args)
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        self.visit(default)
                self._bind_name(node.name, None)
                global_names, nonlocal_names = self._outer_binding_declarations(list(node.body))
                self._push_scope(
                    node.args,
                    default_bindings,
                    self._local_binding_names(list(node.body)),
                    global_names=global_names,
                )
                self.return_binding_stack.append([])
                self._visit_statements(node.body)
                return_binding = self._merge_bindings(self.return_binding_stack.pop())
                effects = [
                    (
                        (
                            "global_delete"
                            if self._global_delete_marker(name) in self.builtins_module_aliases[-1]
                            else "global"
                        ),
                        name,
                        self._binding_from_name(name, -1),
                    )
                    for name in global_names
                    if name in self.alias_scopes[-1]
                ]
                effects.extend(
                    ("nonlocal", name, self._binding_from_name(name, -1))
                    for name in nonlocal_names
                    if name in self.alias_scopes[-1]
                )
                self._pop_scope()
                function_id = str(id(node))
                self.function_nodes[function_id] = node
                self._register_function_summary(node.name, (effects, return_binding, ((function_id, 0),)))
                for decorator in reversed(node.decorator_list):
                    decorator_call = ast.Call(
                        func=decorator,
                        args=[ast.Name(id=node.name, ctx=ast.Load())],
                        keywords=[],
                    )
                    if builtin := self._resolve_builtin(decorator_call.func):
                        self.findings.add(builtin)
                    self._analyze_function_call(decorator_call)
                    self._apply_function_effects(decorator_call.func)
                    decorator_binding = self._binding_from_expression(decorator_call)
                    if self._binding_has_tracked_value(decorator_binding):
                        self._apply_binding(node.name, decorator_binding, scope_index=-1)

            def _sequence_binding(self, bindings: list[_BuiltinAliasBinding]) -> _BuiltinAliasBinding:
                container: dict[tuple[object, ...], str | None] = {}
                for index, binding in enumerate(bindings):
                    item = self._sequence_index_element(index, len(bindings))
                    container[(item,)] = binding[0]
                    for path, builtin in binding[2].items():
                        container[(item, *path)] = builtin
                return None, False, container, set(), {}, None, None, ()

            def _mapping_binding(self, bindings: dict[str, _BuiltinAliasBinding]) -> _BuiltinAliasBinding:
                container: dict[tuple[object, ...], str | None] = {}
                for key, binding in bindings.items():
                    container[(key,)] = binding[0]
                    for path, builtin in binding[2].items():
                        container[(key, *path)] = builtin
                return None, False, container, set(), {}, None, None, ()

            def _expanded_positional_bindings(self, node: ast.Call) -> list[_BuiltinAliasBinding]:
                bindings: list[_BuiltinAliasBinding] = []
                for argument in node.args:
                    if not isinstance(argument, ast.Starred):
                        bindings.append(self._binding_from_expression(argument))
                        continue
                    elements = self._literal_iterable_elements(argument.value)
                    if elements is not None:
                        bindings.extend(self._binding_from_expression(element) for element in elements)
                        continue
                    bindings.extend(
                        (builtin, False, nested, set(), {}, None, None, ())
                        for builtin, nested in self._sequence_container_element_bindings(
                            self._resolve_builtin_container(argument.value)
                        )
                    )
                return bindings

            def _expanded_keyword_bindings(self, node: ast.Call) -> dict[str, _BuiltinAliasBinding]:
                bindings: dict[str, _BuiltinAliasBinding] = {}
                for keyword in node.keywords:
                    if keyword.arg is not None:
                        bindings[keyword.arg] = self._binding_from_expression(keyword.value)
                        continue
                    if isinstance(keyword.value, ast.Dict):
                        for key_node, value_node in zip(keyword.value.keys, keyword.value.values, strict=True):
                            if key_node is not None and (key := self._constant_string(key_node)) is not None:
                                bindings[key] = self._binding_from_expression(value_node)
                        continue
                    container = self._resolve_builtin_container(keyword.value)
                    for path in container:
                        if not path or not isinstance(path[0], str) or len(path) != 1:
                            continue
                        found, builtin, nested = self._container_child_binding(container, path[0])
                        if found:
                            bindings[path[0]] = (builtin, False, nested, set(), {}, None, None, ())
                return bindings

            def _bind_call_arguments(
                self,
                arguments: ast.arguments,
                node: ast.Call,
                *,
                positional_offset: int = 0,
            ) -> None:
                positional_parameters = [*arguments.posonlyargs, *arguments.args]
                call_bindings = self._expanded_positional_bindings(node)
                available_parameters = positional_parameters[positional_offset:]
                for argument, binding in zip(available_parameters, call_bindings, strict=False):
                    self._apply_binding(argument.arg, binding, scope_index=-1)

                extra_bindings = call_bindings[len(available_parameters) :]
                if arguments.vararg is not None and extra_bindings:
                    self._apply_binding(
                        arguments.vararg.arg,
                        self._sequence_binding(extra_bindings),
                        scope_index=-1,
                    )

                keyword_bindings = self._expanded_keyword_bindings(node)
                known_parameters = {
                    argument.arg
                    for argument in [
                        *arguments.args,
                        *arguments.kwonlyargs,
                    ]
                }
                extra_keywords: dict[str, _BuiltinAliasBinding] = {}
                for name, binding in keyword_bindings.items():
                    if name in known_parameters:
                        self._apply_binding(name, binding, scope_index=-1)
                    elif arguments.kwarg is not None:
                        extra_keywords[name] = binding
                if arguments.kwarg is not None and extra_keywords:
                    self._apply_binding(
                        arguments.kwarg.arg,
                        self._mapping_binding(extra_keywords),
                        scope_index=-1,
                    )

            def _analyze_function_call(self, node: ast.Call) -> None:
                summary = self._function_summary_for_node(node.func)
                if summary is None:
                    return
                _effects, _return_binding, functions = summary
                for function_id, positional_offset in functions:
                    if function_id in self.active_function_calls:
                        continue
                    function_node = self.function_nodes.get(function_id)
                    if function_node is None:
                        continue

                    body_nodes: list[ast.AST] = (
                        [function_node.body] if isinstance(function_node, ast.Lambda) else list(function_node.body)
                    )
                    default_bindings = self._argument_default_bindings(function_node.args)
                    function_global_names = (
                        set()
                        if isinstance(function_node, ast.Lambda)
                        else self._outer_binding_declarations(body_nodes)[0]
                    )
                    self.active_function_calls.add(function_id)
                    self._push_scope(
                        function_node.args,
                        default_bindings,
                        self._local_binding_names(body_nodes),
                        global_names=function_global_names,
                    )
                    try:
                        effective_offset = (
                            0
                            if positional_offset
                            and isinstance(node.func, ast.Attribute)
                            and self._is_class_name(node.func.value)
                            and not (
                                isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef))
                                and self._has_named_decorator(function_node, "classmethod")
                            )
                            else positional_offset
                        )
                        self._bind_call_arguments(
                            function_node.args,
                            node,
                            positional_offset=effective_offset,
                        )
                        if isinstance(function_node, ast.Lambda):
                            self.visit(function_node.body)
                        else:
                            self._visit_statements(function_node.body)
                    finally:
                        self._pop_scope()
                        self.active_function_calls.discard(function_id)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._visit_function_node(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._visit_function_node(node)

            def visit_Lambda(self, node: ast.Lambda) -> None:
                default_bindings = self._argument_default_bindings(node.args)
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        self.visit(default)
                self._push_scope(node.args, default_bindings, self._local_binding_names([node.body]))
                self.visit(node.body)
                return_binding = self._binding_from_expression(node.body)
                self._pop_scope()
                function_id = str(id(node))
                self.function_nodes[function_id] = node
                self.lambda_summaries[id(node)] = ([], return_binding, ((function_id, 0),))

            def _instance_bindings_from_constructor(
                self,
                constructor: ast.FunctionDef | ast.AsyncFunctionDef,
                call: ast.Call | None = None,
            ) -> tuple[
                dict[tuple[str, ...], str | None],
                dict[tuple[str, ...], dict[tuple[object, ...], str | None]],
            ]:
                positional_arguments = [
                    *constructor.args.posonlyargs,
                    *constructor.args.args,
                ]
                if not positional_arguments:
                    return {}, {}

                receiver_name = positional_arguments[0].arg
                default_bindings = self._argument_default_bindings(constructor.args)
                global_names, _nonlocal_names = self._outer_binding_declarations(list(constructor.body))
                self._push_scope(
                    constructor.args,
                    default_bindings,
                    self._local_binding_names(list(constructor.body)),
                    global_names=global_names,
                )
                try:
                    if call is not None:
                        self._bind_call_arguments(constructor.args, call, positional_offset=1)
                    self._visit_statements(constructor.body)
                    attribute_aliases = {
                        key[1:]: builtin
                        for key, builtin in self.attribute_alias_scopes[-1].items()
                        if len(key) > 1 and key[0] == receiver_name
                    }
                    container_aliases = {
                        key[1:]: dict(container)
                        for name, container in self.container_alias_scopes[-1].items()
                        if (key := self._attribute_container_key(name)) is not None
                        and len(key) > 1
                        and key[0] == receiver_name
                    }
                    return attribute_aliases, container_aliases
                finally:
                    self._pop_scope()

            def _constructor_instance_bindings(
                self,
                node: ast.ClassDef,
            ) -> tuple[
                dict[tuple[str, ...], str | None],
                dict[tuple[str, ...], dict[tuple[object, ...], str | None]],
            ]:
                constructor = next(
                    (
                        statement
                        for statement in node.body
                        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and statement.name == "__init__"
                    ),
                    None,
                )
                return self._instance_bindings_from_constructor(constructor) if constructor is not None else ({}, {})

            def _constructor_call_instance_bindings(
                self,
                node: ast.Call,
            ) -> tuple[
                dict[tuple[str, ...], str | None],
                dict[tuple[str, ...], dict[tuple[object, ...], str | None]],
            ]:
                if cached := self.constructor_call_bindings.get(id(node)):
                    return cached
                constructor = ast.Attribute(value=node.func, attr="__init__", ctx=ast.Load())
                summary = self._function_summary_for_node(constructor)
                if summary is None:
                    return {}, {}
                attribute_variants: list[dict[tuple[str, ...], str | None]] = []
                container_variants: list[dict[tuple[str, ...], dict[tuple[object, ...], str | None]]] = []
                for function_id, _positional_offset in summary[2]:
                    function_node = self.function_nodes.get(function_id)
                    if isinstance(function_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        variant_attributes, variant_containers = self._instance_bindings_from_constructor(
                            function_node,
                            node,
                        )
                        attribute_variants.append(variant_attributes)
                        container_variants.append(variant_containers)
                attributes: dict[tuple[str, ...], str | None] = {}
                for variant in attribute_variants:
                    for key, builtin in variant.items():
                        if builtin is not None or key not in attributes:
                            attributes[key] = builtin
                containers: dict[tuple[str, ...], dict[tuple[object, ...], str | None]] = {}
                for container_variant in container_variants:
                    for key, nested_container in container_variant.items():
                        containers[key] = self._merge_container_aliases(
                            containers.get(key, {}),
                            nested_container,
                        )
                result = attributes, containers
                self.constructor_call_bindings[id(node)] = result
                return result

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                for base in node.bases:
                    self.visit(base)
                for keyword in node.keywords:
                    self.visit(keyword.value)
                for decorator in node.decorator_list:
                    self.visit(decorator)
                inherited_aliases: dict[tuple[str, ...], str | None] = {}
                inherited_containers: dict[
                    tuple[str, ...],
                    dict[tuple[object, ...], str | None],
                ] = {}
                inherited_functions: dict[tuple[str, ...], _FunctionAliasSummary] = {}
                for base in node.bases:
                    inherited_aliases.update(self._resolve_attribute_aliases(base))
                    inherited_containers.update(self._resolve_attribute_containers(base))
                    inherited_functions.update(self._resolve_attribute_function_summaries(base))
                self._push_scope(kind="class")
                self._visit_statements(node.body)
                class_aliases = {
                    name: builtin
                    for name, builtin in self.alias_scopes[-1].items()
                    if self._attribute_function_key(name) is None
                }
                class_containers = {
                    name: dict(container)
                    for name, container in self.container_alias_scopes[-1].items()
                    if name in class_aliases
                }
                class_attributes = dict(self.attribute_alias_scopes[-1])
                method_nodes = {
                    statement.name: statement
                    for statement in node.body
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                class_functions = {
                    (name,): (
                        summary[0],
                        summary[1],
                        tuple(
                            (
                                function_id,
                                (
                                    0
                                    if (method := method_nodes.get(name)) is not None
                                    and self._has_named_decorator(method, "staticmethod")
                                    else 1
                                ),
                            )
                            for function_id, _positional_offset in summary[2]
                        ),
                    )
                    for name in class_aliases
                    if (summary := self._lookup_function_summary(name)[1]) is not None
                }
                self._pop_scope()
                self._bind_name(node.name, None)
                self.builtins_module_aliases[-1].add(self._class_marker(node.name))
                for key in inherited_aliases.keys() | inherited_containers.keys() | inherited_functions.keys():
                    self._bind_attribute_key(
                        (node.name, *key),
                        inherited_aliases.get(key),
                        container_aliases=inherited_containers.get(key),
                        function_summary=inherited_functions.get(key),
                    )
                for name, builtin in class_aliases.items():
                    self._bind_attribute_key(
                        (node.name, name),
                        builtin,
                        container_aliases=class_containers.get(name),
                        function_summary=class_functions.get((name,)),
                    )
                for key, builtin in class_attributes.items():
                    self._bind_attribute_key((node.name, *key), builtin)

                instance_attributes, instance_containers = self._constructor_instance_bindings(node)
                for key in instance_attributes.keys() | instance_containers.keys():
                    self._bind_attribute_key(
                        (node.name, *key),
                        instance_attributes.get(key),
                        container_aliases=instance_containers.get(key),
                    )
                for decorator in reversed(node.decorator_list):
                    decorator_call = ast.Call(
                        func=decorator,
                        args=[ast.Name(id=node.name, ctx=ast.Load())],
                        keywords=[],
                    )
                    if builtin := self._resolve_builtin(decorator_call.func):
                        self.findings.add(builtin)
                    self._analyze_function_call(decorator_call)
                    self._apply_function_effects(decorator_call.func)
                    decorator_binding = self._binding_from_expression(decorator_call)
                    if self._binding_has_tracked_value(decorator_binding):
                        self._apply_binding(node.name, decorator_binding, scope_index=-1)

            def visit_If(self, node: ast.If) -> ast.stmt | None:
                self.visit(node.test)
                truth = self._constant_truth(node.test)
                if truth is True:
                    return self._visit_statements(node.body)
                if truth is False:
                    return self._visit_statements(node.orelse)

                original = self._snapshot_alias_state()
                body_terminal = self._visit_statements(node.body)
                body = self._snapshot_alias_state()

                self._restore_alias_state(original)
                orelse_terminal = self._visit_statements(node.orelse)
                orelse = self._snapshot_alias_state()

                variants = []
                if body_terminal is None:
                    variants.append(body)
                if orelse_terminal is None:
                    variants.append(orelse)
                if variants:
                    self._merge_alias_state_variants(original, variants)
                    return None
                self._restore_alias_state(original)
                return body_terminal or orelse_terminal

            def _bind_match_pattern_from_aliases(
                self,
                pattern: ast.pattern,
                builtin: str | None,
                container: dict[tuple[object, ...], str | None],
                *,
                builtins_module: bool = False,
            ) -> None:
                if isinstance(pattern, ast.MatchAs):
                    if pattern.pattern is not None:
                        self._bind_match_pattern_from_aliases(
                            pattern.pattern,
                            builtin,
                            container,
                            builtins_module=builtins_module,
                        )
                    if pattern.name is not None:
                        self._bind_name(
                            pattern.name,
                            builtin,
                            builtins_module=builtins_module,
                            container_aliases=container,
                        )
                    return
                if isinstance(pattern, ast.MatchSequence):
                    for index, child_pattern in enumerate(pattern.patterns):
                        found, child_builtin, child_container = self._container_child_binding(
                            container,
                            index,
                            sequence_only=True,
                        )
                        if found:
                            self._bind_match_pattern_from_aliases(
                                child_pattern,
                                child_builtin,
                                child_container,
                            )
                        else:
                            self._bind_match_pattern_from_aliases(child_pattern, None, {})
                    return
                if isinstance(pattern, ast.MatchMapping):
                    for key_node, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
                        key_resolved, key = self._constant_container_key(key_node)
                        if key_resolved:
                            found, child_builtin, child_container = self._container_child_binding(container, key)
                        else:
                            found, child_builtin, child_container = False, None, {}
                        if found:
                            self._bind_match_pattern_from_aliases(
                                child_pattern,
                                child_builtin,
                                child_container,
                            )
                        else:
                            self._bind_match_pattern_from_aliases(child_pattern, None, {})
                    if pattern.rest is not None:
                        self._bind_name(pattern.rest, None)
                    return
                for candidate in ast.walk(pattern):
                    name = None
                    if isinstance(candidate, (ast.MatchAs, ast.MatchStar)):
                        name = candidate.name
                    elif isinstance(candidate, ast.MatchMapping):
                        name = candidate.rest
                    if name is not None:
                        self._bind_name(name, None)

            def _bind_match_pattern(self, pattern: ast.pattern, subject: ast.AST) -> None:
                self._bind_match_pattern_from_aliases(
                    pattern,
                    self._resolve_builtin(subject),
                    self._resolve_builtin_container(subject),
                    builtins_module=self._is_builtins_namespace(subject),
                )

            @staticmethod
            def _match_case_is_irrefutable(case: ast.match_case, guard_truth: bool | None) -> bool:
                return (
                    (case.guard is None or guard_truth is True)
                    and isinstance(case.pattern, ast.MatchAs)
                    and case.pattern.pattern is None
                )

            def visit_Match(self, node: ast.Match) -> ast.stmt | None:
                self.visit(node.subject)
                original = self._snapshot_alias_state()
                variants = []
                has_irrefutable_case = False
                terminal_cases = []
                for case in node.cases:
                    self._restore_alias_state(original)
                    self.visit(case.pattern)
                    self._bind_match_pattern(case.pattern, node.subject)
                    guard_truth = None
                    if case.guard is not None:
                        self.visit(case.guard)
                        guard_truth = self._constant_truth(case.guard)
                        if guard_truth is False:
                            continue
                    terminal = self._visit_statements(case.body)
                    if terminal is None:
                        variants.append(self._snapshot_alias_state())
                    else:
                        terminal_cases.append(terminal)
                    has_irrefutable_case = has_irrefutable_case or self._match_case_is_irrefutable(case, guard_truth)
                if not has_irrefutable_case:
                    variants.append(original)
                if variants:
                    self._merge_alias_state_variants(original, variants)
                    return None
                self._restore_alias_state(original)
                return terminal_cases[0] if terminal_cases else None

            @staticmethod
            def _loop_body_rebinds_target(body: list[ast.stmt], target: ast.AST) -> bool:
                target_names = {
                    candidate.id
                    for candidate in ast.walk(target)
                    if isinstance(candidate, ast.Name) and isinstance(candidate.ctx, ast.Store)
                }

                class TargetRebindVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.found = False

                    def visit_Name(self, node: ast.Name) -> None:
                        if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in target_names:
                            self.found = True

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        self.found = self.found or node.name in target_names
                        self._visit_function_definition_expressions(node)

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        self.found = self.found or node.name in target_names
                        self._visit_function_definition_expressions(node)

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        self.found = self.found or node.name in target_names
                        for base in node.bases:
                            self.visit(base)
                        for keyword in node.keywords:
                            self.visit(keyword.value)
                        for decorator in node.decorator_list:
                            self.visit(decorator)

                    def visit_Lambda(self, node: ast.Lambda) -> None:
                        for default in [*node.args.defaults, *node.args.kw_defaults]:
                            if default is not None:
                                self.visit(default)

                    def _visit_function_definition_expressions(
                        self,
                        node: ast.FunctionDef | ast.AsyncFunctionDef,
                    ) -> None:
                        for decorator in node.decorator_list:
                            self.visit(decorator)
                        for argument in [
                            *node.args.posonlyargs,
                            *node.args.args,
                            *node.args.kwonlyargs,
                            node.args.vararg,
                            node.args.kwarg,
                        ]:
                            if argument is not None and argument.annotation is not None:
                                self.visit(argument.annotation)
                        if node.returns is not None:
                            self.visit(node.returns)
                        for default in [*node.args.defaults, *node.args.kw_defaults]:
                            if default is not None:
                                self.visit(default)

                    def _visit_comprehension(
                        self,
                        generators: list[ast.comprehension],
                        result_nodes: tuple[ast.AST, ...],
                    ) -> None:
                        for generator in generators:
                            self.visit(generator.iter)
                            for condition in generator.ifs:
                                self.visit(condition)
                        for result_node in result_nodes:
                            self.visit(result_node)

                    def visit_ListComp(self, node: ast.ListComp) -> None:
                        self._visit_comprehension(node.generators, (node.elt,))

                    def visit_SetComp(self, node: ast.SetComp) -> None:
                        self._visit_comprehension(node.generators, (node.elt,))

                    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
                        self._visit_comprehension(node.generators, (node.elt,))

                    def visit_DictComp(self, node: ast.DictComp) -> None:
                        self._visit_comprehension(node.generators, (node.key, node.value))

                visitor = TargetRebindVisitor()
                for statement in body:
                    visitor.visit(statement)
                return visitor.found

            @staticmethod
            def _loop_body_may_break(body: list[ast.stmt]) -> bool:
                class LoopBreakVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.found = False

                    def visit_Break(self, node: ast.Break) -> None:
                        self.found = True

                    def visit_For(self, node: ast.For) -> None:
                        return

                    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
                        return

                    def visit_While(self, node: ast.While) -> None:
                        return

                    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                        return

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        return

                    def visit_ClassDef(self, node: ast.ClassDef) -> None:
                        return

                    def visit_Lambda(self, node: ast.Lambda) -> None:
                        return

                visitor = LoopBreakVisitor()
                for statement in body:
                    visitor.visit(statement)
                return visitor.found

            def _refine_known_loop_exit_target(
                self,
                node: ast.For | ast.AsyncFor,
                body_terminal: ast.stmt | None,
            ) -> None:
                if self._loop_body_rebinds_target(node.body, node.target):
                    return
                elements = self._literal_iterable_elements(node.iter)
                if not elements or not isinstance(node.iter, (ast.List, ast.Tuple)):
                    return
                if isinstance(body_terminal, ast.Break):
                    self._bind_target_from_value(node.target, elements[0])
                elif not self._loop_body_may_break(node.body):
                    self._bind_target_from_value(node.target, elements[-1])

            def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
                self.visit(node.iter)
                iterable_truth = self._constant_iterable_truth(node.iter)
                if iterable_truth is False:
                    self._visit_statements(node.orelse)
                    return

                original = self._snapshot_alias_state()
                self._bind_loop_target_from_iterable(node.target, node.iter)
                body_terminal = self._visit_statements(node.body)
                self._refine_known_loop_exit_target(node, body_terminal)
                body_state = self._snapshot_alias_state()
                break_states = [body_state] if self._loop_body_may_break(node.body) else []
                normal_states = []
                if not isinstance(body_terminal, (ast.Return, ast.Raise, ast.Break)):
                    normal_states.append(body_state)
                if iterable_truth is None:
                    normal_states.append(original)

                variants = break_states
                if normal_states:
                    self._merge_alias_state_variants(original, normal_states)
                    self._visit_statements(node.orelse)
                    variants.append(self._snapshot_alias_state())
                if not variants:
                    variants.append(body_state)
                self._merge_alias_state_variants(original, variants)

            def visit_For(self, node: ast.For) -> None:
                self._visit_loop(node)

            def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
                self._visit_loop(node)

            def visit_While(self, node: ast.While) -> ast.stmt | None:
                self.visit(node.test)
                truth = self._constant_truth(node.test)
                if truth is False:
                    return self._visit_statements(node.orelse)

                original = self._snapshot_alias_state()
                body_terminal = self._visit_statements(node.body)
                body_state = self._snapshot_alias_state()
                break_states = [body_state] if self._loop_body_may_break(node.body) else []
                normal_states = []
                if truth is not True and not isinstance(body_terminal, (ast.Return, ast.Raise, ast.Break)):
                    normal_states.append(body_state)
                if truth is None:
                    normal_states.append(original)

                variants = break_states
                orelse_terminal = None
                if normal_states:
                    self._merge_alias_state_variants(original, normal_states)
                    orelse_terminal = self._visit_statements(node.orelse)
                    if orelse_terminal is None:
                        variants.append(self._snapshot_alias_state())
                if not variants:
                    self._restore_alias_state(original)
                    return body_terminal or orelse_terminal
                self._merge_alias_state_variants(original, variants)
                return None

            def _visit_with(self, node: ast.With | ast.AsyncWith) -> ast.stmt | None:
                enter_method = "__aenter__" if isinstance(node, ast.AsyncWith) else "__enter__"
                for item in node.items:
                    self.visit(item.context_expr)
                    enter_call = ast.Call(
                        func=ast.Attribute(
                            value=item.context_expr,
                            attr=enter_method,
                            ctx=ast.Load(),
                        ),
                        args=[],
                        keywords=[],
                    )
                    if builtin := self._resolve_builtin(enter_call.func):
                        self.findings.add(builtin)
                    self._analyze_function_call(enter_call)
                    self._apply_function_effects(enter_call.func)
                    if item.optional_vars is not None:
                        binding = self._binding_from_expression(enter_call)
                        if self._binding_has_tracked_value(binding):
                            self._apply_binding_to_target(item.optional_vars, binding)
                        else:
                            self._bind_target(item.optional_vars, None)
                return self._visit_statements(node.body)

            def visit_With(self, node: ast.With) -> ast.stmt | None:
                return self._visit_with(node)

            def visit_AsyncWith(self, node: ast.AsyncWith) -> ast.stmt | None:
                return self._visit_with(node)

            def visit_Try(self, node: ast.Try) -> ast.stmt | None:
                original = self._snapshot_alias_state()
                handler_entry_states = []
                body_terminal: ast.stmt | None = None
                for statement in node.body:
                    entry_state = self._snapshot_alias_state()
                    visit_result = self.visit(statement)
                    if self._statement_may_raise_before_completion(statement):
                        handler_entry_states.append(entry_state)
                    if isinstance(statement, (ast.Break, ast.Continue, ast.Raise, ast.Return)):
                        body_terminal = statement
                        break
                    if isinstance(visit_result, (ast.Break, ast.Continue, ast.Raise, ast.Return)):
                        body_terminal = visit_result
                        break
                body_state = self._snapshot_alias_state()
                variants = []
                if body_terminal is None:
                    orelse_terminal = self._visit_statements(node.orelse)
                    if orelse_terminal is None:
                        variants.append(self._snapshot_alias_state())
                    else:
                        body_terminal = orelse_terminal
                for handler in node.handlers:
                    for entry_state in handler_entry_states:
                        self._restore_alias_state(entry_state)
                        if handler.type is not None:
                            self.visit(handler.type)
                        if handler.name is not None:
                            self._bind_name(handler.name, None)
                        handler_terminal = self._visit_statements(handler.body)
                        if handler_terminal is None:
                            if handler.name is not None:
                                self._unbind_target(ast.Name(id=handler.name, ctx=ast.Del()))
                            variants.append(self._snapshot_alias_state())
                self._merge_alias_state_variants(original, variants or [body_state])
                finally_terminal = self._visit_statements(node.finalbody)
                if finally_terminal is not None:
                    return finally_terminal
                if not variants:
                    return body_terminal
                return None

            def _visit_comprehension(
                self,
                generators: list[ast.comprehension],
                result_nodes: tuple[ast.AST, ...],
            ) -> None:
                if not generators:
                    return

                first_generator, *remaining_generators = generators
                self.visit(first_generator.iter)
                if self._constant_iterable_truth(first_generator.iter) is False:
                    return

                self._push_scope(kind="comprehension")
                try:
                    self._bind_loop_target_from_iterable(first_generator.target, first_generator.iter)
                    for condition in first_generator.ifs:
                        self.visit(condition)
                        if self._constant_truth(condition) is False:
                            return
                    for generator in remaining_generators:
                        self.visit(generator.iter)
                        if self._constant_iterable_truth(generator.iter) is False:
                            return
                        self._bind_loop_target_from_iterable(generator.target, generator.iter)
                        for condition in generator.ifs:
                            self.visit(condition)
                            if self._constant_truth(condition) is False:
                                return
                    for result_node in result_nodes:
                        self.visit(result_node)
                finally:
                    self._pop_scope()

            def visit_ListComp(self, node: ast.ListComp) -> None:
                self._visit_comprehension(node.generators, (node.elt,))

            def visit_SetComp(self, node: ast.SetComp) -> None:
                self._visit_comprehension(node.generators, (node.elt,))

            def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
                self._visit_comprehension(node.generators, (node.elt,))

            def visit_DictComp(self, node: ast.DictComp) -> None:
                self._visit_comprehension(node.generators, (node.key, node.value))

            def _dangerous_callback_builtins(self, node: ast.Call) -> set[str]:
                callbacks: list[ast.AST] = []
                callback_invoker = self._resolve_callback_invoker(node.func)
                if callback_invoker in {"filter", "map"} and node.args:
                    callbacks.append(node.args[0])
                if callback_invoker in {"max", "min", "sorted"}:
                    callbacks.extend(keyword.value for keyword in node.keywords if keyword.arg == "key")
                return {builtin for callback in callbacks if (builtin := self._resolve_builtin(callback)) is not None}

            def _bind_attribute_setter_call(self, node: ast.Call) -> None:
                target: ast.AST | None = None
                name_node: ast.AST | None = None
                value: ast.AST | None = None
                is_builtin_setattr = self._is_builtin_helper(node.func, "setattr")
                is_object_setattr = (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "__setattr__"
                    and self._is_builtin_helper(node.func.value, "object")
                )
                if len(node.args) >= 3 and (is_builtin_setattr or is_object_setattr):
                    target, name_node, value = node.args[:3]
                if target is None or name_node is None or value is None:
                    return
                target_key = self._attribute_alias_key(target)
                if target_key is not None:
                    for attribute_name in self._constant_strings(name_node):
                        self._bind_attribute_key(
                            (*target_key, attribute_name),
                            self._resolve_builtin(value),
                            container_aliases=self._resolve_builtin_container(value),
                            attribute_aliases=self._resolve_attribute_aliases(value),
                            function_summary=self._function_summary_for_node(value),
                        )

            def _bind_container_mutation_call(self, node: ast.Call) -> None:
                if (
                    not isinstance(node.func, ast.Attribute)
                    or not isinstance(node.func.value, ast.Name)
                    or node.keywords
                ):
                    return
                container_name = node.func.value.id
                container_identity = self._lookup_container_identity(container_name)
                if container_identity is None:
                    return
                container = dict(self._lookup_container_alias(container_name))
                function_container = dict(self._lookup_container_functions(container_name))
                bindings: list[_BuiltinAliasBinding] = [
                    (builtin, False, nested, set(), {}, None, None, ())
                    for builtin, nested in self._sequence_container_element_bindings(container)
                ]
                if node.func.attr == "append" and len(node.args) == 1:
                    previous_length = len(bindings)
                    bindings.append(self._binding_from_expression(node.args[0]))
                    new_length = len(bindings)
                    function_container = {
                        (
                            (
                                path[0][0],
                                path[0][1],
                                new_length,
                            ),
                            *path[1:],
                        ): functions
                        for path, functions in function_container.items()
                        if path
                        and isinstance(path[0], tuple)
                        and len(path[0]) == 3
                        and path[0][0] == self._SEQUENCE_INDEX_MARKER
                    }
                    appended_marker = self._sequence_index_element(previous_length, new_length)
                    if summary := self._function_summary_for_node(node.args[0]):
                        function_container[(appended_marker,)] = summary[2]
                    for path, functions in self._resolve_function_container(node.args[0]).items():
                        function_container[(appended_marker, *path)] = functions
                elif node.func.attr == "pop" and len(node.args) <= 1 and bindings:
                    if node.args:
                        key_resolved, key = self._constant_container_key(node.args[0])
                        if not key_resolved or not isinstance(key, int):
                            return
                    else:
                        key = -1
                    index = key if key >= 0 else len(bindings) + key
                    if not 0 <= index < len(bindings):
                        return
                    bindings.pop(index)
                    new_length = len(bindings)
                    reindexed_functions: dict[
                        tuple[object, ...],
                        tuple[tuple[str, int], ...],
                    ] = {}
                    for path, functions in function_container.items():
                        if (
                            not path
                            or not isinstance(path[0], tuple)
                            or len(path[0]) != 3
                            or path[0][0] != self._SEQUENCE_INDEX_MARKER
                        ):
                            continue
                        old_index = path[0][1]
                        if old_index == index:
                            continue
                        new_index = old_index - 1 if old_index > index else old_index
                        reindexed_functions[
                            (
                                (
                                    self._SEQUENCE_INDEX_MARKER,
                                    new_index,
                                    new_length,
                                ),
                                *path[1:],
                            )
                        ] = functions
                    function_container = reindexed_functions
                else:
                    return
                container = self._sequence_binding(bindings)[2]
                for scope_index, (identity_scope, container_scope) in enumerate(
                    zip(
                        self.container_identity_scopes,
                        self.container_alias_scopes,
                        strict=True,
                    )
                ):
                    for name, identity in identity_scope.items():
                        if identity == container_identity:
                            container_scope[name] = dict(container)
                            self._register_container_functions(
                                name,
                                function_container,
                                scope_index=scope_index,
                            )

            def visit_Call(self, node: ast.Call) -> None:
                if builtin := self._resolve_builtin(node.func):
                    self.findings.add(builtin)
                self.findings.update(self._dangerous_callback_builtins(node))
                self._analyze_function_call(node)
                self.generic_visit(node)
                self._apply_function_effects(node.func)
                self._bind_attribute_setter_call(node)
                self._bind_container_mutation_call(node)

        def method_receiver_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
            positional_arguments = [*node.args.posonlyargs, *node.args.args]
            return positional_arguments[0].arg if positional_arguments else None

        def is_static_method(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            return any(
                (isinstance(decorator, ast.Name) and decorator.id == "staticmethod")
                or (isinstance(decorator, ast.Attribute) and decorator.attr == "staticmethod")
                for decorator in node.decorator_list
            )

        def method_visitor(
            node: ast.FunctionDef | ast.AsyncFunctionDef,
            instance_aliases: dict[tuple[str, ...], str] | None = None,
        ) -> tuple[DangerousBuiltinCallVisitor, str | None]:
            method_analysis = DangerousBuiltinCallVisitor()
            receiver_name = None if is_static_method(node) else method_receiver_name(node)
            default_bindings = method_analysis._argument_default_bindings(node.args)
            global_names, _nonlocal_names = method_analysis._outer_binding_declarations(list(node.body))
            method_analysis._push_scope(
                node.args,
                default_bindings,
                method_analysis._local_binding_names(list(node.body)),
                global_names=global_names,
            )
            if receiver_name is not None:
                for path, builtin in (instance_aliases or {}).items():
                    method_analysis.attribute_alias_scopes[-1][(receiver_name, *path)] = builtin
            method_analysis._visit_statements(node.body)
            return method_analysis, receiver_name

        def class_instance_builtin_findings(node: ast.ClassDef) -> set[str]:
            instance_aliases: dict[tuple[str, ...], str] = {}
            class_analysis = DangerousBuiltinCallVisitor()
            class_analysis._push_scope(kind="class")
            class_analysis._visit_statements(
                [
                    statement
                    for statement in node.body
                    if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
            )
            for name, builtin in class_analysis.alias_scopes[-1].items():
                if builtin is not None:
                    instance_aliases[(name,)] = builtin

            methods = [
                statement for statement in node.body if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            for method in methods:
                method_analysis, receiver_name = method_visitor(method)
                if receiver_name is None:
                    continue
                for key, builtin in method_analysis.attribute_alias_scopes[-1].items():
                    if key[0] == receiver_name and builtin is not None:
                        instance_aliases[key[1:]] = builtin

            findings: set[str] = set()
            for method in methods:
                method_analysis, _receiver_name = method_visitor(method, instance_aliases)
                findings.update(method_analysis.findings)
            return findings

        class ClassInstanceBuiltinVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.findings: set[str] = set()

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                self.findings.update(class_instance_builtin_findings(node))
                self.generic_visit(node)

        visitor = DangerousBuiltinCallVisitor()
        visitor.visit(tree)
        class_visitor = ClassInstanceBuiltinVisitor()
        class_visitor.visit(tree)
        visitor.findings.update(class_visitor.findings)
        return visitor.findings

    @staticmethod
    def _contextual_dangerous_builtin_sources(data: bytes) -> dict[str, str]:
        """Return builtin calls that require framed prefix alias context."""
        sources: dict[str, str] = {}
        for contextual_source, include_full_source in _embedded_python_extraction_windows(data):
            if not include_full_source:
                continue
            code_str, _byte_offsets = _decode_utf8_with_byte_offsets(contextual_source)
            parsed_snippet = _parse_embedded_python_snippet(code_str)
            if parsed_snippet is None:
                continue
            for builtin in JITScriptDetector._dangerous_builtin_calls_in_tree(parsed_snippet[0]):
                sources.setdefault(builtin, code_str)
        return sources

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
        if _has_source_like_embedded_python_start(data):
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

        bounded = data if include_full_source else data[:_EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT]
        matches = _candidate_embedded_python_snippets(bounded, include_full_source=include_full_source)
        prioritized_matches, omitted_budgeted_spans = _select_prioritized_embedded_python_snippets(
            matches, bounded=bounded
        )
        has_bounded_source = _has_source_like_embedded_python_start(bounded)
        has_source_beyond_bound = (
            not include_full_source
            and len(data) > _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT
            and _has_source_like_embedded_python_start(
                data,
                start_offset=max(
                    0,
                    _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT - _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES,
                ),
            )
        )
        if (
            not include_full_source
            and len(data) > _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT
            and (has_bounded_source or has_source_beyond_bound)
        ):
            findings.append(
                _embedded_python_analysis_incomplete_finding(
                    framework=framework,
                    context=context,
                    reason=_EMBEDDED_PYTHON_BYTE_LIMIT_REASON,
                    message=("Embedded Python/JIT analysis incomplete: payload exceeds the bounded byte scan window"),
                    max_scan_bytes=_EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT,
                )
            )
        bounded_high_risk_calls: set[tuple[str, str]] | None = None
        bounded_builtin_calls: set[str] | None = None
        snippet_high_risk_calls: set[tuple[str, str]] = set()
        snippet_builtin_calls: set[str] = set()
        contextual_builtin_sources = self._contextual_dangerous_builtin_sources(bounded)
        parsed_snippet_spans: list[tuple[int, int]] = []
        try:
            bounded_tree = ast.parse(textwrap.dedent(bounded.decode("utf-8")))
            bounded_high_risk_calls = _resolve_alias_aware_high_risk_calls(bounded_tree)
            bounded_builtin_calls = self._dangerous_builtin_calls_in_tree(bounded_tree)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            # Binary model blobs commonly contain non-Python framing bytes; keep
            # raw pattern detection active and fall back to extracted snippets.
            bounded_high_risk_calls = None
            bounded_builtin_calls = None

        for match, span, real_ranges in prioritized_matches:
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
                parsed_builtin_calls = (
                    self._dangerous_builtin_calls_in_tree(parsed_snippet[0]) if parsed_snippet is not None else None
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
                    has_builtin_call = (
                        builtin in parsed_builtin_calls
                        if parsed_builtin_calls is not None
                        else re.search(rf"(?<![.\w]){re.escape(builtin)}\s*\(", code_str) is not None
                    )
                    if has_builtin_call:
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
                    snippet_builtin_calls.update(self._dangerous_builtin_calls_in_tree(tree))
                    ast_findings = self._analyze_ast(tree, framework, context)
                    findings.extend(ast_findings)

            except Exception:
                # Failed to process this code snippet
                continue

        reported_builtins = {
            finding.builtin
            for finding in findings
            if finding.type == "dangerous_builtin" and finding.builtin is not None
        }
        for builtin, code_str in contextual_builtin_sources.items():
            snippet_builtin_calls.add(builtin)
            if builtin in reported_builtins:
                continue
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

        uncovered_omitted_spans = [
            span for span in omitted_budgeted_spans if not _is_span_inside_parsed_spans(span, parsed_snippet_spans)
        ]
        if uncovered_omitted_spans:
            findings.append(
                _embedded_python_analysis_incomplete_finding(
                    framework=framework,
                    context=context,
                    reason=_EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON,
                    message=("Embedded Python/JIT analysis incomplete: candidate snippet budget was exceeded"),
                    omitted_snippets=len(uncovered_omitted_spans),
                    candidates_count=len(matches),
                )
            )

        # Check for common code execution patterns in binary
        resolved_high_risk_calls = (bounded_high_risk_calls or set()) | snippet_high_risk_calls
        resolved_builtin_calls = (bounded_builtin_calls or set()) | snippet_builtin_calls
        for pattern, description in CODE_EXECUTION_PATTERNS:
            raw_pattern_spans = [match.span() for match in re.finditer(pattern, bounded)]
            pattern_match = len(raw_pattern_spans) > 0
            raw_match_only_in_parsed_snippets = bool(parsed_snippet_spans) and not _has_raw_match_outside_parsed_spans(
                raw_pattern_spans, parsed_snippet_spans
            )
            pattern_builtin = _CODE_EXECUTION_PATTERN_BUILTINS.get(description)
            if pattern_builtin is not None:
                if pattern_builtin in resolved_builtin_calls:
                    pattern_match = True
                elif bounded_builtin_calls is not None or raw_match_only_in_parsed_snippets:
                    continue
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
        resolved_dangerous_builtins = self._dangerous_builtin_calls_in_tree(tree)

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
                if isinstance(node.func, ast.Name) and node.func.id in resolved_dangerous_builtins:
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

        source_like_embedded_python = (
            _has_source_like_embedded_python_start(data)
            if model_type == "pickle"
            or (
                model_type in ["pytorch", "torchscript", "unknown"] and len(data) <= _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT
            )
            else False
        )
        model_specific_embedded_python_fully_scanned = False

        # Scan based on model type
        if model_type in ["pytorch", "torchscript"]:
            findings.extend(self.scan_torchscript(data, context))
            findings.extend(self.scan_advanced_torchscript_vulnerabilities(data, context))
            model_specific_embedded_python_fully_scanned = (
                source_like_embedded_python and len(data) <= _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT
            )

        if model_type in ["tensorflow", "tf", "keras"]:
            findings.extend(self.scan_tensorflow(data, context))
            model_specific_embedded_python_fully_scanned = (
                len(data) <= _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT
                and (b"SavedFunction" in data or b"saved_model.pb" in data)
                and (b"python_function" in data or b"function_spec" in data)
                and _has_source_like_embedded_python_start(data)
            )

        if model_type == "onnx":
            findings.extend(self.scan_onnx(data, context))

        if model_type == "pickle" and source_like_embedded_python:
            findings.extend(self._extract_and_check_python_code(data, "Generic Python", context))
            model_specific_embedded_python_fully_scanned = len(data) <= _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT

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
            model_specific_embedded_python_fully_scanned = len(data) <= _EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT and (
                source_like_embedded_python
                or (
                    (b"SavedFunction" in data or b"saved_model.pb" in data)
                    and (b"python_function" in data or b"function_spec" in data)
                    and _has_source_like_embedded_python_start(data)
                )
            )

        if not model_specific_embedded_python_fully_scanned and self._looks_like_dangerous_python_source(data):
            findings.extend(
                self._extract_and_check_python_code(
                    data,
                    "Generic Python",
                    context,
                    include_full_source=True,
                )
            )
        elif not model_specific_embedded_python_fully_scanned and self._looks_like_framed_dangerous_python_source(data):
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
