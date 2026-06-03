"""
JIT/Script Code Execution Detection for ML Models
==================================================

Detects potentially dangerous JIT-compiled code and script execution patterns
in TorchScript, TensorFlow SavedFunction, and ONNX models that could lead to
arbitrary code execution.

Part of ModelAudit's critical security validation suite.
"""

import ast
import builtins
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
_PROVEN_HIGH_RISK_CALL_PROBES = {
    "S108": (
        "runpy.run_path",
        b"\nimport runpy as __modelaudit_runpy\n__modelaudit_runpy.run_path('payload.py')\n",
    ),
    "S109": (
        "webbrowser.open",
        b"\nimport webbrowser as __modelaudit_webbrowser\n__modelaudit_webbrowser.open('https://example.invalid')\n",
    ),
    "S110": (
        "ctypes.CDLL",
        b"\nimport ctypes as __modelaudit_ctypes\n__modelaudit_ctypes.CDLL('payload.so')\n",
    ),
}
_PROVEN_RUNPY_CALL_PROBE = _PROVEN_HIGH_RISK_CALL_PROBES["S108"][1]
_TYPED_PROOF_BINDING_MARKERS = (
    b".get",
    b".open",
    b"CDLL",
    b"OleDLL",
    b"PyDLL",
    b"WinDLL",
    b"LoadLibrary",
    b"LibraryLoader",
    b"cdll",
    b"oledll",
    b"pydll",
    b"windll",
)
_TYPED_PROOF_MEMBER_NAMES = frozenset(
    {
        "get",
        "open",
        "open_new",
        "open_new_tab",
        "CDLL",
        "OleDLL",
        "PyDLL",
        "WinDLL",
        "LoadLibrary",
        "LibraryLoader",
        "cdll",
        "oledll",
        "pydll",
        "windll",
    }
)
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
_PRIORITY_CALL_MEMBER_NAMES = frozenset(
    {
        *(member_name for member_names in _PRIORITY_WILDCARD_IMPORT_ALIASES.values() for member_name in member_names),
        "OleDLL",
        "PyDLL",
        "WinDLL",
        "oledll",
    }
)
_PRIORITY_EMBEDDED_PYTHON_IMPORT_PATTERN = re.compile(
    rb"(?m)^\s*(?:"
    rb"import\s+(?:[a-z_][\w.]*(?:\s+as\s+[a-z_]\w*)?\s*,(?:\s|\\\r?\n)*)*(?:"
    + _PRIORITY_EMBEDDED_PYTHON_MODULE_PATTERN
    + rb")(?:[.\s,]|$)|"
    rb"from\s+(?:" + _PRIORITY_EMBEDDED_PYTHON_MODULE_PATTERN + rb")(?:[.\s]|\\\r?\n|$)"
    rb")"
)
_EMBEDDED_PYTHON_CONTEXT_ASSIGNMENT_LHS_PATTERN = (
    rb"(?:[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*(?:\s*:[^=\n#]+)?|[\(\[][A-Za-z_][^=\n#]*[\)\]])"
)
_EMBEDDED_PYTHON_BLOCK_PATTERN = re.compile(rb"def\s+\w+\s*\([^)]*\):[^}\x00]+|class\s+\w+[^}\x00]+")
_EMBEDDED_PYTHON_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])"
    rb"(?:(?:async\s+)?def\s+\w+|class\s+\w+|import\s+[A-Za-z_][\w.]*|"
    rb"from\s+[A-Za-z_][\w.]*(?:\s|\\\r?\n)+import)"
)
_EMBEDDED_PYTHON_CONTEXT_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])(?:if\s+[^:\n]+\s*:|import\s+[A-Za-z_][\w.]*|from\s+[A-Za-z_][\w.]*|"
    + _EMBEDDED_PYTHON_CONTEXT_ASSIGNMENT_LHS_PATTERN
    + rb"\s*=)"
)
_EMBEDDED_PYTHON_COMPOUND_CONTEXT_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])if\s+[^:\n]+\s*:\s*(?:import|from)\s+"
)
_COMPOUND_HEADER_MATCH_PATTERN = re.compile(
    rb"\b(?:async\s+def|if|elif|else|for|while|try|except|finally|with|class|def)\b"
)
_EMBEDDED_PYTHON_STATIC_MEMBER_CONTEXT_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])(?:[A-Za-z_]\w*\s*\.\s*__dict__|vars\s*\(\s*[A-Za-z_]\w*\s*\))"
    rb"\s*(?:\[[^\]\n]*\]\s*=|"
    rb"\.\s*(?:__setitem__|update|setdefault|pop|__delitem__)\s*\()"
)
_EMBEDDED_PYTHON_STATIC_MAPPING_CALL_CONTEXT_START_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_'\".])[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\([^#\n]*__dict__[^#\n]*\)"
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
    if start_offsets and b"__future__" in bounded and b"annotations" in bounded and _source_defers_annotations(bounded):
        span = (start_offsets[0], len(bounded))
        return [(bounded[span[0] : span[1]], span, (span,))]
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
    if bounded_end < len(candidate):
        complete_line_end = candidate.rfind(b"\n", line_start, bounded_end) + 1
        if complete_line_end > line_start:
            bounded_end = complete_line_end
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

    retained_context = _compact_candidate_segments(candidate, segment_ranges)
    aliases = _priority_import_aliases(retained_context)
    has_late_reference_syntax = any(token in candidate[bounded_end:] for token in (b"(", b".", b"["))
    usage_lines, proved_rule_codes = (
        _priority_alias_usage_lines(candidate, aliases, bounded_end)
        if aliases and has_late_reference_syntax
        else ([], frozenset())
    )
    for usage_line in usage_lines:
        for header_start, header_end in _enclosing_compound_header_segments(candidate, usage_line[0]):
            add_segment(header_start, header_end)
        add_segment(*usage_line)

    tail_start = max(bounded_end, len(candidate) - _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES)
    tail_start = candidate.rfind(b"\n", 0, tail_start) + 1
    if bounded_end < tail_start < len(candidate):
        add_segment(tail_start, len(candidate))

    merged_ranges = _merge_candidate_segment_ranges(segment_ranges)
    compact_candidate = _compact_candidate_segments(candidate, merged_ranges)
    for rule_code in sorted(proved_rule_codes):
        proof = _PROVEN_HIGH_RISK_CALL_PROBES.get(rule_code)
        if proof is not None:
            compact_candidate += proof[1]
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
    source, _byte_offsets = _decode_utf8_with_byte_offsets(candidate)
    source = textwrap.dedent(source)
    parsed_snippet = _parse_embedded_python_snippet(source)
    if parsed_snippet is None:
        return frozenset()
    tree, parsed_chars = parsed_snippet
    source = source[:parsed_chars]

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
        reference_roots = _alias_reference_root_names(value)
        if not reference_roots and isinstance(value, ast.Call):
            reference_roots = _alias_reference_root_names(value.func)
        if not reference_roots or reference_roots.isdisjoint(discovered_aliases):
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
        f"{target}.msvcrt",
    ]


def _priority_alias_usage_lines(
    candidate: bytes,
    aliases: frozenset[bytes],
    search_start: int,
) -> tuple[list[tuple[int, int]], frozenset[str]]:
    usage_lines: list[tuple[int, int]] = []
    retained_alias_names = {alias.decode("utf-8") for alias in aliases}
    relevant_binding_names = set(retained_alias_names)
    late_definitions: dict[str, list[tuple[bytes, tuple[int, int]]]] = {}
    late_definition_starts: dict[str, list[int]] = {}
    alias_dependency_names_cache: dict[tuple[int, int], set[str]] = {}
    definite_shadowed_names: set[str] = set()
    pending_shadow_spans: dict[str, tuple[int, int]] = {}
    fail_closed_dangerous_names: set[str] = set()
    forwarded_rule_codes: dict[str, frozenset[str]] = {}
    typed_rule_source_names: set[str] = set()
    typed_member_state_spans: dict[str, list[tuple[int, int]]] = {}
    typed_member_state_signatures: dict[str, list[bytes]] = {}
    typed_member_state_overflow_starts: dict[str, int] = {}
    typed_member_mapping_aliases: dict[str, str] = {}
    typed_member_setdefault_aliases: dict[str, str] = {}
    typed_member_setitem_aliases: dict[str, str] = {}
    typed_member_update_aliases: dict[str, str] = {}
    typed_member_descriptor_setdefault_aliases: set[str] = set()
    typed_member_delete_aliases: dict[str, str] = {}
    typed_member_descriptor_delete_aliases: set[str] = set()
    definitely_deleted_typed_members: set[str] = set()
    typed_member_delete_spans: dict[str, tuple[int, int]] = {}
    typed_member_write_spans: set[tuple[int, int]] = set()
    typed_safe_member_write_spans: set[tuple[str, tuple[int, int]]] = set()
    typed_fail_closed_member_write_spans: set[tuple[str, tuple[int, int]]] = set()
    typed_binding_state_spans: dict[tuple[int, int], list[tuple[int, int]]] = {}
    typed_statement_rule_codes: dict[tuple[bytes, tuple[bytes, ...]], frozenset[str]] = {}
    typed_rule_probe_count = 0
    forwarded_state_sizes: dict[str, int] = dict.fromkeys(retained_alias_names, 0)
    forwarded_safe_names: set[str] = set()
    runpy_member_state_spans: dict[str, list[tuple[int, int]]] = {}
    fail_closed_runpy_members: set[str] = set()
    runpy_namespace_update_aliases: dict[str, str] = {}
    runpy_namespace_setitem_aliases: dict[str, str] = {}
    runpy_namespace_setdefault_aliases: dict[str, str] = {}
    runpy_namespace_delete_aliases: dict[str, str] = {}
    runpy_descriptor_delete_aliases: set[str] = set()
    definitely_deleted_runpy_members: set[str] = set()
    uncertain_runpy_namespace_names: set[str] = set()
    shadowed_descriptor_names: set[str] = set()
    uncertain_descriptor_names: set[str] = set()
    builtins_alias_names: set[str] = {"builtins"}
    shadowed_builtin_helper_names: set[str] = set()
    shadowed_truthy_builtin_names: set[str] = set()
    truthy_builtin_state_spans: list[tuple[int, int]] = []
    truthy_builtin_capture_names: set[str] = set()
    late_builtins_import_spans: list[tuple[int, int]] = []
    uncertain_builtin_helper_names: set[str] = set()
    canonical_eager_generator_consumer_aliases = _canonical_eager_generator_consumer_aliases()
    locally_shadowed_eager_generator_consumers: set[str] = set()
    invalidated_builtin_eager_generator_consumers: set[str] = set()
    active_builtin_eager_generator_aliases = {
        consumer: {consumer, f"builtins.{consumer}"} for consumer in _EAGER_LATE_GENERATOR_CONSUMERS
    }
    exception_type_aliases = {
        **{name: name for name in _BUILTIN_EXCEPTION_TYPE_NAMES},
        **{f"builtins.{name}": name for name in _BUILTIN_EXCEPTION_TYPE_NAMES},
    }
    canonical_builtin_helper_aliases: dict[str, str] = {
        "getattr": "getattr",
        "builtins.getattr": "getattr",
        "vars": "vars",
        "builtins.vars": "vars",
        "setattr": "setattr",
        "builtins.setattr": "setattr",
        "delattr": "delattr",
        "builtins.delattr": "delattr",
    }
    uncertain_canonical_builtin_helper_aliases: set[str] = set()
    builtin_dict_descriptor_aliases: set[str] = {"dict"}
    builtin_dict_update_aliases: set[str] = set()
    uncertain_builtin_dict_update_aliases: set[str] = set()
    builtin_dict_descriptor_setitem_aliases: set[str] = set()
    uncertain_builtin_dict_descriptor_setitem_aliases: set[str] = set()
    builtin_dict_mapping_aliases: set[str] = set()
    uncertain_builtin_dict_mapping_aliases: set[str] = set()
    builtin_dict_mapping_update_aliases: set[str] = set()
    uncertain_builtin_dict_mapping_update_aliases: set[str] = set()
    builtin_dict_mapping_setitem_aliases: set[str] = set()
    uncertain_builtin_dict_mapping_setitem_aliases: set[str] = set()
    builtin_dict_descriptor_setdefault_aliases: set[str] = set()
    uncertain_builtin_dict_descriptor_setdefault_aliases: set[str] = set()
    builtin_mapping_state_spans: dict[str, tuple[int, int]] = {}
    runpy_namespace_owner_names = {alias.decode("utf-8") for alias in aliases}
    deferred_annotations = _source_defers_annotations(candidate)

    def register_builtins_alias(name: str) -> None:
        builtins_alias_names.add(name)
        canonical_eager_generator_consumer_aliases.update(
            {
                f"{name}.{consumer}": consumer
                for consumer in _EAGER_LATE_GENERATOR_CONSUMERS
                if consumer not in invalidated_builtin_eager_generator_consumers
            }
        )
        for consumer in _EAGER_LATE_GENERATOR_CONSUMERS - invalidated_builtin_eager_generator_consumers:
            active_builtin_eager_generator_aliases[consumer].add(f"{name}.{consumer}")
        canonical_builtin_helper_aliases.update(
            {f"{name}.{helper_name}": helper_name for helper_name in {"getattr", "vars", "setattr", "delattr"}}
        )
        uncertain_canonical_builtin_helper_aliases.difference_update(
            {f"{name}.{helper_name}" for helper_name in {"getattr", "vars", "setattr", "delattr"}}
        )

    def discard_builtins_alias(name: str) -> None:
        builtins_alias_names.discard(name)
        for consumer in _EAGER_LATE_GENERATOR_CONSUMERS:
            canonical_eager_generator_consumer_aliases.pop(f"{name}.{consumer}", None)
            active_builtin_eager_generator_aliases[consumer].discard(f"{name}.{consumer}")
        for helper_name in {"getattr", "vars", "setattr", "delattr"}:
            canonical_builtin_helper_aliases.pop(f"{name}.{helper_name}", None)
            uncertain_canonical_builtin_helper_aliases.discard(f"{name}.{helper_name}")

    def is_truthy_builtin_reference(reference: str | None) -> bool:
        if reference is None:
            return False
        owner, separator, member = reference.rpartition(".")
        return bool(separator) and owner in builtins_alias_names and member in {"print", "len"}

    def is_active_builtin_helper(reference: str | None, helper_name: str) -> bool:
        blocked_helpers = shadowed_builtin_helper_names | uncertain_builtin_helper_names
        return (
            reference is not None
            and canonical_builtin_helper_aliases.get(reference) == helper_name
            and reference not in uncertain_canonical_builtin_helper_aliases
            and reference not in blocked_helpers
            and ("." not in reference or f"builtins.{helper_name}" not in blocked_helpers)
        )

    def is_active_builtin_dict_descriptor_owner(reference: str | None) -> bool:
        if reference is None:
            return False
        blocked_descriptors = shadowed_descriptor_names | uncertain_descriptor_names
        if reference in builtin_dict_descriptor_aliases:
            return reference not in blocked_descriptors
        return (
            reference.endswith(".dict")
            and reference.removesuffix(".dict") in builtins_alias_names
            and "builtins.dict" not in blocked_descriptors
        )

    def is_active_builtin_dict_delete_descriptor(reference: str | None) -> bool:
        if is_active_builtin_dict_descriptor_owner(reference):
            return True
        if reference is None:
            return False
        owner, separator, method = reference.rpartition(".")
        if not separator or method not in {"pop", "__delitem__"}:
            return False
        return is_active_builtin_dict_descriptor_owner(owner)

    def invalidate_eager_consumer_aliases(defined_consumers: set[str], mutated_builtin_consumers: set[str]) -> None:
        for consumer in defined_consumers | mutated_builtin_consumers:
            canonical_eager_generator_consumer_aliases.pop(consumer, None)
        for consumer in mutated_builtin_consumers:
            invalidated_builtin_eager_generator_consumers.add(consumer)
            for alias_reference in active_builtin_eager_generator_aliases[consumer]:
                canonical_eager_generator_consumer_aliases.pop(alias_reference, None)
            active_builtin_eager_generator_aliases[consumer].clear()

    def update_exception_type_aliases(
        statement: bytes, *, evaluate_annotations: bool = True, uncertain: bool = False
    ) -> None:
        uncertain_effect = (
            uncertain
            or _statement_uses_uncertain_builtin_helper(
                statement, uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases
            )
            or not _python_identifier_names(statement).isdisjoint(
                uncertain_builtin_dict_mapping_aliases
                | uncertain_builtin_dict_mapping_update_aliases
                | uncertain_builtin_dict_mapping_setitem_aliases
            )
        )
        for name, canonical_name in _exception_type_alias_bindings(
            statement,
            exception_type_aliases,
            builtins_alias_names=builtins_alias_names,
            builtin_dict_mapping_aliases=builtin_dict_mapping_aliases,
            builtin_dict_mapping_update_aliases=builtin_dict_mapping_update_aliases,
            builtin_dict_mapping_setitem_aliases=builtin_dict_mapping_setitem_aliases,
            shadowed_builtin_helper_names=shadowed_builtin_helper_names,
            canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            evaluate_annotations=evaluate_annotations,
        ).items():
            if uncertain_effect or canonical_name is None:
                exception_type_aliases.pop(name, None)
            else:
                exception_type_aliases[name] = canonical_name

    def add_late_definition(name: str, statement: bytes, span: tuple[int, int]) -> None:
        if late_definition_starts.get(name, [])[-1:] == [span[0]]:
            return
        late_definitions.setdefault(name, []).append((statement, span))
        late_definition_starts.setdefault(name, []).append(span[0])

    def latest_definition_before(name: str, offset: int) -> tuple[bytes, tuple[int, int]] | None:
        starts = late_definition_starts.get(name)
        if starts is None:
            return None
        definition_index = bisect_left(starts, offset) - 1
        if definition_index < 0:
            return None
        return late_definitions[name][definition_index]

    def typed_member_write_keys(statement: bytes, deleted_members: set[str]) -> set[str]:
        structural_statement = statement.lstrip(b"\x00\xff")
        tracked_keys: set[str] = set()

        def tracked_reference(owner: bytes, member: bytes) -> str | None:
            owner_name = owner.decode("utf-8")
            member_name = member.decode("utf-8")
            if owner_name not in retained_alias_names or member_name not in _TYPED_PROOF_MEMBER_NAMES:
                return None
            return f"{owner_name}.{member_name}"

        direct_match = re.match(
            rb"\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)+)(?:\s*:[^=\n]+)?\s*=(?!=)",
            structural_statement,
        )
        if direct_match is not None:
            reference = re.sub(rb"\s+", b"", direct_match.group(1))
            owner, _separator, member = reference.partition(b".")
            tracked = tracked_reference(owner, member)
            if tracked is not None:
                tracked_keys.add(tracked)

        mapping_match = re.match(
            rb"\s*(?:vars\s*\(\s*(?P<vars_owner>[A-Za-z_]\w*)\s*\)|"
            rb"(?P<dict_owner>[A-Za-z_]\w*)\s*\.\s*__dict__)\s*"
            rb"\[\s*['\"](?P<member>[A-Za-z_]\w*)['\"]\s*\]\s*=(?!=)",
            structural_statement,
        )
        if mapping_match is not None and "vars" not in shadowed_builtin_helper_names:
            owner = mapping_match.group("vars_owner") or mapping_match.group("dict_owner")
            tracked = tracked_reference(owner, mapping_match.group("member"))
            if tracked is not None:
                tracked_keys.add(tracked)

        update_match = re.match(
            rb"\s*(?:vars\s*\(\s*(?P<vars_owner>[A-Za-z_]\w*)\s*\)|"
            rb"(?P<dict_owner>[A-Za-z_]\w*)\s*\.\s*__dict__)\s*\.\s*update\s*"
            rb"\(\s*(?P<member>[A-Za-z_]\w*)\s*=",
            structural_statement,
        )
        if update_match is not None and "vars" not in shadowed_builtin_helper_names:
            owner = update_match.group("vars_owner") or update_match.group("dict_owner")
            tracked = tracked_reference(owner, update_match.group("member"))
            if tracked is not None:
                tracked_keys.add(tracked)

        setattr_match = re.match(
            rb"\s*setattr\s*\(\s*(?P<owner>[A-Za-z_]\w*)\s*,\s*['\"](?P<member>[A-Za-z_]\w*)['\"]\s*,",
            structural_statement,
        )
        if (
            setattr_match is not None
            and "setattr" not in shadowed_builtin_helper_names | uncertain_builtin_helper_names
        ):
            tracked = tracked_reference(setattr_match.group("owner"), setattr_match.group("member"))
            if tracked is not None:
                tracked_keys.add(tracked)

        source, _byte_offsets = _decode_utf8_with_byte_offsets(structural_statement)
        tree = _parse_late_replay_tree(source)
        if tree is None:
            return tracked_keys

        def mapping_owner(node: ast.AST) -> str | None:
            if isinstance(node, ast.Name):
                return typed_member_mapping_aliases.get(node.id)
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in retained_alias_names
            ):
                return node.value.id
            if (
                isinstance(node, ast.Call)
                and is_active_builtin_helper(_simple_reference_name(node.func), "vars")
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in retained_alias_names
            ):
                return node.args[0].id
            return None

        def static_member_reference(owner: str | None, key: ast.AST | None) -> str | None:
            if owner is None or key is None:
                return None
            member_name = _static_getattr_member_name(key)
            return (
                f"{owner}.{member_name}"
                if member_name is not None and member_name in _TYPED_PROOF_MEMBER_NAMES
                else None
            )

        def record_target(target: ast.AST) -> None:
            if isinstance(target, (ast.Tuple, ast.List)):
                for element in target.elts:
                    record_target(element)
                return
            if isinstance(target, ast.Starred):
                record_target(target.value)
                return
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                tracked = tracked_reference(target.value.id.encode("utf-8"), target.attr.encode("utf-8"))
                if tracked is not None:
                    tracked_keys.add(tracked)
            elif isinstance(target, ast.Subscript):
                static_reference = static_member_reference(mapping_owner(target.value), target.slice)
                if static_reference is not None:
                    tracked_keys.add(static_reference)

        def record_call(node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"__setitem__", "setdefault"} and node.args:
                static_reference = static_member_reference(mapping_owner(node.func.value), node.args[0])
                if static_reference is not None and (
                    node.func.attr != "setdefault" or static_reference in deleted_members
                ):
                    tracked_keys.add(static_reference)
            helper_reference = _simple_reference_name(node.func)
            if (
                is_active_builtin_helper(helper_reference, "setattr")
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
            ):
                static_reference = static_member_reference(node.args[0].id, node.args[1])
                if static_reference is not None:
                    tracked_keys.add(static_reference)
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in typed_member_setdefault_aliases
                and len(node.args) >= 2
            ):
                static_reference = static_member_reference(typed_member_setdefault_aliases[node.func.id], node.args[0])
                if static_reference is not None and static_reference in deleted_members:
                    tracked_keys.add(static_reference)
            if isinstance(node.func, ast.Name) and node.func.id in typed_member_setitem_aliases and len(node.args) >= 2:
                static_reference = static_member_reference(typed_member_setitem_aliases[node.func.id], node.args[0])
                if static_reference is not None:
                    tracked_keys.add(static_reference)
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in typed_member_descriptor_setdefault_aliases
                and len(node.args) >= 3
            ):
                static_reference = static_member_reference(mapping_owner(node.args[0]), node.args[1])
                if static_reference is not None and static_reference in deleted_members:
                    tracked_keys.add(static_reference)
            update_owner: str | None = None
            update_arguments = node.args
            if isinstance(node.func, ast.Name) and node.func.id in typed_member_update_aliases:
                update_owner = typed_member_update_aliases[node.func.id]
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "update",
                "__ior__",
                "__setitem__",
                "setdefault",
            }:
                update_owner = mapping_owner(node.func.value)
                descriptor_name = _simple_reference_name(node.func.value)
                if (
                    update_owner is None
                    and descriptor_name in builtin_dict_descriptor_aliases
                    and descriptor_name not in shadowed_descriptor_names | uncertain_descriptor_names
                    and node.args
                ):
                    update_owner = mapping_owner(node.args[0])
                    update_arguments = node.args[1:]
            if update_owner is None:
                return
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"__setitem__", "setdefault"}:
                if len(update_arguments) >= 2:
                    static_reference = static_member_reference(update_owner, update_arguments[0])
                    if static_reference is not None and (
                        node.func.attr == "__setitem__" or static_reference in deleted_members
                    ):
                        tracked_keys.add(static_reference)
                return
            for argument in update_arguments:
                for static_key_node, _value in _runpy_static_update_items(argument) or []:
                    static_reference = static_member_reference(update_owner, static_key_node)
                    if static_reference is not None:
                        tracked_keys.add(static_reference)
            for keyword in node.keywords:
                if keyword.arg is not None:
                    static_reference = tracked_reference(update_owner.encode("utf-8"), keyword.arg.encode("utf-8"))
                    if static_reference is not None:
                        tracked_keys.add(static_reference)
                elif isinstance(keyword.value, ast.Dict):
                    for static_keyword_key_node in keyword.value.keys:
                        static_reference = static_member_reference(update_owner, static_keyword_key_node)
                        if static_reference is not None:
                            tracked_keys.add(static_reference)

        for ast_statement in _deterministically_executed_statements(tree.body):
            if isinstance(ast_statement, ast.Assign):
                for target in ast_statement.targets:
                    record_target(target)
            elif isinstance(ast_statement, ast.AnnAssign):
                record_target(ast_statement.target)
            elif isinstance(ast_statement, ast.AugAssign) and isinstance(ast_statement.op, ast.BitOr):
                augmented_owner = mapping_owner(ast_statement.target)
                if augmented_owner is not None:
                    for key, _value in _runpy_static_update_items(ast_statement.value) or []:
                        static_reference = static_member_reference(augmented_owner, key)
                        if static_reference is not None:
                            tracked_keys.add(static_reference)
            elif (
                isinstance(ast_statement, (ast.For, ast.AsyncFor))
                and _static_late_iter_truth(ast_statement.iter) is not False
            ):
                record_target(ast_statement.target)
            elif isinstance(ast_statement, (ast.With, ast.AsyncWith)):
                for item in ast_statement.items:
                    if item.optional_vars is not None:
                        record_target(item.optional_vars)
            for value in _deterministically_evaluated_statement_expressions(
                ast_statement, evaluate_annotations=not deferred_annotations
            ):
                for call in _deterministically_executed_expression_calls(
                    value, eager_generator_consumers=canonical_eager_generator_consumer_aliases
                ):
                    record_call(call)
        return tracked_keys

    def typed_member_delete_keys(statement: bytes) -> set[str]:
        source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
        tree = _parse_late_replay_tree(source)
        if tree is None:
            return set()
        deleted_keys: set[str] = set()

        def mapping_owner(node: ast.AST) -> str | None:
            if isinstance(node, ast.Name):
                return typed_member_mapping_aliases.get(node.id)
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in retained_alias_names
            ):
                return node.value.id
            if (
                isinstance(node, ast.Call)
                and is_active_builtin_helper(_simple_reference_name(node.func), "vars")
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in retained_alias_names
            ):
                return node.args[0].id
            return None

        def record_mapping_key(owner: str | None, key: ast.AST | None) -> None:
            if owner is None or key is None:
                return
            member_name = _static_getattr_member_name(key)
            if member_name in _TYPED_PROOF_MEMBER_NAMES:
                deleted_keys.add(f"{owner}.{member_name}")

        for ast_statement in _deterministically_executed_statements(tree.body):
            if isinstance(ast_statement, ast.Delete):
                for target in ast_statement.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id in retained_alias_names
                        and target.attr in _TYPED_PROOF_MEMBER_NAMES
                    ):
                        deleted_keys.add(f"{target.value.id}.{target.attr}")
                    elif isinstance(target, ast.Subscript):
                        record_mapping_key(mapping_owner(target.value), target.slice)
            for value in _deterministically_evaluated_statement_expressions(
                ast_statement, evaluate_annotations=not deferred_annotations
            ):
                for call in _deterministically_executed_expression_calls(
                    value, eager_generator_consumers=canonical_eager_generator_consumer_aliases
                ):
                    helper_reference = _simple_reference_name(call.func)
                    if (
                        is_active_builtin_helper(helper_reference, "delattr")
                        and len(call.args) >= 2
                        and isinstance(call.args[0], ast.Name)
                        and call.args[0].id in retained_alias_names
                        and (member_name := _static_getattr_member_name(call.args[1])) in _TYPED_PROOF_MEMBER_NAMES
                    ):
                        deleted_keys.add(f"{call.args[0].id}.{member_name}")
                    elif isinstance(call.func, ast.Name) and call.func.id in typed_member_delete_aliases and call.args:
                        record_mapping_key(typed_member_delete_aliases[call.func.id], call.args[0])
                    elif (
                        isinstance(call.func, ast.Name)
                        and call.func.id in typed_member_descriptor_delete_aliases
                        and len(call.args) >= 2
                    ):
                        record_mapping_key(mapping_owner(call.args[0]), call.args[1])
                    elif (
                        isinstance(call.func, ast.Attribute) and call.func.attr in {"pop", "__delitem__"} and call.args
                    ):
                        record_mapping_key(mapping_owner(call.func.value), call.args[0])
                        descriptor_reference = _simple_reference_name(call.func.value)
                        if is_active_builtin_dict_delete_descriptor(descriptor_reference) and len(call.args) >= 2:
                            record_mapping_key(mapping_owner(call.args[0]), call.args[1])
        return deleted_keys

    def typed_reference_rule_codes(reference: str | None) -> frozenset[str]:
        if reference is None:
            return frozenset()
        _owner, _separator, member = reference.partition(".")
        if member in {"get", "open", "open_new", "open_new_tab"}:
            return frozenset({"S109"})
        if member in _TYPED_PROOF_MEMBER_NAMES:
            return frozenset({"S110"})
        return frozenset()

    def typed_member_state_before(reference: str, offset: int) -> tuple[list[tuple[int, int]], bool]:
        spans = typed_member_state_spans.get(reference)
        selected = [span for span in (spans or []) if span[0] < offset]
        overflow_start = typed_member_state_overflow_starts.get(reference)
        return selected, overflow_start is not None and overflow_start < offset

    def typed_member_state_signature(reference: str | None, offset: int) -> tuple[bytes, ...]:
        if reference is None:
            return ()
        spans, overflowed = typed_member_state_before(reference, offset)
        if overflowed:
            return (b"<overflow>",)
        signatures = typed_member_state_signatures.get(reference, [])
        return tuple(signatures[: len(spans)])

    def typed_member_state_is_proven_safe(span: tuple[int, int], reference: str) -> bool:
        statement = candidate[span[0] : span[1]].lstrip(b"\x00\xff")
        if "print" in shadowed_truthy_builtin_names:
            return False
        owner, _separator, member = reference.partition(".")
        source, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
        tree = _parse_late_replay_tree(source)
        if tree is None:
            return False

        def is_builtin_print(node: ast.AST | None) -> bool:
            return isinstance(node, ast.Name) and node.id == "print"

        def is_tracked_member_key(node: ast.AST | None) -> bool:
            return node is not None and _static_getattr_member_name(node) == member

        def mapping_targets_owner(node: ast.AST) -> bool:
            if isinstance(node, ast.Name):
                return typed_member_mapping_aliases.get(node.id) == owner
            return (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id == owner
            ) or (
                isinstance(node, ast.Call)
                and is_active_builtin_helper(_simple_reference_name(node.func), "vars")
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == owner
            )

        tracked_values: list[ast.AST | None] = []

        def record_target_value(target: ast.AST, value: ast.AST | None) -> None:
            if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
                for element, element_value in zip(target.elts, value.elts, strict=False):
                    record_target_value(element, element_value)
                return
            if isinstance(target, ast.Starred):
                return
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == owner
                and target.attr == member
            ) or (
                isinstance(target, ast.Subscript)
                and mapping_targets_owner(target.value)
                and is_tracked_member_key(target.slice)
            ):
                tracked_values.append(value)

        def record_call(call: ast.Call) -> None:
            if (
                is_active_builtin_helper(_simple_reference_name(call.func), "setattr")
                and len(call.args) >= 3
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == owner
                and is_tracked_member_key(call.args[1])
            ):
                tracked_values.append(call.args[2])
                return
            if (
                isinstance(call.func, ast.Name)
                and call.func.id in typed_member_setdefault_aliases
                and len(call.args) >= 2
                and typed_member_setdefault_aliases[call.func.id] == owner
                and is_tracked_member_key(call.args[0])
            ):
                tracked_values.append(call.args[1])
                return
            if isinstance(call.func, ast.Name) and call.func.id in typed_member_setitem_aliases and len(call.args) >= 2:
                if typed_member_setitem_aliases[call.func.id] == owner and is_tracked_member_key(call.args[0]):
                    tracked_values.append(call.args[1])
                return
            if (
                isinstance(call.func, ast.Name)
                and call.func.id in typed_member_descriptor_setdefault_aliases
                and len(call.args) >= 3
                and mapping_targets_owner(call.args[0])
                and is_tracked_member_key(call.args[1])
            ):
                tracked_values.append(call.args[2])
                return
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in {"__setitem__", "setdefault"}
                and len(call.args) >= 2
                and mapping_targets_owner(call.func.value)
                and is_tracked_member_key(call.args[0])
            ):
                tracked_values.append(call.args[1])
                return
            update_owner_matches = False
            update_arguments = call.args
            if isinstance(call.func, ast.Name) and call.func.id in typed_member_update_aliases:
                update_owner_matches = typed_member_update_aliases[call.func.id] == owner
            if isinstance(call.func, ast.Attribute) and call.func.attr in {
                "update",
                "__ior__",
                "__setitem__",
                "setdefault",
            }:
                update_owner_matches = mapping_targets_owner(call.func.value)
                descriptor_name = _simple_reference_name(call.func.value)
                if (
                    not update_owner_matches
                    and descriptor_name in builtin_dict_descriptor_aliases
                    and descriptor_name not in shadowed_descriptor_names | uncertain_descriptor_names
                    and call.args
                ):
                    update_owner_matches = mapping_targets_owner(call.args[0])
                    update_arguments = call.args[1:]
            if not update_owner_matches:
                return
            if isinstance(call.func, ast.Attribute) and call.func.attr in {"__setitem__", "setdefault"}:
                if len(update_arguments) >= 2 and is_tracked_member_key(update_arguments[0]):
                    tracked_values.append(update_arguments[1])
                return
            for argument in update_arguments:
                tracked_values.extend(
                    value for key, value in _runpy_static_update_items(argument) or [] if is_tracked_member_key(key)
                )
            for keyword in call.keywords:
                if keyword.arg == member:
                    tracked_values.append(keyword.value)
                elif keyword.arg is None and isinstance(keyword.value, ast.Dict):
                    tracked_values.extend(
                        value
                        for key, value in zip(keyword.value.keys, keyword.value.values, strict=True)
                        if is_tracked_member_key(key)
                    )

        for ast_statement in _deterministically_executed_statements(tree.body):
            if isinstance(ast_statement, ast.Assign):
                for target in ast_statement.targets:
                    record_target_value(target, ast_statement.value)
            elif isinstance(ast_statement, ast.AnnAssign):
                record_target_value(ast_statement.target, ast_statement.value)
            elif (
                isinstance(ast_statement, ast.AugAssign)
                and isinstance(ast_statement.op, ast.BitOr)
                and mapping_targets_owner(ast_statement.target)
            ):
                tracked_values.extend(
                    value
                    for key, value in _runpy_static_update_items(ast_statement.value) or []
                    if is_tracked_member_key(key)
                )
            elif (
                isinstance(ast_statement, (ast.For, ast.AsyncFor))
                and _static_late_iter_truth(ast_statement.iter) is not False
            ):
                loop_value = (
                    ast_statement.iter.elts[0]
                    if isinstance(ast_statement.iter, (ast.List, ast.Tuple)) and len(ast_statement.iter.elts) == 1
                    else None
                )
                record_target_value(ast_statement.target, loop_value)
            elif isinstance(ast_statement, (ast.With, ast.AsyncWith)):
                for item in ast_statement.items:
                    if item.optional_vars is None:
                        continue
                    record_target_value(item.optional_vars, None)
            for value in _deterministically_evaluated_statement_expressions(
                ast_statement, evaluate_annotations=not deferred_annotations
            ):
                for call in _deterministically_executed_expression_calls(
                    value, eager_generator_consumers=canonical_eager_generator_consumer_aliases
                ):
                    record_call(call)
        return bool(tracked_values) and all(is_builtin_print(value) for value in tracked_values)

    def typed_member_write_is_inert_forwarding(statement: bytes, reference: str | None) -> bool:
        if reference is None:
            return False
        owner, _separator, _member = reference.partition(".")
        if owner in late_definitions:
            return False
        normalized_statement = re.sub(rb"\s+", b"", statement.lstrip(b"\x00\xff"))
        encoded_reference = reference.encode("utf-8")
        return normalized_statement == encoded_reference + b"=" + encoded_reference

    def typed_member_write_dependency_names(statement: bytes) -> set[str]:
        return _assignment_value_dependency_names(statement) | _python_identifier_names(statement)

    def deterministic_binding_references(statement: bytes) -> dict[str, str | None]:
        source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
        try:
            tree = ast.parse(textwrap.dedent(source))
        except (RecursionError, SyntaxError, ValueError):
            return {}
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign) or len(tree.body[0].targets) != 1:
            return {}
        target = tree.body[0].targets[0]
        value = tree.body[0].value
        if isinstance(target, ast.Name):
            return {target.id: _simple_reference_name(value)}
        if not isinstance(target, (ast.Tuple, ast.List)) or not isinstance(value, (ast.Tuple, ast.List)):
            return {}
        if len(target.elts) != len(value.elts):
            return {}
        return {
            element.id: _simple_reference_name(value_element)
            for element, value_element in zip(target.elts, value.elts, strict=True)
            if isinstance(element, ast.Name)
        }

    def typed_member_proof_spans(reference: str | None, offset: int) -> tuple[list[tuple[int, int]], bool]:
        if reference is None:
            return [], False
        state_spans, overflowed = typed_member_state_before(reference, offset)
        if overflowed:
            return [], True
        selected: set[tuple[int, int]] = set()
        selected_size = 0
        pending = [(candidate[start:end], (start, end)) for start, end in state_spans]
        while pending:
            state_statement, state_span = pending.pop()
            if state_span in selected:
                continue
            selected.add(state_span)
            selected_size += state_span[1] - state_span[0] + 1
            pending.extend(
                (candidate[start:end], (start, end)) for start, end in typed_binding_state_spans.get(state_span, [])
            )
            for dependency in _alias_binding_dependency_names(state_statement):
                definition = latest_definition_before(dependency, state_span[0])
                if definition is not None:
                    pending.append(definition)
            for dependency in typed_member_write_dependency_names(state_statement):
                definition = latest_definition_before(dependency, state_span[0])
                if definition is not None:
                    pending.append(definition)
            if selected_size > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
                return [], True
        return sorted(selected), False

    def inferred_binding_rule_codes(name: str, statement: bytes, binding_start: int) -> frozenset[str]:
        nonlocal typed_rule_probe_count
        inference_context = priority_context
        if aliases - _priority_import_aliases(inference_context):
            retained_prefix_context = _extract_priority_prefix_context(candidate[:search_start])
            if retained_prefix_context:
                inference_context = retained_prefix_context + b"\n" + inference_context
        typed_reference = _simple_late_assignment_value_reference(statement)
        typed_state_spans, typed_state_overflowed = typed_member_proof_spans(typed_reference, binding_start)
        if typed_state_overflowed or typed_rule_probe_count >= _MAX_PRIORITY_ASSIGNMENT_PROBES:
            return typed_reference_rule_codes(typed_reference)
        typed_rule_probe_count += 1
        proof = b"\n".join(
            [
                inference_context,
                *(candidate[start:end] for start, end in truthy_builtin_state_spans),
                *(candidate[start:end] for start, end in typed_state_spans),
                statement,
            ]
        )
        source, _byte_offsets = _decode_utf8_with_byte_offsets(
            proof + b"\n" + "\n".join(_priority_assignment_probe_calls(name)).encode("utf-8")
        )
        parsed_snippet = _parse_embedded_python_snippet(textwrap.dedent(source))
        if parsed_snippet is None:
            return frozenset()
        try:
            return frozenset(
                rule_code
                for _call_name, rule_code in _resolve_alias_aware_high_risk_calls(parsed_snippet[0])
                if rule_code in _PROVEN_HIGH_RISK_CALL_PROBES
            )
        except RecursionError:
            return typed_reference_rule_codes(typed_reference)

    def bind_forwarded_rule_codes(name: str, statement: bytes, forwarded_dependency: str, binding_start: int) -> None:
        if forwarded_dependency in forwarded_rule_codes:
            forwarded_rule_codes[name] = forwarded_rule_codes[forwarded_dependency]
            return
        if forwarded_dependency in retained_alias_names and any(
            marker in statement for marker in _TYPED_PROOF_BINDING_MARKERS
        ):
            forwarding = _simple_forwarded_alias_assignment(statement)
            source_expression = forwarding[2] if forwarding is not None else statement
            normalized_expression = re.sub(rb"\s+", b"", source_expression)
            typed_reference = normalized_expression.decode("utf-8") if forwarding is not None else None
            cache_key = (normalized_expression, typed_member_state_signature(typed_reference, binding_start))
            inferred = typed_statement_rule_codes.get(cache_key)
            if inferred is None:
                inferred = inferred_binding_rule_codes(name, statement, binding_start)
                typed_statement_rule_codes[cache_key] = inferred
            typed_inferred = inferred - {"S108"}
            if typed_inferred:
                forwarded_rule_codes[name] = frozenset(typed_inferred)
            return
        if forwarded_dependency in retained_alias_names:
            source_statement = b""
            source_definition_start = binding_start
        else:
            source_definition = latest_definition_before(forwarded_dependency, binding_start)
            if source_definition is None:
                return
            source_statement = source_definition[0]
            source_definition_start = source_definition[1][0]
        inferred = inferred_binding_rule_codes(forwarded_dependency, source_statement, source_definition_start)
        typed_inferred = inferred - {"S108"}
        if typed_inferred:
            forwarded_rule_codes[forwarded_dependency] = frozenset(typed_inferred)
            forwarded_rule_codes[name] = frozenset(typed_inferred)

    def proof_rule_codes(root_names: set[str], *, conservative: bool = False) -> frozenset[str]:
        rule_codes = frozenset(
            rule_code for root_name in root_names for rule_code in forwarded_rule_codes.get(root_name, frozenset())
        )
        return rule_codes or (frozenset({"S108"}) if conservative else frozenset())

    def intersects_relevant_or_fail_closed(names: set[str]) -> bool:
        return not names.isdisjoint(relevant_binding_names) or not names.isdisjoint(fail_closed_dangerous_names)

    def retained_state_spans(root_names: set[str], endpoint_start: int) -> tuple[list[tuple[int, int]], bool, bool]:
        selected: set[tuple[int, int]] = set()
        selected_size = 0
        pending: list[tuple[bytes, tuple[int, int]]] = []
        reaches_retained_alias = False
        for root_name in root_names:
            definition = latest_definition_before(root_name, endpoint_start)
            if definition is not None:
                pending.append(definition)
            elif root_name in retained_alias_names:
                reaches_retained_alias = True
        while pending:
            statement, span = pending.pop()
            if span in selected:
                continue
            selected.add(span)
            selected_size += span[1] - span[0] + 1
            pending.extend(
                (candidate[state_start:state_end], (state_start, state_end))
                for state_start, state_end in typed_binding_state_spans.get(span, [])
            )
            references = alias_dependency_names_cache.setdefault(span, _alias_binding_dependency_names(statement))
            if span in typed_member_write_spans:
                references.update(typed_member_write_dependency_names(statement))
            for reference in references:
                definition = latest_definition_before(reference, span[0])
                if definition is not None:
                    pending.append(definition)
                elif reference in retained_alias_names:
                    reaches_retained_alias = True
        overflowed = selected_size > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES
        return ([] if overflowed else sorted(selected)), reaches_retained_alias, overflowed

    def has_inert_forwarding_state(spans: list[tuple[int, int]]) -> bool:
        return any(
            b";" in candidate[start:end] and _simple_forwarded_alias_assignment(candidate[start:end]) is not None
            for start, end in spans
        )

    def update_pre_replay_deletion_state(statement: bytes) -> None:
        binding_name = _simple_late_binding_name(statement)
        descriptor_reference = _simple_late_assignment_value_reference(statement)
        if binding_name is not None:
            typed_member_mapping_aliases.pop(binding_name, None)
            typed_member_delete_aliases.pop(binding_name, None)
            typed_member_descriptor_delete_aliases.discard(binding_name)
            runpy_namespace_delete_aliases.pop(binding_name, None)
            runpy_descriptor_delete_aliases.discard(binding_name)
            builtin_dict_descriptor_aliases.discard(binding_name)
            typed_mapping_owner = (
                descriptor_reference.removesuffix(".__dict__")
                if descriptor_reference is not None and descriptor_reference.endswith(".__dict__")
                else typed_member_mapping_aliases.get(descriptor_reference or "")
            )
            if typed_mapping_owner in retained_alias_names:
                typed_member_mapping_aliases[binding_name] = typed_mapping_owner
            for delete_name in ("pop", "__delitem__"):
                typed_delete_owner: str | None = None
                if descriptor_reference is not None and descriptor_reference.endswith(f".__dict__.{delete_name}"):
                    candidate_owner = descriptor_reference.removesuffix(f".__dict__.{delete_name}")
                    if candidate_owner in retained_alias_names:
                        typed_delete_owner = candidate_owner
                elif descriptor_reference is not None and descriptor_reference.endswith(f".{delete_name}"):
                    typed_delete_owner = typed_member_mapping_aliases.get(
                        descriptor_reference.removesuffix(f".{delete_name}")
                    )
                if typed_delete_owner in retained_alias_names:
                    typed_member_delete_aliases[binding_name] = typed_delete_owner
            if is_active_builtin_dict_descriptor_owner(descriptor_reference):
                builtin_dict_descriptor_aliases.add(binding_name)
            if (
                descriptor_reference is not None
                and descriptor_reference.endswith((".pop", ".__delitem__"))
                and is_active_builtin_dict_delete_descriptor(descriptor_reference)
            ):
                typed_member_descriptor_delete_aliases.add(binding_name)
                runpy_descriptor_delete_aliases.add(binding_name)
            if descriptor_reference in typed_member_delete_aliases:
                typed_member_delete_aliases[binding_name] = typed_member_delete_aliases[descriptor_reference]
            if descriptor_reference in typed_member_descriptor_delete_aliases:
                typed_member_descriptor_delete_aliases.add(binding_name)
            if descriptor_reference in runpy_namespace_delete_aliases:
                runpy_namespace_delete_aliases[binding_name] = runpy_namespace_delete_aliases[descriptor_reference]
            if descriptor_reference in runpy_descriptor_delete_aliases:
                runpy_descriptor_delete_aliases.add(binding_name)
            vars_delete_alias = re.match(
                rb"\s*([A-Za-z_]\w*)\s*=\s*vars\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*(?:pop|__delitem__)\b",
                statement.lstrip(b"\x00\xff"),
            )
            if (
                vars_delete_alias is not None
                and "vars" not in shadowed_builtin_helper_names | uncertain_builtin_helper_names
                and vars_delete_alias.group(2).decode("utf-8") in retained_alias_names
            ):
                typed_member_delete_aliases[binding_name] = vars_delete_alias.group(2).decode("utf-8")
            runpy_delete_binding = _runpy_priority_namespace_update_binding(
                statement,
                frozenset(name.encode("utf-8") for name in runpy_namespace_owner_names),
                runpy_namespace_update_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if runpy_delete_binding is not None and runpy_delete_binding[2] == "delete":
                runpy_namespace_delete_aliases[runpy_delete_binding[0]] = runpy_delete_binding[1]

        deleted_typed_member_keys = typed_member_delete_keys(statement)
        typed_member_keys = typed_member_write_keys(
            statement,
            definitely_deleted_typed_members | deleted_typed_member_keys,
        )
        definitely_deleted_typed_members.update(deleted_typed_member_keys)
        definitely_deleted_typed_members.difference_update(typed_member_keys)

        deleted_runpy_member_key = _runpy_priority_deleted_member_key(
            statement,
            frozenset(name.encode("utf-8") for name in relevant_binding_names),
            runpy_namespace_update_aliases,
            runpy_namespace_delete_aliases,
            runpy_descriptor_delete_aliases,
            builtin_dict_descriptor_aliases,
            builtins_alias_names,
            shadowed_descriptor_names,
            shadowed_builtin_helper_names,
            canonical_builtin_helper_aliases,
        )
        member_update = _runpy_priority_member_update_key(
            statement,
            _python_structural_line_bytes(statement.lstrip(b"\x00\xff")),
            frozenset(name.encode("utf-8") for name in relevant_binding_names),
            runpy_namespace_update_aliases,
            runpy_namespace_setitem_aliases,
            runpy_namespace_setdefault_aliases,
            shadowed_descriptor_names,
            builtin_dict_update_aliases,
            builtin_dict_descriptor_setitem_aliases,
            builtin_dict_descriptor_setdefault_aliases,
            builtins_alias_names,
            shadowed_builtin_helper_names,
            canonical_builtin_helper_aliases,
        )
        if deleted_runpy_member_key is not None:
            definitely_deleted_runpy_members.add(deleted_runpy_member_key)
        if member_update is not None and member_update[0] != deleted_runpy_member_key:
            definitely_deleted_runpy_members.discard(member_update[0])

    def is_state_neutral_forwarding(statement: bytes, *, replay_only: bool = False) -> bool:
        forwarding = _simple_forwarded_alias_assignment(statement)
        if forwarding is None or (b"." in forwarding[2] and not replay_only):
            return False
        if not deferred_annotations and re.match(rb"\s*[A-Za-z_]\w*\s*:", statement) is not None:
            return False
        target_name, dependency_name, expression = forwarding
        reserved_names = {"dict", "getattr", "vars", "setattr", "delattr", "print", "len"} | set(
            _EAGER_LATE_GENERATOR_CONSUMERS
        )
        if target_name in reserved_names or dependency_name in reserved_names:
            return False
        if replay_only and any(
            marker in expression
            for marker in (
                b"builtins",
                b"__dict__",
                b"dict",
                b"getattr",
                b"vars",
                b"setattr",
                b"delattr",
                b"print",
                b"len",
                b"setdefault",
                b"update",
                b"__setitem__",
                b"pop",
                b"__delitem__",
            )
        ):
            return False
        tracked_name_groups = (
            retained_alias_names,
            builtins_alias_names,
            truthy_builtin_capture_names,
            canonical_eager_generator_consumer_aliases,
            locally_shadowed_eager_generator_consumers,
            builtin_dict_mapping_aliases,
            uncertain_builtin_dict_mapping_aliases,
            builtin_dict_mapping_update_aliases,
            uncertain_builtin_dict_mapping_update_aliases,
            builtin_dict_mapping_setitem_aliases,
            uncertain_builtin_dict_mapping_setitem_aliases,
            builtin_dict_descriptor_aliases,
            shadowed_descriptor_names,
            uncertain_descriptor_names,
            shadowed_builtin_helper_names,
            uncertain_builtin_helper_names,
            canonical_builtin_helper_aliases,
            uncertain_canonical_builtin_helper_aliases,
            exception_type_aliases,
            typed_member_mapping_aliases,
            typed_member_setdefault_aliases,
            typed_member_setitem_aliases,
            typed_member_update_aliases,
            typed_member_descriptor_setdefault_aliases,
            typed_member_delete_aliases,
            typed_member_descriptor_delete_aliases,
            runpy_namespace_owner_names,
            runpy_namespace_update_aliases,
            runpy_namespace_setitem_aliases,
            runpy_namespace_setdefault_aliases,
            runpy_namespace_delete_aliases,
            runpy_descriptor_delete_aliases,
        )
        if (
            replay_only
            and dependency_name in retained_alias_names
            and target_name in retained_alias_names
            and b"." in expression
            and all(
                target_name not in tracked_names
                for tracked_names in tracked_name_groups[1:]
                if tracked_names is not runpy_namespace_owner_names
            )
        ):
            return True
        if any(target_name in tracked_names for tracked_names in tracked_name_groups):
            return False
        return (replay_only and dependency_name in retained_alias_names) or all(
            dependency_name not in tracked_names for tracked_names in tracked_name_groups
        )

    context_start = max(0, search_start - _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES)
    if context_start:
        next_line_start = candidate.find(b"\n", context_start, search_start)
        if next_line_start != -1:
            context_start = next_line_start + 1
    priority_context = candidate[context_start:search_start]
    context_line_start = context_start
    context_active_headers: list[tuple[int, bytes, int]] = []
    for context_line in priority_context.splitlines(keepends=True):
        structural_context_line = _python_structural_line_bytes(context_line.lstrip(b"\x00\xff"))
        if is_state_neutral_forwarding(structural_context_line, replay_only=True):
            context_line_start += len(context_line)
            continue
        if re.search(rb"\bfrom\s+builtins\s+import\b", structural_context_line) is not None:
            import_statement = context_line
            import_span = (context_line_start, context_line_start + len(context_line))
            if b"(" in structural_context_line or _line_has_explicit_continuation(context_line):
                import_statement, import_span = _bounded_late_binding_statement(
                    candidate, context_line_start, context_line_start + len(context_line)
                )
            if import_span[1] <= search_start:
                structural_context_line = (
                    _compact_builtins_dict_import_statement(import_statement) or structural_context_line
                )
        context_line_indent = len(context_line) - len(context_line.lstrip())
        if structural_context_line.strip():
            while context_active_headers and context_line_indent <= context_active_headers[-1][0]:
                context_active_headers.pop()
        context_enclosing_headers = (
            [(header, header_start) for _indent, header, header_start in reversed(context_active_headers)]
            if context_line[:1].isspace()
            else []
        )
        if structural_context_line.strip().endswith(b":"):
            context_active_headers.append((context_line_indent, structural_context_line.strip(), context_line_start))
        context_guard_value = _constant_late_binding_guard_value(
            candidate,
            context_line_start,
            context_line,
            context_enclosing_headers,
            exception_type_aliases,
        )
        context_is_scoped = _is_nested_late_state_statement(
            candidate, context_line_start, context_line, context_enclosing_headers
        )
        canonical_context_import_line = (
            structural_context_line.lstrip()
            if context_guard_value is True and not context_is_scoped
            else structural_context_line
        )
        builtins_import = re.match(rb"\s*import\s+builtins(?:\s+as\s+([A-Za-z_]\w*))?", canonical_context_import_line)
        if builtins_import is not None:
            register_builtins_alias((builtins_import.group(1) or b"builtins").decode("utf-8"))
        builtins_dict_import_aliases = _builtins_dict_import_alias_names(canonical_context_import_line)
        if (
            context_guard_value is True
            and not context_is_scoped
            and builtins_dict_import_aliases
            and "builtins.dict" not in shadowed_descriptor_names | uncertain_descriptor_names
        ):
            builtin_dict_descriptor_aliases.update(builtins_dict_import_aliases)
        context_binding_name = _simple_late_binding_name(structural_context_line)
        context_descriptor_reference = _simple_late_assignment_value_reference(structural_context_line)
        context_canonical_helper = canonical_builtin_helper_aliases.get(context_descriptor_reference or "")
        context_canonical_helper_is_uncertain = (
            context_descriptor_reference in uncertain_canonical_builtin_helper_aliases
        )
        if context_descriptor_reference in shadowed_builtin_helper_names or (
            context_descriptor_reference is not None
            and "." in context_descriptor_reference
            and f"builtins.{context_canonical_helper}" in shadowed_builtin_helper_names
        ):
            context_canonical_helper = None
        if context_binding_name is not None and not context_is_scoped and context_guard_value is not False:
            if context_binding_name in {"getattr", "vars", "setattr", "delattr"}:
                if (
                    context_guard_value is True
                    and context_canonical_helper == context_binding_name
                    and not context_canonical_helper_is_uncertain
                ):
                    shadowed_builtin_helper_names.discard(context_binding_name)
                    uncertain_builtin_helper_names.discard(context_binding_name)
                elif (
                    context_guard_value is True
                    and context_canonical_helper == context_binding_name
                    and context_canonical_helper_is_uncertain
                ):
                    shadowed_builtin_helper_names.discard(context_binding_name)
                    uncertain_builtin_helper_names.add(context_binding_name)
                elif context_guard_value is True:
                    shadowed_builtin_helper_names.add(context_binding_name)
                    uncertain_builtin_helper_names.discard(context_binding_name)
                elif context_guard_value is None:
                    shadowed_builtin_helper_names.discard(context_binding_name)
                    uncertain_builtin_helper_names.add(context_binding_name)
            if context_canonical_helper is not None:
                canonical_builtin_helper_aliases[context_binding_name] = context_canonical_helper
                if context_guard_value is None or context_canonical_helper_is_uncertain:
                    uncertain_canonical_builtin_helper_aliases.add(context_binding_name)
                else:
                    uncertain_canonical_builtin_helper_aliases.discard(context_binding_name)
            elif context_guard_value is True or _is_exhaustive_noncanonical_helper_late_binding(
                candidate, context_line_start, context_line, context_binding_name
            ):
                canonical_builtin_helper_aliases.pop(context_binding_name, None)
                uncertain_canonical_builtin_helper_aliases.discard(context_binding_name)
            elif context_binding_name in canonical_builtin_helper_aliases:
                uncertain_canonical_builtin_helper_aliases.add(context_binding_name)
        context_helper_write = _builtin_helper_attribute_write_state(
            structural_context_line,
            builtins_alias_names,
            builtin_dict_mapping_aliases,
            uncertain_builtin_dict_mapping_aliases,
            builtin_dict_mapping_update_aliases,
            uncertain_builtin_dict_mapping_update_aliases,
            builtin_dict_mapping_setitem_aliases,
            uncertain_builtin_dict_mapping_setitem_aliases,
            builtin_dict_descriptor_aliases,
            shadowed_descriptor_names,
            shadowed_builtin_helper_names,
            uncertain_builtin_helper_names,
            canonical_builtin_helper_aliases,
            uncertain_canonical_builtin_helper_aliases,
        )
        if context_helper_write is not None and not context_is_scoped and context_guard_value is not False:
            helper_name, restores_helper, uncertain_helper_write = context_helper_write
            affected_helper_names = {helper_name, f"builtins.{helper_name}"}
            if context_guard_value is None or uncertain_helper_write:
                shadowed_builtin_helper_names.difference_update(affected_helper_names)
                uncertain_builtin_helper_names.update(affected_helper_names)
                if restores_helper:
                    for affected_helper_name in affected_helper_names:
                        canonical_builtin_helper_aliases[affected_helper_name] = helper_name
                        uncertain_canonical_builtin_helper_aliases.add(affected_helper_name)
                else:
                    uncertain_canonical_builtin_helper_aliases.update(
                        affected_helper_names.intersection(canonical_builtin_helper_aliases)
                    )
            elif restores_helper:
                shadowed_builtin_helper_names.difference_update(affected_helper_names)
                uncertain_builtin_helper_names.difference_update(affected_helper_names)
                for affected_helper_name in affected_helper_names:
                    canonical_builtin_helper_aliases[affected_helper_name] = helper_name
                    uncertain_canonical_builtin_helper_aliases.discard(affected_helper_name)
            else:
                shadowed_builtin_helper_names.update(affected_helper_names)
                uncertain_builtin_helper_names.difference_update(affected_helper_names)
                for affected_helper_name in affected_helper_names:
                    canonical_builtin_helper_aliases.pop(affected_helper_name, None)
                    uncertain_canonical_builtin_helper_aliases.discard(affected_helper_name)
        context_descriptor_write = _builtin_dict_attribute_write_state(
            structural_context_line,
            builtins_alias_names,
            builtin_dict_descriptor_aliases,
            shadowed_descriptor_names,
            builtin_dict_mapping_aliases,
            uncertain_builtin_dict_mapping_aliases,
            builtin_dict_mapping_update_aliases,
            uncertain_builtin_dict_mapping_update_aliases,
            builtin_dict_mapping_setitem_aliases,
            uncertain_builtin_dict_mapping_setitem_aliases,
            builtin_dict_descriptor_setitem_aliases,
            shadowed_builtin_helper_names,
            canonical_builtin_helper_aliases,
            uncertain_canonical_builtin_helper_aliases,
        )
        if context_descriptor_write is not None and not context_is_scoped and context_guard_value is not False:
            descriptor_restores_builtin, uncertain_descriptor_write = context_descriptor_write
            if context_guard_value is None or uncertain_descriptor_write:
                uncertain_descriptor_names.add("builtins.dict")
                shadowed_descriptor_names.discard("builtins.dict")
            elif descriptor_restores_builtin:
                uncertain_descriptor_names.discard("builtins.dict")
                shadowed_descriptor_names.discard("builtins.dict")
            else:
                uncertain_descriptor_names.discard("builtins.dict")
                shadowed_descriptor_names.add("builtins.dict")
        context_defined_names = _deterministically_executed_defined_names(structural_context_line)
        context_defined_eager_consumers = context_defined_names.intersection(_EAGER_LATE_GENERATOR_CONSUMERS)
        context_mutated_builtin_consumers = _mutated_builtin_eager_generator_consumers(
            structural_context_line,
            builtins_alias_names,
            builtin_dict_descriptor_aliases=builtin_dict_descriptor_aliases,
            builtin_dict_mapping_update_aliases=builtin_dict_mapping_update_aliases,
            builtin_dict_mapping_setitem_aliases=builtin_dict_mapping_setitem_aliases,
            shadowed_descriptor_names=shadowed_descriptor_names,
            shadowed_builtin_helper_names=shadowed_builtin_helper_names,
            canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
        )
        invalidate_eager_consumer_aliases(context_defined_eager_consumers, context_mutated_builtin_consumers)
        locally_shadowed_eager_generator_consumers.update(context_defined_eager_consumers)
        for context_name in context_defined_names:
            canonical_eager_generator_consumer_aliases.pop(context_name, None)
        context_eager_bindings = _eager_generator_consumer_alias_bindings(
            structural_context_line, canonical_eager_generator_consumer_aliases
        )
        canonical_eager_generator_consumer_aliases.update(context_eager_bindings)
        locally_shadowed_eager_generator_consumers.difference_update(
            name for name, canonical_name in context_eager_bindings.items() if name == canonical_name
        )
        update_exception_type_aliases(structural_context_line)
        shadowed_truthy_builtin_names.update(
            _late_mutated_truthy_builtin_names(
                structural_context_line,
                builtins_alias_names,
                shadowed_builtin_helper_names,
                builtin_dict_mapping_aliases=builtin_dict_mapping_aliases,
                builtin_dict_descriptor_aliases=builtin_dict_descriptor_aliases,
                builtin_dict_mapping_update_aliases=builtin_dict_mapping_update_aliases,
                builtin_dict_mapping_setitem_aliases=builtin_dict_mapping_setitem_aliases,
                shadowed_descriptor_names=shadowed_descriptor_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            )
        )
        if context_guard_value is True and not context_is_scoped:
            update_pre_replay_deletion_state(context_line)
        context_line_start += len(context_line)
    line_start = context_start
    multiline_quote: bytes | None = _multiline_string_state_after_line(candidate[:context_start], None)
    continued_expression_start: int | None = None
    continued_parenthesis_depth = 0
    continued_has_priority_piece = False
    active_late_headers: list[tuple[int, bytes, int]] = []
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
        code_start = 0
        while code_start < len(line) and not 0x20 <= line[code_start] < 0x7F:
            code_start += 1
        code_line = _python_structural_line_bytes(line[code_start:])
        structural_code_line = code_line.strip()
        if not structural_code_line and continued_expression_start is None:
            multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
            line_start = line_end
            continue
        line_indent = len(line) - len(line.lstrip())
        continues_prior_expression = continued_expression_start is not None
        typed_member_keys: set[str] = set()
        if structural_code_line:
            while active_late_headers and line_indent <= active_late_headers[-1][0]:
                active_late_headers.pop()
        enclosing_headers = (
            [(header, header_start) for _indent, header, header_start in reversed(active_late_headers)]
            if line[:1].isspace()
            else []
        )
        if structural_code_line.endswith(b":"):
            active_late_headers.append((line_indent, structural_code_line, line_start))
        parenthesis_delta = _line_parenthesis_delta(code_line)
        has_line_continuation = code_line.rstrip().endswith(b"\\")
        skips_state_neutral_forwarding = (
            line_end > search_start
            and not enclosing_headers
            and not line[:1].isspace()
            and parenthesis_delta == 0
            and not has_line_continuation
            and is_state_neutral_forwarding(code_line)
        )
        if line_end > search_start and not skips_state_neutral_forwarding:
            late_guard_value = _constant_late_binding_guard_value(
                candidate, line_start, line, enclosing_headers, exception_type_aliases
            )
            typed_member_statement = line
            typed_member_span = (line_start, line_end)
            if (parenthesis_delta > 0 or has_line_continuation) and not continues_prior_expression:
                typed_member_statement, typed_member_span = _bounded_late_binding_statement(
                    candidate, line_start, line_end
                )
            elif structural_code_line.startswith(b"case "):
                match_header_start = next(
                    (header_start for header, header_start in enclosing_headers if header.startswith(b"match ")),
                    None,
                )
                if match_header_start is not None:
                    case_body_end = _line_end_offset(candidate, line_end) if line_end < len(candidate) else line_end
                    typed_member_span = (match_header_start, case_body_end)
                    typed_member_statement = candidate[typed_member_span[0] : typed_member_span[1]]
            mutated_truthy_builtin_names: set[str] = set()
            if late_guard_value is not False:
                mutated_truthy_builtin_names = _late_mutated_truthy_builtin_names(
                    typed_member_statement,
                    builtins_alias_names,
                    shadowed_builtin_helper_names,
                    builtin_dict_mapping_aliases=builtin_dict_mapping_aliases,
                    builtin_dict_descriptor_aliases=builtin_dict_descriptor_aliases,
                    builtin_dict_mapping_update_aliases=builtin_dict_mapping_update_aliases,
                    builtin_dict_mapping_setitem_aliases=builtin_dict_mapping_setitem_aliases,
                    shadowed_descriptor_names=shadowed_descriptor_names | uncertain_descriptor_names,
                    canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
                    evaluate_annotations=not deferred_annotations,
                )
                shadowed_truthy_builtin_names.update(mutated_truthy_builtin_names)
            defined_names = _deterministically_executed_defined_names(
                typed_member_statement, evaluate_annotations=not deferred_annotations
            )
            defined_eager_consumers = defined_names.intersection(_EAGER_LATE_GENERATOR_CONSUMERS)
            mutated_builtin_consumers = _mutated_builtin_eager_generator_consumers(
                typed_member_statement,
                builtins_alias_names,
                builtin_dict_mapping_aliases=builtin_dict_mapping_aliases,
                builtin_dict_descriptor_aliases=builtin_dict_descriptor_aliases,
                builtin_dict_mapping_update_aliases=builtin_dict_mapping_update_aliases,
                builtin_dict_mapping_setitem_aliases=builtin_dict_mapping_setitem_aliases,
                shadowed_descriptor_names=shadowed_descriptor_names | uncertain_descriptor_names,
                shadowed_builtin_helper_names=shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
                evaluate_annotations=not deferred_annotations,
            )
            if late_guard_value is not False:
                invalidate_eager_consumer_aliases(defined_eager_consumers, mutated_builtin_consumers)
                locally_shadowed_eager_generator_consumers.update(defined_eager_consumers)
            if late_guard_value is not False:
                for defined_name in defined_names:
                    canonical_eager_generator_consumer_aliases.pop(defined_name, None)
            if late_guard_value is True:
                eager_bindings = _eager_generator_consumer_alias_bindings(
                    typed_member_statement, canonical_eager_generator_consumer_aliases
                )
                canonical_eager_generator_consumer_aliases.update(eager_bindings)
                locally_shadowed_eager_generator_consumers.difference_update(
                    name for name, canonical_name in eager_bindings.items() if name == canonical_name
                )
                update_exception_type_aliases(typed_member_statement, evaluate_annotations=not deferred_annotations)
            elif late_guard_value is None:
                update_exception_type_aliases(
                    typed_member_statement, evaluate_annotations=not deferred_annotations, uncertain=True
                )
            mutated_helper_names = defined_names.intersection({"getattr", "vars", "setattr", "delattr"})
            if mutated_helper_names:
                if late_guard_value is None:
                    uncertain_builtin_helper_names.update(mutated_helper_names)
                elif late_guard_value is True:
                    uncertain_builtin_helper_names.difference_update(mutated_helper_names)
                    shadowed_builtin_helper_names.update(mutated_helper_names)
                    for helper_name in mutated_helper_names:
                        canonical_builtin_helper_aliases.pop(helper_name, None)
            if "dict" in defined_names and _simple_late_binding_name(code_line) != "dict":
                if late_guard_value is None:
                    uncertain_descriptor_names.add("dict")
                elif late_guard_value is True:
                    shadowed_descriptor_names.add("dict")
                    builtin_dict_descriptor_aliases.discard("dict")
            if late_guard_value is not False:
                for name in defined_names:
                    typed_member_mapping_aliases.pop(name, None)
                    typed_member_setdefault_aliases.pop(name, None)
                    typed_member_setitem_aliases.pop(name, None)
                    typed_member_update_aliases.pop(name, None)
                    typed_member_descriptor_setdefault_aliases.discard(name)
                    typed_member_delete_aliases.pop(name, None)
                    typed_member_descriptor_delete_aliases.discard(name)
            if late_guard_value is True:
                for name, descriptor_reference in deterministic_binding_references(typed_member_statement).items():
                    typed_mapping_owner = (
                        descriptor_reference.removesuffix(".__dict__")
                        if descriptor_reference is not None and descriptor_reference.endswith(".__dict__")
                        else typed_member_mapping_aliases.get(descriptor_reference or "")
                    )
                    if typed_mapping_owner in retained_alias_names:
                        typed_member_mapping_aliases[name] = typed_mapping_owner
                    replay_setdefault_owner: str | None = None
                    if descriptor_reference is not None and descriptor_reference.endswith(".__dict__.setdefault"):
                        candidate_owner = descriptor_reference.removesuffix(".__dict__.setdefault")
                        if candidate_owner in retained_alias_names:
                            replay_setdefault_owner = candidate_owner
                    elif descriptor_reference is not None and descriptor_reference.endswith(".setdefault"):
                        replay_setdefault_owner = typed_member_mapping_aliases.get(
                            descriptor_reference.removesuffix(".setdefault")
                        )
                    if replay_setdefault_owner is None:
                        replay_setdefault_owner = typed_member_setdefault_aliases.get(descriptor_reference or "")
                    if replay_setdefault_owner in retained_alias_names:
                        typed_member_setdefault_aliases[name] = replay_setdefault_owner
                    for mutator_name, mutator_aliases in (
                        ("__setitem__", typed_member_setitem_aliases),
                        ("update", typed_member_update_aliases),
                    ):
                        typed_mutator_owner: str | None = None
                        if descriptor_reference is not None and descriptor_reference.endswith(
                            f".__dict__.{mutator_name}"
                        ):
                            candidate_owner = descriptor_reference.removesuffix(f".__dict__.{mutator_name}")
                            if candidate_owner in retained_alias_names:
                                typed_mutator_owner = candidate_owner
                        elif descriptor_reference is not None and descriptor_reference.endswith(f".{mutator_name}"):
                            typed_mutator_owner = typed_member_mapping_aliases.get(
                                descriptor_reference.removesuffix(f".{mutator_name}")
                            )
                        if typed_mutator_owner is None:
                            typed_mutator_owner = mutator_aliases.get(descriptor_reference or "")
                        if typed_mutator_owner in retained_alias_names:
                            mutator_aliases[name] = typed_mutator_owner
                    if (
                        descriptor_reference == "dict.setdefault"
                        and "dict" in builtin_dict_descriptor_aliases
                        and "dict" not in shadowed_descriptor_names | uncertain_descriptor_names
                    ):
                        typed_member_descriptor_setdefault_aliases.add(name)
                    for delete_name in ("pop", "__delitem__"):
                        typed_delete_owner: str | None = None
                        if descriptor_reference is not None and descriptor_reference.endswith(
                            f".__dict__.{delete_name}"
                        ):
                            candidate_owner = descriptor_reference.removesuffix(f".__dict__.{delete_name}")
                            if candidate_owner in retained_alias_names:
                                typed_delete_owner = candidate_owner
                        elif descriptor_reference is not None and descriptor_reference.endswith(f".{delete_name}"):
                            typed_delete_owner = typed_member_mapping_aliases.get(
                                descriptor_reference.removesuffix(f".{delete_name}")
                            )
                        if typed_delete_owner is None:
                            typed_delete_owner = typed_member_delete_aliases.get(descriptor_reference or "")
                        if typed_delete_owner in retained_alias_names:
                            typed_member_delete_aliases[name] = typed_delete_owner
                    if (
                        descriptor_reference in {"dict.pop", "dict.__delitem__"}
                        and "dict" in builtin_dict_descriptor_aliases
                        and "dict" not in shadowed_descriptor_names | uncertain_descriptor_names
                    ):
                        typed_member_descriptor_delete_aliases.add(name)
                    vars_delete_alias = re.match(
                        rb"\s*([A-Za-z_]\w*)\s*=\s*vars\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*(?:pop|__delitem__)\b",
                        typed_member_statement.lstrip(b"\x00\xff"),
                    )
                    if (
                        vars_delete_alias is not None
                        and "vars" not in shadowed_builtin_helper_names | uncertain_builtin_helper_names
                        and vars_delete_alias.group(2).decode("utf-8") in retained_alias_names
                    ):
                        typed_member_delete_aliases[vars_delete_alias.group(1).decode("utf-8")] = (
                            vars_delete_alias.group(2).decode("utf-8")
                        )
            pre_helper_write = _builtin_helper_attribute_write_state(
                typed_member_statement,
                builtins_alias_names,
                builtin_dict_mapping_aliases,
                uncertain_builtin_dict_mapping_aliases,
                builtin_dict_mapping_update_aliases,
                uncertain_builtin_dict_mapping_update_aliases,
                builtin_dict_mapping_setitem_aliases,
                uncertain_builtin_dict_mapping_setitem_aliases,
                builtin_dict_descriptor_aliases,
                shadowed_descriptor_names | uncertain_descriptor_names,
                shadowed_builtin_helper_names,
                uncertain_builtin_helper_names,
                canonical_builtin_helper_aliases,
                uncertain_canonical_builtin_helper_aliases,
                evaluate_annotations=not deferred_annotations,
            )
            if pre_helper_write is not None and late_guard_value is not False:
                helper_name, restores_helper, uncertain_helper_write = pre_helper_write
                affected_helper_names = {helper_name, f"builtins.{helper_name}"}
                if late_guard_value is None or uncertain_helper_write:
                    shadowed_builtin_helper_names.difference_update(affected_helper_names)
                    uncertain_builtin_helper_names.update(affected_helper_names)
                    if restores_helper:
                        for affected_helper_name in affected_helper_names:
                            canonical_builtin_helper_aliases[affected_helper_name] = helper_name
                            uncertain_canonical_builtin_helper_aliases.add(affected_helper_name)
                    else:
                        uncertain_canonical_builtin_helper_aliases.update(
                            affected_helper_names.intersection(canonical_builtin_helper_aliases)
                        )
                else:
                    if restores_helper:
                        uncertain_builtin_helper_names.difference_update(affected_helper_names)
                        shadowed_builtin_helper_names.difference_update(affected_helper_names)
                        for affected_helper_name in affected_helper_names:
                            canonical_builtin_helper_aliases[affected_helper_name] = helper_name
                            uncertain_canonical_builtin_helper_aliases.discard(affected_helper_name)
                    else:
                        uncertain_builtin_helper_names.difference_update(affected_helper_names)
                        shadowed_builtin_helper_names.update(affected_helper_names)
                        for affected_helper_name in affected_helper_names:
                            canonical_builtin_helper_aliases.pop(affected_helper_name, None)
                            uncertain_canonical_builtin_helper_aliases.discard(affected_helper_name)
            deleted_typed_member_keys = typed_member_delete_keys(typed_member_statement)
            typed_member_keys = (
                typed_member_write_keys(
                    typed_member_statement, definitely_deleted_typed_members | deleted_typed_member_keys
                )
                if (
                    b"." in typed_member_statement
                    or b"setattr" in typed_member_statement
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_mapping_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_setdefault_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_setitem_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_update_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(
                        typed_member_descriptor_setdefault_aliases
                    )
                )
                and (
                    any(member.encode("utf-8") in typed_member_statement for member in _TYPED_PROOF_MEMBER_NAMES)
                    or any(
                        marker in typed_member_statement
                        for marker in (b"__dict__", b"vars", b"setattr", b"update", b"__ior__", b"setdefault")
                    )
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_mapping_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_setdefault_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_setitem_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(typed_member_update_aliases)
                    or not _python_identifier_names(typed_member_statement).isdisjoint(
                        typed_member_descriptor_setdefault_aliases
                    )
                )
                else set()
            )
            if deleted_typed_member_keys and late_guard_value is True:
                definitely_deleted_typed_members.update(deleted_typed_member_keys)
                typed_member_delete_spans.update(dict.fromkeys(deleted_typed_member_keys, typed_member_span))
            state_is_in_standalone_clause = any(
                header.startswith((b"elif ", b"else:", b"except ", b"finally:", b"try:", b"for ", b"while "))
                for header, _header_start in enclosing_headers
            )
            if typed_member_keys and late_guard_value is True:
                definitely_deleted_typed_members.difference_update(typed_member_keys)
                restores_deleted_member = b"setdefault" in typed_member_statement or not _python_identifier_names(
                    typed_member_statement
                ).isdisjoint(set(typed_member_setdefault_aliases) | typed_member_descriptor_setdefault_aliases)
                state_start = (
                    line_start
                    if state_is_in_standalone_clause
                    else _late_binding_statement_start(candidate, line_start, line, enclosing_headers)
                )
                if state_start != line_start:
                    typed_member_span = (state_start, typed_member_span[1])
                    typed_member_statement = candidate[typed_member_span[0] : typed_member_span[1]]
                normalized_state = re.sub(rb"\s+", b"", typed_member_statement)
                for typed_member_key in typed_member_keys:
                    state_spans = typed_member_state_spans.setdefault(typed_member_key, [])
                    state_signatures = typed_member_state_signatures.setdefault(typed_member_key, [])
                    previous_state_is_safe = bool(
                        state_spans and (typed_member_key, state_spans[-1]) in typed_safe_member_write_spans
                    )
                    inert_forwarding_state = typed_member_write_is_inert_forwarding(
                        typed_member_statement, typed_member_key
                    )
                    if not state_signatures or not inert_forwarding_state or state_signatures[-1] != normalized_state:
                        if len(state_spans) >= _MAX_PRIORITY_ASSIGNMENT_PROBES:
                            typed_member_state_overflow_starts.setdefault(typed_member_key, typed_member_span[0])
                        else:
                            preceding_state_spans = [state_spans[-1]] if state_spans else []
                            if restores_deleted_member:
                                delete_span = typed_member_delete_spans.get(typed_member_key)
                                if delete_span is not None:
                                    preceding_state_spans.append(delete_span)
                            if preceding_state_spans:
                                typed_binding_state_spans[typed_member_span] = preceding_state_spans
                            state_span = typed_member_span
                            typed_member_write_spans.add(state_span)
                            state_spans.append(state_span)
                            state_signatures.append(normalized_state)
                            state_has_uncertain_execution = _statement_has_uncertain_expression_execution(
                                typed_member_statement,
                                evaluate_annotations=not deferred_annotations,
                                eager_generator_consumers=canonical_eager_generator_consumer_aliases,
                            )
                            state_is_proven_safe = typed_member_state_is_proven_safe(state_span, typed_member_key) or (
                                inert_forwarding_state and previous_state_is_safe
                            )
                            if state_is_proven_safe and not state_has_uncertain_execution:
                                typed_safe_member_write_spans.add((typed_member_key, state_span))
                            elif (
                                state_is_in_standalone_clause
                                or state_has_uncertain_execution
                                or re.match(rb"\s*(?:async\s+def|def)\b", typed_member_statement.lstrip(b"\x00\xff"))
                                is not None
                                or re.match(
                                    rb"\s*(?:if|elif|for|while|with|match)\b",
                                    typed_member_statement.lstrip(b"\x00\xff"),
                                )
                                is not None
                                or _statement_executes_eager_generator_expression(
                                    typed_member_statement,
                                    eager_generator_consumers=canonical_eager_generator_consumer_aliases,
                                )
                                or restores_deleted_member
                                or len(typed_member_keys) > 1
                                or b"|=" in typed_member_statement
                                or not _python_identifier_names(typed_member_statement).isdisjoint(
                                    shadowed_truthy_builtin_names
                                )
                            ):
                                typed_fail_closed_member_write_spans.add((typed_member_key, state_span))
                    typed_member_delete_spans.pop(typed_member_key, None)
            elif (
                typed_member_keys
                and late_guard_value is None
                and not _is_nested_late_state_statement(candidate, line_start, line, enclosing_headers)
            ):
                for typed_member_key in typed_member_keys:
                    typed_member_state_overflow_starts.setdefault(typed_member_key, typed_member_span[0])
            if mutated_truthy_builtin_names:
                mutation_start = _late_binding_statement_start(candidate, line_start, line, enclosing_headers)
                mutation_end = line_end
                if structural_code_line.startswith((b"for ", b"async for ", b"with ", b"async with ")):
                    mutation_end = _line_end_offset(candidate, line_end)
                mutation_span = (
                    mutation_start,
                    min(mutation_end, mutation_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES),
                )
                capture_spans, _reaches_capture_root, _capture_overflowed = retained_state_spans(
                    _python_identifier_names(line).intersection(truthy_builtin_capture_names), line_start
                )
                mapping_dependency_spans: list[tuple[int, int]] = []
                pending_mapping_names = list(_python_identifier_names(line))
                while pending_mapping_names:
                    mapping_name = pending_mapping_names.pop()
                    mapping_span = builtin_mapping_state_spans.get(mapping_name)
                    if mapping_span is None or mapping_span in mapping_dependency_spans:
                        continue
                    mapping_dependency_spans.append(mapping_span)
                    pending_mapping_names.extend(_python_identifier_names(candidate[mapping_span[0] : mapping_span[1]]))
                for state_span in [
                    *late_builtins_import_spans,
                    *mapping_dependency_spans,
                    *capture_spans,
                    mutation_span,
                ]:
                    if state_span not in truthy_builtin_state_spans:
                        truthy_builtin_state_spans.append(state_span)
            shadowed_aliases = _definitely_executed_late_shadow_aliases(
                code_line,
                aliases,
                nested=bool(enclosing_headers),
            )
            if shadowed_aliases:
                shadow_start = _late_binding_statement_start(candidate, line_start, line, enclosing_headers)
                shadow_span = (
                    shadow_start,
                    min(
                        _priority_alias_shadow_segment_end(candidate, line, line_end),
                        shadow_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES,
                    ),
                )
                for shadowed_alias in shadowed_aliases:
                    pending_shadow_spans[shadowed_alias.decode("utf-8")] = shadow_span
        if continued_expression_start is None:
            if parenthesis_delta > 0 or has_line_continuation:
                continued_expression_start = line_start
                continued_parenthesis_depth = parenthesis_delta
                continued_has_priority_piece = (
                    _line_is_continued_priority_alias_piece(code_line, aliases)
                    or _line_is_continued_priority_name_piece(code_line, relevant_binding_names)
                    or _line_starts_continued_priority_getattr(
                        code_line, canonical_builtin_helper_aliases, shadowed_builtin_helper_names
                    )
                )
        else:
            continued_parenthesis_depth += parenthesis_delta
            continued_has_priority_piece = (
                continued_has_priority_piece
                or _line_is_continued_priority_alias_piece(code_line, aliases)
                or _line_is_continued_priority_name_piece(code_line, relevant_binding_names)
                or _line_starts_continued_priority_getattr(
                    code_line, canonical_builtin_helper_aliases, shadowed_builtin_helper_names
                )
            )
            if line_end - continued_expression_start > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
                continued_expression_start = None
                continued_parenthesis_depth = 0
                continued_has_priority_piece = False
            elif continued_parenthesis_depth <= 0 and not has_line_continuation:
                if line_end > search_start and continued_has_priority_piece:
                    fragment = candidate[continued_expression_start:line_end]
                    root_names = _callable_root_names(fragment)
                    if not root_names.isdisjoint(definite_shadowed_names):
                        continued_expression_start = None
                        continued_parenthesis_depth = 0
                        continued_has_priority_piece = False
                        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                        line_start = line_end
                        continue
                    if not root_names.isdisjoint(fail_closed_dangerous_names):
                        usage_lines.append((continued_expression_start, line_end))
                        return usage_lines, proof_rule_codes(root_names, conservative=True)
                    priority_aliases = frozenset(name.encode("utf-8") for name in relevant_binding_names)
                    getattr_member = _priority_getattr_alias_member(
                        fragment,
                        priority_aliases,
                        shadowed_builtin_helper_names,
                        canonical_builtin_helper_aliases,
                    )
                    if getattr_member is not None:
                        root_names.add(getattr_member[2])
                    state_spans, reaches_retained_alias, overflowed = retained_state_spans(
                        root_names, continued_expression_start
                    )
                    if root_names and (
                        _fragment_has_continued_priority_alias_call(fragment, aliases)
                        or getattr_member is not None
                        or (state_spans and reaches_retained_alias)
                        or (overflowed and reaches_retained_alias)
                    ):
                        usage_lines.extend(truthy_builtin_state_spans)
                        usage_lines.extend(state_spans)
                        usage_lines.extend(
                            span for member_spans in runpy_member_state_spans.values() for span in member_spans
                        )
                        usage_lines.append((continued_expression_start, line_end))
                        needs_proof = (
                            (overflowed and reaches_retained_alias)
                            or (
                                not runpy_member_state_spans
                                and _line_calls_overbounded_runpy_getattr_alias(
                                    fragment,
                                    priority_aliases,
                                    shadowed_builtin_helper_names,
                                    canonical_builtin_helper_aliases,
                                )
                            )
                            or (reaches_retained_alias and has_inert_forwarding_state(state_spans))
                        )
                        return (
                            usage_lines,
                            proof_rule_codes(root_names, conservative=True) if needs_proof else frozenset(),
                        )
                continued_expression_start = None
                continued_parenthesis_depth = 0
                continued_has_priority_piece = False
        fail_closed_forwarding = (
            _simple_forwarded_alias_assignment(code_line) if skips_state_neutral_forwarding else None
        )
        if fail_closed_forwarding is not None and fail_closed_forwarding[1] in fail_closed_dangerous_names:
            fast_binding_name, fast_forwarded_dependency, _expression = fail_closed_forwarding
            fail_closed_dangerous_names.add(fast_binding_name)
            relevant_binding_names.add(fast_binding_name)
            forwarded_rule_codes[fast_binding_name] = forwarded_rule_codes.get(
                fast_forwarded_dependency, frozenset({"S108"})
            )
            forwarded_state_sizes[fast_binding_name] = _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES + 1
            forwarded_safe_names.discard(fast_binding_name)
            multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
            line_start = line_end
            continue
        is_simple_forwarding_binding = False
        if line_end > search_start:
            binding_name = _simple_late_binding_name(code_line)
            if binding_name is not None:
                same_line_priority_endpoint = False
                if b";" in code_line:
                    same_line_suffix = code_line.split(b";", maxsplit=1)[1]
                    same_line_suffix_names = _python_identifier_names(same_line_suffix)
                    same_line_relevant_names = same_line_suffix_names.intersection(
                        relevant_binding_names | {alias.decode("utf-8") for alias in aliases}
                    )
                    if same_line_relevant_names:
                        same_line_aliases = frozenset(name.encode("utf-8") for name in same_line_relevant_names)
                        same_line_priority_endpoint = _line_uses_priority_alias(same_line_suffix, same_line_aliases)
                may_bind_namespace_update = (
                    b"__dict__" in line
                    or b"vars" in line
                    or not _python_identifier_names(line).isdisjoint(
                        {
                            name
                            for name, helper_name in canonical_builtin_helper_aliases.items()
                            if helper_name == "vars" and name not in shadowed_builtin_helper_names
                        }
                    )
                    or (
                        (b".update" in line or b"__ior__" in line)
                        and not _python_identifier_names(code_line).isdisjoint(runpy_namespace_update_aliases)
                    )
                    or (
                        (b"__setitem__" in line or b"setdefault" in line or b".pop" in line or b"__delitem__" in line)
                        and not _python_identifier_names(code_line).isdisjoint(runpy_namespace_update_aliases)
                    )
                )
                update_alias = (
                    _runpy_priority_namespace_update_binding(
                        line,
                        frozenset(name.encode("utf-8") for name in runpy_namespace_owner_names),
                        runpy_namespace_update_aliases,
                        shadowed_builtin_helper_names,
                        canonical_builtin_helper_aliases,
                    )
                    if may_bind_namespace_update
                    else None
                )
                guard_value = _constant_late_binding_guard_value(
                    candidate, line_start, line, enclosing_headers, exception_type_aliases
                )
                if guard_value is False:
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                if update_alias is not None:
                    alias_name, owner_name, mutator_kind = update_alias
                    if mutator_kind == "setitem":
                        runpy_namespace_setitem_aliases[alias_name] = owner_name
                        runpy_namespace_update_aliases.pop(alias_name, None)
                        runpy_namespace_setdefault_aliases.pop(alias_name, None)
                        runpy_namespace_delete_aliases.pop(alias_name, None)
                    elif mutator_kind == "setdefault":
                        runpy_namespace_setdefault_aliases[alias_name] = owner_name
                        runpy_namespace_update_aliases.pop(alias_name, None)
                        runpy_namespace_setitem_aliases.pop(alias_name, None)
                        runpy_namespace_delete_aliases.pop(alias_name, None)
                    elif mutator_kind == "delete":
                        runpy_namespace_delete_aliases[alias_name] = owner_name
                        runpy_namespace_update_aliases.pop(alias_name, None)
                        runpy_namespace_setitem_aliases.pop(alias_name, None)
                        runpy_namespace_setdefault_aliases.pop(alias_name, None)
                    else:
                        runpy_namespace_update_aliases[alias_name] = owner_name
                        runpy_namespace_setitem_aliases.pop(alias_name, None)
                        runpy_namespace_setdefault_aliases.pop(alias_name, None)
                        runpy_namespace_delete_aliases.pop(alias_name, None)
                    if (
                        guard_value is None
                        or _statement_uses_uncertain_builtin_helper(
                            line, uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases
                        )
                        or not _python_identifier_names(line).isdisjoint(uncertain_runpy_namespace_names)
                    ):
                        uncertain_runpy_namespace_names.add(binding_name)
                    else:
                        uncertain_runpy_namespace_names.discard(binding_name)
                definite_shadowed_names.discard(binding_name)
                if guard_value is True:
                    fail_closed_dangerous_names.discard(binding_name)
                    forwarded_rule_codes.pop(binding_name, None)
                    typed_rule_source_names.discard(binding_name)
                if binding_name not in relevant_binding_names and _is_inert_scalar_late_binding(code_line):
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                statement_start = (
                    line_start
                    if guard_value is True
                    and _is_reachable_late_else_binding(
                        candidate, line_start, line, enclosing_headers, exception_type_aliases
                    )
                    else _late_binding_statement_start(candidate, line_start, line, enclosing_headers)
                )
                if statement_start == line_start:
                    statement_start += code_start
                statement = candidate[statement_start:line_end]
                span = (statement_start, line_end)
                if (parenthesis_delta > 0 or has_line_continuation) and not continues_prior_expression:
                    statement, span = _bounded_late_binding_statement(candidate, statement_start, line_end)
                assignment_expression = line[code_start:]
                if (parenthesis_delta > 0 or has_line_continuation) and not continues_prior_expression:
                    assignment_expression, _assignment_span = _bounded_late_binding_statement(
                        candidate, line_start + code_start, line_end
                    )
                nested_state_statement = _is_nested_late_state_statement(candidate, line_start, line, enclosing_headers)
                scoped_binding = _is_nested_late_state_statement(candidate, line_start, line, enclosing_headers)
                referenced_identifiers = _python_identifier_names(statement)
                forwarded_dependency = _simple_forwarded_alias_dependency_name(statement)
                has_evaluated_annotation = (
                    not deferred_annotations and re.match(rb"\s*[A-Za-z_]\w*\s*:", statement) is not None
                )
                is_simple_forwarding_binding = forwarded_dependency is not None and not has_evaluated_annotation
                if update_alias is None:
                    forwarded_namespace_owner = runpy_namespace_update_aliases.get(forwarded_dependency or "")
                    forwarded_namespace_kind = "update"
                    if forwarded_namespace_owner is None:
                        forwarded_namespace_owner = runpy_namespace_setitem_aliases.get(forwarded_dependency or "")
                        forwarded_namespace_kind = "setitem"
                    if forwarded_namespace_owner is None:
                        forwarded_namespace_owner = runpy_namespace_setdefault_aliases.get(forwarded_dependency or "")
                        forwarded_namespace_kind = "setdefault"
                    if forwarded_namespace_owner is None:
                        forwarded_namespace_owner = runpy_namespace_delete_aliases.get(forwarded_dependency or "")
                        forwarded_namespace_kind = "delete"
                    if forwarded_namespace_owner is not None:
                        if forwarded_namespace_kind == "setitem":
                            runpy_namespace_setitem_aliases[binding_name] = forwarded_namespace_owner
                            runpy_namespace_update_aliases.pop(binding_name, None)
                            runpy_namespace_setdefault_aliases.pop(binding_name, None)
                            runpy_namespace_delete_aliases.pop(binding_name, None)
                        elif forwarded_namespace_kind == "setdefault":
                            runpy_namespace_setdefault_aliases[binding_name] = forwarded_namespace_owner
                            runpy_namespace_update_aliases.pop(binding_name, None)
                            runpy_namespace_setitem_aliases.pop(binding_name, None)
                            runpy_namespace_delete_aliases.pop(binding_name, None)
                        elif forwarded_namespace_kind == "delete":
                            runpy_namespace_delete_aliases[binding_name] = forwarded_namespace_owner
                            runpy_namespace_update_aliases.pop(binding_name, None)
                            runpy_namespace_setitem_aliases.pop(binding_name, None)
                            runpy_namespace_setdefault_aliases.pop(binding_name, None)
                        else:
                            runpy_namespace_update_aliases[binding_name] = forwarded_namespace_owner
                            runpy_namespace_setitem_aliases.pop(binding_name, None)
                            runpy_namespace_setdefault_aliases.pop(binding_name, None)
                            runpy_namespace_delete_aliases.pop(binding_name, None)
                        if guard_value is None or forwarded_dependency in uncertain_runpy_namespace_names:
                            uncertain_runpy_namespace_names.add(binding_name)
                        else:
                            uncertain_runpy_namespace_names.discard(binding_name)
                    elif guard_value is None and (
                        binding_name in runpy_namespace_update_aliases
                        or binding_name in runpy_namespace_setitem_aliases
                        or binding_name in runpy_namespace_setdefault_aliases
                        or binding_name in runpy_namespace_delete_aliases
                        or binding_name in runpy_namespace_owner_names
                    ):
                        uncertain_runpy_namespace_names.add(binding_name)
                    else:
                        runpy_namespace_update_aliases.pop(binding_name, None)
                        runpy_namespace_setitem_aliases.pop(binding_name, None)
                        runpy_namespace_setdefault_aliases.pop(binding_name, None)
                        runpy_namespace_delete_aliases.pop(binding_name, None)
                        if guard_value is True:
                            uncertain_runpy_namespace_names.discard(binding_name)
                if binding_name == "dict" and guard_value is None:
                    uncertain_descriptor_names.add("dict")
                descriptor_reference = _simple_late_assignment_value_reference(assignment_expression)
                if not scoped_binding:
                    typed_mapping_owner = (
                        descriptor_reference.removesuffix(".__dict__")
                        if descriptor_reference is not None and descriptor_reference.endswith(".__dict__")
                        else typed_member_mapping_aliases.get(descriptor_reference or "")
                    )
                    if guard_value is True and typed_mapping_owner in retained_alias_names:
                        typed_member_mapping_aliases[binding_name] = typed_mapping_owner
                    else:
                        typed_member_mapping_aliases.pop(binding_name, None)
                    typed_setdefault_owner: str | None = None
                    if descriptor_reference is not None and descriptor_reference.endswith(".__dict__.setdefault"):
                        candidate_owner = descriptor_reference.removesuffix(".__dict__.setdefault")
                        if candidate_owner in retained_alias_names:
                            typed_setdefault_owner = candidate_owner
                    elif descriptor_reference is not None and descriptor_reference.endswith(".setdefault"):
                        typed_setdefault_owner = typed_member_mapping_aliases.get(
                            descriptor_reference.removesuffix(".setdefault")
                        )
                    if typed_setdefault_owner is None:
                        typed_setdefault_owner = typed_member_setdefault_aliases.get(forwarded_dependency or "")
                    if guard_value is True and typed_setdefault_owner in retained_alias_names:
                        typed_member_setdefault_aliases[binding_name] = typed_setdefault_owner
                    else:
                        typed_member_setdefault_aliases.pop(binding_name, None)
                    for mutator_name, mutator_aliases in (
                        ("__setitem__", typed_member_setitem_aliases),
                        ("update", typed_member_update_aliases),
                    ):
                        binding_mutator_owner: str | None = None
                        if descriptor_reference is not None and descriptor_reference.endswith(
                            f".__dict__.{mutator_name}"
                        ):
                            candidate_owner = descriptor_reference.removesuffix(f".__dict__.{mutator_name}")
                            if candidate_owner in retained_alias_names:
                                binding_mutator_owner = candidate_owner
                        elif descriptor_reference is not None and descriptor_reference.endswith(f".{mutator_name}"):
                            binding_mutator_owner = typed_member_mapping_aliases.get(
                                descriptor_reference.removesuffix(f".{mutator_name}")
                            )
                        if binding_mutator_owner is None:
                            binding_mutator_owner = mutator_aliases.get(forwarded_dependency or "")
                        if guard_value is True and binding_mutator_owner in retained_alias_names:
                            mutator_aliases[binding_name] = binding_mutator_owner
                        else:
                            mutator_aliases.pop(binding_name, None)
                    if (
                        guard_value is True
                        and descriptor_reference == "dict.setdefault"
                        and "dict" in builtin_dict_descriptor_aliases
                        and "dict" not in shadowed_descriptor_names | uncertain_descriptor_names
                    ):
                        typed_member_descriptor_setdefault_aliases.add(binding_name)
                    else:
                        typed_member_descriptor_setdefault_aliases.discard(binding_name)
                    binding_delete_owner: str | None = None
                    for delete_name in ("pop", "__delitem__"):
                        if descriptor_reference is not None and descriptor_reference.endswith(
                            f".__dict__.{delete_name}"
                        ):
                            candidate_owner = descriptor_reference.removesuffix(f".__dict__.{delete_name}")
                            if candidate_owner in retained_alias_names:
                                binding_delete_owner = candidate_owner
                        elif descriptor_reference is not None and descriptor_reference.endswith(f".{delete_name}"):
                            binding_delete_owner = typed_member_mapping_aliases.get(
                                descriptor_reference.removesuffix(f".{delete_name}")
                            )
                    if binding_delete_owner is None:
                        binding_delete_owner = typed_member_delete_aliases.get(forwarded_dependency or "")
                    if guard_value is True and binding_delete_owner in retained_alias_names:
                        typed_member_delete_aliases[binding_name] = binding_delete_owner
                    else:
                        typed_member_delete_aliases.pop(binding_name, None)
                    if (
                        guard_value is True
                        and descriptor_reference is not None
                        and descriptor_reference.endswith((".pop", ".__delitem__"))
                        and is_active_builtin_dict_delete_descriptor(descriptor_reference)
                    ):
                        typed_member_descriptor_delete_aliases.add(binding_name)
                    else:
                        typed_member_descriptor_delete_aliases.discard(binding_name)
                    vars_delete_alias = re.match(
                        rb"\s*([A-Za-z_]\w*)\s*=\s*vars\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*(?:pop|__delitem__)\b",
                        assignment_expression.lstrip(b"\x00\xff"),
                    )
                    if (
                        guard_value is True
                        and vars_delete_alias is not None
                        and "vars" not in shadowed_builtin_helper_names | uncertain_builtin_helper_names
                        and vars_delete_alias.group(2).decode("utf-8") in retained_alias_names
                    ):
                        typed_member_delete_aliases[binding_name] = vars_delete_alias.group(2).decode("utf-8")
                    if (
                        guard_value is True
                        and descriptor_reference is not None
                        and descriptor_reference.endswith((".pop", ".__delitem__"))
                        and is_active_builtin_dict_delete_descriptor(descriptor_reference)
                    ) or (guard_value is True and forwarded_dependency in runpy_descriptor_delete_aliases):
                        runpy_descriptor_delete_aliases.add(binding_name)
                    else:
                        runpy_descriptor_delete_aliases.discard(binding_name)
                canonical_helper_reference = canonical_builtin_helper_aliases.get(descriptor_reference or "")
                canonical_helper_reference_is_uncertain = (
                    descriptor_reference in uncertain_canonical_builtin_helper_aliases
                )
                if descriptor_reference in shadowed_builtin_helper_names | uncertain_builtin_helper_names or (
                    descriptor_reference is not None
                    and "." in descriptor_reference
                    and f"builtins.{canonical_helper_reference}"
                    in shadowed_builtin_helper_names | uncertain_builtin_helper_names
                ):
                    canonical_helper_reference = None
                if binding_name in {"getattr", "vars", "setattr", "delattr"} and not scoped_binding:
                    restored_builtin_helper = (
                        guard_value is True
                        and canonical_helper_reference == binding_name
                        and not canonical_helper_reference_is_uncertain
                    )
                    if restored_builtin_helper:
                        shadowed_builtin_helper_names.discard(binding_name)
                        uncertain_builtin_helper_names.discard(binding_name)
                    elif (
                        guard_value is True
                        and canonical_helper_reference == binding_name
                        and canonical_helper_reference_is_uncertain
                    ):
                        shadowed_builtin_helper_names.discard(binding_name)
                        uncertain_builtin_helper_names.add(binding_name)
                    elif guard_value is None:
                        shadowed_builtin_helper_names.discard(binding_name)
                        uncertain_builtin_helper_names.add(binding_name)
                        if canonical_helper_reference == binding_name:
                            canonical_builtin_helper_aliases[binding_name] = binding_name
                    else:
                        shadowed_builtin_helper_names.add(binding_name)
                        uncertain_builtin_helper_names.discard(binding_name)
                if not scoped_binding and guard_value is True:
                    if canonical_helper_reference is not None:
                        canonical_builtin_helper_aliases[binding_name] = canonical_helper_reference
                        if canonical_helper_reference_is_uncertain:
                            uncertain_canonical_builtin_helper_aliases.add(binding_name)
                        else:
                            uncertain_canonical_builtin_helper_aliases.discard(binding_name)
                        add_late_definition(binding_name, statement, span)
                    else:
                        canonical_builtin_helper_aliases.pop(binding_name, None)
                        uncertain_canonical_builtin_helper_aliases.discard(binding_name)
                elif (
                    not scoped_binding
                    and guard_value is None
                    and _is_exhaustive_noncanonical_helper_late_binding(candidate, line_start, line, binding_name)
                ):
                    canonical_builtin_helper_aliases.pop(binding_name, None)
                    uncertain_canonical_builtin_helper_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is None:
                    if canonical_helper_reference is not None:
                        canonical_builtin_helper_aliases[binding_name] = canonical_helper_reference
                        uncertain_canonical_builtin_helper_aliases.add(binding_name)
                    elif binding_name in canonical_builtin_helper_aliases:
                        uncertain_canonical_builtin_helper_aliases.add(binding_name)
                if guard_value is True:
                    if descriptor_reference in builtins_alias_names:
                        register_builtins_alias(binding_name)
                    else:
                        discard_builtins_alias(binding_name)
                    is_builtin_dict_descriptor = descriptor_reference in builtin_dict_descriptor_aliases or (
                        descriptor_reference is not None
                        and descriptor_reference.removesuffix(".dict") in builtins_alias_names
                        and descriptor_reference.endswith(".dict")
                        and "builtins.dict" not in shadowed_descriptor_names
                    )
                    if is_builtin_dict_descriptor:
                        builtin_dict_descriptor_aliases.add(binding_name)
                    else:
                        builtin_dict_descriptor_aliases.discard(binding_name)
                    if binding_name == "dict":
                        uncertain_descriptor_names.discard("dict")
                        if is_builtin_dict_descriptor:
                            shadowed_descriptor_names.discard("dict")
                        else:
                            shadowed_descriptor_names.add("dict")
                binds_builtins_mapping = _late_assignment_binds_builtins_mapping(
                    assignment_expression,
                    builtins_alias_names,
                    builtin_dict_mapping_aliases,
                    shadowed_builtin_helper_names,
                    canonical_builtin_helper_aliases,
                )
                if not scoped_binding and binds_builtins_mapping:
                    builtin_dict_mapping_aliases.add(binding_name)
                    builtin_mapping_state_spans[binding_name] = span
                    mapping_binding_is_uncertain = (
                        descriptor_reference in uncertain_builtin_dict_mapping_aliases
                        or _statement_uses_uncertain_builtin_helper(
                            assignment_expression, uncertain_canonical_builtin_helper_aliases
                        )
                    )
                    if guard_value is None or mapping_binding_is_uncertain:
                        uncertain_builtin_dict_mapping_aliases.add(binding_name)
                    else:
                        uncertain_builtin_dict_mapping_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is True:
                    builtin_dict_mapping_aliases.discard(binding_name)
                    uncertain_builtin_dict_mapping_aliases.discard(binding_name)
                update_binding_kind = _late_assignment_builtin_update_kind(
                    assignment_expression,
                    builtins_alias_names,
                    builtin_dict_descriptor_aliases,
                    shadowed_descriptor_names | uncertain_descriptor_names,
                    shadowed_builtin_helper_names,
                    builtin_dict_mapping_aliases,
                    canonical_builtin_helper_aliases,
                )
                if (
                    not scoped_binding
                    and not nested_state_statement
                    and (update_binding_kind == "descriptor" or forwarded_dependency in builtin_dict_update_aliases)
                ):
                    builtin_dict_update_aliases.add(binding_name)
                    if (
                        forwarded_dependency in uncertain_builtin_dict_update_aliases
                        or _statement_uses_uncertain_builtin_helper(
                            assignment_expression,
                            uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases,
                        )
                    ):
                        uncertain_builtin_dict_update_aliases.add(binding_name)
                    else:
                        uncertain_builtin_dict_update_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is True:
                    builtin_dict_update_aliases.discard(binding_name)
                    uncertain_builtin_dict_update_aliases.discard(binding_name)
                elif (
                    not scoped_binding
                    and not nested_state_statement
                    and guard_value is None
                    and binding_name in builtin_dict_update_aliases
                ):
                    uncertain_builtin_dict_update_aliases.add(binding_name)
                if (
                    not scoped_binding
                    and not nested_state_statement
                    and (
                        update_binding_kind == "mapping" or forwarded_dependency in builtin_dict_mapping_update_aliases
                    )
                ):
                    builtin_dict_mapping_update_aliases.add(binding_name)
                    builtin_mapping_state_spans[binding_name] = span
                    if (
                        guard_value is None
                        or forwarded_dependency in uncertain_builtin_dict_mapping_update_aliases
                        or not referenced_identifiers.isdisjoint(uncertain_builtin_dict_mapping_aliases)
                    ):
                        uncertain_builtin_dict_mapping_update_aliases.add(binding_name)
                    else:
                        uncertain_builtin_dict_mapping_update_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is True:
                    builtin_dict_mapping_update_aliases.discard(binding_name)
                    uncertain_builtin_dict_mapping_update_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is None and binding_name in builtin_dict_mapping_update_aliases:
                    uncertain_builtin_dict_mapping_update_aliases.add(binding_name)
                if (
                    not scoped_binding
                    and not nested_state_statement
                    and (
                        update_binding_kind == "descriptor_setitem"
                        or forwarded_dependency in builtin_dict_descriptor_setitem_aliases
                    )
                ):
                    builtin_dict_descriptor_setitem_aliases.add(binding_name)
                    if (
                        forwarded_dependency in uncertain_builtin_dict_descriptor_setitem_aliases
                        or _statement_uses_uncertain_builtin_helper(
                            assignment_expression,
                            uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases,
                        )
                    ):
                        uncertain_builtin_dict_descriptor_setitem_aliases.add(binding_name)
                    else:
                        uncertain_builtin_dict_descriptor_setitem_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is True:
                    builtin_dict_descriptor_setitem_aliases.discard(binding_name)
                    uncertain_builtin_dict_descriptor_setitem_aliases.discard(binding_name)
                elif (
                    not scoped_binding
                    and not nested_state_statement
                    and guard_value is None
                    and binding_name in builtin_dict_descriptor_setitem_aliases
                ):
                    uncertain_builtin_dict_descriptor_setitem_aliases.add(binding_name)
                if (
                    not scoped_binding
                    and not nested_state_statement
                    and (
                        update_binding_kind == "descriptor_setdefault"
                        or forwarded_dependency in builtin_dict_descriptor_setdefault_aliases
                    )
                ):
                    builtin_dict_descriptor_setdefault_aliases.add(binding_name)
                    if (
                        forwarded_dependency in uncertain_builtin_dict_descriptor_setdefault_aliases
                        or _statement_uses_uncertain_builtin_helper(
                            assignment_expression,
                            uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases,
                        )
                    ):
                        uncertain_builtin_dict_descriptor_setdefault_aliases.add(binding_name)
                    else:
                        uncertain_builtin_dict_descriptor_setdefault_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is True:
                    builtin_dict_descriptor_setdefault_aliases.discard(binding_name)
                    uncertain_builtin_dict_descriptor_setdefault_aliases.discard(binding_name)
                elif (
                    not scoped_binding
                    and not nested_state_statement
                    and guard_value is None
                    and binding_name in builtin_dict_descriptor_setdefault_aliases
                ):
                    uncertain_builtin_dict_descriptor_setdefault_aliases.add(binding_name)
                if (
                    not scoped_binding
                    and not nested_state_statement
                    and (
                        update_binding_kind == "mapping_setitem"
                        or forwarded_dependency in builtin_dict_mapping_setitem_aliases
                    )
                ):
                    builtin_dict_mapping_setitem_aliases.add(binding_name)
                    builtin_mapping_state_spans[binding_name] = span
                    if (
                        guard_value is None
                        or forwarded_dependency in uncertain_builtin_dict_mapping_setitem_aliases
                        or not referenced_identifiers.isdisjoint(uncertain_builtin_dict_mapping_aliases)
                    ):
                        uncertain_builtin_dict_mapping_setitem_aliases.add(binding_name)
                    else:
                        uncertain_builtin_dict_mapping_setitem_aliases.discard(binding_name)
                elif not scoped_binding and guard_value is True:
                    builtin_dict_mapping_setitem_aliases.discard(binding_name)
                    uncertain_builtin_dict_mapping_setitem_aliases.discard(binding_name)
                elif (
                    not scoped_binding and guard_value is None and binding_name in builtin_dict_mapping_setitem_aliases
                ):
                    uncertain_builtin_dict_mapping_setitem_aliases.add(binding_name)
                if (
                    not scoped_binding
                    and guard_value is True
                    and binding_name
                    not in (
                        builtin_dict_mapping_aliases
                        | builtin_dict_mapping_update_aliases
                        | builtin_dict_mapping_setitem_aliases
                    )
                ):
                    builtin_mapping_state_spans.pop(binding_name, None)
                if forwarded_dependency in runpy_namespace_owner_names:
                    forwarded_assignment = _simple_forwarded_alias_assignment(statement)
                    if forwarded_assignment is not None and b"." not in forwarded_assignment[2]:
                        runpy_namespace_owner_names.add(binding_name)
                        if guard_value is None or forwarded_dependency in uncertain_runpy_namespace_names:
                            uncertain_runpy_namespace_names.add(binding_name)
                        else:
                            uncertain_runpy_namespace_names.discard(binding_name)
                elif guard_value is None and binding_name in runpy_namespace_owner_names:
                    uncertain_runpy_namespace_names.add(binding_name)
                alias_dependencies = (
                    {forwarded_dependency}
                    if forwarded_dependency is not None
                    else _alias_binding_dependency_names(statement) or _alias_binding_dependency_names(line)
                )
                if update_alias is not None:
                    alias_dependencies.add(update_alias[1])
                    alias_dependencies.update(
                        referenced_identifiers.intersection(
                            set(runpy_namespace_update_aliases)
                            | set(runpy_namespace_setitem_aliases)
                            | set(runpy_namespace_setdefault_aliases)
                        )
                    )
                    alias_dependencies.update(
                        referenced_identifiers.intersection(
                            {
                                name
                                for name, helper_name in canonical_builtin_helper_aliases.items()
                                if helper_name == "vars"
                            }
                        )
                    )
                if descriptor_reference is not None:
                    typed_state_spans, _typed_state_overflowed = typed_member_state_before(
                        descriptor_reference, span[0]
                    )
                    if _typed_state_overflowed:
                        fail_closed_dangerous_names.add(binding_name)
                        relevant_binding_names.add(binding_name)
                        forwarded_rule_codes[binding_name] = typed_reference_rule_codes(descriptor_reference)
                    elif typed_state_spans:
                        typed_binding_state_spans[span] = [typed_state_spans[-1]]
                        if (
                            guard_value is True
                            and (
                                descriptor_reference,
                                typed_state_spans[-1],
                            )
                            in typed_safe_member_write_spans
                        ):
                            definite_shadowed_names.add(binding_name)
                            pending_shadow_spans[binding_name] = typed_state_spans[-1]
                            forwarded_state_sizes.pop(binding_name, None)
                            forwarded_safe_names.add(binding_name)
                        elif (descriptor_reference, typed_state_spans[-1]) in typed_fail_closed_member_write_spans:
                            fail_closed_dangerous_names.add(binding_name)
                            relevant_binding_names.add(binding_name)
                            forwarded_rule_codes[binding_name] = typed_reference_rule_codes(descriptor_reference)
                if (
                    (
                        is_truthy_builtin_reference(descriptor_reference)
                        or forwarded_dependency in truthy_builtin_capture_names
                    )
                    and binding_name not in relevant_binding_names
                    and binding_name not in fail_closed_dangerous_names
                    and not intersects_relevant_or_fail_closed(alias_dependencies)
                ):
                    truthy_builtin_capture_names.add(binding_name)
                    alias_dependency_names_cache[span] = alias_dependencies
                    add_late_definition(binding_name, statement, span)
                elif guard_value is True:
                    truthy_builtin_capture_names.discard(binding_name)
                has_typed_rule_marker = b"." in statement and any(
                    marker in statement for marker in _TYPED_PROOF_BINDING_MARKERS
                )
                if has_typed_rule_marker and intersects_relevant_or_fail_closed(alias_dependencies):
                    typed_rule_source_names.add(binding_name)
                if (
                    forwarded_dependency is not None
                    and (
                        forwarded_dependency in forwarded_rule_codes
                        or forwarded_dependency in typed_rule_source_names
                        or (
                            forwarded_dependency in retained_alias_names
                            and (has_typed_rule_marker or b"." not in statement)
                        )
                    )
                    and intersects_relevant_or_fail_closed(alias_dependencies)
                ):
                    bind_forwarded_rule_codes(binding_name, statement, forwarded_dependency, span[0])
                if (
                    binding_name in builtin_dict_update_aliases
                    or binding_name in builtin_dict_descriptor_setitem_aliases
                    or binding_name in builtin_dict_descriptor_setdefault_aliases
                    or binding_name in runpy_namespace_update_aliases
                    or binding_name in runpy_namespace_setitem_aliases
                    or binding_name in runpy_namespace_setdefault_aliases
                    or binding_name in runpy_namespace_delete_aliases
                ):
                    alias_dependency_names_cache[span] = alias_dependencies
                    add_late_definition(binding_name, statement, span)
                if (
                    guard_value is None
                    and binding_name in relevant_binding_names
                    and alias_dependencies.isdisjoint(relevant_binding_names)
                    and not has_evaluated_annotation
                ):
                    if _is_exhaustive_safe_late_binding(candidate, line_start, line, binding_name):
                        definite_shadowed_names.add(binding_name)
                        fail_closed_dangerous_names.discard(binding_name)
                        forwarded_state_sizes.pop(binding_name, None)
                        forwarded_safe_names.add(binding_name)
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                if (
                    forwarded_dependency is None
                    and intersects_relevant_or_fail_closed(alias_dependencies)
                    and _assignment_may_bind_priority_alias(
                        statement,
                        relevant_binding_names | fail_closed_dangerous_names,
                        shadowed_truthy_builtin_names,
                    )
                ):
                    conditional_state_size = (span[1] - span[0]) + sum(
                        state_end - state_start for state_start, state_end in truthy_builtin_state_spans
                    )
                    if conditional_state_size > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
                        fail_closed_dangerous_names.add(binding_name)
                        relevant_binding_names.add(binding_name)
                        forwarded_state_sizes[binding_name] = conditional_state_size
                        forwarded_safe_names.discard(binding_name)
                    else:
                        alias_dependency_names_cache[span] = alias_dependencies
                        add_late_definition(binding_name, statement, span)
                        relevant_binding_names.add(binding_name)
                        forwarded_state_sizes[binding_name] = conditional_state_size
                        forwarded_safe_names.discard(binding_name)
                    if not same_line_priority_endpoint:
                        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                        line_start = line_end
                        continue
                if (
                    (guard_value is None or statement[:1].isspace())
                    and not has_evaluated_annotation
                    and intersects_relevant_or_fail_closed(alias_dependencies)
                ):
                    fail_closed_dangerous_names.add(binding_name)
                    relevant_binding_names.add(binding_name)
                    forwarded_state_sizes[binding_name] = _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES + 1
                    forwarded_safe_names.discard(binding_name)
                    if not same_line_priority_endpoint:
                        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                        line_start = line_end
                        continue
                if forwarded_dependency is not None:
                    if forwarded_dependency in fail_closed_dangerous_names:
                        fail_closed_dangerous_names.add(binding_name)
                        relevant_binding_names.add(binding_name)
                        forwarded_state_sizes[binding_name] = _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES + 1
                        forwarded_safe_names.discard(binding_name)
                        if not has_evaluated_annotation and not same_line_priority_endpoint:
                            multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                            line_start = line_end
                            continue
                    source_size = forwarded_state_sizes.get(forwarded_dependency)
                    if source_size is not None:
                        forwarded_size = source_size + span[1] - span[0]
                        if forwarded_size > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
                            fail_closed_dangerous_names.add(binding_name)
                            relevant_binding_names.add(binding_name)
                            forwarded_state_sizes[binding_name] = forwarded_size
                            forwarded_safe_names.discard(binding_name)
                            if not has_evaluated_annotation and not same_line_priority_endpoint:
                                multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                                line_start = line_end
                                continue
                        forwarded_state_sizes[binding_name] = forwarded_size
                        forwarded_safe_names.discard(binding_name)
                    elif (
                        forwarded_dependency in forwarded_safe_names
                        or forwarded_dependency not in relevant_binding_names
                    ):
                        forwarded_state_sizes.pop(binding_name, None)
                        forwarded_safe_names.add(binding_name)
                        if (
                            not has_evaluated_annotation
                            and binding_name not in retained_alias_names
                            and binding_name not in late_definitions
                            and not same_line_priority_endpoint
                        ):
                            relevant_binding_names.discard(binding_name)
                            multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                            line_start = line_end
                            continue
                elif not alias_dependencies:
                    forwarded_state_sizes.pop(binding_name, None)
                    forwarded_safe_names.add(binding_name)
                    if (
                        binding_name not in retained_alias_names
                        and binding_name not in late_definitions
                        and not same_line_priority_endpoint
                    ):
                        relevant_binding_names.discard(binding_name)
                        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                        line_start = line_end
                        continue
                if (
                    binding_name in relevant_binding_names
                    or forwarded_dependency in relevant_binding_names
                    or not referenced_identifiers.isdisjoint(relevant_binding_names)
                ):
                    alias_dependency_names_cache[span] = alias_dependencies
                    add_late_definition(binding_name, statement, span)
                    relevant_binding_names.add(binding_name)
            elif (
                re.match(rb"\s*(?:import|from)\b", code_line) is not None
                or re.search(rb"\bfrom\s+builtins\s+import\b", code_line) is not None
            ):
                import_statement = line
                import_span = (line_start, line_end)
                if (parenthesis_delta > 0 or has_line_continuation) and not continues_prior_expression:
                    import_statement, import_span = _bounded_late_binding_statement(candidate, line_start, line_end)
                import_is_scoped = _is_nested_late_state_statement(candidate, line_start, line, enclosing_headers)
                canonical_import_statement = (
                    import_statement.lstrip() if late_guard_value is True and not import_is_scoped else import_statement
                )
                import_code_line = _python_structural_line_bytes(canonical_import_statement.lstrip(b"\x00\xff"))
                builtins_import = re.match(rb"\s*import\s+builtins(?:\s+as\s+([A-Za-z_]\w*))?", import_code_line)
                if builtins_import is not None and late_guard_value is True and not import_is_scoped:
                    register_builtins_alias((builtins_import.group(1) or b"builtins").decode("utf-8"))
                    late_builtins_import_spans.append(import_span)
                builtins_dict_import_aliases = _builtins_dict_import_alias_names(canonical_import_statement)
                if (
                    late_guard_value is True
                    and not import_is_scoped
                    and builtins_dict_import_aliases
                    and "builtins.dict" not in shadowed_descriptor_names | uncertain_descriptor_names
                ):
                    builtin_dict_descriptor_aliases.update(builtins_dict_import_aliases)
                for name in _statement_defined_names(canonical_import_statement):
                    if name == "dict":
                        shadowed_descriptor_names.add("dict")
                    definite_shadowed_names.discard(name)
                    fail_closed_dangerous_names.discard(name)
                    forwarded_state_sizes.pop(name, None)
                    forwarded_safe_names.discard(name)
                    add_late_definition(name, canonical_import_statement, import_span)
            else:
                descriptor_statement = line
                if (parenthesis_delta > 0 or has_line_continuation) and not continues_prior_expression:
                    descriptor_statement, _descriptor_span = _bounded_late_binding_statement(
                        candidate, line_start, line_end
                    )
                descriptor_code_line = _python_structural_line_bytes(descriptor_statement.lstrip(b"\x00\xff"))
                calls_saved_descriptor_mutator = not _python_identifier_names(descriptor_code_line).isdisjoint(
                    builtin_dict_mapping_update_aliases
                    | builtin_dict_mapping_setitem_aliases
                    | builtin_dict_descriptor_setitem_aliases
                )
                if (
                    (
                        b"dict" in descriptor_code_line
                        and (b"=" in descriptor_code_line or b"update" in descriptor_code_line)
                    )
                    or b"__setitem__" in descriptor_code_line
                    or calls_saved_descriptor_mutator
                ):
                    descriptor_write = _builtin_dict_attribute_write_state(
                        descriptor_statement,
                        builtins_alias_names,
                        builtin_dict_descriptor_aliases,
                        shadowed_descriptor_names,
                        builtin_dict_mapping_aliases,
                        uncertain_builtin_dict_mapping_aliases,
                        builtin_dict_mapping_update_aliases,
                        uncertain_builtin_dict_mapping_update_aliases,
                        builtin_dict_mapping_setitem_aliases,
                        uncertain_builtin_dict_mapping_setitem_aliases,
                        builtin_dict_descriptor_setitem_aliases,
                        shadowed_builtin_helper_names,
                        canonical_builtin_helper_aliases,
                        uncertain_canonical_builtin_helper_aliases,
                    )
                    if descriptor_write is not None and not _is_nested_late_state_statement(
                        candidate, line_start, line, enclosing_headers
                    ):
                        descriptor_guard = _constant_late_binding_guard_value(
                            candidate, line_start, line, enclosing_headers, exception_type_aliases
                        )
                        potentially_conditional_mapping_write = not _python_identifier_names(
                            descriptor_statement
                        ).isdisjoint(
                            uncertain_builtin_dict_mapping_aliases | uncertain_builtin_dict_mapping_update_aliases
                        )
                        descriptor_restores_builtin, uncertain_descriptor_write = descriptor_write
                        if (
                            descriptor_guard is None
                            or potentially_conditional_mapping_write
                            or uncertain_descriptor_write
                        ):
                            uncertain_descriptor_names.add("builtins.dict")
                            shadowed_descriptor_names.discard("builtins.dict")
                        elif descriptor_guard is True:
                            uncertain_descriptor_names.discard("builtins.dict")
                            if descriptor_restores_builtin:
                                shadowed_descriptor_names.discard("builtins.dict")
                            else:
                                shadowed_descriptor_names.add("builtins.dict")
                helper_write = _builtin_helper_attribute_write_state(
                    descriptor_statement,
                    builtins_alias_names,
                    builtin_dict_mapping_aliases,
                    uncertain_builtin_dict_mapping_aliases,
                    builtin_dict_mapping_update_aliases,
                    uncertain_builtin_dict_mapping_update_aliases,
                    builtin_dict_mapping_setitem_aliases,
                    uncertain_builtin_dict_mapping_setitem_aliases,
                    builtin_dict_descriptor_aliases,
                    shadowed_descriptor_names | uncertain_descriptor_names,
                    shadowed_builtin_helper_names,
                    uncertain_builtin_helper_names,
                    canonical_builtin_helper_aliases,
                    uncertain_canonical_builtin_helper_aliases,
                )
                if helper_write is not None and not _is_nested_late_state_statement(
                    candidate, line_start, line, enclosing_headers
                ):
                    helper_name, restores_helper, uncertain_helper_write = helper_write
                    helper_guard = _constant_late_binding_guard_value(
                        candidate, line_start, line, enclosing_headers, exception_type_aliases
                    )
                    affected_helper_names = {helper_name, f"builtins.{helper_name}"}
                    if helper_guard is None or uncertain_helper_write:
                        shadowed_builtin_helper_names.difference_update(affected_helper_names)
                        uncertain_builtin_helper_names.update(affected_helper_names)
                        if restores_helper:
                            for affected_helper_name in affected_helper_names:
                                canonical_builtin_helper_aliases[affected_helper_name] = helper_name
                                uncertain_canonical_builtin_helper_aliases.add(affected_helper_name)
                        else:
                            uncertain_canonical_builtin_helper_aliases.update(
                                affected_helper_names.intersection(canonical_builtin_helper_aliases)
                            )
                    elif helper_guard is True:
                        if restores_helper:
                            uncertain_builtin_helper_names.difference_update(affected_helper_names)
                            shadowed_builtin_helper_names.difference_update(affected_helper_names)
                            for affected_helper_name in affected_helper_names:
                                canonical_builtin_helper_aliases[affected_helper_name] = helper_name
                                uncertain_canonical_builtin_helper_aliases.discard(affected_helper_name)
                        else:
                            uncertain_builtin_helper_names.difference_update(affected_helper_names)
                            shadowed_builtin_helper_names.update(affected_helper_names)
                            for affected_helper_name in affected_helper_names:
                                canonical_builtin_helper_aliases.pop(affected_helper_name, None)
                                uncertain_canonical_builtin_helper_aliases.discard(affected_helper_name)
                helper_delete = _builtin_helper_delete_state(descriptor_statement, builtins_alias_names)
                if helper_delete is not None and not _is_nested_late_state_statement(
                    candidate, line_start, line, enclosing_headers
                ):
                    helper_name, restores_helper = helper_delete
                    helper_guard = _constant_late_binding_guard_value(
                        candidate, line_start, line, enclosing_headers, exception_type_aliases
                    )
                    if helper_guard is None:
                        shadowed_builtin_helper_names.discard(helper_name)
                        uncertain_builtin_helper_names.add(helper_name)
                    elif helper_guard is True:
                        uncertain_builtin_helper_names.discard(helper_name)
                        if restores_helper and f"builtins.{helper_name}" not in shadowed_builtin_helper_names:
                            shadowed_builtin_helper_names.discard(helper_name)
                            canonical_builtin_helper_aliases[helper_name] = helper_name
                            uncertain_canonical_builtin_helper_aliases.discard(helper_name)
                        else:
                            shadowed_builtin_helper_names.add(helper_name)
                            canonical_builtin_helper_aliases.pop(helper_name, None)
                            uncertain_canonical_builtin_helper_aliases.discard(helper_name)
                shadow_name = _definite_late_shadow_name(line, code_line)
                if shadow_name is not None:
                    definite_shadowed_names.add(shadow_name)
                    pending_shadow_spans[shadow_name] = (
                        line_start,
                        min(
                            _priority_alias_shadow_segment_end(candidate, line, line_end),
                            line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES,
                        ),
                    )
                    fail_closed_dangerous_names.discard(shadow_name)
                    forwarded_state_sizes.pop(shadow_name, None)
                    forwarded_safe_names.discard(shadow_name)
                    relevant_binding_names.discard(shadow_name)
        member_statement = line
        member_statement_span = (line_start, line_end)
        if (parenthesis_delta > 0 or has_line_continuation) and not continues_prior_expression:
            member_statement, member_statement_span = _bounded_late_binding_statement(candidate, line_start, line_end)
        member_code_line = _python_structural_line_bytes(member_statement.lstrip(b"\x00\xff"))
        could_update_runpy_member = not is_simple_forwarding_binding and (
            b"run" in member_statement
            or b"__dict__" in member_statement
            or b"vars" in member_statement
            or not _python_identifier_names(member_code_line).isdisjoint(runpy_namespace_update_aliases)
            or not _python_identifier_names(member_code_line).isdisjoint(runpy_namespace_setitem_aliases)
            or not _python_identifier_names(member_code_line).isdisjoint(runpy_namespace_setdefault_aliases)
            or not _python_identifier_names(member_code_line).isdisjoint(runpy_namespace_delete_aliases)
            or not _python_identifier_names(member_code_line).isdisjoint(builtin_dict_update_aliases)
            or not _python_identifier_names(member_code_line).isdisjoint(builtin_dict_descriptor_setitem_aliases)
            or not _python_identifier_names(member_code_line).isdisjoint(builtin_dict_descriptor_setdefault_aliases)
        )
        member_update = (
            _runpy_priority_member_update_key(
                member_statement,
                member_code_line,
                frozenset(name.encode("utf-8") for name in relevant_binding_names),
                runpy_namespace_update_aliases,
                runpy_namespace_setitem_aliases,
                runpy_namespace_setdefault_aliases,
                shadowed_descriptor_names,
                builtin_dict_update_aliases,
                builtin_dict_descriptor_setitem_aliases,
                builtin_dict_descriptor_setdefault_aliases,
                builtins_alias_names,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if line_end > search_start and could_update_runpy_member
            else None
        )
        deleted_runpy_member_key = (
            _runpy_priority_deleted_member_key(
                member_statement,
                frozenset(name.encode("utf-8") for name in relevant_binding_names),
                runpy_namespace_update_aliases,
                runpy_namespace_delete_aliases,
                runpy_descriptor_delete_aliases,
                builtin_dict_descriptor_aliases,
                builtins_alias_names,
                shadowed_descriptor_names,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if line_end > search_start and could_update_runpy_member
            else None
        )
        member_identifiers = _python_identifier_names(member_statement)
        uses_runpy_setdefault = (
            b"setdefault" in member_statement
            or not member_identifiers.isdisjoint(runpy_namespace_setdefault_aliases)
            or not member_identifiers.isdisjoint(builtin_dict_descriptor_setdefault_aliases)
        )
        ignored_runpy_setdefault = False
        if (
            member_update is not None
            and uses_runpy_setdefault
            and member_update[0]
            not in definitely_deleted_runpy_members
            | ({deleted_runpy_member_key} if deleted_runpy_member_key is not None else set())
        ):
            member_update = None
            ignored_runpy_setdefault = True
        if (
            member_update is None
            and deleted_runpy_member_key is not None
            and _constant_late_binding_guard_value(
                candidate, line_start, line, enclosing_headers, exception_type_aliases
            )
            is True
            and not _is_nested_late_state_statement(candidate, line_start, line, enclosing_headers)
        ):
            definitely_deleted_runpy_members.add(deleted_runpy_member_key)
            runpy_member_state_spans[deleted_runpy_member_key] = [member_statement_span]
            fail_closed_runpy_members.discard(deleted_runpy_member_key)
        if member_update is not None and (
            _constant_late_binding_guard_value(candidate, line_start, line, enclosing_headers, exception_type_aliases)
            is False
            or _is_nested_late_state_statement(candidate, line_start, line, enclosing_headers)
        ):
            member_update = None
        if member_update is not None:
            member_key, owner_name = member_update
            prior_member_is_proven_safe = (
                member_key in runpy_member_state_spans and member_key not in fail_closed_runpy_members
            )
            member_start = _late_binding_statement_start(
                candidate, line_start, line, enclosing_headers, skip_class_header=True
            )
            if member_start == line_start:
                member_code_start = 0
                while member_code_start < len(line) and not 0x20 <= line[member_code_start] < 0x7F:
                    member_code_start += 1
                member_start += member_code_start
            member_span = (
                member_start,
                min(member_statement_span[1], member_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES),
            )
            member_dependencies = _runpy_priority_member_update_dependency_names(
                candidate[member_span[0] : member_span[1]],
                member_key,
                runpy_namespace_update_aliases,
                runpy_namespace_setitem_aliases,
                runpy_namespace_setdefault_aliases,
                builtin_dict_update_aliases,
                builtin_dict_descriptor_setitem_aliases,
                builtin_dict_descriptor_setdefault_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            member_dependencies.add(owner_name)
            dependent_spans, reaches_retained_alias, overflowed = retained_state_spans(
                member_dependencies, member_start
            )
            mutator_alias_names = (
                set(runpy_namespace_update_aliases)
                | set(runpy_namespace_setitem_aliases)
                | set(runpy_namespace_setdefault_aliases)
                | set(runpy_namespace_delete_aliases)
                | builtin_dict_update_aliases
                | builtin_dict_descriptor_setitem_aliases
                | builtin_dict_descriptor_setdefault_aliases
            )
            value_dependencies = member_dependencies - {owner_name, "print"} - mutator_alias_names
            _value_spans, value_reaches_retained_alias, _value_overflowed = retained_state_spans(
                value_dependencies, member_start
            )
            writes_tracked_dangerous_value = not value_dependencies.isdisjoint(
                (relevant_binding_names | fail_closed_dangerous_names) - definite_shadowed_names
            )
            uses_state_setter = (
                b"__setitem__" in member_statement
                or b"|=" in member_statement
                or not member_identifiers.isdisjoint(
                    set(runpy_namespace_setitem_aliases)
                    | builtin_dict_descriptor_setitem_aliases
                    | set(runpy_namespace_setdefault_aliases)
                    | builtin_dict_descriptor_setdefault_aliases
                )
                or bool(
                    member_identifiers.intersection(
                        {
                            name
                            for name, helper_name in canonical_builtin_helper_aliases.items()
                            if helper_name == "setattr"
                        }
                    )
                )
            )
            unresolved_setter_value = uses_state_setter and bool(value_dependencies)
            class_header_spans = [
                (header_start, candidate.find(b"\n", header_start) + 1)
                for header, header_start in enclosing_headers
                if re.match(rb"\s*class\b", header) is not None
            ]
            member_builtins_import_spans = late_builtins_import_spans if b"builtins" in member_statement else []
            prior_setdefault_state = runpy_member_state_spans.get(member_key, []) if uses_runpy_setdefault else []
            runpy_member_state_spans[member_key] = [
                *prior_setdefault_state,
                *member_builtins_import_spans,
                *dependent_spans,
                *class_header_spans,
                member_span,
            ]
            unresolved_dependencies = member_dependencies - {owner_name, "print"}
            uncertain_descriptor_update = _runpy_priority_descriptor_update_name(
                member_statement,
                builtins_alias_names,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            ) in uncertain_descriptor_names or not _python_identifier_names(member_statement).isdisjoint(
                uncertain_builtin_dict_update_aliases
                | uncertain_builtin_dict_descriptor_setitem_aliases
                | uncertain_builtin_dict_descriptor_setdefault_aliases
            )
            uncertain_helper_update = _statement_uses_uncertain_builtin_helper(
                member_statement, uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases
            )
            ambiguous_descriptor_update = (uncertain_descriptor_update or uncertain_helper_update) and (
                not prior_member_is_proven_safe or bool(unresolved_dependencies)
            )
            unresolved_member_update = bool(unresolved_dependencies) and (
                overflowed or (not dependent_spans and not reaches_retained_alias)
            )
            if (
                ambiguous_descriptor_update
                or unresolved_member_update
                or value_reaches_retained_alias
                or writes_tracked_dangerous_value
                or unresolved_setter_value
                or owner_name in uncertain_runpy_namespace_names
                or not _python_identifier_names(member_statement).isdisjoint(uncertain_runpy_namespace_names)
            ):
                fail_closed_runpy_members.add(member_key)
            else:
                fail_closed_runpy_members.discard(member_key)
            if deleted_runpy_member_key == member_key:
                definitely_deleted_runpy_members.add(member_key)
            else:
                definitely_deleted_runpy_members.discard(member_key)
        if member_update is not None or ignored_runpy_setdefault or deleted_runpy_member_key is not None:
            tracked_member_names = {f"runpy.{name}" for name in _RUNPY_PRIORITY_MEMBER_NAMES}
            has_member_endpoint = _line_calls_fail_closed_runpy_member(member_code_line, aliases, tracked_member_names)
            has_getattr_endpoint = (
                _priority_getattr_alias_member(
                    member_statement,
                    aliases | frozenset(name.encode("utf-8") for name in relevant_binding_names),
                    shadowed_builtin_helper_names,
                    canonical_builtin_helper_aliases,
                )
                is not None
            )
            if not has_member_endpoint and not has_getattr_endpoint:
                multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                line_start = line_end
                continue
        has_priority_reference_syntax = not is_simple_forwarding_binding and any(
            token in code_line for token in (b"(", b".", b"[")
        )
        priority_aliases = (
            frozenset(name.encode("utf-8") for name in relevant_binding_names)
            if has_priority_reference_syntax
            else frozenset()
        )
        tracked_priority_aliases = aliases | priority_aliases
        has_canonical_namespace_helper_use = has_priority_reference_syntax and not _python_identifier_names(
            line
        ).isdisjoint(
            {
                name
                for name, helper_name in canonical_builtin_helper_aliases.items()
                if helper_name in {"getattr", "vars"} and name not in shadowed_builtin_helper_names
            }
        )
        getattr_member = (
            _priority_getattr_alias_member(
                line,
                tracked_priority_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if has_priority_reference_syntax
            and (b"getattr" in line or b"vars" in line or has_canonical_namespace_helper_use)
            else None
        )
        is_getattr_priority_call = getattr_member is not None
        is_parsed_priority_call = has_priority_reference_syntax and _fragment_has_continued_priority_alias_call(
            line, tracked_priority_aliases
        )
        is_continued_call_prefix = continued_expression_start == line_start and (
            continued_parenthesis_depth > 0 or has_line_continuation
        )
        if (
            line_end > search_start
            and has_priority_reference_syntax
            and (_line_uses_priority_alias(code_line, tracked_priority_aliases) or is_getattr_priority_call)
        ):
            usage_span = (line_start, min(line_end, line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES))
            if (
                is_parsed_priority_call
                or _line_calls_priority_alias(code_line, tracked_priority_aliases)
                or is_getattr_priority_call
            ) and not is_continued_call_prefix:
                root_names = _callable_root_names(code_line)
                if getattr_member is not None:
                    root_names.add(getattr_member[2])
                namespace_update_names = (
                    set(runpy_namespace_update_aliases)
                    | set(runpy_namespace_setitem_aliases)
                    | set(runpy_namespace_setdefault_aliases)
                    | set(runpy_namespace_delete_aliases)
                    | runpy_descriptor_delete_aliases
                    | set(typed_member_setdefault_aliases)
                    | set(typed_member_setitem_aliases)
                    | set(typed_member_update_aliases)
                    | typed_member_descriptor_setdefault_aliases
                    | set(typed_member_delete_aliases)
                    | typed_member_descriptor_delete_aliases
                    | builtin_dict_update_aliases
                    | builtin_dict_descriptor_setitem_aliases
                    | builtin_dict_descriptor_setdefault_aliases
                )
                if not root_names and not _python_identifier_names(code_line).isdisjoint(namespace_update_names):
                    root_names = _callable_root_names(member_statement.lstrip(b"\x00\xff"))
                if root_names and root_names.issubset(namespace_update_names):
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                if not root_names.isdisjoint(definite_shadowed_names):
                    usage_lines.extend(
                        pending_shadow_spans[root_name]
                        for root_name in sorted(root_names & definite_shadowed_names)
                        if root_name in pending_shadow_spans
                    )
                    usage_lines.append(usage_span)
                    return usage_lines, frozenset()
                if not root_names.isdisjoint(fail_closed_dangerous_names):
                    usage_lines.append(usage_span)
                    return usage_lines, proof_rule_codes(root_names, conservative=True)
                state_spans, reaches_retained_alias, overflowed = retained_state_spans(root_names, line_start)
                if _line_calls_fail_closed_runpy_member(code_line, aliases, fail_closed_runpy_members):
                    usage_lines.append(usage_span)
                    return usage_lines, frozenset({"S108"})
                if overflowed and not reaches_retained_alias:
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                usage_lines.extend(truthy_builtin_state_spans)
                usage_lines.extend(
                    pending_shadow_spans[root_name]
                    for root_name in sorted(root_names)
                    if root_name in pending_shadow_spans
                )
                usage_lines.extend(state_spans)
                usage_lines.extend(span for member_spans in runpy_member_state_spans.values() for span in member_spans)
                usage_lines.append(usage_span)
                needs_proof = (
                    (overflowed and reaches_retained_alias)
                    or (
                        not runpy_member_state_spans
                        and _line_calls_overbounded_runpy_getattr_alias(
                            line,
                            tracked_priority_aliases,
                            shadowed_builtin_helper_names,
                            canonical_builtin_helper_aliases,
                        )
                    )
                    or (reaches_retained_alias and has_inert_forwarding_state(state_spans))
                )
                return (
                    usage_lines,
                    proof_rule_codes(root_names, conservative=True) if needs_proof else frozenset(),
                )
            member_load_line = line[code_start:]
            root_names = _member_load_root_names(member_load_line).intersection(
                relevant_binding_names | definite_shadowed_names
            )
            if root_names:
                state_spans, reaches_retained_alias, overflowed = retained_state_spans(root_names, line_start)
                attribute_rule_codes = proof_rule_codes(root_names)
                if (
                    not root_names.isdisjoint(fail_closed_dangerous_names)
                    and root_names.isdisjoint(definite_shadowed_names)
                    and "S110" in attribute_rule_codes
                ):
                    usage_lines.append(usage_span)
                    return usage_lines, frozenset({"S110"})
                if (
                    overflowed
                    and reaches_retained_alias
                    and root_names.isdisjoint(definite_shadowed_names)
                    and "S110" in attribute_rule_codes
                ):
                    usage_lines.append(usage_span)
                    return usage_lines, frozenset({"S110"})
                resolved_context = b"\n".join(
                    [priority_context, *(candidate[start:end] for start, end in state_spans), member_load_line]
                )
                has_native_member_marker = any(
                    loader_name in member_load_line for loader_name in (b"cdll", b"oledll", b"pydll", b"windll")
                )
                if "S110" not in attribute_rule_codes and b"(" not in member_load_line and not has_native_member_marker:
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                resolved_rule_codes = _snippet_resolved_high_risk_rule_codes(resolved_context)
                replay_rule_codes = attribute_rule_codes or resolved_rule_codes
                if not replay_rule_codes.intersection(resolved_rule_codes):
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                if not root_names.isdisjoint(definite_shadowed_names):
                    usage_lines.extend(
                        pending_shadow_spans[root_name]
                        for root_name in sorted(root_names & definite_shadowed_names)
                        if root_name in pending_shadow_spans
                    )
                    usage_lines.append(usage_span)
                    return usage_lines, frozenset()
                if overflowed and not reaches_retained_alias:
                    multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
                    line_start = line_end
                    continue
                usage_lines.extend(
                    pending_shadow_spans[root_name]
                    for root_name in sorted(root_names)
                    if root_name in pending_shadow_spans
                )
                usage_lines.extend(state_spans)
                usage_lines.append(usage_span)
                return (
                    usage_lines,
                    replay_rule_codes if overflowed and reaches_retained_alias else frozenset(),
                )
        elif line_end > search_start and b"(" in code_line:
            potential_root_names = _potential_late_callable_root_names(code_line).intersection(
                late_definitions.keys() | fail_closed_dangerous_names
            )
            potential_root_names.difference_update(runpy_namespace_update_aliases)
            potential_root_names.difference_update(runpy_namespace_setitem_aliases)
            potential_root_names.difference_update(runpy_namespace_setdefault_aliases)
            potential_root_names.difference_update(runpy_namespace_delete_aliases)
            potential_root_names.difference_update(runpy_descriptor_delete_aliases)
            potential_root_names.difference_update(typed_member_setdefault_aliases)
            potential_root_names.difference_update(typed_member_setitem_aliases)
            potential_root_names.difference_update(typed_member_update_aliases)
            potential_root_names.difference_update(typed_member_descriptor_setdefault_aliases)
            potential_root_names.difference_update(typed_member_delete_aliases)
            potential_root_names.difference_update(typed_member_descriptor_delete_aliases)
            potential_root_names.difference_update(builtin_dict_update_aliases)
            potential_root_names.difference_update(builtin_dict_descriptor_setitem_aliases)
            potential_root_names.difference_update(builtin_dict_descriptor_setdefault_aliases)
            if potential_root_names:
                root_names = _callable_root_names(code_line).intersection(potential_root_names)
                if not root_names.isdisjoint(definite_shadowed_names):
                    usage_lines.extend(
                        pending_shadow_spans[root_name]
                        for root_name in sorted(root_names & definite_shadowed_names)
                        if root_name in pending_shadow_spans
                    )
                    usage_lines.append(
                        (line_start, min(line_end, line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES))
                    )
                    return usage_lines, frozenset()
                if not root_names.isdisjoint(fail_closed_dangerous_names):
                    usage_lines.append(
                        (line_start, min(line_end, line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES))
                    )
                    return usage_lines, proof_rule_codes(root_names, conservative=True)
                state_spans, reaches_retained_alias, overflowed = retained_state_spans(root_names, line_start)
                if (state_spans or overflowed) and reaches_retained_alias:
                    usage_lines.extend(state_spans)
                    usage_lines.extend(
                        span for member_spans in runpy_member_state_spans.values() for span in member_spans
                    )
                    usage_lines.append(
                        (line_start, min(line_end, line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES))
                    )
                    needs_proof = overflowed or has_inert_forwarding_state(state_spans)
                    return (
                        usage_lines,
                        proof_rule_codes(root_names, conservative=True) if needs_proof else frozenset(),
                    )
        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
        line_start = line_end
    return usage_lines, frozenset()


def _simple_late_binding_name(code_line: bytes) -> str | None:
    match = re.match(rb"\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)", code_line)
    return match.group(1).decode("utf-8") if match is not None else None


def _parse_late_replay_tree(source: str) -> ast.Module | None:
    normalized_source = textwrap.dedent(source)
    if re.match(r"\s*match\b", normalized_source) and normalized_source.rstrip().endswith(":"):
        normalized_source += "\n    case _:\n        pass\n"
    elif re.match(
        r"\s*(?:async\s+def|async\s+with|def|if|elif|for|while|with)\b", normalized_source
    ) and normalized_source.rstrip().endswith(":"):
        normalized_source += "\n    pass\n"
    try:
        return ast.parse(normalized_source)
    except (RecursionError, SyntaxError, ValueError):
        return None


def _source_defers_annotations(candidate: bytes) -> bool:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(candidate.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    return tree is not None and any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in tree.body
    )


_EAGER_LATE_GENERATOR_CONSUMERS = frozenset({"all", "any", "list", "max", "min", "set", "sorted", "sum", "tuple"})
_BUILTIN_EXCEPTION_TYPE_NAMES = frozenset(
    name
    for name in dir(builtins)
    if isinstance((value := getattr(builtins, name)), type) and issubclass(value, BaseException)
)


def _canonical_eager_generator_consumer_aliases() -> dict[str, str]:
    return {
        **{consumer: consumer for consumer in _EAGER_LATE_GENERATOR_CONSUMERS},
        **{f"builtins.{consumer}": consumer for consumer in _EAGER_LATE_GENERATOR_CONSUMERS},
    }


def _eager_generator_consumer_name(node: ast.AST, aliases: dict[str, str] | None = None) -> str | None:
    reference = _simple_reference_name(node)
    return (aliases or _canonical_eager_generator_consumer_aliases()).get(reference or "")


def _eager_generator_consumer_alias_bindings(statement: bytes, aliases: dict[str, str]) -> dict[str, str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return {}
    bindings: dict[str, str] = {}
    for ast_statement in tree.body:
        if (
            isinstance(ast_statement, ast.Assign)
            and len(ast_statement.targets) == 1
            and isinstance(ast_statement.targets[0], ast.Name)
        ):
            canonical = aliases.get(_simple_reference_name(ast_statement.value) or "")
            if canonical is not None:
                bindings[ast_statement.targets[0].id] = canonical
        elif (
            isinstance(ast_statement, (ast.For, ast.AsyncFor))
            and isinstance(ast_statement.target, ast.Name)
            and isinstance(ast_statement.iter, (ast.List, ast.Tuple))
            and len(ast_statement.iter.elts) == 1
        ):
            canonical = aliases.get(_simple_reference_name(ast_statement.iter.elts[0]) or "")
            if canonical is not None:
                bindings[ast_statement.target.id] = canonical
        elif isinstance(ast_statement, ast.ImportFrom) and ast_statement.module == "builtins":
            for alias in ast_statement.names:
                if alias.name in _EAGER_LATE_GENERATOR_CONSUMERS:
                    bindings[alias.asname or alias.name] = alias.name
    return bindings


def _exception_type_alias_bindings(
    statement: bytes,
    aliases: dict[str, str],
    *,
    builtins_alias_names: set[str] | None = None,
    builtin_dict_mapping_aliases: set[str] | None = None,
    builtin_dict_mapping_update_aliases: set[str] | None = None,
    builtin_dict_mapping_setitem_aliases: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
    evaluate_annotations: bool = True,
) -> dict[str, str | None]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return {}
    bindings: dict[str, str | None] = {}
    builtin_aliases = builtins_alias_names or {"builtins"}
    mapping_aliases = builtin_dict_mapping_aliases or set()
    mapping_update_aliases = builtin_dict_mapping_update_aliases or set()
    mapping_setitem_aliases = builtin_dict_mapping_setitem_aliases or set()
    blocked_helpers = shadowed_builtin_helper_names or set()
    canonical_helpers = canonical_builtin_helper_aliases or {
        "setattr": "setattr",
        "builtins.setattr": "setattr",
    }

    def exception_name(node: ast.AST | None) -> str | None:
        name = _static_getattr_member_name(node) if node is not None else None
        return name if name in _BUILTIN_EXCEPTION_TYPE_NAMES else None

    def canonical_value(node: ast.AST | None) -> str | None:
        if node is None:
            return None
        reference = _simple_reference_name(node) or ""
        return bindings.get(reference) if reference in bindings else aliases.get(reference)

    def bind_name(name: str, value: ast.AST | None) -> None:
        canonical_name = canonical_value(value)
        bindings[name] = canonical_name

    def bind_builtin_member(name: str, value: ast.AST | None) -> None:
        canonical_name = canonical_value(value)
        bindings[name] = canonical_name
        for alias_name in builtin_aliases:
            bindings[f"{alias_name}.{name}"] = canonical_name

    def is_builtins_mapping(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (
            (isinstance(node, ast.Name) and node.id in mapping_aliases)
            or (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in builtin_aliases
            )
            or (
                isinstance(node, ast.Call)
                and canonical_helpers.get(helper_reference or "") == "vars"
                and helper_reference not in blocked_helpers
                and ("." not in (helper_reference or "") or "builtins.vars" not in blocked_helpers)
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in builtin_aliases
            )
        )

    def record_target(target: ast.AST, value: ast.AST | None) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            values = value.elts if isinstance(value, (ast.Tuple, ast.List)) else [None] * len(target.elts)
            for element, element_value in zip(target.elts, values, strict=False):
                record_target(element, element_value)
        elif isinstance(target, ast.Starred):
            record_target(target.value, None)
        elif isinstance(target, ast.Name):
            bind_name(target.id, value)
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in builtin_aliases
            and target.attr in _BUILTIN_EXCEPTION_TYPE_NAMES
        ):
            bind_builtin_member(target.attr, value)
        elif (
            isinstance(target, ast.Subscript)
            and is_builtins_mapping(target.value)
            and (name := exception_name(target.slice)) is not None
        ):
            bind_builtin_member(name, value)

    def record_call(call: ast.Call) -> None:
        helper_reference = _simple_reference_name(call.func)
        if (
            canonical_helpers.get(helper_reference or "") == "setattr"
            and helper_reference not in blocked_helpers
            and ("." not in (helper_reference or "") or "builtins.setattr" not in blocked_helpers)
            and len(call.args) >= 3
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id in builtin_aliases
            and (name := exception_name(call.args[1])) is not None
        ):
            bind_builtin_member(name, call.args[2])
            return
        if isinstance(call.func, ast.Name) and call.func.id in mapping_setitem_aliases:
            if len(call.args) >= 2 and (name := exception_name(call.args[0])) is not None:
                bind_builtin_member(name, call.args[1])
            return
        if isinstance(call.func, ast.Name) and call.func.id in mapping_update_aliases:
            update_arguments = call.args
        elif isinstance(call.func, ast.Attribute) and is_builtins_mapping(call.func.value):
            if (
                call.func.attr == "__setitem__"
                and len(call.args) >= 2
                and (name := exception_name(call.args[0])) is not None
            ):
                bind_builtin_member(name, call.args[1])
                return
            if call.func.attr != "update":
                return
            update_arguments = call.args
        else:
            return
        for keyword in call.keywords:
            if keyword.arg in _BUILTIN_EXCEPTION_TYPE_NAMES:
                bind_builtin_member(keyword.arg, keyword.value)
            elif keyword.arg is None and isinstance(keyword.value, ast.Dict):
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
                    if key is not None and (name := exception_name(key)) is not None:
                        bind_builtin_member(name, value)
        for argument in update_arguments:
            if isinstance(argument, ast.Dict):
                for key, value in zip(argument.keys, argument.values, strict=True):
                    if key is not None and (name := exception_name(key)) is not None:
                        bind_builtin_member(name, value)

    for ast_statement in _deterministically_executed_statements(tree.body):
        if isinstance(ast_statement, ast.Assign) and len(ast_statement.targets) == 1:
            record_target(ast_statement.targets[0], ast_statement.value)
        elif isinstance(ast_statement, ast.AnnAssign):
            record_target(ast_statement.target, ast_statement.value)
        elif (
            isinstance(ast_statement, (ast.For, ast.AsyncFor))
            and _static_late_iter_truth(ast_statement.iter) is not False
        ):
            loop_value = (
                ast_statement.iter.elts[0]
                if isinstance(ast_statement.iter, (ast.List, ast.Tuple)) and len(ast_statement.iter.elts) == 1
                else None
            )
            record_target(ast_statement.target, loop_value)
        elif isinstance(ast_statement, (ast.With, ast.AsyncWith)):
            for item in ast_statement.items:
                if item.optional_vars is not None:
                    record_target(item.optional_vars, None)
        elif isinstance(ast_statement, ast.Match):
            for case in ast_statement.cases:
                pattern = case.pattern
                if not isinstance(pattern, ast.MatchAs) or pattern.pattern is not None:
                    break
                if pattern.name is not None:
                    bind_name(pattern.name, ast_statement.subject)
                if case.guard is None or _static_late_truth_value(case.guard) is not False:
                    break
        elif (
            isinstance(ast_statement, ast.AugAssign)
            and isinstance(ast_statement.op, ast.BitOr)
            and is_builtins_mapping(ast_statement.target)
            and isinstance(ast_statement.value, ast.Dict)
        ):
            for key, update_value in zip(ast_statement.value.keys, ast_statement.value.values, strict=True):
                if key is not None and (name := exception_name(key)) is not None:
                    bind_builtin_member(name, update_value)
        for value in _deterministically_evaluated_statement_expressions(
            ast_statement, evaluate_annotations=evaluate_annotations
        ):
            for expression_node in _deterministically_executed_expression_nodes(value):
                if not isinstance(expression_node, ast.NamedExpr) or not isinstance(expression_node.target, ast.Name):
                    continue
                bind_name(expression_node.target.id, expression_node.value)
            for call in _deterministically_executed_expression_calls(value):
                record_call(call)
    return bindings


def _mutated_builtin_eager_generator_consumers(
    statement: bytes,
    builtins_alias_names: set[str],
    *,
    builtin_dict_mapping_aliases: set[str] | None = None,
    builtin_dict_descriptor_aliases: set[str] | None = None,
    builtin_dict_mapping_update_aliases: set[str] | None = None,
    builtin_dict_mapping_setitem_aliases: set[str] | None = None,
    shadowed_descriptor_names: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
    evaluate_annotations: bool = True,
) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return set()
    mutated: set[str] = set()
    blocked_helpers = shadowed_builtin_helper_names or set()
    canonical_helpers = canonical_builtin_helper_aliases or {
        "setattr": "setattr",
        "builtins.setattr": "setattr",
    }

    def consumer_name(node: ast.AST | None) -> str | None:
        if node is None:
            return None
        name = _static_getattr_member_name(node)
        return name if name in _EAGER_LATE_GENERATOR_CONSUMERS else None

    def is_builtins_mapping(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (
            (isinstance(node, ast.Name) and node.id in (builtin_dict_mapping_aliases or set()))
            or (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in builtins_alias_names
            )
            or (
                isinstance(node, ast.Call)
                and canonical_helpers.get(helper_reference or "") == "vars"
                and helper_reference not in blocked_helpers
                and ("." not in (helper_reference or "") or "builtins.vars" not in blocked_helpers)
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in builtins_alias_names
            )
        )

    def record_target(target: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                record_target(element)
        elif isinstance(target, ast.Starred):
            record_target(target.value)
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in builtins_alias_names
            and target.attr in _EAGER_LATE_GENERATOR_CONSUMERS
        ):
            mutated.add(target.attr)
        elif (
            isinstance(target, ast.Subscript)
            and is_builtins_mapping(target.value)
            and (name := consumer_name(target.slice)) is not None
        ):
            mutated.add(name)

    def record_call(call: ast.Call) -> None:
        helper_reference = _simple_reference_name(call.func)
        if (
            canonical_helpers.get(helper_reference or "") == "setattr"
            and helper_reference not in blocked_helpers
            and ("." not in (helper_reference or "") or "builtins.setattr" not in blocked_helpers)
            and len(call.args) >= 2
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id in builtins_alias_names
            and (name := consumer_name(call.args[1])) is not None
        ):
            mutated.add(name)
            return
        call_arguments = call.args
        if isinstance(call.func, ast.Attribute):
            mapping_method = call.func.attr
            targets_mapping = is_builtins_mapping(call.func.value)
            descriptor_reference = _simple_reference_name(call.func.value)
            if (
                not targets_mapping
                and descriptor_reference in (builtin_dict_descriptor_aliases or {"dict"})
                and descriptor_reference not in (shadowed_descriptor_names or set())
                and call.args
                and is_builtins_mapping(call.args[0])
            ):
                targets_mapping = True
                call_arguments = call.args[1:]
        elif isinstance(call.func, ast.Name) and call.func.id in (builtin_dict_mapping_update_aliases or set()):
            mapping_method = "update"
            targets_mapping = True
        elif isinstance(call.func, ast.Name) and call.func.id in (builtin_dict_mapping_setitem_aliases or set()):
            mapping_method = "__setitem__"
            targets_mapping = True
        else:
            return
        if not targets_mapping:
            return
        if (
            mapping_method == "__setitem__"
            and call_arguments
            and (name := consumer_name(call_arguments[0])) is not None
        ):
            mutated.add(name)
        elif mapping_method == "update":
            mutated.update(keyword.arg for keyword in call.keywords if keyword.arg in _EAGER_LATE_GENERATOR_CONSUMERS)
            for keyword in call.keywords:
                if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                    mutated.update(
                        name
                        for key in keyword.value.keys
                        if key is not None and (name := consumer_name(key)) is not None
                    )
            for argument in call_arguments:
                if isinstance(argument, ast.Dict):
                    mutated.update(
                        name for key in argument.keys if key is not None and (name := consumer_name(key)) is not None
                    )

    for ast_statement in _deterministically_executed_statements(tree.body):
        if isinstance(ast_statement, ast.Assign):
            for target in ast_statement.targets:
                record_target(target)
        elif isinstance(ast_statement, ast.AnnAssign):
            record_target(ast_statement.target)
        elif isinstance(ast_statement, (ast.For, ast.AsyncFor)):
            if _static_late_iter_truth(ast_statement.iter) is not False:
                record_target(ast_statement.target)
        elif isinstance(ast_statement, (ast.With, ast.AsyncWith)):
            for item in ast_statement.items:
                if item.optional_vars is not None:
                    record_target(item.optional_vars)
        elif isinstance(ast_statement, ast.AugAssign):
            record_target(ast_statement.target)
            if (
                isinstance(ast_statement.op, ast.BitOr)
                and is_builtins_mapping(ast_statement.target)
                and isinstance(ast_statement.value, ast.Dict)
            ):
                mutated.update(
                    name
                    for key in ast_statement.value.keys
                    if key is not None and (name := consumer_name(key)) is not None
                )
        elif isinstance(ast_statement, ast.Delete):
            for target in ast_statement.targets:
                record_target(target)
        for value in _deterministically_evaluated_statement_expressions(
            ast_statement, evaluate_annotations=evaluate_annotations
        ):
            for expression_node in _deterministically_executed_expression_nodes(value):
                if isinstance(expression_node, ast.NamedExpr):
                    record_target(expression_node.target)
            for call in _deterministically_executed_expression_calls(value):
                record_call(call)
    return mutated


def _static_late_comparison_value(left_node: ast.AST, operator: ast.cmpop, right_node: ast.AST) -> bool | None:
    try:
        left = ast.literal_eval(left_node)
        right = ast.literal_eval(right_node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    try:
        if isinstance(operator, ast.Eq):
            return bool(left == right)
        if isinstance(operator, ast.NotEq):
            return bool(left != right)
        if isinstance(operator, ast.Lt):
            return bool(left < right)
        if isinstance(operator, ast.LtE):
            return bool(left <= right)
        if isinstance(operator, ast.Gt):
            return bool(left > right)
        if isinstance(operator, ast.GtE):
            return bool(left >= right)
        if isinstance(operator, ast.Is):
            return left is right
        if isinstance(operator, ast.IsNot):
            return left is not right
        if isinstance(operator, ast.In):
            return left in right
        if isinstance(operator, ast.NotIn):
            return left not in right
    except (TypeError, ValueError):
        return None
    return None


def _static_late_truth_value(node: ast.AST, *, _remaining: int = 128) -> bool | None:
    negated = False
    while isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        if _remaining <= 0:
            return None
        _remaining -= 1
        negated = not negated
        node = node.operand
    if _remaining <= 0:
        return None
    try:
        result: bool | None = bool(ast.literal_eval(node))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        result = None
    if result is None and isinstance(node, ast.Compare):
        result = True
        prior = node.left
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            comparison = _static_late_comparison_value(prior, operator, comparator)
            if comparison is None:
                return None
            if not comparison:
                result = False
                break
            prior = comparator
    elif result is None and isinstance(node, ast.BoolOp):
        result = not isinstance(node.op, ast.Or)
        for index, operand in enumerate(node.values):
            value = _static_late_truth_value(operand, _remaining=_remaining - 1)
            if value is None:
                return None
            if isinstance(node.op, ast.And) and not value:
                result = False
                break
            if isinstance(node.op, ast.Or) and value:
                result = True
                break
            if index == len(node.values) - 1:
                result = value
    elif result is None and isinstance(node, ast.IfExp):
        condition = _static_late_truth_value(node.test, _remaining=_remaining - 1)
        if condition is not None:
            result = _static_late_truth_value(node.body if condition else node.orelse, _remaining=_remaining - 1)
    if result is None:
        return None
    return not result if negated else result


def _preceding_static_scalar_guard_value(candidate: bytes, header_start: int, name: str) -> bool | None:
    def namespace_helper_state(helper_name: str, statement_start: int) -> str:
        def is_empty_lambda(node: ast.AST) -> bool:
            return isinstance(node, ast.Lambda) and isinstance(node.body, ast.Dict) and not node.body.keys

        cursor = statement_start
        encoded_helper_name = helper_name.encode("utf-8")
        deleted_shadow = False
        while cursor > 0 and statement_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
            previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
            previous_line = candidate[previous_start:cursor]
            cursor = previous_start
            structural_line = _python_structural_line_bytes(previous_line).strip()
            if not structural_line or encoded_helper_name not in previous_line:
                continue
            source, _byte_offsets = _decode_utf8_with_byte_offsets(previous_line.strip())
            try:
                statement = ast.parse(source).body[0]
            except (IndexError, SyntaxError, ValueError):
                return "uncertain"
            if (
                isinstance(statement, ast.Delete)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == helper_name
            ):
                if deleted_shadow:
                    return "uncertain"
                deleted_shadow = True
                continue
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == helper_name
                and deleted_shadow
            ):
                return "canonical"
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == helper_name
                and is_empty_lambda(statement.value)
            ):
                return "empty"
            mapping_binding_value: ast.AST | None = None
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Subscript)
                and isinstance(statement.targets[0].value, ast.Call)
                and isinstance(statement.targets[0].value.func, ast.Name)
                and statement.targets[0].value.func.id == helper_name
                and not statement.targets[0].value.args
                and not statement.targets[0].value.keywords
                and static_key(statement.targets[0].slice) == helper_name
                and namespace_helper_state(helper_name, previous_start) == "canonical"
            ):
                mapping_binding_value = statement.value
            elif (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
                and isinstance(statement.value.func.value, ast.Call)
                and isinstance(statement.value.func.value.func, ast.Name)
                and statement.value.func.value.func.id == helper_name
                and not statement.value.func.value.args
                and not statement.value.func.value.keywords
                and namespace_helper_state(helper_name, previous_start) == "canonical"
            ):
                call = statement.value
                assert isinstance(call.func, ast.Attribute)
                if call.func.attr == "__setitem__" and len(call.args) == 2 and static_key(call.args[0]) == helper_name:
                    mapping_binding_value = call.args[1]
                elif call.func.attr == "update":
                    for keyword in call.keywords:
                        if keyword.arg == helper_name:
                            mapping_binding_value = keyword.value
                    if mapping_binding_value is None and len(call.args) == 1 and isinstance(call.args[0], ast.Dict):
                        for key, value_node in zip(call.args[0].keys, call.args[0].values, strict=True):
                            if key is not None and static_key(key) == helper_name:
                                mapping_binding_value = value_node
                                break
            if mapping_binding_value is not None:
                if deleted_shadow:
                    return "canonical"
                return "empty" if is_empty_lambda(mapping_binding_value) else "uncertain"
            if isinstance(statement, ast.Expr):
                try:
                    ast.literal_eval(statement.value)
                except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
                    return "uncertain"
                continue
            return "uncertain"
        return "uncertain" if deleted_shadow else "canonical"

    def is_namespace_mapping(node: ast.AST, statement_start: int) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"globals", "locals", "vars"}
            and not node.args
            and not node.keywords
            and namespace_helper_state(node.func.id, statement_start) == "canonical"
        )

    def static_key(node: ast.AST) -> str | None:
        try:
            key = ast.literal_eval(node)
        except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
            return None
        return key if isinstance(key, str) else None

    def static_write_value(statement: ast.stmt, statement_start: int) -> tuple[bool, bool | None]:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target = statement.target
            value = statement.value
        else:
            target = None
            value = None
        if isinstance(target, ast.Name) and target.id == name and value is not None:
            return True, _static_late_truth_value(value)
        if (
            isinstance(target, ast.Subscript)
            and is_namespace_mapping(target.value, statement_start)
            and static_key(target.slice) == name
            and value is not None
        ):
            return True, _static_late_truth_value(value)
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            return False, None
        call = statement.value
        if not isinstance(call.func, ast.Attribute) or not is_namespace_mapping(call.func.value, statement_start):
            return False, None
        if call.func.attr == "__setitem__" and len(call.args) == 2 and static_key(call.args[0]) == name:
            return True, _static_late_truth_value(call.args[1])
        if call.func.attr != "update":
            return False, None
        for keyword in call.keywords:
            if keyword.arg == name:
                return True, _static_late_truth_value(keyword.value)
        if len(call.args) == 1 and isinstance(call.args[0], ast.Dict):
            for key, value_node in zip(call.args[0].keys, call.args[0].values, strict=True):
                if key is not None and static_key(key) == name:
                    return True, _static_late_truth_value(value_node)
        return False, None

    def writes_only_empty_shadow_namespace(statement: ast.stmt, statement_start: int) -> bool:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            return False
        target = statement.targets[0]
        return (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Call)
            and isinstance(target.value.func, ast.Name)
            and target.value.func.id in {"globals", "locals", "vars"}
            and not target.value.args
            and not target.value.keywords
            and namespace_helper_state(target.value.func.id, statement_start) == "empty"
            and static_key(target.slice) == name
        )

    header_line_start = candidate.rfind(b"\n", 0, header_start) + 1
    header_line_end = candidate.find(b"\n", header_start)
    header_line_end = len(candidate) if header_line_end < 0 else header_line_end + 1
    header_indent = _line_indent_width(candidate[header_line_start:header_line_end])
    cursor = header_line_start
    encoded_name = name.encode("utf-8")
    while cursor > 0 and header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line or encoded_name not in previous_line:
            continue
        if _line_indent_width(previous_line) != header_indent:
            return None
        source, _byte_offsets = _decode_utf8_with_byte_offsets(previous_line.strip())
        try:
            statement = ast.parse(source).body[0]
        except (IndexError, SyntaxError, ValueError):
            return None
        writes_name, value = static_write_value(statement, previous_start)
        if writes_name:
            return value
        if writes_only_empty_shadow_namespace(statement, previous_start):
            continue
        if isinstance(statement, ast.Expr):
            try:
                ast.literal_eval(statement.value)
            except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
                return None
            continue
        return None
    return None


def _static_late_iter_truth(node: ast.AST) -> bool | None:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        try:
            ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None
        return bool(node.elts)
    if isinstance(node, ast.Dict):
        try:
            ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None
        return bool(node.keys)
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return bool(node.value)
    return None


def _deterministically_executed_expression_nodes(
    node: ast.AST | None, *, eager_generator_consumers: dict[str, str] | None = None
) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    pending = [node] if node is not None else []
    while pending:
        current = pending.pop()
        nodes.append(current)
        if isinstance(current, ast.Lambda):
            pending.extend(reversed([*current.args.defaults, *[value for value in current.args.kw_defaults if value]]))
            continue
        if isinstance(current, ast.GeneratorExp):
            if current.generators:
                pending.append(current.generators[0].iter)
            continue
        if (
            isinstance(current, ast.Call)
            and _eager_generator_consumer_name(current.func, eager_generator_consumers) is not None
        ):
            for argument in current.args:
                if not isinstance(argument, ast.GeneratorExp) or not argument.generators:
                    continue
                outer = argument.generators[0]
                pending.extend(reversed(outer.ifs))
                if _static_late_iter_truth(outer.iter) is False or any(
                    _static_late_truth_value(condition) is False for condition in outer.ifs
                ):
                    continue
                pending.append(argument.elt)
        if isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp)) and current.generators:
            generators = current.generators
            outer = generators[0]
            pending.append(outer.iter)
            if _static_late_iter_truth(outer.iter) is False:
                continue
            pending.extend(reversed(outer.ifs))
            if any(_static_late_truth_value(condition) is False for condition in outer.ifs):
                continue
            for generator in reversed(generators[1:]):
                pending.extend(reversed(generator.ifs))
                pending.append(generator.iter)
            if isinstance(current, ast.DictComp):
                pending.extend((current.value, current.key))
            else:
                pending.append(current.elt)
            continue
        if isinstance(current, ast.IfExp):
            branch_nodes: list[ast.AST] = [current.test]
            condition = _static_late_truth_value(current.test)
            if condition is None:
                branch_nodes.extend((current.body, current.orelse))
            else:
                branch_nodes.append(current.body if condition else current.orelse)
            pending.extend(reversed(branch_nodes))
            continue
        if isinstance(current, ast.Compare):
            evaluated_nodes = [current.left]
            prior = current.left
            for index, (operator, comparator) in enumerate(zip(current.ops, current.comparators, strict=True)):
                evaluated_nodes.append(comparator)
                comparison = _static_late_comparison_value(prior, operator, comparator)
                if comparison is False:
                    break
                if comparison is None:
                    evaluated_nodes.extend(current.comparators[index + 1 :])
                    break
                prior = comparator
            pending.extend(reversed(evaluated_nodes))
            continue
        if isinstance(current, ast.BoolOp):
            evaluated_operands: list[ast.AST] = []
            for index, operand in enumerate(current.values):
                evaluated_operands.append(operand)
                value = _static_late_truth_value(operand)
                if value is None:
                    evaluated_operands.extend(current.values[index + 1 :])
                    break
                if isinstance(current.op, ast.And) and not value:
                    break
                if isinstance(current.op, ast.Or) and value:
                    break
            pending.extend(reversed(evaluated_operands))
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(current))))
    return nodes


def _deterministically_executed_expression_calls(
    node: ast.AST | None, *, eager_generator_consumers: dict[str, str] | None = None
) -> list[ast.Call]:
    return [
        child
        for child in _deterministically_executed_expression_nodes(
            node, eager_generator_consumers=eager_generator_consumers
        )
        if isinstance(child, ast.Call)
    ]


def _deterministically_evaluated_statement_expressions(
    statement: ast.stmt, *, evaluate_annotations: bool = True
) -> list[ast.AST]:
    if isinstance(statement, (ast.Assign, ast.AugAssign, ast.Expr)):
        return [statement.value]
    if isinstance(statement, ast.AnnAssign):
        return [
            *([statement.annotation] if evaluate_annotations else []),
            *([statement.value] if statement.value is not None else []),
        ]
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        parameters = [
            *statement.args.posonlyargs,
            *statement.args.args,
            *statement.args.kwonlyargs,
            *([statement.args.vararg] if statement.args.vararg is not None else []),
            *([statement.args.kwarg] if statement.args.kwarg is not None else []),
        ]
        return [
            *statement.decorator_list,
            *statement.args.defaults,
            *[value for value in statement.args.kw_defaults if value is not None],
            *(
                [argument.annotation for argument in parameters if argument.annotation is not None]
                if evaluate_annotations
                else []
            ),
            *([statement.returns] if evaluate_annotations and statement.returns is not None else []),
        ]
    if isinstance(statement, ast.ClassDef):
        return [*statement.decorator_list, *statement.bases, *[keyword.value for keyword in statement.keywords]]
    if isinstance(statement, (ast.If, ast.While)):
        return [statement.test]
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return [statement.iter]
    if isinstance(statement, ast.Raise):
        return [
            *([statement.exc] if statement.exc is not None else []),
            *([statement.cause] if statement.cause is not None else []),
        ]
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return [item.context_expr for item in statement.items]
    if isinstance(statement, ast.Match):
        expressions: list[ast.AST] = [statement.subject]
        try:
            subject = ast.literal_eval(statement.subject)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            subject = None
            subject_is_known = False
        else:
            subject_is_known = True
        for case in statement.cases:
            pattern = case.pattern
            matches = False
            if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
                matches = True
            elif not subject_is_known:
                return expressions
            elif isinstance(pattern, ast.MatchValue):
                try:
                    matches = subject == ast.literal_eval(pattern.value)
                except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                    return expressions
            elif isinstance(pattern, ast.MatchSingleton):
                matches = subject is pattern.value
            else:
                return expressions
            if not matches:
                continue
            if case.guard is not None:
                expressions.append(case.guard)
                guard_value = _static_late_truth_value(case.guard)
                if guard_value is False:
                    continue
                if guard_value is None:
                    return expressions
            break
        return expressions
    return []


def _deterministically_executed_statements(statements: list[ast.stmt]) -> list[ast.stmt]:
    executed: list[ast.stmt] = []
    for statement in statements:
        executed.append(statement)
        if isinstance(statement, ast.ClassDef):
            executed.extend(_deterministically_executed_statements(statement.body))
        elif isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant):
            branch = statement.body if bool(statement.test.value) else statement.orelse
            executed.extend(_deterministically_executed_statements(branch))
        elif isinstance(statement, ast.Try):
            executed.extend(_deterministically_executed_statements(statement.finalbody))
    return executed


def _statement_has_uncertain_expression_execution(
    statement: bytes,
    *,
    evaluate_annotations: bool = True,
    eager_generator_consumers: dict[str, str] | None = None,
) -> bool:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return True

    def contains_conditional_member_write(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Call)
            and (
                _simple_reference_name(child.func) in {"setattr", "builtins.setattr"}
                or (isinstance(child.func, ast.Attribute) and child.func.attr in {"__setitem__", "update"})
            )
            for child in ast.walk(node)
        )

    pending = [
        value
        for executed_statement in _deterministically_executed_statements(tree.body)
        for value in _deterministically_evaluated_statement_expressions(
            executed_statement, evaluate_annotations=evaluate_annotations
        )
    ]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.Lambda):
            pending.extend(
                [*current.args.defaults, *[value for value in current.args.kw_defaults if value is not None]]
            )
            continue
        if isinstance(current, ast.GeneratorExp):
            if current.generators:
                pending.append(current.generators[0].iter)
            continue
        if isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp)) and current.generators:
            for generator in current.generators:
                if _static_late_iter_truth(generator.iter) is not True:
                    return True
                if any(_static_late_truth_value(condition) is not True for condition in generator.ifs):
                    return True
            pending.extend(reversed(list(ast.iter_child_nodes(current))))
            continue
        if isinstance(current, ast.IfExp):
            if _static_late_truth_value(current.test) is None and (
                contains_conditional_member_write(current.body) or contains_conditional_member_write(current.orelse)
            ):
                return True
        elif isinstance(current, ast.BoolOp):
            for index, operand in enumerate(current.values[:-1]):
                if _static_late_truth_value(operand) is None and any(
                    contains_conditional_member_write(candidate) for candidate in current.values[index + 1 :]
                ):
                    return True
        elif isinstance(current, ast.Compare):
            prior = current.left
            for index, (operator, comparator) in enumerate(
                zip(current.ops[:-1], current.comparators[:-1], strict=True)
            ):
                comparison = _static_late_comparison_value(prior, operator, comparator)
                if comparison is None and any(
                    contains_conditional_member_write(candidate) for candidate in current.comparators[index + 1 :]
                ):
                    return True
                if comparison is False:
                    break
                prior = comparator
        elif (
            isinstance(current, ast.Call)
            and _eager_generator_consumer_name(current.func, eager_generator_consumers) is not None
        ):
            for argument in current.args:
                if isinstance(argument, ast.GeneratorExp):
                    for generator in argument.generators:
                        if _static_late_iter_truth(generator.iter) is not True or any(
                            _static_late_truth_value(condition) is not True for condition in generator.ifs
                        ):
                            return True
                    pending.append(argument.elt)
        pending.extend(reversed(list(ast.iter_child_nodes(current))))
    return False


def _statement_eager_generator_consumers(
    statement: bytes, *, eager_generator_consumers: dict[str, str] | None = None
) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return set()
    return {
        canonical_consumer
        for executed_statement in _deterministically_executed_statements(tree.body)
        for expression in _deterministically_evaluated_statement_expressions(executed_statement)
        for node in _deterministically_executed_expression_nodes(
            expression, eager_generator_consumers=eager_generator_consumers
        )
        if isinstance(node, ast.Call)
        and (canonical_consumer := _eager_generator_consumer_name(node.func, eager_generator_consumers)) is not None
        and any(isinstance(argument, ast.GeneratorExp) for argument in node.args)
    }


def _statement_executes_eager_generator_expression(
    statement: bytes, *, eager_generator_consumers: dict[str, str] | None = None
) -> bool:
    return bool(_statement_eager_generator_consumers(statement, eager_generator_consumers=eager_generator_consumers))


def _deterministically_executed_defined_names(statement: bytes, *, evaluate_annotations: bool = True) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return set()
    names: set[str] = set()
    for executed_statement in _deterministically_executed_statements(tree.body):
        if isinstance(executed_statement, ast.Assign):
            for target in executed_statement.targets:
                names.update(_assignment_target_names(target))
        elif isinstance(executed_statement, ast.AnnAssign):
            names.update(_assignment_target_names(executed_statement.target))
        elif isinstance(executed_statement, (ast.For, ast.AsyncFor)):
            if _static_late_iter_truth(executed_statement.iter) is not False:
                names.update(_assignment_target_names(executed_statement.target))
        elif isinstance(executed_statement, (ast.With, ast.AsyncWith)):
            for item in executed_statement.items:
                if item.optional_vars is not None:
                    names.update(_assignment_target_names(item.optional_vars))
        elif isinstance(executed_statement, ast.Match):
            for case in executed_statement.cases:
                pattern = case.pattern
                if not isinstance(pattern, ast.MatchAs) or pattern.pattern is not None:
                    break
                if pattern.name is not None:
                    names.add(pattern.name)
                if case.guard is None or _static_late_truth_value(case.guard) is not False:
                    break
        for value in _deterministically_evaluated_statement_expressions(
            executed_statement, evaluate_annotations=evaluate_annotations
        ):
            for expression_node in _deterministically_executed_expression_nodes(value):
                if isinstance(expression_node, ast.NamedExpr):
                    names.update(_assignment_target_names(expression_node.target))
    return names


def _simple_forwarded_alias_dependency_name(statement: bytes) -> str | None:
    assignment = _simple_forwarded_alias_assignment(statement)
    return assignment[1] if assignment is not None else None


def _simple_forwarded_alias_assignment(statement: bytes) -> tuple[str, str, bytes] | None:
    raw_statement = statement.rstrip()

    def parse_assignment(candidate: bytes) -> tuple[str, str, bytes] | None:
        match = re.fullmatch(
            rb"\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*(?:\(\s*)*"
            rb"((?P<root>[A-Za-z_]\w*)(?:\s*\.\s*[A-Za-z_]\w*)*)(?:\s*\))*\s*",
            candidate,
        )
        if match is None:
            return None
        return (
            match.group(1).decode("utf-8"),
            match.group("root").decode("utf-8"),
            match.group(2),
        )

    structural_statement = _python_structural_line_bytes(raw_statement).rstrip()
    while True:
        if structural_statement.endswith(b";"):
            structural_statement = structural_statement[:-1].rstrip()
            continue
        separator = structural_statement.rfind(b";")
        if separator < 0 or not _is_inert_forwarding_suffix(structural_statement[separator + 1 :].strip()):
            break
        structural_statement = structural_statement[:separator].rstrip()
    assignment = parse_assignment(structural_statement)
    if assignment is not None:
        return assignment
    separator = raw_statement.find(b";")
    if separator >= 0 and _is_inert_forwarding_suffix(raw_statement[separator + 1 :].strip()):
        return parse_assignment(raw_statement[:separator].rstrip())
    return None


_INERT_FORWARDING_TOKEN_PATTERN = re.compile(
    rb"\s*(?:"
    rb"None\b|True\b|False\b|not\b|\.\.\.|"
    rb"(?:[rRbBuU]{0,2})?(?:'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
    rb"(?:0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*|"
    rb"(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?[jJ]?)|"
    rb"[\(\)\[\]\{\},:;+\-~]"
    rb")"
)


def _is_inert_forwarding_suffix(suffix: bytes) -> bool:
    if suffix == b"pass":
        return True
    position = 0
    matched_token = False
    while position < len(suffix):
        token_match = _INERT_FORWARDING_TOKEN_PATTERN.match(suffix, position)
        if token_match is None:
            return False
        matched_token = True
        position = token_match.end()
    return matched_token


def _constant_late_binding_guard_value(
    candidate: bytes,
    line_start: int,
    line: bytes,
    enclosing_headers: list[tuple[bytes, int]] | None = None,
    exception_type_aliases: dict[str, str] | None = None,
) -> bool | None:
    if not line[:1].isspace():
        return True
    headers = (
        enclosing_headers
        if enclosing_headers is not None
        else _late_binding_enclosing_headers(candidate, line_start, line)
    )
    if not headers:
        return None
    for header, header_start in headers:
        if (header == b"try:" or header.startswith(b"for ")) and _suite_prefix_has_abrupt_exit(
            candidate, header_start, line_start, exception_type_aliases
        ):
            return False
    header_values = [
        _constant_late_header_value(candidate, header, header_start, exception_type_aliases)
        for header, header_start in headers
    ]
    if any(value is False for value in header_values):
        return False
    if all(value is True for value in header_values):
        return True
    return None


def _is_nested_late_state_statement(
    candidate: bytes,
    line_start: int,
    line: bytes,
    enclosing_headers: list[tuple[bytes, int]] | None = None,
) -> bool:
    return any(
        re.match(rb"\s*(?:async\s+def|def)\b", header) is not None
        for header, _header_start in (
            enclosing_headers
            if enclosing_headers is not None
            else _late_binding_enclosing_headers(candidate, line_start, line)
        )
    )


def _is_reachable_late_else_binding(
    candidate: bytes,
    line_start: int,
    line: bytes,
    enclosing_headers: list[tuple[bytes, int]] | None = None,
    exception_type_aliases: dict[str, str] | None = None,
) -> bool:
    return any(
        header == b"else:"
        and _constant_late_header_value(candidate, header, header_start, exception_type_aliases) is True
        for header, header_start in (
            enclosing_headers
            if enclosing_headers is not None
            else _late_binding_enclosing_headers(candidate, line_start, line)
        )
    )


def _constant_late_header_value(
    candidate: bytes, header: bytes, header_start: int, exception_type_aliases: dict[str, str] | None = None
) -> bool | None:
    header_line_end = candidate.find(b"\n", header_start)
    header_line_end = len(candidate) if header_line_end < 0 else header_line_end + 1
    raw_header = candidate[header_start:header_line_end].strip()
    guard_match = re.fullmatch(rb"(?:if|elif|while)\s+(.+?)\s*:\s*(?:#.*)?", raw_header)
    guard_value: bool | None = None
    if guard_match is not None:
        guard_source, _byte_offsets = _decode_utf8_with_byte_offsets(guard_match.group(1))
        try:
            guard_expression = ast.parse(guard_source, mode="eval").body
        except (SyntaxError, ValueError):
            guard_expression = None
        if guard_expression is not None:
            guard_value = _static_late_truth_value(guard_expression)
            if guard_value is None and isinstance(guard_expression, ast.Name):
                guard_value = _preceding_static_scalar_guard_value(candidate, header_start, guard_expression.id)
    if raw_header.startswith((b"if ", b"while ")):
        return guard_value
    if raw_header == b"try:":
        return True
    if raw_header == b"finally:":
        return True
    if raw_header.startswith(b"match "):
        return True
    if raw_header.startswith(b"for "):
        loop_source, _byte_offsets = _decode_utf8_with_byte_offsets(raw_header + b"\n    pass\n")
        try:
            loop_statement = ast.parse(loop_source).body[0]
        except (SyntaxError, ValueError):
            loop_statement = None
        if isinstance(loop_statement, ast.For) and _static_late_iter_truth(loop_statement.iter) is True:
            return True
    if raw_header.startswith(b"except"):
        outcome = _preceding_deterministic_try_outcome(candidate, header_start, exception_type_aliases)
        if outcome is None:
            return None
        outcome_type, exception_name = outcome
        if outcome_type != "exception":
            return False
        prior_handler_consumption = _preceding_handler_consumes_exception(
            candidate, header_start, exception_name, exception_type_aliases
        )
        if prior_handler_consumption is not False:
            return False if prior_handler_consumption is True else None
        return _deterministic_handler_catches_exception(raw_header, exception_name, exception_type_aliases)
    if header == b"else:":
        try_outcome = _preceding_deterministic_try_outcome(candidate, header_start, exception_type_aliases)
        if try_outcome is not None:
            return try_outcome[0] == "normal"
        loop_else = _preceding_literal_loop_else_value(candidate, header_start)
        if loop_else is not None:
            return loop_else
    if not raw_header.startswith(b"elif ") and header != b"else:":
        return None
    preceding_branches_false = _preceding_late_branch_guards_are_false(candidate, header_start)
    if raw_header.startswith(b"elif "):
        if guard_value is False or preceding_branches_false is False:
            return False
        if guard_value is True and preceding_branches_false is True:
            return True
        return None
    return preceding_branches_false


def _deterministic_abrupt_exception_name(code_line: bytes) -> str | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(code_line)
    try:
        statement = ast.parse(textwrap.dedent(source)).body[0]
    except (IndexError, RecursionError, SyntaxError, ValueError):
        return None
    if isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call):
        reference = _simple_reference_name(statement.exc.func)
        return reference.rsplit(".", 1)[-1] if reference is not None else None
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.BinOp)
        and isinstance(statement.value.op, (ast.Div, ast.FloorDiv, ast.Mod))
    ):
        try:
            denominator = ast.literal_eval(statement.value.right)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None
        if denominator == 0:
            return "ZeroDivisionError"
    return None


def _resolved_exception_name_before(candidate: bytes, offset: int, exception_name: str) -> str | None:
    resolved_name = exception_name
    known_exception_types = {
        name
        for name in dir(builtins)
        if isinstance((value := getattr(builtins, name)), type) and issubclass(value, BaseException)
    }
    source, _byte_offsets = _decode_utf8_with_byte_offsets(candidate[:offset].lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return exception_name
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or target.id != resolved_name:
            continue
        value_reference = _simple_reference_name(statement.value)
        if value_reference is None or value_reference.rsplit(".", 1)[-1] not in known_exception_types:
            return None
        resolved_name = value_reference.rsplit(".", 1)[-1]
    return resolved_name


def _deterministic_handler_catches_exception(
    raw_header: bytes, exception_name: str | None, exception_type_aliases: dict[str, str] | None = None
) -> bool | None:
    if exception_name is None:
        return None
    source, _byte_offsets = _decode_utf8_with_byte_offsets(b"try:\n    pass\n" + raw_header + b"\n    pass\n")
    try:
        statement = ast.parse(source).body[0]
    except (RecursionError, SyntaxError, ValueError):
        return None
    if not isinstance(statement, ast.Try) or not statement.handlers:
        return None
    exception_type = statement.handlers[0].type
    if exception_type is None:
        return True
    raised_type = getattr(builtins, exception_name, None)
    if not isinstance(raised_type, type) or not issubclass(raised_type, BaseException):
        return None

    def handled_type_matches(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Tuple):
            matches = [handled_type_matches(element) for element in node.elts]
            if any(match is True for match in matches):
                return True
            return False if all(match is False for match in matches) else None
        reference = _simple_reference_name(node)
        if reference is None:
            return None
        handled_name = (
            exception_type_aliases.get(reference)
            if exception_type_aliases is not None
            else reference.rsplit(".", 1)[-1]
        )
        if handled_name is None:
            return None
        handled_type = getattr(builtins, handled_name, None)
        if not isinstance(handled_type, type) or not issubclass(handled_type, BaseException):
            return None
        return issubclass(raised_type, handled_type)

    return handled_type_matches(exception_type)


def _preceding_handler_consumes_exception(
    candidate: bytes,
    header_start: int,
    exception_name: str | None,
    exception_type_aliases: dict[str, str] | None = None,
) -> bool | None:
    header_line = candidate[header_start : _line_end_offset(candidate, header_start)]
    header_indent = _line_indent_width(header_line)
    cursor = header_start
    preceding_handlers: list[bytes] = []
    while cursor > 0 and header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line:
            continue
        indent = _line_indent_width(previous_line)
        if indent < header_indent:
            return None
        if indent != header_indent:
            continue
        if structural_line == b"try:":
            break
        if structural_line.startswith(b"except"):
            preceding_handlers.append(structural_line)
            continue
        if not structural_line.startswith((b"else:", b"finally:")):
            return None
    for preceding_header in reversed(preceding_handlers):
        catches = _deterministic_handler_catches_exception(preceding_header, exception_name, exception_type_aliases)
        if catches is not False:
            return catches
    return False


def _preceding_deterministic_try_outcome(
    candidate: bytes, header_start: int, exception_type_aliases: dict[str, str] | None = None
) -> tuple[str, str | None] | None:
    header_line = candidate[header_start : _line_end_offset(candidate, header_start)]
    header_indent = _line_indent_width(header_line)
    cursor = header_start
    try_start: int | None = None
    while cursor > 0 and header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line:
            continue
        indent = _line_indent_width(previous_line)
        if indent < header_indent:
            return None
        if indent == header_indent:
            if structural_line == b"try:":
                try_start = previous_start
                break
            if not structural_line.startswith((b"except", b"else:", b"finally:")):
                return None
    if try_start is None:
        return None
    cursor = _line_end_offset(candidate, try_start)
    body_indent: int | None = None
    while cursor < header_start:
        statement_end = _line_end_offset(candidate, cursor)
        line = candidate[cursor:statement_end]
        cursor = statement_end
        structural_line = _python_structural_line_bytes(line).strip()
        if not structural_line:
            continue
        indent = _line_indent_width(line)
        if indent <= header_indent:
            break
        body_indent = indent if body_indent is None else body_indent
        if indent != body_indent:
            return None
        if structural_line == b"pass":
            continue
        exception_name = _deterministic_abrupt_exception_name(structural_line)
        if exception_name is not None:
            return (
                "exception",
                exception_type_aliases.get(exception_name)
                if exception_type_aliases is not None
                else _resolved_exception_name_before(candidate, try_start, exception_name),
            )
        return None
    return ("normal", None) if body_indent is not None else None


def _preceding_literal_loop_else_value(candidate: bytes, header_start: int) -> bool | None:
    header_line = candidate[header_start : _line_end_offset(candidate, header_start)]
    header_indent = _line_indent_width(header_line)
    cursor = header_start
    while cursor > 0 and header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        indent = _line_indent_width(previous_line)
        if not structural_line:
            continue
        if indent < header_indent:
            return None
        if indent == header_indent and structural_line.startswith(b"for "):
            loop_source, _byte_offsets = _decode_utf8_with_byte_offsets(structural_line + b"\n    pass\n")
            try:
                loop_statement = ast.parse(loop_source).body[0]
            except (SyntaxError, ValueError):
                return None
            if not isinstance(loop_statement, ast.For) or _static_late_iter_truth(loop_statement.iter) is None:
                return None
            loop_body = candidate[_line_end_offset(candidate, previous_start) : header_start]
            return None if re.search(rb"(?m)^\s*break\b", loop_body) is not None else True
        if indent == header_indent:
            return None
    return None


def _nested_exception_is_caught_before(
    candidate: bytes,
    abrupt_start: int,
    line_start: int,
    abrupt_headers: list[tuple[bytes, int]],
    exception_type_aliases: dict[str, str] | None = None,
) -> bool:
    exception_name = _deterministic_abrupt_exception_name(
        _python_structural_line_bytes(candidate[abrupt_start : _line_end_offset(candidate, abrupt_start)]).strip()
    )
    if exception_name is None:
        return False
    try_headers = [(header, start) for header, start in abrupt_headers if header == b"try:"]
    if not try_headers:
        return False
    _header, try_start = try_headers[0]
    try_indent = _line_indent_width(candidate[try_start : _line_end_offset(candidate, try_start)])
    cursor = _line_end_offset(candidate, abrupt_start)
    while cursor < line_start:
        statement_end = _line_end_offset(candidate, cursor)
        structural_line = _python_structural_line_bytes(candidate[cursor:statement_end]).strip()
        indent = _line_indent_width(candidate[cursor:statement_end])
        cursor = statement_end
        if indent != try_indent or not structural_line.startswith(b"except"):
            continue
        catches = _deterministic_handler_catches_exception(
            structural_line,
            exception_type_aliases.get(exception_name, exception_name)
            if exception_type_aliases is not None
            else exception_name,
            exception_type_aliases,
        )
        if catches is True:
            return True
        if catches is None:
            return False
    return False


def _suite_prefix_has_abrupt_exit(
    candidate: bytes,
    header_start: int,
    line_start: int,
    exception_type_aliases: dict[str, str] | None = None,
) -> bool:
    cursor = _line_end_offset(candidate, header_start)
    statement_indent = _line_indent_width(candidate[line_start : _line_end_offset(candidate, line_start)])
    while cursor < line_start:
        statement_end = _line_end_offset(candidate, cursor)
        prior_line = candidate[cursor:statement_end]
        structural_line = _python_structural_line_bytes(prior_line).strip()
        prior_indent = _line_indent_width(prior_line)
        definitely_abrupt = (
            structural_line.startswith((b"raise", b"return", b"break", b"continue"))
            or _deterministic_abrupt_exception_name(structural_line) is not None
        )
        if prior_indent == statement_indent and definitely_abrupt:
            return True
        if prior_indent > statement_indent and definitely_abrupt:
            abrupt_headers = [
                (header, start)
                for header, start in _late_binding_enclosing_headers(candidate, cursor, prior_line)
                if start >= header_start
            ]
            if (
                abrupt_headers
                and not _nested_exception_is_caught_before(
                    candidate, cursor, line_start, abrupt_headers, exception_type_aliases
                )
                and all(
                    _constant_late_header_value(candidate, header, start, exception_type_aliases) is True
                    for header, start in abrupt_headers
                )
            ):
                return True
        cursor = statement_end
    return False


def _preceding_late_branch_guards_are_false(candidate: bytes, header_start: int) -> bool | None:
    header_line_end = candidate.find(b"\n", header_start)
    header_line_end = len(candidate) if header_line_end < 0 else header_line_end + 1
    header_line = candidate[header_start:header_line_end]
    header_indent = len(header_line) - len(header_line.lstrip())
    cursor = header_start
    unknown_guard = False
    while cursor > 0 and header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line:
            continue
        previous_indent = len(previous_line) - len(previous_line.lstrip())
        if previous_indent != header_indent:
            continue
        if not structural_line.startswith((b"if ", b"elif ")):
            return None
        guard_line_end = candidate.find(b"\n", previous_start)
        guard_line_end = len(candidate) if guard_line_end < 0 else guard_line_end + 1
        raw_guard = candidate[previous_start:guard_line_end].strip()
        guard_match = re.fullmatch(rb"(?:if|elif)\s+(.+?)\s*:\s*(?:#.*)?", raw_guard)
        if guard_match is None:
            return None
        guard_source, _byte_offsets = _decode_utf8_with_byte_offsets(guard_match.group(1))
        try:
            expression = ast.parse(guard_source, mode="eval").body
        except (SyntaxError, ValueError):
            expression = None
        if not isinstance(expression, ast.Constant):
            unknown_guard = True
        elif bool(expression.value):
            return False
        if structural_line.startswith(b"if "):
            return None if unknown_guard else True
    return None


def _late_binding_statement_start(
    candidate: bytes,
    line_start: int,
    line: bytes,
    enclosing_headers: list[tuple[bytes, int]] | None = None,
    skip_class_header: bool = False,
) -> int:
    headers = (
        enclosing_headers
        if enclosing_headers is not None
        else _late_binding_enclosing_headers(candidate, line_start, line)
    )
    if not skip_class_header:
        return headers[-1][1] if headers else line_start
    for header, header_start in reversed(headers):
        if re.match(rb"\s*class\b", header) is None:
            return header_start
    return line_start


def _is_exhaustive_safe_late_binding(candidate: bytes, line_start: int, line: bytes, binding_name: str) -> bool:
    headers = _late_binding_enclosing_headers(candidate, line_start, line)
    if not headers:
        return False
    current_header, current_header_start = headers[0]
    if not current_header.startswith((b"elif ", b"else:")):
        return False
    header_line_end = candidate.find(b"\n", current_header_start)
    header_line_end = len(candidate) if header_line_end < 0 else header_line_end + 1
    header_line = candidate[current_header_start:header_line_end]
    header_indent = len(header_line) - len(header_line.lstrip())
    chain_start = current_header_start
    cursor = current_header_start
    while cursor > 0 and current_header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line:
            continue
        previous_indent = len(previous_line) - len(previous_line.lstrip())
        if previous_indent != header_indent:
            continue
        if structural_line.startswith(b"elif "):
            chain_start = previous_start
            continue
        if structural_line.startswith(b"if "):
            chain_start = previous_start
            break
        return False
    if chain_start == current_header_start:
        return False
    preceding_context = candidate[max(0, chain_start - _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES) : chain_start]
    if any(
        _simple_late_binding_name(_python_structural_line_bytes(previous_line)) == "print"
        for previous_line in preceding_context.splitlines(keepends=True)
    ):
        return False
    source, _byte_offsets = _decode_utf8_with_byte_offsets(candidate[chain_start : line_start + len(line)])
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return False
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.If):
        return False

    def body_assigns_print(body: list[ast.stmt]) -> bool:
        for index in range(len(body) - 1, -1, -1):
            statement = body[index]
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if binding_name not in {name for target in targets for name in _assignment_target_names(target)}:
                continue
            return (
                isinstance(statement.value, ast.Name)
                and statement.value.id == "print"
                and all(isinstance(trailing, ast.Pass) for trailing in body[index + 1 :])
            )
        return False

    def exhaustive_safe_if(statement: ast.If) -> bool:
        if not body_assigns_print(statement.body):
            return False
        if isinstance(statement.test, ast.Constant) and bool(statement.test.value):
            return True
        if len(statement.orelse) == 1 and isinstance(statement.orelse[0], ast.If):
            return exhaustive_safe_if(statement.orelse[0])
        return bool(statement.orelse) and body_assigns_print(statement.orelse)

    return exhaustive_safe_if(tree.body[0])


def _is_exhaustive_noncanonical_helper_late_binding(
    candidate: bytes, line_start: int, line: bytes, binding_name: str
) -> bool:
    headers = _late_binding_enclosing_headers(candidate, line_start, line)
    if not headers:
        return False
    current_header, current_header_start = headers[0]
    if not current_header.startswith((b"elif ", b"else:")):
        return False
    header_line_end = candidate.find(b"\n", current_header_start)
    header_line_end = len(candidate) if header_line_end < 0 else header_line_end + 1
    header_line = candidate[current_header_start:header_line_end]
    header_indent = len(header_line) - len(header_line.lstrip())
    chain_start = current_header_start
    cursor = current_header_start
    while cursor > 0 and current_header_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line:
            continue
        previous_indent = len(previous_line) - len(previous_line.lstrip())
        if previous_indent != header_indent:
            continue
        if structural_line.startswith(b"elif "):
            chain_start = previous_start
            continue
        if structural_line.startswith(b"if "):
            chain_start = previous_start
            break
        return False
    if chain_start == current_header_start:
        return False
    source, _byte_offsets = _decode_utf8_with_byte_offsets(candidate[chain_start : line_start + len(line)])
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return False
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.If):
        return False

    def body_assigns_noncanonical_helper(body: list[ast.stmt]) -> bool:
        for index in range(len(body) - 1, -1, -1):
            statement = body[index]
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if binding_name not in {name for target in targets for name in _assignment_target_names(target)}:
                continue
            return isinstance(statement.value, ast.Lambda) and all(
                isinstance(trailing, ast.Pass) for trailing in body[index + 1 :]
            )
        return False

    def exhaustive_noncanonical_if(statement: ast.If) -> bool:
        if not body_assigns_noncanonical_helper(statement.body):
            return False
        if isinstance(statement.test, ast.Constant) and bool(statement.test.value):
            return True
        if len(statement.orelse) == 1 and isinstance(statement.orelse[0], ast.If):
            return exhaustive_noncanonical_if(statement.orelse[0])
        return bool(statement.orelse) and body_assigns_noncanonical_helper(statement.orelse)

    return exhaustive_noncanonical_if(tree.body[0])


def _late_binding_enclosing_headers(candidate: bytes, line_start: int, line: bytes) -> list[tuple[bytes, int]]:
    if not line[:1].isspace():
        return []
    headers: list[tuple[bytes, int]] = []
    line_indent = len(line) - len(line.lstrip())
    cursor = line_start
    while cursor > 0 and line_start - cursor < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES:
        previous_start = candidate.rfind(b"\n", 0, max(0, cursor - 1)) + 1
        previous_line = candidate[previous_start:cursor]
        cursor = previous_start
        structural_line = _python_structural_line_bytes(previous_line).strip()
        if not structural_line:
            continue
        previous_indent = len(previous_line) - len(previous_line.lstrip())
        if previous_indent >= line_indent:
            continue
        if structural_line.endswith(b":"):
            headers.append((structural_line, previous_start))
            line_indent = previous_indent
            continue
        break
    return headers


def _definite_late_shadow_name(line: bytes, code_line: bytes) -> str | None:
    if line[:1].isspace():
        return None
    match = re.match(rb"\s*(?:class|def|async\s+def)\s+([A-Za-z_]\w*)\b", code_line)
    if match is None:
        match = re.fullmatch(rb"\s*del\s+([A-Za-z_]\w*)\s*", code_line)
    return match.group(1).decode("utf-8") if match is not None else None


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


def _is_inert_scalar_late_binding(code_line: bytes) -> bool:
    return (
        re.fullmatch(
            rb"\s*[A-Za-z_]\w*\s*(?::[^=\n]+)?=\s*(?:None|True|False|[-+]?(?:\d+(?:\.\d*)?|\.\d+))\s*",
            code_line,
        )
        is not None
    )


def _python_identifier_names(statement: bytes) -> set[str]:
    return {identifier.decode("utf-8") for identifier in re.findall(rb"\b[A-Za-z_]\w*\b", statement)}


def _simple_late_assignment_value_reference(statement: bytes) -> str | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    if len(tree.body) != 1:
        return None
    assignment = tree.body[0]
    if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1:
        return _simple_reference_name(assignment.value)
    if isinstance(assignment, ast.AnnAssign) and assignment.value is not None:
        return _simple_reference_name(assignment.value)
    return None


def _builtin_dict_attribute_write_state(
    line: bytes,
    builtins_alias_names: set[str],
    builtin_dict_descriptor_aliases: set[str],
    shadowed_descriptor_names: set[str],
    builtin_dict_mapping_aliases: set[str],
    uncertain_builtin_dict_mapping_aliases: set[str],
    builtin_dict_mapping_update_aliases: set[str],
    uncertain_builtin_dict_mapping_update_aliases: set[str],
    builtin_dict_mapping_setitem_aliases: set[str],
    uncertain_builtin_dict_mapping_setitem_aliases: set[str],
    builtin_dict_descriptor_setitem_aliases: set[str],
    shadowed_builtin_helper_names: set[str],
    canonical_builtin_helper_aliases: dict[str, str],
    uncertain_canonical_builtin_helper_aliases: set[str],
) -> tuple[bool, bool] | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(line.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None

    def resolves_builtin_descriptor(value: ast.AST) -> bool:
        reference = _simple_reference_name(value)
        return reference in builtin_dict_descriptor_aliases or (
            reference is not None
            and reference.endswith(".dict")
            and reference.removesuffix(".dict") in builtins_alias_names
            and "builtins.dict" not in shadowed_descriptor_names
        )

    def is_builtins_mapping(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (
            (isinstance(node, ast.Name) and node.id in builtin_dict_mapping_aliases)
            or (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in builtins_alias_names
            )
            or (
                isinstance(node, ast.Call)
                and canonical_builtin_helper_aliases.get(helper_reference or "") == "vars"
                and helper_reference not in shadowed_builtin_helper_names
                and ("." not in (helper_reference or "") or "builtins.vars" not in shadowed_builtin_helper_names)
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in builtins_alias_names
            )
        )

    def mapping_is_uncertain(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (isinstance(node, ast.Name) and node.id in uncertain_builtin_dict_mapping_aliases) or (
            isinstance(node, ast.Call) and helper_reference in uncertain_canonical_builtin_helper_aliases
        )

    for statement in tree.body:
        targets: tuple[ast.AST, ...] = ()
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign):
            targets = tuple(statement.targets)
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = (statement.target,)
            value = statement.value
        if value is not None:
            for target in targets:
                is_attribute_target = (
                    isinstance(target, ast.Attribute)
                    and target.attr == "dict"
                    and isinstance(target.value, ast.Name)
                    and target.value.id in builtins_alias_names
                )
                is_mapping_target = (
                    isinstance(target, ast.Subscript)
                    and _static_getattr_member_name(target.slice) == "dict"
                    and is_builtins_mapping(target.value)
                )
                if not (is_attribute_target or is_mapping_target):
                    continue
                uncertain_write = isinstance(target, ast.Subscript) and mapping_is_uncertain(target.value)
                return resolves_builtin_descriptor(value), uncertain_write
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if (
                node.func.attr == "__setitem__"
                and is_builtins_mapping(node.func.value)
                and len(node.args) >= 2
                and _static_getattr_member_name(node.args[0]) == "dict"
            ):
                return resolves_builtin_descriptor(node.args[1]), mapping_is_uncertain(node.func.value)
            descriptor_name = _static_builtin_dict_descriptor_name(
                node.func.value,
                builtins_alias_names,
                builtin_dict_descriptor_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            is_descriptor_setitem = (
                node.func.attr == "__setitem__"
                and descriptor_name is not None
                and descriptor_name not in shadowed_descriptor_names
                and len(node.args) >= 3
                and is_builtins_mapping(node.args[0])
                and _static_getattr_member_name(node.args[1]) == "dict"
            )
            if is_descriptor_setitem:
                return resolves_builtin_descriptor(node.args[2]), mapping_is_uncertain(node.args[0])
            is_mapping_update = node.func.attr == "update" and is_builtins_mapping(node.func.value)
            if not is_mapping_update:
                continue
            for keyword in node.keywords:
                if keyword.arg == "dict":
                    return resolves_builtin_descriptor(keyword.value), mapping_is_uncertain(node.func.value)
                if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                    for key, update_value in zip(keyword.value.keys, keyword.value.values, strict=True):
                        if key is not None and _static_getattr_member_name(key) == "dict":
                            return resolves_builtin_descriptor(update_value), mapping_is_uncertain(node.func.value)
            for argument in node.args:
                if isinstance(argument, ast.Dict):
                    for key, update_value in zip(argument.keys, argument.values, strict=True):
                        if key is not None and _static_getattr_member_name(key) == "dict":
                            return resolves_builtin_descriptor(update_value), mapping_is_uncertain(node.func.value)
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id in builtin_dict_mapping_setitem_aliases:
                if len(node.args) >= 2 and _static_getattr_member_name(node.args[0]) == "dict":
                    return (
                        resolves_builtin_descriptor(node.args[1]),
                        node.func.id in uncertain_builtin_dict_mapping_setitem_aliases,
                    )
            elif node.func.id in builtin_dict_descriptor_setitem_aliases:
                if (
                    len(node.args) >= 3
                    and is_builtins_mapping(node.args[0])
                    and _static_getattr_member_name(node.args[1]) == "dict"
                ):
                    return resolves_builtin_descriptor(node.args[2]), mapping_is_uncertain(node.args[0])
            elif node.func.id in builtin_dict_mapping_update_aliases:
                for keyword in node.keywords:
                    if keyword.arg == "dict":
                        return (
                            resolves_builtin_descriptor(keyword.value),
                            node.func.id in uncertain_builtin_dict_mapping_update_aliases,
                        )
                    if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                        for key, update_value in zip(keyword.value.keys, keyword.value.values, strict=True):
                            if key is not None and _static_getattr_member_name(key) == "dict":
                                return (
                                    resolves_builtin_descriptor(update_value),
                                    node.func.id in uncertain_builtin_dict_mapping_update_aliases,
                                )
                for argument in node.args:
                    if isinstance(argument, ast.Dict):
                        for key, update_value in zip(argument.keys, argument.values, strict=True):
                            if key is not None and _static_getattr_member_name(key) == "dict":
                                return (
                                    resolves_builtin_descriptor(update_value),
                                    node.func.id in uncertain_builtin_dict_mapping_update_aliases,
                                )
    return None


def _builtin_helper_attribute_write_state(
    statement: bytes,
    builtins_alias_names: set[str],
    builtin_dict_mapping_aliases: set[str],
    uncertain_builtin_dict_mapping_aliases: set[str],
    builtin_dict_mapping_update_aliases: set[str],
    uncertain_builtin_dict_mapping_update_aliases: set[str],
    builtin_dict_mapping_setitem_aliases: set[str],
    uncertain_builtin_dict_mapping_setitem_aliases: set[str],
    builtin_dict_descriptor_aliases: set[str],
    shadowed_descriptor_names: set[str],
    shadowed_builtin_helper_names: set[str],
    uncertain_builtin_helper_names: set[str],
    canonical_builtin_helper_aliases: dict[str, str],
    uncertain_canonical_builtin_helper_aliases: set[str],
    *,
    evaluate_annotations: bool = True,
) -> tuple[str, bool, bool] | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return None

    def helper_name(node: ast.AST) -> str | None:
        name = _static_getattr_member_name(node)
        return name if name in {"getattr", "vars", "setattr", "delattr"} else None

    def is_builtins_mapping(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (
            (isinstance(node, ast.Name) and node.id in builtin_dict_mapping_aliases)
            or (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in builtins_alias_names
            )
            or (
                isinstance(node, ast.Call)
                and canonical_builtin_helper_aliases.get(helper_reference or "") == "vars"
                and helper_reference not in shadowed_builtin_helper_names
                and ("." not in (helper_reference or "") or "builtins.vars" not in shadowed_builtin_helper_names)
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in builtins_alias_names
            )
        )

    def reference_is_uncertain(reference: str | None, helper_name: str) -> bool:
        return reference in uncertain_builtin_helper_names | uncertain_canonical_builtin_helper_aliases or (
            "." in (reference or "") and f"builtins.{helper_name}" in uncertain_builtin_helper_names
        )

    def mapping_is_uncertain(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (isinstance(node, ast.Name) and node.id in uncertain_builtin_dict_mapping_aliases) or (
            isinstance(node, ast.Call) and reference_is_uncertain(helper_reference, "vars")
        )

    def is_canonical_helper(value: ast.AST, target_helper: str) -> tuple[bool, bool]:
        reference = _simple_reference_name(value)
        if (
            canonical_builtin_helper_aliases.get(reference or "") != target_helper
            or reference in shadowed_builtin_helper_names
            or ("." in (reference or "") and f"builtins.{target_helper}" in shadowed_builtin_helper_names)
        ):
            return False, False
        return True, reference_is_uncertain(reference, target_helper)

    def write_result(
        target_helper: str, value: ast.AST | None = None, *, operation_is_uncertain: bool = False
    ) -> tuple[str, bool, bool]:
        if value is None:
            return target_helper, False, operation_is_uncertain
        restores_helper, value_is_uncertain = is_canonical_helper(value, target_helper)
        return target_helper, restores_helper, operation_is_uncertain or value_is_uncertain

    for executed_statement in _deterministically_executed_statements(tree.body):
        if (
            isinstance(executed_statement, ast.AugAssign)
            and isinstance(executed_statement.op, ast.BitOr)
            and is_builtins_mapping(executed_statement.target)
            and isinstance(executed_statement.value, ast.Dict)
        ):
            for key in executed_statement.value.keys:
                if key is not None and (updated_helper := helper_name(key)) is not None:
                    return write_result(
                        updated_helper, operation_is_uncertain=mapping_is_uncertain(executed_statement.target)
                    )
        if (
            isinstance(executed_statement, (ast.For, ast.AsyncFor))
            and _static_late_iter_truth(executed_statement.iter) is not False
        ):
            target_nodes = [executed_statement.target]
        elif isinstance(executed_statement, (ast.With, ast.AsyncWith)):
            target_nodes = [item.optional_vars for item in executed_statement.items if item.optional_vars is not None]
        else:
            target_nodes = []
        for target in target_nodes:
            for nested_target in ast.walk(target):
                if (
                    isinstance(nested_target, ast.Attribute)
                    and nested_target.attr in {"getattr", "vars", "setattr", "delattr"}
                    and isinstance(nested_target.value, ast.Name)
                    and nested_target.value.id in builtins_alias_names
                ):
                    return write_result(nested_target.attr)
                if isinstance(nested_target, ast.Subscript) and is_builtins_mapping(nested_target.value):
                    nested_helper = helper_name(nested_target.slice)
                    if nested_helper is not None:
                        return write_result(
                            nested_helper, operation_is_uncertain=mapping_is_uncertain(nested_target.value)
                        )
        if not isinstance(executed_statement, (ast.Assign, ast.AnnAssign)) or executed_statement.value is None:
            continue
        targets = (
            executed_statement.targets if isinstance(executed_statement, ast.Assign) else [executed_statement.target]
        )
        for target in targets:
            target_helper: str | None = None
            if (
                isinstance(target, ast.Attribute)
                and target.attr in {"getattr", "vars", "setattr", "delattr"}
                and isinstance(target.value, ast.Name)
                and target.value.id in builtins_alias_names
            ):
                target_helper = target.attr
            elif isinstance(target, ast.Subscript) and is_builtins_mapping(target.value):
                target_helper = helper_name(target.slice)
            if target_helper is not None:
                return write_result(
                    target_helper,
                    executed_statement.value,
                    operation_is_uncertain=isinstance(target, ast.Subscript) and mapping_is_uncertain(target.value),
                )
            if isinstance(target, (ast.Tuple, ast.List)):
                for nested_target in ast.walk(target):
                    if (
                        isinstance(nested_target, ast.Attribute)
                        and nested_target.attr in {"getattr", "vars", "setattr", "delattr"}
                        and isinstance(nested_target.value, ast.Name)
                        and nested_target.value.id in builtins_alias_names
                    ):
                        return write_result(nested_target.attr)
                    if isinstance(nested_target, ast.Subscript) and is_builtins_mapping(nested_target.value):
                        nested_helper = helper_name(nested_target.slice)
                        if nested_helper is not None:
                            return write_result(
                                nested_helper, operation_is_uncertain=mapping_is_uncertain(nested_target.value)
                            )
    for statement_node in _deterministically_executed_statements(tree.body):
        for value in _deterministically_evaluated_statement_expressions(
            statement_node, evaluate_annotations=evaluate_annotations
        ):
            for call in _deterministically_executed_expression_calls(value):
                helper_reference = _simple_reference_name(call.func)
                if (
                    canonical_builtin_helper_aliases.get(helper_reference or "") == "setattr"
                    and helper_reference not in shadowed_builtin_helper_names
                    and ("." not in (helper_reference or "") or "builtins.setattr" not in shadowed_builtin_helper_names)
                    and len(call.args) >= 3
                    and isinstance(call.args[0], ast.Name)
                    and call.args[0].id in builtins_alias_names
                    and (target_helper := helper_name(call.args[1])) is not None
                ):
                    return write_result(
                        target_helper,
                        call.args[2],
                        operation_is_uncertain=reference_is_uncertain(helper_reference, "setattr"),
                    )
                if not isinstance(call.func, ast.Attribute):
                    mapping_method = None
                    mapping_arguments = call.args
                    mapping_operation_is_uncertain = False
                else:
                    mapping_method = call.func.attr
                    mapping_arguments = call.args
                    targets_mapping = is_builtins_mapping(call.func.value)
                    mapping_operation_is_uncertain = mapping_is_uncertain(call.func.value)
                    descriptor_reference = _simple_reference_name(call.func.value)
                    if (
                        not targets_mapping
                        and descriptor_reference in builtin_dict_descriptor_aliases
                        and descriptor_reference not in shadowed_descriptor_names
                        and call.args
                        and is_builtins_mapping(call.args[0])
                    ):
                        targets_mapping = True
                        mapping_arguments = call.args[1:]
                        mapping_operation_is_uncertain = mapping_is_uncertain(call.args[0])
                    if not targets_mapping:
                        mapping_method = None
                if (
                    mapping_method == "__setitem__"
                    and len(mapping_arguments) >= 2
                    and (target_helper := helper_name(mapping_arguments[0])) is not None
                ):
                    return write_result(
                        target_helper, mapping_arguments[1], operation_is_uncertain=mapping_operation_is_uncertain
                    )
                if mapping_method != "update":
                    continue
                for keyword in call.keywords:
                    if keyword.arg in {"getattr", "vars", "setattr", "delattr"}:
                        return write_result(
                            keyword.arg, keyword.value, operation_is_uncertain=mapping_operation_is_uncertain
                        )
                    if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                        for key, update_value in zip(keyword.value.keys, keyword.value.values, strict=True):
                            if key is not None and (target_helper := helper_name(key)) is not None:
                                return write_result(
                                    target_helper, update_value, operation_is_uncertain=mapping_operation_is_uncertain
                                )
                for argument in mapping_arguments:
                    if isinstance(argument, ast.Dict):
                        for key, update_value in zip(argument.keys, argument.values, strict=True):
                            if key is not None and (target_helper := helper_name(key)) is not None:
                                return write_result(
                                    target_helper, update_value, operation_is_uncertain=mapping_operation_is_uncertain
                                )
            for call in _deterministically_executed_expression_calls(value):
                if not isinstance(call.func, ast.Name):
                    continue
                if call.func.id in builtin_dict_mapping_setitem_aliases:
                    if len(call.args) >= 2 and (target_helper := helper_name(call.args[0])) is not None:
                        return write_result(
                            target_helper,
                            call.args[1],
                            operation_is_uncertain=call.func.id in uncertain_builtin_dict_mapping_setitem_aliases,
                        )
                elif call.func.id in builtin_dict_mapping_update_aliases:
                    mapping_operation_is_uncertain = call.func.id in uncertain_builtin_dict_mapping_update_aliases
                    for keyword in call.keywords:
                        if keyword.arg in {"getattr", "vars", "setattr", "delattr"}:
                            return write_result(
                                keyword.arg, keyword.value, operation_is_uncertain=mapping_operation_is_uncertain
                            )
                        if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                            for key, update_value in zip(keyword.value.keys, keyword.value.values, strict=True):
                                if key is not None and (target_helper := helper_name(key)) is not None:
                                    return write_result(
                                        target_helper,
                                        update_value,
                                        operation_is_uncertain=mapping_operation_is_uncertain,
                                    )
                    for argument in call.args:
                        if isinstance(argument, ast.Dict):
                            for key, update_value in zip(argument.keys, argument.values, strict=True):
                                if key is not None and (target_helper := helper_name(key)) is not None:
                                    return write_result(
                                        target_helper,
                                        update_value,
                                        operation_is_uncertain=mapping_operation_is_uncertain,
                                    )
    return None


def _statement_uses_uncertain_builtin_helper(statement: bytes, uncertain_builtin_helper_names: set[str]) -> bool:
    if not uncertain_builtin_helper_names:
        return False
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return False
    return any(
        isinstance(node, ast.Call) and _simple_reference_name(node.func) in uncertain_builtin_helper_names
        for node in ast.walk(tree)
    )


def _builtin_helper_delete_state(statement: bytes, builtins_alias_names: set[str]) -> tuple[str, bool] | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Delete):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {"getattr", "vars", "setattr", "delattr"}:
                return target.id, True
            if (
                isinstance(target, ast.Attribute)
                and target.attr in {"getattr", "vars", "setattr", "delattr"}
                and isinstance(target.value, ast.Name)
                and target.value.id in builtins_alias_names
            ):
                return f"builtins.{target.attr}", False
    return None


def _late_assignment_binds_builtins_mapping(
    statement: bytes,
    builtins_alias_names: set[str],
    builtin_dict_mapping_aliases: set[str],
    shadowed_builtin_helper_names: set[str],
    canonical_builtin_helper_aliases: dict[str, str],
) -> bool:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return False
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign):
        return False
    value = tree.body[0].value
    helper_reference = _simple_reference_name(value.func) if isinstance(value, ast.Call) else None
    return (
        (isinstance(value, ast.Name) and value.id in builtin_dict_mapping_aliases)
        or (
            isinstance(value, ast.Attribute)
            and value.attr == "__dict__"
            and isinstance(value.value, ast.Name)
            and value.value.id in builtins_alias_names
        )
        or (
            isinstance(value, ast.Call)
            and canonical_builtin_helper_aliases.get(helper_reference or "") == "vars"
            and helper_reference not in shadowed_builtin_helper_names
            and ("." not in (helper_reference or "") or "builtins.vars" not in shadowed_builtin_helper_names)
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id in builtins_alias_names
        )
    )


def _late_assignment_builtin_update_kind(
    statement: bytes,
    builtins_alias_names: set[str],
    builtin_dict_descriptor_aliases: set[str],
    blocked_descriptor_names: set[str],
    shadowed_builtin_helper_names: set[str],
    builtin_dict_mapping_aliases: set[str],
    canonical_builtin_helper_aliases: dict[str, str],
) -> str | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    if len(tree.body) != 1:
        return None
    assignment = tree.body[0]
    if (isinstance(assignment, ast.Assign) and len(assignment.targets) == 1) or (
        isinstance(assignment, ast.AnnAssign) and assignment.value is not None
    ):
        value = assignment.value
    else:
        return None
    if not isinstance(value, ast.Attribute) or value.attr not in {"update", "__ior__", "__setitem__", "setdefault"}:
        return None
    descriptor_name = _static_builtin_dict_descriptor_name(
        value.value,
        builtins_alias_names,
        builtin_dict_descriptor_aliases,
        shadowed_builtin_helper_names,
        canonical_builtin_helper_aliases,
    )
    if descriptor_name is not None and descriptor_name not in blocked_descriptor_names:
        if value.attr in {"update", "__ior__"}:
            return "descriptor"
        return "descriptor_setdefault" if value.attr == "setdefault" else "descriptor_setitem"
    helper_reference = _simple_reference_name(value.value.func) if isinstance(value.value, ast.Call) else None
    if (
        (isinstance(value.value, ast.Name) and value.value.id in builtin_dict_mapping_aliases)
        or (
            isinstance(value.value, ast.Attribute)
            and value.value.attr == "__dict__"
            and isinstance(value.value.value, ast.Name)
            and value.value.value.id in builtins_alias_names
        )
        or (
            isinstance(value.value, ast.Call)
            and canonical_builtin_helper_aliases.get(helper_reference or "") == "vars"
            and helper_reference not in shadowed_builtin_helper_names
            and ("." not in (helper_reference or "") or "builtins.vars" not in shadowed_builtin_helper_names)
            and len(value.value.args) == 1
            and isinstance(value.value.args[0], ast.Name)
            and value.value.args[0].id in builtins_alias_names
        )
    ):
        if value.attr in {"update", "__ior__"}:
            return "mapping"
        return "mapping_setitem"
    return None


def _alias_reference_root_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _alias_reference_root_names(node.value)
    if (
        isinstance(node, ast.Call)
        and _simple_reference_name(node.func) in {"getattr", "builtins.getattr"}
        and node.args
    ):
        return _alias_reference_root_names(node.args[0])
    if isinstance(node, ast.IfExp):
        return _alias_reference_root_names(node.body) | _alias_reference_root_names(node.orelse)
    if isinstance(node, ast.BoolOp):
        return {root for value in node.values for root in _alias_reference_root_names(value)}
    return set()


def _alias_binding_dependency_names(statement: bytes) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return set()
    dependencies: set[str] = set()
    for _target, value in _assignment_targets_and_values_in_tree(tree):
        dependencies.update(_alias_reference_root_names(value))
    return dependencies


def _assignment_value_dependency_names(statement: bytes) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return set()
    dependencies: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        if node.value is not None:
            dependencies.update(_alias_reference_root_names(node.value))
    return dependencies


def _assignment_may_bind_priority_alias(
    statement: bytes, relevant_names: set[str], shadowed_truthy_builtin_names: set[str]
) -> bool:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return False

    def expression_may_bind_priority_alias(value: ast.AST) -> bool:
        if isinstance(value, ast.IfExp):
            selected_value = None
            if isinstance(value.test, ast.Constant):
                selected_value = value.body if bool(value.test.value) else value.orelse
            return (
                expression_may_bind_priority_alias(selected_value)
                if selected_value is not None
                else any(expression_may_bind_priority_alias(branch) for branch in (value.body, value.orelse))
            )
        if isinstance(value, ast.BoolOp):
            if isinstance(value.op, ast.Or):
                for operand in value.values:
                    if expression_may_bind_priority_alias(operand):
                        return True
                    if _definitely_truthy_safe_expression(operand, relevant_names, shadowed_truthy_builtin_names):
                        return False
                    if isinstance(operand, ast.Constant) and not bool(operand.value):
                        continue
                    return any(expression_may_bind_priority_alias(branch) for branch in value.values[1:])
                return False
            for operand in value.values[:-1]:
                if expression_may_bind_priority_alias(operand):
                    continue
                if isinstance(operand, ast.Constant) and not bool(operand.value):
                    return False
                if _definitely_truthy_safe_expression(operand, relevant_names, shadowed_truthy_builtin_names):
                    continue
                return any(expression_may_bind_priority_alias(branch) for branch in value.values[1:])
            return expression_may_bind_priority_alias(value.values[-1])
        return not _alias_reference_root_names(value).isdisjoint(relevant_names)

    for _target, value in _assignment_targets_and_values_in_tree(tree):
        if isinstance(value, (ast.IfExp, ast.BoolOp)) and expression_may_bind_priority_alias(value):
            return True
    return False


def _definitely_truthy_safe_expression(
    value: ast.AST, relevant_names: set[str], shadowed_truthy_builtin_names: set[str]
) -> bool:
    if isinstance(value, ast.Constant):
        return bool(value.value)
    return (
        isinstance(value, ast.Name)
        and value.id == "print"
        and value.id not in relevant_names
        and value.id not in shadowed_truthy_builtin_names
    )


def _late_mutated_truthy_builtin_names(
    statement: bytes,
    builtins_alias_names: set[str],
    shadowed_builtin_helper_names: set[str],
    *,
    builtin_dict_mapping_aliases: set[str] | None = None,
    builtin_dict_descriptor_aliases: set[str] | None = None,
    builtin_dict_mapping_update_aliases: set[str] | None = None,
    builtin_dict_mapping_setitem_aliases: set[str] | None = None,
    shadowed_descriptor_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
    evaluate_annotations: bool = True,
) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement.lstrip(b"\x00\xff"))
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return set()

    mutated_names = _deterministically_executed_defined_names(
        statement, evaluate_annotations=evaluate_annotations
    ).intersection({"print", "len"})
    canonical_helpers = canonical_builtin_helper_aliases or {
        "vars": "vars",
        "builtins.vars": "vars",
        "setattr": "setattr",
        "builtins.setattr": "setattr",
    }

    def is_builtin_mapping(node: ast.AST) -> bool:
        helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
        return (
            (isinstance(node, ast.Name) and node.id in (builtin_dict_mapping_aliases or set()))
            or (
                isinstance(node, ast.Attribute)
                and node.attr == "__dict__"
                and isinstance(node.value, ast.Name)
                and node.value.id in builtins_alias_names
            )
            or (
                isinstance(node, ast.Call)
                and canonical_helpers.get(helper_reference or "") == "vars"
                and helper_reference not in shadowed_builtin_helper_names
                and ("." not in (helper_reference or "") or "builtins.vars" not in shadowed_builtin_helper_names)
                and len(node.args) == 1
                and not node.keywords
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in builtins_alias_names
            )
        )

    def record_target(target: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                record_target(element)
        elif isinstance(target, ast.Starred):
            record_target(target.value)
        elif isinstance(target, ast.Name) and target.id in {"print", "len"}:
            mutated_names.add(target.id)
        elif (
            isinstance(target, ast.Attribute)
            and target.attr in {"print", "len"}
            and isinstance(target.value, ast.Name)
            and target.value.id in builtins_alias_names
        ):
            mutated_names.add(target.attr)
        elif isinstance(target, ast.Subscript):
            key = _static_getattr_member_name(target.slice)
            if key in {"print", "len"} and is_builtin_mapping(target.value):
                mutated_names.add(key)

    for executed_statement in _deterministically_executed_statements(tree.body):
        if isinstance(executed_statement, ast.Assign):
            for target in executed_statement.targets:
                record_target(target)
        elif isinstance(executed_statement, (ast.AnnAssign, ast.AugAssign)):
            record_target(executed_statement.target)
        elif isinstance(executed_statement, (ast.For, ast.AsyncFor)):
            if _static_late_iter_truth(executed_statement.iter) is not False:
                record_target(executed_statement.target)
        elif isinstance(executed_statement, (ast.With, ast.AsyncWith)):
            for item in executed_statement.items:
                if item.optional_vars is not None:
                    record_target(item.optional_vars)
        elif isinstance(executed_statement, ast.Delete):
            for target in executed_statement.targets:
                record_target(target)
        for value in _deterministically_evaluated_statement_expressions(
            executed_statement, evaluate_annotations=evaluate_annotations
        ):
            for expression_node in _deterministically_executed_expression_nodes(value):
                if isinstance(expression_node, ast.NamedExpr):
                    record_target(expression_node.target)
            for call in _deterministically_executed_expression_calls(value):
                if (
                    (
                        (
                            canonical_helpers.get(_simple_reference_name(call.func) or "") == "setattr"
                            and _simple_reference_name(call.func) not in shadowed_builtin_helper_names
                            and (
                                "." not in (_simple_reference_name(call.func) or "")
                                or "builtins.setattr" not in shadowed_builtin_helper_names
                            )
                        )
                        or (isinstance(call.func, ast.Name) and call.func.id == "delattr")
                    )
                    and len(call.args) >= 2
                    and isinstance(call.args[0], ast.Name)
                    and call.args[0].id in builtins_alias_names
                    and _static_getattr_member_name(call.args[1]) in {"print", "len"}
                ):
                    member_name = _static_getattr_member_name(call.args[1])
                    if member_name is not None:
                        mutated_names.add(member_name)
                else:
                    mapping_method: str | None = None
                    mapping_arguments = call.args
                    if isinstance(call.func, ast.Attribute):
                        mapping_method = call.func.attr
                        targets_mapping = is_builtin_mapping(call.func.value)
                        descriptor_reference = _simple_reference_name(call.func.value)
                        if (
                            not targets_mapping
                            and descriptor_reference in (builtin_dict_descriptor_aliases or {"dict"})
                            and descriptor_reference not in (shadowed_descriptor_names or set())
                            and call.args
                            and is_builtin_mapping(call.args[0])
                        ):
                            targets_mapping = True
                            mapping_arguments = call.args[1:]
                        if not targets_mapping:
                            mapping_method = None
                    elif isinstance(call.func, ast.Name) and call.func.id in (
                        builtin_dict_mapping_update_aliases or set()
                    ):
                        mapping_method = "update"
                    elif isinstance(call.func, ast.Name) and call.func.id in (
                        builtin_dict_mapping_setitem_aliases or set()
                    ):
                        mapping_method = "__setitem__"
                    if mapping_method == "update":
                        mutated_names.update(
                            keyword.arg for keyword in call.keywords if keyword.arg in {"print", "len"}
                        )
                        for keyword in call.keywords:
                            if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                                mutated_names.update(
                                    member_name
                                    for key in keyword.value.keys
                                    if key is not None
                                    and (member_name := _static_getattr_member_name(key)) in {"print", "len"}
                                )
                        for argument in mapping_arguments:
                            if isinstance(argument, ast.Dict):
                                mutated_names.update(
                                    member_name
                                    for key in argument.keys
                                    if key is not None
                                    and (member_name := _static_getattr_member_name(key)) in {"print", "len"}
                                )
                    elif mapping_method == "__setitem__" and mapping_arguments:
                        member_name = _static_getattr_member_name(mapping_arguments[0])
                        if member_name in {"print", "len"}:
                            mutated_names.add(member_name)
    return mutated_names


def _bounded_late_binding_statement(candidate: bytes, line_start: int, line_end: int) -> tuple[bytes, tuple[int, int]]:
    statement_end = line_end
    statement = candidate[line_start:statement_end]
    parenthesis_depth = _line_parenthesis_delta(statement)
    while (
        (_line_has_explicit_continuation(statement.splitlines(keepends=True)[-1]) or parenthesis_depth > 0)
        and statement_end < len(candidate)
        and statement_end - line_start < _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES
    ):
        next_line_end = candidate.find(b"\n", statement_end)
        statement_end = len(candidate) if next_line_end == -1 else next_line_end + 1
        next_line = candidate[line_end:statement_end]
        parenthesis_depth += _line_parenthesis_delta(next_line)
        line_end = statement_end
        statement = candidate[line_start:statement_end]
    span = (line_start, min(statement_end, line_start + _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES))
    return candidate[span[0] : span[1]], span


def _explicit_call_target(node: ast.AST) -> ast.AST:
    while True:
        if isinstance(node, ast.Attribute) and node.attr == "__call__":
            node = node.value
            continue
        if (
            isinstance(node, ast.Call)
            and _simple_reference_name(node.func) in {"getattr", "builtins.getattr"}
            and not node.keywords
            and len(node.args) >= 2
            and _static_getattr_member_name(node.args[1]) == "__call__"
        ):
            node = node.args[0]
            continue
        return node


def _callable_expression_candidates(node: ast.AST) -> list[ast.AST]:
    node = _explicit_call_target(node)
    if isinstance(node, ast.IfExp):
        condition = _static_late_truth_value(node.test)
        if condition is True:
            return _callable_expression_candidates(node.body)
        if condition is False:
            return _callable_expression_candidates(node.orelse)
        return [*(_callable_expression_candidates(node.body)), *(_callable_expression_candidates(node.orelse))]
    return [node]


def _callable_expression_root_names(node: ast.AST) -> set[str]:
    root_names: set[str] = set()
    for callable_node in _callable_expression_candidates(node):
        root = callable_node
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            root = root.value
        if isinstance(root, ast.Name):
            root_names.add(root.id)
    return root_names


def _callable_expression_uses_priority_alias(node: ast.AST, alias_names: set[str]) -> bool:
    for callable_node in _callable_expression_candidates(node):
        root = callable_node
        members: set[str] = set()
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            if isinstance(root, ast.Attribute):
                members.add(root.attr)
            root = root.value
        if (
            isinstance(root, ast.Name)
            and root.id in alias_names
            and (not members or not members.isdisjoint(_PRIORITY_CALL_MEMBER_NAMES))
        ):
            return True
    return False


def _callable_root_names(fragment: bytes) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(fragment)
    source = textwrap.dedent(source)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        try:
            tree = ast.parse("def _candidate():\n" + textwrap.indent(source, "    "))
        except (SyntaxError, ValueError):
            return set()
    root_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        root_names.update(_callable_expression_root_names(node.func))
    return root_names


def _member_load_root_names(fragment: bytes) -> set[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(fragment)
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return set()
    root_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Attribute, ast.Subscript)) or not isinstance(node.ctx, ast.Load):
            continue
        root: ast.AST = node
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            root = root.value
        if isinstance(root, ast.Name):
            root_names.add(root.id)
    return root_names


def _snippet_loads_native_library_member(source_bytes: bytes) -> bool:
    if not any(loader_name in source_bytes for loader_name in (b"cdll", b"oledll", b"pydll", b"windll")):
        return False
    return "S110" in _snippet_resolved_high_risk_rule_codes(source_bytes)


def _snippet_resolved_high_risk_rule_codes(source_bytes: bytes) -> frozenset[str]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(source_bytes)
    parsed_snippet = _parse_embedded_python_snippet(textwrap.dedent(source))
    if parsed_snippet is None:
        return frozenset()
    return frozenset(code for _name, code in _resolve_alias_aware_high_risk_calls(parsed_snippet[0]))


def _potential_late_callable_root_names(code_line: bytes) -> set[str]:
    return {
        match.group(1).decode("utf-8")
        for match in re.finditer(
            rb"(?<![A-Za-z0-9_.])(?:\(\s*)*([A-Za-z_]\w*)\s*(?:\)\s*)*"
            rb"(?:\.[A-Za-z_]\w*\s*)?(?:\)\s*)*\(",
            code_line,
        )
    }


def _referenced_priority_aliases(fragment: bytes, aliases: frozenset[bytes]) -> frozenset[bytes]:
    if len(aliases) <= 8:
        return aliases
    referenced_names = frozenset(match.group(0) for match in re.finditer(rb"(?<![A-Za-z0-9_])[A-Za-z_]\w*", fragment))
    return aliases.intersection(referenced_names)


def _fragment_has_continued_priority_alias_call(fragment: bytes, aliases: frozenset[bytes]) -> bool:
    """Recognize completed calls rooted in retained dangerous imports."""
    aliases = _referenced_priority_aliases(fragment, aliases)
    if not aliases:
        return False
    source, _byte_offsets = _decode_utf8_with_byte_offsets(fragment)
    tree = _parse_late_replay_tree(source)
    if tree is None:
        return False
    alias_names = {alias.decode("utf-8") for alias in aliases}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _callable_expression_uses_priority_alias(node.func, alias_names):
            return True
    return False


def _line_is_continued_priority_alias_piece(code_line: bytes, aliases: frozenset[bytes]) -> bool:
    aliases = _referenced_priority_aliases(code_line, aliases)
    return any(
        re.fullmatch(
            rb"\s*(?:\(\s*)*"
            + re.escape(alias)
            + rb"(?:\s*\)*\s*\.\s*[A-Za-z_]\w*)*\s*\)*\s*(?:\(\s*|\.\s*)?(?:\\)?\s*",
            code_line,
        )
        for alias in aliases
    )


def _line_is_continued_priority_name_piece(code_line: bytes, names: set[str]) -> bool:
    return _line_is_continued_priority_alias_piece(code_line, frozenset(name.encode("utf-8") for name in names))


_RUNPY_PRIORITY_MEMBER_NAMES = frozenset({"_run_module_as_main", "run_module", "run_path"})


def _runpy_static_namespace_owner(
    node: ast.AST,
    aliases: frozenset[bytes],
    namespace_aliases: dict[str, str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> str | None:
    alias_names = {alias.decode("utf-8") for alias in aliases}
    canonical_helpers = canonical_builtin_helper_aliases or {
        "vars": "vars",
        "builtins.vars": "vars",
    }
    if isinstance(node, ast.Name) and node.id in (namespace_aliases or {}):
        return (namespace_aliases or {})[node.id]
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
        and isinstance(node.value, ast.Name)
        and node.value.id in alias_names
    ):
        return node.value.id
    if (
        isinstance(node, ast.Call)
        and (helper_reference := _simple_reference_name(node.func)) is not None
        and canonical_helpers.get(helper_reference) == "vars"
        and helper_reference not in (shadowed_builtin_helper_names or set())
        and ("." not in helper_reference or "builtins.vars" not in (shadowed_builtin_helper_names or set()))
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in alias_names
    ):
        return node.args[0].id
    return None


def _runpy_static_member_key(node: ast.AST) -> str | None:
    member_name = _static_getattr_member_name(node)
    return member_name if member_name in _RUNPY_PRIORITY_MEMBER_NAMES else None


def _runpy_priority_namespace_update_binding(
    line: bytes,
    aliases: frozenset[bytes],
    namespace_aliases: dict[str, str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> tuple[str, str, str] | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(line.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    for statement in tree.body:
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            value = statement.value
            if isinstance(value, ast.Attribute) and value.attr in {
                "update",
                "__ior__",
                "__setitem__",
                "setdefault",
                "pop",
                "__delitem__",
            }:
                owner_name = _runpy_static_namespace_owner(
                    value.value,
                    aliases,
                    namespace_aliases,
                    shadowed_builtin_helper_names,
                    canonical_builtin_helper_aliases,
                )
                if owner_name is not None:
                    if value.attr == "__setitem__":
                        mutator_kind = "setitem"
                    elif value.attr == "setdefault":
                        mutator_kind = "setdefault"
                    elif value.attr in {"pop", "__delitem__"}:
                        mutator_kind = "delete"
                    else:
                        mutator_kind = "update"
                    return statement.targets[0].id, owner_name, mutator_kind
            owner_name = _runpy_static_namespace_owner(
                value,
                aliases,
                namespace_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if owner_name is not None:
                return statement.targets[0].id, owner_name, "mapping"
    return None


def _static_builtin_dict_descriptor_name(
    node: ast.AST,
    builtins_alias_names: set[str],
    builtin_dict_descriptor_aliases: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> str | None:
    reference = _simple_reference_name(node)
    if reference in (builtin_dict_descriptor_aliases or {"dict"}):
        return "dict"
    if (
        reference is not None
        and reference.endswith(".dict")
        and reference.removesuffix(".dict") in builtins_alias_names
    ):
        return "builtins.dict"
    helper_reference = _simple_reference_name(node.func) if isinstance(node, ast.Call) else None
    canonical_helpers = canonical_builtin_helper_aliases or {
        "getattr": "getattr",
        "builtins.getattr": "getattr",
    }
    if (
        isinstance(node, ast.Call)
        and canonical_helpers.get(helper_reference or "") == "getattr"
        and helper_reference not in (shadowed_builtin_helper_names or set())
        and ("." not in (helper_reference or "") or "builtins.getattr" not in (shadowed_builtin_helper_names or set()))
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in builtins_alias_names
        and _static_getattr_member_name(node.args[1]) == "dict"
    ):
        return "builtins.dict"
    return None


def _runpy_priority_descriptor_update_name(
    line: bytes,
    builtins_alias_names: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> str | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(line.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr not in {"update", "__ior__"}
        ):
            continue
        descriptor_name = _static_builtin_dict_descriptor_name(
            node.func.value,
            builtins_alias_names or {"builtins"},
            shadowed_builtin_helper_names=shadowed_builtin_helper_names,
            canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
        )
        if descriptor_name is not None:
            return descriptor_name
    return None


def _runpy_static_update_items(node: ast.AST) -> list[tuple[ast.AST, ast.AST]] | None:
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            return None
        return [(key, value) for key, value in zip(node.keys, node.values, strict=True) if key is not None]
    if isinstance(node, (ast.List, ast.Tuple)):
        items: list[tuple[ast.AST, ast.AST]] = []
        for element in node.elts:
            if not isinstance(element, (ast.List, ast.Tuple)) or len(element.elts) != 2:
                return None
            items.append((element.elts[0], element.elts[1]))
        return items
    return None


def _runpy_priority_ast_member_update(
    line: bytes,
    aliases: frozenset[bytes],
    update_aliases: dict[str, str],
    setitem_aliases: dict[str, str],
    setdefault_aliases: dict[str, str],
    shadowed_descriptor_names: set[str],
    descriptor_update_aliases: set[str],
    descriptor_setitem_aliases: set[str],
    descriptor_setdefault_aliases: set[str],
    builtins_alias_names: set[str],
    shadowed_builtin_helper_names: set[str],
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(line.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    subscript_owner = _runpy_static_namespace_owner(
                        target.value,
                        aliases,
                        update_aliases,
                        shadowed_builtin_helper_names,
                        canonical_builtin_helper_aliases,
                    )
                    member_name = _runpy_static_member_key(target.slice)
                    if subscript_owner is not None and member_name is not None:
                        return f"runpy.{member_name}", subscript_owner
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    subscript_owner = _runpy_static_namespace_owner(
                        target.value,
                        aliases,
                        update_aliases,
                        shadowed_builtin_helper_names,
                        canonical_builtin_helper_aliases,
                    )
                    member_name = _runpy_static_member_key(target.slice)
                    if subscript_owner is not None and member_name is not None:
                        return f"runpy.{member_name}", subscript_owner
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
            update_owner = _runpy_static_namespace_owner(
                node.target,
                aliases,
                update_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if update_owner is not None:
                for key, _value in _runpy_static_update_items(node.value) or []:
                    if (member_name := _runpy_static_member_key(key)) is not None:
                        return f"runpy.{member_name}", update_owner
        if not isinstance(node, ast.Call):
            continue
        helper_reference = _simple_reference_name(node.func)
        canonical_helpers = canonical_builtin_helper_aliases or {
            "getattr": "getattr",
            "builtins.getattr": "getattr",
            "vars": "vars",
            "builtins.vars": "vars",
            "setattr": "setattr",
            "builtins.setattr": "setattr",
        }
        if (
            canonical_helpers.get(helper_reference or "") == "setattr"
            and helper_reference not in shadowed_builtin_helper_names
            and ("." not in (helper_reference or "") or "builtins.setattr" not in shadowed_builtin_helper_names)
            and len(node.args) >= 3
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in {alias.decode("utf-8") for alias in aliases}
            and (member_name := _runpy_static_member_key(node.args[1])) is not None
        ):
            return f"runpy.{member_name}", node.args[0].id
        descriptor_setitem_name = (
            _static_builtin_dict_descriptor_name(
                node.func.value,
                builtins_alias_names,
                shadowed_builtin_helper_names=shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "__setitem__"
            else None
        )
        is_local_descriptor_setitem = descriptor_setitem_name == "dict" and "dict" not in shadowed_descriptor_names
        is_builtin_descriptor_setitem = (
            descriptor_setitem_name == "builtins.dict" and "builtins.dict" not in shadowed_descriptor_names
        )
        is_bound_descriptor_setitem = (
            isinstance(node.func, ast.Name) and node.func.id in descriptor_setitem_aliases and len(node.args) >= 3
        )
        if (
            (is_local_descriptor_setitem or is_builtin_descriptor_setitem) and len(node.args) >= 3
        ) or is_bound_descriptor_setitem:
            setitem_owner = _runpy_static_namespace_owner(
                node.args[0],
                aliases,
                update_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if setitem_owner is not None and (member_name := _runpy_static_member_key(node.args[1])) is not None:
                return f"runpy.{member_name}", setitem_owner
            continue
        if isinstance(node.func, ast.Name) and node.func.id in setitem_aliases and len(node.args) >= 2:
            if (member_name := _runpy_static_member_key(node.args[0])) is not None:
                return f"runpy.{member_name}", setitem_aliases[node.func.id]
            continue
        descriptor_setdefault_name = (
            _static_builtin_dict_descriptor_name(
                node.func.value,
                builtins_alias_names,
                shadowed_builtin_helper_names=shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "setdefault"
            else None
        )
        is_bound_descriptor_setdefault = (
            isinstance(node.func, ast.Name) and node.func.id in descriptor_setdefault_aliases and len(node.args) >= 3
        )
        if (
            descriptor_setdefault_name is not None
            and descriptor_setdefault_name not in shadowed_descriptor_names
            and len(node.args) >= 3
        ) or is_bound_descriptor_setdefault:
            setdefault_owner = _runpy_static_namespace_owner(
                node.args[0],
                aliases,
                update_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            if setdefault_owner is not None and (member_name := _runpy_static_member_key(node.args[1])) is not None:
                return f"runpy.{member_name}", setdefault_owner
            continue
        if isinstance(node.func, ast.Name) and node.func.id in setdefault_aliases and len(node.args) >= 2:
            if (member_name := _runpy_static_member_key(node.args[0])) is not None:
                return f"runpy.{member_name}", setdefault_aliases[node.func.id]
            continue
        call_owner: str | None = None
        update_arguments = node.args
        descriptor_name = (
            _static_builtin_dict_descriptor_name(
                node.func.value,
                builtins_alias_names,
                shadowed_builtin_helper_names=shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            )
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"update", "__ior__"}
            else None
        )
        is_local_descriptor = descriptor_name == "dict" and "dict" not in shadowed_descriptor_names
        is_builtin_descriptor = descriptor_name == "builtins.dict" and "builtins.dict" not in shadowed_descriptor_names
        is_bound_descriptor = (
            isinstance(node.func, ast.Name) and node.func.id in descriptor_update_aliases and bool(node.args)
        )
        if ((is_local_descriptor or is_builtin_descriptor) and node.args) or is_bound_descriptor:
            call_owner = _runpy_static_namespace_owner(
                node.args[0],
                aliases,
                update_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            update_arguments = node.args[1:]
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {
            "__setitem__",
            "update",
            "__ior__",
            "setdefault",
            "pop",
            "__delitem__",
        }:
            call_owner = _runpy_static_namespace_owner(
                node.func.value,
                aliases,
                update_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
        elif isinstance(node.func, ast.Name):
            call_owner = update_aliases.get(node.func.id)
        if call_owner is None:
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"__setitem__", "setdefault", "pop", "__delitem__"}
            and node.args
        ):
            member_name = _runpy_static_member_key(node.args[0])
            if member_name is not None:
                return f"runpy.{member_name}", call_owner
            continue
        if not (
            (isinstance(node.func, ast.Attribute) and node.func.attr in {"update", "__ior__"})
            or isinstance(node.func, ast.Name)
        ):
            continue
        for argument in update_arguments:
            for static_key_node, _value in _runpy_static_update_items(argument) or []:
                member_name = _runpy_static_member_key(static_key_node)
                if member_name is not None:
                    return f"runpy.{member_name}", call_owner
        for keyword in node.keywords:
            if keyword.arg in _RUNPY_PRIORITY_MEMBER_NAMES:
                return f"runpy.{keyword.arg}", call_owner
            if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                for key_node in keyword.value.keys:
                    if key_node is not None:
                        member_name = _runpy_static_member_key(key_node)
                        if member_name is not None:
                            return f"runpy.{member_name}", call_owner
    return None


def _runpy_priority_deleted_member_key(
    line: bytes,
    aliases: frozenset[bytes],
    namespace_aliases: dict[str, str] | None = None,
    delete_aliases: dict[str, str] | None = None,
    descriptor_delete_aliases: set[str] | None = None,
    builtin_dict_descriptor_aliases: set[str] | None = None,
    builtins_alias_names: set[str] | None = None,
    shadowed_descriptor_names: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> str | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(line.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    alias_names = {alias.decode("utf-8") for alias in aliases}
    for node in ast.walk(tree):
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in alias_names
                    and target.attr in _RUNPY_PRIORITY_MEMBER_NAMES
                ):
                    return f"runpy.{target.attr}"
                if isinstance(target, ast.Subscript):
                    owner = _runpy_static_namespace_owner(
                        target.value,
                        aliases,
                        namespace_aliases,
                        shadowed_builtin_helper_names,
                        canonical_builtin_helper_aliases,
                    )
                    member_name = _runpy_static_member_key(target.slice)
                    if owner is not None and member_name is not None:
                        return f"runpy.{member_name}"
        if not isinstance(node, ast.Call):
            continue
        helper_reference = _simple_reference_name(node.func)
        canonical_helpers = canonical_builtin_helper_aliases or {
            "delattr": "delattr",
            "builtins.delattr": "delattr",
        }
        if (
            canonical_helpers.get(helper_reference or "") == "delattr"
            and helper_reference not in (shadowed_builtin_helper_names or set())
            and (
                "." not in (helper_reference or "")
                or "builtins.delattr" not in (shadowed_builtin_helper_names or set())
            )
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in alias_names
            and (member_name := _runpy_static_member_key(node.args[1])) is not None
        ):
            return f"runpy.{member_name}"
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in (delete_aliases or {})
            and node.args
            and (member_name := _runpy_static_member_key(node.args[0])) is not None
        ):
            return f"runpy.{member_name}"
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in (descriptor_delete_aliases or set())
            and len(node.args) >= 2
        ):
            owner = _runpy_static_namespace_owner(
                node.args[0],
                aliases,
                namespace_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            member_name = _runpy_static_member_key(node.args[1])
            if owner is not None and member_name is not None:
                return f"runpy.{member_name}"
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"pop", "__delitem__"} and node.args:
            owner = _runpy_static_namespace_owner(
                node.func.value,
                aliases,
                namespace_aliases,
                shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases,
            )
            member_name = _runpy_static_member_key(node.args[0])
            if owner is not None and member_name is not None:
                return f"runpy.{member_name}"
            descriptor_name = _static_builtin_dict_descriptor_name(
                node.func.value,
                builtins_alias_names or {"builtins"},
                builtin_dict_descriptor_aliases,
                shadowed_builtin_helper_names=shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            )
            if (
                descriptor_name is not None
                and descriptor_name not in (shadowed_descriptor_names or set())
                and len(node.args) >= 2
            ):
                owner = _runpy_static_namespace_owner(
                    node.args[0],
                    aliases,
                    namespace_aliases,
                    shadowed_builtin_helper_names,
                    canonical_builtin_helper_aliases,
                )
                member_name = _runpy_static_member_key(node.args[1])
                if owner is not None and member_name is not None:
                    return f"runpy.{member_name}"
    return None


def _runpy_priority_member_update_key(
    line: bytes,
    code_line: bytes,
    aliases: frozenset[bytes],
    update_aliases: dict[str, str] | None = None,
    setitem_aliases: dict[str, str] | None = None,
    setdefault_aliases: dict[str, str] | None = None,
    shadowed_descriptor_names: set[str] | None = None,
    descriptor_update_aliases: set[str] | None = None,
    descriptor_setitem_aliases: set[str] | None = None,
    descriptor_setdefault_aliases: set[str] | None = None,
    builtins_alias_names: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    ast_update = _runpy_priority_ast_member_update(
        line,
        aliases,
        update_aliases or {},
        setitem_aliases or {},
        setdefault_aliases or {},
        shadowed_descriptor_names or set(),
        descriptor_update_aliases or set(),
        descriptor_setitem_aliases or set(),
        descriptor_setdefault_aliases or set(),
        builtins_alias_names or {"builtins"},
        shadowed_builtin_helper_names or set(),
        canonical_builtin_helper_aliases,
    )
    if ast_update is not None:
        return ast_update
    member_names = rb"(_run_module_as_main|run_module|run_path)"
    for alias in aliases:
        match = re.search(
            rb"(?<![A-Za-z0-9_])" + re.escape(alias) + rb"\s*\.\s*" + member_names + rb"\s*(?::[^=\n]+)?=",
            code_line,
        )
        if match is None:
            match = re.search(
                rb"\bdel\s+" + re.escape(alias) + rb"\s*\.\s*" + member_names + rb"\b",
                code_line,
            )
        if match is not None:
            return f"runpy.{match.group(1).decode('utf-8')}", alias.decode("utf-8")
        for raw_pattern, structural_pattern in (
            (
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\[\s*['\"]" + member_names + rb"['\"]\s*\]\s*=",
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\[\s*\]\s*=",
            ),
            (
                rb"\bvars\s*\(\s*" + re.escape(alias) + rb"\s*\)\s*\[\s*['\"]" + member_names + rb"['\"]\s*\]\s*=",
                rb"\bvars\s*\(\s*" + re.escape(alias) + rb"\s*\)\s*\[\s*\]\s*=",
            ),
            (
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\.\s*__setitem__\s*\(\s*['\"]" + member_names + rb"['\"]\s*,",
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\.\s*__setitem__\s*\(\s*,",
            ),
            (
                rb"\bvars\s*\(\s*"
                + re.escape(alias)
                + rb"\s*\)\s*\.\s*__setitem__\s*\(\s*['\"]"
                + member_names
                + rb"['\"]\s*,",
                rb"\bvars\s*\(\s*" + re.escape(alias) + rb"\s*\)\s*\.\s*__setitem__\s*\(\s*,",
            ),
            (
                re.escape(alias)
                + rb"\s*\.\s*__dict__\s*\.\s*update\s*\(\s*\{[^}\n]*?['\"]"
                + member_names
                + rb"['\"]\s*:",
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\.\s*update\s*\(",
            ),
            (
                rb"\bvars\s*\(\s*"
                + re.escape(alias)
                + rb"\s*\)\s*\.\s*update\s*\(\s*\{[^}\n]*?['\"]"
                + member_names
                + rb"['\"]\s*:",
                rb"\bvars\s*\(\s*" + re.escape(alias) + rb"\s*\)\s*\.\s*update\s*\(",
            ),
            (
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\.\s*update\s*\([^)\n]*?\b" + member_names + rb"\s*=",
                re.escape(alias) + rb"\s*\.\s*__dict__\s*\.\s*update\s*\([^)\n]*?\b" + member_names + rb"\s*=",
            ),
            (
                rb"\bvars\s*\(\s*"
                + re.escape(alias)
                + rb"\s*\)\s*\.\s*update\s*\([^)\n]*?\b"
                + member_names
                + rb"\s*=",
                rb"\bvars\s*\(\s*"
                + re.escape(alias)
                + rb"\s*\)\s*\.\s*update\s*\([^)\n]*?\b"
                + member_names
                + rb"\s*=",
            ),
        ):
            match = re.search(raw_pattern, line)
            if match is not None and b"vars" in raw_pattern and "vars" in (shadowed_builtin_helper_names or set()):
                continue
            if match is not None and re.search(structural_pattern, code_line) is not None:
                return f"runpy.{match.group(1).decode('utf-8')}", alias.decode("utf-8")
    return None


def _runpy_priority_member_update_dependency_names(
    statement: bytes,
    member_key: str,
    update_aliases: dict[str, str] | None = None,
    setitem_aliases: dict[str, str] | None = None,
    setdefault_aliases: dict[str, str] | None = None,
    descriptor_update_aliases: set[str] | None = None,
    descriptor_setitem_aliases: set[str] | None = None,
    descriptor_setdefault_aliases: set[str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> set[str]:
    normalized_statement = statement.lstrip(b"\x00\xff")
    dependencies = _assignment_value_dependency_names(normalized_statement)
    member_name = member_key.removeprefix("runpy.")
    source, _byte_offsets = _decode_utf8_with_byte_offsets(normalized_statement)
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return dependencies
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in (update_aliases or {})
                    and _static_getattr_member_name(target.slice) == member_name
                ):
                    dependencies.add(target.value.id)
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
            if isinstance(node.target, ast.Name) and node.target.id in (update_aliases or {}):
                dependencies.add(node.target.id)
            for key, value in _runpy_static_update_items(node.value) or []:
                if _static_getattr_member_name(key) == member_name:
                    dependencies.update(_alias_reference_root_names(value))
        if not isinstance(node, ast.Call):
            continue
        helper_reference = _simple_reference_name(node.func)
        canonical_helpers = canonical_builtin_helper_aliases or {
            "setattr": "setattr",
            "builtins.setattr": "setattr",
        }
        if (
            canonical_helpers.get(helper_reference or "") == "setattr"
            and helper_reference not in (shadowed_builtin_helper_names or set())
            and (
                "." not in (helper_reference or "")
                or "builtins.setattr" not in (shadowed_builtin_helper_names or set())
            )
            and len(node.args) >= 3
            and _static_getattr_member_name(node.args[1]) == member_name
        ):
            if helper_reference is not None and helper_reference not in {"setattr", "builtins.setattr"}:
                dependencies.add(helper_reference)
            dependencies.update(_alias_reference_root_names(node.args[2]))
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in (setitem_aliases or {})
            and len(node.args) >= 2
            and _static_getattr_member_name(node.args[0]) == member_name
        ):
            dependencies.add(node.func.id)
            dependencies.update(_alias_reference_root_names(node.args[1]))
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in (setdefault_aliases or {})
            and len(node.args) >= 2
            and _static_getattr_member_name(node.args[0]) == member_name
        ):
            dependencies.add(node.func.id)
            dependencies.update(_alias_reference_root_names(node.args[1]))
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in (descriptor_setitem_aliases or set())
            and len(node.args) >= 3
            and _static_getattr_member_name(node.args[1]) == member_name
        ):
            dependencies.add(node.func.id)
            dependencies.update(_alias_reference_root_names(node.args[2]))
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in (descriptor_setdefault_aliases or set())
            and len(node.args) >= 3
            and _static_getattr_member_name(node.args[1]) == member_name
        ):
            dependencies.add(node.func.id)
            dependencies.update(_alias_reference_root_names(node.args[2]))
        descriptor_setitem_name = (
            _static_builtin_dict_descriptor_name(
                node.func.value,
                {"builtins"},
                shadowed_builtin_helper_names=shadowed_builtin_helper_names,
                canonical_builtin_helper_aliases=canonical_builtin_helper_aliases,
            )
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"__setitem__", "setdefault"}
            else None
        )
        if (
            descriptor_setitem_name is not None
            and len(node.args) >= 3
            and _static_getattr_member_name(node.args[1]) == member_name
        ):
            dependencies.update(_alias_reference_root_names(node.args[2]))
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"__setitem__", "setdefault"}
            and len(node.args) >= 2
        ):
            key = node.args[0]
            if _static_getattr_member_name(key) == member_name:
                dependencies.update(_alias_reference_root_names(node.args[1]))
        elif (isinstance(node.func, ast.Attribute) and node.func.attr in {"update", "__ior__"}) or (
            isinstance(node.func, ast.Name)
            and node.func.id in {*((update_aliases or {}).keys()), *(descriptor_update_aliases or set())}
        ):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                helper_reference = _simple_reference_name(node.func.value.func)
                canonical_helper_name = canonical_helpers.get(helper_reference or "")
                helper_is_canonical = (
                    canonical_helper_name in {"getattr", "vars"}
                    and helper_reference not in (shadowed_builtin_helper_names or set())
                    and (
                        "." not in (helper_reference or "")
                        or f"builtins.{canonical_helper_name}" not in (shadowed_builtin_helper_names or set())
                    )
                )
                if not helper_is_canonical:
                    dependencies.update(_alias_reference_root_names(node.func.value.func))
            if isinstance(node.func, ast.Name) and node.func.id in (update_aliases or {}):
                dependencies.add(node.func.id)
            if isinstance(node.func, ast.Name) and node.func.id in (descriptor_update_aliases or set()):
                dependencies.add(node.func.id)
            descriptor_name = _simple_reference_name(node.func)
            if descriptor_name is not None and descriptor_name.endswith(".dict.update"):
                descriptor_owner = descriptor_name.removesuffix(".dict.update")
                if descriptor_owner != "builtins":
                    dependencies.add(descriptor_owner)
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in (update_aliases or {})
            ):
                dependencies.add(node.func.value.id)
            update_arguments = (
                node.args[1:]
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"update", "__ior__"}
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in {"dict", "builtins"}
                    and node.args
                )
                or (
                    isinstance(node.func, ast.Name)
                    and node.func.id in (descriptor_update_aliases or set())
                    and node.args
                )
                else node.args
            )
            for argument in update_arguments:
                for static_member_key_node, member_value in _runpy_static_update_items(argument) or []:
                    if _static_getattr_member_name(static_member_key_node) == member_name:
                        dependencies.update(_alias_reference_root_names(member_value))
            for keyword in node.keywords:
                if keyword.arg == member_name:
                    dependencies.update(_alias_reference_root_names(keyword.value))
                elif keyword.arg is None and isinstance(keyword.value, ast.Dict):
                    for member_key_node, member_value in zip(keyword.value.keys, keyword.value.values, strict=True):
                        if member_key_node is not None and _static_getattr_member_name(member_key_node) == member_name:
                            dependencies.update(_alias_reference_root_names(member_value))
    return dependencies


def _line_calls_fail_closed_runpy_member(
    code_line: bytes, aliases: frozenset[bytes], fail_closed_members: set[str]
) -> bool:
    for alias in aliases:
        match = re.search(
            rb"(?<![A-Za-z0-9_])(?:\(\s*)*"
            + re.escape(alias)
            + rb"(?:\s*\)\s*)*\.\s*(_run_module_as_main|run_module|run_path)(?:\s*\)\s*)*\(",
            code_line,
        )
        if match is not None and f"runpy.{match.group(1).decode('utf-8')}" in fail_closed_members:
            return True
    return False


def _line_starts_continued_priority_getattr(
    code_line: bytes,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
    shadowed_builtin_helper_names: set[str] | None = None,
) -> bool:
    if re.fullmatch(rb"\s*(?:builtins\s*\.\s*)?getattr\s*(?:\\\s*|\(\s*)", code_line) is not None:
        return True
    blocked_helpers = shadowed_builtin_helper_names or set()
    return any(
        "." not in reference
        and helper_name == "getattr"
        and reference not in blocked_helpers
        and re.fullmatch(rb"\s*" + re.escape(reference.encode("utf-8")) + rb"\s*(?:\\\s*|\(\s*)", code_line) is not None
        for reference, helper_name in (canonical_builtin_helper_aliases or {}).items()
    )


def _line_uses_priority_alias(code_line: bytes, aliases: frozenset[bytes]) -> bool:
    aliases = _referenced_priority_aliases(code_line, aliases)
    return _fragment_has_continued_priority_alias_call(code_line, aliases) or any(
        re.search(rb"(?<![A-Za-z0-9_])" + re.escape(alias) + rb"\s*(?:\.|\(|\[)", code_line)
        or re.search(
            rb"(?<![A-Za-z0-9_.])(?:builtins\.)?getattr\s*\(\s*" + re.escape(alias) + rb"\s*,",
            code_line,
        )
        or re.search(
            rb"(?<![A-Za-z0-9_.])(?:builtins\.)?vars\s*\(\s*" + re.escape(alias) + rb"\s*\)\s*\[",
            code_line,
        )
        for alias in aliases
    )


def _priority_getattr_alias_member(
    line: bytes,
    aliases: frozenset[bytes],
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> tuple[str, ast.AST, str] | None:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(line.lstrip(b"\x00\xff"))
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (RecursionError, SyntaxError, ValueError):
        return None
    alias_names = {alias.decode("utf-8") for alias in aliases}
    canonical_helpers = canonical_builtin_helper_aliases or {
        "getattr": "getattr",
        "builtins.getattr": "getattr",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        member_node: ast.AST | None = None
        target_node: ast.AST | None = None
        if isinstance(node.func, ast.Call):
            getter = node.func
            getter_name = _simple_reference_name(getter.func)
            if (
                canonical_helpers.get(getter_name or "") != "getattr"
                or getter_name in (shadowed_builtin_helper_names or set())
                or ("." in (getter_name or "") and "builtins.getattr" in (shadowed_builtin_helper_names or set()))
            ):
                continue
            if getter.keywords or len(getter.args) < 2:
                continue
            target_node = getter.args[0]
            member_node = getter.args[1]
        elif isinstance(node.func, ast.Subscript) and isinstance(node.func.value, ast.Call):
            getter = node.func.value
            getter_name = _simple_reference_name(getter.func)
            if (
                canonical_helpers.get(getter_name or "") != "vars"
                or getter_name in (shadowed_builtin_helper_names or set())
                or ("." in (getter_name or "") and "builtins.vars" in (shadowed_builtin_helper_names or set()))
            ):
                continue
            if getter.keywords or len(getter.args) != 1:
                continue
            target_node = getter.args[0]
            member_node = node.func.slice
        else:
            continue
        if target_node is None or member_node is None or not isinstance(target_node, ast.Name):
            continue
        if target_node.id not in alias_names:
            continue
        member_name = _static_getattr_member_name(member_node)
        if isinstance(member_name, str) and re.fullmatch(r"[A-Za-z_]\w*", member_name) is not None:
            return member_name, member_node, target_node.id
    return None


def _line_calls_priority_getattr_alias(line: bytes, aliases: frozenset[bytes]) -> bool:
    return _priority_getattr_alias_member(line, aliases) is not None


def _line_calls_overbounded_runpy_getattr_alias(
    line: bytes,
    aliases: frozenset[bytes],
    shadowed_builtin_helper_names: set[str] | None = None,
    canonical_builtin_helper_aliases: dict[str, str] | None = None,
) -> bool:
    resolved_member = _priority_getattr_alias_member(
        line, aliases, shadowed_builtin_helper_names, canonical_builtin_helper_aliases
    )
    if resolved_member is None or resolved_member[0] not in _RUNPY_PRIORITY_MEMBER_NAMES:
        return False
    pending = [resolved_member[1]]
    parts = 0
    while pending:
        current = pending.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            pending.extend((current.right, current.left))
        elif isinstance(current, ast.Constant) and isinstance(current.value, str):
            parts += 1
            if parts > 256:
                return True
        else:
            return False
    return False


def _static_getattr_member_name(node: ast.AST) -> str | None:
    pieces: list[str] = []
    pending = [node]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 8192:
            return None
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            pieces.append(current.value)
            continue
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            pending.extend((current.right, current.left))
            continue
        return None
    member_name = "".join(pieces)
    return member_name if len(member_name) <= 256 else None


def _line_calls_priority_alias(code_line: bytes, aliases: frozenset[bytes]) -> bool:
    aliases = _referenced_priority_aliases(code_line, aliases)
    return _fragment_has_continued_priority_alias_call(code_line, aliases) or any(
        re.search(
            rb"(?<![A-Za-z0-9_])(?:\(\s*)*"
            + re.escape(alias)
            + rb"(?:\s*\)\s*)*(?:\(|\s*\.\s*[A-Za-z_]\w*(?:\s*\)\s*)*"
            rb"(?:\s*\.\s*__call__(?:\s*\)\s*)*)*\s*\()",
            code_line,
        )
        or re.search(
            rb"(?<![A-Za-z0-9_.])(?:builtins\.)?getattr\s*\(\s*"
            + re.escape(alias)
            + rb"\s*,\s*['\"][A-Za-z_]\w*['\"]\s*\)\s*\(",
            code_line,
        )
        for alias in aliases
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


def _definitely_executed_late_shadow_aliases(
    code_line: bytes, aliases: frozenset[bytes], *, nested: bool
) -> frozenset[bytes]:
    source = textwrap.dedent(code_line.decode("utf-8", errors="ignore"))
    try:
        tree = ast.parse(source)
    except SyntaxError:
        if not source.rstrip().endswith(":"):
            return frozenset()
        try:
            tree = ast.parse(f"{source.rstrip()}\n    pass\n")
        except (SyntaxError, ValueError):
            return frozenset()
    except ValueError:
        return frozenset()
    if len(tree.body) != 1:
        return frozenset()

    statement = tree.body[0]
    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Import, ast.ImportFrom, ast.Delete)):
        return _statement_bound_priority_aliases(statement, aliases)
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        statement_name = statement.name.encode("utf-8")
        return frozenset({statement_name}) if statement_name in aliases else frozenset()
    if not nested and isinstance(statement, (ast.With, ast.AsyncWith)):
        return _statement_bound_priority_aliases(statement, aliases)
    if not nested and isinstance(statement, ast.Expr) and isinstance(statement.value, ast.NamedExpr):
        return _target_bound_priority_aliases(statement.value.target, aliases)
    if (
        isinstance(statement, (ast.For, ast.AsyncFor))
        and isinstance(statement.iter, (ast.List, ast.Tuple, ast.Set))
        and statement.iter.elts
    ):
        return _target_bound_priority_aliases(statement.target, aliases)
    return frozenset()


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
        oversized_priority_candidate = (
            has_priority_marker and bounded is not None and len(candidate) > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES
        )
        if oversized_priority_candidate:
            if selected_priority_candidates >= _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS:
                continue
            candidate, span, real_ranges = _bounded_priority_embedded_python_candidate(
                candidate, span, priority_offsets
            )
            selected_priority_candidates += 1
        if index >= _MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS:
            if not has_priority_marker:
                continue
            if oversized_priority_candidate:
                pass
            elif selected_priority_candidates >= _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS:
                continue
            elif bounded is not None:
                candidate, span, real_ranges = _bounded_priority_embedded_python_candidate(
                    candidate, span, priority_offsets
                )
                selected_priority_candidates += 1
            elif not oversized_priority_candidate:
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
    return (
        structural.count(b"(")
        + structural.count(b"[")
        + structural.count(b"{")
        - structural.count(b")")
        - structural.count(b"]")
        - structural.count(b"}")
    )


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
    for match in _EMBEDDED_PYTHON_STATIC_MEMBER_CONTEXT_START_PATTERN.finditer(line):
        if _is_embedded_top_level_prefix(line[: match.start()]):
            return match.start()
    for match in _EMBEDDED_PYTHON_STATIC_MAPPING_CALL_CONTEXT_START_PATTERN.finditer(line):
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


def _compact_builtins_dict_import_statement(statement: bytes) -> bytes | None:
    dict_imports = _canonical_builtins_dict_import_aliases(statement)
    if not dict_imports:
        return None
    imports = ", ".join(
        "dict" if (alias.asname or "dict") == "dict" else f"dict as {alias.asname}" for alias in dict_imports
    )
    return f"from builtins import {imports}\n".encode()


def _canonical_builtins_dict_import_aliases(statement: bytes) -> list[ast.alias]:
    source, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    def selected_dict_imports(statements: list[ast.stmt]) -> list[ast.alias] | None:
        dict_imports: list[ast.alias] = []
        for child in statements:
            if isinstance(child, ast.Pass):
                continue
            if isinstance(child, ast.Expr):
                try:
                    ast.literal_eval(child.value)
                except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
                    return None
                continue
            if isinstance(child, ast.If):
                try:
                    condition = ast.literal_eval(child.test)
                except (MemoryError, RecursionError, SyntaxError, TypeError, ValueError):
                    return None
                selected_branch = child.body if bool(condition) else child.orelse
                nested_imports = selected_dict_imports(selected_branch)
                if nested_imports is None:
                    return None
                dict_imports.extend(nested_imports)
                continue
            if not isinstance(child, ast.ImportFrom) or child.module != "builtins":
                return None
            dict_imports.extend(alias for alias in child.names if alias.name == "dict")
        return dict_imports

    return selected_dict_imports(tree.body) or []


def _builtins_dict_import_alias_names(statement: bytes) -> set[str]:
    return {alias.asname or "dict" for alias in _canonical_builtins_dict_import_aliases(statement)}


def _is_priority_prefix_context_statement(context: bytes, statement: bytes) -> bool:
    aliases = _priority_import_aliases(context)
    if (
        aliases
        and _runpy_priority_member_update_key(statement, _python_structural_line_bytes(statement), aliases) is not None
    ):
        return True
    if aliases and _runpy_priority_namespace_update_binding(statement, aliases) is not None:
        return True
    if aliases and _runpy_priority_deleted_member_key(statement, aliases) is not None:
        return True
    if aliases:
        descriptor_reference = _simple_late_assignment_value_reference(statement)
        if descriptor_reference is not None and (
            descriptor_reference == "dict"
            or descriptor_reference.startswith("dict.")
            or descriptor_reference.endswith(".dict")
            or descriptor_reference.endswith((".dict.pop", ".dict.__delitem__", ".pop", ".__delitem__"))
        ):
            return True
        alias_names = {alias.decode("utf-8") for alias in aliases}
        saved_delete_aliases = {
            match.group(1).decode("utf-8")
            for match in re.finditer(
                rb"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:(?:builtins\.)?dict|[A-Za-z_]\w*\s*\.\s*__dict__)"
                rb"\s*\.\s*(?:pop|__delitem__)\b",
                context,
            )
        }
        for forwarded_alias, forwarded_dependency in re.findall(
            rb"(?m)^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$",
            context,
        ):
            if forwarded_dependency.decode("utf-8") in saved_delete_aliases:
                saved_delete_aliases.add(forwarded_alias.decode("utf-8"))
        if _simple_late_assignment_value_reference(statement) in saved_delete_aliases:
            return True
        statement_identifiers = _python_identifier_names(statement)
        if not statement_identifiers.isdisjoint(saved_delete_aliases) and not statement_identifiers.isdisjoint(
            alias_names
        ):
            return True
        if not statement_identifiers.isdisjoint(alias_names) and any(
            marker in statement for marker in (b"del ", b".pop", b"__delitem__", b"delattr")
        ):
            return True
    if aliases and (
        re.match(rb"\s*import\s+builtins(?:\s+as\s+[A-Za-z_]\w*)?(?:\s|$)", statement) is not None
        or re.match(rb"\s*from\s+builtins\s+import\s+dict(?:\s+as\s+[A-Za-z_]\w*)?(?:\s|$)", statement) is not None
    ):
        return True
    code_str, _byte_offsets = _decode_utf8_with_byte_offsets(statement)
    try:
        tree = ast.parse(code_str)
    except (SyntaxError, ValueError):
        return False
    if aliases:
        for target, value in _assignment_targets_and_values_in_tree(tree):
            if target and _simple_reference_name(value) in {
                "builtins.getattr",
                "builtins.vars",
                "builtins.setattr",
            }:
                return True
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
        if _is_deferred_annotations_directive(context[index]):
            continue
        defined_names = _statement_defined_names(context[index])
        if defined_names.isdisjoint(later_references):
            return index
        later_references.difference_update(defined_names)
        later_references.update(_statement_referenced_names(context[index]))
    return len(context)


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


def _is_deferred_annotations_directive(statement: bytes) -> bool:
    return b"__future__" in statement and b"annotations" in statement and _source_defers_annotations(statement)


def _extract_priority_prefix_context(data: bytes) -> bytes:
    """Return bounded top-level dangerous imports and aliases from a prefix window."""
    context: list[bytes] = []
    context_size = 0
    active_priority_names: set[str] = set()
    compact_alias_expressions: dict[str, bytes] = {}
    retained_context_names: set[str] = set()
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
        if re.match(rb"\s*if\s+[^:\n]+\s*:\s*$", statement_lines[0]) is not None:
            while index + 1 < len(lines) and lines[index + 1][:1].isspace():
                index += 1
                statement_lines.append(lines[index])

        statement = b"".join(statement_lines).rstrip() + b"\n"
        statement = _compact_builtins_dict_import_statement(statement) or statement
        preserves_deferred_annotations = _is_deferred_annotations_directive(statement) and _source_defers_annotations(
            b"".join(lines[: index + 1])
        )
        compact_forward = _simple_forwarded_alias_assignment(statement)
        compact_priority_statement = False
        if compact_forward is not None:
            target_name, dependency_name, expression = compact_forward
            retained_expression = compact_alias_expressions.get(dependency_name)
            if retained_expression is None and dependency_name in active_priority_names:
                retained_expression = expression
            if retained_expression is not None:
                statement = target_name.encode("utf-8") + b" = " + retained_expression + b"\n"
                compact_alias_expressions[target_name] = retained_expression
                compact_priority_statement = True
            elif dependency_name not in retained_context_names and target_name not in retained_context_names:
                multiline_quote = statement_line_quote
                index += 1
                continue
        else:
            binding_name = _simple_late_binding_name(_python_structural_line_bytes(statement))
            if binding_name is not None:
                compact_alias_expressions.pop(binding_name, None)

        current_context = b"".join(context)
        if (
            not compact_priority_statement
            and not preserves_deferred_annotations
            and not _is_priority_prefix_context_statement(current_context, statement)
            and not _is_prefix_context_shadow_statement(current_context, statement)
        ):
            multiline_quote = statement_line_quote
            index += 1
            continue
        if len(statement) > _MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES:
            index += 1
            continue
        while context and context_size + len(statement) > _MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES:
            drop_index = (
                next(
                    (
                        context_index
                        for context_index, context_statement in enumerate(context)
                        if _simple_forwarded_alias_assignment(context_statement) is not None
                    ),
                    len(context),
                )
                if compact_priority_statement
                else _drop_context_statement_index([*context, statement])
            )
            if drop_index >= len(context):
                break
            context_size -= len(context.pop(drop_index))
        context.append(statement)
        context_size += len(statement)
        if compact_priority_statement:
            defined_names = {target_name}
            priority_aliases: set[str] = set()
        else:
            defined_names = _statement_defined_names(statement)
            priority_aliases = (
                {alias.decode("utf-8") for alias in _priority_import_aliases(statement)}
                if re.match(rb"\s*(?:import|from)\b", statement) is not None
                else set()
            )
        active_priority_names.difference_update(defined_names - priority_aliases)
        active_priority_names.update(priority_aliases)
        retained_context_names.update(defined_names)
        index += 1

    return b"".join(context)


def _embedded_python_extraction_windows(data: bytes) -> list[tuple[bytes, bool]]:
    windows = _embedded_python_scan_windows(data)
    if len(windows) == 1:
        return [(windows[0], False), *_contextual_priority_framed_windows(windows[0])]

    prefix, tail = windows
    extraction_windows = [(prefix, False), *_contextual_priority_framed_windows(prefix), (tail, False)]
    tail_start = len(data) - len(tail)
    contextual_tail_offset = tail.find(b"\n") + 1
    if contextual_tail_offset == 0:
        contextual_tail_offset = len(tail)
    contextual_tail = tail[contextual_tail_offset:]
    prefix_context_end = min(len(prefix), tail_start + contextual_tail_offset)
    import_context = _extract_priority_prefix_context(data[:prefix_context_end])
    if import_context:
        contextual_source = import_context + b"\n" + contextual_tail
        extraction_windows.append((contextual_source, True))
        extraction_windows.extend(_contextual_priority_framed_windows(contextual_source))
        tail_starts = [
            match.start() for match in _EMBEDDED_PYTHON_START_PATTERN.finditer(contextual_tail) if match.start() > 0
        ]
        context_aliases = _priority_import_aliases(import_context)
        priority_tail_starts = set(_tail_starts_for_priority_alias_uses(contextual_tail, tail_starts, context_aliases))
        for priority_offset in _priority_import_offsets(contextual_tail):
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
            extraction_windows.append((import_context + b"\n" + contextual_tail[start:], True))
    return extraction_windows


def _contextual_priority_framed_windows(data: bytes) -> list[tuple[bytes, bool]]:
    first_line_end = data.find(b"\n")
    if first_line_end < 0 or not any(marker in data[first_line_end + 1 :] for marker in (b"\x00", b"\xff")):
        return []
    potential_framed_calls: list[tuple[int, bytes, bytes]] = []
    offset = 0
    multiline_quote: bytes | None = None
    for line in data.splitlines(keepends=True):
        code_start = 0
        while code_start < len(line) and not 0x20 <= line[code_start] < 0x7F:
            code_start += 1
        structural_line = _python_structural_line_bytes(line[code_start:])
        if (
            multiline_quote is None
            and code_start
            and (
                b"(" in structural_line
                or b"=" in structural_line
                or structural_line.rstrip().endswith(b"\\")
                or re.match(rb"\s*(?:if|elif|else)\b", structural_line) is not None
            )
        ):
            potential_framed_calls.append((offset + code_start, line[code_start:], structural_line))
        multiline_quote = _multiline_string_state_after_line(line, multiline_quote)
        offset += len(line)
    if not potential_framed_calls:
        return []
    full_context = _extract_priority_prefix_context(data)
    aliases = _priority_import_aliases(full_context)
    if not aliases:
        return []
    framed_call_starts = [
        start
        for start, raw_line, structural_line in potential_framed_calls
        if (
            _line_calls_priority_alias(structural_line, aliases)
            or _line_calls_priority_getattr_alias(raw_line, aliases)
            or _line_is_continued_priority_alias_piece(structural_line, aliases)
            or _line_starts_continued_priority_getattr(structural_line)
            or _line_parenthesis_delta(structural_line) > 0
            or _runpy_priority_namespace_update_binding(raw_line, aliases) is not None
            or _runpy_priority_member_update_key(raw_line, structural_line, aliases) is not None
            or (
                _simple_late_binding_name(structural_line) is not None
                and not _python_identifier_names(raw_line).isdisjoint({alias.decode("utf-8") for alias in aliases})
            )
            or re.match(rb"\s*(?:if|elif|else)\b", structural_line) is not None
        )
    ]
    priority_starts = _bounded_priority_tail_starts(framed_call_starts)
    contextual_windows: list[tuple[bytes, bool]] = []
    for start in dict.fromkeys(priority_starts):
        import_context = _extract_priority_prefix_context(data[:start])
        if import_context:
            contextual_windows.append((import_context + b"\n" + data[start:], True))
    return contextual_windows


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
    usage_lines, _proved_rule_codes = _priority_alias_usage_lines(tail, aliases, 0)
    for usage_start, _usage_end in usage_lines:
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
    def _looks_like_framed_dangerous_python_source(
        data: bytes,
        prioritized_snippets_by_window: dict[int, list[_EmbeddedPythonCandidate]] | None = None,
    ) -> bool:
        """Return whether a bounded binary blob has parseable dangerous Python framing."""
        if not any(marker in data for marker in _EMBEDDED_PYTHON_START_MARKERS):
            return False
        for window_index, (window, include_full_source) in enumerate(_embedded_python_extraction_windows(data)):
            bounded = window if include_full_source else window[:1000000]
            candidates = _candidate_embedded_python_snippets(bounded, include_full_source=include_full_source)
            prioritized_snippets = _prioritized_embedded_python_snippets(candidates, bounded=bounded)
            if prioritized_snippets_by_window is not None:
                prioritized_snippets_by_window[window_index] = prioritized_snippets
            for candidate, _span, _real_ranges in prioritized_snippets:
                if any(probe in candidate for _name, probe in _PROVEN_HIGH_RISK_CALL_PROBES.values()):
                    return True
                code_str, _byte_offsets = _decode_utf8_with_byte_offsets(candidate)
                parsed_snippet = _parse_embedded_python_snippet(code_str)
                if parsed_snippet is None:
                    continue
                snippet_tree, _parsed_chars = parsed_snippet
                try:
                    if JITScriptDetector._ast_contains_dangerous_python(snippet_tree):
                        return True
                except RecursionError:
                    if any(probe in candidate for _name, probe in _PROVEN_HIGH_RISK_CALL_PROBES.values()):
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
        prioritized_snippets: list[_EmbeddedPythonCandidate] | None = None,
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
        skips_unbounded_ast_prepass = len(bounded) > _MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES and (
            (include_full_source and _PRIORITY_EMBEDDED_PYTHON_IMPORT_PATTERN.search(bounded.lower()) is not None)
            or (not include_full_source and not any(marker in bounded for marker in _EMBEDDED_PYTHON_START_MARKERS))
        )
        if not skips_unbounded_ast_prepass:
            try:
                bounded_tree = ast.parse(textwrap.dedent(bounded.decode("utf-8")))
                bounded_high_risk_calls = _resolve_alias_aware_high_risk_calls(bounded_tree)
            except (SyntaxError, UnicodeDecodeError, ValueError):
                # Binary model blobs commonly contain non-Python framing bytes; keep
                # raw pattern detection active and fall back to extracted snippets.
                bounded_high_risk_calls = None

        selected_snippets = (
            prioritized_snippets
            if prioritized_snippets is not None
            else _prioritized_embedded_python_snippets(matches, bounded=bounded)
        )
        for match, span, real_ranges in selected_snippets:
            for rule_code, (call_name, probe) in _PROVEN_HIGH_RISK_CALL_PROBES.items():
                if probe in match:
                    snippet_high_risk_calls.add((call_name, rule_code))
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
        else:
            prioritized_snippets_by_window: dict[int, list[_EmbeddedPythonCandidate]] = {}
            if self._looks_like_framed_dangerous_python_source(data, prioritized_snippets_by_window):
                for window_index, (window, include_full_source) in enumerate(_embedded_python_extraction_windows(data)):
                    findings.extend(
                        self._extract_and_check_python_code(
                            window,
                            "Generic Python",
                            context,
                            include_full_source=include_full_source,
                            prioritized_snippets=prioritized_snippets_by_window.get(window_index),
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
