"""Bounded static call-graph checks for importable Python pickle globals."""

from __future__ import annotations

import ast
import os
import sys
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_MAX_IMPORT_REFERENCES = 32
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_CALL_GRAPH_DEPTH = 4
_MAX_VISITED_FUNCTIONS = 64
_MAX_CALLS_PER_FUNCTION = 128
_MAX_ASSIGNMENT_ALIASES = 128
_MAX_FUNCTION_INSTANCE_ALIASES = 32
_MAX_CLASS_INSTANCE_ALIASES = 128
_MAX_INHERITED_CLASS_METHODS = 128
_MAX_WILDCARD_IMPORTS = 16
_MAX_WILDCARD_REEXPORT_DEPTH = 4
_MAX_SHORT_SINK_DEPTH = 2
_CONTROLLED_GETATTR_DISPATCH_SINK = "builtins.getattr.__call__"
_PICKLE_CONSTRUCTOR_ENTRYPOINT_METHODS = ("__new__", "__init__")
_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS = ("__setstate__",)
_INHERITED_CLASS_ENTRYPOINT_METHODS = (
    *_PICKLE_CONSTRUCTOR_ENTRYPOINT_METHODS,
    *_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS,
)

_CLASS_ENTRYPOINT_METHODS = (
    "__getattribute__",
    "__getattr__",
    "__call__",
    "__iter__",
    "__next__",
    "__enter__",
    "__exit__",
    "__new__",
    *_PICKLE_LIFECYCLE_ENTRYPOINT_METHODS,
    "__init__",
)
_RCE_SINK_EXACT = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "builtins.__import__",
        "builtins.compile",
        "builtins.eval",
        "builtins.exec",
        _CONTROLLED_GETATTR_DISPATCH_SINK,
        "dill.load",
        "dill.loads",
        "importlib.import_module",
        "marshal.load",
        "marshal.loads",
        "pickle.load",
        "pickle.loads",
        "runpy.run_module",
        "runpy.run_path",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
        "yaml.load",
        "yaml.unsafe_load",
    }
)
_RCE_SINK_PREFIXES = ("os.exec", "os.posix_spawn", "os.spawn", "os.system", "os.popen")
_FILE_OPEN_SINK_EXACT = frozenset(
    {
        "builtins.open",
        "codecs.open",
        "io.open",
    }
)
_FILE_WRITE_METHODS = frozenset({"write", "writelines"})
_BUILTIN_CALLS = frozenset({"__import__", "compile", "eval", "exec", "open"})
_TCL_CALL_DISPATCH_SUFFIXES = (".tk.call", "._tk.call")
_TCL_EVAL_DISPATCH_SUFFIXES = (".tk.eval", "._tk.eval")
_SUBPROCESS_DISPATCH_SUFFIXES = (
    ".subprocess.Popen",
    ".subprocess.call",
    ".subprocess.check_call",
    ".subprocess.check_output",
    ".subprocess.run",
)
_STATIC_IMPORT_REFERENCE_ALIAS_SUFFIXES = {
    "six.moves.builtins.__import__": "builtins.__import__",
    "six.moves.builtins.compile": "builtins.compile",
    "six.moves.builtins.eval": "builtins.eval",
    "six.moves.builtins.exec": "builtins.exec",
    "six.moves.cPickle.load": "pickle.load",
    "six.moves.cPickle.loads": "pickle.loads",
    "six.moves.getoutput": "subprocess.getoutput",
}
_SHORT_SINK_PRIORITY_TOKENS = (
    "subprocess",
    "popen",
    "spawn",
    "create_io",
    "fork_exec",
)
_SHORT_SINK_SECONDARY_PRIORITY_TOKENS = ("exec", "system", "run")


@dataclass(frozen=True)
class CallGraphFinding:
    module: str
    name: str
    import_reference: str
    sink: str
    call_path: tuple[str, ...]


@dataclass(frozen=True)
class StartupHookWriteFinding:
    opener_module: str
    opener_name: str
    writer_module: str
    writer_name: str
    opener_import_reference: str
    writer_import_reference: str
    open_sink: str
    write_sink: str
    opener_call_path: tuple[str, ...]
    writer_call_path: tuple[str, ...]


@dataclass(frozen=True)
class _ModuleAnalysis:
    module: str
    source_path: str
    aliases: dict[str, str]
    calls_by_function: dict[str, tuple[str, ...]]
    class_entrypoints: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class _WildcardExportSummary:
    direct_names: frozenset[str]
    wildcard_imports: tuple[str, ...]


@dataclass(frozen=True)
class _ClassSourceContext:
    module_name: str
    class_node: ast.ClassDef
    aliases: dict[str, str]
    local_defs: set[str]
    local_class_nodes: dict[str, ast.ClassDef]


@dataclass(frozen=True)
class _InheritedClassMethod:
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module_name: str
    aliases: dict[str, str]
    local_defs: set[str]


@dataclass(frozen=True)
class _ImportCallPath:
    module: str
    name: str
    import_reference: str
    call_path: tuple[str, ...]


def find_dangerous_call_graphs(import_references: object) -> tuple[CallGraphFinding, ...]:
    findings: list[CallGraphFinding] = []
    seen: set[tuple[str, str]] = set()
    for reference in _iter_import_references(import_references):
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if not module or not name or (module, name) in seen:
            continue
        seen.add((module, name))

        entrypoints = _call_graph_entrypoints(f"{module}.{name}")
        if not entrypoints:
            continue
        sink_path = next(
            (path for entrypoint in entrypoints if (path := _find_sink_path(entrypoint)) is not None),
            None,
        )
        if sink_path is None:
            continue

        sink = sink_path[-1]
        findings.append(
            CallGraphFinding(
                module=module,
                name=name,
                import_reference=f"{module}.{name}",
                sink=sink,
                call_path=sink_path,
            )
        )
        if len(findings) >= _MAX_IMPORT_REFERENCES:
            break
    return tuple(findings)


def find_startup_hook_write_call_graphs(import_references: object) -> tuple[StartupHookWriteFinding, ...]:
    openers: list[_ImportCallPath] = []
    writers: list[_ImportCallPath] = []
    seen: set[tuple[str, str]] = set()
    for reference in _iter_import_references(import_references):
        module = str(reference.get("module", ""))
        name = str(reference.get("name", ""))
        if not module or not name or (module, name) in seen:
            continue
        seen.add((module, name))

        entrypoints = _call_graph_entrypoints(f"{module}.{name}")
        if not entrypoints:
            continue
        if any(_find_sink_path(entrypoint) is not None for entrypoint in entrypoints):
            continue
        open_path = next(
            (path for entrypoint in entrypoints if (path := _find_file_open_path(entrypoint)) is not None),
            None,
        )
        if open_path is not None:
            openers.append(
                _ImportCallPath(
                    module=module,
                    name=name,
                    import_reference=f"{module}.{name}",
                    call_path=open_path,
                )
            )
        write_path = next(
            (path for entrypoint in entrypoints if (path := _find_file_write_path(entrypoint)) is not None),
            None,
        )
        if write_path is not None:
            writers.append(
                _ImportCallPath(
                    module=module,
                    name=name,
                    import_reference=f"{module}.{name}",
                    call_path=write_path,
                )
            )

    if not openers or not writers:
        return ()

    findings: list[StartupHookWriteFinding] = []
    seen_pairs: set[tuple[str, str]] = set()
    for opener in openers:
        for writer in writers:
            pair = (opener.import_reference, writer.import_reference)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            findings.append(
                StartupHookWriteFinding(
                    opener_module=opener.module,
                    opener_name=opener.name,
                    writer_module=writer.module,
                    writer_name=writer.name,
                    opener_import_reference=opener.import_reference,
                    writer_import_reference=writer.import_reference,
                    open_sink=opener.call_path[-1],
                    write_sink=writer.call_path[-1],
                    opener_call_path=opener.call_path,
                    writer_call_path=writer.call_path,
                )
            )
            if len(findings) >= _MAX_IMPORT_REFERENCES:
                return tuple(findings)
    return tuple(findings)


def _iter_import_references(import_references: object) -> tuple[dict[str, object], ...]:
    if not isinstance(import_references, list | tuple):
        return ()
    normalized: list[dict[str, object]] = []
    for item in import_references[:_MAX_IMPORT_REFERENCES]:
        if isinstance(item, Mapping):
            normalized.append(dict(item))
    return tuple(normalized)


@lru_cache(maxsize=4096)
def _find_sink_path(start: str) -> tuple[str, ...] | None:
    return _find_matching_call_path(start, _rce_sink)


@lru_cache(maxsize=4096)
def _find_file_open_path(start: str) -> tuple[str, ...] | None:
    return _find_matching_call_path(start, _file_open_sink)


@lru_cache(maxsize=4096)
def _find_file_write_path(start: str) -> tuple[str, ...] | None:
    return _find_matching_call_path(start, _file_write_sink)


def _find_matching_call_path(start: str, sink_for: Callable[[str], str | None]) -> tuple[str, ...] | None:
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(start, (start,))])
    visited = {start}

    while queue and len(visited) <= _MAX_VISITED_FUNCTIONS:
        function_name, path = queue.popleft()
        sink = sink_for(function_name)
        if sink is not None:
            return path
        resolved_function = _resolve_function_target(function_name)
        if resolved_function is not None and resolved_function != function_name:
            sink = sink_for(resolved_function)
            if sink is not None:
                return (*path, sink)

        calls = _calls_for_function(function_name)
        if calls is None:
            continue

        bounded_calls = calls[:_MAX_CALLS_PER_FUNCTION]
        for call in bounded_calls:
            sink = sink_for(call)
            if sink is not None:
                # Tcl dispatch risk depends on the local call argument shape; do not
                # propagate it through wrappers whose arguments may be fixed safely.
                if _is_tcl_interpreter_dispatch_call(sink) and len(path) > 1:
                    continue
                return (*path, sink)

        if sink_for is _rce_sink:
            for call in sorted(bounded_calls, key=_short_sink_call_priority):
                short_sink_path = _find_short_matching_call_path(call, sink_for)
                if short_sink_path is not None:
                    sink = short_sink_path[-1]
                    if _is_tcl_interpreter_dispatch_call(sink):
                        continue
                    return (*path, *short_sink_path)

        for call in bounded_calls:
            if len(path) > _MAX_CALL_GRAPH_DEPTH:
                continue
            resolved = _resolve_function_target(call)
            if resolved is None or resolved in visited:
                continue
            visited.add(resolved)
            queue.append((resolved, (*path, resolved)))
    return None


def _short_sink_call_priority(call_name: str) -> int:
    tail = call_name.rpartition(".")[2].lower()
    if any(token in tail for token in _SHORT_SINK_PRIORITY_TOKENS):
        return 0
    if any(token in tail for token in _SHORT_SINK_SECONDARY_PRIORITY_TOKENS):
        return 1
    return 2


def _find_short_matching_call_path(start: str, sink_for: Callable[[str], str | None]) -> tuple[str, ...] | None:
    queue: deque[tuple[str, tuple[str, ...], int]] = deque([(start, (start,), 0)])
    visited = {start}

    while queue and len(visited) <= _MAX_VISITED_FUNCTIONS:
        function_name, path, depth = queue.popleft()
        calls = _calls_for_function(function_name)
        if calls is None:
            continue
        for call in calls[:_MAX_CALLS_PER_FUNCTION]:
            sink = sink_for(call)
            if sink is not None:
                return (*path, sink)
            if depth >= _MAX_SHORT_SINK_DEPTH:
                continue
            resolved = _resolve_function_target(call)
            if resolved is None or resolved in visited:
                continue
            visited.add(resolved)
            queue.append((resolved, (*path, resolved), depth + 1))
    return None


def _calls_for_function(function_name: str) -> tuple[str, ...] | None:
    resolved = _resolve_function_target(function_name)
    if resolved is None:
        return None
    module_name, qualified_name = _split_function_name(resolved)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    return analysis.calls_by_function.get(f"{module_name}.{qualified_name}")


@lru_cache(maxsize=4096)
def _call_graph_entrypoints(function_name: str) -> tuple[str, ...]:
    resolved = _resolve_function_target(function_name)
    if resolved is not None:
        return (resolved,)

    class_target = _resolve_class_target(function_name)
    if class_target is None:
        return ()
    return _class_entrypoints(class_target)


@lru_cache(maxsize=4096)
def _resolve_function_target(function_name: str) -> str | None:
    alias_target = _static_import_reference_alias(function_name)
    if alias_target is not None and alias_target != function_name:
        return _resolve_alias_function_target(alias_target)

    module_name, qualified_name = _split_function_name(function_name)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    full_name = f"{module_name}.{qualified_name}"
    if full_name in analysis.calls_by_function:
        return full_name
    alias_target = analysis.aliases.get(qualified_name)
    if alias_target is not None and alias_target != function_name:
        return _resolve_alias_function_target(alias_target)
    if "." not in qualified_name:
        wildcard_target = _resolve_wildcard_reexport_alias(module_name, qualified_name)
        if wildcard_target is not None and wildcard_target != function_name:
            return _resolve_alias_function_target(wildcard_target)
    return None


def _resolve_alias_function_target(alias_target: str) -> str | None:
    if (
        _rce_sink(alias_target) is not None
        or _file_open_sink(alias_target) is not None
        or _file_write_sink(alias_target) is not None
    ):
        return alias_target
    return _resolve_function_target(alias_target)


def _static_import_reference_alias(function_name: str) -> str | None:
    for suffix, target in _STATIC_IMPORT_REFERENCE_ALIAS_SUFFIXES.items():
        if function_name == suffix or function_name.endswith(f".{suffix}"):
            return target
    return None


@lru_cache(maxsize=4096)
def _resolve_wildcard_reexport_alias(module_name: str, qualified_name: str) -> str | None:
    return _resolve_wildcard_reexport_alias_inner(module_name, qualified_name, set(), 0)


def _resolve_wildcard_reexport_alias_inner(
    module_name: str,
    qualified_name: str,
    visited: set[str],
    depth: int,
) -> str | None:
    if depth >= _MAX_WILDCARD_REEXPORT_DEPTH or module_name in visited:
        return None
    summary = _wildcard_export_summary(module_name)
    if summary is None:
        return None

    next_visited = {*visited, module_name}
    for imported_module in summary.wildcard_imports[:_MAX_WILDCARD_IMPORTS]:
        if imported_module in next_visited:
            continue
        imported_summary = _wildcard_export_summary(imported_module)
        if imported_summary is None:
            continue
        if qualified_name in imported_summary.direct_names:
            return f"{imported_module}.{qualified_name}"
        nested_target = _resolve_wildcard_reexport_alias_inner(
            imported_module,
            qualified_name,
            next_visited,
            depth + 1,
        )
        if nested_target is not None:
            return nested_target
    return None


@lru_cache(maxsize=4096)
def _wildcard_export_summary(module_name: str) -> _WildcardExportSummary | None:
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return None
    try:
        if source_path.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return None

    is_package = source_path.name == "__init__.py"
    direct_names: set[str] = set()
    wildcard_imports: list[str] = []
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            direct_names.add(statement.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                direct_names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(statement, ast.ImportFrom):
            if statement.module == "__future__":
                continue
            imported_module = _resolve_import_from_module(module_name, is_package, statement.level, statement.module)
            for alias in statement.names:
                if alias.name == "*":
                    if imported_module and len(wildcard_imports) < _MAX_WILDCARD_IMPORTS:
                        wildcard_imports.append(imported_module)
                    continue
                direct_names.add(alias.asname or alias.name)
        elif isinstance(statement, ast.Assign | ast.AnnAssign):
            direct_names.update(_assignment_alias_target_names(statement))
    return _WildcardExportSummary(frozenset(direct_names), tuple(wildcard_imports))


@lru_cache(maxsize=4096)
def _resolve_class_target(function_name: str) -> str | None:
    module_name, qualified_name = _split_function_name(function_name)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    full_name = f"{module_name}.{qualified_name}"
    if full_name in analysis.class_entrypoints:
        return full_name
    if "." not in qualified_name:
        alias_target = analysis.aliases.get(qualified_name)
        if alias_target is not None and alias_target != function_name:
            return _resolve_class_target(alias_target)
        wildcard_target = _resolve_wildcard_reexport_alias(module_name, qualified_name)
        if wildcard_target is not None and wildcard_target != function_name:
            return _resolve_class_target(wildcard_target)
    return None


def _class_entrypoints(class_name: str) -> tuple[str, ...]:
    module_name, qualified_name = _split_function_name(class_name)
    if module_name is None:
        return ()
    analysis = _analyze_module(module_name)
    if analysis is None:
        return ()
    return analysis.class_entrypoints.get(f"{module_name}.{qualified_name}", ())


def _split_function_name(function_name: str) -> tuple[str | None, str]:
    parts = function_name.split(".")
    for index in range(len(parts) - 1, 0, -1):
        module_name = ".".join(parts[:index])
        qualified_name = ".".join(parts[index:])
        analysis = _analyze_module(module_name)
        if analysis is not None:
            return module_name, qualified_name
    return None, function_name


@lru_cache(maxsize=1024)
def _analyze_module(module_name: str) -> _ModuleAnalysis | None:
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return None
    try:
        if source_path.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return None

    is_package = source_path.name == "__init__.py"
    import_aliases = _collect_aliases(tree, module_name, is_package)
    local_defs = _collect_local_defs(tree)
    local_class_entrypoints = _collect_local_class_entrypoints(tree, module_name, import_aliases, local_defs)
    local_class_targets = set(local_class_entrypoints)
    aliases = {
        **import_aliases,
        **_collect_assignment_aliases(
            tree.body,
            module_name,
            import_aliases,
            local_defs,
            local_class_targets,
        ),
    }
    aliases.update(
        _collect_class_instance_default_aliases(
            tree,
            module_name,
            aliases,
            local_defs,
            local_class_targets,
        )
    )
    calls_by_function, class_entrypoints = _collect_function_calls(
        tree,
        module_name,
        is_package,
        aliases,
        local_defs,
        local_class_targets,
        local_class_entrypoints,
    )
    return _ModuleAnalysis(
        module=module_name,
        source_path=str(source_path),
        aliases=aliases,
        calls_by_function=calls_by_function,
        class_entrypoints=class_entrypoints,
    )


def _collect_aliases(tree: ast.Module, module_name: str, is_package: bool) -> dict[str, str]:
    return _collect_import_aliases(tree.body, module_name, is_package)


def _collect_import_aliases(nodes: Iterable[ast.AST], module_name: str, is_package: bool) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in nodes:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom):
            if statement.module == "__future__":
                continue
            imported_module = _resolve_import_from_module(module_name, is_package, statement.level, statement.module)
            for alias in statement.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                aliases[local_name] = f"{imported_module}.{alias.name}" if imported_module else alias.name
    return aliases


def _collect_local_defs(tree: ast.Module) -> set[str]:
    local_defs: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            local_defs.add(statement.name)
    return local_defs


def _collect_local_class_entrypoints(
    tree: ast.Module,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> dict[str, tuple[str, ...]]:
    class_entrypoints: dict[str, tuple[str, ...]] = {}
    local_class_nodes = _local_class_nodes(tree)
    for statement in tree.body:
        if not isinstance(statement, ast.ClassDef):
            continue
        class_name = f"{module_name}.{statement.name}"
        method_names = set(_class_method_nodes(statement))
        inherited_method_names = set(
            _inherited_class_methods(
                statement,
                module_name,
                aliases,
                local_defs,
                local_class_nodes,
            )
        )
        class_entrypoints[class_name] = tuple(
            f"{class_name}.{method_name}"
            for method_name in _CLASS_ENTRYPOINT_METHODS
            if method_name in method_names
            or (method_name in inherited_method_names and method_name in _INHERITED_CLASS_ENTRYPOINT_METHODS)
        )
    return class_entrypoints


def _local_class_nodes(tree: ast.Module) -> dict[str, ast.ClassDef]:
    return {statement.name: statement for statement in tree.body if isinstance(statement, ast.ClassDef)}


def _class_method_nodes(class_node: ast.ClassDef) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {child.name: child for child in class_node.body if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)}


def _inherited_class_methods(
    class_node: ast.ClassDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_nodes: dict[str, ast.ClassDef],
) -> dict[str, _InheritedClassMethod]:
    inherited: dict[str, _InheritedClassMethod] = {}
    direct_method_names = set(_class_method_nodes(class_node))
    visited: set[str] = set()

    def visit_base(context: _ClassSourceContext) -> None:
        base_key = f"{context.module_name}.{context.class_node.name}"
        if base_key in visited or len(inherited) >= _MAX_INHERITED_CLASS_METHODS:
            return
        visited.add(base_key)
        for method_name, method_node in _class_method_nodes(context.class_node).items():
            if method_name in direct_method_names or method_name in inherited:
                continue
            inherited[method_name] = _InheritedClassMethod(
                name=method_name,
                node=method_node,
                module_name=context.module_name,
                aliases=context.aliases,
                local_defs=context.local_defs,
            )
            if len(inherited) >= _MAX_INHERITED_CLASS_METHODS:
                return
        for nested_base in _class_base_targets(
            context.class_node,
            context.module_name,
            context.aliases,
            context.local_defs,
        ):
            nested_context = _class_source_context_for_target(
                nested_base,
                context.module_name,
                context.aliases,
                context.local_defs,
                context.local_class_nodes,
            )
            if nested_context is not None:
                visit_base(nested_context)

    for base in _class_base_targets(class_node, module_name, aliases, local_defs):
        base_context = _class_source_context_for_target(
            base,
            module_name,
            aliases,
            local_defs,
            local_class_nodes,
        )
        if base_context is not None:
            visit_base(base_context)
    return inherited


def _class_source_context_for_target(
    class_target: str,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_nodes: dict[str, ast.ClassDef],
) -> _ClassSourceContext | None:
    local_class_node = _local_class_node_from_target(class_target, module_name, local_class_nodes)
    if local_class_node is not None:
        return _ClassSourceContext(
            module_name=module_name,
            class_node=local_class_node,
            aliases=aliases,
            local_defs=local_defs,
            local_class_nodes=local_class_nodes,
        )
    return _source_class_context(class_target)


@lru_cache(maxsize=4096)
def _source_class_context(class_name: str) -> _ClassSourceContext | None:
    module_name, qualified_name = _split_source_qualified_name(class_name)
    if module_name is None:
        return None
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return None
    try:
        if source_path.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return None

    class_node = _find_qualified_class_def(tree, qualified_name)
    if class_node is None:
        return None
    is_package = source_path.name == "__init__.py"
    aliases = _collect_aliases(tree, module_name, is_package)
    local_defs = _collect_local_defs(tree)
    return _ClassSourceContext(
        module_name=module_name,
        class_node=class_node,
        aliases=aliases,
        local_defs=local_defs,
        local_class_nodes=_local_class_nodes(tree),
    )


def _local_class_node_from_target(
    class_target: str,
    module_name: str,
    local_class_nodes: dict[str, ast.ClassDef],
) -> ast.ClassDef | None:
    prefix = f"{module_name}."
    if not class_target.startswith(prefix):
        return None
    class_name = class_target[len(prefix) :]
    if "." in class_name:
        return None
    return local_class_nodes.get(class_name)


def _collect_assignment_aliases(
    nodes: Iterable[ast.AST],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None = None,
) -> dict[str, str]:
    node_list = tuple(nodes)
    assignment_aliases: dict[str, str] = {}

    changed = True
    while changed and len(assignment_aliases) < _MAX_ASSIGNMENT_ALIASES:
        changed = False
        scoped_aliases = {**aliases, **assignment_aliases}
        for node in node_list:
            resolved = _assignment_alias_value(
                node,
                module_name,
                scoped_aliases,
                local_defs,
                local_class_targets,
                class_name=class_name,
            )
            if resolved is None:
                continue
            for target_name in _assignment_alias_target_names(node):
                if assignment_aliases.get(target_name) == resolved:
                    continue
                assignment_aliases[target_name] = resolved
                changed = True
                if len(assignment_aliases) >= _MAX_ASSIGNMENT_ALIASES:
                    break
    return assignment_aliases


def _assignment_alias_value(
    node: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> str | None:
    value: ast.AST | None
    if isinstance(node, ast.Assign | ast.AnnAssign):
        value = node.value
    else:
        return None
    if value is None:
        return None

    if isinstance(value, ast.Call):
        call_target = _resolve_expr(value.func, module_name, aliases, local_defs, class_name)
        if call_target in local_class_targets:
            return call_target
        return None

    resolved = _resolve_expr(value, module_name, aliases, local_defs, class_name)
    if resolved is None:
        return None
    if _is_local_class_member_alias(resolved, local_class_targets):
        return resolved
    if (
        _rce_sink(resolved) is not None
        or _file_open_sink(resolved) is not None
        or _file_write_sink(resolved) is not None
    ):
        return resolved
    return None


def _assignment_alias_target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Assign):
        targets: set[str] = set()
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.add(target.id)
        return targets
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    return set()


def _is_local_class_member_alias(resolved: str, local_class_targets: set[str]) -> bool:
    return any(
        resolved == class_target or resolved.startswith(f"{class_target}.") for class_target in local_class_targets
    )


def _collect_class_instance_default_aliases(
    tree: ast.Module,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
) -> dict[str, str]:
    instance_aliases: dict[str, str] = {}
    for statement in tree.body:
        if not isinstance(statement, ast.ClassDef):
            continue
        init_node = next(
            (
                child
                for child in statement.body
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) and child.name == "__init__"
            ),
            None,
        )
        if init_node is None:
            continue
        default_aliases = _parameter_default_sink_aliases(
            init_node,
            module_name,
            aliases,
            local_defs,
            local_class_targets,
        )
        if not default_aliases:
            continue
        for node in ast.walk(init_node):
            if not isinstance(node, ast.Assign | ast.AnnAssign):
                continue
            value = node.value
            if not isinstance(value, ast.Name):
                continue
            resolved = default_aliases.get(value.id)
            if resolved is None:
                continue
            for target_name in sorted(_self_attribute_assignment_target_names(node)):
                instance_aliases[f"{statement.name}.{target_name}"] = resolved
                if len(instance_aliases) >= _MAX_CLASS_INSTANCE_ALIASES:
                    return instance_aliases
        for call_node in _iter_call_nodes(init_node):
            if not _is_super_init_call(call_node.func):
                continue
            forwarded_defaults = _super_init_forwarded_sink_defaults(call_node, default_aliases)
            if not forwarded_defaults:
                continue
            for base_target in _class_base_targets(statement, module_name, aliases, local_defs):
                for parameter_name, resolved in forwarded_defaults.items():
                    for target_name in _constructor_parameter_self_attribute_targets(base_target, parameter_name):
                        instance_aliases[f"{statement.name}.{target_name}"] = resolved
                        if len(instance_aliases) >= _MAX_CLASS_INSTANCE_ALIASES:
                            return instance_aliases
    return instance_aliases


def _parameter_default_sink_aliases(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
) -> dict[str, str]:
    default_aliases: dict[str, str] = {}
    positional_args = (*function_node.args.posonlyargs, *function_node.args.args)
    positional_defaults = function_node.args.defaults
    if positional_defaults:
        for arg, default in zip(positional_args[-len(positional_defaults) :], positional_defaults, strict=True):
            if arg.arg in {"self", "cls"}:
                continue
            resolved = _sink_alias_default_target(default, module_name, aliases, local_defs, local_class_targets)
            if resolved is not None:
                default_aliases[arg.arg] = resolved
    for arg, keyword_default in zip(function_node.args.kwonlyargs, function_node.args.kw_defaults, strict=True):
        if keyword_default is None or arg.arg in {"self", "cls"}:
            continue
        resolved = _sink_alias_default_target(keyword_default, module_name, aliases, local_defs, local_class_targets)
        if resolved is not None:
            default_aliases[arg.arg] = resolved
    return default_aliases


def _sink_alias_default_target(
    default: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
) -> str | None:
    resolved = _resolve_expr(default, module_name, aliases, local_defs)
    if resolved is None or _is_local_class_member_alias(resolved, local_class_targets):
        return None
    alias_target = _static_import_reference_alias(resolved) or resolved
    if (
        _rce_sink(alias_target) is not None
        or _file_open_sink(alias_target) is not None
        or _file_write_sink(alias_target) is not None
    ):
        return alias_target
    return None


def _self_attribute_assignment_target_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets: list[ast.AST] = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
    names: set[str] = set()
    for target in targets:
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            names.add(target.attr)
    return names


def _is_super_init_call(expression: ast.AST) -> bool:
    return (
        isinstance(expression, ast.Attribute)
        and expression.attr == "__init__"
        and isinstance(expression.value, ast.Call)
        and isinstance(expression.value.func, ast.Name)
        and expression.value.func.id == "super"
    )


def _super_init_forwarded_sink_defaults(call_node: ast.Call, default_aliases: dict[str, str]) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for keyword in call_node.keywords:
        if keyword.arg is None or not isinstance(keyword.value, ast.Name):
            continue
        resolved = default_aliases.get(keyword.value.id)
        if resolved is not None:
            forwarded[keyword.arg] = resolved
    return forwarded


def _class_base_targets(
    class_node: ast.ClassDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> tuple[str, ...]:
    targets: list[str] = []
    for base in class_node.bases:
        resolved = _resolve_expr(base, module_name, aliases, local_defs)
        if resolved is not None:
            targets.append(resolved)
    return tuple(targets)


@lru_cache(maxsize=4096)
def _constructor_parameter_self_attribute_targets(class_name: str, parameter_name: str) -> tuple[str, ...]:
    module_name, qualified_name = _split_source_qualified_name(class_name)
    if module_name is None:
        return ()
    source_path = _resolve_module_source(module_name)
    if source_path is None:
        return ()
    try:
        if source_path.stat().st_size > _MAX_SOURCE_BYTES:
            return ()
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except Exception:
        return ()

    class_node = _find_qualified_class_def(tree, qualified_name)
    if class_node is None:
        return ()
    init_node = next(
        (
            child
            for child in class_node.body
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) and child.name == "__init__"
        ),
        None,
    )
    if init_node is None:
        return ()

    target_names: set[str] = set()
    for node in ast.walk(init_node):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        value = node.value
        if isinstance(value, ast.Name) and value.id == parameter_name:
            target_names.update(_self_attribute_assignment_target_names(node))
    return tuple(sorted(target_names))


def _split_source_qualified_name(function_name: str) -> tuple[str | None, str]:
    parts = function_name.split(".")
    for index in range(len(parts) - 1, 0, -1):
        module_name = ".".join(parts[:index])
        if _resolve_module_source(module_name) is not None:
            return module_name, ".".join(parts[index:])
    return None, function_name


def _find_qualified_class_def(tree: ast.Module, qualified_name: str) -> ast.ClassDef | None:
    nodes: Iterable[ast.AST] = tree.body
    current: ast.ClassDef | None = None
    for part in qualified_name.split("."):
        current = next((node for node in nodes if isinstance(node, ast.ClassDef) and node.name == part), None)
        if current is None:
            return None
        nodes = current.body
    return current


def _collect_function_calls(
    tree: ast.Module,
    module_name: str,
    is_package: bool,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    local_class_entrypoints: dict[str, tuple[str, ...]],
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    calls_by_function: dict[str, tuple[str, ...]] = {}
    local_class_nodes = _local_class_nodes(tree)
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            function_name = f"{module_name}.{statement.name}"
            calls_by_function[function_name] = _calls_in_function(
                statement,
                module_name,
                is_package,
                aliases,
                local_defs,
                local_class_targets,
                local_class_entrypoints,
            )
        elif isinstance(statement, ast.ClassDef):
            for child in statement.body:
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    function_name = f"{module_name}.{statement.name}.{child.name}"
                    calls_by_function[function_name] = _calls_in_function(
                        child,
                        module_name,
                        is_package,
                        aliases,
                        local_defs,
                        local_class_targets,
                        local_class_entrypoints,
                        class_name=statement.name,
                    )
            for method_name, method in _inherited_class_methods(
                statement,
                module_name,
                aliases,
                local_defs,
                local_class_nodes,
            ).items():
                function_name = f"{module_name}.{statement.name}.{method_name}"
                if function_name in calls_by_function:
                    continue
                inherited_aliases = {
                    **aliases,
                    **method.aliases,
                    **{local_name: f"{method.module_name}.{local_name}" for local_name in method.local_defs},
                }
                calls_by_function[function_name] = _calls_in_function(
                    method.node,
                    module_name,
                    is_package,
                    inherited_aliases,
                    local_defs,
                    local_class_targets,
                    local_class_entrypoints,
                    class_name=statement.name,
                )
    return calls_by_function, local_class_entrypoints


def _calls_in_function(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    is_package: bool,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    local_class_entrypoints: dict[str, tuple[str, ...]],
    *,
    class_name: str | None = None,
) -> tuple[str, ...]:
    calls: list[str] = []
    call_nodes = _iter_call_nodes(function_node)
    function_aliases = {
        **aliases,
        **_collect_import_aliases(ast.walk(function_node), module_name, is_package),
    }
    function_aliases.update(
        _collect_function_instance_aliases(
            function_node,
            call_nodes,
            module_name,
            function_aliases,
            local_defs,
            local_class_targets,
            class_name=class_name,
        )
    )
    parameter_controlled_names: set[str] | None = None
    tcl_command_controlled_names: set[str] | None = None
    dynamic_getattr_callable_names: set[str] | None = None
    may_use_getattr_dispatch = _may_use_getattr_dispatch(call_nodes, function_aliases)
    for node in call_nodes:
        if may_use_getattr_dispatch:
            if parameter_controlled_names is None:
                parameter_controlled_names = _parameter_controlled_names(function_node)
            if _is_controlled_direct_getattr_dispatch(
                node,
                module_name,
                function_aliases,
                local_defs,
                parameter_controlled_names,
                class_name=class_name,
            ):
                calls.append(_CONTROLLED_GETATTR_DISPATCH_SINK)
                continue
            if isinstance(node.func, ast.Name):
                if dynamic_getattr_callable_names is None:
                    dynamic_getattr_callable_names = _controlled_getattr_callable_names(
                        function_node,
                        module_name,
                        function_aliases,
                        local_defs,
                        parameter_controlled_names,
                        class_name=class_name,
                    )
                if node.func.id in dynamic_getattr_callable_names and _call_uses_parameter_controlled_argument(
                    node, parameter_controlled_names
                ):
                    calls.append(_CONTROLLED_GETATTR_DISPATCH_SINK)
                    continue
        resolved = _resolve_expr(node.func, module_name, function_aliases, local_defs, class_name)
        if resolved is not None:
            if _is_tcl_interpreter_dispatch_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if tcl_command_controlled_names is None:
                    tcl_command_controlled_names = _parameter_controlled_tcl_command_names(function_node)
                if not _tcl_dispatch_uses_parameter_controlled_command(
                    node,
                    resolved,
                    parameter_controlled_names,
                    tcl_command_controlled_names,
                ):
                    continue
            if _is_file_write_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if not _call_uses_parameter_controlled_argument(node, parameter_controlled_names):
                    continue
            if _is_object_subprocess_dispatch_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if not _call_uses_parameter_controlled_argument(node, parameter_controlled_names):
                    continue
            class_entrypoints = local_class_entrypoints.get(resolved, ())
            if class_entrypoints:
                calls.extend(class_entrypoints)
                continue
            calls.append(resolved)
    return tuple(calls)


def _may_use_getattr_dispatch(call_nodes: tuple[ast.Call, ...], aliases: Mapping[str, str]) -> bool:
    return any(_call_node_may_be_getattr_call(node, aliases) for node in call_nodes)


def _call_node_may_be_getattr_call(call_node: ast.Call, aliases: Mapping[str, str]) -> bool:
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id == "getattr" or aliases.get(func.id) == "builtins.getattr"
    if isinstance(func, ast.Attribute):
        return func.attr == "getattr"
    return False


def _is_controlled_direct_getattr_dispatch(
    call_node: ast.Call,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    controlled_names: set[str],
    *,
    class_name: str | None,
) -> bool:
    if not isinstance(call_node.func, ast.Call):
        return False
    return _controlled_getattr_call(
        call_node.func,
        module_name,
        aliases,
        local_defs,
        controlled_names,
        class_name=class_name,
    ) and _call_uses_parameter_controlled_argument(call_node, controlled_names)


def _controlled_getattr_callable_names(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    controlled_names: set[str],
    *,
    class_name: str | None,
) -> set[str]:
    callable_names: set[str] = set()
    for node in ast.walk(function_node):
        value: ast.AST | None
        if isinstance(node, ast.Assign):
            value = node.value
            targets = set()
            for target in node.targets:
                targets.update(_assignment_target_names(target))
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = _assignment_target_names(node.target)
        else:
            continue
        if not isinstance(value, ast.Call):
            continue
        if _controlled_getattr_call(
            value,
            module_name,
            aliases,
            local_defs,
            controlled_names,
            class_name=class_name,
        ):
            callable_names.update(targets)
    return callable_names


def _controlled_getattr_call(
    call_node: ast.Call,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    controlled_names: set[str],
    *,
    class_name: str | None,
) -> bool:
    resolved = _resolve_expr(call_node.func, module_name, aliases, local_defs, class_name)
    if resolved not in {"getattr", "builtins.getattr"}:
        return False
    if len(call_node.args) < 2:
        return False
    return _expr_uses_names(call_node.args[1], controlled_names)


def _collect_function_instance_aliases(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    call_nodes: tuple[ast.Call, ...],
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> dict[str, str]:
    receiver_names = _method_call_receiver_names(call_nodes)
    if not receiver_names:
        return {}

    assignment_candidates = tuple(
        (node, target_names)
        for node in ast.walk(function_node)
        if isinstance(node, ast.Assign | ast.AnnAssign)
        and (target_names := _assignment_alias_target_names(node) & receiver_names)
    )
    if not assignment_candidates:
        return {}

    instance_aliases: dict[str, str] = {}
    controlled_names = _parameter_controlled_names(function_node)
    for node, target_names in assignment_candidates:
        if not _function_instance_alias_is_parameter_controlled(node, target_names, call_nodes, controlled_names):
            continue
        resolved = _function_instance_alias_value(
            node,
            module_name,
            {**aliases, **instance_aliases},
            local_defs,
            local_class_targets,
            class_name=class_name,
        )
        if resolved is None:
            continue
        for target_name in sorted(target_names):
            if instance_aliases.get(target_name) == resolved:
                continue
            instance_aliases[target_name] = resolved
            if len(instance_aliases) >= _MAX_FUNCTION_INSTANCE_ALIASES:
                return instance_aliases
    return instance_aliases


def _method_call_receiver_names(call_nodes: tuple[ast.Call, ...]) -> set[str]:
    names: set[str] = set()
    for call_node in call_nodes:
        if isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Name):
            names.add(call_node.func.value.id)
    return names


def _function_instance_alias_is_parameter_controlled(
    node: ast.AST,
    target_names: set[str],
    call_nodes: tuple[ast.Call, ...],
    controlled_names: set[str],
) -> bool:
    value: ast.AST | None
    if isinstance(node, ast.Assign | ast.AnnAssign):
        value = node.value
    else:
        return False
    if isinstance(value, ast.Call) and _call_uses_parameter_controlled_argument(value, controlled_names):
        return True

    return any(
        isinstance(call_node.func, ast.Attribute)
        and isinstance(call_node.func.value, ast.Name)
        and call_node.func.value.id in target_names
        and _call_uses_parameter_controlled_argument(call_node, controlled_names)
        for call_node in call_nodes
    )


def _function_instance_alias_value(
    node: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    local_class_targets: set[str],
    *,
    class_name: str | None,
) -> str | None:
    value: ast.AST | None
    if isinstance(node, ast.Assign | ast.AnnAssign):
        value = node.value
    else:
        return None
    if not isinstance(value, ast.Call):
        return None

    call_target = _resolve_expr(value.func, module_name, aliases, local_defs, class_name)
    if call_target in local_class_targets:
        return call_target
    if call_target is None or call_target.startswith(f"{module_name}."):
        return None
    return _resolve_class_target(call_target)


def _iter_call_nodes(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.Call, ...]:
    calls: list[ast.Call] = []

    class _CallVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            calls.append(node)
            self.generic_visit(node)

    _CallVisitor().visit(function_node)
    return tuple(calls)


def _parameter_controlled_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    controlled = _initial_parameter_controlled_names(function_node)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(function_node):
            target_names: set[str]
            if isinstance(node, ast.Assign):
                if not _expr_uses_names(node.value, controlled):
                    continue
                target_names = set()
                for target in node.targets:
                    target_names.update(_assignment_target_names(target))
            elif isinstance(node, ast.AnnAssign):
                if node.value is None or not _expr_uses_names(node.value, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            elif isinstance(node, ast.For | ast.AsyncFor):
                if not _expr_uses_names(node.iter, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            else:
                continue
            before = len(controlled)
            controlled.update(target_names)
            changed = changed or len(controlled) != before
    return controlled


def _initial_parameter_controlled_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    controlled = {
        arg.arg
        for arg in (
            *function_node.args.posonlyargs,
            *function_node.args.args,
            *function_node.args.kwonlyargs,
        )
        if arg.arg not in {"self", "cls"}
    }
    if function_node.args.vararg is not None:
        controlled.add(function_node.args.vararg.arg)
    if function_node.args.kwarg is not None:
        controlled.add(function_node.args.kwarg.arg)

    return controlled


def _parameter_controlled_tcl_command_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    controlled = _initial_parameter_controlled_names(function_node)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(function_node):
            target_names: set[str]
            if isinstance(node, ast.Assign):
                if not _tcl_call_command_uses_names(node.value, controlled):
                    continue
                target_names = set()
                for target in node.targets:
                    target_names.update(_assignment_target_names(target))
            elif isinstance(node, ast.AnnAssign):
                if node.value is None or not _tcl_call_command_uses_names(node.value, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            elif isinstance(node, ast.For | ast.AsyncFor):
                if not _tcl_call_command_uses_names(node.iter, controlled):
                    continue
                target_names = _assignment_target_names(node.target)
            else:
                continue
            before = len(controlled)
            controlled.update(target_names)
            changed = changed or len(controlled) != before
    return controlled


def _assignment_target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in target.elts:
            names.update(_assignment_target_names(element))
        return names
    return set()


def _call_uses_parameter_controlled_argument(call_node: ast.Call, controlled_names: set[str]) -> bool:
    return any(_expr_uses_names(argument, controlled_names) for argument in call_node.args) or any(
        _expr_uses_names(keyword.value, controlled_names) for keyword in call_node.keywords
    )


def _tcl_dispatch_uses_parameter_controlled_command(
    call_node: ast.Call,
    call_name: str,
    controlled_names: set[str],
    command_controlled_names: set[str],
) -> bool:
    if call_name.endswith(_TCL_EVAL_DISPATCH_SUFFIXES):
        return _call_uses_parameter_controlled_argument(call_node, controlled_names)
    if not call_node.args:
        return False
    return _tcl_call_command_uses_names(call_node.args[0], command_controlled_names)


def _tcl_call_command_uses_names(expression: ast.AST, names: set[str]) -> bool:
    if isinstance(expression, ast.Starred):
        return _expr_uses_names(expression.value, names)
    if isinstance(expression, ast.Tuple | ast.List):
        if not expression.elts:
            return False
        return _tcl_call_command_uses_names(expression.elts[0], names)
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
        return _tcl_call_command_uses_names(expression.left, names)
    if isinstance(expression, ast.Call) and _is_flatten_call(expression):
        return bool(expression.args) and _tcl_call_command_uses_names(expression.args[0], names)
    return _expr_uses_names(expression, names)


def _is_flatten_call(expression: ast.Call) -> bool:
    if isinstance(expression.func, ast.Name):
        return expression.func.id == "_flatten"
    if isinstance(expression.func, ast.Attribute):
        return expression.func.attr == "_flatten"
    return False


def _expr_uses_names(expression: ast.AST, names: set[str]) -> bool:
    return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(expression))


def _resolve_expr(
    expression: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
    class_name: str | None = None,
) -> str | None:
    if isinstance(expression, ast.Name):
        if class_name is not None and expression.id in {"self", "cls"}:
            return f"{module_name}.{class_name}"
        if expression.id in aliases:
            return aliases[expression.id]
        if expression.id in local_defs:
            return f"{module_name}.{expression.id}"
        if expression.id in _BUILTIN_CALLS:
            return f"builtins.{expression.id}"
        return expression.id
    if isinstance(expression, ast.Attribute):
        base = _resolve_expr(expression.value, module_name, aliases, local_defs, class_name)
        if base is not None:
            return f"{base}.{expression.attr}"
    return None


def _resolve_import_from_module(module_name: str, is_package: bool, level: int, imported_module: str | None) -> str:
    if level == 0:
        return imported_module or ""
    package = module_name if is_package else module_name.rpartition(".")[0]
    package_parts = package.split(".") if package else []
    if level > 1:
        package_parts = package_parts[: max(len(package_parts) - (level - 1), 0)]
    parts = [*package_parts]
    if imported_module:
        parts.extend(imported_module.split("."))
    return ".".join(part for part in parts if part)


@lru_cache(maxsize=1024)
def _resolve_module_source(module_name: str) -> Path | None:
    parts = module_name.split(".")
    if not parts or any(not part or "/" in part or "\\" in part for part in parts):
        return None
    for entry in sys.path:
        root = Path(entry or os.getcwd())
        current = root
        for index, part in enumerate(parts):
            is_last = index == len(parts) - 1
            if is_last:
                module_file = current / f"{part}.py"
                if module_file.is_file():
                    return module_file
                package_file = current / part / "__init__.py"
                if package_file.is_file():
                    return package_file
            else:
                current = current / part
                if not current.is_dir():
                    break
    return None


def _rce_sink(call_name: str) -> str | None:
    if call_name in _RCE_SINK_EXACT:
        return call_name
    if call_name.startswith(_RCE_SINK_PREFIXES):
        return call_name
    if _is_tcl_interpreter_dispatch_call(call_name):
        return call_name
    if _is_object_subprocess_dispatch_call(call_name):
        return call_name
    return None


def _file_open_sink(call_name: str) -> str | None:
    if call_name in _FILE_OPEN_SINK_EXACT:
        return call_name
    return None


def _file_write_sink(call_name: str) -> str | None:
    if _is_file_write_call(call_name):
        return call_name
    return None


def _is_file_write_call(call_name: str) -> bool:
    return call_name.rpartition(".")[2] in _FILE_WRITE_METHODS


def _is_tcl_interpreter_dispatch_call(call_name: str) -> bool:
    return call_name.endswith(_TCL_CALL_DISPATCH_SUFFIXES) or call_name.endswith(_TCL_EVAL_DISPATCH_SUFFIXES)


def _is_object_subprocess_dispatch_call(call_name: str) -> bool:
    return call_name.endswith(_SUBPROCESS_DISPATCH_SUFFIXES)
