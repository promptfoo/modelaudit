"""Bounded static call-graph checks for importable Python pickle globals."""

from __future__ import annotations

import ast
import os
import sys
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_MAX_IMPORT_REFERENCES = 32
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_CALL_GRAPH_DEPTH = 4
_MAX_VISITED_FUNCTIONS = 64
_MAX_CALLS_PER_FUNCTION = 128

_RCE_SINK_EXACT = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "builtins.__import__",
        "builtins.compile",
        "builtins.eval",
        "builtins.exec",
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

        resolved = _resolve_function_target(f"{module}.{name}")
        if resolved is None:
            continue
        sink_path = _find_sink_path(resolved)
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

        resolved = _resolve_function_target(f"{module}.{name}")
        if resolved is None:
            continue
        open_path = _find_file_open_path(resolved)
        if open_path is not None:
            openers.append(
                _ImportCallPath(
                    module=module,
                    name=name,
                    import_reference=f"{module}.{name}",
                    call_path=open_path,
                )
            )
        write_path = _find_file_write_path(resolved)
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
        calls = _calls_for_function(function_name)
        if calls is None:
            continue

        for call in calls[:_MAX_CALLS_PER_FUNCTION]:
            sink = sink_for(call)
            if sink is not None:
                return (*path, sink)
            if len(path) > _MAX_CALL_GRAPH_DEPTH:
                continue
            resolved = _resolve_function_target(call)
            if resolved is None or resolved in visited:
                continue
            visited.add(resolved)
            queue.append((resolved, (*path, resolved)))
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
def _resolve_function_target(function_name: str) -> str | None:
    module_name, qualified_name = _split_function_name(function_name)
    if module_name is None:
        return None
    analysis = _analyze_module(module_name)
    if analysis is None:
        return None
    full_name = f"{module_name}.{qualified_name}"
    if full_name in analysis.calls_by_function:
        return full_name
    if "." not in qualified_name:
        alias_target = analysis.aliases.get(qualified_name)
        if alias_target is not None and alias_target != function_name:
            return _resolve_function_target(alias_target)
    return None


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
    aliases = _collect_aliases(tree, module_name, is_package)
    local_defs = _collect_local_defs(tree)
    calls_by_function = _collect_function_calls(tree, module_name, aliases, local_defs)
    return _ModuleAnalysis(
        module=module_name,
        source_path=str(source_path),
        aliases=aliases,
        calls_by_function=calls_by_function,
    )


def _collect_aliases(tree: ast.Module, module_name: str, is_package: bool) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in tree.body:
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


def _collect_function_calls(
    tree: ast.Module,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> dict[str, tuple[str, ...]]:
    calls_by_function: dict[str, tuple[str, ...]] = {}
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            function_name = f"{module_name}.{statement.name}"
            calls_by_function[function_name] = _calls_in_function(statement, module_name, aliases, local_defs)
        elif isinstance(statement, ast.ClassDef):
            for child in statement.body:
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    function_name = f"{module_name}.{statement.name}.{child.name}"
                    calls_by_function[function_name] = _calls_in_function(child, module_name, aliases, local_defs)
    return calls_by_function


def _calls_in_function(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> tuple[str, ...]:
    calls: list[str] = []
    parameter_controlled_names: set[str] | None = None
    for node in ast.walk(function_node):
        if not isinstance(node, ast.Call):
            continue
        resolved = _resolve_expr(node.func, module_name, aliases, local_defs)
        if resolved is not None:
            if _is_file_write_call(resolved):
                if parameter_controlled_names is None:
                    parameter_controlled_names = _parameter_controlled_names(function_node)
                if not _call_uses_parameter_controlled_argument(node, parameter_controlled_names):
                    continue
            calls.append(resolved)
    return tuple(calls)


def _parameter_controlled_names(function_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
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


def _expr_uses_names(expression: ast.AST, names: set[str]) -> bool:
    return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(expression))


def _resolve_expr(
    expression: ast.AST,
    module_name: str,
    aliases: dict[str, str],
    local_defs: set[str],
) -> str | None:
    if isinstance(expression, ast.Name):
        if expression.id in aliases:
            return aliases[expression.id]
        if expression.id in local_defs:
            return f"{module_name}.{expression.id}"
        if expression.id in _BUILTIN_CALLS:
            return f"builtins.{expression.id}"
        return expression.id
    if isinstance(expression, ast.Attribute):
        base = _resolve_expr(expression.value, module_name, aliases, local_defs)
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
