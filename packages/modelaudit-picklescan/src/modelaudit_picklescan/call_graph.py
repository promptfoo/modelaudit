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

_CLASS_ENTRYPOINT_METHODS = (
    "__getattribute__",
    "__getattr__",
    "__call__",
    "__iter__",
    "__next__",
    "__enter__",
    "__exit__",
    "__new__",
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
        calls = _calls_for_function(function_name)
        if calls is None:
            continue

        for call in calls[:_MAX_CALLS_PER_FUNCTION]:
            sink = sink_for(call)
            if sink is not None:
                # Tcl dispatch risk depends on the local call argument shape; do not
                # propagate it through wrappers whose arguments may be fixed safely.
                if _is_tcl_interpreter_dispatch_call(sink) and len(path) > 1:
                    continue
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
    aliases = _collect_aliases(tree, module_name, is_package)
    local_defs = _collect_local_defs(tree)
    calls_by_function, class_entrypoints = _collect_function_calls(tree, module_name, is_package, aliases, local_defs)
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


def _collect_function_calls(
    tree: ast.Module,
    module_name: str,
    is_package: bool,
    aliases: dict[str, str],
    local_defs: set[str],
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    calls_by_function: dict[str, tuple[str, ...]] = {}
    class_entrypoints: dict[str, tuple[str, ...]] = {}
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            function_name = f"{module_name}.{statement.name}"
            calls_by_function[function_name] = _calls_in_function(
                statement,
                module_name,
                is_package,
                aliases,
                local_defs,
            )
        elif isinstance(statement, ast.ClassDef):
            class_name = f"{module_name}.{statement.name}"
            method_names: set[str] = set()
            for child in statement.body:
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    function_name = f"{module_name}.{statement.name}.{child.name}"
                    method_names.add(child.name)
                    calls_by_function[function_name] = _calls_in_function(
                        child,
                        module_name,
                        is_package,
                        aliases,
                        local_defs,
                        class_name=statement.name,
                    )
            class_entrypoints[class_name] = tuple(
                f"{class_name}.{method_name}"
                for method_name in _CLASS_ENTRYPOINT_METHODS
                if method_name in method_names
            )
    return calls_by_function, class_entrypoints


def _calls_in_function(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_name: str,
    is_package: bool,
    aliases: dict[str, str],
    local_defs: set[str],
    *,
    class_name: str | None = None,
) -> tuple[str, ...]:
    calls: list[str] = []
    function_aliases = {
        **aliases,
        **_collect_import_aliases(ast.walk(function_node), module_name, is_package),
    }
    parameter_controlled_names: set[str] | None = None
    tcl_command_controlled_names: set[str] | None = None
    for node in ast.walk(function_node):
        if not isinstance(node, ast.Call):
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
            calls.append(resolved)
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
