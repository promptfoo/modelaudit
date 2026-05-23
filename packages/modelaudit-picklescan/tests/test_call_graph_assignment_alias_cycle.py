"""Regression: assignment-alias fixpoint must terminate on oscillating binds.

A module that binds the same name in both branches of an ``if``/``else``
(e.g. the ``imaplib``/``http.server``/``nntplib`` stdlib ``__main__`` blocks)
makes ``_collect_assignment_aliases`` oscillate the alias between two values
without ever growing the dict. The dict-size guard never trips, so the
fixpoint loop spins forever and the whole scan hangs (GitHub issue #1247).
"""

from __future__ import annotations

import ast
import threading
from collections.abc import Iterable
from importlib.util import find_spec

import pytest

from modelaudit_picklescan import PickleReport, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import (
    CallGraphFinding,
    StartupHookWriteFinding,
    _CallGraphAnalysisLimitError,
    _collect_assignment_aliases,
    _collect_local_defs,
    _first_matching_path,
    _module_level_statements,
    _safe_call_graph_entrypoints,
    find_dangerous_call_graphs,
    find_startup_hook_write_call_graphs,
)

_OSCILLATING_MODULE_SOURCE = """\
class A:
    pass


class B:
    pass


if cond:
    m = A()
else:
    m = B()
"""

_DEPENDENT_CYCLE_SOURCE = """\
class A:
    pass


class B:
    pass


a = A()
a = b
b = B()
b = a
c = a
"""

_SEQUENTIAL_REBIND_SOURCE = """\
class A:
    pass


class B:
    pass


m = A()
m = B()
"""

_TRY_REBIND_SOURCE = """\
class A:
    pass


class B:
    pass


try:
    m = A()
    operation()
except Exception:
    m = B()
"""

_LOOP_ELSE_REBIND_SOURCE = """\
class A:
    pass


class B:
    pass


for value in values:
    m = A()
    break
else:
    m = B()
"""

_LOOP_ELSE_COMPLETION_SOURCE = """\
class A:
    pass


class B:
    pass


for value in values:
    m = A()
else:
    m = B()
"""

_LOOP_MATCHING_TERMINAL_REBIND_SOURCE = """\
class A:
    pass


class Final:
    pass


m = A()
for value in values:
    m = Final()
    break
else:
    m = Final()
exposed = m
"""

_LOOP_EARLY_BREAK_BEFORE_TERMINAL_REBIND_SOURCE = """\
class A:
    pass


class Final:
    pass


m = A()
for value in values:
    if cond:
        break
    m = Final()
    break
else:
    m = Final()
exposed = m
"""

_UNCONDITIONAL_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
else:
    m = B()
m = Final()
"""

_READ_BEFORE_UNCONDITIONAL_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
else:
    m = B()
exposed = m
m = Final()
"""

_CALL_READ_BEFORE_UNCONDITIONAL_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
else:
    m = B()
exposed = m()
m = Final()
"""

_TERMINATING_ALIAS_BRANCH_SOURCE = """\
class A:
    pass


class B:
    pass


if cond:
    m = A()
    consumed = m
    raise ImportError
else:
    m = B()
exposed = m
"""

_OVERWRITE_BEFORE_READ_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
else:
    m = B()
m = Final()
exposed = m
"""

_ONE_SIDED_REBIND_SOURCE = """\
class A:
    pass


class B:
    pass


m = A()
if cond:
    m = B()
exposed = m
"""

_NONEXHAUSTIVE_MATCH_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


m = A()
match value:
    case 1:
        m = B()
    case 2:
        m = B()
exposed = m
"""

_CONDITIONALLY_REBOUND_TERMINAL_DEPENDENCY_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    F = A
else:
    F = B
if cond:
    m = F()
else:
    m = F()
F = Final
exposed = m
"""

_BRANCH_READ_BEFORE_MATCHING_TERMINAL_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
    exposed = m
    m = Final()
else:
    m = B()
    exposed = m
    m = Final()
"""

_MATCHING_BRANCH_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
    m = Final()
else:
    m = B()
    m = Final()
exposed = m
"""

_MATCHING_BRANCH_EPILOGUE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    m = A()
    m = Final()
    log()
else:
    m = B()
    m = Final()
    log()
exposed = m
"""

_RESOLVED_MATCHING_BRANCH_OVERWRITE_SOURCE = """\
class Final:
    pass


F = Final
if cond:
    m = F()
else:
    m = Final()
exposed = m
"""

_SAME_LINE_RESOLVED_MATCHING_BRANCH_OVERWRITE_SOURCE = """\
class Final:
    pass


if cond:
    F = Final; m = F()
else:
    F = Final; m = F()
exposed = m
"""

_OVERWRITTEN_TERMINAL_DEPENDENCY_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


if cond:
    F = A
else:
    F = B
F = Final
if cond:
    m = F()
else:
    m = F()
exposed = m
"""

_MUTUALLY_DEPENDENT_TERMINAL_ALIAS_SOURCE = """\
class Final:
    pass


if cond:
    m = Final()
    exposed = m
else:
    exposed = Final()
    m = exposed
"""

_TERMINATING_ALTERNATIVE_SOURCE = """\
class Final:
    pass


if cond:
    m = Final()
else:
    raise ImportError
exposed = m
"""

_SCOPED_TERMINAL_DEPENDENCY_SOURCE = """\
class Final:
    pass


if cond:
    F = first_value
else:
    F = second_value
if cond:
    m = Final([F for F in values])
else:
    m = Final(lambda F: F)
exposed = m
"""

_MATCHING_ONE_SIDED_REBIND_SOURCE = """\
class Final:
    pass


m = Final()
if cond:
    m = Final()
exposed = m
"""

_UNBOUND_ONE_SIDED_REBIND_SOURCE = """\
class Final:
    pass


if cond:
    m = Final()
exposed = m
"""

_TERMINATING_UNRELATED_ALIAS_SOURCE = """\
class A:
    pass


class Final:
    pass


if cond:
    unused = A()
    raise ImportError
else:
    m = Final()
exposed = m
"""

_MATCHING_TRY_EXCEPT_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


try:
    m = A()
    m = Final()
except Exception:
    m = B()
    m = Final()
exposed = m
"""

_EXHAUSTIVE_MATCH_OVERWRITE_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


match value:
    case 1:
        m = A()
        m = Final()
        exposed = m
    case _:
        m = B()
        m = Final()
        exposed = m
"""

_TRY_FINALLY_NO_HANDLER_SOURCE = """\
class Final:
    pass


try:
    m = Final()
finally:
    cleanup()
exposed = m
"""

_TRY_FINALLY_REBIND_SOURCE = """\
class A:
    pass


class B:
    pass


class Final:
    pass


try:
    m = A()
except Exception:
    m = B()
finally:
    m = Final()
"""


def _run_with_timeout(target: object, timeout: float = 10.0) -> None:
    thread = threading.Thread(target=target)  # type: ignore[arg-type]
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pytest.fail(f"call-graph analysis did not terminate within {timeout}s")


@pytest.mark.parametrize(
    "source",
    (
        _OSCILLATING_MODULE_SOURCE,
        _TRY_REBIND_SOURCE,
        _LOOP_ELSE_REBIND_SOURCE,
        _LOOP_EARLY_BREAK_BEFORE_TERMINAL_REBIND_SOURCE,
        _READ_BEFORE_UNCONDITIONAL_OVERWRITE_SOURCE,
        _CALL_READ_BEFORE_UNCONDITIONAL_OVERWRITE_SOURCE,
        _TERMINATING_ALIAS_BRANCH_SOURCE,
        _ONE_SIDED_REBIND_SOURCE,
        _NONEXHAUSTIVE_MATCH_OVERWRITE_SOURCE,
        _CONDITIONALLY_REBOUND_TERMINAL_DEPENDENCY_SOURCE,
        _BRANCH_READ_BEFORE_MATCHING_TERMINAL_OVERWRITE_SOURCE,
    ),
    ids=(
        "if-else",
        "try-except",
        "loop-else",
        "loop-early-break",
        "read-before-overwrite",
        "call-read-before-overwrite",
        "terminating-alias-branch",
        "one-sided-rebind",
        "match-no-default",
        "conditional-terminal-dependency",
        "branch-read-before-terminal-overwrite",
    ),
)
def test_collect_assignment_aliases_fails_closed_on_stable_branch_rebind(source: str) -> None:
    tree = ast.parse(source)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    local_class_targets = {"testmod.A", "testmod.B", "testmod.Final"}

    result: dict[str, bool] = {}

    def _collect() -> None:
        with pytest.raises(_CallGraphAnalysisLimitError, match="ambiguous conditional rebinding"):
            _collect_assignment_aliases(
                statements,
                "testmod",
                {},
                local_defs,
                local_class_targets,
            )
        result["limited"] = True

    _run_with_timeout(_collect)

    assert result == {"limited": True}


@pytest.mark.parametrize(
    ("source", "expected_target"),
    (
        (_SEQUENTIAL_REBIND_SOURCE, "testmod.B"),
        (_LOOP_ELSE_COMPLETION_SOURCE, "testmod.B"),
        (_UNCONDITIONAL_OVERWRITE_SOURCE, "testmod.Final"),
        (_TRY_FINALLY_REBIND_SOURCE, "testmod.Final"),
    ),
    ids=("sequential", "loop-else-completion", "unconditional-overwrite", "try-finally-overwrite"),
)
def test_collect_assignment_aliases_converges_on_deterministic_final_rebind(
    source: str,
    expected_target: str,
) -> None:
    tree = ast.parse(source)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    local_class_targets = {"testmod.A", "testmod.B", "testmod.Final"}

    aliases = _collect_assignment_aliases(
        statements,
        "testmod",
        {},
        local_defs,
        local_class_targets,
    )

    assert aliases["m"] == expected_target


def test_collect_assignment_aliases_allows_alias_read_after_deterministic_overwrite() -> None:
    tree = ast.parse(_OVERWRITE_BEFORE_READ_SOURCE)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)

    aliases = _collect_assignment_aliases(
        statements,
        "testmod",
        {},
        local_defs,
        {"testmod.A", "testmod.B", "testmod.Final"},
    )

    assert aliases["m"] == "testmod.Final"
    assert aliases["exposed"] == "testmod.Final"


@pytest.mark.parametrize(
    "source",
    (
        _MATCHING_BRANCH_OVERWRITE_SOURCE,
        _MATCHING_BRANCH_EPILOGUE_SOURCE,
        _RESOLVED_MATCHING_BRANCH_OVERWRITE_SOURCE,
        _SAME_LINE_RESOLVED_MATCHING_BRANCH_OVERWRITE_SOURCE,
        _OVERWRITTEN_TERMINAL_DEPENDENCY_SOURCE,
        _MUTUALLY_DEPENDENT_TERMINAL_ALIAS_SOURCE,
        _TERMINATING_ALTERNATIVE_SOURCE,
        _SCOPED_TERMINAL_DEPENDENCY_SOURCE,
        _MATCHING_ONE_SIDED_REBIND_SOURCE,
        _UNBOUND_ONE_SIDED_REBIND_SOURCE,
        _TERMINATING_UNRELATED_ALIAS_SOURCE,
        _MATCHING_TRY_EXCEPT_OVERWRITE_SOURCE,
        _EXHAUSTIVE_MATCH_OVERWRITE_SOURCE,
        _LOOP_MATCHING_TERMINAL_REBIND_SOURCE,
        _TRY_FINALLY_NO_HANDLER_SOURCE,
    ),
    ids=(
        "if-else",
        "if-expression-epilogue",
        "if-semantic-resolution",
        "if-same-line-semantic-resolution",
        "overwritten-terminal-dependency",
        "mutually-dependent-terminal-alias",
        "terminating-alternative",
        "scoped-terminal-dependency",
        "matching-one-sided-rebind",
        "unbound-one-sided-rebind",
        "terminating-unrelated-alias",
        "try-except",
        "exhaustive-match",
        "loop-terminal-break",
        "try-finally-no-handler",
    ),
)
def test_collect_assignment_aliases_allows_matching_terminal_branch_overwrites(source: str) -> None:
    tree = ast.parse(source)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)

    aliases = _collect_assignment_aliases(
        statements,
        "testmod",
        {},
        local_defs,
        {"testmod.A", "testmod.B", "testmod.Final"},
    )

    assert aliases["m"] == "testmod.Final"
    assert aliases["exposed"] == "testmod.Final"


def test_collect_assignment_aliases_fails_closed_on_cyclic_dependency_propagation() -> None:
    tree = ast.parse(_DEPENDENT_CYCLE_SOURCE)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    local_class_targets = {"testmod.A", "testmod.B"}

    result: dict[str, bool] = {}

    def _collect() -> None:
        with pytest.raises(_CallGraphAnalysisLimitError, match="entered a propagation cycle"):
            _collect_assignment_aliases(
                statements,
                "testmod",
                {},
                local_defs,
                local_class_targets,
            )
        result["limited"] = True

    _run_with_timeout(_collect)

    assert result == {"limited": True}


def test_collect_assignment_aliases_fails_closed_on_long_period_cycles() -> None:
    periods = (7, 11, 13, 17, 19)
    source_lines: list[str] = []
    local_class_targets: set[str] = set()
    for ring_index, period in enumerate(periods):
        for position in range(period):
            class_name = f"Ring{ring_index}Class{position}"
            variable_name = f"ring_{ring_index}_{position}"
            source_lines.extend((f"class {class_name}:", "    pass", "", f"{variable_name} = {class_name}()", ""))
            local_class_targets.add(f"testmod.{class_name}")
        for position in range(period):
            next_position = (position + 1) % period
            source_lines.append(f"ring_{ring_index}_{position} = ring_{ring_index}_{next_position}")

    tree = ast.parse("\n".join(source_lines))
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    result: dict[str, bool] = {}

    def _collect() -> None:
        with pytest.raises(_CallGraphAnalysisLimitError):
            _collect_assignment_aliases(
                statements,
                "testmod",
                {},
                local_defs,
                local_class_targets,
            )
        result["limited"] = True

    _run_with_timeout(_collect)

    assert result == {"limited": True}


def test_assignment_alias_limit_is_not_hidden_by_safe_entrypoint_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_limit(_function_name: str) -> tuple[str, ...]:
        raise _CallGraphAnalysisLimitError("assignment alias limit")

    monkeypatch.setattr("modelaudit_picklescan.call_graph._call_graph_entrypoints", _raise_limit)
    _safe_call_graph_entrypoints.cache_clear()

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit"):
        _safe_call_graph_entrypoints("long_period.module")


def test_assignment_alias_limit_is_not_hidden_by_path_search() -> None:
    def _raise_limit(_entrypoint: str) -> tuple[str, ...] | None:
        raise _CallGraphAnalysisLimitError("assignment alias limit")

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit"):
        _first_matching_path(("wrapper.entrypoint",), _raise_limit)


def test_assignment_alias_limit_retains_later_matching_entrypoint_path() -> None:
    def _path(entrypoint: str) -> tuple[str, ...] | None:
        if entrypoint == "constructor.__new__":
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return ("constructor.__init__", "builtins.exec")

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        _first_matching_path(("constructor.__new__", "constructor.__init__"), _path)

    assert exc_info.value.partial_path == ("constructor.__init__", "builtins.exec")


def test_assignment_alias_limit_preserves_prior_call_graph_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    references = (
        {"module": "dangerous", "name": "entry"},
        {"module": "limited", "name": "entry"},
    )

    def _iter_references(
        _import_references: object,
        _callable_references: tuple[dict[str, object], ...],
        _invoked_references: set[tuple[str, str]],
    ) -> tuple[dict[str, str], ...]:
        return references

    def _entrypoints(module: str, name: str, _reference: dict[str, object]) -> tuple[str, ...]:
        return (f"{module}.{name}",)

    def _path(entrypoints: Iterable[str], _path_for: object) -> tuple[str, ...] | None:
        if tuple(entrypoints) == ("limited.entry",):
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return ("dangerous.entry", "builtins.exec")

    monkeypatch.setattr("modelaudit_picklescan.call_graph._iter_call_graph_references", _iter_references)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._call_graph_entrypoints_for_reference", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._first_matching_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_dangerous_call_graphs(())

    assert exc_info.value.partial_findings == (
        CallGraphFinding(
            module="dangerous",
            name="entry",
            import_reference="dangerous.entry",
            sink="builtins.exec",
            call_path=("dangerous.entry", "builtins.exec"),
        ),
    )


def test_assignment_alias_limit_preserves_later_call_graph_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    references = (
        {"module": "limited", "name": "entry"},
        {"module": "dangerous", "name": "entry"},
    )

    def _iter_references(
        _import_references: object,
        _callable_references: tuple[dict[str, object], ...],
        _invoked_references: set[tuple[str, str]],
    ) -> tuple[dict[str, str], ...]:
        return references

    def _entrypoints(module: str, name: str, _reference: dict[str, object]) -> tuple[str, ...]:
        return (f"{module}.{name}",)

    def _path(entrypoints: Iterable[str], _path_for: object) -> tuple[str, ...] | None:
        if tuple(entrypoints) == ("limited.entry",):
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return ("dangerous.entry", "builtins.exec")

    monkeypatch.setattr("modelaudit_picklescan.call_graph._iter_call_graph_references", _iter_references)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._call_graph_entrypoints_for_reference", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._first_matching_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_dangerous_call_graphs(())

    assert exc_info.value.partial_findings == (
        CallGraphFinding(
            module="dangerous",
            name="entry",
            import_reference="dangerous.entry",
            sink="builtins.exec",
            call_path=("dangerous.entry", "builtins.exec"),
        ),
    )


def test_assignment_alias_limit_preserves_invoked_finding_after_sink_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = {"module": "invoked", "name": "entry"}
    path_calls = 0

    def _iter_references(
        _import_references: object,
        _callable_references: tuple[dict[str, object], ...],
        _invoked_references: set[tuple[str, str]],
    ) -> tuple[dict[str, str], ...]:
        return (reference,)

    def _entrypoints(module: str, name: str, _reference: dict[str, object]) -> tuple[str, ...]:
        return (f"{module}.{name}",)

    def _path(_entrypoints: Iterable[str], _path_for: object) -> tuple[str, ...] | None:
        nonlocal path_calls
        path_calls += 1
        if path_calls == 1:
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return ("invoked.entry", "builtins.exec")

    monkeypatch.setattr("modelaudit_picklescan.call_graph._iter_call_graph_references", _iter_references)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._call_graph_entrypoints_for_reference", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._first_matching_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_dangerous_call_graphs(
            (),
            ({"module": "invoked", "name": "entry", "positional_arg_count": 1},),
        )

    assert exc_info.value.partial_findings == (
        CallGraphFinding(
            module="invoked",
            name="entry",
            import_reference="invoked.entry",
            sink="builtins.exec",
            call_path=("invoked.entry", "builtins.exec"),
        ),
    )


def test_assignment_alias_limit_preserves_later_entrypoint_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = {"module": "constructor", "name": "Type"}

    def _iter_references(
        _import_references: object,
        _callable_references: tuple[dict[str, object], ...],
        _invoked_references: set[tuple[str, str]],
    ) -> tuple[dict[str, str], ...]:
        return (reference,)

    def _entrypoints(_module: str, _name: str, _reference: dict[str, object]) -> tuple[str, ...]:
        return ("constructor.Type.__new__", "constructor.Type.__init__")

    def _path(entrypoint: str) -> tuple[str, ...] | None:
        if entrypoint.endswith(".__new__"):
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return ("constructor.Type.__init__", "builtins.exec")

    monkeypatch.setattr("modelaudit_picklescan.call_graph._iter_call_graph_references", _iter_references)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._call_graph_entrypoints_for_reference", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._find_sink_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_dangerous_call_graphs(())

    assert exc_info.value.partial_findings == (
        CallGraphFinding(
            module="constructor",
            name="Type",
            import_reference="constructor.Type",
            sink="builtins.exec",
            call_path=("constructor.Type.__init__", "builtins.exec"),
        ),
    )


def test_assignment_alias_limit_preserves_prior_startup_hook_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    references = (
        {"module": "opener", "name": "entry"},
        {"module": "writer", "name": "entry"},
        {"module": "limited", "name": "entry"},
    )

    def _entrypoints(function_name: str) -> tuple[str, ...]:
        if function_name == "limited.entry":
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return (function_name,)

    def _path(entrypoints: Iterable[str], path_for: object) -> tuple[str, ...] | None:
        entrypoint = next(iter(entrypoints))
        path_name = getattr(path_for, "__name__", "")
        if path_name == "_find_file_open_path" and entrypoint == "opener.entry":
            return ("opener.entry", "builtins.open")
        if path_name == "_find_file_write_path" and entrypoint == "writer.entry":
            return ("writer.entry", "binary_file.write")
        return None

    monkeypatch.setattr("modelaudit_picklescan.call_graph._safe_call_graph_entrypoints", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._first_matching_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_startup_hook_write_call_graphs(references)

    assert exc_info.value.partial_startup_hook_write_findings == (
        StartupHookWriteFinding(
            opener_module="opener",
            opener_name="entry",
            writer_module="writer",
            writer_name="entry",
            opener_import_reference="opener.entry",
            writer_import_reference="writer.entry",
            open_sink="builtins.open",
            write_sink="binary_file.write",
            opener_call_path=("opener.entry", "builtins.open"),
            writer_call_path=("writer.entry", "binary_file.write"),
        ),
    )


def test_assignment_alias_limit_preserves_later_startup_hook_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    references = (
        {"module": "limited", "name": "entry"},
        {"module": "opener", "name": "entry"},
        {"module": "writer", "name": "entry"},
    )

    def _entrypoints(function_name: str) -> tuple[str, ...]:
        if function_name == "limited.entry":
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        return (function_name,)

    def _path(entrypoints: Iterable[str], path_for: object) -> tuple[str, ...] | None:
        entrypoint = next(iter(entrypoints))
        path_name = getattr(path_for, "__name__", "")
        if path_name == "_find_file_open_path" and entrypoint == "opener.entry":
            return ("opener.entry", "builtins.open")
        if path_name == "_find_file_write_path" and entrypoint == "writer.entry":
            return ("writer.entry", "binary_file.write")
        return None

    monkeypatch.setattr("modelaudit_picklescan.call_graph._safe_call_graph_entrypoints", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._first_matching_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_startup_hook_write_call_graphs(references)

    assert exc_info.value.partial_startup_hook_write_findings == (
        StartupHookWriteFinding(
            opener_module="opener",
            opener_name="entry",
            writer_module="writer",
            writer_name="entry",
            opener_import_reference="opener.entry",
            writer_import_reference="writer.entry",
            open_sink="builtins.open",
            write_sink="binary_file.write",
            opener_call_path=("opener.entry", "builtins.open"),
            writer_call_path=("writer.entry", "binary_file.write"),
        ),
    )


def test_assignment_alias_limit_preserves_startup_hook_findings_after_sink_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    references = (
        {"module": "opener", "name": "entry"},
        {"module": "writer", "name": "entry"},
    )

    def _entrypoints(function_name: str) -> tuple[str, ...]:
        return (function_name,)

    def _path(entrypoints: Iterable[str], path_for: object) -> tuple[str, ...] | None:
        entrypoint = next(iter(entrypoints))
        path_name = getattr(path_for, "__name__", "")
        if path_name == "_find_sink_path":
            raise _CallGraphAnalysisLimitError("assignment alias limit")
        if path_name == "_find_file_open_path" and entrypoint == "opener.entry":
            return ("opener.entry", "builtins.open")
        if path_name == "_find_file_write_path" and entrypoint == "writer.entry":
            return ("writer.entry", "binary_file.write")
        return None

    monkeypatch.setattr("modelaudit_picklescan.call_graph._safe_call_graph_entrypoints", _entrypoints)
    monkeypatch.setattr("modelaudit_picklescan.call_graph._first_matching_path", _path)

    with pytest.raises(_CallGraphAnalysisLimitError, match="assignment alias limit") as exc_info:
        find_startup_hook_write_call_graphs(references)

    assert exc_info.value.partial_startup_hook_write_findings == (
        StartupHookWriteFinding(
            opener_module="opener",
            opener_name="entry",
            writer_module="writer",
            writer_name="entry",
            opener_import_reference="opener.entry",
            writer_import_reference="writer.entry",
            open_sink="builtins.open",
            write_sink="binary_file.write",
            opener_call_path=("opener.entry", "builtins.open"),
            writer_call_path=("writer.entry", "binary_file.write"),
        ),
    )


def _stack_global_payload(module: str, name: str) -> bytes:
    def _operand(value: str) -> bytes:
        data = value.encode()
        return b"\x8c" + bytes([len(data)]) + data

    return b"\x80\x04" + _operand(module) + _operand(name) + b"\x93" + _operand("proof_of_bypass") + b"\x85R."


@pytest.mark.skipif(
    find_spec(_RUST_EXTENSION_MODULE) is None,
    reason="Rust picklescan extension is not built",
)
@pytest.mark.skipif(
    find_spec("imaplib") is None,
    reason="imaplib stdlib module is unavailable",
)
def test_scan_imaplib_reference_terminates_and_flags() -> None:
    """The issue #1247 proof-of-concept must finish and stay flagged."""
    payload = _stack_global_payload("imaplib", "test")
    result: dict[str, PickleReport] = {}

    def _scan() -> None:
        result["report"] = scan_bytes(payload)

    _run_with_timeout(_scan)

    report = result["report"]
    severities = {finding.severity for finding in report.findings}
    assert Severity.CRITICAL in severities
