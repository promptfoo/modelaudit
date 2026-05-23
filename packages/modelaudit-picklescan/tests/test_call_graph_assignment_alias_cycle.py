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
    (_OSCILLATING_MODULE_SOURCE, _TRY_REBIND_SOURCE, _LOOP_ELSE_REBIND_SOURCE),
    ids=("if-else", "try-except", "loop-else"),
)
def test_collect_assignment_aliases_fails_closed_on_stable_branch_rebind(source: str) -> None:
    tree = ast.parse(source)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    local_class_targets = {"testmod.A", "testmod.B"}

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
        (_UNCONDITIONAL_OVERWRITE_SOURCE, "testmod.Final"),
        (_TRY_FINALLY_REBIND_SOURCE, "testmod.Final"),
    ),
    ids=("sequential", "unconditional-overwrite", "try-finally-overwrite"),
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
