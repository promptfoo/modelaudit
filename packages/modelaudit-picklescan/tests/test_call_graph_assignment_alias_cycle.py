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
from importlib.util import find_spec

import pytest

from modelaudit_picklescan import PickleReport, Severity, scan_bytes
from modelaudit_picklescan.api import _RUST_EXTENSION_MODULE
from modelaudit_picklescan.call_graph import (
    _collect_assignment_aliases,
    _collect_local_defs,
    _module_level_statements,
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


def _run_with_timeout(target: object, timeout: float = 10.0) -> None:
    thread = threading.Thread(target=target)  # type: ignore[arg-type]
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pytest.fail(f"call-graph analysis did not terminate within {timeout}s")


def test_collect_assignment_aliases_terminates_on_branch_rebind() -> None:
    tree = ast.parse(_OSCILLATING_MODULE_SOURCE)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    local_class_targets = {"testmod.A", "testmod.B"}

    result: dict[str, dict[str, str]] = {}

    def _collect() -> None:
        result["aliases"] = _collect_assignment_aliases(
            statements,
            "testmod",
            {},
            local_defs,
            local_class_targets,
        )

    _run_with_timeout(_collect)

    aliases = result["aliases"]
    # The rebinding name still resolves to one of the two local classes; the
    # exact branch is order-dependent, but the loop must converge.
    assert aliases.get("m") in {"testmod.A", "testmod.B"}


def test_collect_assignment_aliases_terminates_after_cyclic_dependency_propagation() -> None:
    tree = ast.parse(_DEPENDENT_CYCLE_SOURCE)
    statements = _module_level_statements(tree)
    local_defs = _collect_local_defs(statements)
    local_class_targets = {"testmod.A", "testmod.B"}

    result: dict[str, dict[str, str]] = {}

    def _collect() -> None:
        result["aliases"] = _collect_assignment_aliases(
            statements,
            "testmod",
            {},
            local_defs,
            local_class_targets,
        )

    _run_with_timeout(_collect)

    assert result["aliases"].get("c") in local_class_targets


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
