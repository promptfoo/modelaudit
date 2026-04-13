from __future__ import annotations

import os
import pickle
from collections import OrderedDict
from pathlib import Path
from typing import Any

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner


class SafeStateDict:
    def __reduce__(self) -> tuple[Any, tuple[list[tuple[str, str]]]]:
        return (OrderedDict, ([("layer.weight", "tensor_data"), ("layer.bias", "bias_data")],))


class MaliciousPayload:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (os.system, ("id",))


def test_rust_pickle_scanner_keeps_common_ml_serialization_clean(tmp_path: Path) -> None:
    path = tmp_path / "state.pkl"
    path.write_bytes(pickle.dumps(SafeStateDict(), protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]


def test_rust_pickle_scanner_does_not_let_ml_context_hide_dangerous_reduce(tmp_path: Path) -> None:
    path = tmp_path / "mixed.pkl"
    payload = {
        "state_dict": OrderedDict([("layer.weight", "tensor_data")]),
        "payload": MaliciousPayload(),
    }
    path.write_bytes(pickle.dumps(payload, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.details.get("import_reference") in {"posix.system", "os.system", "nt.system"} for issue in result.issues
    )
    assert not any(issue.details.get("pattern_type") == "setitem_near_dangerous_global" for issue in result.issues)
