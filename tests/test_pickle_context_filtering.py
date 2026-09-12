from __future__ import annotations

import os
import pickle
import struct
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


def _short_binunicode(value: bytes) -> bytes:
    return b"\x8c" + bytes([len(value)]) + value


def _alternate_platform_system_payload() -> tuple[bytes, str]:
    native_module = b"nt" if os.name == "nt" else b"posix"
    alternate_module = b"posix" if native_module == b"nt" else b"nt"
    payload = pickle.dumps(
        {
            "state_dict": OrderedDict([("layer.weight", "tensor_data")]),
            "payload": MaliciousPayload(),
        },
        protocol=4,
    )
    payload = payload.replace(_short_binunicode(native_module), _short_binunicode(alternate_module), 1)
    if payload.startswith(b"\x80\x04\x95"):
        payload = payload[:3] + struct.pack("<Q", len(payload) - 11) + payload[11:]
    return payload, f"{alternate_module.decode()}.system"


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

    assert result.success is True, result.to_dict()
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        issue.details.get("import_reference") in {"posix.system", "os.system", "nt.system"} for issue in result.issues
    )
    assert not any(issue.details.get("pattern_type") == "setitem_near_dangerous_global" for issue in result.issues)


def test_rust_pickle_scanner_keeps_direct_platform_system_detection_complete(tmp_path: Path) -> None:
    payload, import_reference = _alternate_platform_system_payload()
    path = tmp_path / "platform-system.pkl"
    path.write_bytes(payload)

    result = PickleScanner().scan(str(path))

    assert result.success is True, result.to_dict()
    assert result.metadata.get("analysis_incomplete") is not True
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("import_reference") == import_reference
        for issue in result.issues
    )
