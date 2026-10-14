"""Runtime regression coverage shared by the supported Python/platform lanes."""

import json
import os
import pickle
from pathlib import Path

import pytest

from modelaudit.models import ModelAuditResultModel, create_initial_audit_result
from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from tests import conftest as root_conftest
from tests.helpers.file_creators import SystemCommandPayload


def test_python314_keeps_the_broad_test_profile() -> None:
    assert (3, 14) not in root_conftest.RESTRICTED_PYTHON_VERSIONS


@pytest.mark.parametrize("protocol", [None, 4, 5], ids=["runtime-default", "protocol-4", "protocol-5"])
@pytest.mark.parametrize("malicious", [False, True], ids=["benign", "malicious"])
def test_pickle_runtime_protocols_preserve_native_verdicts(
    tmp_path: Path, protocol: int | None, malicious: bool
) -> None:
    payload = (
        SystemCommandPayload("echo modelaudit-compatibility", lambda: os.system) if malicious else {"weights": [1, 2]}
    )
    data = pickle.dumps(payload) if protocol is None else pickle.dumps(payload, protocol=protocol)
    path = tmp_path / "model.pkl"
    path.write_bytes(data)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_primary_engine"] == "rust"
    critical = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    if malicious:
        expected = "nt.system" if os.name == "nt" else "posix.system"
        assert any(issue.details.get("import_reference") == expected for issue in critical)
    else:
        assert not critical
        assert not any(issue.severity == IssueSeverity.WARNING for issue in result.issues)


@pytest.mark.h5py
@pytest.mark.parametrize("libver", ["earliest", "latest"])
@pytest.mark.parametrize("malicious", [False, True], ids=["benign", "malicious"])
def test_hdf5_runtime_formats_preserve_verdicts(tmp_path: Path, libver: str, malicious: bool) -> None:
    import h5py

    from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner

    layers = [{"class_name": "Dense", "config": {"units": 2, "activation": "relu"}}]
    if malicious:
        layers.append(
            {
                "class_name": "Lambda",
                "config": {"function": "lambda x: __import__('os').system('echo modelaudit-compatibility')"},
            }
        )
    path = tmp_path / "model.h5"
    with h5py.File(path, "w", libver=libver) as model:
        model.attrs["model_config"] = json.dumps({"class_name": "Sequential", "config": {"layers": layers}})
        model.attrs["keras_version"] = "3.15.0"
        model.create_group("model_weights").create_dataset("dense/kernel:0", data=[[1.0, 2.0]])

    result = KerasH5Scanner().scan(str(path))

    assert result.success is (not malicious)
    critical = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert bool(critical) is malicious
    if not malicious:
        assert not any(issue.severity == IssueSeverity.WARNING for issue in result.issues)


def test_result_models_resolve_runtime_annotations_and_round_trip() -> None:
    result = create_initial_audit_result()
    encoded = result.model_dump_json()
    restored = ModelAuditResultModel.model_validate_json(encoded)

    assert restored.model_dump(mode="json") == result.model_dump(mode="json")
    assert ModelAuditResultModel.model_json_schema()["properties"]["files_scanned"]
