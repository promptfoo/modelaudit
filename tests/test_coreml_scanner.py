import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.coreml_scanner import CoreMLScanner

pytest.importorskip("coremltools")

from coremltools.proto import Model_pb2  # type: ignore[possibly-unbound-import]


def create_coreml_model(safe_tmp_path, *, custom=False):
    spec = Model_pb2.Model()
    spec.specificationVersion = 4
    nn = spec.neuralNetwork
    if custom:
        layer = nn.layers.add()
        layer.name = "custom_layer"
        layer.custom.className = "Danger"
    path = safe_tmp_path / "model.mlmodel"
    path.write_bytes(spec.SerializeToString())
    return path


def test_coreml_scanner_can_handle(safe_tmp_path):
    model_path = create_coreml_model(safe_tmp_path)
    assert CoreMLScanner.can_handle(str(model_path))


def test_coreml_scanner_custom_layer(safe_tmp_path):
    model_path = create_coreml_model(safe_tmp_path, custom=True)
    result = CoreMLScanner().scan(str(model_path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_coreml_scanner_no_coremltools(safe_tmp_path, monkeypatch):
    model_path = create_coreml_model(safe_tmp_path)
    monkeypatch.setattr("modelaudit.scanners.coreml_scanner.HAS_COREML", False)
    result = CoreMLScanner().scan(str(model_path))
    assert not result.success
    assert any("coremltools package not installed" in i.message for i in result.issues)
