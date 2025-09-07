import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.coreml_scanner import CoreMLScanner


def create_coreml_model(safe_tmp_path, *, custom=False):
    pytest.importorskip("coremltools")
    from coremltools.proto import Model_pb2  # type: ignore[import-untyped]

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
    # Create a dummy .mlmodel file without using coremltools
    model_path = safe_tmp_path / "dummy.mlmodel"
    model_path.write_bytes(b"dummy mlmodel content")  # Not a real CoreML file, but that's ok for this test

    # Mock the import function to simulate coremltools not being available
    def mock_import_coreml():
        import modelaudit.scanners.coreml_scanner as scanner_module

        scanner_module.HAS_COREML = False
        scanner_module.Model_pb2 = None

    monkeypatch.setattr("modelaudit.scanners.coreml_scanner._import_coreml", mock_import_coreml)

    result = CoreMLScanner().scan(str(model_path))
    assert not result.success
    assert any("coremltools package not installed" in i.message for i in result.issues)
