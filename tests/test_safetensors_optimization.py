"""SafeTensors files should be scanned once, without loading their weight distribution."""

import json
from pathlib import Path

import pytest

from modelaudit.scanners.safetensors_scanner import SafeTensorsScanner
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner


@pytest.mark.parametrize("extension", ["safetensors", "SAFETENSORS", "SafeTensors", "saFeTenSors"])
def test_safetensors_uses_dedicated_scanner(tmp_path: Path, extension: str) -> None:
    # Keep model fixtures out of the checkout, which is on other workers' import paths.
    path = tmp_path / f"model.{extension}"
    header = json.dumps(
        {
            "test_tensor": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
            "__metadata__": {"format": "pt"},
        }
    ).encode()
    path.write_bytes(len(header).to_bytes(8, "little") + header + bytes(16))

    assert not WeightDistributionScanner.can_handle(str(path))
    assert SafeTensorsScanner.can_handle(str(path))
    result = SafeTensorsScanner().scan(str(path))
    assert result.success, result.issues
    assert not result.has_errors
    assert result.metadata["tensor_count"] == 1


def test_weight_distribution_supported_extensions() -> None:
    extensions = set(WeightDistributionScanner.supported_extensions)
    assert ".safetensors" not in extensions
    assert {".pt", ".pth", ".h5", ".keras", ".hdf5", ".pb", ".onnx"} <= extensions
