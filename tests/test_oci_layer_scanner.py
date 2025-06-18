import json
import tarfile
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.oci_layer_scanner import OciLayerScanner


def test_oci_layer_scanner_with_malicious_pickle(tmp_path):
    evil_pickle = Path(__file__).parent / "evil.pickle"
    layer_path = tmp_path / "layer.tar.gz"
    with tarfile.open(layer_path, "w:gz") as tar:
        tar.add(evil_pickle, arcname="malicious.pkl")

    manifest = {"layers": ["layer.tar.gz"]}
    manifest_path = tmp_path / "image.manifest"
    manifest_path.write_text(json.dumps(manifest))

    scanner = OciLayerScanner()
    result = scanner.scan(str(manifest_path))

    assert result.success is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
