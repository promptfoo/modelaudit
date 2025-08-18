import json

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.manifest_scanner import ManifestScanner


def test_manifest_scanner_model_name_blacklist(tmp_path):
    """Manifests with blacklisted model names should trigger an error."""
    manifest_content = {"model_name": "malicious_model"}
    test_file = tmp_path / "manifest.json"
    with test_file.open("w") as f:
        json.dump(manifest_content, f)

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("model" in issue.message.lower() and "blocked" in issue.message.lower() for issue in result.issues)
