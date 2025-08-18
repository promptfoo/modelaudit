import json
import tarfile
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.oci_layer_scanner import OciLayerScanner


class TestOciLayerScanner:
    """Comprehensive tests for OCI Layer Scanner."""

    def test_can_handle_valid_manifest_with_tar_gz(self, tmp_path):
        """Test can_handle correctly identifies valid manifest files."""
        manifest_path = tmp_path / "test.manifest"
        manifest_content = {"layers": ["layer1.tar.gz", "layer2.tar.gz"]}
        manifest_path.write_text(json.dumps(manifest_content))

        scanner = OciLayerScanner()
        assert scanner.can_handle(str(manifest_path)) is True

    def test_can_handle_rejects_non_manifest_extension(self, tmp_path):
        """Test can_handle rejects files without .manifest extension."""
        json_path = tmp_path / "test.json"
        json_path.write_text(json.dumps({"layers": ["layer.tar.gz"]}))

        scanner = OciLayerScanner()
        assert scanner.can_handle(str(json_path)) is False

    def test_can_handle_rejects_manifest_without_tar_gz(self, tmp_path):
        """Test can_handle rejects manifest files without .tar.gz references."""
        manifest_path = tmp_path / "test.manifest"
        manifest_content = {"config": "config.json", "layers": ["layer1.json"]}
        manifest_path.write_text(json.dumps(manifest_content))

        scanner = OciLayerScanner()
        assert scanner.can_handle(str(manifest_path)) is False

    def test_can_handle_rejects_nonexistent_file(self):
        """Test can_handle rejects non-existent files."""
        scanner = OciLayerScanner()
        assert scanner.can_handle("/nonexistent/file.manifest") is False

    def test_can_handle_rejects_directory(self, tmp_path):
        """Test can_handle rejects directories."""
        dir_path = tmp_path / "test.manifest"
        dir_path.mkdir()

        scanner = OciLayerScanner()
        assert scanner.can_handle(str(dir_path)) is False

    def test_can_handle_with_unreadable_file(self, tmp_path):
        """Test can_handle handles unreadable files gracefully."""
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text("invalid content")

        scanner = OciLayerScanner()
        # Should return False for files that can't be read or don't contain .tar.gz
        assert scanner.can_handle(str(manifest_path)) is False

    def test_scan_valid_json_manifest_with_malicious_pickle(self, tmp_path):
        """Test scanning a valid JSON manifest with malicious content."""
        # Create malicious pickle
        evil_pickle = Path(__file__).parent / "assets/samples/pickles/evil.pickle"
        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="malicious.pkl")

        # Create JSON manifest
        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "image.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        # Check that location includes manifest:layer:file format
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert any("image.manifest:layer.tar.gz:malicious.pkl" in issue.location for issue in critical_issues)

    def test_scan_yaml_manifest(self, tmp_path):
        """Test scanning a YAML manifest file."""
        import importlib.util

        import pytest

        if importlib.util.find_spec("yaml") is None:
            pytest.skip("YAML support not available")

        # Create safe content for YAML test
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("Hello, world!")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")

        # Create YAML manifest
        manifest_content = """
        layers:
          - layer.tar.gz
        config: config.json
        """
        manifest_path = tmp_path / "image.manifest"
        manifest_path.write_text(manifest_content)

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True

    def test_scan_invalid_json_manifest(self, tmp_path):
        """Test scanning an invalid JSON manifest."""
        manifest_path = tmp_path / "invalid.manifest"
        manifest_path.write_text("{ invalid json content")

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("Error parsing manifest" in issue.message for issue in result.issues)

    def test_scan_empty_manifest(self, tmp_path):
        """Test scanning an empty manifest."""
        manifest_path = tmp_path / "empty.manifest"
        manifest_path.write_text("{}")

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        assert len(result.issues) == 0  # No layers to process

    def test_scan_manifest_with_missing_layer(self, tmp_path):
        """Test scanning manifest with reference to non-existent layer."""
        manifest = {"layers": ["nonexistent.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)
        assert any("Layer not found: nonexistent.tar.gz" in issue.message for issue in result.issues)

    def test_scan_manifest_with_multiple_layers(self, tmp_path):
        """Test scanning manifest with multiple layers."""
        # Create two layers with different content
        layer1_path = tmp_path / "layer1.tar.gz"
        layer2_path = tmp_path / "layer2.tar.gz"

        # Create safe files
        safe_file1 = tmp_path / "safe1.txt"
        safe_file1.write_text("Safe content 1")
        safe_file2 = tmp_path / "safe2.txt"
        safe_file2.write_text("Safe content 2")

        with tarfile.open(layer1_path, "w:gz") as tar:
            tar.add(safe_file1, arcname="safe1.txt")

        with tarfile.open(layer2_path, "w:gz") as tar:
            tar.add(safe_file2, arcname="safe2.txt")

        manifest = {"layers": ["layer1.tar.gz", "layer2.tar.gz"]}
        manifest_path = tmp_path / "multi.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True

    def test_scan_manifest_with_absolute_layer_path(self, tmp_path):
        """Test scanning manifest with absolute layer paths."""
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("Safe content")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")

        # Use absolute path in manifest
        manifest = {"layers": [str(layer_path)]}
        manifest_path = tmp_path / "abs.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True

    def test_scan_manifest_with_traversal_layer_path(self, tmp_path):
        """Test detection of path traversal in layer references."""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        evil_file = outside_dir / "evil.txt"
        evil_file.write_text("bad")

        layer_path = outside_dir / "evil.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_file, arcname="evil.txt")

        manifest = {"layers": ["../outside/evil.tar.gz"]}
        manifest_path = tmp_path / "traversal.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert any("path traversal" in i.message.lower() for i in result.issues)

    def test_scan_manifest_with_nested_layer_references(self, tmp_path):
        """Test scanning manifest with nested layer references."""
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("Safe content")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")

        # Nested structure
        manifest = {
            "config": "config.json",
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:abc123",
                    "urls": ["layer.tar.gz"],
                },
            ],
        }
        manifest_path = tmp_path / "nested.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True

    def test_scan_layer_with_non_scannable_files(self, tmp_path):
        """Test scanning layer containing files that don't match any scanner."""
        # Create a random binary file
        random_file = tmp_path / "random.bin"
        random_file.write_bytes(b"random binary content that doesn't match any scanner")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(random_file, arcname="random.bin")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        # Should have no issues since the file doesn't match any scanner

    def test_scan_layer_with_directory_entries(self, tmp_path):
        """Test scanning layer with directory entries (should be skipped)."""
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("Safe content")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")
            # Add a directory entry manually
            tarinfo = tarfile.TarInfo(name="somedir/")
            tarinfo.type = tarfile.DIRTYPE
            tar.addfile(tarinfo)

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True

    def test_scan_corrupted_tar_layer(self, tmp_path):
        """Test scanning corrupted tar layer."""
        # Create a file that looks like tar.gz but is corrupted
        layer_path = tmp_path / "corrupted.tar.gz"
        layer_path.write_bytes(b"corrupted tar.gz content")

        manifest = {"layers": ["corrupted.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)
        assert any("Error processing layer" in issue.message for issue in result.issues)

    def test_scan_nonexistent_file(self):
        """Test scanning non-existent manifest file."""
        scanner = OciLayerScanner()
        result = scanner.scan("/nonexistent/file.manifest")

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("Path does not exist" in issue.message for issue in result.issues)

    def test_scanner_properties(self):
        """Test scanner class properties."""
        scanner = OciLayerScanner()
        assert scanner.name == "oci_layer"
        assert "container manifests" in scanner.description.lower()
        assert ".manifest" in scanner.supported_extensions

    def test_issue_location_format(self, tmp_path):
        """Test that issues have correct location format."""
        evil_pickle = Path(__file__).parent / "assets/samples/pickles/evil.pickle"
        layer_path = tmp_path / "test_layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="model/evil.pkl")

        manifest = {"layers": ["test_layer.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        # Check location format: manifest:layer:file
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0

        issue = critical_issues[0]
        assert "test.manifest:test_layer.tar.gz:model/evil.pkl" in issue.location
        assert issue.details is not None
        assert issue.details.get("layer") == "test_layer.tar.gz"

    def test_layer_with_multiple_model_files(self, tmp_path):
        """Test layer containing multiple model files."""
        evil_pickle = Path(__file__).parent / "assets/samples/pickles/evil.pickle"

        layer_path = tmp_path / "multi_model.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="model1.pkl")
            tar.add(evil_pickle, arcname="model2.pkl")

        manifest = {"layers": ["multi_model.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        # Should have issues from both model files
        assert len(critical_issues) >= 2

        locations = [issue.location for issue in critical_issues]
        assert any("model1.pkl" in loc for loc in locations)
        assert any("model2.pkl" in loc for loc in locations)


# Keep the original test for backward compatibility
def test_oci_layer_scanner_with_malicious_pickle(tmp_path):
    """Original test for backward compatibility."""
    evil_pickle = Path(__file__).parent / "assets/samples/pickles/evil.pickle"
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
