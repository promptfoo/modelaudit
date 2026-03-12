import json
import shutil
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch

from modelaudit.scanners.base import IssueSeverity, ScanResult
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
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
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
        assert any("image.manifest:layer.tar.gz:malicious.pkl" in (issue.location or "") for issue in critical_issues)

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
        """Absolute layer paths must be rejected instead of opened from the host."""
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
        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.open") as mock_tar_open:
            result = scanner.scan(str(manifest_path))

        mock_tar_open.assert_not_called()
        assert result.success is True
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("path traversal" in issue.message.lower() for issue in result.issues)

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

    def test_scan_manifest_with_symlinked_layer_path_outside_base(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Symlinked layer references must not escape the manifest directory."""
        manifest_dir = tmp_path / "manifest"
        manifest_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("Safe content")

        layer_path = outside_dir / "outside-layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")

        (manifest_dir / "layers").symlink_to(outside_dir, target_is_directory=True)

        manifest = {"layers": ["layers/outside-layer.tar.gz"]}
        manifest_path = manifest_dir / "symlinked.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.open") as mock_tar_open:
            result = scanner.scan(str(manifest_path))

        mock_tar_open.assert_not_called()
        assert any("path traversal" in issue.message.lower() for issue in result.issues)

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

    def test_scan_layer_dispatches_scannable_member_using_extracted_path(self, tmp_path: Path) -> None:
        """Members with registered extensions should be extracted and scanned."""
        onnx_file = tmp_path / "model.onnx"
        onnx_file.write_bytes(b"fake onnx payload")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(onnx_file, arcname="models/model.onnx")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "dispatch.manifest"
        manifest_path.write_text(json.dumps(manifest))

        mocked_result = ScanResult(scanner_name="onnx")
        with (
            patch("modelaudit.core.scan_file", return_value=mocked_result) as mock_scan,
            patch(
                "modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj",
                wraps=shutil.copyfileobj,
            ) as mock_copy,
        ):
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        mock_copy.assert_called_once()
        mock_scan.assert_called_once()
        scanned_path = mock_scan.call_args.args[0]
        assert scanned_path != "models/model.onnx"
        assert scanned_path.endswith(".onnx")

    def test_scan_layer_detects_extensionless_pickle_member(self, tmp_path: Path) -> None:
        """Extensionless pickle members should still be dispatched by content."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="payload")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "extensionless.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("extensionless.manifest:layer.tar.gz:payload" in (issue.location or "") for issue in result.issues)

    def test_scan_layer_detects_member_with_trailing_space_extension(self, tmp_path: Path) -> None:
        """Trailing whitespace after a scannable extension should not bypass dispatch."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="malicious.pkl ")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "trailing-space.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any(
            "trailing-space.manifest:layer.tar.gz:malicious.pkl " in (issue.location or "") for issue in result.issues
        )

    def test_scan_layer_prefers_model_extension_over_trailing_generic_suffix(self, tmp_path: Path) -> None:
        """Multi-suffix names like model.onnx.exe should preserve the model extension."""
        fake_member = tmp_path / "fake.bin"
        fake_member.write_bytes(b"fake onnx payload")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(fake_member, arcname="models/model.onnx.exe")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "suffix-choice.manifest"
        manifest_path.write_text(json.dumps(manifest))

        mocked_result = ScanResult(scanner_name="onnx")
        with patch("modelaudit.core.scan_file", return_value=mocked_result) as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        mock_scan.assert_called_once()
        assert mock_scan.call_args.args[0].endswith(".onnx")

    def test_scan_layer_preserves_multipart_extension_for_dispatch(self, tmp_path: Path) -> None:
        """Multipart extensions should survive extraction so nested scanners can dispatch correctly."""
        nested_archive = tmp_path / "nested.tar.gz"
        nested_archive.write_bytes(b"fake nested tar payload")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(nested_archive, arcname="models/nested.tar.gz")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "dispatch-multipart.manifest"
        manifest_path.write_text(json.dumps(manifest))

        mocked_result = ScanResult(scanner_name="tar")
        with patch("modelaudit.core.scan_file", return_value=mocked_result) as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        mock_scan.assert_called_once()
        scanned_path = mock_scan.call_args.args[0]
        assert scanned_path != "models/nested.tar.gz"
        assert scanned_path.endswith(".tar.gz")

    def test_scan_layer_rewrites_embedded_issue_and_check_locations(self, tmp_path: Path) -> None:
        """Embedded scan results should reference the OCI member, not temp extraction paths."""
        onnx_file = tmp_path / "model.onnx"
        onnx_file.write_bytes(b"fake onnx payload")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(onnx_file, arcname="models/model.onnx")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "location-rewrite.manifest"
        manifest_path.write_text(json.dumps(manifest))

        def _mock_scan_file(scanned_path: str, _config: dict | None = None) -> ScanResult:
            result = ScanResult(scanner_name="onnx")
            result.add_check(
                name="Mock Failure",
                passed=False,
                message="Mock embedded finding",
                severity=IssueSeverity.WARNING,
                location=scanned_path,
            )
            result.add_check(
                name="Mock Positional Failure",
                passed=False,
                message="Mock positional finding",
                severity=IssueSeverity.WARNING,
                location=f"{scanned_path} (pos 52)",
            )
            result.finish(success=True)
            return result

        with patch("modelaudit.core.scan_file", side_effect=_mock_scan_file) as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        mock_scan.assert_called_once()
        scanned_path = mock_scan.call_args.args[0]
        member_prefix = f"{manifest_path}:layer.tar.gz:models/model.onnx"
        embedded_checks = [
            check for check in result.checks if check.name in {"Mock Failure", "Mock Positional Failure"}
        ]
        embedded_issues = [issue for issue in result.issues if "Mock" in issue.message]

        assert embedded_checks
        assert embedded_issues
        assert all((check.location or "").startswith(member_prefix) for check in embedded_checks)
        assert all((issue.location or "").startswith(member_prefix) for issue in embedded_issues)
        assert all(scanned_path not in (check.location or "") for check in embedded_checks)
        assert all(scanned_path not in (issue.location or "") for issue in embedded_issues)
        assert any((check.location or "").endswith("(pos 52)") for check in embedded_checks)

    def test_scan_layer_cleans_up_temp_file_when_copy_fails(self, tmp_path: Path) -> None:
        """Failed member extraction should not leave temp files behind."""
        onnx_file = tmp_path / "model.onnx"
        onnx_file.write_bytes(b"fake onnx payload")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(onnx_file, arcname="models/model.onnx")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "copy-failure.manifest"
        manifest_path.write_text(json.dumps(manifest))

        created_paths: list[str] = []
        real_named_temporary_file = tempfile.NamedTemporaryFile

        def _capture_named_temporary_file(*args, **kwargs):
            tmp = real_named_temporary_file(*args, **kwargs)
            created_paths.append(tmp.name)
            return tmp

        with (
            patch(
                "modelaudit.scanners.oci_layer_scanner.tempfile.NamedTemporaryFile",
                side_effect=_capture_named_temporary_file,
            ),
            patch(
                "modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj",
                side_effect=RuntimeError("copy failed"),
            ),
        ):
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        assert created_paths
        assert all(not Path(path).exists() for path in created_paths)
        assert any("Error processing layer" in issue.message for issue in result.issues)

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
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
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
        assert "test.manifest:test_layer.tar.gz:model/evil.pkl" in (issue.location or "")
        assert issue.details is not None
        assert issue.details.get("layer") == "test_layer.tar.gz"

    def test_layer_with_multiple_model_files(self, tmp_path):
        """Test layer containing multiple model files."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

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
        assert any("model1.pkl" in (loc or "") for loc in locations)
        assert any("model2.pkl" in (loc or "") for loc in locations)


# Keep the original test for backward compatibility
def test_oci_layer_scanner_with_malicious_pickle(tmp_path):
    """Original test for backward compatibility."""
    evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
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
