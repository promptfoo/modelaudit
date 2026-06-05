import gzip
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanner_results import mark_inconclusive_scan_result
from modelaudit.scanners import flax_msgpack_scanner
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity, ScanResult
from modelaudit.scanners.oci_layer_scanner import OciLayerScanner
from modelaudit.utils.file.detection import FLAX_MSGPACK_STRUCTURE_READ_BYTES


def _gzip_with_comment(payload: bytes, comment: bytes) -> bytes:
    """Return a valid gzip member whose optional comment is not part of the deflate payload."""
    assert b"\0" not in comment
    member = bytearray(gzip.compress(payload))
    member[3] |= 0x10
    return bytes(member[:10] + comment + b"\0" + member[10:])


def _assert_inconclusive_aggregate_not_cached(
    path: Path,
    expected_reason: str,
    cache_dir: Path,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert expected_reason in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def _write_delayed_flax_cntk_overlap(path: Path) -> None:
    prefix = b"\x08\x01\x12\x11\x0a\x07version\x12\x06\x08\x01\x10\x03(\x02\x12\x09\x0a\x03uid\x12\x02ab"
    structure = b" CompositeFunction primitive_functions "
    delayed_flax_root = flax_msgpack_scanner.msgpack.packb(
        {"params": {"w": [1, 2, 3]}, "__reduce__": "attacker_callable"},
        use_bin_type=True,
    )
    path.write_bytes(prefix + structure + (b"\xc0" * (FLAX_MSGPACK_STRUCTURE_READ_BYTES + 1)) + delayed_flax_root)


class TestOciLayerScanner:
    """Comprehensive tests for OCI Layer Scanner."""

    @pytest.mark.parametrize("invalid_ratio", [float("nan"), float("inf"), float("-inf")])
    def test_invalid_decompression_ratio_uses_safe_default(self, invalid_ratio: float) -> None:
        scanner = OciLayerScanner({"compressed_max_decompression_ratio": invalid_ratio})

        assert scanner.max_decompression_ratio == scanner._DEFAULT_MAX_DECOMPRESSION_RATIO

    def test_can_handle_valid_manifest_with_tar_gz(self, tmp_path: Path) -> None:
        """Test can_handle correctly identifies valid manifest files."""
        manifest_path = tmp_path / "test.manifest"
        manifest_content = {"layers": ["layer1.tar.gz", "layer2.tar.gz"]}
        manifest_path.write_text(json.dumps(manifest_content))

        scanner = OciLayerScanner()
        assert scanner.can_handle(str(manifest_path)) is True

    def test_can_handle_accepts_uppercase_tar_gz_reference_after_large_prefix(self, tmp_path: Path) -> None:
        """Layer refs beyond the first chunk and with uppercase suffixes should still route here."""
        manifest_path = tmp_path / "late.manifest"
        manifest_content = {
            "padding": "A" * (OciLayerScanner._MANIFEST_PROBE_CHUNK_BYTES + 512),
            "layers": ["LAYER.TAR.GZ"],
        }
        manifest_path.write_text(json.dumps(manifest_content))

        assert OciLayerScanner.can_handle(str(manifest_path)) is True

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

    def test_scan_valid_json_manifest_with_malicious_pickle(self, tmp_path: Path) -> None:
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

        assert result.success is False
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

    def test_scan_invalid_json_manifest(self, tmp_path: Path) -> None:
        """Test scanning an invalid JSON manifest."""
        manifest_path = tmp_path / "invalid.manifest"
        manifest_path.write_text("{ invalid json content layer.tar.gz")

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "oci_manifest_parse_failed" in result.metadata["scan_outcome_reasons"]
        assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)
        assert any("Error parsing manifest" in issue.message for issue in result.issues)
        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_manifest_parse_failed",
            tmp_path / "parse-cache",
        )

    def test_scan_empty_manifest(self, tmp_path):
        """Test scanning an empty manifest."""
        manifest_path = tmp_path / "empty.manifest"
        manifest_path.write_text("{}")

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is True
        assert len(result.issues) == 0  # No layers to process

    def test_scan_manifest_with_missing_layer(self, tmp_path: Path) -> None:
        """Test scanning manifest with reference to non-existent layer."""
        manifest = {"layers": ["nonexistent.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "oci_layer_missing" in result.metadata["scan_outcome_reasons"]
        assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)
        assert any("Layer not found: nonexistent.tar.gz" in issue.message for issue in result.issues)
        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_layer_missing",
            tmp_path / "missing-cache",
        )

    def test_scan_manifest_preserves_layer_and_nested_incomplete_reasons(self, tmp_path: Path) -> None:
        """Nested inconclusive results must not replace OCI-level coverage reasons."""
        member_path = tmp_path / "nested.pkl"
        member_path.write_bytes(b"safe nested member")
        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(member_path, arcname="nested.pkl")

        manifest_path = tmp_path / "mixed-incomplete.manifest"
        manifest_path.write_text(json.dumps({"layers": ["missing.tar.gz", "layer.tar.gz"]}))

        nested_result = ScanResult(scanner_name="pickle")
        mark_inconclusive_scan_result(nested_result, "nested_scan_incomplete")
        nested_result.finish(success=False)

        with patch("modelaudit.core.scan_file", return_value=nested_result) as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        assert mock_scan.call_count == 1
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "oci_layer_missing" in result.metadata["scan_outcome_reasons"]
        assert "nested_scan_incomplete" in result.metadata["scan_outcome_reasons"]
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_scan_manifest_preserves_composed_nested_incomplete_reasons_without_caching(self, tmp_path: Path) -> None:
        """OCI gaps and nested overlap-analysis gaps must survive together."""
        if not flax_msgpack_scanner.HAS_MSGPACK:
            pytest.skip("msgpack unavailable")

        member_path = tmp_path / "delayed-flax-cntk.jpg"
        _write_delayed_flax_cntk_overlap(member_path)
        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(member_path, arcname="delayed-flax-cntk.jpg")

        manifest_path = tmp_path / "stacked-incomplete.manifest"
        manifest_path.write_text(json.dumps({"layers": ["missing.tar.gz", "layer.tar.gz"]}))
        cache_dir = tmp_path / "stacked-cache"

        reset_cache_manager()
        try:
            first = scan_model_directory_or_file(
                str(manifest_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
                compressed_max_decompression_ratio=1000.0,
            )
            second = scan_model_directory_or_file(
                str(manifest_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
                compressed_max_decompression_ratio=1000.0,
            )

            for aggregate in (first, second):
                metadata = aggregate.file_metadata[str(manifest_path)]
                assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
                assert "oci_layer_missing" in metadata["scan_outcome_reasons"]
                assert "flax_msgpack_routing_incomplete" in metadata["scan_outcome_reasons"]
                assert metadata["file_size"] == manifest_path.stat().st_size
                assert aggregate.assets[0].size == manifest_path.stat().st_size
                assert determine_exit_code(aggregate) == 2
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

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

    def test_scan_manifest_with_absolute_layer_path(self, tmp_path: Path) -> None:
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
        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("path traversal" in issue.message.lower() for issue in result.issues)

    def test_scan_manifest_with_traversal_layer_path(self, tmp_path: Path) -> None:
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

        assert result.success is False
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
        assert result.success is False
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

    def test_scan_manifest_ignores_non_layer_tar_gz_metadata_strings(self, tmp_path: Path) -> None:
        """Metadata URLs ending in .tar.gz should not be treated as required local layer files."""
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("Safe content")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")

        manifest = {
            "layers": ["layer.tar.gz"],
            "homepage": "https://cdn.example.com/not-a-local-layer.tar.gz",
            "metadata": {
                "release_notes": "https://cdn.example.com/docs.tar.gz",
                "labels": ["stable", "https://cdn.example.com/archive.tar.gz"],
            },
        }
        manifest_path = tmp_path / "metadata-url.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        assert not any("not-a-local-layer.tar.gz" in issue.message for issue in result.issues)
        assert not any("docs.tar.gz" in issue.message for issue in result.issues)
        assert not any("archive.tar.gz" in issue.message for issue in result.issues)

    def test_scan_manifest_ignores_remote_layer_urls(self, tmp_path: Path) -> None:
        """Remote layer URLs under layers[].urls should not mask local layer refs."""
        missing_local_layer = "missing-local-layer.tar.gz"
        manifest = {
            "schemaVersion": 2,
            "layers": [
                {
                    "digest": "sha256:abc123",
                    "urls": [
                        "https://cdn.example.com/layer.tar.gz",
                        missing_local_layer,
                    ],
                }
            ],
        }
        manifest_path = tmp_path / "remote-layer-url.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(
            "Layer not found" in issue.message and missing_local_layer in issue.message for issue in result.issues
        )
        assert any(
            "Remote layer was not scanned" in issue.message and "https://cdn.example.com/layer.tar.gz" in issue.message
            for issue in result.issues
        )

    def test_scan_manifest_remote_only_layer_url_marks_scan_incomplete(self, tmp_path: Path) -> None:
        """Remote-only layer refs should not produce a clean scan when no local layer was inspected."""
        remote_layer_ref = "https://cdn.example.com/layer.tar.gz"
        manifest = {"schemaVersion": 2, "layers": [{"digest": "sha256:abc123", "urls": [remote_layer_ref]}]}
        manifest_path = tmp_path / "remote-only-layer-url.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "oci_remote_layer_unavailable" in result.metadata["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.INFO
            and "Remote layer was not scanned" in issue.message
            and remote_layer_ref in issue.message
            for issue in result.issues
        )
        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_remote_layer_unavailable",
            tmp_path / "remote-cache",
        )

    def test_scan_manifest_scans_url_like_layer_ref_when_local_path_exists(self, tmp_path: Path) -> None:
        """URL-like layer refs should still scan when they map to a safe local path."""
        if os.name == "nt":
            pytest.skip("URL-scheme path components use ':' and are not representable on Windows")

        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
        url_layer_ref = "https://cdn.example.com/layer.tar.gz"
        local_layer_path = tmp_path / "https:" / "cdn.example.com" / "layer.tar.gz"
        local_layer_path.parent.mkdir(parents=True)
        with tarfile.open(local_layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="malicious.pkl")

        manifest = {"schemaVersion": 2, "layers": [{"digest": "sha256:abc123", "urls": [url_layer_ref]}]}
        manifest_path = tmp_path / "local-url-layer.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and f"local-url-layer.manifest:{url_layer_ref}:malicious.pkl" in (issue.location or "")
            for issue in result.issues
        )

    def test_scan_manifest_validates_file_url_like_layer_refs(self, tmp_path: Path) -> None:
        """URL-like local refs should still pass through path traversal validation."""
        malformed_layer_ref = "file://../../outside/layer.tar.gz"
        manifest = {
            "schemaVersion": 2,
            "layers": [
                {"digest": "sha256:abc123", "urls": ["https://cdn.example.com/layer.tar.gz", malformed_layer_ref]}
            ],
        }
        manifest_path = tmp_path / "file-url-layer.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and "path traversal" in issue.message
            and malformed_layer_ref in issue.message
            for issue in result.issues
        )
        assert any(
            "Remote layer was not scanned" in issue.message and "https://cdn.example.com/layer.tar.gz" in issue.message
            for issue in result.issues
        )

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

    def test_scan_layer_dispatches_unknown_suffix_non_model_members_without_findings(self, tmp_path: Path) -> None:
        """Unknown-suffix members should still be dispatched so misnamed payloads cannot hide behind padding."""
        random_file = tmp_path / "picture.jpg"
        random_file.write_bytes(b"not-a-model-image-payload")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(random_file, arcname="assets/picture.jpg")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "skip-non-model.manifest"
        manifest_path.write_text(json.dumps(manifest))

        with (
            patch("modelaudit.core.scan_file", return_value=ScanResult(scanner_name="unknown")) as mock_scan,
            patch(
                "modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj",
                wraps=shutil.copyfileobj,
            ) as mock_copy,
        ):
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        mock_scan.assert_called_once()
        mock_copy.assert_called_once()
        scanned_path = mock_scan.call_args.args[0]
        assert scanned_path != "assets/picture.jpg"

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

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("extensionless.manifest:layer.tar.gz:payload" in (issue.location or "") for issue in result.issues)

    def test_scan_layer_detects_extensionless_protocol0_pickle_member_with_non_magic_prefix(
        self,
        tmp_path: Path,
    ) -> None:
        """Extensionless protocol-0 pickles should still be scanned when the first 64-byte probe is inconclusive."""
        protocol0_payload = tmp_path / "payload"
        protocol0_payload.write_bytes(b"I1\n0cos\nsystem\n(S'echo oci-owned'\ntR.")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(protocol0_payload, arcname="payload")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "extensionless-protocol0.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any(
            "extensionless-protocol0.manifest:layer.tar.gz:payload" in (issue.location or "") for issue in result.issues
        )

    def test_scan_layer_detects_misnamed_pickle_member(self, tmp_path: Path) -> None:
        """Unsupported member suffixes should still be content-routed when payload bytes are model-like."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="payload.jpg")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "misnamed.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("misnamed.manifest:layer.tar.gz:payload.jpg" in (issue.location or "") for issue in result.issues)

    def test_scan_layer_detects_misnamed_protocol0_pickle_member_with_non_magic_prefix(
        self,
        tmp_path: Path,
    ) -> None:
        """Misnamed protocol-0 pickle members should still be scanned when the first probe bytes are inconclusive."""
        protocol0_payload = tmp_path / "payload.jpg"
        protocol0_payload.write_bytes(b"I1\n0cos\nsystem\n(S'echo oci-owned'\ntR.")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(protocol0_payload, arcname="payload.jpg")

        manifest = {"layers": ["layer.tar.gz"]}
        manifest_path = tmp_path / "misnamed-protocol0.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any(
            "misnamed-protocol0.manifest:layer.tar.gz:payload.jpg" in (issue.location or "") for issue in result.issues
        )

    def test_scan_manifest_normalizes_layer_refs_with_uppercase_and_trailing_space(self, tmp_path: Path) -> None:
        """Cosmetic layer-ref suffix changes should not hide a real .tar.gz payload."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        layer_path = tmp_path / "  UPPER.TAR.GZ  "
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="malicious.pkl")

        manifest = {"layers": ["  UPPER.TAR.GZ  "]}
        manifest_path = tmp_path / "uppercase.manifest"
        manifest_path.write_text(json.dumps(manifest))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any(
            "uppercase.manifest:  UPPER.TAR.GZ  :malicious.pkl" in (issue.location or "") for issue in result.issues
        )

    def test_scan_manifest_resolves_exact_dotted_layer_ref(self, tmp_path: Path) -> None:
        """Manifest refs with trailing dots should resolve to the exact layer path, not a normalized sibling."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        benign_payload = tmp_path / "safe.txt"
        benign_payload.write_text("Safe content")

        benign_layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(benign_layer_path, "w:gz") as tar:
            tar.add(benign_payload, arcname="safe.txt")

        malicious_layer_path = tmp_path / "layer.tar.gz."
        with tarfile.open(malicious_layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="malicious.pkl")

        manifest_path = tmp_path / "exact-ref.manifest"
        manifest_path.write_text(json.dumps({"layers": ["layer.tar.gz."]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and "exact-ref.manifest:layer.tar.gz.:malicious.pkl" in (issue.location or "")
            for issue in result.issues
        )

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

        assert result.success is False
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

    def test_scan_skipped_oversized_layer_is_inconclusive(self, tmp_path: Path) -> None:
        """A layer outside the inspection budget must be reported as incomplete coverage."""
        benign_member = tmp_path / "notes.txt"
        benign_member.write_text("safe content")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(benign_member, arcname="notes.txt")
        assert layer_path.stat().st_size > 64

        manifest_path = tmp_path / "limited-layer.manifest"
        manifest_path.write_text(json.dumps({"layers": ["layer.tar.gz"]}))

        result = OciLayerScanner({"max_file_size": 64}).scan(str(manifest_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "oci_layer_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer File Size Check"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.INFO

        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_layer_size_limit_exceeded",
            tmp_path / "layer-size-cache",
            max_file_size=64,
        )

    def test_scan_layer_skips_oversized_member_before_copying(self, tmp_path: Path) -> None:
        """Oversized members should be rejected before they are copied to temp storage."""
        huge_member = tmp_path / "huge.bin"
        huge_member.write_bytes(b"A" * 8192)

        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"

        layer_path = tmp_path / "mixed.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(huge_member, arcname="huge.bin")
            tar.add(evil_pickle, arcname="payload.pkl")

        manifest = {"layers": ["mixed.tar.gz"]}
        manifest_path = tmp_path / "oversized-member.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner(config={"max_file_size": 4096})
        with patch(
            "modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj",
            wraps=shutil.copyfileobj,
        ) as mock_copy:
            result = scanner.scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 1
        size_checks = [check for check in result.checks if check.name == "Layer Member Size Check"]
        assert len(size_checks) == 1
        assert size_checks[0].severity == IssueSeverity.INFO
        assert size_checks[0].location is not None
        assert "huge.bin" in size_checks[0].location
        assert "oci_member_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and "oversized-member.manifest:mixed.tar.gz:payload.pkl" in (issue.location or "")
            for issue in result.issues
        )

    def test_scan_skipped_oversized_malicious_member_is_inconclusive(self, tmp_path: Path) -> None:
        """A malicious member outside the inspection budget must not be reported as a finding."""
        malicious_pickle = tmp_path / "payload.pkl"
        malicious_pickle.write_bytes(b"\x80\x04cos\nsystem\n(S'echo oci-owned'\ntR." + (b"A" * 8192))

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(malicious_pickle, arcname="payload.pkl")

        manifest_path = tmp_path / "limited.manifest"
        manifest_path.write_text(json.dumps({"layers": ["layer.tar.gz"]}))

        result = OciLayerScanner({"max_file_size": 4096}).scan(str(manifest_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "oci_member_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_member_size_limit_exceeded",
            tmp_path / "member-size-cache",
            max_file_size=4096,
        )

    def test_scan_member_at_size_limit_remains_clean(self, tmp_path: Path) -> None:
        """Content at the configured member limit is inspected rather than failed closed."""
        benign_member = tmp_path / "notes.bin"
        benign_member.write_bytes(b"A" * 4096)

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(benign_member, arcname="notes.bin")

        manifest_path = tmp_path / "exact-limit.manifest"
        manifest_path.write_text(json.dumps({"layers": ["layer.tar.gz"]}))

        result = OciLayerScanner({"max_file_size": 4096}).scan(str(manifest_path))

        assert result.success is True
        assert result.metadata.get("scan_outcome") != "inconclusive"
        assert not any(check.name == "Layer Member Size Check" for check in result.checks)

    def test_scan_layer_rejects_decompression_ratio_before_copying(self, tmp_path: Path) -> None:
        """High-ratio gzip layers should fail closed before member extraction."""
        compressible_member = tmp_path / "zeros.bin"
        compressible_member.write_bytes(b"\x00" * 65536)

        layer_path = tmp_path / "ratio.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(compressible_member, arcname="zeros.bin")

        manifest_path = tmp_path / "ratio.manifest"
        manifest_path.write_text(json.dumps({"layers": ["ratio.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"compressed_max_decompression_ratio": 2.0}).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 0
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.INFO
        assert "decompression ratio exceeded" in checks[0].message.lower()

        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_layer_decompression_ratio_exceeded",
            tmp_path / "ratio-cache",
            compressed_max_decompression_ratio=2.0,
        )

    def test_scan_layer_rejects_padded_decompression_ratio_before_copying(self, tmp_path: Path) -> None:
        """Trailing gzip padding should not dilute the decompression-ratio denominator."""
        compressible_member = tmp_path / "zeros.bin"
        compressible_member.write_bytes(b"\x00" * 65536)

        layer_path = tmp_path / "padded-ratio.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(compressible_member, arcname="zeros.bin")
        layer_path.write_bytes(layer_path.read_bytes() + (b"\x00" * 256 * 1024))

        manifest_path = tmp_path / "padded-ratio.manifest"
        manifest_path.write_text(json.dumps({"layers": ["padded-ratio.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"compressed_max_decompression_ratio": 2.0}).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 0
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["compressed_size"] < layer_path.stat().st_size
        assert checks[0].details["actual_ratio"] > 2.0

    def test_scan_layer_rejects_gzip_prefixed_padding_ratio_before_copying(self, tmp_path: Path) -> None:
        """Malformed gzip-like padding should not erase completed-stream ratio metrics."""
        compressible_member = tmp_path / "zeros.bin"
        compressible_member.write_bytes(b"\x00" * 65536)

        layer_path = tmp_path / "gzip-prefixed-padding.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(compressible_member, arcname="zeros.bin")
        layer_path.write_bytes(layer_path.read_bytes() + b"\x1f\x8b" + (b"X" * 256 * 1024))

        manifest_path = tmp_path / "gzip-prefixed-padding.manifest"
        manifest_path.write_text(json.dumps({"layers": ["gzip-prefixed-padding.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"compressed_max_decompression_ratio": 2.0}).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 0
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["compressed_size"] < layer_path.stat().st_size
        assert checks[0].details["actual_ratio"] > 2.0

    @pytest.mark.parametrize("tail_kind", ["checksum", "truncated"])
    def test_scan_layer_counts_partial_gzip_tail_for_ratio(self, tmp_path: Path, tail_kind: str) -> None:
        """Decoded bytes from malformed trailing gzip members must still count toward the ratio budget."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")

        raw_tar_path = tmp_path / "raw-partial-tail.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(payload, arcname="payload.bin")
        raw_tar = raw_tar_path.read_bytes()

        malformed_tail = bytearray(gzip.compress(b"\x00" * 256 * 1024))
        if tail_kind == "checksum":
            malformed_tail[-8] ^= 0x01
        else:
            del malformed_tail[-4:]

        layer_path = tmp_path / f"{tail_kind}-partial-tail.tar.gz"
        layer_path.write_bytes(gzip.compress(raw_tar) + malformed_tail)

        manifest_path = tmp_path / f"{tail_kind}-partial-tail.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner(
                {
                    "compressed_max_decompressed_bytes": 1024 * 1024,
                    "compressed_max_decompression_ratio": 100.0,
                }
            ).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 1
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["decompressed_size"] > len(raw_tar)
        assert checks[0].details["actual_ratio"] > 100.0

    def test_scan_layer_sizes_concatenated_gzip_members_for_ratio(self, tmp_path: Path) -> None:
        """Concatenated gzip members should be included in the compressed budget denominator."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"".join(hashlib.sha256(str(index).encode()).digest() for index in range(8192)))

        layer_path = tmp_path / "concatenated.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(payload, arcname="payload.bin")
        layer_path.write_bytes(gzip.compress(b"") + layer_path.read_bytes())

        manifest_path = tmp_path / "concatenated.manifest"
        manifest_path.write_text(json.dumps({"layers": ["concatenated.tar.gz"]}))

        result = OciLayerScanner({"compressed_max_decompression_ratio": 100.0}).scan(str(manifest_path))

        assert result.success is True
        assert "oci_layer_decompression_ratio_exceeded" not in result.metadata.get("scan_outcome_reasons", [])

    def test_scan_layer_reports_gzip_tail_decompressed_size_after_tar_eof(self, tmp_path: Path) -> None:
        """Gzip bytes after TAR EOF should still count toward the decompressed-byte budget."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")

        raw_tar_path = tmp_path / "raw-tail.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(payload, arcname="payload.bin")
        raw_tar = raw_tar_path.read_bytes()

        layer_path = tmp_path / "tail-size.tar.gz"
        layer_path.write_bytes(gzip.compress(raw_tar + (b"\x00" * 8192)))

        manifest_path = tmp_path / "tail-size.manifest"
        manifest_path.write_text(json.dumps({"layers": ["tail-size.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"compressed_max_decompressed_bytes": len(raw_tar) + 1024}).scan(
                str(manifest_path)
            )

        assert result.success is False
        assert mock_copy.call_count == 1
        assert "oci_layer_decompressed_size_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["decompressed_size"] > checks[0].details["max_decompressed_size"]

    def test_scan_layer_checks_gzip_tail_ratio_after_tar_eof(self, tmp_path: Path) -> None:
        """Highly-compressible gzip data after TAR EOF should still count toward ratio limits."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")

        raw_tar_path = tmp_path / "raw-ratio.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(payload, arcname="payload.bin")
        raw_tar = raw_tar_path.read_bytes()

        layer_path = tmp_path / "tail-ratio.tar.gz"
        layer_path.write_bytes(gzip.compress(raw_tar + (b"\x00" * 1024 * 1024)))

        manifest_path = tmp_path / "tail-ratio.manifest"
        manifest_path.write_text(json.dumps({"layers": ["tail-ratio.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner(
                {
                    "compressed_max_decompressed_bytes": len(raw_tar) + (2 * 1024 * 1024),
                    "compressed_max_decompression_ratio": 100.0,
                }
            ).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 1
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["actual_ratio"] > 100.0

    @pytest.mark.parametrize("tail_mode", ["same_member", "concatenated_member"])
    def test_scan_layer_rejects_incompressible_gzip_tail_ratio_dilution(
        self,
        tmp_path: Path,
        tail_mode: str,
    ) -> None:
        """Valid gzip data after TAR EOF must not dilute the TAR stream's decompression ratio."""
        compressible_member = tmp_path / "zeros.bin"
        compressible_member.write_bytes(b"\x00" * 65536)

        raw_tar_path = tmp_path / "raw-tail-dilution.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(compressible_member, arcname="zeros.bin")
        raw_tar = raw_tar_path.read_bytes()
        incompressible_tail = b"".join(hashlib.sha256(str(index).encode()).digest() for index in range(4096))

        layer_path = tmp_path / f"{tail_mode}-tail-dilution.tar.gz"
        if tail_mode == "same_member":
            layer_path.write_bytes(gzip.compress(raw_tar + incompressible_tail))
        else:
            layer_path.write_bytes(gzip.compress(raw_tar) + gzip.compress(incompressible_tail))

        manifest_path = tmp_path / f"{tail_mode}-tail-dilution.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner({"compressed_max_decompression_ratio": 2.0}).scan(str(manifest_path))

        assert result.success is False
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["actual_ratio"] > 2.0

    @pytest.mark.parametrize("tail_mode", ["same_member", "concatenated_member"])
    def test_scan_layer_allows_incompressible_gzip_tail_for_low_ratio_tar(
        self,
        tmp_path: Path,
        tail_mode: str,
    ) -> None:
        """Extra gzip data alone must not fail a TAR stream that remains within the ratio policy."""
        incompressible_payload = b"".join(hashlib.sha256(f"payload-{index}".encode()).digest() for index in range(2048))
        payload_path = tmp_path / "payload.bin"
        payload_path.write_bytes(incompressible_payload)

        raw_tar_path = tmp_path / "raw-benign-tail.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(payload_path, arcname="payload.bin")
        raw_tar = raw_tar_path.read_bytes()
        incompressible_tail = b"".join(hashlib.sha256(f"tail-{index}".encode()).digest() for index in range(4096))

        layer_path = tmp_path / f"{tail_mode}-benign-tail.tar.gz"
        if tail_mode == "same_member":
            layer_path.write_bytes(gzip.compress(raw_tar + incompressible_tail))
        else:
            layer_path.write_bytes(gzip.compress(raw_tar) + gzip.compress(incompressible_tail))

        manifest_path = tmp_path / f"{tail_mode}-benign-tail.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner({"compressed_max_decompression_ratio": 2.0}).scan(str(manifest_path))

        assert result.success is True
        assert "oci_layer_decompression_ratio_exceeded" not in result.metadata.get("scan_outcome_reasons", [])

    def test_scan_layer_rejects_in_tar_ratio_dilution_before_copying(self, tmp_path: Path) -> None:
        """Later incompressible TAR members must not hide an earlier high-ratio prefix."""
        compressible = tmp_path / "zeros.bin"
        compressible.write_bytes(b"\0" * 1024 * 1024)
        filler = tmp_path / "filler.bin"
        filler.write_bytes(b"".join(hashlib.sha256(str(index).encode()).digest() for index in range(65536)))

        layer_path = tmp_path / "in-tar-dilution.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(compressible, arcname="zeros.bin")
            tar.add(filler, arcname="filler.bin")

        manifest_path = tmp_path / "in-tar-dilution.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"compressed_max_decompression_ratio": 2.0}).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 0
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("dilution", ["comment", "empty_members"])
    def test_scan_layer_rejects_gzip_framing_ratio_dilution(self, tmp_path: Path, dilution: str) -> None:
        """Gzip metadata and zero-output members must not increase the ratio denominator."""
        payload = tmp_path / "zeros.bin"
        payload.write_bytes(b"\0" * 256 * 1024)
        raw_tar_path = tmp_path / "raw-framing.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(payload, arcname="zeros.bin")
        raw_tar = raw_tar_path.read_bytes()

        layer_path = tmp_path / f"{dilution}.tar.gz"
        if dilution == "comment":
            layer_path.write_bytes(_gzip_with_comment(raw_tar, b"A" * 4096))
        else:
            layer_path.write_bytes((gzip.compress(b"") * 128) + gzip.compress(raw_tar))

        manifest_path = tmp_path / f"{dilution}.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner({"compressed_max_decompression_ratio": 100.0}).scan(str(manifest_path))

        assert result.success is False
        assert "oci_layer_decompression_ratio_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_scan_layer_follows_nul_padded_gzip_continuation(self, tmp_path: Path) -> None:
        """Permitted NUL padding between gzip members must not hide later expanded bytes."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")
        raw_tar_path = tmp_path / "raw-continuation.tar"
        with tarfile.open(raw_tar_path, "w") as tar:
            tar.add(payload, arcname="payload.bin")
        raw_tar = raw_tar_path.read_bytes()

        layer_path = tmp_path / "padded-continuation.tar.gz"
        layer_path.write_bytes(gzip.compress(raw_tar) + (b"\0" * 10) + gzip.compress(b"\0" * 64 * 1024))
        manifest_path = tmp_path / "padded-continuation.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"compressed_max_decompressed_bytes": len(raw_tar) + 1024}).scan(
                str(manifest_path)
            )

        assert result.success is False
        assert mock_copy.call_count == 1
        assert "oci_layer_decompressed_size_exceeded" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("corruption", ["checksum", "truncated"])
    def test_scan_layer_rejects_corrupt_gzip_before_tar_parsing(self, tmp_path: Path, corruption: str) -> None:
        """CRC and trailer truncation must fail preflight even when TAR EOF hides them from tarfile."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")
        layer_path = tmp_path / f"{corruption}.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(payload, arcname="payload.bin")
        encoded = bytearray(layer_path.read_bytes())
        if corruption == "checksum":
            encoded[-8] ^= 0x01
        else:
            del encoded[-4:]
        layer_path.write_bytes(encoded)

        manifest_path = tmp_path / f"{corruption}.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.open") as mock_tar_open:
            result = OciLayerScanner().scan(str(manifest_path))

        mock_tar_open.assert_not_called()
        assert result.success is False
        assert "oci_layer_processing_failed" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("budget", ["members", "metadata", "header", "padding"])
    def test_scan_layer_bounds_gzip_framing_work(self, tmp_path: Path, budget: str) -> None:
        """Gzip member and optional-header floods must fail before TAR parsing."""
        scanner = OciLayerScanner()
        if budget == "members":
            encoded = gzip.compress(b"") * (scanner._MAX_GZIP_MEMBERS + 1)
            expected_message = "member count exceeded"
        elif budget == "metadata":
            comment = b"A" * (scanner._MAX_GZIP_HEADER_BYTES - 32)
            member_count = (scanner._MAX_GZIP_METADATA_BYTES // len(comment)) + 2
            encoded = b"".join(_gzip_with_comment(b"", comment) for _ in range(member_count))
            expected_message = "metadata limit exceeded"
        elif budget == "header":
            encoded = _gzip_with_comment(b"", b"A" * scanner._MAX_GZIP_HEADER_BYTES)
            expected_message = "header limit exceeded"
        else:
            encoded = gzip.compress(b"") + (b"\0" * (scanner._MAX_GZIP_PADDING_BYTES + 1))
            expected_message = "padding limit exceeded"

        layer_path = tmp_path / f"{budget}-budget.tar.gz"
        layer_path.write_bytes(encoded)
        manifest_path = tmp_path / f"{budget}-budget.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.open") as mock_tar_open:
            result = scanner.scan(str(manifest_path))

        mock_tar_open.assert_not_called()
        assert result.success is False
        assert "oci_layer_gzip_structure_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(expected_message in check.message for check in result.checks)

    def test_scan_layer_counts_hidden_pax_headers_against_entry_budget(self, tmp_path: Path) -> None:
        """PAX headers consumed internally by tarfile must still count toward raw entry limits."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")
        layer_path = tmp_path / "pax.tar.gz"
        with tarfile.open(layer_path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            tar.add(payload, arcname=f"{'nested/' * 20}payload.bin")

        manifest_path = tmp_path / "pax.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.open") as mock_tar_open:
            result = OciLayerScanner({"max_oci_layer_entries": 1}).scan(str(manifest_path))

        mock_tar_open.assert_not_called()
        assert result.success is False
        assert "oci_layer_entry_count_exceeded" in result.metadata["scan_outcome_reasons"]
        check = next(check for check in result.checks if check.name == "Layer Decompression Budget Check")
        assert check.details["hidden_entries"] == 1

    def test_scan_layer_stops_after_visible_members_within_raw_entry_budget(self, tmp_path: Path) -> None:
        """Visible entries beyond a hidden-header-adjusted raw limit must not be parsed."""
        first_payload = tmp_path / "first.bin"
        first_payload.write_bytes(b"first")
        second_payload = tmp_path / "second.bin"
        second_payload.write_bytes(b"second")
        layer_path = tmp_path / "pax-plus-visible.tar.gz"
        with tarfile.open(layer_path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            tar.add(first_payload, arcname=f"{'nested/' * 20}first.bin")
            tar.add(second_payload, arcname="second.bin")

        manifest_path = tmp_path / "pax-plus-visible.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"max_oci_layer_entries": 2}).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 1
        assert "oci_layer_entry_count_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_scan_layer_rejects_oversized_gnu_metadata_before_tar_parsing(self, tmp_path: Path) -> None:
        """A large GNU long-name body must hit preflight limits before tarfile can allocate it."""
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"safe")
        layer_path = tmp_path / "long-name.tar.gz"
        with tarfile.open(layer_path, "w:gz", format=tarfile.GNU_FORMAT) as tar:
            tar.add(payload, arcname=f"{'a' * (2 * 1024 * 1024)}/payload.bin")

        manifest_path = tmp_path / "long-name.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.open") as mock_tar_open:
            result = OciLayerScanner(
                {
                    "compressed_max_decompressed_bytes": 1024,
                    "compressed_max_decompression_ratio": 10000.0,
                }
            ).scan(str(manifest_path))

        mock_tar_open.assert_not_called()
        assert result.success is False
        assert "oci_layer_decompressed_size_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_scan_layer_rejects_non_regular_layer_path(self, tmp_path: Path) -> None:
        """Directory and device-like layer paths must not be opened as gzip streams."""
        layer_path = tmp_path / "directory.tar.gz"
        layer_path.mkdir()
        manifest_path = tmp_path / "directory.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        assert "oci_layer_processing_failed" in result.metadata["scan_outcome_reasons"]
        assert any("not a regular file" in check.message for check in result.checks)

    def test_huge_ratio_config_falls_back_to_default(self) -> None:
        """Integer-to-float overflow in untrusted config must not crash scanner construction."""
        scanner = OciLayerScanner({"compressed_max_decompression_ratio": 10**400})

        assert scanner.max_decompression_ratio == scanner._DEFAULT_MAX_DECOMPRESSION_RATIO

    @pytest.mark.parametrize("budget", ["size", "ratio"])
    def test_scan_layer_reports_early_malicious_member_before_stream_budget_exhaustion(
        self,
        tmp_path: Path,
        budget: str,
    ) -> None:
        """Later expansion must not suppress malicious members completed inside the safe prefix."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
        filler = tmp_path / "zeros.bin"
        filler.write_bytes(b"\0" * 1024 * 1024)

        layer_path = tmp_path / f"early-malicious-{budget}.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="payload.pkl")
            tar.add(filler, arcname="zeros.bin")

        manifest_path = tmp_path / f"early-malicious-{budget}.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))
        config: dict[str, int | float]
        if budget == "size":
            config = {
                "compressed_max_decompressed_bytes": 32 * 1024,
                "compressed_max_decompression_ratio": 10000.0,
            }
            expected_reason = "oci_layer_decompressed_size_exceeded"
        else:
            config = {
                "compressed_max_decompressed_bytes": 2 * 1024 * 1024,
                "compressed_max_decompression_ratio": 10.0,
            }
            expected_reason = "oci_layer_decompression_ratio_exceeded"

        result = OciLayerScanner(config).scan(str(manifest_path))

        assert result.success is False
        assert expected_reason in result.metadata["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and f"{manifest_path.name}:{layer_path.name}:payload.pkl" in (issue.location or "")
            for issue in result.issues
        )

    def test_scan_layer_scans_in_budget_members_before_entry_count_exhaustion(self, tmp_path: Path) -> None:
        """Layer entry exhaustion should preserve findings from members already within budget."""
        layer_path = tmp_path / "many.tar.gz"
        with tarfile.open(layer_path, "w:gz", format=tarfile.GNU_FORMAT) as tar:
            for index in range(3):
                member_path = tmp_path / f"member-{index}.bin"
                member_path.write_bytes(b"safe")
                tar.add(member_path, arcname=f"member-{index}.bin")

        manifest_path = tmp_path / "many.manifest"
        manifest_path.write_text(json.dumps({"layers": ["many.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.shutil.copyfileobj", wraps=shutil.copyfileobj) as mock_copy:
            result = OciLayerScanner({"max_oci_layer_entries": 2}).scan(str(manifest_path))

        assert result.success is False
        assert mock_copy.call_count == 2
        assert "oci_layer_entry_count_exceeded" in result.metadata["scan_outcome_reasons"]
        checks = [check for check in result.checks if check.name == "Layer Decompression Budget Check"]
        assert len(checks) == 1
        assert checks[0].details["entries"] == 3
        assert "too many entries" in checks[0].message.lower()

        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_layer_entry_count_exceeded",
            tmp_path / "entry-count-cache",
            max_oci_layer_entries=2,
        )

    def test_scan_layer_reports_early_malicious_member_before_entry_count_exhaustion(self, tmp_path: Path) -> None:
        """Later filler entries should not suppress malicious members scanned before the cap is hit."""
        evil_pickle = Path(__file__).parent.parent / "assets/samples/pickles/evil.pickle"
        benign_member = tmp_path / "notes.txt"
        benign_member.write_text("safe")

        layer_path = tmp_path / "early-malicious.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(evil_pickle, arcname="payload.pkl")
            tar.add(benign_member, arcname="notes-1.txt")
            tar.add(benign_member, arcname="notes-2.txt")

        manifest_path = tmp_path / "early-malicious.manifest"
        manifest_path.write_text(json.dumps({"layers": ["early-malicious.tar.gz"]}))

        result = OciLayerScanner({"max_oci_layer_entries": 2}).scan(str(manifest_path))

        assert result.success is False
        assert "oci_layer_entry_count_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and "early-malicious.manifest:early-malicious.tar.gz:payload.pkl" in (issue.location or "")
            for issue in result.issues
        )

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

        assert result.success is False
        assert created_paths
        assert all(not Path(path).exists() for path in created_paths)
        assert any("Error processing layer" in issue.message for issue in result.issues)

    def test_scan_member_extraction_failure_is_inconclusive(self, tmp_path: Path) -> None:
        """A member that cannot be extracted represents incomplete coverage, not malicious content."""
        safe_file = tmp_path / "safe.txt"
        safe_file.write_text("safe content")

        layer_path = tmp_path / "layer.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(safe_file, arcname="safe.txt")

        manifest_path = tmp_path / "extraction-failure.manifest"
        manifest_path.write_text(json.dumps({"layers": ["layer.tar.gz"]}))

        with patch("modelaudit.scanners.oci_layer_scanner.tarfile.TarFile.extractfile", return_value=None):
            result = OciLayerScanner().scan(str(manifest_path))

            assert result.success is False
            assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert "oci_member_extraction_failed" in result.metadata["scan_outcome_reasons"]
            assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
            _assert_inconclusive_aggregate_not_cached(
                manifest_path,
                "oci_member_extraction_failed",
                tmp_path / "extraction-cache",
            )

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

    def test_scan_layer_reports_member_path_traversal_metadata(self, tmp_path: Path) -> None:
        """Unsafe member names should be reported even though OCI uses temp extraction."""
        payload = tmp_path / "payload.pkl"
        payload.write_bytes(b"safe")

        layer_path = tmp_path / "traversal.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(payload, arcname="../../payload.pkl")

        manifest_path = tmp_path / "traversal.manifest"
        manifest_path.write_text(json.dumps({"layers": ["traversal.tar.gz"]}))

        with patch("modelaudit.core.scan_file") as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        mock_scan.assert_not_called()
        assert result.success is False
        checks = [check for check in result.checks if check.name == "Path Traversal Protection"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.CRITICAL
        assert checks[0].message == "Layer member ../../payload.pkl attempted path traversal outside the layer"
        assert checks[0].details["member"] == "../../payload.pkl"

        cache_dir = tmp_path / "traversal-cache"
        reset_cache_manager()
        try:
            aggregate = scan_model_directory_or_file(
                str(manifest_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert determine_exit_code(aggregate) == 1
            assert any(
                issue.message == "Layer member ../../payload.pkl attempted path traversal outside the layer"
                for issue in aggregate.issues
            )
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_scan_layer_reports_unsafe_link_metadata(self, tmp_path: Path) -> None:
        """Host-absolute symlink targets should be reported from layer metadata."""
        layer_path = tmp_path / "unsafe-link.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("links/system")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "C:\\Windows\\System32\\config\\SAM"
            tar.addfile(link_info)

        manifest_path = tmp_path / "unsafe-link.manifest"
        manifest_path.write_text(json.dumps({"layers": ["unsafe-link.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.CRITICAL
        assert checks[0].details["target"] == "C:\\Windows\\System32\\config\\SAM"

    @pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
    def test_scan_layer_reports_empty_link_target(self, tmp_path: Path, link_type: bytes) -> None:
        """Links without a target are malformed and must not be treated as safe."""
        layer_path = tmp_path / "empty-link.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("links/empty")
            link_info.type = link_type
            link_info.linkname = ""
            tar.addfile(link_info)

        manifest_path = tmp_path / "empty-link.manifest"
        manifest_path.write_text(json.dumps({"layers": ["empty-link.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.CRITICAL
        assert checks[0].message == "Layer link links/empty has an empty target"
        assert checks[0].details["target"] == ""

    @pytest.mark.parametrize("target", ["/bin/dash", "/C:/models/model.bin"])
    def test_scan_layer_allows_posix_absolute_symlink_within_container_root(
        self,
        tmp_path: Path,
        target: str,
    ) -> None:
        """OCI rootfs symlinks may use ordinary POSIX-absolute container paths."""
        layer_path = tmp_path / "absolute-container-link.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("bin/sh")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = target
            tar.addfile(link_info)

        manifest_path = tmp_path / "absolute-container-link.manifest"
        manifest_path.write_text(json.dumps({"layers": ["absolute-container-link.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert checks == []

    def test_scan_layer_reports_absolute_hardlink_target(self, tmp_path: Path) -> None:
        """Hardlink targets remain archive-root relative and must not be absolute."""
        layer_path = tmp_path / "absolute-hardlink.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("bin/tool")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "/bin/target"
            tar.addfile(link_info)

        manifest_path = tmp_path / "absolute-hardlink.manifest"
        manifest_path.write_text(json.dumps({"layers": ["absolute-hardlink.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.CRITICAL
        assert checks[0].details["target"] == "/bin/target"

    def test_scan_layer_allows_safe_link_metadata(self, tmp_path: Path) -> None:
        """Benign relative link metadata should remain clean."""
        layer_path = tmp_path / "safe-link.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("links/model")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "model.bin"
            tar.addfile(link_info)

        manifest_path = tmp_path / "safe-link.manifest"
        manifest_path.write_text(json.dumps({"layers": ["safe-link.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert checks == []

    def test_scan_layer_allows_symlink_target_under_layer_root(self, tmp_path: Path) -> None:
        """Symlink targets are resolved from the link directory but contained by the layer root."""
        layer_path = tmp_path / "safe-sibling-link.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("usr/bin/tool")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "../lib/tool"
            tar.addfile(link_info)

        manifest_path = tmp_path / "safe-sibling-link.manifest"
        manifest_path.write_text(json.dumps({"layers": ["safe-sibling-link.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert checks == []

    def test_resolve_symlink_target_does_not_follow_host_symlinks(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Layer metadata validation should not depend on host filesystem symlinks."""
        extraction_root = tmp_path / "extract"
        extraction_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (extraction_root / "usr").symlink_to(outside, target_is_directory=True)

        resolved, is_safe = OciLayerScanner._resolve_link_target(
            "../lib/tool",
            resolved_member_name=str(extraction_root / "usr/bin/tool"),
            extraction_root=str(extraction_root),
            is_symlink=True,
        )

        assert resolved == str(extraction_root / "usr/lib/tool")
        assert is_safe is True

    def test_resolve_symlink_target_rejects_host_alias_back_into_layer_root(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Host aliases must not make lexically escaping layer links appear safe."""
        extraction_root = tmp_path / "extract"
        extraction_root.mkdir()
        (tmp_path / "alias").symlink_to(extraction_root, target_is_directory=True)

        resolved, is_safe = OciLayerScanner._resolve_link_target(
            "../../../alias/etc/passwd",
            resolved_member_name=str(extraction_root / "usr/bin/tool"),
            extraction_root=str(extraction_root),
            is_symlink=True,
        )

        assert resolved == str(tmp_path / "alias/etc/passwd")
        assert is_safe is False

    def test_scan_layer_reports_symlink_target_traversal_outside_layer_root(self, tmp_path: Path) -> None:
        """Symlink targets that escape the layer root should still be rejected."""
        layer_path = tmp_path / "unsafe-relative-link.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("usr/bin/tool")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "../../../etc/passwd"
            tar.addfile(link_info)

        manifest_path = tmp_path / "unsafe-relative-link.manifest"
        manifest_path.write_text(json.dumps({"layers": ["unsafe-relative-link.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.CRITICAL
        assert checks[0].details["target"] == "../../../etc/passwd"

    def test_scan_layer_reports_hardlink_target_traversal_from_layer_root(self, tmp_path: Path) -> None:
        """Hardlink targets are archive-root relative, not relative to the link directory."""
        layer_path = tmp_path / "unsafe-hardlink.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("dir/link")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "../dir/model.bin"
            tar.addfile(link_info)

        manifest_path = tmp_path / "unsafe-hardlink.manifest"
        manifest_path.write_text(json.dumps({"layers": ["unsafe-hardlink.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is False
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert len(checks) == 1
        assert checks[0].severity == IssueSeverity.CRITICAL
        assert checks[0].details["target"] == "../dir/model.bin"

    def test_scan_layer_allows_safe_hardlink_target_from_layer_root(self, tmp_path: Path) -> None:
        """Benign hardlink targets under the archive root should remain clean."""
        layer_path = tmp_path / "safe-hardlink.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            link_info = tarfile.TarInfo("dir/link")
            link_info.type = tarfile.LNKTYPE
            link_info.linkname = "dir/model.bin"
            tar.addfile(link_info)

        manifest_path = tmp_path / "safe-hardlink.manifest"
        manifest_path.write_text(json.dumps({"layers": ["safe-hardlink.tar.gz"]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
        assert checks == []

    def test_scan_layer_does_not_retain_checks_for_many_safe_links(self, tmp_path: Path) -> None:
        """Benign link floods must not amplify a small layer into a large result."""
        layer_path = tmp_path / "many-links.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            for index in range(250):
                link_info = tarfile.TarInfo(f"links/link-{index}")
                link_info.type = tarfile.SYMTYPE
                link_info.linkname = "../targets/model.bin"
                tar.addfile(link_info)

        manifest_path = tmp_path / "many-links.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner(
            {
                "max_oci_layer_entries": 300,
                "compressed_max_decompression_ratio": 10000.0,
            }
        ).scan(str(manifest_path))

        assert result.success is True
        assert not [check for check in result.checks if check.name == "Symlink Safety Validation"]

    def test_scan_layer_reports_normalized_duplicate_paths_and_scans_both_members(self, tmp_path: Path) -> None:
        """OCI-invalid path aliases must fail closed without hiding either payload."""
        payload = tmp_path / "payload.txt"
        payload.write_text("safe")
        layer_path = tmp_path / "duplicate.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.add(payload, arcname="same.txt")
            tar.add(payload, arcname="./same.txt")

        manifest_path = tmp_path / "duplicate.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        def clean_scan(_path: str, _config: dict[str, Any]) -> ScanResult:
            nested_result = ScanResult(scanner_name="unknown")
            nested_result.finish()
            return nested_result

        with patch("modelaudit.core.scan_file", side_effect=clean_scan) as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        checks = [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]
        assert result.success is False
        assert mock_scan.call_count == 2
        assert len(checks) == 1
        assert checks[0].details["normalized_path"] == "same.txt"
        assert "duplicates normalized path" in checks[0].message

    @pytest.mark.parametrize(
        ("member_name", "payload", "expected_scan_calls"),
        [(".wh.", b"", 0), (".wh.deleted", b"payload", 1)],
    )
    def test_scan_layer_reports_invalid_whiteout_metadata(
        self,
        tmp_path: Path,
        member_name: str,
        payload: bytes,
        expected_scan_calls: int,
    ) -> None:
        """Bare or non-empty whiteout markers are invalid OCI layer metadata."""
        layer_path = tmp_path / "invalid-whiteout.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            whiteout = tarfile.TarInfo(member_name)
            whiteout.size = len(payload)
            tar.addfile(whiteout, io.BytesIO(payload))

        manifest_path = tmp_path / "invalid-whiteout.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        nested_result = ScanResult(scanner_name="unknown")
        nested_result.finish()
        with patch("modelaudit.core.scan_file", return_value=nested_result) as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        checks = [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]
        assert result.success is False
        assert mock_scan.call_count == expected_scan_calls
        assert len(checks) == 1
        assert "valid empty OCI whiteout" in checks[0].message

    def test_scan_layer_allows_valid_empty_whiteouts(self, tmp_path: Path) -> None:
        """Deletion and opaque-directory whiteouts are valid empty regular files."""
        layer_path = tmp_path / "valid-whiteout.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            tar.addfile(tarfile.TarInfo("root/.wh.deleted"))
            tar.addfile(tarfile.TarInfo("root/.wh..wh..opq"))

        manifest_path = tmp_path / "valid-whiteout.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        with patch("modelaudit.core.scan_file") as mock_scan:
            result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        mock_scan.assert_not_called()
        assert not [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]

    def test_scan_layer_reports_reserved_whiteout_parent_component(self, tmp_path: Path) -> None:
        """Implicit directories with reserved whiteout names are invalid OCI metadata."""
        layer_path = tmp_path / "reserved-whiteout-parent.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            payload = b"benign"
            member = tarfile.TarInfo("root/.wh.deleted/payload.dat")
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))

        manifest_path = tmp_path / "reserved-whiteout-parent.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner().scan(str(manifest_path))

        checks = [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]
        assert result.success is False
        assert len(checks) == 1
        assert checks[0].message == (
            "Layer member root/.wh.deleted/payload.dat uses reserved OCI whiteout path component .wh.deleted"
        )
        assert checks[0].details["reserved_component"] == ".wh.deleted"

    @pytest.mark.parametrize(
        "member_name",
        [
            "root/.wh.deleted/../payload.dat",
            "root\\.wh.deleted\\..\\payload.dat",
        ],
    )
    def test_scan_layer_reports_reserved_whiteout_parent_hidden_by_normalization(
        self,
        tmp_path: Path,
        member_name: str,
    ) -> None:
        """Dot segments must not erase a reserved raw whiteout component."""
        layer_path = tmp_path / "normalized-whiteout-parent.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            payload = b"benign"
            member = tarfile.TarInfo(member_name)
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))

        manifest_path = tmp_path / "normalized-whiteout-parent.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner().scan(str(manifest_path))

        checks = [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]
        assert result.success is False
        assert len(checks) == 1
        assert checks[0].details["reserved_component"] == ".wh.deleted"

    def test_scan_layer_allows_whiteout_prefix_near_match_in_parent_component(self, tmp_path: Path) -> None:
        """Ordinary parent directory names that merely start similarly remain valid."""
        layer_path = tmp_path / "whiteout-parent-near-match.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            payload = b"benign"
            member = tarfile.TarInfo("root/.whitehouse/payload.dat")
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))

        manifest_path = tmp_path / "whiteout-parent-near-match.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        assert not [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]

    def test_scan_layer_allows_normalized_whiteout_prefix_near_match(self, tmp_path: Path) -> None:
        """Normalization through an ordinary similarly named directory remains benign."""
        layer_path = tmp_path / "normalized-whiteout-parent-near-match.tar.gz"
        with tarfile.open(layer_path, "w:gz") as tar:
            payload = b"benign"
            member = tarfile.TarInfo("root/.whitehouse/../payload.dat")
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))

        manifest_path = tmp_path / "normalized-whiteout-parent-near-match.manifest"
        manifest_path.write_text(json.dumps({"layers": [layer_path.name]}))

        result = OciLayerScanner().scan(str(manifest_path))

        assert result.success is True
        assert not [check for check in result.checks if check.name == "OCI Layer Metadata Validation"]

    def test_scan_corrupted_tar_layer(self, tmp_path: Path) -> None:
        """Test scanning corrupted tar layer."""
        # Create a file that looks like tar.gz but is corrupted
        layer_path = tmp_path / "corrupted.tar.gz"
        layer_path.write_bytes(b"corrupted tar.gz content")

        manifest = {"layers": ["corrupted.tar.gz"]}
        manifest_path = tmp_path / "test.manifest"
        manifest_path.write_text(json.dumps(manifest))

        scanner = OciLayerScanner()
        result = scanner.scan(str(manifest_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "oci_layer_processing_failed" in result.metadata["scan_outcome_reasons"]
        assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)
        assert any("Error processing layer" in issue.message for issue in result.issues)
        _assert_inconclusive_aggregate_not_cached(
            manifest_path,
            "oci_layer_processing_failed",
            tmp_path / "processing-cache",
        )

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

    def test_layer_with_multiple_model_files(self, tmp_path: Path) -> None:
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

        assert result.success is False
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        # Should have issues from both model files
        assert len(critical_issues) >= 2

        locations = [issue.location for issue in critical_issues]
        assert any("model1.pkl" in (loc or "") for loc in locations)
        assert any("model2.pkl" in (loc or "") for loc in locations)


# Keep the original test for backward compatibility
def test_oci_layer_scanner_with_malicious_pickle(tmp_path: Path) -> None:
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

    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
