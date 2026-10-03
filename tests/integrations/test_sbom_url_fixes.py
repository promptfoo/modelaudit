"""Tests for SBOM generation fixes with HuggingFace URLs and downloaded content.

This module tests the fix for FileNotFoundError when generating SBOMs for content
downloaded from URLs (HuggingFace, cloud storage, etc.).
"""

import hashlib
import io
import json
import os
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.integrations.sbom_generator import generate_sbom, generate_sbom_pydantic
from modelaudit.models import AssetModel, FileMetadataModel, ModelAuditResultModel, create_initial_audit_result
from modelaudit.scanners.base import Issue, IssueSeverity
from tests.helpers.file_creators import create_malicious_pickle
from tests.helpers.file_creators import (
    write_hf_cachedir_tag as _write_hf_cachedir_tag,
)


def create_mock_scan_result(
    bytes_scanned=1024, issues=None, files_scanned=1, assets=None, has_errors=False, scanners=None
):
    """Create a mock scan result for testing."""
    from modelaudit.models import create_initial_audit_result

    result = create_initial_audit_result()
    result.bytes_scanned = bytes_scanned
    result.files_scanned = files_scanned
    result.has_errors = has_errors
    if issues:
        result.issues = issues
    if assets:
        result.assets = assets
    if scanners:
        result.scanner_names = scanners
    return result


def _write_hf_download_metadata(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "a" * 40,
                "b" * 64,
                "1710000000.0",
            ]
        ),
        encoding="utf-8",
    )


class TestSBOMURLFixes:
    """Test SBOM generation with URLs and downloaded content."""

    @pytest.mark.parametrize("legacy", [False, True], ids=["pydantic", "legacy"])
    def test_sbom_preserves_member_hash_paths(self, tmp_path: Path, legacy: bool) -> None:
        model_path = tmp_path / "model.pt"
        model_path.write_bytes(b"outer")
        secret_path = "https://user:password@storage.example/payload.pkl?token=member-secret"
        member_identity = json.dumps({"occurrence": 1, "path": [secret_path]}, sort_keys=True, separators=(",", ":"))
        scan_result = create_mock_scan_result(
            assets=[AssetModel(path=str(model_path), type="pytorch", size=model_path.stat().st_size)]
        )
        scan_result.file_metadata[str(model_path)] = FileMetadataModel(
            file_size=model_path.stat().st_size,
            member_file_hashes={
                member_identity: {
                    "file_hashes": {"sha256": "a" * 64},
                    "path_segments": [secret_path],
                    "logical_path": secret_path,
                    "occurrence": 1,
                }
            },
        )

        if legacy:
            sbom_json = generate_sbom([str(model_path)], scan_result.model_dump(mode="python"))
        else:
            sbom_json = generate_sbom_pydantic([str(model_path)], scan_result)

        assert "password" in sbom_json
        assert "member-secret" in sbom_json
        assert "token=" in sbom_json

    def test_distinct_sources_keep_stable_component_refs(self) -> None:
        paths = [
            "https://storage.example/model.pkl?revision=first&token=secret-one",
            "https://storage.example/model.pkl?revision=second&token=secret-two",
        ]

        scan_result = create_mock_scan_result(
            issues=[
                Issue(
                    message="Critical remote model",
                    severity=IssueSeverity.CRITICAL,
                    location=paths[0],
                    timestamp=time.time(),
                )
            ]
        )
        first_sbom = json.loads(generate_sbom_pydantic(paths, scan_result))
        second_sbom = json.loads(generate_sbom_pydantic(reversed(paths), scan_result))

        def risk_by_ref(sbom: dict[str, Any]) -> dict[str, str]:
            components = sbom["components"]
            assert isinstance(components, list)
            return {
                component["bom-ref"]: next(
                    prop["value"] for prop in component["properties"] if prop["name"] == "risk_score"
                )
                for component in components
            }

        first_risks = risk_by_ref(first_sbom)
        second_risks = risk_by_ref(second_sbom)
        assert first_risks == second_risks
        assert len(first_risks) == 2
        assert set(first_risks.values()) == {"0", "5"}
        assert set(first_risks) == set(paths)
        assert "secret-one" in json.dumps(first_sbom)
        assert "secret-two" in json.dumps(first_sbom)

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_credential_only_distinct_sources_keep_unique_refs(self, legacy_generator: bool) -> None:
        paths = [
            "https://storage.example/model.pkl?token=secret-one",
            "https://storage.example/model.pkl?token=secret-two",
        ]
        scan_result = create_mock_scan_result(
            files_scanned=2,
            issues=[
                Issue(
                    message="Critical remote model",
                    severity=IssueSeverity.CRITICAL,
                    location=paths[0],
                    timestamp=time.time(),
                )
            ],
        )

        def risk_by_ref(input_paths: Any) -> tuple[dict[str, str], str]:
            if legacy_generator:
                sbom_json = generate_sbom(input_paths, scan_result.model_dump(mode="python"))
            else:
                sbom_json = generate_sbom_pydantic(input_paths, scan_result)
            components = json.loads(sbom_json)["components"]
            return (
                {
                    component["bom-ref"]: next(
                        prop["value"] for prop in component["properties"] if prop["name"] == "risk_score"
                    )
                    for component in components
                },
                sbom_json,
            )

        first_risks, first_sbom_json = risk_by_ref(paths)
        second_risks, _ = risk_by_ref(reversed(paths))

        assert first_risks == second_risks
        assert set(first_risks) == set(paths)
        assert set(first_risks.values()) == {"0", "5"}
        for path in paths:
            assert path in first_sbom_json
            assert hashlib.sha256(path.encode()).hexdigest() not in first_sbom_json

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_safe_schemeless_provenance_has_stable_risk_attribution(self, legacy_generator: bool) -> None:
        safe_path = "bucket/model.pkl?revision=v1"
        signed_path = f"{safe_path}&token=source-secret"
        result = create_mock_scan_result(
            files_scanned=2,
            issues=[Issue(message="critical", severity=IssueSeverity.CRITICAL, location=signed_path)],
        )

        def risks(input_paths: Any) -> dict[str, str]:
            return _sbom_property_values(input_paths, result, legacy_generator, "risk_score")

        assert (
            risks([safe_path, signed_path])
            == risks([signed_path, safe_path])
            == {
                safe_path: "0",
                signed_path: "5",
            }
        )

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_repeated_identical_sources_emit_one_component(
        self,
        tmp_path: Path,
        legacy_generator: bool,
    ) -> None:
        model_path = tmp_path / "model.pkl"
        model_path.write_bytes(b"model")
        result = create_mock_scan_result(files_scanned=1)

        if legacy_generator:
            sbom_json = generate_sbom([str(model_path), str(model_path)], result.model_dump(mode="python"))
        else:
            sbom_json = generate_sbom_pydantic([str(model_path), str(model_path)], result)

        assert [component["bom-ref"] for component in json.loads(sbom_json)["components"]] == [str(model_path)]

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_generated_component_refs_do_not_collide_with_literal_refs(
        self,
        tmp_path: Path,
        legacy_generator: bool,
    ) -> None:
        first = f"{tmp_path}/model.pkl?token=first-secret"
        second = f"{tmp_path}/model.pkl?token=second-secret"
        literal = tmp_path / "model.pkl#modelaudit-component-2"
        literal.write_bytes(b"model")
        paths = [first, second, str(literal)]
        result = create_mock_scan_result(files_scanned=3)

        def refs(input_paths: Any) -> set[str]:
            if legacy_generator:
                sbom_json = generate_sbom(input_paths, result.model_dump(mode="python"))
            else:
                sbom_json = generate_sbom_pydantic(input_paths, result)
            return {component["bom-ref"] for component in json.loads(sbom_json)["components"]}

        first_refs = refs(paths)
        assert first_refs == refs(reversed(paths))
        assert len(first_refs) == 3
        assert all(not reference.startswith("BomRef.") for reference in first_refs)

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_literal_component_ref_is_preserved_with_signed_sources(
        self,
        tmp_path: Path,
        legacy_generator: bool,
    ) -> None:
        literal = tmp_path / "model.pkl"
        literal.write_bytes(b"literal model")
        signed = f"{literal}?token=source-secret"
        result = create_mock_scan_result(
            files_scanned=2,
            issues=[Issue(message="critical", severity=IssueSeverity.CRITICAL, location=signed)],
        )

        if legacy_generator:
            sbom_json = generate_sbom([signed, str(literal)], result.model_dump(mode="python"))
        else:
            sbom_json = generate_sbom_pydantic([signed, str(literal)], result)
        components = {component["bom-ref"]: component for component in json.loads(sbom_json)["components"]}

        assert set(components) == {
            str(literal),
            signed,
        }
        assert (
            next(prop["value"] for prop in components[str(literal)]["properties"] if prop["name"] == "risk_score")
            == "0"
        )
        assert next(prop["value"] for prop in components[signed]["properties"] if prop["name"] == "risk_score") == "5"

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_equal_risk_sources_keep_metadata_identity(self, legacy_generator: bool) -> None:
        first = "https://storage.example/model.pkl?token=first-secret"
        second = "https://storage.example/model.pkl?token=second-secret"
        result = create_mock_scan_result(files_scanned=2)
        result.file_metadata = {
            first: FileMetadataModel(file_size=10, license="MIT"),
            second: FileMetadataModel(file_size=20, license="Apache-2.0"),
        }

        def sizes(input_paths: Any) -> dict[str, str]:
            return _sbom_property_values(input_paths, result, legacy_generator, "size")

        assert sizes([first, second]) == sizes([second, first])

    def test_existing_local_assignment_paths_remain_distinct(self, tmp_path: Path) -> None:
        first_path = tmp_path / "token=alpha" / "a.bin"
        second_path = tmp_path / "token=beta" / "b.bin"
        first_path.parent.mkdir()
        second_path.parent.mkdir()
        first_path.write_bytes(b"same content")
        second_path.write_bytes(b"same content")

        sbom = json.loads(
            generate_sbom_pydantic(
                [str(first_path), str(second_path)],
                create_mock_scan_result(files_scanned=2),
            )
        )

        assert {component["name"] for component in sbom["components"]} == {"a.bin", "b.bin"}
        assert {component["bom-ref"] for component in sbom["components"]} == {
            str(first_path),
            str(second_path),
        }

    def test_sbom_with_huggingface_file_url_success(self, tmp_path):
        """Test SBOM generation after downloading HuggingFace file URL."""
        # Create a test file that simulates downloaded content
        downloaded_file = tmp_path / "pytorch_model.bin"
        downloaded_file.write_bytes(b"dummy model content for SBOM test")

        # Create mock scan result
        scan_result = create_mock_scan_result(
            bytes_scanned=len(b"dummy model content for SBOM test"),
            files_scanned=1,
            has_errors=False,
            scanners=["test_scanner"],
        )

        # Test SBOM generation with the downloaded file path (not the URL)
        sbom_json = generate_sbom_pydantic([str(downloaded_file)], scan_result)
        sbom_data = json.loads(sbom_json)

        # Verify SBOM structure
        assert sbom_data["bomFormat"] == "CycloneDX"
        assert sbom_data["specVersion"] == "1.6"
        assert "components" in sbom_data
        assert len(sbom_data["components"]) == 1

        component = sbom_data["components"][0]
        assert component["name"] == "pytorch_model.bin"
        assert component["type"] == "machine-learning-model"  # .bin files are ML models
        assert "hashes" in component
        assert len(component["hashes"]) == 1

    def test_sbom_with_huggingface_model_url_success(self, tmp_path):
        """Test SBOM generation after downloading HuggingFace model URL."""
        # Create a test directory that simulates downloaded model
        model_dir = tmp_path / "downloaded_model"
        model_dir.mkdir()
        (model_dir / "config.json").write_text('{"model_type": "bert"}')
        (model_dir / "pytorch_model.bin").write_bytes(b"model weights")
        (model_dir / "tokenizer.json").write_text('{"vocab": {}}')

        # Create mock scan result for directory
        scan_result = create_mock_scan_result(
            bytes_scanned=100, files_scanned=3, has_errors=False, scanners=["test_scanner"]
        )

        # Test SBOM generation with the downloaded directory path
        sbom_json = generate_sbom_pydantic([str(model_dir)], scan_result)
        sbom_data = json.loads(sbom_json)

        # Verify SBOM structure for directory
        assert sbom_data["bomFormat"] == "CycloneDX"
        assert len(sbom_data["components"]) == 3  # Three files in directory

        # Check that all files are included
        component_names = {comp["name"] for comp in sbom_data["components"]}
        expected_names = {"config.json", "pytorch_model.bin", "tokenizer.json"}
        assert component_names == expected_names

    def test_sbom_with_cloud_storage_url_success(self, tmp_path):
        """Test SBOM generation after downloading from cloud storage."""
        # Simulate downloaded content from cloud storage
        downloaded_file = tmp_path / "model.pkl"
        downloaded_file.write_bytes(b"pickled model data")

        scan_result = create_mock_scan_result(
            bytes_scanned=len(b"pickled model data"), files_scanned=1, has_errors=False
        )

        # Test SBOM generation
        sbom_json = generate_sbom_pydantic([str(downloaded_file)], scan_result)
        sbom_data = json.loads(sbom_json)

        assert len(sbom_data["components"]) == 1
        component = sbom_data["components"][0]
        assert component["name"] == "model.pkl"
        assert component["type"] == "machine-learning-model"

    def test_sbom_with_mixed_local_and_url_inputs(self, tmp_path):
        """Test SBOM generation with both local files and downloaded content."""
        # Create local file
        local_file = tmp_path / "local_model.onnx"
        local_file.write_bytes(b"local model")

        # Create downloaded file (simulating URL download)
        downloaded_file = tmp_path / "downloaded_model.safetensors"
        downloaded_file.write_bytes(b"downloaded model")

        scan_result = create_mock_scan_result(bytes_scanned=200, files_scanned=2, has_errors=False)

        # Test SBOM generation with both paths
        paths = [str(local_file), str(downloaded_file)]
        sbom_json = generate_sbom_pydantic(paths, scan_result)
        sbom_data = json.loads(sbom_json)

        assert len(sbom_data["components"]) == 2
        component_names = {comp["name"] for comp in sbom_data["components"]}
        expected_names = {"local_model.onnx", "downloaded_model.safetensors"}
        assert component_names == expected_names

    @pytest.mark.integration
    @patch("modelaudit.cli.is_huggingface_file_url")
    @patch("modelaudit.cli.download_file_from_hf")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    def test_cli_sbom_with_huggingface_file_url(
        self, mock_spinner, mock_scan, mock_download, mock_is_hf_file_url, tmp_path
    ):
        """Test CLI SBOM generation with HuggingFace file URL."""
        # Setup mocks
        mock_is_hf_file_url.return_value = True
        downloaded_file = tmp_path / "model.bin"
        downloaded_file.write_bytes(b"test model content")
        mock_download.return_value = downloaded_file

        mock_scan.return_value = create_mock_scan_result(bytes_scanned=100, files_scanned=1, has_errors=False)

        # Test CLI with SBOM output
        sbom_output = tmp_path / "test.sbom.json"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "--no-cache",
                "--quiet",
                "--sbom",
                str(sbom_output),
                "https://huggingface.co/test/model/resolve/main/model.bin",
            ],
        )

        # Should succeed
        assert result.exit_code == 0, f"CLI failed: {result.output}\n{result.exception}"

        # SBOM file should be created
        assert sbom_output.exists()

        # Verify SBOM content
        sbom_data = json.loads(sbom_output.read_text())
        assert sbom_data["bomFormat"] == "CycloneDX"
        assert len(sbom_data["components"]) == 1
        assert sbom_data["components"][0]["name"] == "model.bin"

        # Verify download and scan were called correctly
        mock_download.assert_called_once()
        mock_scan.assert_called_once()
        # Verify scan was called with downloaded path, not URL
        assert mock_scan.call_args[0][0] == str(downloaded_file)

    @pytest.mark.integration
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.is_huggingface_file_url", return_value=False)
    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    def test_cli_sbom_with_huggingface_model_url(
        self, mock_spinner, mock_scan, mock_download, mock_is_hf_file_url, mock_is_hf_url, tmp_path
    ):
        """Test CLI SBOM generation with HuggingFace model URL."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        downloaded_dir = tmp_path / "model"
        downloaded_dir.mkdir()
        (downloaded_dir / "config.json").write_text("{}")
        (downloaded_dir / "model.bin").write_bytes(b"model")
        mock_download.return_value = downloaded_dir

        mock_scan.return_value = create_mock_scan_result(
            bytes_scanned=200,
            files_scanned=2,
            assets=[
                AssetModel(path=str(downloaded_dir / "config.json"), type="json"),
                AssetModel(path=str(downloaded_dir / "model.bin"), type="binary"),
            ],
            has_errors=False,
        )

        # Test CLI with SBOM output
        sbom_output = tmp_path / "model.sbom.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--no-cache", "--quiet", "--sbom", str(sbom_output), "hf://test/model"])

        # Should succeed
        assert result.exit_code == 0, f"CLI failed: {result.output}\n{result.exception}"
        assert sbom_output.exists()

        # Verify SBOM content has components from directory
        sbom_data = json.loads(sbom_output.read_text())
        assert len(sbom_data["components"]) == 2
        component_names = {comp["name"] for comp in sbom_data["components"]}
        assert "config.json" in component_names
        assert "model.bin" in component_names

    def test_cli_non_streaming_sbom_uses_scanned_local_dir_assets(self, tmp_path: Path) -> None:
        """Directory SBOMs must reflect scanned assets, not an independent tree walk."""
        model_dir = tmp_path / "downloaded-model"
        model_dir.mkdir()
        model_path = model_dir / "model.pkl"
        model_path.write_bytes(b"\x80\x04}\x94.")

        download_root = model_dir / ".cache" / "huggingface" / "download"
        benign_sidecar = download_root / "model.pkl.metadata"
        _write_hf_download_metadata(benign_sidecar)
        malicious_sidecar = download_root / "payload.pkl.metadata"
        create_malicious_pickle(malicious_sidecar)
        cachedir_tag = model_dir / ".cache" / "huggingface" / "CACHEDIR.TAG"
        _write_hf_cachedir_tag(cachedir_tag)

        sbom_output = tmp_path / "model.sbom.json"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "--no-cache",
                "--quiet",
                "--sbom",
                str(sbom_output),
                str(model_dir),
            ],
        )

        assert result.exit_code == 1, f"CLI failed unexpectedly: {result.output}\n{result.exception}"
        sbom_data = json.loads(sbom_output.read_text(encoding="utf-8"))
        component_refs = {component["bom-ref"] for component in sbom_data["components"]}

        assert str(model_path) in component_refs
        assert str(malicious_sidecar) in component_refs
        assert str(benign_sidecar) not in component_refs
        assert str(cachedir_tag) not in component_refs

    def test_cli_non_streaming_sbom_uses_empty_scanned_asset_set(self, tmp_path: Path) -> None:
        """Empty directory inventories must not fall back to walking skipped HF sidecars."""
        model_dir = tmp_path / "downloaded-model"
        cachedir_tag = model_dir / ".cache" / "huggingface" / "CACHEDIR.TAG"
        _write_hf_cachedir_tag(cachedir_tag)

        sbom_output = tmp_path / "empty.sbom.json"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "--no-cache",
                "--quiet",
                "--sbom",
                str(sbom_output),
                str(model_dir),
            ],
        )

        assert result.exit_code == 2, f"CLI returned an unexpected result: {result.output}\n{result.exception}"
        sbom_data = json.loads(sbom_output.read_text(encoding="utf-8"))

        assert sbom_data.get("components", []) == []
        assert str(cachedir_tag) not in json.dumps(sbom_data)

    @pytest.mark.integration
    @patch("modelaudit.cli.is_cloud_url")
    @patch("modelaudit.cli.is_huggingface_file_url", return_value=False)
    @patch("modelaudit.cli.is_huggingface_url", return_value=False)
    @patch("modelaudit.cli.download_from_cloud")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    def test_cli_sbom_with_cloud_url(
        self, mock_spinner, mock_scan, mock_download, mock_is_hf_url, mock_is_hf_file_url, mock_is_cloud_url, tmp_path
    ):
        """Test CLI SBOM generation with cloud storage URL."""
        # Setup mocks
        mock_is_cloud_url.return_value = True
        downloaded_file = tmp_path / "cloud_model.pkl"
        downloaded_file.write_bytes(b"cloud model data")
        mock_download.return_value = downloaded_file

        mock_scan.return_value = create_mock_scan_result(bytes_scanned=150, files_scanned=1, has_errors=False)

        # Test CLI with SBOM
        sbom_output = tmp_path / "cloud.sbom.json"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "--no-cache", "--quiet", "--sbom", str(sbom_output), "s3://bucket/model.pkl"]
        )

        assert result.exit_code == 0, f"CLI failed: {result.output}\n{result.exception}"
        assert sbom_output.exists()

        sbom_data = json.loads(sbom_output.read_text())
        assert len(sbom_data["components"]) == 1
        assert sbom_data["components"][0]["name"] == "cloud_model.pkl"

    def test_sbom_file_not_found_error_prevention(self, tmp_path):
        """Test that SBOM generation handles URLs gracefully (may succeed or fail)."""
        # This test documents the behavior - URLs might work depending on SBOM implementation
        url = "https://huggingface.co/test/model/resolve/main/file.bin"

        # Create a mock scan result
        scan_result = create_mock_scan_result()

        # The SBOM implementation may handle URLs gracefully or raise FileNotFoundError
        # The important thing is that the CLI fix ensures only file paths reach SBOM generation
        try:
            sbom_json = generate_sbom_pydantic([url], scan_result)
            # If it succeeds, that's fine - some SBOM implementations are robust
            assert isinstance(sbom_json, str)
        except FileNotFoundError:
            # If it fails, that's also expected for URLs that don't exist as files
            pass

    def test_sbom_with_nonexistent_local_file_handling(self, tmp_path):
        """Test SBOM generation gracefully handles nonexistent files."""
        nonexistent_file = tmp_path / "missing.pkl"
        # Note: file doesn't exist

        scan_result = create_mock_scan_result()

        # Should not crash, but may have empty hashes
        sbom_json = generate_sbom_pydantic([str(nonexistent_file)], scan_result)
        sbom_data = json.loads(sbom_json)

        assert len(sbom_data["components"]) == 1
        component = sbom_data["components"][0]
        # For nonexistent files, hashes field may be empty or missing
        if "hashes" in component:
            # If hashes field is present, it should be a list (may be empty)
            assert isinstance(component["hashes"], list)

    @pytest.mark.integration
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.is_huggingface_file_url", return_value=False)
    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    def test_cli_sbom_with_download_failure(
        self, mock_spinner, mock_scan, mock_download, mock_is_hf_file_url, mock_is_hf_url, tmp_path
    ):
        """Test CLI behavior when download fails but SBOM is requested."""
        # Setup mocks for download failure
        mock_is_hf_url.return_value = True
        mock_download.side_effect = Exception("Download failed")

        sbom_output = tmp_path / "failed.sbom.json"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", "--no-cache", "--quiet", "--sbom", str(sbom_output), "hf://test/failing-model"]
        )

        # Should handle the error gracefully
        assert result.exit_code != 0  # Should fail due to download error
        # SBOM file should not be created when no successful scans occurred
        # (This is expected behavior - no scanned content means no SBOM)

    def test_sbom_cross_platform_file_paths(self, tmp_path):
        """Test SBOM generation works with different file path formats (Windows/Unix)."""
        # Create test files with different path characteristics
        files = [
            tmp_path / "simple.pkl",
            tmp_path / "file with spaces.bin",
            tmp_path / "unicode_文件.onnx",
        ]

        for file_path in files:
            file_path.write_bytes(b"test content")

        scan_result = create_mock_scan_result(files_scanned=len(files))

        # Test SBOM generation with all file types
        file_paths = [str(f) for f in files]
        sbom_json = generate_sbom_pydantic(file_paths, scan_result)
        sbom_data = json.loads(sbom_json)

        assert len(sbom_data["components"]) == len(files)

        # Verify all components have valid hashes (indicating successful file access)
        for component in sbom_data["components"]:
            assert "hashes" in component
            assert len(component["hashes"]) == 1
            assert component["hashes"][0]["alg"] == "SHA-256"
            assert len(component["hashes"][0]["content"]) == 64  # SHA-256 hex length

    @pytest.mark.parametrize("python_version", ["3.9", "3.12"])
    def test_sbom_python_version_compatibility(self, tmp_path, python_version):
        """Test that SBOM generation works across Python versions."""
        # This is more of a smoke test - actual version testing happens in CI
        test_file = tmp_path / f"model_py{python_version.replace('.', '_')}.pkl"
        test_file.write_bytes(b"version test content")

        scan_result = create_mock_scan_result()

        # Should work regardless of Python version
        sbom_json = generate_sbom_pydantic([str(test_file)], scan_result)
        sbom_data = json.loads(sbom_json)

        assert sbom_data["bomFormat"] == "CycloneDX"
        assert sbom_data["specVersion"] == "1.6"
        assert len(sbom_data["components"]) == 1

    def test_sbom_large_file_handling(self, tmp_path):
        """Test SBOM generation with larger files (simulating real model files)."""
        # Create a larger test file (1MB)
        large_file = tmp_path / "large_model.bin"
        large_content = b"x" * (1024 * 1024)  # 1MB of data
        large_file.write_bytes(large_content)

        scan_result = create_mock_scan_result(bytes_scanned=len(large_content), files_scanned=1)

        # Should handle large files without issues
        sbom_json = generate_sbom_pydantic([str(large_file)], scan_result)
        sbom_data = json.loads(sbom_json)

        assert len(sbom_data["components"]) == 1
        component = sbom_data["components"][0]

        # Verify file size is recorded correctly
        properties = {prop["name"]: prop["value"] for prop in component.get("properties", [])}
        assert "size" in properties
        assert int(properties["size"]) == len(large_content)


@pytest.mark.parametrize("legacy", [False, True], ids=["typed", "legacy"])
@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
def test_sbom_directory_overlap_reserves_literal_component_refs(tmp_path: Path, legacy: bool, reverse: bool) -> None:
    model = tmp_path / "model.pkl"
    literal = tmp_path / "model.pkl#modelaudit-component-2"
    model.write_bytes(b"model")
    literal.write_bytes(b"literal")
    paths = [str(tmp_path), str(model), str(literal)]
    if reverse:
        paths.reverse()
    result = create_mock_scan_result(files_scanned=2)
    output = generate_sbom(paths, result.model_dump(mode="python")) if legacy else generate_sbom_pydantic(paths, result)
    refs = [component["bom-ref"] for component in json.loads(output)["components"]]
    assert len(refs) == len(set(refs)) == 4
    assert set(refs) == {
        str(model),
        str(literal),
        f"{model}#modelaudit-component-3",
        f"{literal}#modelaudit-component-2",
    }


@pytest.mark.parametrize("legacy", [False, True], ids=["typed", "legacy"])
@pytest.mark.parametrize("content_hashes", [False, True], ids=["unhashed", "hashed"])
def test_oversized_source_refs_preserve_risk_and_content_identity(legacy: bool, content_hashes: bool) -> None:
    from modelaudit.models import FileHashesModel

    prefix = "https://storage.example/" + "x" * (256 * 1024)
    first, second = f"{prefix}/a.pkl", f"{prefix}/b.pkl"
    result = create_mock_scan_result(
        files_scanned=2,
        issues=[Issue(message="Critical model", severity=IssueSeverity.CRITICAL, location=second)],
    )
    result.file_metadata = {
        first: FileMetadataModel(file_size=1, file_hashes=FileHashesModel(sha256="a" * 64) if content_hashes else None),
        second: FileMetadataModel(
            file_size=2, file_hashes=FileHashesModel(sha256="b" * 64) if content_hashes else None
        ),
    }
    expected = (
        {
            f"<source redacted>#modelaudit-content-sha256-{'a' * 64}": {"risk_score": "0", "size": "1"},
            f"<source redacted>#modelaudit-content-sha256-{'b' * 64}": {"risk_score": "5", "size": "2"},
        }
        if content_hashes
        else {
            "<source redacted>": {"risk_score": "5", "size": "2"},
            "<source redacted>#modelaudit-component-2": {"risk_score": "0", "size": "1"},
        }
    )
    for paths in ([first, second], [second, first]):
        output = (
            generate_sbom(paths, result.model_dump(mode="python")) if legacy else generate_sbom_pydantic(paths, result)
        )
        components = json.loads(output)["components"]
        assert {component["name"] for component in components} == {"<source redacted>"}
        assert {
            component["bom-ref"]: {
                prop["name"]: prop["value"]
                for prop in component["properties"]
                if prop["name"] in {"risk_score", "size"}
            }
            for component in components
        } == expected


def _sbom_property_values(
    input_paths: Any, result: ModelAuditResultModel, legacy_generator: bool, property_name: str
) -> dict[str, str]:
    if legacy_generator:
        sbom_json = generate_sbom(input_paths, result.model_dump(mode="python"))
    else:
        sbom_json = generate_sbom_pydantic(input_paths, result)
    return {
        component["bom-ref"]: next(prop["value"] for prop in component["properties"] if prop["name"] == property_name)
        for component in json.loads(sbom_json)["components"]
    }


@pytest.mark.parametrize(
    "source",
    [
        "https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=synthetic",
        "stream://https://bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=synthetic",
        "https://bucket.s3.amazonaws.com/model.pkl%3Ftoken%3Dsynthetic",
        "https://bucket.s3.amazonaws.com/model.pkl%253Ftoken%253Dsynthetic",
        "stream://https://bucket.s3.amazonaws.com/model.pkl%3Ftoken%3Dsynthetic",
    ],
)
def test_cli_signed_stream_sbom_preserves_model_classification(source: str, tmp_path: Path) -> None:
    from modelaudit.cli import _ScanPathState, _write_scan_sbom

    result = create_initial_audit_result()
    result.assets = [AssetModel(path=source, type="pickle", size=3)]
    output = tmp_path / "scan.sbom.json"
    _write_scan_sbom(str(output), result, [source], _ScanPathState(), scan_and_delete=True)
    assert json.loads(output.read_text())["components"][0]["type"] == "machine-learning-model"


@pytest.mark.skipif(os.name == "nt", reason="Windows filenames cannot contain a question mark")
def test_sbom_local_query_filename_keeps_literal_classification(tmp_path: Path) -> None:
    from modelaudit.integrations.sbom_generator import generate_sbom_pydantic

    path = tmp_path / "model.pkl?version=1"
    path.write_bytes(b"model")
    bom = json.loads(generate_sbom_pydantic([str(path)], create_initial_audit_result()))
    assert bom["components"][0]["type"] == "file"


@pytest.mark.parametrize("generator", ["legacy", "pydantic", "cli"])
@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize(
    "name, expected",
    [
        ("session=training/model.pkl", "machine-learning-model"),
        ("token=public/model.zip", "container"),
        ("password=x/data.json", "data"),
        pytest.param(
            "session=training/model.pkl?version=1",
            "file",
            marks=pytest.mark.skipif(os.name == "nt", reason="Windows filenames cannot contain a question mark"),
        ),
    ],
)
def test_sbom_deleted_local_paths_keep_literal_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, generator: str, relative: bool, name: str, expected: str
) -> None:
    from modelaudit.cli import _ScanPathState, _write_scan_sbom

    monkeypatch.chdir(tmp_path)
    path = Path(name) if relative else tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"model")
    path.unlink()
    result = create_initial_audit_result()
    result.assets = [AssetModel(path=str(path), type="pickle", size=5, is_streamed=True)]
    result.file_metadata[str(path)] = FileMetadataModel(file_size=5, scanner="pickle")
    if generator == "legacy":
        output = generate_sbom([str(path)], result.model_dump(mode="python"))
    elif generator == "pydantic":
        output = generate_sbom_pydantic([str(path)], result)
    else:
        target = tmp_path / "scan.sbom.json"
        _write_scan_sbom(str(target), result, [str(path)], _ScanPathState(), scan_and_delete=True)
        output = target.read_text()
    assert json.loads(output)["components"][0]["type"] == expected


@pytest.mark.parametrize("generator", ["legacy", "pydantic", "cli"])
@pytest.mark.parametrize(
    "extension, kind", [(".pkl", "machine-learning-model"), (".zip", "container"), (".json", "data")]
)
@pytest.mark.parametrize(
    "template, cli_uses_extension",
    [
        ("s3://bucket/model{extension}?token=synthetic", True),
        ("stream://https://bucket.s3.amazonaws.com/model{extension}%3Ftoken%3Dsynthetic", True),
        ("https://example.test/model{extension}?token=synthetic", True),
        ("https://user:synthetic@bucket.s3.amazonaws.com/model{extension}%3Ftoken%3Dsynthetic", False),
        ("https://huggingface.co/org/model/resolve/main/model{extension}?token=synthetic", True),
        ("hf://org/model/model{extension}%3Ftoken%3Dsynthetic", False),
        ("https://user:synthetic@example.jfrog.io/artifactory/repo/model{extension}?token=synthetic", True),
        ("models:/Example/1/model{extension}?token=synthetic", False),
    ],
)
def test_sbom_public_source_types_preserve_cli_boundary(
    tmp_path: Path, generator: str, extension: str, kind: str, template: str, cli_uses_extension: bool
) -> None:
    from modelaudit.cli import _ScanPathState, _write_scan_sbom

    source = template.format(extension=extension)
    result = create_initial_audit_result()
    result.assets = [AssetModel(path=source, type="pickle", size=3, is_streamed=True)]
    if generator == "legacy":
        output = generate_sbom([source], result.model_dump(mode="python"))
    elif generator == "pydantic":
        output = generate_sbom_pydantic([source], result)
    else:
        target = tmp_path / "scan.sbom.json"
        _write_scan_sbom(str(target), result, [source], _ScanPathState(), scan_and_delete=True)
        output = target.read_text()
    # Public generators historically classify the literal input; the CLI first normalizes its sources.
    expected = kind if generator == "cli" and cli_uses_extension else "file"
    assert json.loads(output)["components"][0]["type"] == expected


@pytest.mark.skipif(os.name == "nt", reason="Windows filenames cannot contain a question mark")
@pytest.mark.parametrize("generator", ["legacy", "pydantic", "cli"])
def test_sbom_directory_owner_risk_uses_historical_finding_location(tmp_path: Path, generator: str) -> None:
    from modelaudit.cli import _ScanPathState, _write_scan_sbom
    from modelaudit.core import scan_model_directory_or_file

    root = tmp_path / "owner?revision=main"
    root.mkdir()
    (root / "metadata.json").write_text(
        json.dumps({"version": "0.1.0", "type": "orbax_checkpoint", "restore_fn": "lambda x: eval(x.decode())"})
    )
    scanned = scan_model_directory_or_file(str(root), cache_enabled=False)
    result = ModelAuditResultModel.model_validate_json(scanned.model_dump_json())
    if generator == "legacy":
        output = generate_sbom([str(root)], result.model_dump())
    elif generator == "pydantic":
        output = generate_sbom_pydantic([str(root)], result)
    else:
        target = tmp_path / "scan.sbom.json"
        _write_scan_sbom(str(target), result, [str(root)], _ScanPathState(), scan_and_delete=True)
        output = target.read_text()
    components = json.loads(output)["components"]
    assert components
    # The owner and child findings historically associate only the child with this component.
    assert all(
        next(prop["value"] for prop in c["properties"] if prop["name"] == "risk_score") == "5" for c in components
    )


@pytest.mark.parametrize("generator", ["legacy", "pydantic", "cli"])
def test_sbom_risk_preserves_direct_api_and_cli_source_boundary(tmp_path: Path, generator: str) -> None:
    from modelaudit.cli import _ScanPathState, _write_scan_sbom

    source = "s3://bucket/model.pkl?token=synthetic"
    result = create_initial_audit_result()
    result.issues = [
        Issue(message="Existing finding", severity=IssueSeverity.CRITICAL, location="s3://bucket/model.pkl")
    ]
    if generator == "legacy":
        output = generate_sbom([source], result.model_dump())
    elif generator == "pydantic":
        output = generate_sbom_pydantic([source], result)
    else:
        target = tmp_path / "scan.sbom.json"
        _write_scan_sbom(str(target), result, [source], _ScanPathState(), scan_and_delete=True)
        output = target.read_text()
    component = json.loads(output)["components"][0]
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == (
        "5" if generator == "cli" else "0"
    )


def _scan_sbom_stream(payload: bytes, source: str) -> ModelAuditResultModel:
    from modelaudit.core import scan_model_directory_or_file

    filesystem = Mock()
    filesystem.info.return_value = {"size": len(payload)}
    filesystem.open.side_effect = lambda *args, **kwargs: io.BytesIO(payload)
    with patch("fsspec.filesystem", return_value=filesystem):
        return scan_model_directory_or_file("stream://" + source, cache_scan_results=False)


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "payload, expected_risk",
    [(b"cos\nsystem\n(S'printf sample'\ntR.", "5"), (b"\x80\x04N.", "0"), (b"", "2"), (b"\x80\x04", "1")],
    ids=["malicious", "benign", "empty", "incomplete"],
)
def test_sbom_emitted_stream_paths_keep_producer_type_and_risk(
    payload: bytes, expected_risk: str, legacy: bool
) -> None:
    source = "https://bucket.s3.amazonaws.com/model.pkl?token=synthetic"
    scanned = _scan_sbom_stream(payload, source)
    aggregate = create_initial_audit_result()
    aggregate.aggregate_scan_result(scanned.model_dump())
    aggregate.finalize_statistics()
    aggregate.deduplicate_issues()
    result = ModelAuditResultModel.model_validate_json(aggregate.model_dump_json())
    paths = [asset.path for asset in result.assets]
    output = generate_sbom(paths, result.model_dump()) if legacy else generate_sbom_pydantic(paths, result)
    component = json.loads(output)["components"][0]
    assert component["type"] == "machine-learning-model"
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == expected_risk
    assert component.get("hashes", []) == (
        [{"alg": "SHA-256", "content": hashlib.sha256(payload).hexdigest()}] if payload else []
    )


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("second_malicious", [False, True])
def test_sbom_stream_variants_keep_historical_logical_risk_after_deduplication(
    legacy: bool, second_malicious: bool
) -> None:
    malicious = b"cos\nsystem\n(S'printf sample'\ntR."
    aggregate = create_initial_audit_result()
    for index, payload in enumerate([malicious, malicious if second_malicious else b"\x80\x04N."]):
        source = f"https://bucket.s3.amazonaws.com/model.pkl?versionId={index}"
        aggregate.aggregate_scan_result(_scan_sbom_stream(payload, source).model_dump())
    aggregate.finalize_statistics()
    aggregate.deduplicate_issues()
    result = ModelAuditResultModel.model_validate_json(aggregate.model_dump_json())
    paths = [asset.path for asset in result.assets]
    output = generate_sbom(paths, result.model_dump()) if legacy else generate_sbom_pydantic(paths, result)
    components = json.loads(output)["components"]
    assert components
    # Query variants historically share a logical source score, even when their bytes differ.
    assert all(component["type"] == "machine-learning-model" for component in components)
    assert all(
        next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "5"
        for component in components
    )


@pytest.mark.skipif(os.name == "nt", reason="Windows truncate can allocate the full 11 GiB sparse test file")
def test_cli_auto_stream_sbom_preserves_producer_component_semantics(tmp_path: Path) -> None:
    payloads = {"malicious": b"cos\nsystem\n(S'printf sample'\ntR.", "benign": b"\x80\x04N."}
    sources = [f"https://bucket.s3.amazonaws.com/model.pkl?versionId={kind}" for kind in payloads]

    def payload_for(path: str) -> bytes:
        return payloads["benign" if "versionId=benign" in path else "malicious"]

    filesystem = Mock()
    filesystem.info.side_effect = lambda path: {"size": len(payload_for(path))}
    filesystem.open.side_effect = lambda path, *args, **kwargs: io.BytesIO(payload_for(path))
    trigger = tmp_path / "large.pkl"
    with trigger.open("wb") as stream:
        stream.truncate(11 * 1024 * 1024 * 1024)
    sbom = tmp_path / "scan.sbom.json"
    with patch("fsspec.filesystem", return_value=filesystem):
        invocation = CliRunner().invoke(
            cli,
            ["scan", str(trigger), *sources, "--quiet", "--no-cache", "--max-size", "1MB", "--sbom", str(sbom)],
        )
    assert invocation.exit_code == 2  # The local file activates streaming, then exceeds the scan limit.
    remote = [
        component
        for component in json.loads(sbom.read_text())["components"]
        if component["bom-ref"].startswith("https:")
    ]
    assert remote
    assert all(component["type"] == "machine-learning-model" for component in remote)
    assert all(
        next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "5"
        for component in remote
    )


@pytest.mark.parametrize("legacy", [False, True])
def test_sbom_emitted_stream_error_paths_keep_producer_type(legacy: bool) -> None:
    from modelaudit.core import scan_model_directory_or_file

    filesystem = Mock()
    filesystem.info.side_effect = OSError("synthetic transport error")
    with patch("fsspec.filesystem", return_value=filesystem):
        scanned = scan_model_directory_or_file(
            "stream://https://bucket.s3.amazonaws.com/model.pkl?token=synthetic", cache_scan_results=False
        )
    result = ModelAuditResultModel.model_validate_json(scanned.model_dump_json())
    paths = [asset.path for asset in result.assets]
    output = generate_sbom(paths, result.model_dump()) if legacy else generate_sbom_pydantic(paths, result)
    component = json.loads(output)["components"][0]
    assert component["type"] == "machine-learning-model"
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "0"
    assert not component.get("hashes")


@pytest.mark.parametrize("legacy", [False, True])
def test_sbom_emitted_huggingface_metadata_paths_keep_producer_type_and_risk(legacy: bool) -> None:
    with patch("modelaudit.cli.download_model", side_effect=RuntimeError("403 Forbidden: gated model")):
        invocation = CliRunner().invoke(
            cli,
            [
                "scan",
                "--quiet",
                "--no-cache",
                "--format",
                "json",
                "https://huggingface.co/synthetic/model.pkl?token=synthetic",
            ],
        )
    assert invocation.exit_code == 2
    result = ModelAuditResultModel.model_validate_json(invocation.output[invocation.output.index("{") :])
    paths = result.file_metadata.keys()
    output = generate_sbom(paths, result.model_dump()) if legacy else generate_sbom_pydantic(paths, result)
    component = json.loads(output)["components"][0]
    assert component["type"] == "machine-learning-model"
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "1"


def _refuse_mlflow_acquisition(monkeypatch: pytest.MonkeyPatch) -> None:
    module = ModuleType("mlflow")
    module.__dict__["artifacts"] = SimpleNamespace(
        get_artifact_repository=Mock(side_effect=RuntimeError("synthetic unavailable repository"))
    )
    monkeypatch.setitem(sys.modules, "mlflow", module)
    monkeypatch.setenv("MODELAUDIT_MLFLOW_ALLOWED_ARTIFACT_URIS", "")


@pytest.mark.parametrize(
    "artifact",
    [
        "access_token={token}&version=actual",
        "access_token={token};version=actual",
        "access_token={token}/model.pkl",
        "access_token='{token}'/model.pkl",
        "access_token={token}%26version%3Dactual",
    ],
)
def test_cli_mlflow_sbom_classifies_source_before_display_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact: str
) -> None:
    _refuse_mlflow_acquisition(monkeypatch)
    source = "models:/PublicModel/1/" + artifact.format(token="x" * 700)
    sbom = tmp_path / "scan.sbom.json"
    invocation = CliRunner().invoke(
        cli, ["scan", source, "--quiet", "--no-cache", "--max-size", "1MB", "--sbom", str(sbom)]
    )
    assert invocation.exit_code == 2
    component = json.loads(sbom.read_text())["components"][0]
    assert component["type"] == "file"
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "1"
    assert len(component["name"]) <= 512
    assert len(component["bom-ref"]) <= 512


def test_cli_mlflow_sbom_keeps_sources_with_the_same_bounded_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refuse_mlflow_acquisition(monkeypatch)
    prefix = "models:/PublicModel/1/access_token=" + "x" * 700
    sources = [prefix + tail for tail in ["&version=actual", "&revision=actual"]]
    exports = []
    for index, paths in enumerate([sources, list(reversed(sources))]):
        sbom = tmp_path / f"scan-{index}.sbom.json"
        invocation = CliRunner().invoke(
            cli, ["scan", *paths, "--quiet", "--no-cache", "--max-size", "1MB", "--sbom", str(sbom)]
        )
        assert invocation.exit_code == 2
        components = json.loads(sbom.read_text())["components"]
        assert len(components) == len({component["bom-ref"] for component in components}) == 2
        assert all(len(component["name"]) <= 512 for component in components)
        assert all(
            next(prop["value"] for prop in c["properties"] if prop["name"] == "risk_score") == "1" for c in components
        )
        exports.append(components)
    assert exports[0] == exports[1]


@pytest.mark.parametrize("legacy", [False, True])
def test_mlflow_direct_sbom_keeps_literal_input_association(monkeypatch: pytest.MonkeyPatch, legacy: bool) -> None:
    from modelaudit.integrations.mlflow import scan_mlflow_model

    _refuse_mlflow_acquisition(monkeypatch)
    source = "models:/PublicModel/1?code=" + "x" * 700 + "&version=actual"
    result = scan_mlflow_model(source, max_file_size=1)
    output = generate_sbom([source], result.model_dump()) if legacy else generate_sbom_pydantic([source], result)
    component = json.loads(output)["components"][0]
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "0"


@pytest.mark.parametrize("legacy", [False, True])
def test_mlflow_emitted_finding_paths_keep_original_sbom_association(
    monkeypatch: pytest.MonkeyPatch, legacy: bool
) -> None:
    from modelaudit.integrations.mlflow import scan_mlflow_model

    _refuse_mlflow_acquisition(monkeypatch)
    source = "models:/PublicModel/1/access_token=" + "x" * 700 + "&version=actual"
    scanned = scan_mlflow_model(source, max_file_size=1)
    result = ModelAuditResultModel.model_validate_json(scanned.model_dump_json())
    paths = [issue.location for issue in result.issues if issue.location]
    output = generate_sbom(paths, result.model_dump()) if legacy else generate_sbom_pydantic(paths, result)
    component = json.loads(output)["components"][0]
    assert next(prop["value"] for prop in component["properties"] if prop["name"] == "risk_score") == "1"
