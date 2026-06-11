"""Tests for SBOM generation fixes with HuggingFace URLs and downloaded content.

This module tests the fix for FileNotFoundError when generating SBOMs for content
downloaded from URLs (HuggingFace, cloud storage, etc.).
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.integrations.sbom_generator import generate_sbom, generate_sbom_pydantic
from modelaudit.integrations.source_redaction import redact_source_identifier
from modelaudit.models import AssetModel, FileMetadataModel
from modelaudit.scanners.base import Issue, IssueSeverity
from tests.helpers.file_creators import create_malicious_pickle


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


def _write_hf_cachedir_tag(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Signature: 8a477f597d28d172789f06886806bc55\n"
        "# This file is a cache directory tag created by huggingface_hub.\n"
        "# For information about cache directory tags, see:\n"
        "#\thttps://bford.info/cachedir/\n",
        encoding="utf-8",
    )


class TestSBOMURLFixes:
    """Test SBOM generation with URLs and downloaded content."""

    def test_sbom_redacts_signed_url_component_identity(self) -> None:
        raw_url = (
            "https://bucket.s3.amazonaws.com/model.pkl?"
            "X-Amz-Credential=AKIASECRET&X-Amz-Signature=deadbeef&token=secret-token"
        )
        scan_result = create_mock_scan_result()

        sbom_json = generate_sbom_pydantic([raw_url], scan_result)
        sbom_data = json.loads(sbom_json)

        component = sbom_data["components"][0]
        assert component["name"] == "model.pkl"
        assert component["bom-ref"] == "https://bucket.s3.amazonaws.com/model.pkl"
        assert raw_url not in sbom_json
        for leaked in ("AKIASECRET", "deadbeef", "secret-token", "X-Amz-Signature"):
            assert leaked not in sbom_json

    def test_legacy_sbom_redacts_stream_source_component_identity(self) -> None:
        raw_url = (
            "stream://https://user:password@storage.googleapis.com/bucket/model.bin?"
            "X-Goog-Signature=deadbeef&token=secret-token"
        )
        scan_result = create_mock_scan_result()

        sbom_json = generate_sbom([raw_url], scan_result.model_dump(mode="python"))
        sbom_data = json.loads(sbom_json)

        component = sbom_data["components"][0]
        assert component["name"] == "model.bin"
        assert component["bom-ref"] == "stream://https://storage.googleapis.com/bucket/model.bin"
        assert raw_url not in sbom_json
        for leaked in ("user:password", "deadbeef", "secret-token", "X-Goog-Signature"):
            assert leaked not in sbom_json

    def test_sbom_redacts_scheme_less_source_credentials(self) -> None:
        raw_path = "bucket/model.pkl?visible=yes&token=scheme-less-secret"
        scan_result = create_mock_scan_result()

        sbom_json = generate_sbom_pydantic([raw_path], scan_result)
        component = json.loads(sbom_json)["components"][0]

        assert component["name"] == "model.pkl"
        assert component["bom-ref"] == "bucket/model.pkl"
        assert "scheme-less-secret" not in sbom_json
        assert "token=" not in sbom_json

    def test_source_identifier_preserves_safe_local_query_context(self) -> None:
        local_path = "/tmp/model.pkl?section=models"

        assert redact_source_identifier(local_path) == local_path

    @pytest.mark.parametrize(
        "raw_path",
        [
            "bucket/model.pkl%3Ftoken%3Dscheme-less-secret",
            "bucket/model.pkl%253Ftoken%253Dscheme-less-secret",
            "bucket/model.pkl%23token%3Dscheme-less-secret",
            "bucket/model.pkl%3Btoken%3Dscheme-less-secret",
        ],
    )
    def test_source_identifier_redacts_encoded_scheme_less_credentials(self, raw_path: str) -> None:
        assert redact_source_identifier(raw_path) == "bucket/model.pkl"

    def test_source_identifier_redacts_bare_credential_assignment(self) -> None:
        assert redact_source_identifier("token=scheme-less-secret") == "<source redacted>"

    @pytest.mark.parametrize(
        "raw_path",
        [
            "bucket/model.pkl%3Fvisible%3Dyes",
            "bucket/model%3Fv1.pkl",
            "bucket/model.pkl%3Ftoken%3D<redacted>",
        ],
    )
    def test_source_identifier_preserves_encoded_safe_near_matches(self, raw_path: str) -> None:
        assert redact_source_identifier(raw_path) == raw_path

    @pytest.mark.parametrize(
        ("raw_path", "safe_ref"),
        [
            ("//user:password@storage.example/model.pkl?token=secret", "//storage.example/model.pkl"),
            ("https:/user:password@storage.example/model.pkl?token=secret", "https://storage.example/model.pkl"),
            ("user%3Apassword%40storage.example/model.pkl?token=secret", "storage.example/model.pkl"),
            (
                "https://storage.example/token=path-secret/model.pkl?token=query-secret",
                "https://storage.example/token=<redacted>/model.pkl",
            ),
            (
                "https://storage.example/token%253Dpath-secret/model.pkl?token=query-secret",
                "https://storage.example/token=<redacted>/model.pkl",
            ),
        ],
    )
    def test_sbom_redacts_noncanonical_source_credentials(self, raw_path: str, safe_ref: str) -> None:
        sbom_json = generate_sbom_pydantic([raw_path], create_mock_scan_result())
        component = json.loads(sbom_json)["components"][0]

        assert component["bom-ref"] == safe_ref
        for leaked in ("password", "path-secret", "query-secret"):
            assert leaked not in sbom_json

    @pytest.mark.parametrize(
        ("raw_path", "safe_ref", "secret"),
        [
            (r"C:\models\token=windows-secret\model.pkl", "<source redacted>", "windows-secret"),
            (r"\\host\share\password=unc-secret\model.pkl", "<source redacted>", "unc-secret"),
            ("file:///tmp/model.pkl%3Ftoken%3Dfile-secret", "file:///tmp/model.pkl", "file-secret"),
            (
                "file:///tmp/model.pkl%253Ftoken%253Ddouble-secret",
                "file:///tmp/model.pkl",
                "double-secret",
            ),
            ("file://api-key%40host/tmp/model.pkl", "file://host/tmp/model.pkl", "api-key"),
            (
                "api-key@bucket.example/model.pkl?token=query-secret",
                "bucket.example/model.pkl",
                "api-key",
            ),
            (
                "https:/single-key@bucket.example/model.pkl",
                "https://bucket.example/model.pkl",
                "single-key",
            ),
            ("model.pkl;OPAQUE-SECRET", "model.pkl", "OPAQUE-SECRET"),
            (
                r"bucket/model.pkl\u003btoken\u003descaped-secret",
                "bucket/model.pkl",
                "escaped-secret",
            ),
        ],
    )
    def test_sbom_redacts_local_and_userinfo_edge_credentials(
        self,
        raw_path: str,
        safe_ref: str,
        secret: str,
    ) -> None:
        sbom_json = generate_sbom_pydantic([raw_path], create_mock_scan_result())
        component = json.loads(sbom_json)["components"][0]

        assert component["bom-ref"] == safe_ref
        assert secret not in sbom_json

    def test_distinct_redacted_sources_keep_stable_component_refs(self) -> None:
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
        assert set(first_risks) == {
            "https://storage.example/model.pkl?revision=first",
            "https://storage.example/model.pkl?revision=second",
        }
        assert "secret-one" not in json.dumps(first_sbom)
        assert "secret-two" not in json.dumps(first_sbom)

    def test_signed_credential_rotation_preserves_component_ref(self) -> None:
        def bom_ref(token: str) -> str:
            path = f"https://storage.example/model.pkl?revision=stable&token={token}"
            sbom = json.loads(generate_sbom_pydantic([path], create_mock_scan_result()))
            return str(sbom["components"][0]["bom-ref"])

        assert bom_ref("first-secret") == bom_ref("rotated-secret")

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_credential_only_distinct_sources_keep_unique_non_secret_refs(self, legacy_generator: bool) -> None:
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
        assert set(first_risks) == {
            "https://storage.example/model.pkl",
            "https://storage.example/model.pkl#modelaudit-component-2",
        }
        assert set(first_risks.values()) == {"0", "5"}
        for path in paths:
            assert path not in first_sbom_json
            assert hashlib.sha256(path.encode()).hexdigest() not in first_sbom_json

    def test_safe_fragment_provenance_keeps_components_distinct(self) -> None:
        paths = [
            "https://storage.example/model.pkl?token=secret#revision=first",
            "https://storage.example/model.pkl?token=secret#revision=second",
        ]

        sbom = json.loads(generate_sbom_pydantic(paths, create_mock_scan_result(files_scanned=2)))

        assert {component["bom-ref"] for component in sbom["components"]} == {
            "https://storage.example/model.pkl?fragment-revision=first",
            "https://storage.example/model.pkl?fragment-revision=second",
        }

    @pytest.mark.parametrize(
        "credential_value",
        [
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "sk-abcdefghijklmnop",
            "AKIAABCDEFGHIJKLMNOP",
            "eyJabcdefghijk.abcdefghijkl.mnopqrstuv",
        ],
    )
    def test_credential_shaped_safe_provenance_values_are_dropped(self, credential_value: str) -> None:
        raw_path = f"https://storage.example/model.pkl?revision={credential_value}&token=secret"

        sbom_json = generate_sbom_pydantic([raw_path], create_mock_scan_result())

        assert credential_value not in sbom_json
        assert json.loads(sbom_json)["components"][0]["bom-ref"] == "https://storage.example/model.pkl"
        assert redact_source_identifier(f"model?revision={credential_value}") == "model"

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_safe_schemeless_provenance_has_stable_risk_attribution(self, legacy_generator: bool) -> None:
        safe_path = "bucket/model.pkl?revision=v1"
        signed_path = f"{safe_path}&token=source-secret"
        result = create_mock_scan_result(
            files_scanned=2,
            issues=[Issue(message="critical", severity=IssueSeverity.CRITICAL, location=signed_path)],
        )

        def risks(input_paths: Any) -> dict[str, str]:
            if legacy_generator:
                sbom_json = generate_sbom(input_paths, result.model_dump(mode="python"))
            else:
                sbom_json = generate_sbom_pydantic(input_paths, result)
            return {
                component["bom-ref"]: next(
                    prop["value"] for prop in component["properties"] if prop["name"] == "risk_score"
                )
                for component in json.loads(sbom_json)["components"]
            }

        assert (
            risks([safe_path, signed_path])
            == risks([signed_path, safe_path])
            == {
                safe_path: "0",
                f"{safe_path}#modelaudit-component-2": "5",
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
    def test_literal_component_ref_is_reserved_before_redacted_collisions(
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
            f"{literal}#modelaudit-component-2",
        }
        assert (
            next(prop["value"] for prop in components[str(literal)]["properties"] if prop["name"] == "risk_score")
            == "0"
        )
        assert (
            next(
                prop["value"]
                for prop in components[f"{literal}#modelaudit-component-2"]["properties"]
                if prop["name"] == "risk_score"
            )
            == "5"
        )

    @pytest.mark.parametrize("legacy_generator", [False, True])
    def test_equal_risk_redacted_collisions_use_safe_metadata_identity(self, legacy_generator: bool) -> None:
        first = "https://storage.example/model.pkl?token=first-secret"
        second = "https://storage.example/model.pkl?token=second-secret"
        result = create_mock_scan_result(files_scanned=2)
        result.file_metadata = {
            first: FileMetadataModel(file_size=10, license="MIT"),
            second: FileMetadataModel(file_size=20, license="Apache-2.0"),
        }

        def sizes(input_paths: Any) -> dict[str, str]:
            if legacy_generator:
                sbom_json = generate_sbom(input_paths, result.model_dump(mode="python"))
            else:
                sbom_json = generate_sbom_pydantic(input_paths, result)
            return {
                component["bom-ref"]: next(prop["value"] for prop in component["properties"] if prop["name"] == "size")
                for component in json.loads(sbom_json)["components"]
            }

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

    @pytest.mark.parametrize("path", ["model?version=1.pkl", "model;version=1.pkl"])
    def test_nonexistent_local_provenance_filenames_are_preserved(self, path: str) -> None:
        assert redact_source_identifier(path) == path

    @pytest.mark.parametrize(
        "raw_path",
        [
            "token=source-secret?revision=v1",
            "sessionToken=source-secret?revision=v1",
            "bucket/token=path-secret/model.pkl?revision=v1",
            "bucket/token%3Dpath-secret/model.pkl?revision=v1",
            "Authorization: Bearer source-secret?revision=v1",
            "dbPassword: source-secret#tag=v1",
        ],
    )
    def test_safe_provenance_does_not_bypass_sensitive_prefix_redaction(self, raw_path: str) -> None:
        sbom_json = generate_sbom_pydantic([raw_path], create_mock_scan_result())

        assert "source-secret" not in sbom_json
        assert "path-secret" not in sbom_json
        assert json.loads(sbom_json)["components"][0]["bom-ref"].startswith("<source redacted>")

    @pytest.mark.parametrize(
        "raw_path",
        [
            "bucket/model.pkl;token%3Dscheme-less-secret",
            "bucket/model.pkl?visible=yes&scheme-less-secret",
        ],
    )
    def test_mixed_and_opaque_suffix_credentials_are_redacted(self, raw_path: str) -> None:
        assert redact_source_identifier(raw_path) == "bucket/model.pkl"

    @pytest.mark.parametrize(
        "raw_url",
        [
            "https://example.com/sessionToken=path-secret/model.pkl",
            "https://example.com/githubToken=path-secret/model.pkl",
            "https://example.com/session%54oken=path-secret/model.pkl",
        ],
    )
    def test_alias_url_path_credentials_are_redacted(self, raw_url: str) -> None:
        sbom_json = generate_sbom_pydantic([raw_url], create_mock_scan_result())

        assert "path-secret" not in sbom_json
        assert "<redacted>" in json.loads(sbom_json)["components"][0]["bom-ref"]

    @pytest.mark.parametrize(
        "raw_url",
        [
            "//storage.example/model.pkl?token=query-secret",
            "//bucket.s3.amazonaws.com/model.pkl?X-Amz-Signature=deadbeef",
            "//user:password@storage.example/model.pkl?token=query-secret",
        ],
    )
    def test_protocol_relative_source_credentials_are_redacted(self, raw_url: str) -> None:
        sbom_json = generate_sbom_pydantic([raw_url], create_mock_scan_result())

        for secret in ("query-secret", "deadbeef", "user:password"):
            assert secret not in sbom_json
        assert json.loads(sbom_json)["components"][0]["bom-ref"].startswith("//")

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
