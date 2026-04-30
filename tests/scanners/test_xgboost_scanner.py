"""
Tests for XGBoost model scanner

Tests cover various XGBoost model formats and security vulnerabilities:
- JSON models with valid/invalid schemas
- UBJ (Universal Binary JSON) models
- Binary .bst models with integrity checks
- Malicious content detection in all formats
- Integration with pickle scanner for .pkl/.joblib files
"""

import copy
import json
import pickle
import subprocess as real_subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast
from unittest.mock import ANY, Mock, patch

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.xgboost_scanner import XGBOOST_JSON_ROUTING_CHUNK_BYTES, XGBoostScanner


class FakeBooster:
    """A simple class that can be pickled for testing."""

    def __init__(self):
        self.__class__.__name__ = "Booster"


@pytest.fixture
def temp_dir() -> Iterator[Path]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def xgboost_scanner() -> XGBoostScanner:
    """Create an XGBoost scanner instance."""
    return XGBoostScanner()


@pytest.fixture
def valid_xgboost_json() -> dict[str, Any]:
    """Valid XGBoost JSON model structure."""
    return {
        "version": [1, 7, 4],
        "learner": {
            "feature_names": ["feature_0", "feature_1", "feature_2"],
            "feature_types": ["float", "float", "float"],
            "learner_model_param": {
                "base_score": "0.5",
                "boost_from_average": "1",
                "num_class": "0",
                "num_features": "3",
                "num_parallel_tree": "1",
                "num_target": "1",
                "objective": "reg:squarederror",
                "predictor": "auto",
                "random_state": "0",
                "seed": "0",
                "seed_per_iteration": "0",
                "validate_parameters": "1",
            },
            "gradient_booster": {
                "name": "gbtree",
                "model": {
                    "gbtree_model_param": {"num_trees": "2", "num_parallel_tree": "1"},
                    "trees": [
                        {
                            "tree_param": {
                                "num_roots": "1",
                                "num_nodes": "3",
                                "num_deleted": "0",
                                "max_depth": "1",
                                "num_feature": "3",
                                "size_leaf_vector": "1",
                            },
                            "loss_changes": [0.5, 0.0, 0.0],
                            "sum_hessian": [2.0, 1.0, 1.0],
                            "base_weights": [0.25, -0.5, 0.5],
                            "left_children": [1, -1, -1],
                            "right_children": [2, -1, -1],
                            "parents": [2147483647, 0, 0],
                            "split_indices": [0, 0, 0],
                            "split_conditions": [0.5, 0.0, 0.0],
                            "split_type": [0, 0, 0],
                            "default_left": [0, 0, 0],
                            "categories": [],
                            "categories_nodes": [],
                            "categories_segments": [],
                            "categories_sizes": [],
                        },
                        {
                            "tree_param": {
                                "num_roots": "1",
                                "num_nodes": "1",
                                "num_deleted": "0",
                                "max_depth": "0",
                                "num_feature": "3",
                                "size_leaf_vector": "1",
                            },
                            "loss_changes": [0.0],
                            "sum_hessian": [2.0],
                            "base_weights": [0.125],
                            "left_children": [-1],
                            "right_children": [-1],
                            "parents": [2147483647],
                            "split_indices": [0],
                            "split_conditions": [0.0],
                            "split_type": [0],
                            "default_left": [0],
                            "categories": [],
                            "categories_nodes": [],
                            "categories_segments": [],
                            "categories_sizes": [],
                        },
                    ],
                    "tree_info": [0, 0],
                },
            },
        },
    }


def _scan_twice_with_cache(path: Path, cache_dir: Path) -> tuple[ModelAuditResultModel, ModelAuditResultModel]:
    first = scan_model_directory_or_file(
        str(path),
        cache_enabled=True,
        cache_dir=str(cache_dir),
        min_cache_file_size=0,
    )
    second = scan_model_directory_or_file(
        str(path),
        cache_enabled=True,
        cache_dir=str(cache_dir),
        min_cache_file_size=0,
    )
    return first, second


def _assert_inconclusive_metadata(result: ModelAuditResultModel, path: Path, reason: str) -> None:
    metadata = result.file_metadata[str(path)]
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert metadata.get("analysis_incomplete") is True
    assert reason in metadata.get("scan_outcome_reasons", [])


def _xgboost_ubjson_probe() -> bytes:
    return b"{L" + (b"\0" * 8) + b"learner" + b"learner_model_param" + b"version"


class TestXGBoostScannerBasic:
    """Test basic XGBoost scanner functionality."""

    def test_can_handle_supported_extensions(self, temp_dir):
        """Test that scanner handles supported XGBoost file extensions."""
        # .bst, .model, .ubj are accepted based on extension
        for ext in [".bst", ".model", ".ubj"]:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")
            assert XGBoostScanner.can_handle(str(test_file))

        # .json requires valid XGBoost structure
        json_file = temp_dir / "test.json"
        json_file.write_text(json.dumps({"version": [1, 5, 2], "learner": {"gradient_booster": {}}}))
        assert XGBoostScanner.can_handle(str(json_file))

    def test_cannot_handle_unsupported_extensions(self, temp_dir):
        """Test that scanner rejects unsupported file extensions."""
        unsupported_extensions = [".txt", ".pkl", ".h5", ".onnx"]

        for ext in unsupported_extensions:
            test_file = temp_dir / f"test{ext}"
            test_file.write_text("dummy content")

            assert not XGBoostScanner.can_handle(str(test_file))

    def test_can_handle_extensionless_ubjson_with_xgboost_markers(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(_xgboost_ubjson_probe())

        assert XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_like_header_without_xgboost_markers(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(b"{L" + (b"\0" * 64))

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_with_only_learner_marker(self, temp_dir: Path) -> None:
        model_file = temp_dir / "model"
        model_file.write_bytes(b"{L" + (b"\0" * 8) + b"learner")

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_rejects_extensionless_ubjson_when_strong_marker_past_probe_window(self, temp_dir: Path) -> None:
        """Extensionless files require a strong marker *within* the probe window.

        `.bst`/`.model` files trust the extension and need only `learner`, but an
        extensionless file with `learner` early and every strong marker past the
        probe window must be rejected so unrelated archives that happen to embed
        `{L...learner` near the top are not misrouted to the UBJ scanner.
        """
        probe_bytes = XGBoostScanner._UBJSON_PROBE_READ_BYTES
        # `learner` sits near the start; all strong markers live past the probe cap.
        prefix = b"{L" + (b"\0" * 8) + b"learner"
        padding_len = probe_bytes - len(prefix) + 32
        payload = prefix + (b"\0" * padding_len) + b"version" + b"gbtree"
        assert all(marker not in payload[:probe_bytes] for marker in XGBoostScanner._UBJSON_STRONG_MARKERS)
        assert any(marker in payload for marker in XGBoostScanner._UBJSON_STRONG_MARKERS)

        model_file = temp_dir / "model"
        model_file.write_bytes(payload)

        assert not XGBoostScanner.can_handle(str(model_file))

    def test_scanner_name_and_description(self):
        """Test scanner metadata."""
        assert XGBoostScanner.name == "xgboost"
        assert "XGBoost" in XGBoostScanner.description
        assert "vulnerabilities" in XGBoostScanner.description

    def test_nonexistent_file_handling(self, xgboost_scanner):
        """Test handling of non-existent files."""
        result = xgboost_scanner.scan("/nonexistent/path/model.bst")
        assert not result.success
        assert any("does not exist" in str(issue.message) for issue in result.issues)


class TestXGBoostJSONScanning:
    """Test XGBoost JSON model scanning."""

    def test_valid_json_model_passes(
        self,
        temp_dir: Path,
        xgboost_scanner: XGBoostScanner,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Test that valid XGBoost JSON model passes all checks."""
        json_file = temp_dir / "valid_model.json"
        json_file.write_text(json.dumps(valid_xgboost_json, indent=2))

        result = xgboost_scanner.scan(str(json_file))

        assert result.success
        # Should have passing checks for JSON parsing and schema validation
        passing_checks = [c for c in result.checks if c.status.value == "passed"]
        assert len(passing_checks) > 0

        # Should not have critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    def test_tree_depth_validation_uses_child_structure(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Tree depth validation should use child arrays, not size_leaf_vector metadata."""
        tree = valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"][0]
        tree["tree_param"]["size_leaf_vector"] = "1"
        tree["left_children"] = [1, 2, 3, -1]
        tree["right_children"] = [-1, -1, -1, -1]
        tree["parents"] = [2147483647, 0, 1, 2]

        json_file = temp_dir / "deep_tree.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner({"max_tree_depth": 2}).scan(str(json_file))

        checks = {check.name: check for check in result.checks}
        assert checks["Tree Depth Validation"].status == CheckStatus.FAILED
        assert checks["Tree Depth Validation"].details["depth"] == 3

    def test_tree_depth_validation_checks_trees_after_first_ten(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Late trees should not bypass structure validation."""
        trees = valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"]
        shallow_tree = copy.deepcopy(trees[1])
        deep_tree = copy.deepcopy(trees[0])
        deep_tree["left_children"] = [1, 2, 3, -1]
        deep_tree["right_children"] = [-1, -1, -1, -1]
        deep_tree["parents"] = [2147483647, 0, 1, 2]
        valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"] = [
            *[copy.deepcopy(shallow_tree) for _ in range(10)],
            deep_tree,
        ]

        json_file = temp_dir / "late_deep_tree.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner({"max_tree_depth": 2}).scan(str(json_file))

        checks = [check for check in result.checks if check.name == "Tree Depth Validation"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].details["tree_index"] == 10
        assert checks[0].details["depth"] == 3

    def test_tree_depth_validation_aggregates_many_late_failures(
        self,
        temp_dir: Path,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """Repeated deep trees should not flood the scan result."""
        trees = valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"]
        deep_tree = copy.deepcopy(trees[0])
        deep_tree["left_children"] = [1, 2, 3, -1]
        deep_tree["right_children"] = [-1, -1, -1, -1]
        deep_tree["parents"] = [2147483647, 0, 1, 2]
        valid_xgboost_json["learner"]["gradient_booster"]["model"]["trees"] = [
            copy.deepcopy(deep_tree) for _ in range(25)
        ]

        json_file = temp_dir / "many_deep_trees.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner({"max_tree_depth": 2}).scan(str(json_file))

        checks = [check for check in result.checks if check.name == "Tree Depth Validation"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.FAILED
        assert checks[0].details["tree_count"] == 25
        assert checks[0].details["tree_index"] == 0
        assert checks[0].details["max_observed_depth"] == 3
        assert checks[0].details["examples"] == [{"tree_index": tree_index, "depth": 3} for tree_index in range(10)]

    def test_invalid_json_fails(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test that invalid JSON content is detected."""
        json_file = temp_dir / "invalid.json"
        json_file.write_text('{"invalid": json content}')  # Invalid JSON

        result = xgboost_scanner.scan(str(json_file))

        # Should detect JSON parsing error
        assert any("Invalid JSON format" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_json_parse_failed" in result.metadata["scan_outcome_reasons"]

    def test_malformed_xgboost_json_candidate_is_routed(self, temp_dir: Path) -> None:
        """Malformed XGBoost-shaped JSON should reach the fail-closed parser path."""
        json_file = temp_dir / "booster.json"
        json_file.write_text('{"version":[1,7,4],"learner":{"gradient_booster":')

        assert XGBoostScanner.can_handle(str(json_file))

    @pytest.mark.parametrize(
        ("filename", "payload"),
        [
            ("model.json", '{"version":"1","learner":'),
            ("settings.json", '{"version":"1","learner":{"objective":'),
        ],
    )
    def test_generic_malformed_json_candidate_is_not_routed(self, temp_dir: Path, filename: str, payload: str) -> None:
        """Generic malformed JSON should not be misclassified from weak key names alone."""
        json_file = temp_dir / filename
        json_file.write_text(payload)

        assert not XGBoostScanner.can_handle(str(json_file))

    def test_missing_required_keys_detected(self, temp_dir: Path) -> None:
        """Test that scanner rejects JSON files missing required XGBoost keys in can_handle()."""
        incomplete_json = {"version": [1, 0, 0]}  # Missing learner

        json_file = temp_dir / "incomplete.json"
        json_file.write_text(json.dumps(incomplete_json))

        # Should be rejected by can_handle() - scanner won't even try to scan it
        assert not XGBoostScanner.can_handle(str(json_file))

    def test_can_handle_json_uses_bounded_structural_sniff(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Routing should not fully parse arbitrary JSON before scanner limits apply."""
        json_file = tmp_path / "large_non_xgboost.json"
        json_file.write_text('{"padding": "' + ("A" * 200_000) + '"}', encoding="utf-8")

        def fail_json_load(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("can_handle() must not call json.load()")

        monkeypatch.setattr("modelaudit.scanners.xgboost_scanner.json.load", fail_json_load)

        read_sizes: list[int] = []
        real_open = open

        class TrackingBinaryReader:
            def __init__(self, raw: Any) -> None:
                self._raw = raw

            def __enter__(self) -> "TrackingBinaryReader":
                self._raw.__enter__()
                return self

            def __exit__(self, *args: Any) -> object:
                return self._raw.__exit__(*args)

            def read(self, size: int = -1) -> bytes:
                read_sizes.append(size)
                if size < 0:
                    raise AssertionError("can_handle() must not perform unbounded full-file read()")
                data = self._raw.read(size)
                assert isinstance(data, bytes)
                return data

            def seek(self, offset: int, whence: int = 0) -> int:
                return cast(int, self._raw.seek(offset, whence))

            def __getattr__(self, name: str) -> Any:
                return getattr(self._raw, name)

        def instrumented_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            stream = real_open(file, mode, *args, **kwargs)
            if isinstance(file, str) and Path(file) == json_file and "b" in mode:
                return TrackingBinaryReader(stream)
            return stream

        with patch("builtins.open", side_effect=instrumented_open):
            assert XGBoostScanner.can_handle(str(json_file)) is False

        assert XGBOOST_JSON_ROUTING_CHUNK_BYTES in read_sizes
        assert all(size <= XGBoostScanner._JSON_PROBE_READ_BYTES for size in read_sizes)

    def test_can_handle_json_detects_malicious_xgboost_after_large_prefix(self, tmp_path: Path) -> None:
        """Routing should find malicious XGBoost JSON markers beyond the first read chunk."""
        delayed_malicious_model = {
            "padding": "A" * (XGBOOST_JSON_ROUTING_CHUNK_BYTES + 1024),
            "version": [1, 7, 4],
            "learner": {
                "malicious_code": "os.system('touch pwned')",
            },
        }
        json_file = tmp_path / "delayed_malicious_xgboost.json"
        json_file.write_text(json.dumps(delayed_malicious_model), encoding="utf-8")

        assert XGBoostScanner.can_handle(str(json_file)) is True

        result = XGBoostScanner().scan(str(json_file))

        assert any("Suspicious pattern detected" in str(issue.message) for issue in result.issues)

    def test_can_handle_json_rejects_manifest_near_match(self, tmp_path: Path) -> None:
        """Manifest-like JSON should not be claimed by XGBoost on shallow marker names alone."""
        manifest_like_config = {
            "version": [1],
            "learner": {},
            "download_url": "s3://bucket/model.bin",
        }
        json_file = tmp_path / "config.json"
        json_file.write_text(json.dumps(manifest_like_config), encoding="utf-8")

        assert XGBoostScanner.can_handle(str(json_file)) is False

    def test_scan_default_read_limit_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        valid_xgboost_json: dict[str, Any],
    ) -> None:
        """JSON scans should fail closed before full parsing when the read cap is exceeded."""
        monkeypatch.setattr(XGBoostScanner, "default_max_file_read_size", 32)
        json_file = tmp_path / "oversized_model.json"
        json_file.write_text(json.dumps(valid_xgboost_json), encoding="utf-8")

        result = XGBoostScanner().scan(str(json_file))

        checks = {check.name: check for check in result.checks}
        assert checks["File Size Limit"].status == CheckStatus.FAILED
        assert "File too large" in checks["File Size Limit"].message
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["analysis_incomplete"] is True
        assert "max_file_read_size_exceeded" in result.metadata["scan_outcome_reasons"]

    def test_malicious_json_content_detected(self, temp_dir, xgboost_scanner):
        """Test detection of malicious patterns in JSON."""
        malicious_json = {
            "version": [1, 0, 0],
            "learner": {
                "malicious_code": "os.system('rm -rf /')",
                "eval_call": "eval('__import__(\\'os\\').system(\\'ls\\')')",
                "subprocess_usage": "subprocess.run(['cat', '/etc/passwd'])",
            },
        }

        json_file = temp_dir / "malicious.json"
        json_file.write_text(json.dumps(malicious_json))

        result = xgboost_scanner.scan(str(json_file))

        # Should detect multiple suspicious patterns
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Suspicious pattern detected" in str(issue.message) for issue in critical_issues)


@pytest.mark.skipif(not hasattr(pytest, "importorskip"), reason="pytest.importorskip not available")
class TestXGBoostUBJScanning:
    """Test XGBoost UBJ model scanning."""

    def test_ubj_without_ubjson_library(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test UBJ scanning without ubjson library (INFO level)."""
        ubj_file = temp_dir / "model.ubj"
        ubj_file.write_bytes(b"\x7b\x55")  # UBJ object start

        with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
            result = xgboost_scanner.scan(str(ubj_file))

        # Message changed to "Cannot scan UBJ file"
        assert any("cannot scan ubj file" in str(issue.message).lower() for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]

    def test_invalid_ubj_detected(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test detection of invalid UBJ content."""
        pytest.importorskip("ubjson", reason="ubjson not installed")
        ubj_file = temp_dir / "invalid.ubj"
        ubj_file.write_bytes(b"\xff\xff\xff\xff")  # Invalid UBJ data

        # Mock ubjson to be available but raise exception on decode
        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch("ubjson.loadb") as mock_loadb,
        ):
            mock_loadb.side_effect = Exception("Invalid UBJ format")

            result = xgboost_scanner.scan(str(ubj_file))

        assert any("Error analyzing XGBoost UBJ model" in str(issue.message) for issue in result.issues)


class TestXGBoostBinaryScanning:
    """Test XGBoost binary model scanning."""

    def test_empty_binary_file_detected(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test detection of empty binary files."""
        binary_file = temp_dir / "empty.bst"
        binary_file.write_bytes(b"")

        result = xgboost_scanner.scan(str(binary_file))

        assert any("empty" in str(issue.message).lower() for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_empty" in result.metadata["scan_outcome_reasons"]

    @pytest.mark.parametrize("suffix", [".bst", ".model"])
    def test_pickle_masquerading_as_binary_model_is_inconclusive(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner, suffix: str
    ) -> None:
        """Pickle files masquerading as XGBoost binaries should fail closed."""
        # Create a pickle file
        pickle_data = pickle.dumps({"fake": "model"})

        fake_bst = temp_dir / f"fake{suffix}"
        fake_bst.write_bytes(pickle_data)

        result = xgboost_scanner.scan(str(fake_bst))

        assert any("pickle file" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_pickle_spoof" in result.metadata["scan_outcome_reasons"]

    def test_non_pickle_binary_starting_with_proto0_like_byte_is_not_spoof(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Custom XGBoost-like binaries starting with 'c' are not automatically pickle spoofs."""
        binary_file = temp_dir / "custom.bst"
        binary_file.write_bytes(b"custom xgboost binary gbtree reg:squarederror")

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert not any("pickle file" in str(issue.message) for issue in result.issues)

    def test_bst_with_ubjson_header_routes_to_ubj_scan(self, temp_dir: Path) -> None:
        """Modern UBJSON-backed .bst files should bypass binary structure validation."""
        binary_file = temp_dir / "modern.bst"
        binary_file.write_bytes(_xgboost_ubjson_probe())
        scanner = XGBoostScanner()

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch.object(scanner, "_scan_ubj_model") as mock_scan_ubj,
            patch.object(scanner, "_validate_binary_structure") as mock_validate_binary_structure,
        ):
            result = scanner.scan(str(binary_file))

        mock_scan_ubj.assert_called_once_with(str(binary_file), result)
        mock_validate_binary_structure.assert_not_called()

    def test_bst_with_late_ubjson_strong_marker_routes_to_ubj_scan(self, temp_dir: Path) -> None:
        """Large UBJSON .bst files should not require strong markers in the probe window."""
        binary_file = temp_dir / "modern_large.bst"
        binary_file.write_bytes(
            b"{L" + (b"\0" * 8) + b"learner" + (b"\0" * XGBoostScanner._UBJSON_PROBE_READ_BYTES) + b"version"
        )
        scanner = XGBoostScanner()

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=True),
            patch.object(scanner, "_scan_ubj_model") as mock_scan_ubj,
            patch.object(scanner, "_validate_binary_structure") as mock_validate_binary_structure,
        ):
            result = scanner.scan(str(binary_file))

        mock_scan_ubj.assert_called_once_with(str(binary_file), result)
        mock_validate_binary_structure.assert_not_called()

    def test_bst_with_ubjson_like_header_without_markers_uses_binary_validation(self, temp_dir: Path) -> None:
        """UBJSON-looking bytes without XGBoost markers should not bypass binary validation."""
        binary_file = temp_dir / "custom.bst"
        binary_file.write_bytes(b"{Llegacy gbtree reg:squarederror with enough bytes")
        scanner = XGBoostScanner()

        with (
            patch.object(scanner, "_scan_ubj_model") as mock_scan_ubj,
            patch.object(scanner, "_validate_binary_structure") as mock_validate_binary_structure,
        ):
            scanner.scan(str(binary_file))

        mock_scan_ubj.assert_not_called()
        mock_validate_binary_structure.assert_called_once_with(str(binary_file), ANY)

    def test_binary_structure_exception_is_inconclusive(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Binary analyzer exceptions should fail closed instead of returning success."""
        binary_file = temp_dir / "broken.bst"
        binary_file.write_bytes(b"gbtree reg:squarederror with enough bytes")

        with patch.object(xgboost_scanner, "_validate_binary_structure", side_effect=RuntimeError("boom")):
            result = xgboost_scanner.scan(str(binary_file))

        assert any("Error analyzing XGBoost binary model: boom" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_analysis_failed" in result.metadata["scan_outcome_reasons"]

    def test_binary_structure_read_failure_is_inconclusive(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Read failures caught inside structure validation should still fail closed."""
        binary_file = temp_dir / "unreadable.bst"
        binary_file.write_bytes(b"gbtree reg:squarederror with enough bytes")
        result = xgboost_scanner._create_result()

        with patch("builtins.open", side_effect=OSError("forced read failure")):
            xgboost_scanner._validate_binary_structure(str(binary_file), result)
        xgboost_scanner._finish_scan_result(result)

        assert any("forced read failure" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_analysis_failed" in result.metadata["scan_outcome_reasons"]

    def test_binary_structure_validation(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test binary structure validation."""
        # Create a file with some XGBoost-like content
        binary_content = b"binf\x00\x00\x01\x02reg:squarederror\x00\x00extra xgboost bytes"

        binary_file = temp_dir / "valid.bst"
        binary_file.write_bytes(binary_content)

        result = xgboost_scanner.scan(str(binary_file))

        # Should find expected XGBoost patterns
        pattern_checks = [c for c in result.checks if "Pattern Check" in c.name and c.status.value == "passed"]
        assert len(pattern_checks) > 0

    def test_marker_only_binary_is_inconclusive(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Printable marker-shaped junk should not pass as a legacy binary model."""
        binary_file = temp_dir / "marker_only.bst"
        binary_file.write_bytes(b"custom xgboost binary gbtree reg:squarederror")

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]
        assert any("expected XGBoost binary signature" in str(issue.message) for issue in result.issues)

    def test_binf_binary_signature_passes_structure_validation(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """The binary binf signature should not be treated as markerless."""
        binary_file = temp_dir / "signature.bst"
        binary_file.write_bytes(b"binf" + (b"\0" * 60) + b"gbtree appears outside first read window")

        result = xgboost_scanner.scan(str(binary_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert any(
            "binf" in check.details.get("patterns_found", [])
            for check in result.checks
            if "Pattern Check" in check.name
        )

    def test_suspicious_binary_patterns_detected(self, temp_dir: Path, xgboost_scanner: XGBoostScanner) -> None:
        """Test detection of suspicious binary patterns."""
        # Create binary data with no recognizable XGBoost patterns
        suspicious_binary = bytes(range(256))  # All byte values 0-255

        binary_file = temp_dir / "suspicious.bst"
        binary_file.write_bytes(suspicious_binary)

        result = xgboost_scanner.scan(str(binary_file))

        # Should detect unusual binary patterns
        assert any("unusual binary patterns" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]

    def test_printable_binary_without_xgboost_markers_is_inconclusive(
        self, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Printable .bst content without XGBoost markers should not pass cleanly."""
        binary_file = temp_dir / "printable.bst"
        binary_file.write_bytes(b"abcdefghijklmnopqrstuvwxyzabcdef")

        result = xgboost_scanner.scan(str(binary_file))

        assert any("expected XGBoost binary signature" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_structure_unrecognized" in result.metadata["scan_outcome_reasons"]

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    def test_xgboost_loading_disabled_by_default(
        self, mock_check_xgb: Mock, temp_dir: Path, xgboost_scanner: XGBoostScanner
    ) -> None:
        """Test that XGBoost loading is disabled by default."""
        mock_check_xgb.return_value = True

        binary_file = temp_dir / "test.bst"
        binary_file.write_bytes(b"some_binary_data gbtree reg:squarederror")

        result = xgboost_scanner.scan(str(binary_file))

        # Should indicate safe mode (loading disabled)
        assert any("safe mode" in str(check.message) for check in result.checks)

    def test_ubjson_bst_without_decoder_uses_loading_fallback(self, temp_dir: Path) -> None:
        """Detected UBJSON .bst files should still exercise XGBoost loading when enabled."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_probe())
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        def record_successful_load(path: str, result: ScanResult) -> None:
            result.add_check(
                name="XGBoost Model Loading",
                passed=True,
                message="XGBoost model loaded successfully in isolated process",
                location=path,
                details={"load_test": "passed"},
            )

        with (
            patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False),
            patch.object(loading_scanner, "_safe_xgboost_load", side_effect=record_successful_load) as mock_safe_load,
        ):
            result = loading_scanner.scan(str(ubjson_bst))

        mock_safe_load.assert_called_once()
        assert mock_safe_load.call_args.args[0] == str(ubjson_bst)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJSON Library Check" for check in result.checks)
        assert any(
            check.name == "XGBoost Model Loading" and check.status == CheckStatus.PASSED for check in result.checks
        )
        assert not any(check.name == "Binary Structure Validation" for check in result.checks)

    def test_ubjson_bst_without_decoder_or_loading_fails_closed(self, temp_dir: Path) -> None:
        """Detected UBJSON .bst files should not be misreported as malformed legacy binaries."""
        ubjson_bst = temp_dir / "model.bst"
        ubjson_bst.write_bytes(_xgboost_ubjson_probe())

        with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
            result = XGBoostScanner({"enable_xgb_loading": False}).scan(str(ubjson_bst))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_ubj_dependency_missing" in result.metadata["scan_outcome_reasons"]
        assert any(check.name == "UBJSON Library Check" for check in result.checks)
        assert not any(check.name == "Binary Structure Validation" for check in result.checks)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_success(self, mock_subprocess: Mock, mock_check_xgb: Mock, temp_dir: Path) -> None:
        """Test successful XGBoost model loading."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = "SUCCESS: Model loaded successfully"
        mock_proc.stderr = ""
        mock_subprocess.run.return_value = mock_proc

        # Create scanner with loading enabled
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "valid.bst"
        binary_file.write_bytes(b"dummy_xgboost_data gbtree reg:squarederror")

        result = loading_scanner.scan(str(binary_file))

        assert any("loaded successfully" in str(check.message) for check in result.checks)
        mock_subprocess.run.assert_called_once()
        _, run_kwargs = mock_subprocess.run.call_args
        assert "cwd" in run_kwargs
        assert run_kwargs["cwd"] is not None
        assert "env" in run_kwargs
        assert isinstance(run_kwargs["env"], dict)
        assert "PYTHONPATH" not in run_kwargs["env"]

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_failure(self, mock_subprocess: Mock, mock_check_xgb: Mock, temp_dir: Path) -> None:
        """Test XGBoost model loading failure detection."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "ERROR: Invalid model format"
        mock_subprocess.run.return_value = mock_proc

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "invalid.bst"
        binary_file.write_bytes(b"invalid_data gbtree reg:squarederror")

        result = loading_scanner.scan(str(binary_file))

        assert any("Failed to load XGBoost model" in str(issue.message) for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_load_failed" in result.metadata["scan_outcome_reasons"]

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_windows_path_passed_via_argv(self, mock_subprocess: Mock, mock_check_xgb: Mock) -> None:
        """Test subprocess load command handles backslashes by passing paths via argv."""
        mock_check_xgb.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = "SUCCESS: Model loaded successfully"
        mock_proc.stderr = ""
        mock_subprocess.run.return_value = mock_proc

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})
        result = loading_scanner._create_result()
        windows_path = r"C:\temp\model\xgboost.bin"

        loading_scanner._safe_xgboost_load(windows_path, result)

        run_args, run_kwargs = mock_subprocess.run.call_args
        cmd = run_args[0]
        script = cmd[3]
        assert cmd[1] == "-I"
        assert "sys.argv[1]" in script
        assert windows_path not in script
        assert cmd[4] == windows_path
        assert run_kwargs["cwd"] != str(Path.cwd())
        assert "PYTHONPATH" not in run_kwargs["env"]
        assert any("loaded successfully" in str(check.message) for check in result.checks)

    @patch("modelaudit.scanners.xgboost_scanner._check_xgboost_available")
    @patch("modelaudit.scanners.xgboost_scanner.subprocess")
    def test_xgboost_loading_timeout(self, mock_subprocess: Mock, mock_check_xgb: Mock, temp_dir: Path) -> None:
        """Test XGBoost model loading timeout handling."""
        mock_check_xgb.return_value = True
        mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
        mock_subprocess.run.side_effect = real_subprocess.TimeoutExpired(["python"], 30)

        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})

        binary_file = temp_dir / "timeout.bst"
        binary_file.write_bytes(b"data_that_causes_timeout gbtree reg:squarederror")

        result = loading_scanner.scan(str(binary_file))

        assert any("timeout" in str(issue.message).lower() for issue in result.issues)
        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_load_timeout" in result.metadata["scan_outcome_reasons"]


class TestXGBoostFailClosedEndToEnd:
    """Test CLI/core-visible XGBoost fail-closed semantics."""

    def test_malformed_xgboost_json_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        json_file = tmp_path / "booster.json"
        json_file.write_text('{"version":[1,7,4],"learner":{"gradient_booster":')
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(json_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert "xgboost" in result.scanner_names
                _assert_inconclusive_metadata(result, json_file, "xgboost_json_parse_failed")
                assert any("Invalid JSON format" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_missing_ubjson_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        ubj_file = tmp_path / "model.ubj"
        ubj_file.write_bytes(b"\x7b\x55")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
                first, second = _scan_twice_with_cache(ubj_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                _assert_inconclusive_metadata(result, ubj_file, "xgboost_ubj_dependency_missing")
                assert any("Cannot scan UBJ file" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_missing_ubjson_for_bst_header_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        bst_file = tmp_path / "model.bst"
        bst_file.write_bytes(_xgboost_ubjson_probe())
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            with patch("modelaudit.scanners.xgboost_scanner._check_ubjson_available", return_value=False):
                first, second = _scan_twice_with_cache(bst_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert "xgboost" in result.scanner_names
                _assert_inconclusive_metadata(result, bst_file, "xgboost_ubj_dependency_missing")
                assert any("Cannot scan UBJ file" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_pickle_spoof_core_preserves_pickle_scan_and_is_uncached(self, tmp_path: Path) -> None:
        spoof_file = tmp_path / "spoof.bst"
        spoof_file.write_bytes(pickle.dumps({"safe": True}, protocol=4))
        cache_dir = tmp_path / "cache"

        direct = scan_file(str(spoof_file), config={"cache_enabled": False})
        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert "xgboost_binary_pickle_spoof" in direct.metadata["scan_outcome_reasons"]

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(spoof_file, cache_dir)

            for result in (first, second):
                assert determine_exit_code(result) == 1
                assert "pickle" in result.scanner_names
                _assert_inconclusive_metadata(result, spoof_file, "xgboost_binary_pickle_spoof")
                assert any(
                    issue.severity == IssueSeverity.WARNING and "pickle file with .bst extension" in str(issue.message)
                    for issue in result.issues
                )

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_directory_dedup_preserves_filename_sensitive_spoof_detection(self, tmp_path: Path) -> None:
        payload = pickle.dumps({"safe": True}, protocol=4)
        pickle_file = tmp_path / "same.pkl"
        spoof_file = tmp_path / "same.bst"
        pickle_file.write_bytes(payload)
        spoof_file.write_bytes(payload)

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        spoof_issues = [issue for issue in result.issues if "pickle file with .bst extension" in str(issue.message)]
        assert result.files_scanned == 2
        assert determine_exit_code(result) == 1
        assert len(spoof_issues) == 1
        assert spoof_issues[0].location == str(spoof_file)
        assert (
            "xgboost_binary_pickle_spoof" in result.file_metadata[str(spoof_file)].model_dump()["scan_outcome_reasons"]
        )
        assert "xgboost_binary_pickle_spoof" not in result.file_metadata[str(pickle_file)].model_dump().get(
            "scan_outcome_reasons",
            [],
        )

    def test_generic_model_pickle_core_does_not_false_positive(self, tmp_path: Path) -> None:
        model_file = tmp_path / "safe.model"
        model_file.write_bytes(pickle.dumps({"safe": True}, protocol=4))

        result = scan_model_directory_or_file(str(model_file), cache_enabled=False)

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "pickle" in result.scanner_names
        assert not result.issues

    def test_tiny_binary_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "tiny.bst"
        binary_file.write_bytes(b"abcdefghijklmnopqrstuvwxyzabcde")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(binary_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                _assert_inconclusive_metadata(result, binary_file, "xgboost_binary_structure_too_small")
                assert any("too small" in str(issue.message).lower() for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_marker_only_xgboost_binary_core_fails_closed(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "custom.bst"
        binary_file.write_bytes(b"custom xgboost binary gbtree reg:squarederror")

        result = scan_model_directory_or_file(str(binary_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert "xgboost" in result.scanner_names
        _assert_inconclusive_metadata(result, binary_file, "xgboost_binary_structure_unrecognized")

    def test_binf_signature_core_does_not_false_positive(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "signature.bst"
        binary_file.write_bytes(b"binf" + (b"\0" * 60) + b"gbtree appears outside first read window")

        result = scan_model_directory_or_file(str(binary_file), cache_enabled=False)

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert "xgboost" in result.scanner_names
        assert not result.issues

    def test_markerless_binary_core_fails_closed_and_is_uncached(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "markerless.bst"
        binary_file.write_bytes(b"abcdefghijklmnopqrstuvwxyzabcdef")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(binary_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                _assert_inconclusive_metadata(result, binary_file, "xgboost_binary_structure_unrecognized")
                assert any("expected XGBoost binary signature" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()


class TestXGBoostScannerConfiguration:
    """Test XGBoost scanner configuration options."""

    def test_xgboost_loading_enabled(self, temp_dir):
        """Test enabling XGBoost loading."""
        loading_scanner = XGBoostScanner({"enable_xgb_loading": True})
        assert loading_scanner.enable_xgb_loading is True


class TestXGBoostSecurityPatterns:
    """Test specific security vulnerability patterns."""

    def test_hex_encoded_data_detection(self, temp_dir, xgboost_scanner):
        """Test detection of hex-encoded data that could be shellcode."""
        malicious_json = {
            "version": [1, 0, 0],
            "learner": {
                "suspicious_field": "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48",  # Hex pattern
                "another_field": "\\x90\\x90\\x90\\x90",  # NOP sled pattern
            },
        }

        json_file = temp_dir / "hex_encoded.json"
        json_file.write_text(json.dumps(malicious_json))

        result = xgboost_scanner.scan(str(json_file))

        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) > 0
        assert any("Hex-encoded data" in str(issue.message) for issue in critical_issues)


class TestXGBoostPickleIntegration:
    """Test integration with pickle scanner for XGBoost pickle files."""

    def test_pickle_file_with_xgboost_extension_detected(self, temp_dir, xgboost_scanner):
        """Test that pickle files masquerading as XGBoost files are detected."""
        # Create a pickle file with XGBoost-related content
        xgb_mock = FakeBooster()
        pickle_data = pickle.dumps(xgb_mock)

        fake_bst = temp_dir / "xgb_model.bst"
        fake_bst.write_bytes(pickle_data)

        result = xgboost_scanner.scan(str(fake_bst))

        # Should detect file format spoofing
        assert any("pickle file" in str(issue.message) for issue in result.issues)
        assert result.success is False


# Integration tests (require actual dependencies)
@pytest.mark.integration
@pytest.mark.xgboost
class TestXGBoostScannerIntegration:
    """Integration tests requiring actual XGBoost/ubjson libraries."""

    def test_real_xgboost_model_creation_and_scan(self, temp_dir: Path) -> None:
        """Test scanning of a real XGBoost model."""
        pytest.importorskip("xgboost", minversion="1.0")
        import numpy as np
        import xgboost as xgb

        # Create a simple dataset and train a model
        X = np.random.randn(100, 3)
        y = np.random.randn(100)

        dtrain = xgb.DMatrix(X, label=y)
        params = {"objective": "reg:squarederror", "max_depth": 3, "eta": 0.1}
        model = xgb.train(params, dtrain, num_boost_round=5)

        # Save in different formats
        json_path = temp_dir / "real_model.json"
        bst_path = temp_dir / "real_model.bst"

        model.save_model(str(json_path))
        model.save_model(str(bst_path))

        # Scan both files
        scanner = XGBoostScanner()

        json_result = scanner.scan(str(json_path))
        bst_result = scanner.scan(str(bst_path))

        # Both should scan successfully without critical issues
        assert json_result.success
        assert bst_result.success

        json_critical = [i for i in json_result.issues if i.severity == IssueSeverity.CRITICAL]
        bst_critical = [i for i in bst_result.issues if i.severity == IssueSeverity.CRITICAL]

        assert len(json_critical) == 0, f"JSON model had critical issues: {json_critical}"
        assert len(bst_critical) == 0, f"BST model had critical issues: {bst_critical}"

    def test_real_ubj_format_scan(self, temp_dir, valid_xgboost_json):
        """Test scanning of real UBJ format."""
        ubjson = pytest.importorskip("ubjson")

        # Create UBJ file
        ubj_path = temp_dir / "model.ubj"
        ubj_data = ubjson.dumpb(valid_xgboost_json)
        ubj_path.write_bytes(ubj_data)

        scanner = XGBoostScanner()
        result = scanner.scan(str(ubj_path))

        assert result.success

        # Should successfully decode UBJ
        assert any("decoded successfully" in str(check.message) for check in result.checks)

        # Should not have critical issues for valid content (except analysis errors which are acceptable)
        critical_issues = [
            i for i in result.issues if i.severity == IssueSeverity.CRITICAL and "Error analyzing" not in str(i.message)
        ]
        assert len(critical_issues) == 0
