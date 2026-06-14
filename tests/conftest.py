import hashlib
import importlib
import importlib.util
import logging
import os
import pickle
import shutil
import sys
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.xdist_status import (
    WORKER_STATUS_DIR_KEY,
    XdistWorkerStatusReporter,
    clear_worker_status,
    status_file_for_worker,
    write_worker_status,
)

# ============================================================================
# Framework availability detection (cached for performance)
# ============================================================================
_FRAMEWORK_MODULES = {
    "tensorflow": "tensorflow",
    "pytorch": "torch",
    "onnx": "onnx",
    "h5py": "h5py",
    "msgpack": "msgpack",
    "xgboost": "xgboost",
    "safetensors": "safetensors",
    "joblib": "joblib",
    "dill": "dill",
}
_FRAMEWORK_AVAILABILITY: dict[str, bool] = {}

# Reduced CI lanes only install the dependency set needed for this curated test
# subset. Keep this centralized so adding a supported Python version requires one
# deliberate update instead of duplicating version checks in hook logic.
RESTRICTED_PYTHON_VERSIONS = frozenset({(3, 10), (3, 12), (3, 13)})


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register deterministic CI sharding options."""
    group = parser.getgroup("modelaudit sharding")
    group.addoption(
        "--modelaudit-shard-count",
        dest="modelaudit_shard_count",
        type=int,
        default=None,
        help="Split collected tests into this many deterministic shards.",
    )
    group.addoption(
        "--modelaudit-shard-index",
        dest="modelaudit_shard_index",
        type=int,
        default=None,
        help="Run this zero-based deterministic shard.",
    )


def _nodeid_shard(nodeid: str, shard_count: int) -> int:
    """Map a pytest node ID to one stable shard."""
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    digest = hashlib.sha256(nodeid.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % shard_count


def _configured_shard(config: pytest.Config) -> tuple[int, int] | None:
    """Return the validated ``(index, count)`` requested by CI."""
    shard_count = config.getoption("modelaudit_shard_count")
    shard_index = config.getoption("modelaudit_shard_index")
    if shard_count is None and shard_index is None:
        return None
    if shard_count is None or shard_index is None:
        raise pytest.UsageError("--modelaudit-shard-count and --modelaudit-shard-index must be used together")
    if shard_count <= 0:
        raise pytest.UsageError("--modelaudit-shard-count must be positive")
    if shard_index < 0 or shard_index >= shard_count:
        raise pytest.UsageError(f"--modelaudit-shard-index must be between 0 and {shard_count - 1}")
    return shard_index, shard_count


def _check_framework(name: str) -> bool:
    """Check whether a framework package can be imported, with lazy caching."""
    cached_result = _FRAMEWORK_AVAILABILITY.get(name)
    if cached_result is not None:
        return cached_result

    try:
        is_available = importlib.util.find_spec(name) is not None
        if is_available:
            importlib.import_module(name)
    except Exception:
        is_available = False

    _FRAMEWORK_AVAILABILITY[name] = is_available
    return is_available


_xdist_status_reporter: XdistWorkerStatusReporter | None = None
_xdist_worker_status_file: Path | None = None
_xdist_workerid: str | None = None


def _detect_symlink_support() -> bool:
    if os.name != "nt":
        return True
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            target = temp_path / "target.txt"
            target.write_text("data")
            link = temp_path / "link.txt"
            link.symlink_to(target)
        return True
    except (OSError, NotImplementedError):
        return False


HAS_SYMLINKS = _detect_symlink_support()


def pytest_runtest_setup(item):
    """Skip tests based on Python version and framework availability."""
    # Skip problematic tests on restricted Python versions to ensure CI passes
    if sys.version_info[:2] in RESTRICTED_PYTHON_VERSIONS:
        test_file = str(item.fspath)

        # Only allow core XGBoost scanner tests and basic unit tests on problematic Python versions
        allowed_test_files = [
            "test_xgboost_scanner.py",
            "test_pickle_scanner.py",
            "test_pickle_binunicode8_setitem.py",
            "test_picklescan_adapter.py",
            "test_nested_budget_limits.py",
            "test_basic.py",  # ScanResult private-metadata merge regressions
            "test_joblib_scanner.py",
            "test_scanner_registry.py",  # Scanner registry routing and metadata tests
            "test_scanner_selection.py",  # Scanner selection policy and routing tests
            "test_lazy_loading.py",  # Lazy scanner descriptor/catalog tests
            "test_graceful_degradation.py",  # Scanner dependency degradation tests
            "test_onnx_dependency_handling.py",  # ONNX optional dependency capability outcomes
            "test_joblib_scanner_codecs.py",  # Joblib raw/compressed pickle fallback regression tests
            "test_base_scanner.py",
            "test_core.py",
            "test_cli.py",
            "test_sarif_formatter.py",  # SARIF output and credential-redaction regressions
            "test_sarif_redaction.py",  # SARIF exported source credential-redaction regressions
            "test_directory_file_filtering.py",  # Directory prefilter regression tests
            "test_dependency_lock.py",  # Security-sensitive uv.lock dependency guardrails
            "test_perf_workflow.py",  # GitHub Actions workflow contract and benchmark regression tests
            "test_bug1_confidence_exploit.py",  # Security bug test
            "test_gguf_scanner.py",  # GGUF scanner tests
            "test_jax_checkpoint_scanner.py",  # JAX checkpoint scanner tests
            "test_shebang_context.py",  # Shebang context verification tests
            "test_file_hash.py",  # SHA256 hashing utility tests
            "test_streaming_scan.py",  # Streaming scan tests
            "test_secure_hasher.py",  # Aggregate hash computation tests
            "test_advanced_file_handler.py",  # Large-file fail-closed handler regressions
            "test_huggingface_extensions.py",  # HuggingFace MODEL_EXTENSIONS tests
            "test_huggingface_inconclusive_coverage.py",  # Pinned HF incomplete-coverage regression
            "test_huggingface_symlinks.py",  # HuggingFace cache symlink routing tests
            "test_regular_scan_hash.py",  # Regular scan mode hash generation tests
            "test_core_asset_extraction.py",  # Check consolidation and location parsing regressions
            "test_manifest_scanner.py",  # Manifest scanner tests
            "test_text_scanner.py",  # ML-related text scanner outcome tests
            "test_metadata_scanner.py",  # Metadata scanner tests
            "test_metadata_extractor.py",  # Metadata extractor helper routing and CLI tests
            "test_weak_hash_detection.py",  # Weak hash detection tests
            "test_cloud_url_detection.py",  # Cloud storage URL detection tests
            "test_license_checker.py",  # License metadata and nearby-license caching tests
            "test_license_integration.py",  # End-to-end license metadata integration tests
            "tests/utils/sources/test_cloud_storage.py",  # Cloud storage source tests
            "tests/utils/sources/test_dvc_integration.py",  # DVC fail-closed resolution tests
            "test_skops_scanner.py",  # Skops scanner CVE detection tests
            "test_keras_zip_scanner.py",  # Keras ZIP scanner tests
            "test_flax_msgpack_scanner.py",  # Flax msgpack scanner performance and safety tests
            "test_keras_utils.py",  # Shared Keras scanner helper tests
            "test_nemo_scanner.py",  # NeMo scanner CVE-2025-23304 tests
            "test_numpy_scanner.py",  # NumPy scanner CVE-2019-6446 tests
            "test_onnx_scanner.py",  # ONNX scanner CVE-2025-51480 tests
            "test_pmml_scanner.py",  # PMML suspicious-content false-positive regressions
            "test_pmml_dependency_handling.py",  # PMML safe-parser fail-closed regressions
            "test_safetensors_scanner.py",  # SafeTensors scanner dtype and metadata tests
            "test_weight_distribution_scanner.py",  # Weight-distribution false-positive and coverage tests
            "test_rule_mapper.py",  # Rule mapper validity and network mapping tests
            "test_rule_code_registry_consistency.py",  # Scanner literal rule-code registry consistency
            "test_network_comm_detector.py",  # Network URL/path redaction tests
            "test_secrets_detector.py",  # Embedded secret detector redaction tests
            "test_jit_script_detector.py",  # JIT embedded Python execution regressions
            "test_keras_h5_scanner.py",  # Keras H5 scanner CVE-2025-9905 tests
            "test_keras_h5_lambda_helpers.py",  # Keras H5 Lambda callback classification tests
            "test_code_validation.py",  # In-memory Python syntax validation regressions
            "test_cve_detection.py",  # CVE detection tests
            "test_pytorch_zip_scanner.py",  # PyTorch ZIP scanner tests
            "test_pytorch_binary_scanner.py",  # PyTorch binary scanner outcome regressions
            "test_paddle_scanner.py",  # PaddlePaddle scanner tests
            "test_cve_2025_10155_bin_pickle.py",  # CVE-2025-10155 .bin pickle detection tests
            "test_compressed_scanner.py",  # standalone compressed wrapper scanner tests
            "test_catboost_scanner.py",  # CatBoost scanner tests
            "test_r_serialized_scanner.py",  # R serialized scanner tests
            "test_cntk_scanner.py",  # CNTK .dnn/.cmf scanner tests
            "test_rknn_scanner.py",  # RKNN scanner tests
            "test_torch7_scanner.py",  # Torch7 scanner tests
            "test_lightgbm_scanner.py",  # LightGBM native scanner tests
            "test_llamafile_scanner.py",  # Llamafile executable scanner tests
            "test_coreml_scanner.py",  # CoreML scanner tests
            "test_mxnet_scanner.py",  # MXNet scanner tests
            "test_openvino_scanner.py",  # OpenVINO namespace and sidecar safety tests
            "test_filetype.py",  # File type detection and validation tests
            "test_tf_metagraph_scanner.py",  # TensorFlow MetaGraph scanner tests
            "test_tf_savedmodel_scanner.py",  # TensorFlow SavedModel scanner tests
            "test_tflite_scanner.py",  # TFLite scanner guardrail tests
            "test_tensorrt_scanner.py",  # TensorRT scanner tests
            "test_torchserve_mar_scanner.py",  # TorchServe .mar scanner tests
            "test_jinja2_template_scanner.py",  # Jinja2 template parse fallback regression tests
            "test_evidence_redaction.py",  # Shared scanner evidence redaction tests
            "test_evidence_redaction_authorization_continuation.py",  # Folded auth-header redaction regressions
            "test_catboost_evidence_redaction.py",  # CatBoost command evidence redaction tests
            "test_executorch_scanner.py",  # ExecuTorch scanner tests
            "test_telemetry.py",  # telemetry payload and availability tests
            "test_telemetry_decoupling.py",  # telemetry failure-isolation tests
            "test_debug_command.py",  # debug output telemetry flags
            "test_auth_config.py",  # auth config path and secret-storage hardening tests
            "test_utils.py",  # archive path sanitization regression coverage
            "test_exit_codes.py",  # exit-code precedence regression tests
            "test_models.py",  # aggregate result model and exit-code propagation tests
            "test_file_filter.py",  # Directory file prefilter tests
            "test_huggingface.py",  # HuggingFace provenance and cache path tests
            "test_huggingface_fp_regression_harness.py",  # opt-in HuggingFace false-positive harness tests
            "test_pytorch_hub.py",  # PyTorch Hub artifact URL and download budget regression tests
            "test_oci_layer_scanner.py",  # OCI layer path safety regression tests
            "test_jfrog.py",  # JFrog utility tests
            "test_jfrog_integration.py",  # JFrog integration tests
            "test_jfrog_redirect_security.py",  # JFrog redirect SSRF regression tests
            "test_mlflow_integration.py",  # MLflow integration tests
            "test_streaming_analysis.py",  # signed stream routing and fallback regressions
            "test_tar_scanner.py",  # TAR archive scanner tests
            "test_zip_scanner.py",  # ZIP archive scanner tests
            "test_sevenzip_scanner.py",  # 7-Zip archive scanner tests
            "test_regression_corpus.py",  # malicious/safe fixture regression gate
            "test_committed_fixture_hygiene.py",  # committed fixture artifact inventory guardrails
            "test_nested_pickle_integration.py",  # nested pickle false-positive/true-positive integration tests
            "test_ml_context_false_positives.py",  # ML-context executable filtering regression tests
            "test_cli_output.py",  # CliRunner JSON parsing helper regression tests
            "test_cache_cli.py",  # cache CLI command regression tests
            "test_cache_correctness.py",  # cache invalidation and persistence correctness tests
            "test_optimized_config.py",  # optimized cache config regression tests
            "test_large_file_handler.py",  # Large file handler regression tests
            "test_file_iterator.py",  # Streaming file iterator memory regression tests
            "test_large_pickle_corpus_qa.py",  # large PickleScan Rust corpus QA harness tests
            "test_hf_whitelist_generators.py",  # Hugging Face whitelist code-generation security tests
            "test_call_graph_click.py",  # standalone picklescan Click editor call-graph RCE regressions
            "test_call_graph_execnet.py",  # standalone picklescan execnet call-graph RCE regressions
            "test_call_graph_instance_defaults.py",  # standalone picklescan constructor-default alias RCE regressions
            "test_call_graph_import_statements.py",  # standalone picklescan import-statement call-graph RCE regressions
            "test_call_graph_local_imports.py",  # standalone picklescan function-local import RCE regressions
            "test_call_graph_six.py",  # standalone picklescan six.moves alias RCE regressions
            "test_call_graph_tkinter.py",  # standalone picklescan Tcl call-graph RCE regressions
            "test_call_graph_assignment_alias_cycle.py",  # standalone picklescan alias fixpoint termination regressions
            "test_dill_joblib_enhanced.py",  # Dill/joblib pickle routing regression tests
            "test_pickle_context_filtering.py",  # Pickle context filtering regression tests
            "test_xdist_status.py",  # xdist worker progress reporting tests
            "test_hooks_egress.py",  # progress hook egress allowlist regressions
            "test_release_workflow.py",  # release workflow regression tests
            "test_docker_workflow.py",  # Docker workflow regression tests
            "test_sbom_symlink_containment.py",  # SBOM symlink containment regression tests
            "test_sbom_url_fixes.py",  # SBOM URL handling and credential-redaction regressions
        ]
        allowed_test_nodeids = [
            "tests/scanners/test_weight_distribution_scanner.py::TestWeightDistributionScanner::test_blocks_torch_load_for_vulnerable_pytorch_prereleases",
            "tests/scanners/test_weight_distribution_scanner.py::TestWeightDistributionScanner::test_allows_torch_load_for_stable_patched_pytorch",
            "tests/scanners/test_weight_distribution_scanner.py::TestWeightDistributionScanner::test_blocks_torch_load_for_unknown_pytorch_version",
            "tests/scanners/test_weight_distribution_scanner.py::TestWeightDistributionScanner::test_blocks_torch_load_for_unknown_patched_version_suffixes",
            "tests/test_security_enhancements.py::TestNumPyScannerSecurity::test_negative_dimension_rejection",
        ]

        # Check if this is an allowed test file
        if any(allowed_file in test_file for allowed_file in allowed_test_files) or any(
            item.nodeid.startswith(allowed_nodeid) for allowed_nodeid in allowed_test_nodeids
        ):
            pass  # Allow these tests to continue to framework check
        else:
            # Skip all other tests on Python 3.10/3.12/3.13 to prevent CI issues
            pytest.skip(f"Skipping test on Python {sys.version_info[:2]} - only core functionality tested")

    # Auto-skip tests based on framework markers when framework is unavailable
    for marker_name, module_name in _FRAMEWORK_MODULES.items():
        marker = item.get_closest_marker(marker_name)
        if marker is not None and not _check_framework(module_name):
            pytest.skip(f"{marker_name} is not installed")


@pytest.fixture(autouse=True)
def reset_rule_config_between_tests() -> Iterator[None]:
    """Keep CLI rule suppressions from leaking between tests."""
    from modelaudit.config import reset_config

    reset_config()
    yield
    reset_config()


@pytest.fixture(autouse=True)
def setup_logging():
    """Set up logging for tests."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    # Suppress excessive logging during tests
    logging.getLogger("modelaudit").setLevel(logging.CRITICAL)

    yield

    # Reset logging after test
    logging.getLogger("modelaudit").setLevel(logging.NOTSET)


@pytest.fixture
def requires_symlinks():
    """Skip tests when symlink creation is not supported."""
    if not HAS_SYMLINKS:
        pytest.skip("Symlinks are not supported on this platform")


@pytest.fixture
def sample_results():
    """Return a sample results dictionary for testing."""
    return {
        "path": "/path/to/model",
        "files_scanned": 5,
        "bytes_scanned": 1024,
        "duration": 0.5,
        "start_time": 1000.0,
        "finish_time": 1000.5,
        "issues": [
            {
                "message": "Test issue 1",
                "severity": "warning",
                "location": "test1.pkl",
                "details": {"test": "value1"},
                "timestamp": 1000.1,
            },
            {
                "message": "Test issue 2",
                "severity": "error",
                "location": "test2.pkl",
                "details": {"test": "value2"},
                "timestamp": 1000.2,
            },
            {
                "message": "Test issue 3",
                "severity": "info",
                "location": "test3.pkl",
                "details": {"test": "value3"},
                "timestamp": 1000.3,
            },
        ],
        "success": True,
        "has_errors": True,
    }


@pytest.fixture
def temp_model_dir(tmp_path):
    """Create a temporary directory with various model files for testing."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()

    # Create a real pickle file
    pickle_data = {"weights": [1, 2, 3], "bias": [0.1]}
    with (model_dir / "model1.pkl").open("wb") as f:
        pickle.dump(pickle_data, f)

    # Create a real PyTorch ZIP file
    zip_path = model_dir / "model2.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Add a real pickle inside
        pickled_data = pickle.dumps({"model": "data"})
        zipf.writestr("data.pkl", pickled_data)

    # Create a TensorFlow SavedModel directory
    tf_dir = model_dir / "tf_model"
    tf_dir.mkdir()
    (tf_dir / "saved_model.pb").write_bytes(b"tensorflow model content")

    # Create a subdirectory with more models
    sub_dir = model_dir / "subdir"
    sub_dir.mkdir()
    (sub_dir / "model3.h5").write_bytes(b"\x89HDF\r\n\x1a\nkeras model content")

    return model_dir


@pytest.fixture
def mock_progress_callback() -> "ProgressCallbackRecorder":
    """Return a mock progress callback object that records calls."""
    return ProgressCallbackRecorder()


class ProgressCallbackRecorder:
    """Record progress callback calls for assertions in integration tests."""

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.percentages: list[float] = []

    def __call__(self, message: str, percentage: float) -> None:
        self.messages.append(message)
        self.percentages.append(percentage)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_malicious_pickle_data():
    """Provide mock malicious pickle data for testing."""
    return {
        "os_system": b"cos\nsystem\nq\x00.",
        "eval_call": b"cbuiltins\neval\nq\x00.",
        "subprocess_call": b"csubprocess\ncall\nq\x00.",
    }


@pytest.fixture
def performance_markers():
    """Markers for performance-related tests."""
    return {
        "max_scan_time": 1.0,  # Maximum scan time in seconds
        "max_validation_time": 0.001,  # Maximum validation time in seconds
    }


# Configure pytest to handle missing optional dependencies gracefully
def pytest_configure(config):
    """Configure pytest with custom markers."""
    global _xdist_worker_status_file, _xdist_workerid

    # Test category markers
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow (deselect with '-m \"not slow\"')",
    )
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line(
        "markers",
        "performance: mark test as performance benchmark",
    )

    # Framework-specific markers (tests auto-skip if framework unavailable)
    config.addinivalue_line(
        "markers",
        "tensorflow: mark test as requiring TensorFlow",
    )
    config.addinivalue_line(
        "markers",
        "pytorch: mark test as requiring PyTorch",
    )
    config.addinivalue_line(
        "markers",
        "onnx: mark test as requiring ONNX",
    )
    config.addinivalue_line(
        "markers",
        "h5py: mark test as requiring h5py",
    )
    config.addinivalue_line(
        "markers",
        "msgpack: mark test as requiring msgpack",
    )
    config.addinivalue_line(
        "markers",
        "xgboost: mark test as requiring XGBoost",
    )
    config.addinivalue_line(
        "markers",
        "safetensors: mark test as requiring safetensors",
    )
    config.addinivalue_line(
        "markers",
        "joblib: mark test as requiring joblib",
    )
    config.addinivalue_line(
        "markers",
        "dill: mark test as requiring dill",
    )

    workerinput = getattr(config, "workerinput", None)
    if not workerinput:
        return

    status_dir = workerinput.get(WORKER_STATUS_DIR_KEY)
    workerid = workerinput.get("workerid")
    if status_dir and workerid:
        _xdist_workerid = str(workerid)
        _xdist_worker_status_file = status_file_for_worker(Path(status_dir), _xdist_workerid)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    """Pass the shared xdist worker-status directory to each worker."""
    global _xdist_status_reporter

    if _xdist_status_reporter is None:
        # pytest does not expose a public API at this xdist hook point for creating
        # a controller-owned temp directory. Pytest 8.4+ provides this internal
        # factory; fail clearly if a future pytest release removes it.
        tmp_path_factory = getattr(node.config, "_tmp_path_factory", None)
        if tmp_path_factory is None:
            raise RuntimeError(
                "pytest internal API changed: '_tmp_path_factory' is unavailable in pytest_configure_node"
            )

        status_dir = tmp_path_factory.mktemp("modelaudit-pytest-xdist")
        _xdist_status_reporter = XdistWorkerStatusReporter.from_environment(status_dir)
        if _xdist_status_reporter is None:
            return
        _xdist_status_reporter.start()

    node.workerinput[WORKER_STATUS_DIR_KEY] = str(_xdist_status_reporter.status_dir)


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node: Any, error: object | None) -> None:
    """Remove stale xdist worker-status files when a worker exits or crashes."""
    if _xdist_status_reporter is None:
        return

    workerid = node.workerinput.get("workerid")
    if workerid:
        _xdist_status_reporter.remove_worker_status(str(workerid))


def pytest_runtest_logstart(
    nodeid: str,
    location: tuple[str, int | None, str],
) -> None:
    """Record the test currently running in this worker process."""
    if _xdist_worker_status_file is None or _xdist_workerid is None:
        return

    write_worker_status(
        _xdist_worker_status_file,
        _xdist_workerid,
        nodeid,
    )


def pytest_runtest_logfinish(
    nodeid: str,
    location: tuple[str, int | None, str],
) -> None:
    """Clear this worker's running-test status after the test finishes."""
    if _xdist_worker_status_file is None:
        return

    clear_worker_status(_xdist_worker_status_file)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Stop controller-side xdist status reporting and clear worker status files."""
    global _xdist_status_reporter

    if _xdist_worker_status_file is not None:
        clear_worker_status(_xdist_worker_status_file)

    if _xdist_status_reporter is not None:
        _xdist_status_reporter.stop()
        _xdist_status_reporter = None


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests based on their file names (not test function names).

    Using file names instead of test function names avoids false positives
    like marking test_multiple_issues as slow just because 'multiple' appears
    in the name.
    """
    for item in items:
        test_file = str(item.fspath).lower()

        # Mark performance tests by file name
        if "performance" in test_file or "benchmark" in test_file:
            item.add_marker(pytest.mark.performance)

        # Mark integration tests by file name
        if "integration" in test_file:
            item.add_marker(pytest.mark.integration)

    configured_shard = _configured_shard(config)
    if configured_shard is None:
        return

    shard_index, shard_count = configured_shard
    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        destination = selected if _nodeid_shard(item.nodeid, shard_count) == shard_index else deselected
        destination.append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)


@pytest.fixture
def mock_scanner_registry():
    """Mock scanner registry to avoid loading heavy ML dependencies."""
    with patch("modelaudit.scanners.SCANNER_REGISTRY") as mock_registry:
        # Create lightweight mock scanners
        mock_pickle_scanner = Mock()
        mock_pickle_scanner.can_handle.return_value = True
        mock_pickle_scanner.scan.return_value = Mock(issues=[], files_scanned=1)

        mock_registry.__iter__.return_value = [mock_pickle_scanner]
        yield mock_registry


@pytest.fixture
def mock_ml_dependencies():
    """Mock heavy ML dependencies to prevent imports during unit tests."""
    mocks = {}

    # Mock TensorFlow
    mock_tf = MagicMock()
    mock_tf.__version__ = "2.13.0"
    mocks["tensorflow"] = mock_tf

    # Mock Keras
    mock_keras = MagicMock()
    mock_keras.__version__ = "2.13.0"
    mocks["keras"] = mock_keras

    # Mock PyTorch
    mock_torch = MagicMock()
    mock_torch.__version__ = "2.6.0"
    mocks["torch"] = mock_torch

    # Mock pandas/pyarrow that causes the crash
    mock_pandas = MagicMock()
    mocks["pandas"] = mock_pandas

    with patch.dict("sys.modules", mocks):
        yield mocks


@pytest.fixture
def mock_cli_scan_command():
    """Mock the CLI scan command to avoid heavy dependency loading."""
    # Mock the core scan function that the CLI actually uses
    # Create complete mock data matching ModelAuditResultModel structure
    import time

    current_time = time.time()

    mock_result_dict = {
        "files_scanned": 1,
        "bytes_scanned": 1024,
        "duration": 0.1,
        "issues": [],  # Use empty list to avoid Issue object complications
        "checks": [],  # Required field
        "assets": [],  # Required field
        "has_errors": False,
        "scanner_names": ["test_scanner"],  # Required field
        "file_metadata": {},  # Required field
        "start_time": current_time,  # Required field
        "total_checks": 1,  # Required field
        "passed_checks": 1,  # Required field
        "failed_checks": 0,  # Required field
        "success": True,
    }

    with patch("modelaudit.cli.scan_model_directory_or_file") as mock_scan:
        # Create a mock ModelAuditResultModel that properly exposes attributes
        mock_model = Mock()
        mock_model.model_dump.return_value = mock_result_dict

        # Ensure the mock exposes the attributes the CLI expects
        mock_model.issues = mock_result_dict["issues"]
        mock_model.files_scanned = mock_result_dict["files_scanned"]
        mock_model.bytes_scanned = mock_result_dict["bytes_scanned"]
        mock_model.has_errors = mock_result_dict["has_errors"]
        mock_model.assets = mock_result_dict["assets"]
        mock_model.file_metadata = mock_result_dict["file_metadata"]

        mock_scan.return_value = mock_model
        yield mock_scan


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Ensure test temp files are cleaned up after each test.

    Tests should use tmp_path for any temporary files;
    pytest handles tmp_path cleanup automatically.
    """
    yield


# =============================================================================
# Common file creation fixtures
# =============================================================================
@pytest.fixture
def safe_pickle_file(tmp_path):
    """Create a safe pickle file for testing."""
    path = tmp_path / "safe_model.pkl"
    data = {"model": "test", "weights": [1.0, 2.0, 3.0]}
    with open(path, "wb") as f:
        pickle.dump(data, f)
    return path


@pytest.fixture
def malicious_pickle_file(tmp_path):
    """Create a malicious pickle file for testing detection."""
    path = tmp_path / "malicious.pkl"
    # os.system payload
    path.write_bytes(b"cos\nsystem\n(S'echo pwned'\ntR.")
    return path


@pytest.fixture
def mock_pytorch_zip(tmp_path):
    """Create a mock PyTorch ZIP model file."""
    path = tmp_path / "model.pt"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("version", "3")
        data = pickle.dumps({"model": "pytorch_test"})
        zf.writestr("data.pkl", data)
    return path


@pytest.fixture
def model_directory(tmp_path):
    """Create a directory with various model files for comprehensive testing."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()

    # Create pickle file
    pickle_path = model_dir / "model.pkl"
    with open(pickle_path, "wb") as f:
        pickle.dump({"weights": [1, 2, 3]}, f)

    # Create a subdirectory
    sub_dir = model_dir / "subdir"
    sub_dir.mkdir()
    (sub_dir / "config.json").write_text('{"name": "test"}')

    return model_dir
