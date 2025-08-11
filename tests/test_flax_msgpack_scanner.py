import os

import msgpack

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner


def create_msgpack_file(path, data):
    """Helper to create msgpack files with specific data."""
    with open(path, "wb") as f:
        f.write(msgpack.packb(data, use_bin_type=True))


def create_malicious_msgpack_file(path):
    """Create a msgpack file with suspicious content."""
    malicious_data = {
        "params": {"w": list(range(5))},
        "__reduce__": "malicious_function",
        "code": "import os; os.system('rm -rf /')",
        "suspicious_blob": b"eval(compile('malicious code', 'string', 'exec'))" * 1000,
    }
    create_msgpack_file(path, malicious_data)


def test_flax_msgpack_valid_checkpoint(tmp_path):
    """Test scanning a valid Flax checkpoint."""
    path = tmp_path / "model.msgpack"
    # Create realistic Flax checkpoint structure
    data = {
        "params": {
            "layers_0": {"kernel": [[0.1, 0.2], [0.3, 0.4]], "bias": [0.1, 0.2]},
            "layers_1": {"kernel": [[0.5, 0.6]], "bias": [0.3]},
        },
        "opt_state": {"step": 1000},
        "metadata": {"model_name": "test_model", "version": "1.0"},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.metadata.get("top_level_type") == "dict"
    assert "params" in result.metadata.get("top_level_keys", [])
    assert (
        len(
            [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL],
        )
        == 0
    )


def test_flax_msgpack_suspicious_content(tmp_path):
    """Test detection of suspicious patterns in msgpack content."""
    path = tmp_path / "suspicious.msgpack"
    create_malicious_msgpack_file(path)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Should detect multiple security issues
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) > 0

    # Check for specific threats
    issue_messages = [issue.message for issue in result.issues]

    # Should detect suspicious key
    assert any("__reduce__" in msg for msg in issue_messages)

    # Should detect suspicious code patterns
    assert any("os.system" in msg or "import\\s+os" in msg for msg in issue_messages)


def test_flax_msgpack_large_containers(tmp_path):
    """Test detection of containers with excessive items."""
    path = tmp_path / "large.msgpack"
    # Create oversized containers (default limit is 50000)
    # Use smaller sizes in CI to avoid memory issues
    is_ci = os.getenv("CI") or os.getenv("GITHUB_ACTIONS")
    dict_size = 52000 if is_ci else 60000  # Just over limit, but smaller in CI
    list_size = 51000 if is_ci else 55000  # Just over limit, but smaller in CI

    large_dict = {f"key_{i}": f"value_{i}" for i in range(dict_size)}
    large_list = list(range(list_size))

    data = {"params": {"large_dict": large_dict, "large_list": large_list}}
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    assert len(info_issues) >= 2  # Should report both large containers at INFO level

    issue_messages = [issue.message for issue in info_issues]
    assert any("excessive items" in msg for msg in issue_messages)


def test_flax_msgpack_deep_nesting(tmp_path):
    """Test detection of excessive recursion depth."""
    path = tmp_path / "deep.msgpack"

    # Create deeply nested structure
    deep_data = {"level": 0}
    current = deep_data
    for i in range(1, 150):  # Deeper than default limit
        current["nested"] = {"level": i}
        current = current["nested"]

    create_msgpack_file(path, deep_data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert any("recursion depth exceeded" in issue.message for issue in critical_issues)


def test_flax_msgpack_non_standard_structure(tmp_path):
    """Test detection of non-standard Flax structures using structural analysis."""
    path = tmp_path / "nonstandard.msgpack"
    # Create structure that doesn't look like a Flax checkpoint
    data = {
        "random_key": "random_value",
        "another_key": [1, 2, 3],
        "not_flax": {"definitely": "not a model"},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # With our new structural analysis, this should be flagged as suspicious
    # because it has no numerical data that looks like ML weights
    warning_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
    assert any("Suspicious data structure" in issue.message for issue in warning_issues)


def test_flax_msgpack_corrupted(tmp_path):
    """Test handling of corrupted msgpack files."""
    path = tmp_path / "corrupt.msgpack"
    data = {"params": {"w": list(range(5))}}
    create_msgpack_file(path, data)

    # Corrupt the file by truncating it
    original_data = path.read_bytes()
    path.write_bytes(original_data[:-10])

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.has_errors
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert any(
        "Invalid msgpack format" in issue.message or "Unexpected error processing" in issue.message
        for issue in critical_issues
    )


def test_flax_msgpack_enhanced_jax_support(tmp_path):
    """Test enhanced JAX-specific functionality."""
    path = tmp_path / "jax_model.flax"

    # Create JAX model with transformer architecture
    data = {
        "params": {
            "transformer": {
                "attention": {"query": b"\x00" * 1000, "key": b"\x00" * 1000},
                "feed_forward": {"dense": b"\x00" * 2000},
            }
        },
        "opt_state": {"step": 1000, "learning_rate": 0.001},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success
    # Should detect transformer architecture
    assert result.metadata.get("model_architecture") == "transformer"
    assert result.metadata.get("estimated_parameters") > 0

    # Should detect optimizer state
    jax_metadata = result.metadata.get("jax_metadata", {})
    assert jax_metadata.get("has_optimizer_state") is True


def test_flax_msgpack_orbax_format_detection(tmp_path):
    """Test detection of Orbax checkpoint format."""
    path = tmp_path / "orbax_checkpoint.orbax"

    data = {
        "__orbax_metadata__": {"version": "0.1.0", "format": "flax"},
        "state": {"params": {"layer": b"\x00" * 1000}},
        "metadata": {"step": 5000},
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success

    # Should detect Orbax format
    jax_metadata = result.metadata.get("jax_metadata", {})
    assert jax_metadata.get("orbax_format") is True

    # Should have check about Orbax detection
    # Now using checks instead of issues - look for passed check with Orbax message
    orbax_checks = [check for check in result.checks if "Orbax checkpoint format detected" in check.message]
    assert len(orbax_checks) > 0, "No Orbax detection check found"
    assert orbax_checks[0].status.value == "passed"


def test_flax_msgpack_jax_specific_threats(tmp_path):
    """Test detection of JAX-specific security threats."""
    path = tmp_path / "malicious_jax.jax"

    data = {
        "params": {"layer": b"\x00" * 100},
        "__jax_array__": "fake_array_metadata",
        "custom_transform": "jax.jit(eval(malicious_code))",
        "shape": [-1, 100],  # Invalid negative dimension
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    # Should detect multiple threats
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    warning_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]

    # Check for JAX-specific threats
    issues_messages = [issue.message for issue in critical_issues + warning_issues]

    assert any("JAX array metadata" in msg for msg in issues_messages)
    assert any("negative dimensions" in msg for msg in issues_messages)


def test_flax_msgpack_large_model_support(tmp_path):
    """Test support for large transformer models."""
    path = tmp_path / "large_model.msgpack"

    # Create scanner with lower blob limit for testing
    is_ci = os.getenv("CI") or os.getenv("GITHUB_ACTIONS")
    blob_limit = 5 * 1024 * 1024 if is_ci else 10 * 1024 * 1024  # 5MB in CI, 10MB locally
    scanner = FlaxMsgpackScanner(config={"max_blob_bytes": blob_limit})

    # Simulate large model embedding
    embedding_size = 10 * 1024 * 1024 if is_ci else 20 * 1024 * 1024  # 10MB in CI, 20MB locally
    large_embedding = b"\x00" * embedding_size

    data = {
        "params": {
            "embedding": {"vocab_embedding": large_embedding},
            "transformer": {"layer_0": {"attention": b"\x00" * 1000}},
        }
    }
    create_msgpack_file(path, data)

    result = scanner.scan(str(path))

    assert result.success

    # Should handle large blobs without flagging as suspicious for legitimate models
    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    # The large blob should be detected but at INFO level, not CRITICAL
    large_blob_issues = [issue for issue in info_issues if "large binary blob" in issue.message.lower()]
    assert len(large_blob_issues) >= 1


def test_flax_msgpack_can_handle_extensions(tmp_path):
    """Test that scanner can handle all JAX/Flax file extensions."""
    extensions = [".msgpack", ".flax", ".orbax", ".jax"]

    for ext in extensions:
        test_file = tmp_path / f"test{ext}"
        test_file.write_bytes(b"\x81\xa4test\xa5value")  # Simple msgpack

        assert FlaxMsgpackScanner.can_handle(str(test_file))


def test_flax_msgpack_ml_context_confidence(tmp_path):
    """Test ML context confidence scoring."""
    path = tmp_path / "ml_model.msgpack"

    # Create data that strongly indicates ML model
    data = {
        "params": {
            "transformer": {
                "attention": {"query": b"\x00" * (768 * 768 * 4)},  # 768x768 matrix
                "feed_forward": {"dense": b"\x00" * (768 * 3072 * 4)},  # 768x3072 matrix
            },
            "embedding": {"token_embedding": b"\x00" * (50257 * 768 * 4)},  # GPT-2 vocab size
        }
    }
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success

    # Should have high confidence this is an ML model
    jax_metadata = result.metadata.get("jax_metadata", {})
    assert jax_metadata.get("confidence", 0) >= 0.7
    assert jax_metadata.get("is_ml_model") is True

    # Should find evidence of transformer architecture
    assert "transformer" in result.metadata.get("model_architecture", "")


def test_flax_msgpack_trailing_data(tmp_path):
    """Test detection of trailing data after msgpack content."""
    path = tmp_path / "trailing.msgpack"
    data = {"params": {"w": [1, 2, 3]}}
    create_msgpack_file(path, data)

    # Add trailing bytes
    original_data = path.read_bytes()
    path.write_bytes(original_data + b"TRAILING_GARBAGE_DATA")

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    warning_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.WARNING]
    assert any("trailing" in issue.message for issue in warning_issues)


def test_flax_msgpack_large_binary_blob(tmp_path):
    """Test detection of suspiciously large binary blobs.

    Uses smaller sizes in CI environments for faster test execution.
    GitHub Actions automatically sets CI=true.
    """
    import os

    # In CI, use smaller sizes for faster tests
    if os.getenv("CI") == "true":
        # Use 1MB threshold and 2MB blob for CI
        threshold_mb = 1
        blob_size_mb = 2
    else:
        # Use production-like sizes for local testing
        threshold_mb = 500
        blob_size_mb = 550

    path = tmp_path / "large_blob.msgpack"
    # Create large binary blob (exceeds threshold)
    large_blob = b"X" * (blob_size_mb * 1024 * 1024)
    data = {"params": {"normal_param": [1, 2, 3]}, "suspicious_blob": large_blob}
    create_msgpack_file(path, data)

    # Configure scanner with appropriate threshold
    config = {"max_blob_bytes": threshold_mb * 1024 * 1024}
    scanner = FlaxMsgpackScanner(config=config)
    result = scanner.scan(str(path))

    info_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.INFO]
    assert any("Suspiciously large binary blob" in issue.message for issue in info_issues)


def test_flax_msgpack_custom_config(tmp_path):
    """Test scanner with custom configuration parameters."""
    path = tmp_path / "test.msgpack"
    create_malicious_msgpack_file(path)

    # Test with custom config
    custom_config = {
        "max_recursion_depth": 10,
        "max_items_per_container": 100,
        "suspicious_patterns": [r"custom_threat"],
    }

    scanner = FlaxMsgpackScanner(config=custom_config)
    result = scanner.scan(str(path))

    # Should still detect some issues but with different thresholds
    assert len(result.issues) > 0
