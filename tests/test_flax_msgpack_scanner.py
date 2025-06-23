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
            [
                issue
                for issue in result.issues
                if issue.severity == IssueSeverity.CRITICAL
            ]
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
    critical_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
    ]
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
    # Create oversized containers
    large_dict = {f"key_{i}": f"value_{i}" for i in range(20000)}  # Over default limit
    large_list = list(range(15000))  # Over default limit

    data = {"params": {"large_dict": large_dict, "large_list": large_list}}
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    info_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.INFO
    ]
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

    critical_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
    ]
    assert any("recursion depth exceeded" in issue.message for issue in critical_issues)


def test_flax_msgpack_non_standard_structure(tmp_path):
    """Test detection of non-standard Flax structures."""
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

    info_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.INFO
    ]
    assert any(
        "No standard Flax checkpoint keys found" in issue.message
        for issue in info_issues
    )


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
    critical_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL
    ]
    assert any(
        "Invalid msgpack format" in issue.message
        or "Unexpected error processing" in issue.message
        for issue in critical_issues
    )


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

    warning_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.WARNING
    ]
    assert any("trailing" in issue.message for issue in warning_issues)


def test_flax_msgpack_large_binary_blob(tmp_path):
    """Test detection of suspiciously large binary blobs."""
    path = tmp_path / "large_blob.msgpack"
    # Create large binary blob (over 50MB default limit)
    large_blob = b"X" * (60 * 1024 * 1024)  # 60MB
    data = {"params": {"normal_param": [1, 2, 3]}, "suspicious_blob": large_blob}
    create_msgpack_file(path, data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    info_issues = [
        issue for issue in result.issues if issue.severity == IssueSeverity.INFO
    ]
    assert any(
        "Suspiciously large binary blob" in issue.message for issue in info_issues
    )


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
