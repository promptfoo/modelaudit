import struct

from unittest.mock import patch

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.paddle_scanner import PaddleScanner
from modelaudit.utils.file.detection import validate_file_type


def test_paddle_scanner_can_handle(tmp_path):
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"dummy")
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        assert PaddleScanner.can_handle(str(path))


def test_paddle_scanner_cannot_handle_without_paddle(tmp_path):
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"dummy")
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", False):
        assert not PaddleScanner.can_handle(str(path))


def test_paddle_scanner_detects_suspicious_pattern(tmp_path):
    content = b"os.system('ls')"
    path = tmp_path / "model.pdmodel"
    path.write_bytes(content)
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))
        assert any("suspicious" in i.message.lower() for i in result.issues)


def test_paddle_scanner_missing_dependency(tmp_path):
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"dummy")
    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", False):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))
        assert not result.success
        assert any("paddlepaddle" in i.message for i in result.issues)
        # Find the paddlepaddle-related issue specifically
        paddle_issues = [i for i in result.issues if "paddlepaddle" in i.message]
        assert len(paddle_issues) > 0
        # Missing optional dependency is WARNING severity
        assert paddle_issues[0].severity == IssueSeverity.WARNING


# ---- Tests for false-positive fixes ----


def test_pdiparams_hex_escape_not_flagged(tmp_path):
    """Raw float32 tensor data in .pdiparams should NOT trigger the hex-escape
    pattern (\\x[0-9a-fA-F]{2}).  Before the fix every .pdiparams file was
    flagged because lossy UTF-8 decoding of float bytes produces \\xNN runs."""
    # Build a payload of 1024 random-looking float32 values whose byte
    # representation, when decoded with errors="ignore", will contain
    # sequences that match \\x[0-9a-fA-F]{2}.
    import random

    random.seed(42)
    floats = [random.uniform(-1e6, 1e6) for _ in range(1024)]
    raw = struct.pack(f"<{len(floats)}f", *floats)

    path = tmp_path / "weights.pdiparams"
    path.write_bytes(raw)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    hex_issues = [
        i for i in result.issues if "\\x[0-9a-fA-F]{2}" in i.details.get("pattern", "")
    ]
    assert hex_issues == [], (
        f"Hex-escape pattern should be suppressed for .pdiparams, got {hex_issues}"
    )


def test_pdiparams_dunder_pattern_not_flagged(tmp_path):
    """The __[\\w]+__ (magic-method) regex should be suppressed for .pdiparams
    files because random binary data decoded as UTF-8 can coincidentally match."""
    raw = b"\x00__fake__\x00" + b"\xff" * 200
    path = tmp_path / "weights.pdiparams"
    path.write_bytes(raw)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    dunder_issues = [
        i for i in result.issues if "__[\\w]+__" in i.details.get("pattern", "")
    ]
    assert dunder_issues == [], (
        f"Dunder pattern should be suppressed for .pdiparams, got {dunder_issues}"
    )


def test_pdiparams_real_threats_still_detected(tmp_path):
    """Even with FP suppression, genuinely suspicious content in a .pdiparams
    file (e.g. 'import os', 'eval(') must still be reported."""
    content = b"padding " + b"import os" + b" eval(payload) " + b"os.system('rm -rf /')"
    path = tmp_path / "bad_weights.pdiparams"
    path.write_bytes(content)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    patterns_found = {i.details.get("pattern", "") for i in result.issues}
    # These should NOT be suppressed
    assert any("import os" in p for p in patterns_found), "import os should be detected"
    assert any("eval(" in p for p in patterns_found), "eval( should be detected"
    assert any("os.system" in p for p in patterns_found), "os.system should be detected"


def test_pdmodel_hex_escape_still_flagged(tmp_path):
    """For .pdmodel files (protobuf model descriptors), the hex-escape pattern
    should NOT be suppressed -- only .pdiparams gets the suppression."""
    # Craft content that contains a literal hex escape sequence in text form
    content = b"normal protobuf data \\x41\\x42 more data"
    path = tmp_path / "model.pdmodel"
    path.write_bytes(content)

    with patch("modelaudit.scanners.paddle_scanner.HAS_PADDLE", True):
        scanner = PaddleScanner()
        result = scanner.scan(str(path))

    hex_issues = [
        i for i in result.issues if "\\x[0-9a-fA-F]{2}" in i.details.get("pattern", "")
    ]
    assert len(hex_issues) > 0, "Hex-escape pattern should still fire for .pdmodel files"


def test_pdmodel_magic_bytes_validation_passes(tmp_path):
    """A .pdmodel file should pass file-type validation even though it has no
    distinctive magic bytes (protobuf files start with arbitrary field tags)."""
    # Write some plausible protobuf-like bytes
    path = tmp_path / "model.pdmodel"
    path.write_bytes(b"\x08\x01\x12\x0asome_data_here_for_testing")

    assert validate_file_type(str(path)), (
        ".pdmodel should pass file type validation (no magic byte mismatch)"
    )


def test_pdiparams_magic_bytes_validation_passes(tmp_path):
    """A .pdiparams file should pass file-type validation even though its raw
    tensor data has no recognisable magic bytes."""
    path = tmp_path / "weights.pdiparams"
    # Write raw float data (no recognisable magic bytes)
    path.write_bytes(struct.pack("<4f", 1.0, -2.5, 3.14, 0.0))

    assert validate_file_type(str(path)), (
        ".pdiparams should pass file type validation (no magic byte mismatch)"
    )
