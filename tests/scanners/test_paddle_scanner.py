from unittest.mock import patch

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.paddle_scanner import PaddleScanner


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
        assert paddle_issues[0].severity == IssueSeverity.CRITICAL
