"""Tests for SkopsScanner content analysis fix."""

import zipfile
from pathlib import Path

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.skops_scanner import SkopsScanner


class TestSkopsScannerContentAnalysis:
    """Test content-based CVE detection (not just filename patterns)."""

    def test_detects_operatorfuncnode_in_content(self, tmp_path: Path) -> None:
        """Test detection of OperatorFuncNode pattern in file content (not filename)."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            # Pattern is in content, not filename
            zf.writestr("data.json", '{"node_type": "OperatorFuncNode", "func": "eval"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

        # Verify it detected the content pattern, not filename
        details = cve_checks[0].details
        patterns_matched = details.get("patterns_matched", [])
        assert any("content:" in p for p in patterns_matched)

    def test_detects_methodnode_in_content(self, tmp_path: Path) -> None:
        """Test detection of MethodNode pattern in file content (not filename)."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            # Pattern is in content, not filename
            zf.writestr("tree.json", '{"type": "MethodNode", "method": "__getattr__"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

        # Verify it detected the content pattern, not filename
        details = cve_checks[0].details
        patterns_matched = details.get("patterns_matched", [])
        assert any("content:" in p for p in patterns_matched)

    def test_reduce_in_content_not_flagged(self, tmp_path: Path) -> None:
        """__reduce__ is a standard Python serialization method and should NOT trigger CVE-2025-54412."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            # __reduce__ is standard pickle protocol, not specific to CVE-2025-54412
            zf.writestr("object.bin", b'{"method": "__reduce__", "args": ["os.system", "id"]}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name and c.status == CheckStatus.FAILED]
        assert len(cve_checks) == 0

    def test_detects_getattr_in_content(self, tmp_path: Path) -> None:
        """Test detection of __getattr__ pattern in file content."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            # Pattern is in content, not filename
            zf.writestr("hooks.json", '{"hook": "__getattr__", "target": "os"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED

    def test_clean_file_no_content_detection(self, tmp_path: Path) -> None:
        """Test that clean files without malicious content don't trigger."""
        skops_file = tmp_path / "clean.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0", "protocol": "3"}')
            zf.writestr("model.bin", b"\x00\x01\x02\x03 model weights here")
            zf.writestr("metadata.json", '{"name": "clean_model", "type": "sklearn"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should not have any CVE-2025-54412 or CVE-2025-54413 failed checks
        cve_54412 = [c for c in result.checks if "CVE-2025-54412" in c.name and c.status == CheckStatus.FAILED]
        cve_54413 = [c for c in result.checks if "CVE-2025-54413" in c.name and c.status == CheckStatus.FAILED]
        assert len(cve_54412) == 0
        assert len(cve_54413) == 0

    def test_detects_both_filename_and_content(self, tmp_path: Path) -> None:
        """Test that scanner detects patterns in both filename and content."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            # Pattern in filename
            zf.writestr("OperatorFuncNode.json", '{"type": "node"}')
            # OperatorFuncNode pattern in content of a different file
            zf.writestr("data.json", '{"node_type": "OperatorFuncNode", "func": "exec"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert len(cve_checks) > 0

        # Should detect both filename and content patterns
        details = cve_checks[0].details
        patterns_matched = details.get("patterns_matched", [])
        has_filename = any("filename:" in p for p in patterns_matched)
        has_content = any("content:" in p for p in patterns_matched)
        assert has_filename, f"Expected filename pattern, got: {patterns_matched}"
        assert has_content, f"Expected content pattern, got: {patterns_matched}"
