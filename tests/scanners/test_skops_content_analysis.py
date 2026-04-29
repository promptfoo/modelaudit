"""Tests for SkopsScanner content analysis fix."""

import zipfile
from pathlib import Path

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.skops_scanner import SkopsScanner


class TestSkopsScannerContentAnalysis:
    """Test content-based CVE detection (not just filename patterns)."""

    def test_detects_operatorfuncnode_in_content(self, tmp_path: Path) -> None:
        """Test detection of structured OperatorFuncNode content."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("data.json", '{"__loader__": "OperatorFuncNode"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

        # Verify it detected the structured loader, not a filename.
        details = cve_checks[0].details
        patterns_matched = details.get("patterns_matched", [])
        assert any("loader:" in p for p in patterns_matched)

    def test_detects_methodnode_in_content(self, tmp_path: Path) -> None:
        """Test detection of structured MethodNode content."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("tree.json", '{"__loader__": "MethodNode"}')
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

        # Verify it detected the structured loader, not a filename.
        details = cve_checks[0].details
        patterns_matched = details.get("patterns_matched", [])
        assert any("loader:" in p for p in patterns_matched)

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

    def test_getattr_prose_without_methodnode_loader_is_not_flagged(self, tmp_path: Path) -> None:
        """Plain prose should not stand in for structured MethodNode entries."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("README.md", "This document mentions MethodNode and __getattr__.")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert not [c for c in cve_checks if c.status == CheckStatus.FAILED]

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

    def test_operatorfuncnode_prose_and_filename_without_loader_are_not_flagged(self, tmp_path: Path) -> None:
        """Plain prose and filenames should not stand in for structured loader entries."""
        skops_file = tmp_path / "benign.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("OperatorFuncNode_notes.txt", "OperatorFuncNode is discussed here.")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert not [c for c in cve_checks if c.status == CheckStatus.FAILED]
