"""Tests for SkopsScanner covering CVE-2025-54412, CVE-2025-54413, CVE-2025-54886."""

import builtins
import os
import stat
import textwrap
import zipfile
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.models import ModelAuditResultModel
from modelaudit.scanners import zip_scanner as zip_scanner_module
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.skops_scanner import SkopsScanner

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "samples")


def _make_numeric_npy(element_count: int = 64) -> bytes:
    header = f"{{'descr': '<f8', 'fortran_order': False, 'shape': ({element_count},), }}"
    header_bytes = header.encode("latin1")
    header_len = len(header_bytes) + 1
    padding_len = (16 - ((10 + header_len) % 16)) % 16
    padded_header = header_bytes + (b" " * padding_len) + b"\n"
    return (
        b"\x93NUMPY\x01\x00"
        + len(padded_header).to_bytes(2, "little")
        + padded_header
        + (b"\x00" * (element_count * 8))
    )


def _scan_twice_with_cache(
    path: Path,
    cache_dir: Path,
    *,
    max_files_in_archive: int | None = None,
    max_skops_file_size: int | None = None,
    max_zip_entry_read_size: int | None = None,
) -> tuple[ModelAuditResultModel, ModelAuditResultModel]:
    scan_kwargs: dict[str, Any] = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }
    if max_files_in_archive is not None:
        scan_kwargs["max_files_in_archive"] = max_files_in_archive
    if max_skops_file_size is not None:
        scan_kwargs["max_skops_file_size"] = max_skops_file_size
    if max_zip_entry_read_size is not None:
        scan_kwargs["max_zip_entry_read_size"] = max_zip_entry_read_size

    first = scan_model_directory_or_file(str(path), **scan_kwargs)
    second = scan_model_directory_or_file(str(path), **scan_kwargs)
    return first, second


def _assert_inconclusive_reason(metadata: Any, reason: str) -> None:
    assert metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert reason in metadata.get("scan_outcome_reasons", [])


def test_protocol_probe_reuses_lowered_member_names() -> None:
    """Keep ZIP member normalization linear while probing large archives."""

    class CountingMemberName(str):
        lower_calls = 0

        def lower(self) -> str:
            self.lower_calls += 1
            return super().lower()

    class FakeZipFile:
        def __init__(self, member_name: str) -> None:
            self.member_name = member_name

        def namelist(self) -> list[str]:
            return [self.member_name]

    member_name = CountingMemberName("archive/member.txt")

    SkopsScanner()._check_protocol_version(
        FakeZipFile(member_name),  # type: ignore[arg-type]
        ScanResult(scanner_name="skops"),
        "model.skops",
    )

    assert member_name.lower_calls == 1


class TestSkopsScannerCanHandle:
    """Test the can_handle method."""

    def test_can_handle_skops_extension(self, tmp_path: Path) -> None:
        """Test that scanner handles .skops files."""
        skops_file = tmp_path / "model.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')

        assert SkopsScanner.can_handle(str(skops_file)) is True

    def test_cannot_handle_non_skops_extension(self, tmp_path: Path) -> None:
        """Test that scanner rejects non-.skops files."""
        other_file = tmp_path / "model.pkl"
        other_file.write_bytes(b"not a skops file")

        assert SkopsScanner.can_handle(str(other_file)) is False

    def test_cannot_handle_nonexistent_file(self) -> None:
        """Test that scanner rejects nonexistent files."""
        assert SkopsScanner.can_handle("/nonexistent/path/model.skops") is False

    def test_cannot_handle_directory(self, tmp_path: Path) -> None:
        """Test that scanner rejects directories."""
        skops_dir = tmp_path / "model.skops"
        skops_dir.mkdir()

        assert SkopsScanner.can_handle(str(skops_dir)) is False


class TestSkopsScannerCVE2025_54412:
    """Test CVE-2025-54412: OperatorFuncNode trusted-type confusion detection."""

    def test_detects_malicious_operatorfuncnode_loader(self, tmp_path: Path) -> None:
        """OperatorFuncNode nodes outside the operator module should be detected."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(
                "schema.json",
                '{"__loader__": "OperatorFuncNode", "__module__": "builtins", "__class__": "eval"}',
            )

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_reduce_pattern_no_false_positive(self, tmp_path: Path) -> None:
        """Test that __reduce__ filenames do NOT trigger CVE-2025-54412.

        __reduce__ is a standard Python serialization method used by ALL
        sklearn Cython types (e.g. sklearn.tree._tree.Tree).  It was
        intentionally removed from CVE-2025-54412 pattern matching to
        prevent false positives on legitimate models.
        """
        skops_file = tmp_path / "legitimate.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("__reduce__payload.bin", b"malicious content")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        # __reduce__ alone should NOT trigger CVE-2025-54412
        failed = [c for c in cve_checks if c.status == CheckStatus.FAILED]
        assert len(failed) == 0

    def test_no_false_positive_clean_file(self, tmp_path: Path) -> None:
        """Test that clean skops files don't trigger CVE-2025-54412."""
        skops_file = tmp_path / "clean.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("model.bin", b"model weights")
            zf.writestr("metadata.json", '{"name": "clean_model"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_54412_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        # Should not have any CVE-2025-54412 failed checks
        failed = [c for c in cve_54412_checks if c.status == CheckStatus.FAILED]
        assert len(failed) == 0

    def test_valid_operatorfuncnode_loader_is_not_flagged(self, tmp_path: Path) -> None:
        """Legitimate operator helper nodes are part of normal Skops schemas."""
        skops_file = tmp_path / "benign_operator.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(
                "schema.json",
                '{"__loader__": "OperatorFuncNode", "__module__": "operator", "__class__": "methodcaller"}',
            )

        result = SkopsScanner().scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name]
        assert not [c for c in cve_checks if c.status == CheckStatus.FAILED]


class TestSkopsScannerCVE2025_54413:
    """Test CVE-2025-54413: MethodNode inconsistency detection."""

    def test_detects_malicious_methodnode_loader(self, tmp_path: Path) -> None:
        """MethodNode nodes whose wrapped object type disagrees should be detected."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(
                "schema.json",
                (
                    '{"__loader__": "MethodNode", "__module__": "builtins", "__class__": "str", '
                    '"content": {"obj": {"__module__": "os", "__class__": "system"}}}'
                ),
            )

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_getattr_filename_without_methodnode_loader_is_not_flagged(self, tmp_path: Path) -> None:
        """Plain filenames should not stand in for structured MethodNode entries."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("__getattr__hook.py", "malicious code")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert not [c for c in cve_checks if c.status == CheckStatus.FAILED]

    def test_valid_methodnode_loader_is_not_flagged(self, tmp_path: Path) -> None:
        """Legitimate bound-method nodes keep their wrapped object type aligned."""
        skops_file = tmp_path / "benign_method.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(
                "schema.json",
                (
                    '{"__loader__": "MethodNode", "__module__": "sklearn.preprocessing", '
                    '"__class__": "FunctionTransformer", "content": {"obj": {'
                    '"__module__": "sklearn.preprocessing", "__class__": "FunctionTransformer"}}}'
                ),
            )

        result = SkopsScanner().scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54413" in c.name]
        assert not [c for c in cve_checks if c.status == CheckStatus.FAILED]


class TestSkopsScannerCVE2025_54886:
    """Test CVE-2025-54886: Card.get_model silent joblib fallback detection."""

    def test_detects_card_with_get_model(self, tmp_path: Path) -> None:
        """Test detection of Card.get_model with joblib references."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            card_content = textwrap.dedent(
                """
                # Model Card
                This model uses get_model() to load the model.
                Fallback to joblib for compatibility.
                """
            ).strip()
            zf.writestr("model_card.md", card_content)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2025-54886" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_detects_readme_with_joblib(self, tmp_path: Path) -> None:
        """Test detection of README with joblib fallback pattern."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            readme_content = textwrap.dedent(
                """
                # Model README
                Load the model using joblib.load() if skops fails.
                """
            ).strip()
            zf.writestr("README.md", readme_content)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is False
        cve_checks = [c for c in result.checks if "CVE-2025-54886" in c.name]
        assert len(cve_checks) > 0
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.CRITICAL

    def test_download_text_in_readme_is_not_cve_54886(self, tmp_path: Path) -> None:
        """Benign README prose containing 'download' must not trigger CVE-2025-54886."""
        skops_file = tmp_path / "benign_readme.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("README.md", "# Model Card\nDownload this safe model from the release page.\n")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is True
        cve_checks = [c for c in result.checks if "CVE-2025-54886" in c.name and c.status == CheckStatus.FAILED]
        assert len(cve_checks) == 0


class TestSkopsScannerJoblibFallback:
    """Test unsafe joblib fallback detection."""

    def test_detects_joblib_load_pattern(self, tmp_path: Path) -> None:
        """Test detection of joblib.load patterns in file content."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("model.pkl", b"joblib.load(model_path)")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name]
        assert len(joblib_checks) > 0
        assert joblib_checks[0].status == CheckStatus.FAILED
        assert joblib_checks[0].severity == IssueSeverity.WARNING

    def test_detects_pickle_load_pattern(self, tmp_path: Path) -> None:
        """Test detection of pickle.load patterns."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("loader.py", b"import pickle\npickle.load(f)")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name]
        assert len(joblib_checks) > 0
        assert joblib_checks[0].status == CheckStatus.FAILED
        assert joblib_checks[0].severity == IssueSeverity.WARNING

    def test_no_false_positive_sklearn_in_schema_json(self, tmp_path: Path) -> None:
        """Regression: schema.json with sklearn type refs must NOT trigger joblib fallback.

        Real .skops files contain a schema.json that references sklearn module
        paths (e.g. "sklearn.linear_model.LogisticRegression"). These are type
        schema references, not pickle/joblib deserialization code.
        """
        skops_file = tmp_path / "legit.skops"
        schema_content = (
            '{"__class__": "sklearn.linear_model._logistic.LogisticRegression",'
            ' "__module__": "sklearn.linear_model._logistic",'
            ' "content": {"C": {"__class__": "float", "content": 1.0}}}'
        )
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", schema_content)
            zf.writestr("step/0/content/0.npy", b"\x93NUMPY\x01\x00model data")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name and c.status == CheckStatus.FAILED]
        assert len(joblib_checks) == 0, (
            f"False positive: schema.json triggered Unsafe Joblib Fallback Detection: {joblib_checks}"
        )

    def test_no_false_positive_sklearn_in_schema_bare(self, tmp_path: Path) -> None:
        """Regression: bare 'schema' file (no .json ext) must also be excluded.

        Some skops archives use a file named just ``schema`` without the
        ``.json`` extension.  The metadata exclusion must cover both variants.
        """
        skops_file = tmp_path / "legit_bare.skops"
        schema_content = (
            '{"__class__": "sklearn.ensemble._forest.RandomForestClassifier",'
            ' "__module__": "sklearn.ensemble._forest",'
            ' "content": {"n_estimators": {"__class__": "int", "content": 100}}}'
        )
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema", schema_content)
            zf.writestr("step/0/content/0.npy", b"\x93NUMPY\x01\x00model data")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name and c.status == CheckStatus.FAILED]
        assert len(joblib_checks) == 0, (
            f"False positive: bare 'schema' file triggered Unsafe Joblib Fallback Detection: {joblib_checks}"
        )

    def test_sklearn_in_data_file_still_detected(self, tmp_path: Path) -> None:
        """Ensure sklearn references in non-metadata files are still flagged."""
        skops_file = tmp_path / "suspicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            # sklearn reference in a data file IS suspicious
            zf.writestr("payload.bin", b"import sklearn; sklearn.externals.joblib.load(f)")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        joblib_checks = [c for c in result.checks if "Joblib" in c.name and c.status == CheckStatus.FAILED]
        assert len(joblib_checks) > 0, "sklearn in a data file should still be flagged"


class TestSkopsScannerEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_empty_archive(self, tmp_path: Path) -> None:
        """Test handling of empty ZIP archive."""
        skops_file = tmp_path / "empty.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            pass  # Create empty archive

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should complete without error
        assert result.success is True

    def test_handles_corrupted_file(self, tmp_path: Path) -> None:
        """Test handling of corrupted/non-ZIP file."""
        skops_file = tmp_path / "corrupted.skops"
        skops_file.write_bytes(b"not a valid zip file content")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is False
        _assert_inconclusive_reason(result.metadata, "skops_not_zip_archive")
        format_checks = [c for c in result.checks if c.name == "Skops File Format Check"]
        assert len(format_checks) > 0

    def test_handles_deeply_nested_files(self, tmp_path: Path) -> None:
        """Test handling of deeply nested file paths."""
        skops_file = tmp_path / "nested.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            deep_path = "/".join(["dir"] * 10) + "/model.bin"
            zf.writestr(deep_path, b"model data")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should complete without error
        assert result.success is True

    def test_handles_unicode_filenames(self, tmp_path: Path) -> None:
        """Test handling of unicode characters in filenames."""
        skops_file = tmp_path / "unicode.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("模型_data.json", '{"name": "test"}')
            zf.writestr("données_modèle.bin", b"model data")
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        # Should complete without error
        assert result.success is True

    def test_handles_decompression_bomb(self, tmp_path: Path) -> None:
        """Test that archives exceeding max file count are rejected."""
        skops_file = tmp_path / "bomb.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.bin", b"data")

        scanner = SkopsScanner(config={"max_files_in_archive": 5})
        result = scanner.scan(str(skops_file))

        assert result.success is False
        _assert_inconclusive_reason(result.metadata, "skops_archive_file_count_limited")
        bomb_checks = [c for c in result.checks if "Archive Bomb" in c.name]
        assert len(bomb_checks) > 0
        assert bomb_checks[0].status == CheckStatus.FAILED

    def test_rejects_archive_exceeding_uncompressed_size_limit(self, tmp_path: Path) -> None:
        """Archive should fail when total uncompressed bytes exceed max_skops_file_size."""
        skops_file = tmp_path / "size_limit.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", "A" * 4096)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner(config={"max_skops_file_size": 2048})
        result = scanner.scan(str(skops_file))

        assert result.success is False
        _assert_inconclusive_reason(result.metadata, "skops_archive_uncompressed_size_limited")
        size_checks = [c for c in result.checks if "Archive Uncompressed Size Limit" in c.name]
        assert len(size_checks) > 0
        assert size_checks[0].status == CheckStatus.FAILED

    @pytest.mark.parametrize(
        ("entry_name", "payload"),
        [
            ("schema.json", b"\xff\xfe\xfd"),
            ("schema", b'{"__loader__": "OperatorFuncNode"'),
        ],
    )
    def test_unparseable_structured_json_marks_scan_incomplete(
        self,
        tmp_path: Path,
        entry_name: str,
        payload: bytes,
    ) -> None:
        """Unreadable loader JSON should fail closed instead of suppressing CVE coverage."""
        skops_file = tmp_path / "unparseable.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(entry_name, payload)

        result = SkopsScanner().scan(str(skops_file))

        assert result.success is False
        _assert_inconclusive_reason(result.metadata, "skops_structured_json_parse_failed")
        parse_checks = [check for check in result.checks if check.name == "Skops Structured JSON Parse Check"]
        assert len(parse_checks) == 1
        assert parse_checks[0].status == CheckStatus.FAILED
        assert parse_checks[0].severity == IssueSeverity.INFO
        assert parse_checks[0].details["entry"] == entry_name
        cache_dir = tmp_path / "parse-cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(skops_file, cache_dir)
            for aggregate in (first, second):
                metadata = aggregate.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_structured_json_parse_failed")
                assert determine_exit_code(aggregate) == 2
            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
        finally:
            reset_cache_manager()

    @pytest.mark.parametrize(
        ("loader_name", "payload"),
        [
            (
                "OperatorFuncNode",
                b'\xef\xbb\xbf{"__loader__":"OperatorFuncNode","__module__":"builtins","__class__":"eval"}',
            ),
            (
                "MethodNode",
                (
                    '{"__loader__":"MethodNode","__module__":"builtins","__class__":"str",'
                    '"content":{"obj":{"__module__":"os","__class__":"system"}}}'
                ).encode("utf-16"),
            ),
        ],
    )
    def test_structured_loader_detection_matches_json_bytes_encodings(
        self,
        tmp_path: Path,
        loader_name: str,
        payload: bytes,
    ) -> None:
        """Loader detection should follow json.loads(bytes) encoding support."""
        skops_file = tmp_path / "encoded_loader.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", payload)

        result = SkopsScanner().scan(str(skops_file))

        cve_name = "CVE-2025-54412" if loader_name == "OperatorFuncNode" else "CVE-2025-54413"
        assert any(
            check.name == f"{cve_name} Detection" and check.status == CheckStatus.FAILED for check in result.checks
        )

    def test_non_schema_json_parse_failures_do_not_mark_scan_incomplete(self, tmp_path: Path) -> None:
        """Auxiliary JSON members are not authoritative Skops metadata."""
        skops_file = tmp_path / "auxiliary_json.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("metadata.json", b'{"broken":')

        result = SkopsScanner().scan(str(skops_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata

    def test_oversized_readme_entry_marks_scan_incomplete(self, tmp_path: Path) -> None:
        """Oversized archive entries should fail closed when bounded reads skip them."""
        skops_file = tmp_path / "oversized_readme.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", "get_model via joblib.load" * 512)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner(config={"max_zip_entry_read_size": 128, "max_skops_file_size": 10 * 1024 * 1024})
        result = scanner.scan(str(skops_file))

        assert result.success is False
        _assert_inconclusive_reason(result.metadata, "skops_zip_entry_size_limited")
        oversized_checks = [c for c in result.checks if c.name == "Skops Oversized ZIP Entry"]
        assert len(oversized_checks) == 1
        assert oversized_checks[0].severity == IssueSeverity.INFO
        assert oversized_checks[0].details["entry"] == "README.md"
        cve_checks = [c for c in result.checks if "CVE-2025-54886" in c.name and c.status == CheckStatus.FAILED]
        assert len(cve_checks) == 0

    def test_oversized_numpy_payload_does_not_mark_skops_incomplete(self, tmp_path: Path) -> None:
        """Large Skops numeric arrays are covered by nested scanners, not Skops CVE text matching."""
        skops_file = tmp_path / "oversized_array.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("step/0/content/0.npy", _make_numeric_npy())

        scanner = SkopsScanner(config={"max_zip_entry_read_size": 128, "max_skops_file_size": 10 * 1024 * 1024})
        result = scanner.scan(str(skops_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        oversized_checks = [c for c in result.checks if c.name == "Skops Oversized ZIP Entry"]
        assert len(oversized_checks) == 0

    def test_unreadable_numpy_payload_marks_skops_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unreadable numeric payload has no nested coverage and must fail closed."""
        skops_file = tmp_path / "unreadable_array.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("step/0/content/0.npy", _make_numeric_npy())

        original_open = zipfile.ZipFile.open

        def open_with_failure(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            if isinstance(name, zipfile.ZipInfo) and name.filename == "step/0/content/0.npy":
                raise zipfile.BadZipFile("CRC mismatch")
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_read_failed")
        assert "_known_unreadable_archive_entry_offsets" not in metadata
        assert not any("Error scanning ZIP entry step/0/content/0.npy" in issue.message for issue in result.issues)
        assert determine_exit_code(result) == 2

    def test_detected_cve_before_oversized_entry_preserves_security_exit_code(self, tmp_path: Path) -> None:
        """Observed CVE payloads remain findings even when later coverage is bounded."""
        skops_file = tmp_path / "detected_before_oversized_entry.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "schema.json",
                '{"__loader__":"OperatorFuncNode","__module__":"builtins","__class__":"eval"}',
            )
            zf.writestr("README.md", "ordinary documentation " * 512)

        result = scan_model_directory_or_file(
            str(skops_file),
            cache_enabled=False,
            max_zip_entry_read_size=128,
            max_skops_file_size=10 * 1024 * 1024,
        )

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_size_limited")
        assert any("CVE-2025-54412" in str(issue.message) for issue in result.issues)
        assert determine_exit_code(result) == 1

    def test_oversized_entry_diagnostic_is_emitted_once(self, tmp_path: Path) -> None:
        """Repeated detector passes over one oversized member should emit one incomplete diagnostic."""
        skops_file = tmp_path / "oversized_methodnode.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("payload.bin", "MethodNode __getattr__" * 512)
            zf.writestr("schema.json", '{"version": "1.0"}')

        scanner = SkopsScanner(config={"max_zip_entry_read_size": 128, "max_skops_file_size": 10 * 1024 * 1024})
        result = scanner.scan(str(skops_file))

        oversized_checks = [c for c in result.checks if c.name == "Skops Oversized ZIP Entry"]
        assert len(oversized_checks) == 1
        assert oversized_checks[0].severity == IssueSeverity.INFO
        assert oversized_checks[0].details["entry"] == "payload.bin"
        assert result.success is False
        assert result.metadata["oversized_zip_entries"] == ["payload.bin"]

    def test_oversized_executable_member_is_still_checked_by_nested_scanner(self, tmp_path: Path) -> None:
        """A Skops detector read limit must not suppress a generic security finding."""
        skops_file = tmp_path / "oversized_executable_member.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("bin/run.sh", "#!/bin/sh\n" + ("echo hidden\n" * 32))

        result = scan_model_directory_or_file(
            str(skops_file),
            cache_enabled=False,
            max_zip_entry_read_size=128,
            max_skops_file_size=10 * 1024 * 1024,
        )

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_size_limited")
        assert any(
            issue.severity == IssueSeverity.WARNING
            and issue.message == "Executable file found in ZIP archive: bin/run.sh"
            and issue.details.get("entry") == "bin/run.sh"
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    def test_python_member_getattribute_high_risk_call_is_reported(self, tmp_path: Path) -> None:
        """Skops nested ZIP analysis must catch active code recovered through __getattribute__."""
        skops_file = tmp_path / "getattribute_payload.skops"
        source = "import os\nresolve = os.__getattribute__\nrunner = resolve('sys' + 'tem')\nrunner('echo hidden')\n"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("handler.py", source)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        python_issues = [
            issue
            for issue in result.issues
            if issue.message == "High-risk Python code found in ZIP member handler.py: high-risk calls: os.system"
            and issue.details.get("entry") == "handler.py"
            and issue.details.get("reason") == "high-risk calls: os.system"
        ]
        assert len(python_issues) == 1
        assert python_issues[0].severity == IssueSeverity.WARNING
        assert determine_exit_code(result) == 1

    def test_python_member_benign_getattribute_remains_quiet(self, tmp_path: Path) -> None:
        """Benign attribute retrieval in Skops Python members should not become a finding."""
        skops_file = tmp_path / "benign_getattribute.skops"
        source = "import os\nresolve = os.__getattribute__\ncurrent_dir = resolve('getcwd')\ncurrent_dir()\n"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("handler.py", source)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        assert determine_exit_code(result) == 0
        assert not any(
            issue.message.startswith("High-risk Python code found in ZIP member handler.py") for issue in result.issues
        )

    @pytest.mark.parametrize(
        ("exception_type", "message"),
        [
            (zipfile.BadZipFile, "CRC mismatch"),
            (NotImplementedError, "unsupported compression method"),
        ],
    )
    def test_unreadable_entry_core_exits_two_and_avoids_cache_reuse(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        exception_type: type[Exception],
        message: str,
    ) -> None:
        """Member read failures are unavailable coverage, not observed vulnerabilities."""
        skops_file = tmp_path / "unreadable_readme.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("README.md", "ordinary documentation")

        original_open = zipfile.ZipFile.open

        def open_with_failure(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            filename = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if filename == "README.md":
                raise exception_type(message)
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

        cache_dir = tmp_path / f"unreadable-cache-{exception_type.__name__}"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(skops_file, cache_dir)
            for aggregate in (first, second):
                metadata = aggregate.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_zip_entry_read_failed")
                assert determine_exit_code(aggregate) == 2
                read_issues = [
                    issue for issue in aggregate.issues if "Unable to read ZIP entry README.md" in issue.message
                ]
                assert len(read_issues) == 1
                assert read_issues[0].severity == IssueSeverity.INFO
                assert not any("Error scanning ZIP entry README.md" in issue.message for issue in aggregate.issues)
            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
            assert stats["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_unreadable_executable_member_name_remains_a_security_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Skipping duplicate reads must not suppress an executable-name signal."""
        skops_file = tmp_path / "unreadable_executable.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("bin/run.sh", "#!/bin/sh\necho hidden\n")

        original_open = zipfile.ZipFile.open

        def open_with_failure(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            filename = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if filename == "bin/run.sh":
                raise zipfile.BadZipFile("CRC mismatch")
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_read_failed")
        assert any(
            issue.severity == IssueSeverity.WARNING
            and issue.message == "Executable file found in ZIP archive: bin/run.sh"
            and issue.details.get("entry") == "bin/run.sh"
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    def test_unreadable_member_alias_does_not_suppress_readable_pickle_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unreadable alias must not suppress scanning a distinct readable pickle member."""
        skops_file = tmp_path / "unreadable_alias_payload.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("./payload.pkl", b"unreadable alias")
            zf.writestr("payload.pkl", b'cos\nsystem\n(S"echo pwned"\ntR.')

        original_open = zipfile.ZipFile.open

        def open_with_failure(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            if isinstance(name, zipfile.ZipInfo) and name.filename == "./payload.pkl":
                raise zipfile.BadZipFile("CRC mismatch")
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_read_failed")
        assert "_known_unreadable_archive_entry_offsets" not in metadata
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and ("os.system" in issue.message.lower() or "posix.system" in issue.message.lower())
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    def test_unreadable_symlink_member_remains_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A known unreadable symlink must not be reopened by nested ZIP metadata checks."""
        skops_file = tmp_path / "unreadable_symlink.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            symlink_info = zipfile.ZipInfo("weights_link")
            symlink_info.create_system = 3
            symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(symlink_info, "safe-target.bin")

        original_open = zipfile.ZipFile.open

        def open_with_failure(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            filename = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if filename == "weights_link":
                raise zipfile.BadZipFile("CRC mismatch")
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_read_failed")
        assert not any("Unable to read symlink target" in issue.message for issue in result.issues)
        assert determine_exit_code(result) == 2

    def test_unreadable_symlink_alias_does_not_suppress_readable_escape_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unreadable symlink alias must not suppress a separate escaping symlink."""
        skops_file = tmp_path / "unreadable_symlink_alias.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            unreadable_info = zipfile.ZipInfo("./weights_link")
            unreadable_info.create_system = 3
            unreadable_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(unreadable_info, "safe-target.bin")
            readable_info = zipfile.ZipInfo("weights_link")
            readable_info.create_system = 3
            readable_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(readable_info, "../outside.bin")

        original_open = zipfile.ZipFile.open

        def open_with_failure(
            archive: zipfile.ZipFile,
            name: str | zipfile.ZipInfo,
            mode: str = "r",
            pwd: bytes | None = None,
            *,
            force_zip64: bool = False,
        ) -> Any:
            if isinstance(name, zipfile.ZipInfo) and name.filename == "./weights_link":
                raise zipfile.BadZipFile("CRC mismatch")
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)

        monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)

        result = scan_model_directory_or_file(str(skops_file), cache_enabled=False)

        metadata = result.file_metadata[str(skops_file)]
        _assert_inconclusive_reason(metadata, "skops_zip_entry_read_failed")
        assert "_known_unreadable_archive_entry_offsets" not in metadata
        assert any(
            issue.severity == IssueSeverity.CRITICAL
            and issue.details.get("entry") == "weights_link"
            and "resolves outside extraction directory" in issue.message
            for issue in result.issues
        )
        assert determine_exit_code(result) == 1

    def test_oversized_entry_core_exits_two_and_avoids_cache_reuse(self, tmp_path: Path) -> None:
        """Aggregate scans should preserve fail-closed exit and avoid reusing incomplete outer results."""
        skops_file = tmp_path / "oversized_readme.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", "ordinary model documentation " * 512)
            zf.writestr("schema.json", '{"version": "1.0"}')

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(
                skops_file,
                cache_dir,
                max_zip_entry_read_size=128,
                max_skops_file_size=10 * 1024 * 1024,
            )

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                assert "skops" in result.scanner_names
                metadata = result.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_zip_entry_size_limited")
                assert any("Skipped oversized ZIP entry README.md" in str(issue.message) for issue in result.issues)
                assert not any("Error scanning ZIP entry README.md" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["cache_hits"] == 0
        finally:
            reset_cache_manager()

    def test_archive_file_count_limit_core_exits_two_and_avoids_cache_reuse(self, tmp_path: Path) -> None:
        """Core scans should fail closed and avoid caching when Skops file-count limits stop analysis."""
        skops_file = tmp_path / "too_many_files.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for index in range(6):
                zf.writestr(f"file_{index}.bin", b"data")

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(
                skops_file,
                cache_dir,
                max_files_in_archive=5,
                max_skops_file_size=10 * 1024 * 1024,
            )

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                metadata = result.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_archive_file_count_limited")
                assert any("Archive contains 6 files" in str(issue.message) for issue in result.issues)

            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
            assert stats["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_archive_uncompressed_size_limit_core_exits_two_and_avoids_cache_reuse(self, tmp_path: Path) -> None:
        """Core scans should fail closed and avoid caching when Skops aggregate size limits stop analysis."""
        skops_file = tmp_path / "too_large.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", "A" * 4096)
            zf.writestr("schema.json", '{"version": "1.0"}')

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(
                skops_file,
                cache_dir,
                max_skops_file_size=2048,
            )

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                metadata = result.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_archive_uncompressed_size_limited")
                assert any("uncompressed content exceeds" in str(issue.message) for issue in result.issues)

            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
            assert stats["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_not_zip_core_exits_one_and_avoids_cache_reuse(self, tmp_path: Path) -> None:
        """A non-ZIP .skops path is incomplete Skops coverage, not a cacheable clean result."""
        skops_file = tmp_path / "not_zip.skops"
        skops_file.write_bytes(b"not a zip archive")

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(skops_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 1
                metadata = result.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_not_zip_archive")
                assert any("not a ZIP archive" in str(issue.message) for issue in result.issues)

            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
            assert stats["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_bad_zip_core_exits_two_and_avoids_cache_reuse(self, tmp_path: Path) -> None:
        """A corrupt ZIP-like .skops path should also fail closed and stay uncached."""
        skops_file = tmp_path / "bad_zip.skops"
        skops_file.write_bytes(b"PK\x03\x04not a complete zip")

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(skops_file, cache_dir)

            for result in (first, second):
                assert result.success is False
                assert determine_exit_code(result) == 2
                metadata = result.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_bad_zip_file")
                assert any("Invalid ZIP file" in str(issue.message) for issue in result.issues)

            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
            assert stats["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_unexpected_scan_failure_core_exits_two_and_avoids_cache_reuse(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unexpected scanner failures stay fail closed without becoming findings."""
        skops_file = tmp_path / "unexpected_scan_failure.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')

        def fail_member_scan(
            _self: SkopsScanner,
            _path: str,
            _result: ScanResult,
            archive: zipfile.ZipFile | None = None,
        ) -> None:
            del archive
            raise RuntimeError("unexpected nested scan failure")

        monkeypatch.setattr(SkopsScanner, "_scan_archive_members", fail_member_scan)
        cache_dir = tmp_path / "unexpected-failure-cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(skops_file, cache_dir)
            for aggregate in (first, second):
                metadata = aggregate.file_metadata[str(skops_file)]
                _assert_inconclusive_reason(metadata, "skops_scan_failed")
                assert determine_exit_code(aggregate) == 2
                scan_issues = [issue for issue in aggregate.issues if "Error scanning skops file" in issue.message]
                assert len(scan_issues) == 1
                assert scan_issues[0].severity == IssueSeverity.INFO
            stats = get_cache_manager(str(cache_dir), enabled=True).get_stats()
            assert stats["cache_hits"] == 0
            assert stats["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_recursive_member_scan_reuses_preflighted_archive_after_path_replacement(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        skops_path = tmp_path / "same_descriptor.skops"
        with zipfile.ZipFile(skops_path, "w") as archive:
            archive.writestr("schema.json", '{"version": "1.0"}')
            archive.writestr("safe.txt", "safe")

        replacement_path = tmp_path / "replacement.skops"
        with zipfile.ZipFile(replacement_path, "w") as archive:
            archive.writestr("schema.json", '{"version": "1.0"}')
            archive.writestr("payload.pkl", b'cos\nsystem\n(S"echo replacement"\ntR.')

        original_scan_archive_members = zip_scanner_module.ZipScanner.scan_archive_members
        original_open = builtins.open
        path_reopened = False

        def redirect_path_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal path_reopened
            if str(file) == str(skops_path):
                path_reopened = True
                file = replacement_path
            return original_open(file, *args, **kwargs)

        def replace_then_scan(
            scanner: zip_scanner_module.ZipScanner,
            path: str,
            archive: zipfile.ZipFile | None = None,
        ) -> ScanResult:
            assert archive is not None
            with monkeypatch.context() as path_swap:
                path_swap.setattr(builtins, "open", redirect_path_open)
                return original_scan_archive_members(scanner, path, archive=archive)

        monkeypatch.setattr(zip_scanner_module.ZipScanner, "scan_archive_members", replace_then_scan)

        result = SkopsScanner().scan(str(skops_path))

        assert path_reopened is False
        assert not any(issue.details.get("zip_entry") == "payload.pkl" for issue in result.issues)
        assert any(entry.get("path", "").endswith(":safe.txt") for entry in result.metadata["contents"])
        assert not any(entry.get("path", "").endswith(":payload.pkl") for entry in result.metadata["contents"])

    def test_oversized_numpy_payload_core_exits_zero_and_still_caches(self, tmp_path: Path) -> None:
        """Oversized numeric arrays should not become Skops CVE false positives in aggregate scans."""
        skops_file = tmp_path / "large_array.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("step/0/content/0.npy", _make_numeric_npy())

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(
                skops_file,
                cache_dir,
                max_zip_entry_read_size=128,
                max_skops_file_size=10 * 1024 * 1024,
            )

            for result in (first, second):
                assert result.success is True
                assert determine_exit_code(result) == 0
                metadata = result.file_metadata[str(skops_file)]
                assert "scan_outcome" not in metadata
                assert not any("Skipped oversized ZIP entry" in str(issue.message) for issue in result.issues)

            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["cache_hits"] >= 1
        finally:
            reset_cache_manager()

    def test_small_benign_core_scan_still_caches(self, tmp_path: Path) -> None:
        """Clean Skops scans should still be cacheable."""
        skops_file = tmp_path / "small_benign.skops"
        with zipfile.ZipFile(skops_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("README.md", "normal safe model card")
            zf.writestr("schema.json", '{"version": "1.0"}')

        cache_dir = tmp_path / "cache"
        reset_cache_manager()
        try:
            first, second = _scan_twice_with_cache(
                skops_file,
                cache_dir,
                max_zip_entry_read_size=128,
                max_skops_file_size=10 * 1024 * 1024,
            )

            assert first.success is True
            assert second.success is True
            assert determine_exit_code(first) == 0
            assert determine_exit_code(second) == 0
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["cache_hits"] >= 1
        finally:
            reset_cache_manager()

    def test_counts_embedded_member_bytes(self, tmp_path: Path) -> None:
        """Embedded member scans should contribute to total bytes_scanned."""
        skops_file = tmp_path / "byte_count.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr("schema.json", '{"version": "1.0"}')
            zf.writestr("weights.bin", b"model weights")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is True
        assert result.bytes_scanned > skops_file.stat().st_size


class TestSkopsScannerMultipleCVEs:
    """Test detection of multiple CVEs in a single file."""

    def test_detects_multiple_cves(self, tmp_path: Path) -> None:
        """Test that scanner can detect multiple CVEs in one file."""
        skops_file = tmp_path / "multi_exploit.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(
                "schema.json",
                (
                    '{"items": ['
                    '{"__loader__": "OperatorFuncNode", "__module__": "builtins", "__class__": "eval"},'
                    '{"__loader__": "MethodNode", "__module__": "builtins", "__class__": "str", '
                    '"content": {"obj": {"__module__": "os", "__class__": "system"}}}'
                    "]}"
                ),
            )
            # CVE-2025-54886 pattern
            zf.writestr("model_card.md", "use get_model() with joblib fallback")

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        assert result.success is False
        # Should detect all three CVEs
        cve_54412 = [c for c in result.checks if "CVE-2025-54412" in c.name]
        cve_54413 = [c for c in result.checks if "CVE-2025-54413" in c.name]
        cve_54886 = [c for c in result.checks if "CVE-2025-54886" in c.name]

        assert len(cve_54412) > 0
        assert len(cve_54413) > 0
        assert len(cve_54886) > 0

        # All failed checks should be critical
        all_cve_checks = cve_54412 + cve_54413 + cve_54886
        for check in all_cve_checks:
            if check.status == CheckStatus.FAILED:
                assert check.severity == IssueSeverity.CRITICAL


class TestSkopsScannerCVEDetails:
    """Test that CVE details are properly populated."""

    def test_cve_details_include_required_fields(self, tmp_path: Path) -> None:
        """Test that CVE checks include all required detail fields."""
        skops_file = tmp_path / "malicious.skops"
        with zipfile.ZipFile(skops_file, "w") as zf:
            zf.writestr(
                "schema.json",
                '{"__loader__": "OperatorFuncNode", "__module__": "builtins", "__class__": "eval"}',
            )

        scanner = SkopsScanner()
        result = scanner.scan(str(skops_file))

        cve_checks = [c for c in result.checks if "CVE-2025-54412" in c.name and c.status == CheckStatus.FAILED]
        assert len(cve_checks) > 0

        check = cve_checks[0]
        details = check.details

        # Verify required fields
        assert "cve_id" in details
        assert "cvss" in details
        assert "cwe" in details
        assert "affected_versions" in details
        assert "remediation" in details
        assert "skops < 0.12.0" in details["affected_versions"]
        assert "0.12.0" in details["remediation"]


class TestSkopsScannerRealModel:
    """Integration tests using a real .skops model from HuggingFace."""

    REAL_SKOPS = os.path.join(SAMPLES_DIR, "pipeline.skops")

    @pytest.mark.skipif(
        not os.path.isfile(os.path.join(SAMPLES_DIR, "pipeline.skops")),
        reason="Real .skops sample not available",
    )
    def test_can_handle_real_skops_model(self) -> None:
        """Test that scanner recognises a real .skops file (scikit-learn/persistence)."""
        assert SkopsScanner.can_handle(self.REAL_SKOPS) is True

    @pytest.mark.skipif(
        not os.path.isfile(os.path.join(SAMPLES_DIR, "pipeline.skops")),
        reason="Real .skops sample not available",
    )
    def test_scan_real_skops_model_no_cve_false_positives(self) -> None:
        """Test that a legitimate model doesn't trigger CVE detections."""
        scanner = SkopsScanner()
        result = scanner.scan(self.REAL_SKOPS)

        assert result.success is True

        # No CVE checks should fail on a legitimate model
        cve_failed = [
            c
            for c in result.checks
            if any(cve in c.name for cve in ["CVE-2025-54412", "CVE-2025-54413", "CVE-2025-54886"])
            and c.status == CheckStatus.FAILED
        ]
        assert len(cve_failed) == 0, f"False positive CVE detections: {[c.name for c in cve_failed]}"

    @pytest.mark.skipif(
        not os.path.isfile(os.path.join(SAMPLES_DIR, "pipeline.skops")),
        reason="Real .skops sample not available",
    )
    def test_scan_real_skops_model_metadata(self) -> None:
        """Test that scan metadata is populated for a real model."""
        scanner = SkopsScanner()
        result = scanner.scan(self.REAL_SKOPS)

        assert result.metadata.get("file_size", 0) > 0
        assert result.metadata.get("file_count", 0) > 0
