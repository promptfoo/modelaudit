import errno
import json
import os
import pickle
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from modelaudit import core as core_module
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.models import create_initial_audit_result
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, Check, CheckStatus, Issue, IssueSeverity, ScanResult
from modelaudit.utils.sources.dvc import (
    DVC_ANALYSIS_INCOMPLETE_REASON,
    DVC_OUTPUT_LIMIT_EXCEEDED_REASON,
    DVC_POINTER_TOO_LARGE_REASON,
    MAX_DVC_POINTER_BYTES,
    DvcResolution,
    dvc_omitted_outputs_covered,
    resolve_dvc_file,
    resolve_dvc_file_status,
    resolve_dvc_file_with_metadata,
)


class _LateMaliciousPayload:
    def __reduce__(self) -> tuple[Callable[[str], int], tuple[str]]:
        return (os.system, ("echo c085",))


def _write_incomplete_png_payload(path: Path) -> None:
    png_header = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (b"\x00" * 32)
    path.write_bytes(png_header + (b"\x00" * (100_000 - len(png_header))))


def _patch_metadata_only_incomplete_scan(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    *,
    reason: str = "synthetic_metadata_only_incomplete",
) -> None:
    original_scan_file = core_module.scan_file

    def patched_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        if Path(path).name != filename:
            return original_scan_file(path, config)

        result = ScanResult(scanner_name="synthetic_incomplete")
        result.bytes_scanned = Path(path).stat().st_size
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = [reason]
        return result

    monkeypatch.setattr(core_module, "scan_file", patched_scan_file)


def _patch_detail_only_incomplete_scan(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    *,
    record_kind: str,
    reason: str = "synthetic_detail_only_incomplete",
    location_suffix: str | None = None,
) -> None:
    original_scan_file = core_module.scan_file

    def patched_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        if Path(path).name != filename:
            return original_scan_file(path, config)

        result = ScanResult(scanner_name="synthetic_incomplete")
        result.bytes_scanned = Path(path).stat().st_size
        details = {"analysis_incomplete": True, "scan_outcome_reason": reason}
        location = f"{path}:{location_suffix}" if location_suffix is not None else path
        if record_kind == "issue":
            result.issues.append(
                Issue(
                    message="Synthetic issue-only incomplete coverage",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details=details,
                    type="synthetic_incomplete_coverage",
                )
            )
        elif record_kind == "check":
            result.checks.append(
                Check(
                    name="Synthetic Detail Coverage",
                    status=CheckStatus.FAILED,
                    message="Synthetic check-only incomplete coverage",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details=details,
                )
            )
        else:
            raise AssertionError(f"unsupported record kind: {record_kind}")
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "scan_file", patched_scan_file)


def _patch_issue_only_incomplete_scan(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    *,
    reason: str = "synthetic_issue_only_incomplete",
) -> None:
    original_scan_file = core_module.scan_file

    def patched_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        if Path(path).name != filename:
            return original_scan_file(path, config)

        result = ScanResult(scanner_name="synthetic_incomplete")
        result.bytes_scanned = Path(path).stat().st_size
        result.add_issue(
            "Synthetic scan retained incomplete coverage only in issue details",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": reason,
            },
        )
        return result

    monkeypatch.setattr(core_module, "scan_file", patched_scan_file)


def _patch_clean_detail_scan(monkeypatch: pytest.MonkeyPatch, filename: str) -> None:
    original_scan_file = core_module.scan_file

    def patched_scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        if Path(path).name != filename:
            return original_scan_file(path, config)

        result = ScanResult(scanner_name="synthetic_clean")
        result.bytes_scanned = Path(path).stat().st_size
        result.checks.append(
            Check(
                name="Synthetic Clean Coverage",
                status=CheckStatus.PASSED,
                message="Synthetic clean sibling coverage",
                details={"scan_outcome_reason": "", "scan_outcome_reasons": []},
            )
        )
        result.finish(success=True)
        return result

    monkeypatch.setattr(core_module, "scan_file", patched_scan_file)


class TestDvcIntegration:
    """Test DVC integration functionality."""

    def test_resolve_dvc_file_basic(self, tmp_path):
        """Test basic DVC file resolution."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"a": 1}, f)

        dvc_file = tmp_path / "model.pkl.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")

        resolved = resolve_dvc_file(str(dvc_file))
        assert resolved == [str(target)]

    def test_scan_dvc_pointer(self, tmp_path):
        """Test scanning through DVC pointer files."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"b": 2}, f)

        dvc_file = tmp_path / "model.pkl.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")

        results = scan_model_directory_or_file(str(dvc_file))
        assert results["files_scanned"] == 1
        assert any(target.name in asset["path"] for asset in results["assets"])

    def test_directory_scan_expands_dvc(self, tmp_path):
        """Test that directory scans expand DVC files to their targets."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"c": 3}, f)

        dvc_file = tmp_path / "model.pkl.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results["files_scanned"] == 1
        assert any(target.name in asset["path"] for asset in results["assets"])

    def test_resolve_multiple_outputs(self, tmp_path):
        """Test DVC file with multiple outputs."""
        # Create multiple targets
        targets = []
        for i in range(3):
            target = tmp_path / f"model_{i}.pkl"
            with target.open("wb") as f:
                pickle.dump({"data": i}, f)
            targets.append(target)

        # Create DVC file with multiple outputs
        dvc_content = "outs:\n"
        for target in targets:
            dvc_content += f"- path: {target.name}\n"

        dvc_file = tmp_path / "multi_model.dvc"
        dvc_file.write_text(dvc_content)

        resolved = resolve_dvc_file(str(dvc_file))
        assert len(resolved) == 3
        for target in targets:
            assert str(target) in resolved

    def test_resolve_subdirectory_outputs(self, tmp_path):
        """Test DVC file with outputs in subdirectories."""
        # Create subdirectory
        sub_dir = tmp_path / "models"
        sub_dir.mkdir()

        target = sub_dir / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"nested": True}, f)

        dvc_file = tmp_path / "nested.dvc"
        dvc_file.write_text("outs:\n- path: models/model.pkl\n")

        resolved = resolve_dvc_file(str(dvc_file))
        assert resolved == [str(target)]

    def test_missing_targets_ignored(self, tmp_path):
        """Test that missing targets are ignored gracefully."""
        # Create one existing target
        existing = tmp_path / "existing.pkl"
        with existing.open("wb") as f:
            pickle.dump({"exists": True}, f)

        dvc_file = tmp_path / "partial.dvc"
        dvc_file.write_text("""outs:
- path: existing.pkl
- path: missing.pkl
- path: also_missing.txt
""")

        resolved = resolve_dvc_file(str(dvc_file))
        assert resolved == [str(existing)]

    def test_missing_dvc_outputs_mark_scan_incomplete_with_resolved_target(self, tmp_path: Path) -> None:
        """Missing declared DVC outputs should not be silently dropped."""

        class MaliciousClass:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os

                return (os.system, ("echo dvc-existing-malicious",))

        existing = tmp_path / "existing_malicious.pkl"
        with existing.open("wb") as f:
            pickle.dump(MaliciousClass(), f)

        missing = tmp_path / "hidden_payload.pkl"
        dvc_file = tmp_path / "partial.dvc"
        dvc_file.write_text(f"""outs:
- path: {existing.name}
- path: {missing.name}
""")

        results = scan_model_directory_or_file(str(dvc_file))

        assert results.files_scanned == 1
        assert results.has_errors is True
        assert results.success is False
        assert results.content_hash is None
        assert any("existing_malicious.pkl" in (issue.location or "") for issue in results.issues)

        dvc_issues = [
            issue
            for issue in results.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
        ]
        assert len(dvc_issues) == 1
        assert dvc_issues[0].details["analysis_incomplete"] is True
        assert any("hidden_payload.pkl" in path for path in dvc_issues[0].details["unresolved_outputs"])
        assert any(Path(asset.path).name == existing.name for asset in results.assets)
        assert all(Path(asset.path).name != dvc_file.name for asset in results.assets)

    def test_unresolved_dvc_pointer_does_not_scan_pointer_text_as_clean(self, tmp_path: Path) -> None:
        """A DVC pointer with no resolved outputs should fail closed instead of scanning the pointer."""
        dvc_file = tmp_path / "missing.dvc"
        dvc_file.write_text("""outs:
- path: hidden_payload.pkl
""")

        results = scan_model_directory_or_file(str(dvc_file))

        assert results.files_scanned == 0
        assert results.has_errors is True
        assert results.success is False
        assert all(Path(asset.path).name != dvc_file.name for asset in results.assets)
        assert any(
            issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and any("hidden_payload.pkl" in path for path in issue.details["unresolved_outputs"])
            for issue in results.issues
        )

    def test_directory_scan_marks_missing_dvc_outputs_incomplete(self, tmp_path: Path) -> None:
        """Directory DVC expansion should not hide missing declared outputs."""
        target = tmp_path / "visible.pkl"
        with target.open("wb") as f:
            pickle.dump({"visible": True}, f)

        dvc_file = tmp_path / "partial.dvc"
        dvc_file.write_text("""outs:
- path: visible.pkl
- path: missing.pkl
""")

        results = scan_model_directory_or_file(str(tmp_path))

        assert results.files_scanned == 1
        assert results.has_errors is True
        assert results.success is False
        assert any(Path(asset.path).name == target.name for asset in results.assets)
        assert all(Path(asset.path).name != dvc_file.name for asset in results.assets)
        assert any(
            issue.location == str(dvc_file)
            and issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and any("missing.pkl" in path for path in issue.details["unresolved_outputs"])
            for issue in results.issues
        )

    def test_resolved_dvc_outputs_remain_successful(self, tmp_path: Path) -> None:
        """Fully resolved benign DVC pointers should keep the normal clean path."""
        target = tmp_path / "benign.pkl"
        with target.open("wb") as f:
            pickle.dump({"benign": True}, f)

        dvc_file = tmp_path / "benign.dvc"
        dvc_file.write_text("outs:\n- path: benign.pkl\n")

        results = scan_model_directory_or_file(str(dvc_file))

        assert results.files_scanned == 1
        assert results.has_errors is False
        assert results.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON for issue in results.issues
        )
        assert any(Path(asset.path).name == target.name for asset in results.assets)

    def test_partial_dvc_directory_output_scans_nested_payload(self, tmp_path: Path) -> None:
        """Resolved directories should still be traversed when another output is missing."""

        class MaliciousClass:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os

                return (os.system, ("echo dvc-directory-malicious",))

        output_dir = tmp_path / "model"
        output_dir.mkdir()
        nested_payload = output_dir / "nested.pkl"
        with nested_payload.open("wb") as f:
            pickle.dump(MaliciousClass(), f)

        dvc_file = tmp_path / "partial-directory.dvc"
        dvc_file.write_text("""outs:
- path: model
- path: missing.pkl
""")

        results = scan_model_directory_or_file(str(dvc_file))

        assert results.files_scanned == 1
        assert results.has_errors is True
        assert results.success is False
        assert any(Path(asset.path).name == nested_payload.name for asset in results.assets)
        assert any("nested.pkl" in (issue.location or "") for issue in results.issues)
        assert any(
            issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON for issue in results.issues
        )

    @pytest.mark.parametrize("scan_directory", [False, True])
    def test_unreadable_dvc_directory_subtree_marks_scan_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        scan_directory: bool,
    ) -> None:
        """Walk failures below resolved DVC directories must not look like complete coverage."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        blocked_dir = output_dir / "blocked"
        blocked_dir.mkdir()
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")
        original_walk = os.walk

        def walk_with_denied_subtree(
            top: str,
            topdown: bool = True,
            onerror: Callable[[OSError], None] | None = None,
            followlinks: bool = False,
        ) -> Iterator[tuple[str, list[str], list[str]]]:
            resolved_top = Path(top).resolve()
            if resolved_top == (tmp_path if scan_directory else output_dir).resolve():
                if scan_directory:
                    yield str(tmp_path), [output_dir.name], [dvc_file.name]
                else:
                    yield str(output_dir), [blocked_dir.name], []
                if onerror is not None:
                    onerror(PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(blocked_dir)))
                return
            yield from original_walk(
                top,
                topdown=topdown,
                onerror=onerror,
                followlinks=followlinks,
            )

        monkeypatch.setattr(core_module.os, "walk", walk_with_denied_subtree)

        result = scan_model_directory_or_file(str(tmp_path if scan_directory else dvc_file))
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and issue.details.get("incomplete_reason") == "dvc_directory_walk_failed"
        )

        assert result.files_scanned == 0
        assert result.has_errors is True
        assert result.success is False
        assert result.content_hash is None
        assert str(blocked_dir) in incomplete_issue.details["unresolved_outputs"]

    def test_escaping_dvc_directory_symlink_marks_scan_incomplete(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A linked directory outside the declared output must not be silently skipped."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        payload = outside_dir / "payload.pkl"
        payload.write_bytes(pickle.dumps({"hidden": True}))
        linked_dir = output_dir / "linked"
        linked_dir.symlink_to(outside_dir, target_is_directory=True)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")

        result = scan_model_directory_or_file(str(dvc_file))
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned"
        )

        assert result.files_scanned == 0
        assert result.has_errors is True
        assert result.success is False
        assert result.content_hash is None
        assert str(linked_dir) in incomplete_issue.details["unresolved_outputs"]

    def test_escaping_dvc_directory_junction_marks_scan_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Windows junctions must be pruned and reported like directory symlinks."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        junction_dir = output_dir / "junction"
        junction_dir.mkdir()
        hidden_payload = junction_dir / "hidden.pkl"
        hidden_payload.write_bytes(pickle.dumps({"hidden": True}))
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")
        original_resolve = Path.resolve

        def resolve_simulated_junction(self: Path, *args: Any, **kwargs: Any) -> Path:
            if self == junction_dir:
                return outside_dir
            return original_resolve(self, *args, **kwargs)

        monkeypatch.setattr(Path, "is_junction", lambda self: self == junction_dir, raising=False)
        monkeypatch.setattr(Path, "resolve", resolve_simulated_junction)

        result = scan_model_directory_or_file(str(dvc_file))
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned"
        )

        assert result.files_scanned == 0
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert result.content_hash is None
        assert str(junction_dir) in incomplete_issue.details["unresolved_outputs"]
        assert all(Path(asset.path).name != hidden_payload.name for asset in result.assets)

    def test_non_dvc_symlink_bypasses_dvc_resolution(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Unrelated cache symlinks must stay on the generic symlink-handling path."""
        snapshots = tmp_path / "cache" / "snapshots" / "abc"
        snapshots.mkdir(parents=True)
        broken_link = snapshots / "model.bin"
        broken_link.symlink_to(Path("../../blobs/missing"))

        def resolve_without_dvc_strict(self: Path, *args: Any, **kwargs: Any) -> Path:
            assert kwargs.get("strict") is not True
            return Path(os.path.abspath(self))

        def fail_readlink(path: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> str:
            raise OSError(f"dangling link: {path!r}")

        monkeypatch.setattr(Path, "resolve", resolve_without_dvc_strict)
        monkeypatch.setattr(os, "readlink", fail_readlink)

        result = scan_model_directory_or_file(str(snapshots))

        assert any("broken symlink" in issue.message.lower() for issue in result.issues)

    def test_escaping_dvc_file_symlink_marks_scan_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """A linked file outside the declared output must invalidate coverage and its aggregate hash."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        safe_file = output_dir / "safe.pkl"
        safe_file.write_bytes(pickle.dumps({"safe": True}))
        outside_file = tmp_path / "outside.pkl"
        outside_file.write_bytes(pickle.dumps({"hidden": True}))
        linked_file = output_dir / "linked.pkl"
        linked_file.symlink_to(outside_file)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")
        scanned_paths: list[str] = []

        def fake_scan_file(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned"
        )

        assert scanned_paths == [str(safe_file)]
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert result.content_hash is None
        assert str(linked_file) in incomplete_issue.details["unresolved_outputs"]

    def test_project_scan_marks_dvc_file_symlink_escape_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """A broader project scan must not hide a symlink escape from the declared DVC output."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        safe_file = output_dir / "safe.pkl"
        safe_file.write_bytes(pickle.dumps({"safe": True}))
        outside_file = tmp_path / "outside.pkl"
        outside_file.write_bytes(pickle.dumps({"outside": True}))
        linked_file = output_dir / "linked.pkl"
        linked_file.symlink_to(outside_file)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")
        scanned_paths: list[str] = []

        def fake_scan_file(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned"
        )

        assert set(scanned_paths) == {str(safe_file), str(outside_file)}
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert result.content_hash is None
        assert str(linked_file) in incomplete_issue.details["unresolved_outputs"]

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
    def test_dvc_directory_special_file_marks_scan_incomplete(self, tmp_path: Path) -> None:
        """A model-suffixed FIFO must not reach hashing or scanner dispatch."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        fifo = output_dir / "blocked.pkl"
        os.mkfifo(fifo)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and issue.details.get("incomplete_reason") == "dvc_directory_special_file_unscanned"
        )

        assert result.files_scanned == 0
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert result.content_hash is None
        assert str(fifo) in incomplete_issue.details["unresolved_outputs"]

    def test_internal_dvc_file_symlink_does_not_create_coverage_gap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """An internal file alias remains covered and is scanned only once."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        payload = output_dir / "payload.pkl"
        payload.write_bytes(pickle.dumps({"covered": True}))
        (output_dir / "alias.pkl").symlink_to(payload)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")
        scanned_paths: list[str] = []

        def fake_scan_file(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)

        assert scanned_paths == [str(payload)]
        assert result.has_errors is False
        assert result.success is True
        assert result.content_hash is not None
        assert not any(
            issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned" for issue in result.issues
        )

    def test_dvc_file_symlink_covered_by_another_declared_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """A file alias into another declared output remains covered without duplicate scanning."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        linked_target = tmp_path / "linked-target"
        linked_target.mkdir()
        payload = linked_target / "payload.pkl"
        payload.write_bytes(pickle.dumps({"covered": True}))
        (model_dir / "linked.pkl").symlink_to(payload)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n- path: linked-target\n")
        scanned_paths: list[str] = []

        def fake_scan_file(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)

        assert scanned_paths == [str(payload)]
        assert result.files_scanned == 1
        assert result.has_errors is False
        assert result.success is True
        assert result.content_hash is not None
        assert not any(issue.message == "Path traversal outside scanned directory" for issue in result.issues)
        assert not any(
            issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned" for issue in result.issues
        )

    def test_dvc_file_symlink_covered_by_declared_file_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """A directory symlink to a separately declared file remains covered and scans once."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        payload = tmp_path / "payload.pkl"
        payload.write_bytes(pickle.dumps({"covered": True}))
        (model_dir / "linked.pkl").symlink_to(payload)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n- path: payload.pkl\n")
        scanned_paths: list[str] = []

        def fake_scan_file(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)

        assert scanned_paths == [str(payload)]
        assert result.files_scanned == 1
        assert result.has_errors is False
        assert result.success is True
        assert result.content_hash is not None
        assert not any(issue.message == "Path traversal outside scanned directory" for issue in result.issues)
        assert not any(
            issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned" for issue in result.issues
        )

    def test_dvc_file_symlink_next_to_declared_file_remains_uncovered(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        requires_symlinks: None,
    ) -> None:
        """Declaring one file must not cover sibling files in the same directory."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        declared_file = tmp_path / "declared.pkl"
        declared_file.write_bytes(pickle.dumps({"declared": True}))
        undeclared_file = tmp_path / "undeclared.pkl"
        undeclared_file.write_bytes(pickle.dumps({"hidden": True}))
        linked_file = model_dir / "linked.pkl"
        linked_file.symlink_to(undeclared_file)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n- path: declared.pkl\n")
        scanned_paths: list[str] = []

        def fake_scan_file(path: str, _config: dict[str, Any]) -> ScanResult:
            scanned_paths.append(path)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned"
        )

        assert scanned_paths == [str(declared_file)]
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert result.content_hash is None
        assert str(linked_file) in incomplete_issue.details["unresolved_outputs"]

    def test_internal_dvc_directory_symlinks_cannot_hide_later_escape(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Benign links must not consume the bounded diagnostic sample before an escape."""
        output_dir = tmp_path / "model"
        real_dir = output_dir / "real"
        real_dir.mkdir(parents=True)
        (real_dir / "payload.pkl").write_bytes(pickle.dumps({"covered": True}))
        for index in range(100):
            (output_dir / f"internal-{index:03}").symlink_to(real_dir, target_is_directory=True)
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        escaping_link = output_dir / "zz-escaping"
        escaping_link.symlink_to(outside_dir, target_is_directory=True)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")

        result = scan_model_directory_or_file(str(dvc_file))
        incomplete_issue = next(
            issue
            for issue in result.issues
            if issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned"
        )

        assert result.has_errors is True
        assert result.success is False
        assert str(escaping_link) in incomplete_issue.details["unresolved_outputs"]

    def test_internal_dvc_directory_symlink_does_not_create_coverage_gap(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """A linked directory whose target is already inside the output remains covered."""
        output_dir = tmp_path / "model"
        real_dir = output_dir / "real"
        real_dir.mkdir(parents=True)
        payload = real_dir / "payload.pkl"
        payload.write_bytes(pickle.dumps({"covered": True}))
        (output_dir / "linked").symlink_to(real_dir, target_is_directory=True)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")

        result = scan_model_directory_or_file(str(dvc_file))

        assert result.files_scanned == 1
        assert result.has_errors is False
        assert result.success is True
        assert any(Path(asset.path) == payload for asset in result.assets)
        assert not any(
            issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned" for issue in result.issues
        )

    def test_dvc_directory_symlink_covered_by_another_declared_output(
        self,
        tmp_path: Path,
        requires_symlinks: None,
    ) -> None:
        """Overlapping declared directories should cover a linked target exactly once."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        linked_target = tmp_path / "linked-target"
        linked_target.mkdir()
        payload = linked_target / "payload.pkl"
        payload.write_bytes(pickle.dumps({"covered": True}))
        (model_dir / "linked").symlink_to(linked_target, target_is_directory=True)
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n- path: linked-target\n")

        result = scan_model_directory_or_file(str(dvc_file))

        assert result.files_scanned == 1
        assert result.has_errors is False
        assert result.success is True
        assert any(Path(asset.path) == payload for asset in result.assets)
        assert not any(
            issue.details.get("incomplete_reason") == "dvc_directory_symlink_unscanned" for issue in result.issues
        )

    def test_dvc_directory_outputs_share_timeout_and_total_size_budgets(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each resolved directory must receive only the remaining parent scan budget."""
        first_dir = tmp_path / "first"
        second_dir = tmp_path / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        dvc_file = tmp_path / "directories.dvc"
        dvc_file.write_text("outs:\n- path: first\n- path: second\n")

        original_scan = core_module.scan_model_directory_or_file
        calls: list[tuple[int, int]] = []
        now = [100.0]
        monkeypatch.setattr(core_module.time, "time", lambda: now[0])

        def fake_recursive_scan(path: str, *args: Any, **kwargs: Any) -> Any:
            assert Path(path).is_dir()
            calls.append((kwargs["timeout"], kwargs["max_total_size"]))
            nested_result = create_initial_audit_result()
            nested_result.files_scanned = 1
            nested_result.bytes_scanned = 60
            nested_result.success = True
            now[0] += 3
            return nested_result

        monkeypatch.setattr(core_module, "scan_model_directory_or_file", fake_recursive_scan)

        result = original_scan(str(dvc_file), timeout=10, max_total_size=100)

        assert calls == [(10, 100), (7, 40)]
        assert result.has_errors is True
        assert result.success is False
        assert any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted"
            and issue.details.get("budget_type") == "total_size"
            for issue in result.issues
        )

    @pytest.mark.parametrize("target_kind", ["file", "directory"])
    def test_final_dvc_output_timeout_overrun_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        target_kind: str,
    ) -> None:
        """The last resolved output must not overrun the shared deadline silently."""
        target = tmp_path / ("model.pkl" if target_kind == "file" else "model")
        if target_kind == "file":
            target.write_bytes(pickle.dumps({"covered": True}))
        else:
            target.mkdir()
        dvc_file = tmp_path / "timeout.dvc"
        dvc_file.write_text(f"outs:\n- path: {target.name}\n")
        now = [100.0]
        monkeypatch.setattr(core_module.time, "time", lambda: now[0])

        if target_kind == "file":

            def fake_scan_file(path: str, config: dict[str, Any]) -> ScanResult:
                now[0] += 11
                result = ScanResult(scanner_name="test")
                result.bytes_scanned = Path(path).stat().st_size
                result.finish(success=True)
                return result

            monkeypatch.setattr(core_module, "scan_file", fake_scan_file)
            result = scan_model_directory_or_file(str(dvc_file), timeout=10, cache_scan_results=False)
        else:
            original_scan = core_module.scan_model_directory_or_file

            def fake_recursive_scan(path: str, *args: Any, **kwargs: Any) -> Any:
                assert Path(path).is_dir()
                now[0] += 11
                nested_result = create_initial_audit_result()
                nested_result.success = True
                return nested_result

            monkeypatch.setattr(core_module, "scan_model_directory_or_file", fake_recursive_scan)
            result = original_scan(str(dvc_file), timeout=10)

        assert result.has_errors is True
        assert result.success is False
        assert result.content_hash is None
        assert any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted"
            and issue.details.get("budget_type") == "timeout"
            for issue in result.issues
        )

    def test_exact_dvc_budget_allows_remaining_zero_byte_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An exhausted byte budget still permits a remaining zero-byte artifact."""
        first = tmp_path / "first.bin"
        empty = tmp_path / "empty.bin"
        first.write_bytes(b"x" * 100)
        empty.write_bytes(b"")
        dvc_file = tmp_path / "exact-budget.dvc"
        dvc_file.write_text("outs:\n- path: first.bin\n- path: empty.bin\n")
        scanned: list[str] = []

        def fake_scan_file(path: str, config: dict[str, Any]) -> ScanResult:
            scanned.append(Path(path).name)
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), max_total_size=100)

        assert scanned == [first.name, empty.name]
        assert result.files_scanned == 2
        assert result.bytes_scanned == 100
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in result.issues
        )

    def test_exact_dvc_budget_allows_remaining_zero_byte_directory(self, tmp_path: Path) -> None:
        """An exhausted byte budget still permits a directory of empty artifacts."""
        first = tmp_path / "first.bin"
        empty_dir = tmp_path / "empty-dir"
        first.write_bytes(b"x")
        empty_dir.mkdir()
        (empty_dir / "empty.bin").write_bytes(b"")
        dvc_file = tmp_path / "exact-directory-budget.dvc"
        dvc_file.write_text("outs:\n- path: first.bin\n- path: empty-dir\n")

        result = scan_model_directory_or_file(str(dvc_file), max_total_size=1)

        assert result.files_scanned == 2
        assert result.bytes_scanned == 1
        assert result.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in result.issues
        )

    def test_exact_dvc_budget_ignores_skipped_non_model_directory_files(self, tmp_path: Path) -> None:
        """Skipped files must not create a false DVC budget exhaustion error."""
        first = tmp_path / "first.bin"
        output_dir = tmp_path / "output"
        first.write_bytes(b"x")
        output_dir.mkdir()
        (output_dir / "empty.pkl").write_bytes(b"")
        (output_dir / "notes.txt").write_text("not a model" * 100)
        dvc_file = tmp_path / "exact-directory-budget.dvc"
        dvc_file.write_text("outs:\n- path: first.bin\n- path: output\n")

        result = scan_model_directory_or_file(str(dvc_file), max_total_size=1)

        assert result.files_scanned == 2
        assert result.bytes_scanned == 1
        assert result.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in result.issues
        )

    def test_exact_dvc_budget_rejects_remaining_nonempty_directory(self, tmp_path: Path) -> None:
        """An exhausted budget must reject a non-empty directory before scanning it."""
        first = tmp_path / "first.bin"
        nonempty_dir = tmp_path / "nonempty-dir"
        first.write_bytes(b"x")
        nonempty_dir.mkdir()
        payload = nonempty_dir / "payload.pkl"
        payload.write_bytes(pickle.dumps({"payload": "must-not-be-scanned"}))
        dvc_file = tmp_path / "exact-directory-budget.dvc"
        dvc_file.write_text("outs:\n- path: first.bin\n- path: nonempty-dir\n")

        result = scan_model_directory_or_file(str(dvc_file), max_total_size=1)

        assert result.files_scanned == 1
        assert result.bytes_scanned == 1
        assert not any(Path(asset.path) == payload for asset in result.assets)
        assert result.success is False
        assert result.has_errors is True
        assert result.content_hash is None
        assert any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted"
            and issue.details.get("budget_type") == "total_size"
            for issue in result.issues
        )

    def test_dvc_directory_rejects_file_larger_than_remaining_budget(self, tmp_path: Path) -> None:
        """A directory output must not scan a file larger than the shared remainder."""
        first = tmp_path / "first.bin"
        output_dir = tmp_path / "output"
        first.write_bytes(b"x")
        output_dir.mkdir()
        payload = output_dir / "payload.pkl"
        payload.write_bytes(pickle.dumps({"payload": "must-not-be-scanned"}))
        dvc_file = tmp_path / "bounded-directory.dvc"
        dvc_file.write_text("outs:\n- path: first.bin\n- path: output\n")

        result = scan_model_directory_or_file(str(dvc_file), max_total_size=2)

        assert result.files_scanned == 1
        assert result.bytes_scanned == 1
        assert not any(Path(asset.path) == payload for asset in result.assets)
        assert result.success is False
        assert any(issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in result.issues)

    def test_incomplete_dvc_directory_scan_omits_partial_content_hash(self, tmp_path: Path) -> None:
        """Rejected nested files must prevent publication of a partial aggregate hash."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "small.pkl").write_bytes(pickle.dumps({"small": True}))
        (output_dir / "oversized.pkl").write_bytes(pickle.dumps({"large": "x" * 256}))
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: output\n")

        result = scan_model_directory_or_file(str(dvc_file), max_file_size=64, cache_scan_results=False)

        assert result.has_errors is True
        assert result.success is False
        assert result.content_hash is None

    def test_dvc_directory_and_file_outputs_all_contribute_to_content_hash(self, tmp_path: Path) -> None:
        """Mutating either a nested directory file or a direct output must change the aggregate hash."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        nested_path = output_dir / "nested.pkl"
        direct_path = tmp_path / "direct.pkl"
        nested_path.write_bytes(pickle.dumps({"nested": 1}))
        direct_path.write_bytes(pickle.dumps({"direct": 1}))
        dvc_file = tmp_path / "mixed.dvc"
        dvc_file.write_text("outs:\n- path: model\n- path: direct.pkl\n")

        initial = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)
        nested_path.write_bytes(pickle.dumps({"nested": 2}))
        nested_changed = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)
        direct_path.write_bytes(pickle.dumps({"direct": 2}))
        direct_changed = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)

        assert initial.content_hash is not None
        assert nested_changed.content_hash is not None
        assert direct_changed.content_hash is not None
        assert initial.content_hash != nested_changed.content_hash
        assert nested_changed.content_hash != direct_changed.content_hash


class TestDvcSecurity:
    """Test security aspects of DVC integration."""

    def test_path_traversal_prevention(self, tmp_path):
        """Test that path traversal attempts are blocked."""
        # Create a file outside the DVC directory
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "secret.pkl"
        with outside_file.open("wb") as f:
            pickle.dump({"secret": "data"}, f)

        # Create DVC directory
        dvc_dir = tmp_path / "dvc_project"
        dvc_dir.mkdir()

        # Create DVC file with path traversal attempt
        dvc_file = dvc_dir / "malicious.dvc"
        dvc_file.write_text("outs:\n- path: ../../outside/secret.pkl\n")

        resolved = resolve_dvc_file(str(dvc_file))
        # Should be empty due to path traversal protection
        assert resolved == []

    def test_parent_directory_target_prevention(self, tmp_path: Path) -> None:
        """Test that sibling-directory DVC targets are blocked."""
        outside_file = tmp_path / "secret.pkl"
        with outside_file.open("wb") as f:
            pickle.dump({"secret": "data"}, f)

        dvc_dir = tmp_path / "dvc_project"
        dvc_dir.mkdir()
        dvc_file = dvc_dir / "sibling.dvc"
        dvc_file.write_text("outs:\n- path: ../secret.pkl\n")

        resolved = resolve_dvc_file(str(dvc_file))
        assert resolved == []

    def test_wdir_routes_to_declared_artifact_instead_of_decoy(self, tmp_path: Path) -> None:
        """DVC output paths must be resolved relative to the declared working directory."""

        class MaliciousClass:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                return (os.system, ("echo dvc-wdir-malicious",))

        decoy = tmp_path / "model.pkl"
        decoy.write_bytes(pickle.dumps({"benign": True}))
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()
        payload = artifacts / "model.pkl"
        payload.write_bytes(pickle.dumps(MaliciousClass()))
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("wdir: artifacts\nouts:\n- path: model.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file))

        assert resolution.resolved_paths == (str(payload),)
        assert result.files_scanned == 1
        assert any(Path(asset.path) == payload for asset in result.assets)
        assert not any(Path(asset.path) == decoy for asset in result.assets)
        assert any("model.pkl" in (issue.location or "") for issue in result.issues)

    @pytest.mark.parametrize("wdir", ["../outside", "", 123])
    def test_unsafe_or_invalid_wdir_marks_pointer_incomplete(self, tmp_path: Path, wdir: object) -> None:
        """Invalid working directories must fail closed instead of changing the trust boundary."""
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text(f"wdir: {json.dumps(wdir)}\nouts:\n- path: model.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file))

        assert resolution.analysis_incomplete is True
        assert result.files_scanned == 0
        assert result.has_errors is True
        assert result.success is False

    def test_absolute_path_prevention(self, tmp_path):
        """Test that absolute paths are handled safely."""
        # Create a target file
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"data": "test"}, f)

        dvc_file = tmp_path / "absolute.dvc"
        # Try to use absolute path
        dvc_file.write_text(f"outs:\n- path: {target.absolute()}\n")

        resolved = resolve_dvc_file(str(dvc_file))
        # Should resolve if within safe boundaries
        # This is allowed since it resolves to the same directory
        assert str(target) in resolved or resolved == []

    def test_symlink_traversal_prevention(self, tmp_path, requires_symlinks):
        """Test prevention of symlink-based traversal."""
        # Create directories
        safe_dir = tmp_path / "safe"
        safe_dir.mkdir()
        unsafe_dir = tmp_path / "unsafe"
        unsafe_dir.mkdir()

        # Create file in unsafe directory
        unsafe_file = unsafe_dir / "secret.pkl"
        with unsafe_file.open("wb") as f:
            pickle.dump({"secret": True}, f)

        # Create symlink in safe directory pointing to unsafe file
        symlink = safe_dir / "link.pkl"
        symlink.symlink_to(unsafe_file)

        # Create DVC file
        dvc_file = safe_dir / "test.dvc"
        dvc_file.write_text("outs:\n- path: link.pkl\n")

        resolved = resolve_dvc_file(str(dvc_file))
        # Should be blocked or handled safely
        if resolved:
            # If allowed, should still point to the resolved location
            assert len(resolved) <= 1

    def test_resource_exhaustion_prevention(self, tmp_path: Path) -> None:
        """Test prevention of resource exhaustion via too many outputs."""
        # Create DVC file with excessive outputs
        dvc_content = "outs:\n"
        for i in range(150):  # Exceeds MAX_OUTPUTS limit
            dvc_content += f"- path: model_{i}.pkl\n"

        dvc_file = tmp_path / "excessive.dvc"
        dvc_file.write_text(dvc_content)

        resolved = resolve_dvc_file(str(dvc_file))
        # Should be limited to MAX_OUTPUTS (100)
        assert len(resolved) <= 100
        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.declared_output_count == 150
        assert resolution.output_limit == 100
        assert resolution.omitted_output_count == 50
        assert resolution.analysis_incomplete is True
        assert resolution.omitted_targets == []
        assert resolution.unresolved_omitted_output_count == 50
        assert resolution.unverified_omitted_output_count == 0

    def test_over_limit_dvc_scan_fails_closed_for_omitted_late_output(self, tmp_path: Path) -> None:
        """A malicious output past the DVC cap must not look like complete clean coverage."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        late_malicious = tmp_path / "late_malicious.pkl"
        with late_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)
        dvc_lines.append(f"- path: {late_malicious.name}")

        dvc_file = tmp_path / "over_limit.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(dvc_file))

        assert result.files_scanned == 100
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 2
        asset_paths = {asset.path for asset in result.assets}
        assert str(late_malicious) not in asset_paths
        output_limit_issues = [issue for issue in result.issues if issue.type == "dvc_output_limit_exceeded"]
        assert len(output_limit_issues) == 1
        assert output_limit_issues[0].message == "DVC output limit exceeded - not all declared outputs were scanned"
        details = output_limit_issues[0].details
        assert details["analysis_incomplete"] is True
        assert details["scan_outcome"] == "inconclusive"
        assert details["declared_output_count"] == 101
        assert details["output_limit"] == 100
        assert details["resolved_output_count"] == 100
        assert details["omitted_output_count"] == 1
        assert details["unresolved_omitted_output_count"] == 0
        assert details["unverified_omitted_output_count"] == 0

        cached_result = scan_model_directory_or_file(
            str(dvc_file),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
        )
        assert cached_result.success is False
        assert determine_exit_code(cached_result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in cached_result.issues)

    def test_over_limit_dvc_with_security_finding_keeps_exit_code_1(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """DVC output-limit gaps stay visible without masking scanned security findings."""
        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_OUTPUTS", 1)
        malicious = tmp_path / "malicious.pkl"
        with malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)
        omitted = tmp_path / "omitted.pkl"
        with omitted.open("wb") as f:
            pickle.dump({"omitted": True}, f)
        dvc_file = tmp_path / "over_limit_with_finding.dvc"
        dvc_file.write_text("outs:\n- path: malicious.pkl\n- path: omitted.pkl\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 1
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 1
        assert any(
            issue.rule_code == "S201" and issue.location is not None and str(malicious) in issue.location
            for issue in result.issues
        )
        output_limit_issues = [issue for issue in result.issues if issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON]
        assert len(output_limit_issues) == 1
        assert output_limit_issues[0].details["analysis_incomplete"] is True
        assert output_limit_issues[0].details["scan_outcome"] == "inconclusive"
        assert output_limit_issues[0].details["omitted_output_count"] == 1

    def test_duplicate_dvc_outputs_do_not_exhaust_cap_or_fail_closed(self, tmp_path: Path) -> None:
        """Duplicate declarations do not omit any unique artifact or trigger repeated scans."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"ok": True}, f)

        dvc_file = tmp_path / "duplicate_outputs.dvc"
        dvc_file.write_text("outs:\n" + "- path: model.pkl\n" * 101)

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.targets == [str(target)]
        assert resolution.omitted_output_count == 1
        assert resolution.omitted_targets == []
        assert resolution.analysis_incomplete is False

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 1
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_duplicate_dvc_tail_past_verification_window_does_not_fail_closed(self, tmp_path: Path) -> None:
        """Repeated known outputs beyond the verification window do not represent omitted artifacts."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"ok": True}, f)

        dvc_file = tmp_path / "duplicate_tail.dvc"
        dvc_file.write_text("outs:\n" + "- path: model.pkl\n" * 250)

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.targets == [str(target)]
        assert resolution.omitted_output_count == 150
        assert resolution.unverified_omitted_output_count == 0
        assert resolution.analysis_incomplete is False

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 1
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_capped_dvc_scan_rejects_same_count_pointer_rewrite(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Coverage metadata must not discharge a pointer rewritten after resolution."""
        benign = tmp_path / "benign.pkl"
        late_malicious = tmp_path / "late_malicious.pkl"
        with benign.open("wb") as f:
            pickle.dump({"ok": True}, f)
        with late_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)

        dvc_file = tmp_path / "rewritten.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 101)

        from modelaudit import core

        original_resolver = core.resolve_dvc_file_status

        def resolve_then_rewrite(file_path: str) -> DvcResolution:
            resolution = original_resolver(file_path)
            dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late_malicious.pkl\n")
            return resolution

        monkeypatch.setattr(core, "resolve_dvc_file_status", resolve_then_rewrite)

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)
        assert not any(asset.path == str(late_malicious) for asset in result.assets)

    def test_capped_dvc_revalidation_rejects_oversized_rewrite(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The post-scan pointer identity check must retain the bounded read limit."""
        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_OUTPUTS", 2)
        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_POINTER_BYTES", 128)
        target = tmp_path / "model.pkl"
        target.write_bytes(pickle.dumps({"safe": True}))
        dvc_file = tmp_path / "rewritten-large.dvc"
        dvc_file.write_text("outs:\n" + "- path: model.pkl\n" * 3)
        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.source_digest is not None

        dvc_file.write_bytes(b"x" * 129)

        assert (
            dvc_omitted_outputs_covered(
                str(dvc_file),
                resolution,
                lambda _target: True,
                coverage_budget=0,
            )
            is False
        )

    def test_directory_scan_accepts_unchanged_duplicate_only_cap(self, tmp_path: Path) -> None:
        """Stable duplicate declarations remain complete when the directory walk covers the target."""
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"ok": True}, f)

        dvc_file = tmp_path / "directory_duplicates.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 101)

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.success is True
        assert determine_exit_code(result) == 0
        assert any(asset.path == str(benign) for asset in result.assets)
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_cli_keeps_capped_pointer_rewritten_during_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CLI pre-expansion must not discard a capped pointer that changes after resolution."""
        from modelaudit import cli

        benign = tmp_path / "benign.pkl"
        late_malicious = tmp_path / "late_malicious.pkl"
        with benign.open("wb") as f:
            pickle.dump({"ok": True}, f)
        with late_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)

        dvc_file = tmp_path / "cli_rewritten.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 101)
        original_resolver = cli.resolve_dvc_file_with_metadata

        def resolve_then_rewrite(file_path: str) -> DvcResolution:
            resolution = original_resolver(file_path)
            dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late_malicious.pkl\n")
            return resolution

        monkeypatch.setattr(cli, "resolve_dvc_file_with_metadata", resolve_then_rewrite)

        resolved_paths = cli._resolve_scan_paths((str(dvc_file),), 0.0)

        assert resolved_paths == [str(dvc_file)]

    def test_dvc_tail_verification_is_bounded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Duplicate padding beyond the verification budget must fail closed."""
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"ok": True}, f)

        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_TAIL_DECLARATIONS", 2)
        dvc_file = tmp_path / "bounded_tail.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 203)

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert resolution.tail_verification_truncated is True
        assert resolution.analysis_incomplete is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        issues = [issue for issue in result.issues if issue.type == "dvc_output_limit_exceeded"]
        assert len(issues) == 1
        assert issues[0].details["tail_verification_truncated"] is True

    def test_duplicate_dvc_tail_cannot_hide_new_output_past_verification_window(self, tmp_path: Path) -> None:
        """A genuinely new output after duplicate padding must still fail closed."""
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"ok": True}, f)

        late_malicious = tmp_path / "late_malicious.pkl"
        with late_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)

        dvc_file = tmp_path / "duplicate_tail_padding.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 200 + f"- path: {late_malicious.name}\n")

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.targets == [str(benign)]
        assert resolution.unverified_omitted_output_count == 1
        assert resolution.analysis_incomplete is True

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 1
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_duplicate_dvc_outputs_cannot_hide_unique_late_output(self, tmp_path: Path) -> None:
        """Duplicate padding must not discharge a unique output beyond the declaration cap."""
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"ok": True}, f)

        late_malicious = tmp_path / "late_malicious.pkl"
        with late_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)

        dvc_file = tmp_path / "duplicate_padding.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late_malicious.pkl\n")

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.targets == [str(benign)]
        assert resolution.omitted_targets == [str(late_malicious)]
        assert resolution.analysis_incomplete is True

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 1
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_accepts_over_limit_dvc_when_walk_covers_omitted_outputs(self, tmp_path: Path) -> None:
        """Directory traversal should discharge the cap when it scans the omitted in-tree output."""
        dvc_lines = ["outs:"]
        for index in range(101):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        dvc_file = tmp_path / "directory_over_limit.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.files_scanned == 101
        assert result.success is True
        assert result.has_errors is False
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    @pytest.mark.parametrize("record_kind", ["issue", "check"])
    def test_directory_scan_rejects_detail_only_incomplete_dvc_tail_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        record_kind: str,
    ) -> None:
        """Detail-only incomplete scans must not discharge a DVC output cap."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        late = tmp_path / "late.pkl"
        with late.open("wb") as f:
            pickle.dump({"late": True}, f)
        dvc_lines.append(f"- path: {late.name}")

        dvc_file = tmp_path / "directory_over_limit_detail_only_incomplete.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")
        _patch_detail_only_incomplete_scan(monkeypatch, late.name, record_kind=record_kind)

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.files_scanned == 101
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    @pytest.mark.parametrize("record_kind", ["issue", "check"])
    def test_directory_scan_rejects_archive_member_detail_only_incomplete_dvc_tail_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        record_kind: str,
    ) -> None:
        """Archive-member incomplete diagnostics must not discharge a DVC output cap."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        late = tmp_path / "late_archive_location.pkl"
        with late.open("wb") as f:
            pickle.dump({"late": True}, f)
        dvc_lines.append(f"- path: {late.name}")

        dvc_file = tmp_path / "directory_over_limit_archive_location_incomplete.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")
        _patch_detail_only_incomplete_scan(
            monkeypatch,
            late.name,
            record_kind=record_kind,
            location_suffix="nested/member.pkl",
        )

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.files_scanned == 101
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_accepts_clean_detail_dvc_tail_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Benign issue/check details should not block completed DVC tail coverage."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        late = tmp_path / "late.pkl"
        with late.open("wb") as f:
            pickle.dump({"late": True}, f)
        dvc_lines.append(f"- path: {late.name}")

        dvc_file = tmp_path / "directory_over_limit_clean_detail.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")
        _patch_clean_detail_scan(monkeypatch, late.name)

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.files_scanned == 101
        assert result.success is True
        assert result.has_errors is False
        assert determine_exit_code(result) == 0
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_detects_malicious_omitted_output(self, tmp_path: Path) -> None:
        """Discharging the DVC cap must still scan and report a malicious omitted output."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        late_malicious = tmp_path / "late_malicious.pkl"
        with late_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)
        dvc_lines.append(f"- path: {late_malicious.name}")

        dvc_file = tmp_path / "directory_over_limit_malicious.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.files_scanned == 101
        assert result.success is True
        assert result.has_errors is False
        assert determine_exit_code(result) == 1
        assert any(
            issue.rule_code == "S201" and issue.location is not None and str(late_malicious) in issue.location
            for issue in result.issues
        )
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_dvc_directory_output_keeps_security_exit_when_nested_coverage_incomplete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Nested DVC coverage gaps should not mask security findings as operational errors."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()

        malicious = output_dir / "late_malicious.pkl"
        with malicious.open("wb") as handle:
            pickle.dump(_LateMaliciousPayload(), handle)

        incomplete = output_dir / "preview.png"
        _write_incomplete_png_payload(incomplete)
        _patch_metadata_only_incomplete_scan(
            monkeypatch,
            incomplete.name,
            reason="synthetic_nested_coverage_incomplete",
        )

        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_scan_results=False)

        assert result.files_scanned == 2
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 1
        assert any(
            issue.rule_code == "S201" and issue.location is not None and str(malicious) in issue.location
            for issue in result.issues
        )
        incomplete_metadata = result.file_metadata[str(incomplete)]
        assert incomplete_metadata["scan_outcome"] == "inconclusive"
        assert incomplete_metadata["analysis_incomplete"] is True
        assert "synthetic_nested_coverage_incomplete" in incomplete_metadata["scan_outcome_reasons"]

    def test_directory_scan_accepts_fully_covered_tail_past_verification_window(self, tmp_path: Path) -> None:
        """A large in-tree DVC tail is covered by the already completed directory walk."""
        dvc_lines = ["outs:"]
        for index in range(205):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        dvc_file = tmp_path / "directory_large_covered_tail.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.files_scanned == 205
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_rejects_skipped_tail_past_verification_window(self, tmp_path: Path) -> None:
        """Tail verification must not treat a filtered path as directory-walk coverage."""
        dvc_lines = ["outs:"]
        for index in range(200):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")
        skipped_target = tmp_path / "payload.py"
        skipped_target.write_text("print('not scanned')\n")
        dvc_lines.append(f"- path: {skipped_target.name}")

        dvc_file = tmp_path / "directory_large_skipped_tail.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_over_limit_dvc_stays_incomplete_for_skipped_output(self, tmp_path: Path) -> None:
        """A filtered omitted output is not covered merely because it lives under the walked root."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        skipped_target = tmp_path / "payload.py"
        skipped_target.write_text("print('not scanned by the ordinary directory walk')\n")
        dvc_lines.append(f"- path: {skipped_target.name}")

        dvc_file = tmp_path / "directory_over_limit_skipped.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_accepts_covered_omitted_directory_output(self, tmp_path: Path) -> None:
        """An omitted directory is covered when the walk scans all model files inside it."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        model_dir = tmp_path / "model_dir"
        model_dir.mkdir()
        nested_model = model_dir / "nested.pkl"
        with nested_model.open("wb") as f:
            pickle.dump({"nested": True}, f)
        dvc_lines.append(f"- path: {model_dir.name}")

        dvc_file = tmp_path / "directory_output.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.files_scanned == 101
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert str(nested_model) in {asset.path for asset in result.assets}
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_directory_scan_stays_incomplete_for_unresolved_omitted_output(self, tmp_path: Path) -> None:
        """An unsafe omitted output must not vacuously discharge the DVC cap."""
        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        dvc_lines.append("- path: ../outside.pkl")
        dvc_file = tmp_path / "directory_over_limit_unsafe.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 2
        output_limit_issues = [issue for issue in result.issues if issue.type == "dvc_output_limit_exceeded"]
        assert len(output_limit_issues) == 1
        assert output_limit_issues[0].details["unresolved_omitted_output_count"] == 1

    def test_over_limit_dvc_coverage_verification_is_bounded(self, tmp_path: Path) -> None:
        """Directory coverage metadata must not resolve an unbounded omitted tail."""
        dvc_file = tmp_path / "large_tail.dvc"
        dvc_file.write_text("outs:\n" + "".join(f"- path: missing_{index:03}.pkl\n" for index in range(250)))

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))

        assert resolution.declared_output_count == 250
        assert resolution.omitted_output_count == 150
        assert resolution.omitted_targets == []
        assert resolution.unresolved_omitted_output_count == 100
        assert resolution.unverified_omitted_output_count == 50

    def test_in_limit_dvc_scan_remains_complete_for_benign_outputs(self, tmp_path: Path) -> None:
        """Normal DVC pointers under the cap still expand and scan cleanly."""
        targets = []
        for index in range(2):
            target = tmp_path / f"benign_{index}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            targets.append(target)

        dvc_file = tmp_path / "in_limit.dvc"
        dvc_file.write_text("outs:\n" + "".join(f"- path: {target.name}\n" for target in targets))

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        assert resolution.analysis_incomplete is False
        assert resolution.omitted_output_count == 0

        result = scan_model_directory_or_file(str(dvc_file))

        assert result.files_scanned == len(targets)
        assert result.success is True
        assert result.has_errors is False
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_cli_preserves_over_limit_dvc_pointer_for_core_fail_closed(self, tmp_path: Path) -> None:
        """CLI pre-expansion should not discard DVC cap metadata before core sees it."""
        from modelaudit.cli import _resolve_scan_paths

        dvc_lines = ["outs:"]
        for index in range(101):
            target = tmp_path / f"model_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")

        dvc_file = tmp_path / "cli_over_limit.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        assert _resolve_scan_paths((str(dvc_file),), 0.0) == [str(dvc_file)]

    def test_cli_does_not_prewalk_directories_without_capped_dvc(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ordinary directory scans must not pay the DVC coverage traversal cost."""
        from modelaudit import cli as cli_module

        monkeypatch.setattr(cli_module.os, "walk", lambda *_args, **_kwargs: pytest.fail("unexpected directory walk"))

        assert cli_module._resolve_scan_paths((str(tmp_path),), 0.0) == [str(tmp_path)]

    def test_cli_error_asset_does_not_count_as_dvc_coverage(self, tmp_path: Path) -> None:
        """An operationally failed sibling scan must not discharge a capped output."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        failed_path = tmp_path / "failed.pkl"
        failed_path.write_bytes(b"not-a-complete-scan")
        failed_result = create_initial_audit_result()
        failed_result.success = False
        failed_result.has_errors = True
        failed_result.assets.append(AssetModel(path=str(failed_path), type="error"))
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(failed_path), failed_result)

        assert path_state.dvc_covered_paths == set()
        assert path_state.dvc_covered_directories == set()

    def test_cli_security_finding_asset_counts_as_dvc_coverage(self, tmp_path: Path) -> None:
        """A completed sibling scan remains coverage when it reports a critical finding."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        malicious_path = tmp_path / "malicious.pkl"
        malicious_path.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        finding_result = create_initial_audit_result()
        finding_result.success = True
        finding_result.has_errors = True
        finding_result.assets.append(AssetModel(path=str(malicious_path), type="pickle"))
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(malicious_path), finding_result)

        assert path_state.dvc_covered_paths == {str(malicious_path)}

    @pytest.mark.parametrize("record_kind", ["issue", "check"])
    def test_cli_issue_check_only_incomplete_asset_does_not_count_as_dvc_coverage(
        self,
        tmp_path: Path,
        record_kind: str,
    ) -> None:
        """Issue/check-only incomplete coverage must not discharge capped DVC outputs."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        incomplete_path = tmp_path / "incomplete.pkl"
        incomplete_path.write_bytes(pickle.dumps({"incomplete": True}))
        incomplete_result = create_initial_audit_result()
        incomplete_result.assets.append(AssetModel(path=str(incomplete_path), type="pickle"))
        details = {
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": f"dvc_{record_kind}_only_incomplete",
        }
        if record_kind == "issue":
            incomplete_result.issues.append(
                Issue(
                    message="Incomplete coverage retained only in issue details",
                    severity=IssueSeverity.INFO,
                    location=str(incomplete_path),
                    details=details,
                )
            )
        else:
            incomplete_result.checks.append(
                Check(
                    name="Incomplete Coverage Check",
                    status=CheckStatus.FAILED,
                    message="Incomplete coverage retained only in check details",
                    severity=IssueSeverity.INFO,
                    location=str(incomplete_path),
                    details=details,
                )
            )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(incomplete_path), incomplete_result)

        assert path_state.dvc_covered_paths == set()
        assert path_state.dvc_covered_directories == set()

    @pytest.mark.parametrize("record_kind", ["issue", "check"])
    def test_cli_archive_member_detail_only_incomplete_asset_does_not_count_as_dvc_coverage(
        self,
        tmp_path: Path,
        record_kind: str,
    ) -> None:
        """Relative asset:member diagnostics still apply to the outer DVC asset."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        incomplete_path = tmp_path / f"{record_kind}_archive_location_incomplete.pkl"
        incomplete_path.write_bytes(pickle.dumps({"incomplete": True}))
        incomplete_result = create_initial_audit_result()
        incomplete_result.success = True
        incomplete_result.assets.append(AssetModel(path=str(incomplete_path), type="pickle"))
        details = {
            "analysis_incomplete": True,
            "scan_outcome_reason": "synthetic_detail_only_incomplete",
        }
        location = f"{incomplete_path.name}:nested/member.pkl"
        if record_kind == "issue":
            incomplete_result.issues.append(
                Issue(
                    message="Synthetic issue-only archive member incomplete coverage",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details=details,
                    type="synthetic_incomplete_coverage",
                )
            )
        else:
            incomplete_result.checks.append(
                Check(
                    name="Synthetic Archive Member Detail Coverage",
                    status=CheckStatus.FAILED,
                    message="Synthetic check-only archive member incomplete coverage",
                    severity=IssueSeverity.INFO,
                    location=location,
                    details=details,
                )
            )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(incomplete_path), incomplete_result)

        assert path_state.dvc_covered_paths == set()
        assert path_state.dvc_covered_directories == set()

    def test_cli_incomplete_sibling_location_does_not_block_dvc_coverage(self, tmp_path: Path) -> None:
        """Coverage matching should use path boundaries, not arbitrary substrings."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        model_path = tmp_path / "model.pkl"
        model_path.write_bytes(pickle.dumps({"safe": True}))
        sibling_path = tmp_path / "model.pkl.bak"
        sibling_path.write_bytes(pickle.dumps({"incomplete": True}))
        result = create_initial_audit_result()
        result.assets.append(AssetModel(path=str(model_path), type="pickle"))
        result.issues.append(
            Issue(
                message="Incomplete coverage belongs to a sibling",
                severity=IssueSeverity.INFO,
                location=str(sibling_path),
                details={"analysis_incomplete": True},
            )
        )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(model_path), result)

        assert path_state.dvc_covered_paths == {str(model_path)}

    def test_cli_nested_incomplete_location_blocks_dvc_coverage(self, tmp_path: Path) -> None:
        """Nested archive-style locations should still mark the owning file incomplete."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        model_path = tmp_path / "model.pkl"
        model_path.write_bytes(pickle.dumps({"safe": True}))
        result = create_initial_audit_result()
        result.assets.append(AssetModel(path=str(model_path), type="pickle"))
        result.issues.append(
            Issue(
                message="Incomplete coverage in nested member",
                severity=IssueSeverity.INFO,
                location=f"{model_path}:member.pkl",
                details={"analysis_incomplete": True},
            )
        )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(model_path), result)

        assert path_state.dvc_covered_paths == set()
        assert path_state.dvc_covered_directories == set()

    def test_cli_shard_check_paths_count_as_dvc_coverage(self, tmp_path: Path) -> None:
        """Shard siblings scanned by the advanced handler must discharge capped outputs."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        first_shard = tmp_path / "model-00001-of-00002.safetensors"
        second_shard = tmp_path / "model-00002-of-00002.safetensors"
        first_shard.write_bytes(b"first")
        second_shard.write_bytes(b"second")
        shard_result = create_initial_audit_result()
        shard_result.assets.append(AssetModel(path=str(first_shard), type="safetensors"))
        shard_result.checks.append(
            Check(
                name="Sharded Model Detection",
                status=CheckStatus.PASSED,
                message="Detected complete sharded model",
                details={"shards": [str(first_shard), str(second_shard)]},
            )
        )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(first_shard), shard_result)

        assert path_state.dvc_covered_paths == {str(first_shard), str(second_shard)}

    def test_core_incomplete_shard_family_matching_is_family_scoped(self, tmp_path: Path) -> None:
        """Incomplete shard records should not poison unrelated detected families."""
        complete_first = tmp_path / "complete-00001-of-00002.safetensors"
        complete_second = tmp_path / "complete-00002-of-00002.safetensors"
        failed_first = tmp_path / "failed-00001-of-00002.safetensors"
        failed_second = tmp_path / "failed-00002-of-00002.safetensors"
        for shard_path in (complete_first, complete_second, failed_first, failed_second):
            shard_path.write_bytes(b"shard")

        incomplete_record = Check(
            name="Shard Scan",
            status=CheckStatus.FAILED,
            message="Error scanning shard",
            location=str(failed_second),
            details={
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "shard_scan_error",
            },
        )
        complete_family = {str(complete_first.resolve()), str(complete_second.resolve())}
        failed_family = {str(failed_first.resolve()), str(failed_second.resolve())}

        assert (
            core_module._shard_family_has_incomplete_coverage(
                (incomplete_record,),
                complete_family,
                only_detected_shard_family=False,
            )
            is False
        )
        assert (
            core_module._shard_family_has_incomplete_coverage(
                (incomplete_record,),
                failed_family,
                only_detected_shard_family=False,
            )
            is True
        )
        ambiguous_record = Check(
            name="Shard Scan",
            status=CheckStatus.FAILED,
            message="Error scanning shard without a retained path",
            details={
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "shard_scan_error",
            },
        )
        assert (
            core_module._shard_family_has_incomplete_coverage(
                (ambiguous_record,),
                complete_family,
                only_detected_shard_family=True,
            )
            is True
        )
        assert (
            core_module._shard_family_has_incomplete_coverage(
                (ambiguous_record,),
                complete_family,
                only_detected_shard_family=False,
            )
            is False
        )

    def test_cli_incomplete_shard_family_does_not_block_complete_sibling_family(self, tmp_path: Path) -> None:
        """A failed shard scan should only suppress DVC coverage for its own family."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        complete_first = tmp_path / "complete-00001-of-00002.safetensors"
        complete_second = tmp_path / "complete-00002-of-00002.safetensors"
        failed_first = tmp_path / "failed-00001-of-00002.safetensors"
        failed_second = tmp_path / "failed-00002-of-00002.safetensors"
        for shard_path in (complete_first, complete_second, failed_first, failed_second):
            shard_path.write_bytes(b"shard")

        shard_result = create_initial_audit_result()
        shard_result.success = False
        shard_result.assets.append(AssetModel(path=str(complete_first), type="safetensors"))
        shard_result.assets.append(AssetModel(path=str(failed_first), type="safetensors"))
        shard_result.checks.extend(
            [
                Check(
                    name="Sharded Model Detection",
                    status=CheckStatus.PASSED,
                    message="Detected complete sharded model",
                    details={"shards": [str(complete_first), str(complete_second)]},
                ),
                Check(
                    name="Sharded Model Detection",
                    status=CheckStatus.PASSED,
                    message="Detected incomplete sharded model",
                    details={"shards": [str(failed_first), str(failed_second)]},
                ),
                Check(
                    name="Shard Scan",
                    status=CheckStatus.FAILED,
                    message="Error scanning shard",
                    location=str(failed_second),
                    details={
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "shard_scan_error",
                    },
                ),
            ]
        )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(tmp_path), shard_result)

        assert path_state.dvc_covered_paths == {
            str(complete_first),
            str(complete_second),
            str(failed_first),
        }

    def test_cli_incomplete_shard_check_paths_do_not_count_as_dvc_coverage(self, tmp_path: Path) -> None:
        """Incomplete shard-family scans must not discharge omitted DVC shard outputs."""
        from modelaudit.cli import _ScanPathState
        from modelaudit.models import AssetModel, create_initial_audit_result

        first_shard = tmp_path / "model-00001-of-00002.safetensors"
        second_shard = tmp_path / "model-00002-of-00002.safetensors"
        first_shard.write_bytes(b"first")
        second_shard.write_bytes(b"second")
        shard_result = create_initial_audit_result()
        shard_result.success = False
        shard_result.assets.append(AssetModel(path=str(first_shard), type="safetensors"))
        shard_result.checks.append(
            Check(
                name="Sharded Model Detection",
                status=CheckStatus.PASSED,
                message="Detected sharded model",
                details={"shards": [str(first_shard), str(second_shard)]},
            )
        )
        shard_result.checks.append(
            Check(
                name="Shard Scan",
                status=CheckStatus.FAILED,
                message="Error scanning shard",
                location=str(second_shard),
                details={
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_scan_error",
                },
            )
        )
        path_state = _ScanPathState(collect_dvc_coverage=True)

        path_state.record_dvc_coverage(str(first_shard), shard_result)

        assert path_state.dvc_covered_paths == {str(first_shard)}

    def test_cli_orders_capped_pointer_after_sibling_paths(self, tmp_path: Path) -> None:
        """Concrete sibling inputs should run before a capped pointer verifies their coverage."""
        from modelaudit.cli import _resolve_scan_paths

        targets = []
        dvc_lines = ["outs:"]
        for index in range(101):
            target = tmp_path / f"model_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            targets.append(target)
            dvc_lines.append(f"- path: {target.name}")

        dvc_file = tmp_path / "cli_sibling_coverage.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        resolved_paths = _resolve_scan_paths(tuple(str(path) for path in [dvc_file, *targets]), 0.0)

        assert resolved_paths == [*(str(path) for path in targets), str(dvc_file)]

    def test_cli_orders_uppercase_capped_pointer_after_sibling(self, tmp_path: Path) -> None:
        """DVC pointer ordering should use the same case-insensitive suffix rule as core."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        late_target = tmp_path / "late.pkl"
        benign.write_bytes(pickle.dumps({"benign": True}))
        late_target.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "MODEL.DVC"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(late_target)), 0.0)

        assert resolved_paths == [str(late_target), str(dvc_file)]

    def test_cli_preserves_capped_pointer_with_non_model_sibling(self, tmp_path: Path) -> None:
        """Coverage decisions occur after runtime filtering rather than during path expansion."""
        from modelaudit.cli import _resolve_scan_paths

        dvc_lines = ["outs:"]
        for index in range(100):
            target = tmp_path / f"model_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")
        skipped_target = tmp_path / "payload.py"
        skipped_target.write_text("print('filtered')\n")
        dvc_lines.append(f"- path: {skipped_target.name}")

        dvc_file = tmp_path / "cli_filtered_sibling.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(skipped_target)), 0.0)

        assert resolved_paths == [str(skipped_target), str(dvc_file)]

    def test_cli_preserves_capped_pointer_for_runtime_coverage(self, tmp_path: Path) -> None:
        """Runtime filtering determines whether a sibling actually covers an omitted output."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        strict_target = tmp_path / "payload.py"
        strict_target.write_text("print('strictly scanned')\n")
        dvc_file = tmp_path / "cli_strict_sibling.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: payload.py\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(strict_target)), 0.0)

        assert resolved_paths == [str(strict_target), str(dvc_file)]

    def test_cli_orders_scannable_text_sibling_before_capped_pointer(self, tmp_path: Path) -> None:
        """A text sibling is scanned before the capped pointer verifies coverage."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        vocabulary = tmp_path / "vocab.txt"
        vocabulary.write_text("safe-token\n")
        dvc_file = tmp_path / "cli_text_sibling.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: vocab.txt\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(vocabulary)), 0.0)

        assert resolved_paths == [str(vocabulary), str(dvc_file)]

    def test_cli_orders_sibling_directory_before_capped_pointer(self, tmp_path: Path) -> None:
        """A sibling directory is scanned before the capped pointer verifies descendants."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        late_target = models_dir / "late.pkl"
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)
        dvc_file = tmp_path / "cli_directory_sibling.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/late.pkl\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(models_dir)), 0.0)

        assert resolved_paths == [str(models_dir), str(dvc_file)]

    def test_cli_directory_auto_defaults_preserve_capped_pointer(self, tmp_path: Path) -> None:
        """Directory auto-defaults apply before the capped pointer verifies coverage."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        source_target = models_dir / "payload.py"
        source_target.write_text("value = 1\n")
        dvc_file = tmp_path / "cli_directory_source_sibling.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/payload.py\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(models_dir)), 0.0)

        assert resolved_paths == [str(models_dir), str(dvc_file)]

    @pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics are required")
    def test_cli_keeps_pointer_for_directory_with_unwalked_symlink_subtree(self, tmp_path: Path) -> None:
        """A sibling directory must not cover content reachable only through a symlink."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        malicious = real_dir / "malicious.pkl"
        with malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "linked").symlink_to(real_dir, target_is_directory=True)
        dvc_file = tmp_path / "cli_symlinked_directory.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: bundle\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(bundle_dir)), 0.0)

        assert resolved_paths == [str(bundle_dir), str(dvc_file)]

    def test_cli_orders_under_limit_sibling_dvc_before_capped_pointer(self, tmp_path: Path) -> None:
        """An under-limit sibling pointer should establish concrete coverage first."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        late_target = tmp_path / "late.pkl"
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)
        capped_pointer = tmp_path / "capped.dvc"
        capped_pointer.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")
        sibling_pointer = tmp_path / "late.dvc"
        sibling_pointer.write_text("outs:\n- path: late.pkl\n")

        resolved_paths = _resolve_scan_paths((str(capped_pointer), str(sibling_pointer)), 0.0)

        assert resolved_paths == [str(sibling_pointer), str(capped_pointer)]

    def test_single_pointer_discharges_omitted_file_scanned_through_directory(self, tmp_path: Path) -> None:
        """A resolved first-window directory can cover an omitted descendant."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        late_target = models_dir / "late.pkl"
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        dvc_file = tmp_path / "directory_coverage.dvc"
        dvc_file.write_text("outs:\n- path: models\n" + "- path: benign.pkl\n" * 99 + "- path: models/late.pkl\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.success is True
        assert result.has_errors is False
        assert determine_exit_code(result) == 0
        assert any(asset.path == str(late_target) for asset in result.assets)
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_single_pointer_discharges_omitted_directory_scanned_through_parent(self, tmp_path: Path) -> None:
        """A resolved parent directory can cover an omitted nested directory."""
        models_dir = tmp_path / "models"
        nested_dir = models_dir / "nested"
        nested_dir.mkdir(parents=True)
        late_target = nested_dir / "late.pkl"
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        dvc_file = tmp_path / "nested_directory_coverage.dvc"
        dvc_file.write_text("outs:\n- path: models\n" + "- path: benign.pkl\n" * 99 + "- path: models/nested\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.success is True
        assert result.has_errors is False
        assert determine_exit_code(result) == 0
        assert any(asset.path == str(late_target) for asset in result.assets)
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_canonical_tail_aliases_count_as_one_covered_output(self, tmp_path: Path) -> None:
        """Lexical aliases of one target must not inflate the verification budget."""
        benign = tmp_path / "benign.pkl"
        late_target = tmp_path / "late.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)
        aliases = ["late.pkl", "./late.pkl", ".//late.pkl", ".///late.pkl", ".////late.pkl"]
        dvc_file = tmp_path / "canonical_aliases.dvc"
        dvc_file.write_text(
            "outs:\n" + "- path: benign.pkl\n" * 200 + "".join(f"- path: {alias}\n" for alias in aliases)
        )

        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert resolution.unverified_omitted_output_count == 1
        assert result.success is True
        assert determine_exit_code(result) == 0
        assert not any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_duplicate_directory_tail_is_verified_once(self, tmp_path: Path) -> None:
        """Duplicate tail declarations must not repeat recursive coverage work."""
        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        directory = tmp_path / "models"
        directory.mkdir()
        dvc_file = tmp_path / "duplicate_directory_tail.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 200 + "- path: models\n" * 1000)
        resolution = resolve_dvc_file_with_metadata(str(dvc_file))
        verified: list[Path] = []

        def record_covered(target: Path) -> bool:
            verified.append(target)
            return True

        covered = dvc_omitted_outputs_covered(
            str(dvc_file),
            resolution,
            record_covered,
            coverage_budget=1,
        )

        assert covered is True
        assert verified == [directory]

    def test_cli_orders_unique_tail_sibling_before_duplicate_padded_pointer(self, tmp_path: Path) -> None:
        """A unique late sibling should be scanned before the capped pointer verifies it."""
        from modelaudit.cli import _resolve_scan_paths

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        late_target = tmp_path / "late.pkl"
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)

        dvc_file = tmp_path / "cli_duplicate_padding.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 200 + "- path: late.pkl\n")

        resolved_paths = _resolve_scan_paths((str(dvc_file), str(late_target)), 0.0)

        assert resolved_paths == [str(late_target), str(dvc_file)]

    def test_over_limit_dvc_recurses_into_resolved_directory_output(self, tmp_path: Path) -> None:
        """Preserving an over-limit pointer must still recurse into directories in the scanned window."""
        model_dir = tmp_path / "model_dir"
        model_dir.mkdir()
        nested_malicious = model_dir / "nested_malicious.pkl"
        with nested_malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)

        dvc_lines = ["outs:", f"- path: {model_dir.name}"]
        for index in range(99):
            target = tmp_path / f"benign_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            dvc_lines.append(f"- path: {target.name}")
        late_target = tmp_path / "late.pkl"
        with late_target.open("wb") as f:
            pickle.dump({"late": True}, f)
        dvc_lines.append(f"- path: {late_target.name}")

        dvc_file = tmp_path / "directory_first.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 100
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 1
        assert any(
            issue.rule_code == "S201" and issue.location is not None and str(nested_malicious) in issue.location
            for issue in result.issues
        )
        assert any(issue.type == "dvc_output_limit_exceeded" for issue in result.issues)

    def test_over_limit_dvc_directory_output_keeps_tail_directory_incomplete_after_sibling_gap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An incomplete directory scan must not blanket-cover a tail subdirectory."""
        model_dir = tmp_path / "model_dir"
        covered_subdir = model_dir / "covered"
        covered_subdir.mkdir(parents=True)
        covered_payload = covered_subdir / "covered.pkl"
        covered_payload.write_bytes(pickle.dumps({"covered": True}))
        malicious = model_dir / "malicious.pkl"
        malicious.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        incomplete = model_dir / "incomplete.pkl"
        incomplete.write_bytes(pickle.dumps({"incomplete": True}))
        _patch_metadata_only_incomplete_scan(monkeypatch, incomplete.name)

        dvc_lines = ["outs:", f"- path: {model_dir.name}"]
        for index in range(99):
            target = tmp_path / f"benign_{index:03}.pkl"
            target.write_bytes(pickle.dumps({"index": index}))
            dvc_lines.append(f"- path: {target.name}")
        dvc_lines.append(f"- path: {model_dir.name}/{covered_subdir.name}")
        dvc_file = tmp_path / "covered_subdir_tail.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 102
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(
            issue.rule_code == "S201" and issue.location is not None and str(malicious) in issue.location
            for issue in result.issues
        )
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)
        assert result.file_metadata[str(incomplete)]["analysis_incomplete"] is True
        assert "synthetic_metadata_only_incomplete" in result.file_metadata[str(incomplete)]["scan_outcome_reasons"]

    def test_directory_dvc_limit_does_not_credit_metadata_only_incomplete_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A metadata-only incomplete sibling cannot suppress a capped DVC gap."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        _patch_metadata_only_incomplete_scan(monkeypatch, late.name)
        dvc_file = tmp_path / "capped.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.files_scanned == 2
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert result.file_metadata[str(late)]["analysis_incomplete"] is True
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_directory_dvc_limit_does_not_credit_issue_only_incomplete_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An issue-only incomplete sibling cannot suppress a capped DVC gap."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        _patch_issue_only_incomplete_scan(monkeypatch, late.name)
        dvc_file = tmp_path / "capped.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

        assert result.files_scanned == 2
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_duplicate_only_output_limit_is_complete(self, tmp_path: Path) -> None:
        """A capped tail containing only duplicate declarations adds no coverage gap."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"safe": True}, f)

        dvc_file = tmp_path / "excessive.dvc"
        dvc_file.write_text("outs:\n" + "- path: model.pkl\n" * 101)

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == (str(target),)
        assert resolution.omitted_output_count == 1
        assert resolution.analysis_incomplete is False
        assert resolution.incomplete_reason is None

        results = scan_model_directory_or_file(str(dvc_file))

        assert results.files_scanned == 1
        assert results.has_errors is False
        assert results.success is True
        assert not any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in results.issues)

    def test_partially_materialized_directory_output_fails_closed(self, tmp_path: Path) -> None:
        """Declared DVC file and byte lower bounds must not be silently underfilled."""

        class MaliciousClass:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                return (os.system, ("echo dvc-partial-materialization",))

        output_dir = tmp_path / "model"
        output_dir.mkdir()
        payload = output_dir / "payload.pkl"
        payload.write_bytes(pickle.dumps(MaliciousClass()))
        dvc_file = tmp_path / "partial.dvc"
        dvc_file.write_text(f"outs:\n- path: model\n  size: {payload.stat().st_size + 100}\n  nfiles: 2\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file))

        assert resolution.resolved_paths == (str(output_dir),)
        assert resolution.analysis_incomplete is True
        assert result.files_scanned == 1
        assert any(Path(asset.path) == payload for asset in result.assets)
        assert result.has_errors is True
        assert result.success is False
        assert result.content_hash is None

    def test_duplicate_outputs_are_scanned_once_without_budget_error(self, tmp_path: Path) -> None:
        """Repeated declarations should not consume scan or budget twice."""
        target = tmp_path / "model.pkl"
        target.write_bytes(pickle.dumps({"payload": "x" * 30}))
        dvc_file = tmp_path / "duplicate.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n- path: model.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        results = scan_model_directory_or_file(str(dvc_file), max_total_size=target.stat().st_size)

        assert resolution.resolved_paths == (str(target),)
        assert results.files_scanned == 1
        assert results.bytes_scanned == target.stat().st_size
        assert results.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in results.issues
        )

    def test_hardlink_output_aliases_are_scanned_once_without_budget_error(self, tmp_path: Path) -> None:
        """Hardlink aliases should not consume scan or budget twice."""
        target = tmp_path / "model.pkl"
        alias = tmp_path / "model-alias.pkl"
        target.write_bytes(pickle.dumps({"payload": "x" * 30}))
        try:
            alias.hardlink_to(target)
        except OSError as exc:
            pytest.skip(f"hardlink creation unavailable: {exc}")
        dvc_file = tmp_path / "hardlink-alias.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n- path: model-alias.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        results = scan_model_directory_or_file(str(dvc_file), max_total_size=target.stat().st_size)

        assert resolution.resolved_paths == (str(target),)
        assert results.files_scanned == 1
        assert results.bytes_scanned == target.stat().st_size
        assert results.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in results.issues
        )

    @pytest.mark.parametrize(
        "outputs",
        [
            ["model", "model/model.pkl"],
            ["model/model.pkl", "model"],
        ],
    )
    def test_overlapping_directory_and_file_outputs_are_scanned_once(
        self,
        tmp_path: Path,
        outputs: list[str],
    ) -> None:
        """Directory and child declarations must not consume the shared budget twice."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        target = output_dir / "model.pkl"
        target.write_bytes(pickle.dumps({"payload": "x" * 30}))
        dvc_file = tmp_path / "overlap.dvc"
        dvc_file.write_text("outs:\n" + "".join(f"- path: {output}\n" for output in outputs))

        result = scan_model_directory_or_file(str(dvc_file), max_total_size=target.stat().st_size)

        assert result.files_scanned == 1
        assert result.bytes_scanned == target.stat().st_size
        assert result.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in result.issues
        )

    def test_scanner_expanded_shards_are_not_rescanned_by_overlapping_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A direct shard scan must cover its siblings for later DVC output deduplication."""
        output_dir = tmp_path / "model"
        output_dir.mkdir()
        shards = [
            output_dir / "model-00001-of-00002.safetensors",
            output_dir / "model-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(b"0123456789")
        dvc_file = tmp_path / "overlap.dvc"
        dvc_file.write_text(f"outs:\n- path: model/{shards[0].name}\n- path: model\n")
        calls: list[str] = []

        def fake_scan_file(path: str, config: dict[str, Any]) -> ScanResult:
            calls.append(path)
            result = ScanResult(scanner_name="safetensors")
            result.bytes_scanned = sum(shard.stat().st_size for shard in shards)
            result.add_check(
                name="Sharded Model Detection",
                passed=True,
                message="Detected sharded model",
                details={"shards": [str(shard) for shard in shards]},
            )
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(
            str(dvc_file),
            max_total_size=sum(shard.stat().st_size for shard in shards),
        )

        assert calls == [str(shards[0])]
        assert result.bytes_scanned == sum(shard.stat().st_size for shard in shards)
        assert result.success is True
        assert not any(
            issue.details.get("scan_outcome_reason") == "dvc_scan_budget_exhausted" for issue in result.issues
        )

    def test_direct_dvc_incomplete_shard_scan_does_not_cover_omitted_shard(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct DVC scans must not credit omitted shards from incomplete shard-family details."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        first_shard = model_dir / "model-00001-of-00002.safetensors"
        second_shard = model_dir / "model-00002-of-00002.safetensors"
        benign = tmp_path / "benign.pkl"
        first_shard.write_bytes(b"first")
        second_shard.write_bytes(b"second")
        benign.write_bytes(pickle.dumps({"safe": True}))
        dvc_file = tmp_path / "shards.dvc"
        dvc_file.write_text(
            "outs:\n"
            f"- path: model/{first_shard.name}\n" + "- path: benign.pkl\n" * 99 + f"- path: model/{second_shard.name}\n"
        )
        original_scan_file = core_module.scan_file

        def fake_scan_file(path: str, config: dict[str, Any]) -> ScanResult:
            if path != str(first_shard):
                return original_scan_file(path, config)
            result = ScanResult(scanner_name="safetensors")
            result.bytes_scanned = first_shard.stat().st_size
            result.add_check(
                name="Sharded Model Detection",
                passed=True,
                message="Detected sharded model",
                details={"shards": [str(first_shard), str(second_shard)]},
            )
            result.add_check(
                name="Shard Scan",
                passed=False,
                message="Error scanning shard",
                severity=IssueSeverity.INFO,
                location=str(second_shard),
                details={
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_scan_error",
                },
            )
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.files_scanned == 2
        assert result.success is False
        assert determine_exit_code(result) == 2
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_direct_dvc_ambiguous_multifamily_shard_failure_preserves_complete_family_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ambiguous multi-family shard failures must not poison complete sibling families."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        complete_first = model_dir / "complete-00001-of-00002.safetensors"
        complete_second = model_dir / "complete-00002-of-00002.safetensors"
        failed_first = model_dir / "failed-00001-of-00002.safetensors"
        failed_second = model_dir / "failed-00002-of-00002.safetensors"
        for shard_path in (complete_first, complete_second, failed_first, failed_second):
            shard_path.write_bytes(b"shard")
        dvc_file = tmp_path / "multifamily.dvc"
        dvc_file.write_text(f"outs:\n- path: model/{complete_first.name}\n- path: model/{complete_second.name}\n")
        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_OUTPUTS", 1)
        original_scan_file = core_module.scan_file

        def fake_scan_file(path: str, config: dict[str, Any]) -> ScanResult:
            if path != str(complete_first):
                return original_scan_file(path, config)
            result = ScanResult(scanner_name="safetensors")
            result.bytes_scanned = complete_first.stat().st_size
            result.add_check(
                name="Sharded Model Detection",
                passed=True,
                message="Detected complete sharded model",
                details={"shards": [str(complete_first), str(complete_second)]},
            )
            result.add_check(
                name="Sharded Model Detection",
                passed=True,
                message="Detected unrelated incomplete sharded model",
                details={"shards": [str(failed_first), str(failed_second)]},
            )
            result.add_check(
                name="Shard Scan",
                passed=False,
                message="Error scanning shard without retained path",
                severity=IssueSeverity.INFO,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_scan_error",
                },
            )
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        result = scan_model_directory_or_file(str(dvc_file), cache_enabled=False)

        assert result.success is False
        assert determine_exit_code(result) == 2
        assert not any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_duplicate_yaml_keys_mark_pointer_incomplete(self, tmp_path: Path) -> None:
        """Duplicate outs mappings must not discard an earlier hidden declaration."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"benign": True}))
        dvc_file = tmp_path / "duplicate-keys.dvc"
        dvc_file.write_text("outs:\n- path: hidden.pkl\nouts:\n- path: benign.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        results = scan_model_directory_or_file(str(dvc_file))

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == "dvc_parse_failed"
        assert results.files_scanned == 0
        assert results.success is False
        assert results.has_errors is True

    def test_oversized_pointer_marks_resolution_incomplete(self, tmp_path: Path) -> None:
        """Pointer metadata reads should be bounded before YAML parsing."""
        dvc_file = tmp_path / "oversized.dvc"
        with dvc_file.open("wb") as handle:
            handle.truncate(MAX_DVC_POINTER_BYTES + 1)

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == DVC_POINTER_TOO_LARGE_REASON

    def test_uppercase_dvc_pointer_fails_closed(self, tmp_path: Path) -> None:
        """Pointer routing should not depend on extension case."""
        dvc_file = tmp_path / "hidden.DVC"
        dvc_file.write_text("outs:\n- path: hidden.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        direct = scan_model_directory_or_file(str(dvc_file))
        directory = scan_model_directory_or_file(str(tmp_path))

        assert resolution.analysis_incomplete is True
        for results in (direct, directory):
            assert results.files_scanned == 0
            assert results.success is False
            assert results.has_errors is True
            assert any(
                issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON for issue in results.issues
            )

    def test_non_mapping_dvc_document_marks_resolution_incomplete(self, tmp_path: Path) -> None:
        """Valid YAML with an invalid top-level shape should fail closed."""
        dvc_file = tmp_path / "sequence.dvc"
        dvc_file.write_text("- outs\n")

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == "dvc_invalid_structure"

    @pytest.mark.parametrize("output_path", ["", ".", "./"])
    def test_self_referential_dvc_directory_output_is_unresolved(
        self,
        tmp_path: Path,
        output_path: str,
    ) -> None:
        """A pointer must not recursively expand the directory containing itself."""
        dvc_file = tmp_path / "recursive.dvc"
        dvc_file.write_text(f"outs:\n- path: {output_path!r}\n")

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == DVC_ANALYSIS_INCOMPLETE_REASON

    def test_relative_pointer_rejects_self_referential_directory_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Relative pointer paths must use the same self-reference check as absolute paths."""
        dvc_file = tmp_path / "recursive.dvc"
        dvc_file.write_text("outs:\n- path: '.'\n")
        monkeypatch.chdir(tmp_path)

        resolution = resolve_dvc_file_status(dvc_file.name)

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == DVC_ANALYSIS_INCOMPLETE_REASON

    def test_pointer_file_output_is_unresolved(self, tmp_path: Path) -> None:
        """A pointer must not scan itself or another pointer as harmless artifact text."""
        self_pointer = tmp_path / "self.dvc"
        self_pointer.write_text("outs:\n- path: self.dvc\n")
        nested_pointer = tmp_path / "nested.dvc"
        nested_pointer.write_text("outs:\n- path: payload.pkl\n")
        outer_pointer = tmp_path / "outer.dvc"
        outer_pointer.write_text("outs:\n- path: nested.dvc\n")

        for pointer in (self_pointer, outer_pointer):
            resolution = resolve_dvc_file_status(str(pointer))
            results = scan_model_directory_or_file(str(pointer))

            assert resolution.resolved_paths == ()
            assert resolution.analysis_incomplete is True
            assert resolution.incomplete_reason == DVC_ANALYSIS_INCOMPLETE_REASON
            assert results.files_scanned == 0
            assert results.success is False
            assert results.has_errors is True
            assert any(
                issue.details.get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON for issue in results.issues
            )

    def test_hardlink_to_pointer_is_unresolved(self, tmp_path: Path) -> None:
        """A hardlink must not disguise the pointer itself as an artifact."""
        dvc_file = tmp_path / "self.dvc"
        alias = tmp_path / "model.pkl"
        dvc_file.write_text("outs:\n- path: model.pkl\n")
        try:
            alias.hardlink_to(dvc_file)
        except OSError as exc:
            pytest.skip(f"hardlink creation unavailable: {exc}")

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == DVC_ANALYSIS_INCOMPLETE_REASON

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
    def test_non_regular_output_is_unresolved(self, tmp_path: Path) -> None:
        """Special files must never reach hashing or scanner dispatch."""
        fifo = tmp_path / "model.pkl"
        dvc_file = tmp_path / "fifo.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")
        os.mkfifo(fifo)

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == ()
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == DVC_ANALYSIS_INCOMPLETE_REASON

    def test_symlinked_pointer_keeps_outputs_confined_to_link_directory(self, tmp_path: Path) -> None:
        """A pointer symlink must not move output resolution to the target directory."""
        safe_dir = tmp_path / "safe"
        outside_dir = tmp_path / "outside"
        safe_dir.mkdir()
        outside_dir.mkdir()
        outside_artifact = outside_dir / "secret.pkl"
        outside_artifact.write_bytes(pickle.dumps({"outside": True}))
        real_pointer = outside_dir / "real.dvc"
        real_pointer.write_text("outs:\n- path: secret.pkl\n")
        link_pointer = safe_dir / "link.dvc"
        try:
            link_pointer.symlink_to(real_pointer)
        except OSError as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")

        resolution = resolve_dvc_file_status(str(link_pointer))
        results = scan_model_directory_or_file(str(link_pointer))

        assert str(outside_artifact) not in resolution.resolved_paths
        assert resolution.analysis_incomplete is True
        assert results.files_scanned == 0
        assert results.success is False
        assert results.has_errors is True

    def test_malformed_dvc_file_handling(self, tmp_path):
        """Test handling of malformed DVC files."""
        test_cases = [
            ("", "empty file"),
            ("invalid: yaml: content:", "invalid YAML"),
            ("outs: not_a_list", "outs not a list"),
            ("outs:\n- invalid_entry", "invalid output entry"),
            ("outs:\n- path: 123", "non-string path"),
            ("no_outs_key: true", "missing outs key"),
        ]

        for content, description in test_cases:
            dvc_file = tmp_path / f"malformed_{description.replace(' ', '_')}.dvc"
            dvc_file.write_text(content)

            resolved = resolve_dvc_file(str(dvc_file))
            assert resolved == [], f"Should handle {description} gracefully"

    def test_special_characters_in_paths(self, tmp_path):
        """Test handling of special characters in DVC paths."""
        # Create files with special characters
        special_files = [
            "model with spaces.pkl",
            "model-with-dashes.pkl",
            "model_with_underscores.pkl",
            "model.with.dots.pkl",
        ]

        for filename in special_files:
            file_path = tmp_path / filename
            with file_path.open("wb") as f:
                pickle.dump({"name": filename}, f)

        # Create DVC file
        dvc_content = "outs:\n"
        for filename in special_files:
            dvc_content += f"- path: {filename}\n"

        dvc_file = tmp_path / "special_chars.dvc"
        dvc_file.write_text(dvc_content)

        resolved = resolve_dvc_file(str(dvc_file))
        assert len(resolved) == len(special_files)

    def test_non_dvc_file_ignored(self, tmp_path):
        """Test that non-DVC files are ignored."""
        regular_file = tmp_path / "not_dvc.txt"
        regular_file.write_text("outs:\n- path: something.pkl\n")

        resolved = resolve_dvc_file(str(regular_file))
        assert resolved == []

    def test_missing_yaml_dependency(self, tmp_path, monkeypatch):
        """Test graceful handling when PyYAML is not available."""
        # Mock yaml import to fail
        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named 'yaml'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", mock_import)

        dvc_file = tmp_path / "test.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")

        resolved = resolve_dvc_file(str(dvc_file))
        assert resolved == []

    def test_dvc_with_malicious_pickle(self, tmp_path):
        """Test that DVC integration doesn't bypass security scanning."""
        # Create a malicious pickle file
        malicious_pickle = tmp_path / "malicious.pkl"

        # Create a pickle with suspicious content
        class MaliciousClass:
            def __reduce__(self):
                import os

                return (os.system, ("echo 'malicious code'",))

        with malicious_pickle.open("wb") as f:
            pickle.dump(MaliciousClass(), f)

        # Create DVC file pointing to malicious pickle
        dvc_file = tmp_path / "malicious.dvc"
        dvc_file.write_text("outs:\n- path: malicious.pkl\n")

        # Scan through DVC file
        results = scan_model_directory_or_file(str(dvc_file))

        # Should detect the malicious content
        assert results["files_scanned"] == 1
        assert len(results["issues"]) > 0

        # Should have security-related issues
        security_issues = [
            issue
            for issue in results["issues"]
            if any(keyword in issue.message.lower() for keyword in ["malicious", "suspicious", "security", "dangerous"])
        ]
        assert len(security_issues) > 0


class TestDvcCliIntegration:
    """Test DVC integration through CLI."""

    def test_cli_sibling_coverage_avoids_false_inconclusive_exit(self, tmp_path: Path) -> None:
        """A fully covered expanded argument list should complete without a DVC cap error."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        targets = []
        dvc_lines = ["outs:"]
        for index in range(101):
            target = tmp_path / f"model_{index:03}.pkl"
            with target.open("wb") as f:
                pickle.dump({"index": index}, f)
            targets.append(target)
            dvc_lines.append(f"- path: {target.name}")

        dvc_file = tmp_path / "cli_covered.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "--format", "json", str(dvc_file), *(str(target) for target in targets)],
        )

        assert result.exit_code == 0, result.output
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 101
        assert not any(issue.get("type") == "dvc_output_limit_exceeded" for issue in output_data["issues"])

    def test_cli_directory_sibling_scans_malicious_omitted_output(self, tmp_path: Path) -> None:
        """Directory coverage must still surface a malicious omitted descendant."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        benign = tmp_path / "benign.pkl"
        with benign.open("wb") as f:
            pickle.dump({"benign": True}, f)
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        malicious = models_dir / "malicious.pkl"
        with malicious.open("wb") as f:
            pickle.dump(_LateMaliciousPayload(), f)
        dvc_file = tmp_path / "cli_directory_sibling.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/malicious.pkl\n")

        result = CliRunner().invoke(
            cli,
            ["scan", "--format", "json", str(dvc_file), str(models_dir)],
        )

        assert result.exit_code == 1, result.output
        output_data = json.loads(result.output)
        assert any(issue.get("rule_code") == "S201" for issue in output_data["issues"])
        assert not any(issue.get("type") == "dvc_output_limit_exceeded" for issue in output_data["issues"])

    def test_cli_directory_prior_coverage_survives_findings_and_incomplete_siblings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Prior directory coverage should record complete files even when aggregate success is false."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        models_dir = tmp_path / "models"
        models_dir.mkdir()
        malicious = models_dir / "malicious.pkl"
        malicious.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        incomplete = models_dir / "incomplete.pkl"
        incomplete.write_bytes(pickle.dumps({"incomplete": True}))
        _patch_metadata_only_incomplete_scan(monkeypatch, incomplete.name)
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        dvc_file = tmp_path / "cli_directory_first.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/malicious.pkl\n")

        result = CliRunner().invoke(
            cli,
            ["scan", str(models_dir), str(dvc_file), "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 1, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert output_data["success"] is False
        assert output_data["file_metadata"][str(incomplete)]["analysis_incomplete"] is True
        assert any(
            issue.get("rule_code") == "S201" and issue.get("location") and str(malicious) in issue["location"]
            for issue in output_data["issues"]
        )
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_incomplete_directory_prior_coverage_does_not_cover_tail_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Prior incomplete directory scans must not blanket-cover capped DVC tail directories."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        models_dir = tmp_path / "models"
        covered_dir = models_dir / "covered"
        covered_dir.mkdir(parents=True)
        covered_payload = covered_dir / "covered.pkl"
        covered_payload.write_bytes(pickle.dumps({"covered": True}))
        incomplete = models_dir / "incomplete.pkl"
        incomplete.write_bytes(pickle.dumps({"incomplete": True}))
        _patch_metadata_only_incomplete_scan(monkeypatch, incomplete.name)
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        dvc_file = tmp_path / "cli_directory_tail.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/covered\n")

        result = CliRunner().invoke(
            cli,
            ["scan", str(models_dir), str(dvc_file), "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 2, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert output_data["success"] is False
        assert output_data["file_metadata"][str(incomplete)]["analysis_incomplete"] is True
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    @pytest.mark.parametrize(
        "shard_failure_details",
        [
            {
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "shard_scan_error",
            },
            {
                "component_count": 2,
                "findings": [
                    {
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "shard_scan_error",
                    },
                ],
            },
        ],
    )
    def test_cli_incomplete_shard_prior_coverage_keeps_capped_dvc_gap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        shard_failure_details: dict[str, Any],
    ) -> None:
        """An incomplete prior shard-family scan must not cover omitted DVC shard outputs."""
        from click.testing import CliRunner

        from modelaudit import cli as cli_module
        from modelaudit.cli import cli
        from modelaudit.models import AssetModel

        model_dir = tmp_path / "model"
        model_dir.mkdir()
        first_shard = model_dir / "model-00001-of-00002.safetensors"
        second_shard = model_dir / "model-00002-of-00002.safetensors"
        first_shard.write_bytes(b"first")
        second_shard.write_bytes(b"second")
        dvc_file = tmp_path / "shards.dvc"
        dvc_file.write_text(f"outs:\n- path: model/{first_shard.name}\n- path: model/{second_shard.name}\n")
        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_OUTPUTS", 1)

        incomplete_shard_result = create_initial_audit_result()
        incomplete_shard_result.success = False
        incomplete_shard_result.assets.append(AssetModel(path=str(first_shard), type="safetensors"))
        incomplete_shard_result.checks.append(
            Check(
                name="Sharded Model Detection",
                status=CheckStatus.PASSED,
                message="Detected sharded model",
                details={"shards": [str(first_shard), str(second_shard)]},
            )
        )
        incomplete_shard_result.checks.append(
            Check(
                name="Shard Scan",
                status=CheckStatus.FAILED,
                message="Error scanning shard",
                location=str(second_shard),
                details=shard_failure_details,
            )
        )
        original_scan = cli_module.scan_model_directory_or_file

        def fake_scan_model_directory_or_file(path: str, *args: Any, **kwargs: Any) -> Any:
            if path == str(first_shard):
                return incomplete_shard_result
            return original_scan(path, *args, **kwargs)

        monkeypatch.setattr(cli_module, "scan_model_directory_or_file", fake_scan_model_directory_or_file)

        result = CliRunner().invoke(
            cli,
            ["scan", str(first_shard), str(dvc_file), "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 2, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert output_data["success"] is False
        assert output_data["has_errors"] is False
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_dvc_file_expansion(self, tmp_path: Path) -> None:
        """Test that CLI properly expands DVC files."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        # Create target file
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"cli_test": True}, f)

        # Create DVC file
        dvc_file = tmp_path / "model.pkl.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(dvc_file), "--format", "json"])

        assert result.exit_code in [0, 1]  # 0 for clean, 1 for issues found

        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 1

    def test_cli_sibling_file_discharges_output_cap_after_actual_scan(self, tmp_path: Path) -> None:
        """A completed sibling scan can prove coverage without expanding the pointer."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(cli, ["scan", str(dvc_file), str(late), "--format", "json", "--no-cache"])

        assert result.exit_code == 0
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 2
        assert output_data["success"] is True
        assert output_data["has_errors"] is False
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    @pytest.mark.parametrize("record_kind", ["issue", "check"])
    def test_cli_capped_pointer_rejects_detail_only_incomplete_sibling_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        record_kind: str,
    ) -> None:
        """A detail-only incomplete sibling scan must not cover an omitted DVC output."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")
        _patch_detail_only_incomplete_scan(monkeypatch, late.name, record_kind=record_kind)

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(cli, ["scan", str(dvc_file), str(late), "--format", "json", "--no-cache"])

        assert result.exit_code == 2, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert output_data["files_scanned"] == 2
        assert output_data["success"] is False
        assert output_data["has_errors"] is False
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])
        detail_records = output_data["issues"] if record_kind == "issue" else output_data["checks"]
        assert any(
            record.get("details", {}).get("scan_outcome_reason") == "synthetic_detail_only_incomplete"
            for record in detail_records
        )

    def test_cli_capped_pointer_accepts_clean_detail_sibling_coverage(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A clean sibling with benign details should still cover an omitted DVC output."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")
        _patch_clean_detail_scan(monkeypatch, late.name)

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(cli, ["scan", str(dvc_file), str(late), "--format", "json", "--no-cache"])

        assert result.exit_code == 0, result.output
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 2
        assert output_data["success"] is True
        assert output_data["has_errors"] is False
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])
        assert any(check.get("name") == "Synthetic Clean Coverage" for check in output_data["checks"])

    def test_cli_sibling_malicious_file_is_reported_when_cap_is_discharged(self, tmp_path: Path) -> None:
        """Coverage reconciliation must preserve findings from the late output."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(cli, ["scan", str(dvc_file), str(late), "--format", "json", "--no-cache"])

        assert result.exit_code == 1
        output_data = json.loads(result.output)
        assert any(issue.get("location") and str(late) in issue["location"] for issue in output_data["issues"])
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_scanner_selection_does_not_credit_excluded_sibling(self, tmp_path: Path) -> None:
        """An explicit sibling is not coverage when the selected scanner cannot analyze it."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.yaml"
        late.write_text("framework: pytorch\n")
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.yaml\n")

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), str(late), "--scanners", "pickle", "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 2
        output_data = json.loads(result.output)
        assert output_data["success"] is False
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_scanner_selection_does_not_credit_excluded_directory_descendant(
        self,
        tmp_path: Path,
    ) -> None:
        """A walked directory is not coverage for descendants excluded by scanner selection."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        excluded = models_dir / "metadata.yaml"
        excluded.write_text("framework: pytorch\n")
        dvc_file = tmp_path / "late-directory-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/metadata.yaml\n")

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "scan",
                str(dvc_file),
                str(models_dir),
                "--scanners",
                "pickle",
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 2, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert output_data["success"] is False
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_scanner_selection_credits_and_reports_selected_directory_descendant(
        self,
        tmp_path: Path,
    ) -> None:
        """A selected malicious descendant discharges the cap without hiding its finding."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        malicious = models_dir / "payload.pkl"
        malicious.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        dvc_file = tmp_path / "selected-directory-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/payload.pkl\n")

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "scan",
                str(dvc_file),
                str(models_dir),
                "--scanners",
                "pickle",
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 1, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert any(
            issue.get("rule_code") == "S201" and issue.get("location") and str(malicious) in issue["location"]
            for issue in output_data["issues"]
        )
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_strict_mode_does_not_override_scanner_selection_for_coverage(self, tmp_path: Path) -> None:
        """Strict filtering cannot make a file covered when its scanner remains excluded."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        excluded = tmp_path / "payload.py"
        excluded.write_text("value = 1\n")
        dvc_file = tmp_path / "strict-selected-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: payload.py\n")

        from click.testing import CliRunner

        from modelaudit.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "scan",
                str(dvc_file),
                str(excluded),
                "--strict",
                "--scanners",
                "pickle",
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 2, result.output
        output_data = json.loads(result.output[result.output.index("{") :])
        assert output_data["success"] is False
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_unresolved_dvc_output_exits_operational_error_with_json(self, tmp_path: Path) -> None:
        """CLI scans should surface unresolved DVC outputs as incomplete coverage."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        dvc_file = tmp_path / "missing.dvc"
        dvc_file.write_text("""outs:
- path: hidden_payload.pkl
""")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(dvc_file), "--format", "json"])

        assert result.exit_code == 2
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 0
        assert output_data["has_errors"] is True
        assert output_data["success"] is False
        assert any(
            issue["details"].get("scan_outcome_reason") == DVC_ANALYSIS_INCOMPLETE_REASON
            and any("hidden_payload.pkl" in path for path in issue["details"]["unresolved_outputs"])
            for issue in output_data["issues"]
        )

    def test_cli_capped_pointer_uses_actual_sibling_coverage(self, tmp_path: Path) -> None:
        """A scanned sibling should discharge the cap without expanding the pointer."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        benign = tmp_path / "benign.pkl"
        late_target = tmp_path / "late.pkl"
        benign.write_bytes(pickle.dumps({"benign": True}))
        late_target.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "capped.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), str(late_target), "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 0
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 2
        assert output_data["success"] is True
        assert output_data["has_errors"] is False
        assert output_data.get("content_hash") is None
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_streamed_directory_sibling_covers_omitted_output(self, tmp_path: Path) -> None:
        """Streaming a sibling directory should provide concrete DVC coverage."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"benign": True}))
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        nested_target = models_dir / "nested.pkl"
        nested_target.write_bytes(pickle.dumps({"nested": True}))
        dvc_file = tmp_path / "streamed-directory.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: models/nested.pkl\n")

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), str(models_dir), "--stream", "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 0
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 2
        assert output_data["success"] is True
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_capped_pointer_respects_runtime_filtering_for_sibling_coverage(self, tmp_path: Path) -> None:
        """A filtered sibling covers an omitted output only when strict mode scans it."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        benign = tmp_path / "benign.pkl"
        source_target = tmp_path / "payload.py"
        benign.write_bytes(pickle.dumps({"benign": True}))
        source_target.write_text("value = 1\n")
        dvc_file = tmp_path / "filtered-sibling.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: payload.py\n")

        default_result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), str(source_target), "--format", "json", "--no-cache"],
        )
        strict_result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), str(source_target), "--strict", "--format", "json", "--no-cache"],
        )

        assert default_result.exit_code == 2
        default_output = json.loads(default_result.output)
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in default_output["issues"])

        assert strict_result.exit_code == 0
        strict_output = json.loads(strict_result.output)
        assert strict_output["files_scanned"] == 2
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in strict_output["issues"])

    def test_cli_capped_pointer_preserves_shared_total_size_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sibling coverage must not split capped DVC outputs into fresh per-file budgets."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        monkeypatch.setattr("modelaudit.utils.sources.dvc.MAX_DVC_OUTPUTS", 2)
        first = tmp_path / "first.pkl"
        second = tmp_path / "second.pkl"
        sibling = tmp_path / "sibling.pkl"
        for target, value in ((first, "first"), (second, "second"), (sibling, "sibling")):
            target.write_bytes(pickle.dumps({"payload": value * 20}))
        max_size = max(first.stat().st_size, second.stat().st_size, sibling.stat().st_size)
        assert first.stat().st_size + second.stat().st_size > max_size

        dvc_file = tmp_path / "budgeted-capped.dvc"
        dvc_file.write_text("outs:\n- path: first.pkl\n- path: second.pkl\n- path: sibling.pkl\n")

        result = CliRunner().invoke(
            cli,
            [
                "scan",
                str(dvc_file),
                str(sibling),
                "--max-size",
                f"{max_size}B",
                "--format",
                "json",
                "--no-cache",
            ],
        )

        assert result.exit_code == 2
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 2
        assert output_data["success"] is False
        assert output_data["has_errors"] is True
        assert any(
            issue["details"].get("scan_outcome_reason") == "dvc_scan_budget_exhausted"
            and issue["details"].get("budget_type") == "total_size"
            for issue in output_data["issues"]
        )
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_partial_dvc_directory_output_scans_nested_payload(self, tmp_path: Path) -> None:
        """CLI partial DVC scans should traverse resolved directory outputs."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        class MaliciousClass:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                import os

                return (os.system, ("echo dvc-cli-directory-malicious",))

        output_dir = tmp_path / "model"
        output_dir.mkdir()
        nested_payload = output_dir / "nested.pkl"
        with nested_payload.open("wb") as f:
            pickle.dump(MaliciousClass(), f)

        dvc_file = tmp_path / "partial-directory.dvc"
        dvc_file.write_text("""outs:
- path: model
- path: missing.pkl
""")

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(dvc_file), "--format", "json"])

        assert result.exit_code == 2
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 1
        assert any(Path(asset["path"]).name == nested_payload.name for asset in output_data["assets"])
        assert any("nested.pkl" in (issue.get("location") or "") for issue in output_data["issues"])

    def test_cli_resolved_outputs_share_total_size_budget(self, tmp_path: Path) -> None:
        """CLI scans must preserve the DVC pointer so core can share its total-size budget."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        first = tmp_path / "first.pkl"
        second = tmp_path / "second.pkl"
        first.write_bytes(pickle.dumps({"payload": "x" * 30}))
        second.write_bytes(pickle.dumps({"payload": "x" * 30}))
        assert first.stat().st_size < 100
        assert second.stat().st_size < 100
        assert first.stat().st_size + second.stat().st_size > 100
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: first.pkl\n- path: second.pkl\n")

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), "--max-size", "100B", "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 2
        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 1
        assert output_data["bytes_scanned"] == first.stat().st_size
        assert output_data["success"] is False
        assert output_data["has_errors"] is True
        assert output_data.get("content_hash") is None
        assert any(
            issue["details"].get("scan_outcome_reason") == "dvc_scan_budget_exhausted"
            and issue["details"].get("budget_type") == "total_size"
            for issue in output_data["issues"]
        )

    def test_cli_sbom_uses_resolved_dvc_artifact(self, tmp_path: Path) -> None:
        """SBOM output should name the scanned artifact rather than its DVC pointer."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        target = tmp_path / "model.pkl"
        target.write_bytes(pickle.dumps({"model": True}))
        dvc_file = tmp_path / "model.dvc"
        dvc_file.write_text("outs:\n- path: model.pkl\n")
        sbom_file = tmp_path / "model.sbom.json"

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), "--sbom", str(sbom_file), "--quiet", "--no-cache"],
        )

        assert result.exit_code == 0
        components = {component["name"] for component in json.loads(sbom_file.read_text())["components"]}
        assert target.name in components
        assert dvc_file.name not in components

    def test_cli_sbom_omits_fully_unresolved_dvc_pointer(self, tmp_path: Path) -> None:
        """An unscanned DVC pointer must not be emitted as an SBOM component."""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        dvc_file = tmp_path / "missing.dvc"
        dvc_file.write_text("outs:\n- path: missing.pkl\n")
        sbom_file = tmp_path / "missing.sbom.json"

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), "--sbom", str(sbom_file), "--quiet", "--no-cache"],
        )

        assert result.exit_code == 2
        components = json.loads(sbom_file.read_text()).get("components", [])
        assert not any(component["name"] == dvc_file.name for component in components)
