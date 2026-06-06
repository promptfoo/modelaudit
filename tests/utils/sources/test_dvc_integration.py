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
from modelaudit.models import ModelAuditResultModel, create_initial_audit_result
from modelaudit.scanner_results import Issue, IssueSeverity, ScanResult
from modelaudit.utils.sources.dvc import (
    DVC_ANALYSIS_INCOMPLETE_REASON,
    DVC_OUTPUT_LIMIT_EXCEEDED_REASON,
    DVC_POINTER_TOO_LARGE_REASON,
    MAX_DVC_POINTER_BYTES,
    dvc_omitted_outputs_covered,
    resolve_dvc_file,
    resolve_dvc_file_status,
)


class _LateMaliciousPayload:
    def __reduce__(self) -> tuple[Callable[[str], int], tuple[str]]:
        return (os.system, ("echo c085",))


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
        hf_home = tmp_path / ".cache" / "huggingface"
        monkeypatch.setenv("HF_HOME", str(hf_home))
        snapshots = hf_home / "hub" / "models--test" / "snapshots" / "abc"
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

    def test_resource_exhaustion_prevention(self, tmp_path):
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

    def test_duplicate_outputs_past_limit_are_discharged(self, tmp_path: Path) -> None:
        """Repeated declarations do not create an unscanned physical artifact."""
        target = tmp_path / "model.pkl"
        with target.open("wb") as f:
            pickle.dump({"safe": True}, f)

        dvc_file = tmp_path / "excessive.dvc"
        dvc_file.write_text("outs:\n" + "- path: model.pkl\n" * 101)

        resolution = resolve_dvc_file_status(str(dvc_file))

        assert resolution.resolved_paths == (str(target),)
        assert resolution.analysis_incomplete is True
        assert resolution.incomplete_reason == DVC_OUTPUT_LIMIT_EXCEEDED_REASON

        results = scan_model_directory_or_file(str(dvc_file))

        assert results.files_scanned == 1
        assert results.has_errors is False
        assert results.success is True
        assert not any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in results.issues)

    def test_unique_output_past_limit_fails_closed(self, tmp_path: Path) -> None:
        """A unique artifact after duplicate padding must remain an explicit gap."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late_malicious = tmp_path / "late-malicious.pkl"
        late_malicious.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late-malicious.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file))

        assert resolution.omitted_targets == (str(late_malicious),)
        assert str(late_malicious) not in {asset.path for asset in result.assets}
        assert result.has_errors is True
        assert result.success is False
        assert determine_exit_code(result) == 2
        cap_issue = next(issue for issue in result.issues if issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON)
        assert cap_issue.details["pointer_digest"] == resolution.pointer_digest
        assert cap_issue.details["resolved_outputs"] == list(resolution.resolved_paths)

        cached_result = scan_model_directory_or_file(
            str(dvc_file),
            cache_enabled=True,
            cache_dir=str(tmp_path / "cache"),
        )
        assert cached_result.success is False
        assert determine_exit_code(cached_result) == 2
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in cached_result.issues)

    def test_directory_scan_covers_and_detects_unique_late_output(self, tmp_path: Path) -> None:
        """Independent directory coverage discharges the cap without hiding findings."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late_malicious = tmp_path / "late-malicious.pkl"
        late_malicious.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late-malicious.pkl\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert determine_exit_code(result) == 1
        assert str(late_malicious) in {asset.path for asset in result.assets}
        assert any(issue.location and str(late_malicious) in issue.location for issue in result.issues)
        assert not any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_filtered_late_output_does_not_discharge_directory_coverage(self, tmp_path: Path) -> None:
        """A file skipped by the directory prefilter remains an unscanned output."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        skipped = tmp_path / "payload.py"
        skipped.write_text("print('not scanned')\n")
        dvc_file = tmp_path / "filtered-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: payload.py\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert determine_exit_code(result) == 2
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_duplicate_tail_past_verification_window_is_discharged(self, tmp_path: Path) -> None:
        """Duplicate padding after the bounded window cannot manufacture a gap."""
        target = tmp_path / "model.pkl"
        target.write_bytes(pickle.dumps({"safe": True}))
        dvc_file = tmp_path / "duplicate-tail.dvc"
        dvc_file.write_text("outs:\n" + "- path: model.pkl\n" * 250)

        resolution = resolve_dvc_file_status(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file))

        assert resolution.unverified_omitted_output_count == 0
        assert result.files_scanned == 1
        assert determine_exit_code(result) == 0
        assert not any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_unique_tail_past_verification_window_fails_closed(self, tmp_path: Path) -> None:
        """A new physical output after duplicate padding remains an unresolved gap."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        dvc_file = tmp_path / "unique-tail.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 200 + "- path: late.pkl\n")

        resolution = resolve_dvc_file_status(str(dvc_file))
        result = scan_model_directory_or_file(str(dvc_file))

        assert resolution.unverified_omitted_output_count == 1
        assert str(late) not in {asset.path for asset in result.assets}
        assert determine_exit_code(result) == 2
        assert any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_directory_scan_covers_tail_past_verification_window(self, tmp_path: Path) -> None:
        """Actual directory assets can prove coverage for the bounded unverified tail."""
        dvc_lines = ["outs:"]
        for index in range(205):
            target = tmp_path / f"model-{index:03}.pkl"
            target.write_bytes(pickle.dumps({"index": index}))
            dvc_lines.append(f"- path: {target.name}")
        dvc_file = tmp_path / "large-tail.dvc"
        dvc_file.write_text("\n".join(dvc_lines) + "\n")

        result = scan_model_directory_or_file(str(tmp_path))

        assert result.files_scanned == 205
        assert determine_exit_code(result) == 0
        assert not any(issue.type == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in result.issues)

    def test_coverage_revalidates_bounded_omitted_outputs(self, tmp_path: Path) -> None:
        """A same-count pointer rewrite cannot inherit stale coverage metadata."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        old_late = tmp_path / "old-late.pkl"
        old_late.write_bytes(pickle.dumps({"old": True}))
        new_late = tmp_path / "new-late.pkl"
        new_late.write_bytes(pickle.dumps(_LateMaliciousPayload()))
        dvc_file = tmp_path / "rewritten.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: old-late.pkl\n")
        resolution = resolve_dvc_file_status(str(dvc_file))
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: new-late.pkl\n")

        covered = dvc_omitted_outputs_covered(
            str(dvc_file),
            resolution,
            lambda target: target == old_late,
            coverage_budget=1,
        )

        assert covered is False

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

    def test_cli_benign_info_issue_does_not_become_operational_after_cap_discharge(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ordinary informational findings must not turn a completed scan into exit 2."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "late-output.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + "- path: late.pkl\n")

        from click.testing import CliRunner

        from modelaudit import cli as cli_module
        from modelaudit.cli import cli

        real_scan = cli_module.scan_model_directory_or_file

        def scan_with_info(path: str, *args: Any, **kwargs: Any) -> ModelAuditResultModel:
            result = real_scan(path, *args, **kwargs)
            if path == str(late):
                result.issues.append(
                    Issue(
                        message="Benign informational note",
                        severity=IssueSeverity.INFO,
                        location=path,
                    )
                )
            return result

        monkeypatch.setattr(cli_module, "scan_model_directory_or_file", scan_with_info)

        result = CliRunner().invoke(cli, ["scan", str(dvc_file), str(late), "--format", "json", "--no-cache"])

        assert result.exit_code == 0
        output_data = json.loads(result.output)
        assert output_data["success"] is True
        assert output_data["has_errors"] is False
        assert any(issue["message"] == "Benign informational note" for issue in output_data["issues"])
        assert not any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_pointer_rewrite_cannot_discharge_prior_output_cap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Coverage must remain bound to the DVC pointer that produced the cap issue."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        hidden = tmp_path / "hidden.pkl"
        hidden.write_bytes(pickle.dumps({"hidden": True}))
        late = tmp_path / "late.pkl"
        late.write_bytes(pickle.dumps({"late": True}))
        dvc_file = tmp_path / "mutable.dvc"
        pointer_prefix = "outs:\n" + "- path: benign.pkl\n" * 100
        dvc_file.write_text(pointer_prefix + "- path: hidden.pkl\n")

        from click.testing import CliRunner

        from modelaudit import cli as cli_module
        from modelaudit.cli import cli

        real_scan = cli_module.scan_model_directory_or_file

        def scan_then_rewrite_pointer(path: str, *args: Any, **kwargs: Any) -> ModelAuditResultModel:
            result = real_scan(path, *args, **kwargs)
            if path == str(dvc_file):
                dvc_file.write_text(pointer_prefix + "- path: late.pkl\n")
            return result

        monkeypatch.setattr(cli_module, "scan_model_directory_or_file", scan_then_rewrite_pointer)

        result = CliRunner().invoke(cli, ["scan", str(dvc_file), str(late), "--format", "json", "--no-cache"])

        assert result.exit_code == 2
        output_data = json.loads(result.output)
        assert output_data["success"] is False
        assert output_data["has_errors"] is True
        assert any(issue.get("type") == DVC_OUTPUT_LIMIT_EXCEEDED_REASON for issue in output_data["issues"])

    def test_cli_shard_check_coverage_discharges_output_cap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A passed shard check can prove coverage of siblings omitted from assets."""
        benign = tmp_path / "benign.pkl"
        benign.write_bytes(pickle.dumps({"safe": True}))
        shards = [
            tmp_path / "model-00001-of-00002.safetensors",
            tmp_path / "model-00002-of-00002.safetensors",
        ]
        for shard in shards:
            shard.write_bytes(b"0123456789")
        dvc_file = tmp_path / "shards.dvc"
        dvc_file.write_text("outs:\n" + "- path: benign.pkl\n" * 100 + f"- path: {shards[1].name}\n")

        def fake_scan_file(path: str, config: dict[str, Any]) -> ScanResult:
            result = ScanResult(scanner_name="test")
            result.bytes_scanned = Path(path).stat().st_size
            if path == str(shards[0]):
                result.add_check(
                    name="Sharded Model Detection",
                    passed=True,
                    message="Detected sharded model",
                    details={"shards": [str(shard) for shard in shards]},
                )
            result.finish(success=True)
            return result

        monkeypatch.setattr(core_module, "scan_file", fake_scan_file)

        from click.testing import CliRunner

        from modelaudit import cli as cli_module
        from modelaudit.cli import cli

        real_scan = cli_module.scan_model_directory_or_file

        def scan_without_sibling_asset(path: str, *args: Any, **kwargs: Any) -> ModelAuditResultModel:
            result = real_scan(path, *args, **kwargs)
            if path == str(shards[0]):
                result.assets = [asset for asset in result.assets if asset.path != str(shards[1])]
                result.file_metadata.pop(str(shards[1]), None)
            return result

        monkeypatch.setattr(cli_module, "scan_model_directory_or_file", scan_without_sibling_asset)

        result = CliRunner().invoke(
            cli,
            ["scan", str(dvc_file), str(shards[0]), "--format", "json", "--no-cache"],
        )

        assert result.exit_code == 0
        output_data = json.loads(result.output)
        assert output_data["success"] is True
        assert output_data["has_errors"] is False
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
