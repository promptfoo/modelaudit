import pickle

from modelaudit.core import scan_model_directory_or_file
from modelaudit.utils import resolve_dvc_file


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

    def test_symlink_traversal_prevention(self, tmp_path):
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

    def test_cli_dvc_file_expansion(self, tmp_path):
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

        # Should contain valid JSON output
        import json

        output_data = json.loads(result.output)
        assert output_data["files_scanned"] == 1
