import builtins
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanner_results import SCAN_OUTCOME_MESSAGE_METADATA_KEY
from modelaudit.scanners import manifest_scanner
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.manifest_scanner import _PARSE_FAILED, ManifestScanner, _is_trusted_url_domain
from modelaudit.utils.helpers import cache_decorator


def _https_url(host: str, path: str = "/model.bin") -> str:
    """Build HTTPS URLs without embedding full host literals in test assertions."""
    return f"https://{host}{path}"


def test_manifest_scanner_blacklist(tmp_path):
    """Test the manifest scanner with blacklisted terms."""
    test_file = tmp_path / "model_card.json"
    manifest_content = {
        "model_name": "test_model",
        "version": "1.0.0",
        "description": "This is an UNSAFE model that should be flagged",
    }

    test_file.write_text(json.dumps(manifest_content))

    # Create scanner with blacklist patterns
    scanner = ManifestScanner(
        config={"blacklist_patterns": ["unsafe", "malicious"]},
    )

    # Test scan
    result = scanner.scan(str(test_file))

    # Verify scan completed successfully
    assert result.success is True

    # Check that blacklisted term was detected
    blacklist_issues = [
        issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
    ]
    assert len(blacklist_issues) > 0
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in blacklist_issues)

    # Verify the specific blacklisted term was identified
    blacklisted_terms = [
        issue.details.get("blacklisted_term", "") for issue in blacklist_issues if hasattr(issue, "details")
    ]
    assert "unsafe" in blacklisted_terms


def test_manifest_scanner_reuses_manifest_text_during_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "manifest.json"
    test_file.write_text(
        json.dumps(
            {
                "model_name": "safe-model",
                "description": "ordinary manifest",
                "source": _https_url("huggingface.co"),
            }
        )
    )

    original_open = builtins.open
    open_count = 0

    def counting_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal open_count
        if file == str(test_file) and kwargs.get("encoding") == "utf-8":
            open_count += 1
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    result = ManifestScanner(config={"blacklist_patterns": ["blocked"]}).scan(str(test_file))

    assert result.success is True
    assert open_count == 1


def test_manifest_scanner_clears_manifest_text_after_scan(tmp_path: Path) -> None:
    test_file = tmp_path / "manifest.json"
    test_file.write_text(json.dumps({"model_name": "safe-model"}))
    scanner = ManifestScanner(config={"blacklist_patterns": ["blocked"]})

    result = scanner.scan(str(test_file))

    assert result.scanner is scanner
    assert scanner._manifest_text_cache == {}


def test_manifest_blacklist_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}), encoding="utf-8")

    def raise_os_error(_self: ManifestScanner, _path: str) -> str:
        raise OSError("simulated manifest read failure")

    monkeypatch.setattr(ManifestScanner, "_read_manifest_text", raise_os_error)

    direct = ManifestScanner(config={"blacklist_patterns": ["blocked"]}).scan(str(test_file))
    aggregate = scan_model_directory_or_file(
        str(test_file),
        blacklist_patterns=["blocked"],
        cache_scan_results=False,
    )

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert SCAN_OUTCOME_MESSAGE_METADATA_KEY in direct.metadata
    assert "manifest_blacklist_read_failed" in direct.metadata.get("scan_outcome_reasons", [])
    assert direct.metadata.get("operational_error") is True
    assert direct.metadata.get("operational_error_reason") == "manifest_blacklist_read_failed"
    assert any(
        check.name == "Blacklist Pattern Check"
        and check.severity == IssueSeverity.INFO
        and check.details.get("scan_outcome_reason") == "manifest_blacklist_read_failed"
        and check.rule_code is None
        for check in direct.checks
    )
    assert all(check.rule_code != "S1001" for check in direct.checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert aggregate.file_metadata[str(test_file)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2


def test_manifest_blacklist_invalid_utf8_is_operational_not_security_finding(tmp_path: Path) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_bytes(b'{"model_type": "bert", "label": "\xff"}')
    cache_dir = tmp_path / "cache"

    direct = ManifestScanner(config={"blacklist_patterns": ["blocked"]}).scan(str(test_file))
    reset_cache_manager()
    try:
        aggregates = [
            scan_model_directory_or_file(
                str(test_file),
                blacklist_patterns=["blocked"],
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]

        assert direct.success is False
        assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert direct.metadata.get("operational_error_reason") == "manifest_blacklist_read_failed"
        assert any(
            check.name == "Blacklist Pattern Check"
            and check.details.get("exception_type") == "UnicodeDecodeError"
            and check.severity == IssueSeverity.INFO
            and check.rule_code is None
            for check in direct.checks
        )
        assert all(check.rule_code not in {"S902", "S1001"} for check in direct.checks)
        for aggregate in aggregates:
            assert not any(
                issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
            )
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_manifest_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}), encoding="utf-8")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = ManifestScanner().scan(str(test_file))
    aggregate = scan_model_directory_or_file(str(test_file), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "manifest_read_failed"
    assert aggregate.file_metadata[str(test_file)].get("operational_error_reason") == "manifest_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_manifest_zip_probe_failure_preserves_owner_for_parser_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}), encoding="utf-8")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    def raise_os_error(_self: ManifestScanner, _path: str) -> str:
        raise OSError("simulated manifest parser read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr(ManifestScanner, "_read_manifest_text", raise_os_error)

    aggregate = scan_model_directory_or_file(str(test_file), cache_enabled=False)

    assert "manifest" in aggregate.scanner_names
    assert aggregate.file_metadata[str(test_file)].get("operational_error_reason") == "manifest_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_manifest_blacklist_read_failure_bypasses_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "padding": "x" * 11_000}), encoding="utf-8")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as warm_cache:
            warm_cache.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm_result = scan_file(
                str(test_file),
                config={
                    "blacklist_patterns": ["blocked"],
                    "cache_enabled": True,
                    "cache_dir": str(cache_dir),
                    "min_cache_file_size": 0,
                },
            )

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        def raise_os_error(_self: ManifestScanner, _path: str) -> str:
            raise OSError("simulated manifest read failure after cache warm")

        monkeypatch.setattr(ManifestScanner, "_read_manifest_text", raise_os_error)

        aggregate = scan_model_directory_or_file(
            str(test_file),
            blacklist_patterns=["blocked"],
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert aggregate.file_metadata[str(test_file)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert (
            aggregate.file_metadata[str(test_file)].get("operational_error_reason") == "manifest_blacklist_read_failed"
        )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_manifest_parser_read_failure_bypasses_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "padding": "x" * 11_000}), encoding="utf-8")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as warm_cache:
            warm_cache.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm_result = scan_file(
                str(test_file),
                config={
                    "cache_enabled": True,
                    "cache_dir": str(cache_dir),
                    "min_cache_file_size": 0,
                },
            )

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        def raise_os_error(_self: ManifestScanner, _path: str) -> str:
            raise OSError("simulated manifest parser read failure after cache warm")

        monkeypatch.setattr(ManifestScanner, "_read_manifest_text", raise_os_error)

        aggregate = scan_model_directory_or_file(
            str(test_file),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert aggregate.file_metadata[str(test_file)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert aggregate.file_metadata[str(test_file)].get("operational_error_reason") == "manifest_read_failed"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_manifest_cloud_storage_read_failure_is_inconclusive_after_parse_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(
        json.dumps({"model_type": "bert", "weights": "https://bucket.s3.amazonaws.com/malware/model.bin"}),
        encoding="utf-8",
    )
    original_read = ManifestScanner._read_manifest_text
    read_counts: dict[int, int] = {}

    def fail_cloud_url_read_once(self: ManifestScanner, path: str) -> str:
        scanner_id = id(self)
        read_counts[scanner_id] = read_counts.get(scanner_id, 0) + 1
        if read_counts[scanner_id] == 1:
            raise OSError("simulated cloud storage URL read failure")
        return original_read(self, path)

    monkeypatch.setattr(ManifestScanner, "_read_manifest_text", fail_cloud_url_read_once)

    result = ManifestScanner().scan(str(test_file))
    aggregate = scan_model_directory_or_file(str(test_file), cache_enabled=False)

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "manifest_cloud_storage_read_failed"
    assert any(
        check.name == "Cloud Storage URL Detection"
        and check.severity == IssueSeverity.INFO
        and check.details.get("scan_outcome_reason") == "manifest_cloud_storage_read_failed"
        for check in result.checks
    )
    assert (
        aggregate.file_metadata[str(test_file)].get("operational_error_reason") == "manifest_cloud_storage_read_failed"
    )
    assert determine_exit_code(aggregate) == 2


def test_manifest_cloud_storage_read_failure_remains_unsuccessful_with_recovered_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(
        json.dumps(
            {
                "model_type": "bert",
                "weights": "https://bucket.s3.amazonaws.com/releases/model.bin",
                "checksum": "0" * 40,
            }
        ),
        encoding="utf-8",
    )
    original_read = ManifestScanner._read_manifest_text
    read_counts: dict[int, int] = {}

    def fail_cloud_url_read_once(self: ManifestScanner, path: str) -> str:
        scanner_id = id(self)
        read_counts[scanner_id] = read_counts.get(scanner_id, 0) + 1
        if read_counts[scanner_id] == 1:
            raise OSError("simulated cloud storage URL read failure")
        return original_read(self, path)

    monkeypatch.setattr(ManifestScanner, "_read_manifest_text", fail_cloud_url_read_once)

    result = ManifestScanner().scan(str(test_file))
    aggregate = scan_model_directory_or_file(str(test_file), cache_enabled=False)

    assert result.success is False
    assert result.metadata.get("operational_error_reason") == "manifest_cloud_storage_read_failed"
    assert any(
        check.name == "Weak Hash Detection" and check.severity == IssueSeverity.WARNING for check in result.checks
    )
    assert any(issue.severity == IssueSeverity.WARNING for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_manifest_cloud_storage_read_failure_bypasses_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(
        json.dumps(
            {
                "model_type": "bert",
                "weights": "https://bucket.s3.amazonaws.com/releases/model.bin",
                "padding": "x" * 11_000,
            }
        ),
        encoding="utf-8",
    )
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as warm_cache:
            warm_cache.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm_result = scan_file(
                str(test_file),
                config={
                    "cache_enabled": True,
                    "cache_dir": str(cache_dir),
                    "min_cache_file_size": 0,
                },
            )

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        original_read = ManifestScanner._read_manifest_text
        read_counts: dict[int, int] = {}

        def fail_cloud_url_read_once(self: ManifestScanner, path: str) -> str:
            scanner_id = id(self)
            read_counts[scanner_id] = read_counts.get(scanner_id, 0) + 1
            if read_counts[scanner_id] == 1:
                raise OSError("simulated cloud storage URL read failure after cache warm")
            return original_read(self, path)

        monkeypatch.setattr(ManifestScanner, "_read_manifest_text", fail_cloud_url_read_once)

        aggregate = scan_model_directory_or_file(
            str(test_file),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert aggregate.file_metadata[str(test_file)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert (
            aggregate.file_metadata[str(test_file)].get("operational_error_reason")
            == "manifest_cloud_storage_read_failed"
        )
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()


def test_manifest_scanner_case_insensitive_blacklist(tmp_path):
    """Test that blacklist matching is case-insensitive."""
    test_file = tmp_path / "inference_config.json"

    test_file.write_text('{"model": "This is a MaLiCiOuS model"}')

    # Create scanner with lowercase blacklist pattern
    scanner = ManifestScanner(config={"blacklist_patterns": ["malicious"]})

    # Test scan
    result = scanner.scan(str(test_file))

    # Check that the mixed-case term was detected
    blacklist_issues = [
        issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
    ]
    assert len(blacklist_issues) > 0


def test_manifest_scanner_no_blacklist_clean_file(tmp_path):
    """Test that clean files with no blacklist patterns pass."""
    test_file = tmp_path / "config.json"
    clean_config = {
        "model_type": "bert",
        "hidden_size": 768,
        "architectures": ["BertModel"],
        "_name_or_path": "bert-base-uncased",
    }

    test_file.write_text(json.dumps(clean_config))

    scanner = ManifestScanner(config={"blacklist_patterns": ["malware", "trojan"]})
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should have a passed blacklist check
    passed_checks = [check for check in result.checks if check.status == CheckStatus.PASSED]
    assert any("Blacklist" in check.name for check in passed_checks)

    # Should have no critical issues
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_manifest_scanner_model_name_policy(tmp_path):
    """Test model name policy checking."""
    test_file = tmp_path / "config.json"
    config_with_model_name = {
        "model_name": "legitimate_model",
        "model_type": "bert",
    }

    test_file.write_text(json.dumps(config_with_model_name))

    scanner = ManifestScanner(config={"blacklist_patterns": []})
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should have model name policy checks
    model_name_checks = [check for check in result.checks if "Model Name Policy" in check.name]
    assert len(model_name_checks) > 0


def test_manifest_scanner_metadata_extraction(tmp_path):
    """Test that model metadata is extracted from config.json files."""
    test_file = tmp_path / "config.json"
    huggingface_config = {
        "_name_or_path": "bert-base-uncased",
        "model_type": "bert",
        "architectures": ["BertModel"],
        "hidden_size": 768,
        "num_hidden_layers": 12,
        "num_attention_heads": 12,
        "vocab_size": 30522,
        "transformers_version": "4.35.0",
    }

    test_file.write_text(json.dumps(huggingface_config))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Check that model metadata was extracted
    assert "model_info" in result.metadata
    model_info = result.metadata["model_info"]
    assert model_info["model_type"] == "bert"
    assert model_info["architectures"] == ["BertModel"]
    assert model_info["hidden_size"] == 768
    assert model_info["num_layers"] == 12
    assert model_info["num_heads"] == 12
    assert model_info["vocab_size"] == 30522
    assert model_info["framework_version"] == "4.35.0"


def test_manifest_scanner_license_extraction(tmp_path):
    """Test that license information is extracted."""
    test_file = tmp_path / "model_card.json"
    config_with_license = {
        "model_name": "test_model",
        "license": "apache-2.0",
        "version": "1.0.0",
    }

    test_file.write_text(json.dumps(config_with_license))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True
    assert "license" in result.metadata
    assert result.metadata["license"] == "apache-2.0"


def test_parse_file_read_failure_logs_warning(caplog, capsys):
    """Ensure read failures log warnings without stdout output."""
    scanner = ManifestScanner()

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result = ScanResult(scanner.name)
        content = scanner._parse_file("nonexistent.json", ".json", result)

    assert content is _PARSE_FAILED
    assert any("Error reading file nonexistent.json" in record.getMessage() for record in caplog.records)
    assert capsys.readouterr().out == ""
    assert all(issue.severity == IssueSeverity.INFO for issue in result.issues)
    assert any(
        check.name == "Manifest File Read"
        and check.severity == IssueSeverity.INFO
        and check.details.get("scan_outcome_reason") == "manifest_read_failed"
        for check in result.checks
    )


def test_manifest_scanner_yaml_not_handled(tmp_path):
    """Test that YAML files are not handled by the manifest scanner."""
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("model_type: bert\nhidden_size: 768\n")

    scanner = ManifestScanner()
    assert scanner.can_handle(str(yaml_file)) is False


def test_manifest_scanner_yml_not_handled(tmp_path):
    """Test that .yml files are not handled by the manifest scanner."""
    yml_file = tmp_path / "config.yml"
    yml_file.write_text("model_type: gpt2\nhidden_size: 768\n")

    scanner = ManifestScanner()
    assert scanner.can_handle(str(yml_file)) is False


def test_manifest_scanner_can_handle(tmp_path: Path) -> None:
    """Test that scanner correctly identifies supported files."""
    scanner = ManifestScanner()

    # Create actual files for testing (scanner requires files to exist)
    (tmp_path / "config.json").write_text('{"model_type": "test"}')
    (tmp_path / "generation_config.json").write_text("{}")
    (tmp_path / "model_index.json").write_text("{}")
    (tmp_path / "manifest.json").write_text("{}")
    (tmp_path / "hyperparams.yaml").write_text("model_type: bert\n")
    (tmp_path / "environment.yml").write_text("name: model-env\n")
    (tmp_path / "conda.yaml").write_text("name: model-env\n")
    (tmp_path / "artifact.manifest").write_text('{"model_type": "bert"}')
    (tmp_path / "weights.model").write_text('{"blob": true}')
    (tmp_path / "weights.metadata").write_text('{"blob": true}')
    (tmp_path / "tokenizer_config.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "tsconfig.json").write_text("{}")

    # Should handle HuggingFace configs
    assert scanner.can_handle(str(tmp_path / "config.json")) is True
    assert scanner.can_handle(str(tmp_path / "generation_config.json")) is True
    assert scanner.can_handle(str(tmp_path / "model_index.json")) is True
    assert scanner.can_handle(str(tmp_path / "manifest.json")) is True
    assert scanner.can_handle(str(tmp_path / "hyperparams.yaml")) is True
    assert scanner.can_handle(str(tmp_path / "environment.yml")) is True
    assert scanner.can_handle(str(tmp_path / "conda.yaml")) is True
    assert scanner.can_handle(str(tmp_path / "artifact.manifest")) is True
    assert scanner.can_handle(str(tmp_path / "weights.model")) is False
    assert scanner.can_handle(str(tmp_path / "weights.metadata")) is False

    # Should not handle tokenizer configs (excluded)
    assert scanner.can_handle(str(tmp_path / "tokenizer_config.json")) is False

    # Should not handle non-ML configs
    assert scanner.can_handle(str(tmp_path / "package.json")) is False
    assert scanner.can_handle(str(tmp_path / "tsconfig.json")) is False


def test_manifest_scanner_flags_blacklist_on_manifest_suffix(tmp_path: Path) -> None:
    test_file = tmp_path / "artifact.manifest"
    test_file.write_text(json.dumps({"description": "unsafe model"}), encoding="utf-8")

    result = ManifestScanner(config={"blacklist_patterns": ["unsafe"]}).scan(str(test_file))

    assert result.success is True
    assert any(
        issue.details.get("blacklisted_term") == "unsafe" and issue.severity == IssueSeverity.CRITICAL
        for issue in result.issues
    )


def test_manifest_scanner_url_shortener_flagged(tmp_path):
    """Test that URL shorteners are flagged (not in allowlist)."""
    test_file = tmp_path / "config.json"
    config_with_shortener = {
        "model_type": "bert",
        "download_url": "https://bit.ly/abc123",
        "architectures": ["BertModel"],
    }

    test_file.write_text(json.dumps(config_with_shortener))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should flag URL shortener as untrusted domain
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1
    assert "bit.ly" in failed_url_checks[0].details.get("url", "")


def test_manifest_scanner_delegates_malicious_chat_templates_to_jinja_analysis(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_delegates_nested_chat_template_containers_to_jinja_analysis(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": {
                    "default": payload,
                    "description": "plain prose",
                },
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert any(
        check.name == "Jinja2 Template Injection Detection"
        and check.status == CheckStatus.FAILED
        and check.details["template_location"] == "chat_template.default"
        for check in result.checks
    )


def test_manifest_scanner_nested_chat_template_collection_enforces_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = ManifestScanner()
    timeout_calls = 0

    def raise_during_nested_collection() -> None:
        nonlocal timeout_calls
        timeout_calls += 1
        if timeout_calls == 4:
            raise TimeoutError("embedded Jinja collection timed out")

    monkeypatch.setattr(scanner, "_check_timeout", raise_during_nested_collection)

    with pytest.raises(TimeoutError, match="embedded Jinja collection timed out"):
        scanner._collect_jinja_template_fields({"chat_template": {"default": "{{ harmless }}"}})


def test_manifest_scanner_deep_jinja_collection_budget_fails_closed(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    nested_config: dict[str, Any] = {"leaf": "plain metadata"}
    for index in range(5):
        nested_config = {"nested": nested_config, "level": index}

    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "metadata": nested_config,
            }
        ),
        encoding="utf-8",
    )
    config = {"jinja_template_collection_max_depth": 3}

    result = ManifestScanner(config=config).scan(str(config_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "manifest_jinja_template_collection_budget_exceeded" in result.metadata["scan_outcome_reasons"]
    budget_checks = [check for check in result.checks if check.name == "Embedded Jinja Collection Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].status == CheckStatus.FAILED
    assert "parsed manifest traversal exceeded" in budget_checks[0].message
    assert budget_checks[0].details["limit_type"] == "depth"
    assert budget_checks[0].details["max_depth"] == 3
    assert budget_checks[0].details["scan_outcome_reason"] == "manifest_jinja_template_collection_budget_exceeded"


def test_manifest_scanner_jinja_collection_budget_preserves_malicious_template_detection(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    nested_config: dict[str, Any] = {"leaf": "plain metadata"}
    for index in range(5):
        nested_config = {"nested": nested_config, "level": index}

    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                "metadata": nested_config,
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"jinja_template_collection_max_depth": 3}).scan(str(config_path))

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "manifest_jinja_template_collection_budget_exceeded" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Embedded Jinja Collection Budget"
        and check.status == CheckStatus.FAILED
        and check.details["templates_collected"] == 1
        for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_shared_jinja_aliases_expand_once_per_mode() -> None:
    scanner = ManifestScanner(
        config={
            "jinja_template_collection_max_depth": 16,
            "jinja_template_collection_max_items": 1100,
        }
    )
    shared = {"chat_template": {"default": "{{ message['content'] }}"}}

    collection = scanner._collect_jinja_template_fields_with_budget({"metadata": [shared] * 1000})

    assert collection.budget_exceeded is False
    assert collection.items_visited == 1004
    assert collection.templates == {"metadata[0].chat_template.default": "{{ message['content'] }}"}


def test_manifest_scanner_recursive_jinja_alias_preserves_sibling_template() -> None:
    scanner = ManifestScanner(
        config={
            "jinja_template_collection_max_depth": 3,
            "jinja_template_collection_max_items": 100,
        }
    )
    malicious = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    recursive: dict[str, Any] = {}
    recursive["loop"] = recursive
    recursive["chat_template"] = malicious

    collection = scanner._collect_jinja_template_fields_with_budget(recursive)

    assert collection.budget_exceeded is False
    assert collection.items_visited == 3
    assert collection.templates == {"chat_template": malicious}


def test_manifest_scanner_recursive_yaml_alias_reaches_jinja_analysis(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
1: &recursive
  self: *recursive
  chat_template: "{{ ''.__class__.__mro__[1].__subclasses__() }}"
""".lstrip(),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any(check.name == "Manifest File Scan" for check in result.checks)


def test_manifest_scanner_benign_recursive_yaml_alias_terminates(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
metadata: &recursive
  self: *recursive
  description: benign metadata
""".lstrip(),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert not any(check.name == "Manifest File Scan" for check in result.checks)
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_manifest_scanner_bounds_jinja_collection_paths_before_concatenation() -> None:
    scanner = ManifestScanner(config={"jinja_template_collection_max_depth": 8})
    long_key = "metadata-" + ("x" * 4096)
    nested: dict[str, Any] = {"leaf": "benign"}
    for _ in range(9):
        nested = {long_key: nested}

    collection = scanner._collect_jinja_template_fields_with_budget(nested)

    assert collection.budget_exceeded is True
    assert collection.limit_type == "depth"
    assert len(collection.path) <= 240


def test_manifest_scanner_alias_identity_is_scoped_to_collection_mode() -> None:
    scanner = ManifestScanner()
    malicious = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    shared = {"chat_template": malicious}

    collection = scanner._collect_jinja_template_fields_with_budget(
        {
            "chat_template": shared,
            "metadata": shared,
        }
    )

    assert collection.templates == {
        "chat_template.chat_template": malicious,
        "metadata.chat_template": malicious,
    }


def test_manifest_scanner_alias_identity_preserves_chat_template_context(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    benign_macro = "{% macro render() %}hello{% endmacro %}"
    config_path.write_text(
        f"""
a:
  template: &shared
    default: "{benign_macro}"
z:
  chat_template: *shared
""".lstrip(),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert not any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_reexpands_alias_at_shallower_depth(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    malicious = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    config_path.write_text(
        f"""
metadata:
  deep: &shared
    chat_template: "{malicious}"
later: *shared
""".lstrip(),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"jinja_template_collection_max_depth": 2}).scan(str(config_path))

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Embedded Jinja Collection Budget"
        and check.status == CheckStatus.FAILED
        and check.details["limit_type"] == "depth"
        for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_depth_budget_skips_only_overdeep_branch(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    malicious = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    nested_config: dict[str, Any] = {"leaf": "plain metadata"}
    for _ in range(5):
        nested_config = {"nested": nested_config}
    config_path.write_text(
        json.dumps(
            {
                "metadata": nested_config,
                "later": {"chat_template": malicious},
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"jinja_template_collection_max_depth": 3}).scan(str(config_path))

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Embedded Jinja Collection Budget"
        and check.status == CheckStatus.FAILED
        and check.details["limit_type"] == "depth"
        and check.details["templates_collected"] == 1
        for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_prioritizes_template_fields_before_item_budget(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    malicious = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    config_path.write_text(
        json.dumps(
            {
                "metadata": [{"name": f"layer-{index}"} for index in range(8)],
                "chat_template": malicious,
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"jinja_template_collection_max_items": 3}).scan(str(config_path))

    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Embedded Jinja Collection Budget"
        and check.status == CheckStatus.FAILED
        and check.details["limit_type"] == "items"
        and check.details["templates_collected"] == 1
        for check in result.checks
    )
    assert any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_invalid_jinja_budget_values_use_defaults() -> None:
    scanner = ManifestScanner(
        config={
            "jinja_template_collection_max_depth": float("inf"),
            "jinja_template_collection_max_items": float("inf"),
        }
    )

    collection = scanner._collect_jinja_template_fields_with_budget({"chat_template": "{{ message }}"})

    assert collection.budget_exceeded is False
    assert collection.templates == {"chat_template": "{{ message }}"}


def test_manifest_scanner_wide_jinja_collection_item_budget_fails_closed(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "metadata": [{"name": f"layer-{index}"} for index in range(8)],
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"jinja_template_collection_max_items": 4}).scan(str(config_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "manifest_jinja_template_collection_budget_exceeded" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Embedded Jinja Collection Budget"
        and check.status == CheckStatus.FAILED
        and check.details["limit_type"] == "items"
        and check.details["max_items"] == 4
        for check in result.checks
    )


def test_manifest_scanner_jinja_collection_budget_redacts_path_evidence(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    secret = "MANIFEST_COLLECTION_SECRET"
    config_path.write_text(
        json.dumps({f"api_key={secret}": {"nested": {"value": "plain metadata"}}}),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"jinja_template_collection_max_depth": 1}).scan(str(config_path))

    budget_checks = [check for check in result.checks if check.name == "Embedded Jinja Collection Budget"]
    assert len(budget_checks) == 1
    assert budget_checks[0].details["path"] == "api_key=<redacted>"
    assert secret not in json.dumps(budget_checks[0].details)


def test_manifest_scanner_redacts_embedded_jinja_template_locations(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    secret = "MANIFEST_TEMPLATE_SECRET_123"
    config_path.write_text(
        json.dumps(
            {
                f"api_key={secret}": {
                    "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
                }
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    detections = [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]
    assert detections
    assert all(check.details["template_location"] == "api_key=<redacted>.chat_template" for check in detections)
    assert all(check.location == f"{config_path}:api_key=<redacted>.chat_template" for check in detections)
    assert secret not in json.dumps([check.to_dict() for check in detections])


def test_manifest_scanner_redacts_oversized_jinja_template_locations(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    secret = "MANIFEST_TEMPLATE_SECRET_123"
    config_path.write_text(
        json.dumps({f"api_key={secret}": {"chat_template": "{{ value }}" + ("x" * 100)}}),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"max_template_size": 64}).scan(str(config_path))

    size_checks = [check for check in result.checks if check.name == "Template Size Limit"]
    assert len(size_checks) == 1
    assert size_checks[0].details["skipped_template_locations"] == ["api_key=<redacted>.chat_template"]
    assert secret not in json.dumps([check.to_dict() for check in size_checks])


def test_manifest_scanner_preserves_benign_template_locations() -> None:
    templates = {"metadata.chat_template.default": "{{ message['content'] }}"}

    assert ManifestScanner._redact_jinja_template_locations(templates) == templates


def test_manifest_scanner_preserves_templates_with_colliding_redacted_locations() -> None:
    safe_templates = ManifestScanner._redact_jinja_template_locations(
        {
            "api_key=first-secret.chat_template": "{{ first }}",
            "api_key=second-secret.chat_template": "{{ second }}",
        }
    )

    assert safe_templates == {
        "api_key=<redacted>.chat_template": "{{ first }}",
        "api_key=<redacted>.chat_template [duplicate 2]": "{{ second }}",
    }


def test_manifest_scanner_nested_near_match_jinja_template_still_scanned(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template_metadata": {"description": "near-match container name"},
                "generation": {
                    "variants": [
                        {"chat_template": ("{% for message in messages %}{{ message['content'] }}{% endfor %}")}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner(
        config={
            "jinja_template_collection_max_depth": 8,
            "jinja_template_collection_max_items": 64,
        }
    ).scan(str(config_path))

    assert "manifest_jinja_template_collection_budget_exceeded" not in result.metadata.get(
        "scan_outcome_reasons",
        [],
    )
    assert not any(check.name == "Embedded Jinja Collection Budget" for check in result.checks)
    assert any(check.name == "Jinja2 SSTI Analysis" and check.status == CheckStatus.PASSED for check in result.checks)
    assert not any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_ignores_plain_nested_template_metadata() -> None:
    scanner = ManifestScanner()
    payload = "{{ message['content'] }}"

    assert scanner._collect_jinja_template_fields({"chat_template": "plain template text"}) == {
        "chat_template": "plain template text"
    }

    templates = scanner._collect_jinja_template_fields(
        {
            "chat_template": {
                "default": payload,
                "metadata": {"template": "Documentation example: requests.get(url)"},
            }
        }
    )

    assert templates == {"chat_template.default": payload}


def test_manifest_scanner_nested_oversized_chat_template_fails_closed(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    payload = "{{ message['content'] }}" + (" safe" * 32)
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": {
                    "default": payload,
                },
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner(config={"max_template_size": 64}).scan(str(config_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == "inconclusive"
    assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    size_checks = [c for c in result.checks if c.name == "Template Size Limit"]
    assert len(size_checks) == 1
    assert size_checks[0].details["skipped_template_locations"] == ["chat_template.default"]


def test_manifest_scanner_ignores_plain_nested_chat_template_container_strings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": {
                    "description": "plain prose",
                },
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert not any(check.name.startswith("Jinja2") or check.name == "Template Size Limit" for check in result.checks)


def test_manifest_scanner_template_path_collision_does_not_hide_malicious_candidate(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    malicious = "{{ lipsum.__globals__.os.popen('id') }}"
    benign = "{{ message['content'] }}"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": {
                    "a.b": malicious,
                    "a": {"b": benign},
                },
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    failed_checks = [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]
    assert failed_checks
    assert any(check.details.get("template_location") == "chat_template.a.b" for check in failed_checks)
    summary = [check for check in result.checks if check.name == "Jinja2 SSTI Analysis Summary"]
    assert len(summary) == 1
    assert summary[0].details["templates_analyzed"] == 2


def test_manifest_scanner_keeps_benign_chat_templates_clean(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{% for message in messages %}{{ message['content'] }}{% endfor %}",
            }
        ),
        encoding="utf-8",
    )

    result = ManifestScanner().scan(str(config_path))

    assert any(check.name == "Jinja2 SSTI Analysis" and check.status == CheckStatus.PASSED for check in result.checks)
    assert not any(
        check.name == "Jinja2 Template Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_manifest_scanner_propagates_jinja_sandbox_budget_inconclusive(tmp_path: Path) -> None:
    pytest.importorskip("jinja2.sandbox")
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "model_type": "llama",
                "chat_template": "{{ 'A' * 1000000 }}",
            }
        ),
        encoding="utf-8",
    )
    config = {
        "sandbox_render_max_output_chars": 16,
        "sandbox_render_timeout_seconds": 2,
    }

    result = ManifestScanner(config=config).scan(str(config_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Template Sandbox Safety Probe"
        and check.status == CheckStatus.FAILED
        and check.details["reason"] == "jinja2_sandbox_render_budget_exceeded"
        for check in result.checks
    )

    aggregate_result = scan_model_directory_or_file(
        str(config_path),
        config={**config, "cache_scan_results": False},
    )
    assert determine_exit_code(aggregate_result) == 2


def test_manifest_scanner_delegates_templates_from_parsed_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text('{"chat_template": "{{ harmless }}"}', encoding="utf-8")
    captured: dict[str, dict[str, str]] = {}

    def capture_templates(self: object, path: str, templates: dict[str, str]) -> ScanResult:
        captured[path] = templates
        return ScanResult("jinja2_template")

    monkeypatch.setattr(
        "modelaudit.scanners.jinja2_template_scanner.Jinja2TemplateScanner.scan_extracted_templates",
        capture_templates,
    )

    ManifestScanner().scan(str(config_path))

    assert captured[str(config_path)] == {"chat_template": "{{ harmless }}"}


def test_manifest_scanner_honors_excluded_embedded_jinja_selection(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        '{"chat_template":"{{ \'\'.__class__.__mro__[1].__subclasses__() }}"}',
        encoding="utf-8",
    )

    result = ManifestScanner(config={"scanners": ["manifest"]}).scan(str(config_path))

    assert "jinja2_template" in result.metadata["skipped_scanner_ids"]
    assert not any(check.name == "Jinja2 Template Injection Detection" for check in result.checks)


def test_manifest_scanner_skips_jinja_collection_budget_when_excluded(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"model_type": "llama", "metadata": {"nested": {"value": "benign"}}}),
        encoding="utf-8",
    )

    result = ManifestScanner(
        config={
            "scanners": ["manifest"],
            "jinja_template_collection_max_depth": 1,
        }
    ).scan(str(config_path))

    assert "jinja2_template" in result.metadata["skipped_scanner_ids"]
    assert "manifest_jinja_template_collection_budget_exceeded" not in result.metadata.get(
        "scan_outcome_reasons",
        [],
    )
    assert not any(check.name == "Embedded Jinja Collection Budget" for check in result.checks)


def test_manifest_scanner_redacts_untrusted_url_credentials(tmp_path: Path) -> None:
    """Untrusted URL findings should not store userinfo, query strings, or fragments."""
    test_file = tmp_path / "config.json"
    raw_url = "https://user:leaky-pass@totally-legit-models.com/model.bin?token=leaky-token#fragment"
    test_file.write_text(json.dumps({"model_type": "bert", "download_url": raw_url}))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1

    check = failed_url_checks[0]
    assert check.details["url"] == "https://<credentials-redacted>@totally-legit-models.com/model.bin"
    assert "leaky-pass" not in check.message
    assert "leaky-token" not in check.message
    assert "fragment" not in check.message
    assert "leaky-pass" not in check.details["url"]
    assert "leaky-token" not in check.details["url"]
    assert "fragment" not in check.details["url"]


def test_manifest_scanner_container_schemes_redact_userinfo(tmp_path: Path) -> None:
    """Azure container URI findings should redact userinfo-looking values."""
    test_file = tmp_path / "config.json"
    raw_urls = {
        "abfs": "abfs://container:secret@workspace.dfs.core.windows.net/models/path.bin?token=leak#frag",
        "abfss": "abfss://container:secret@workspace.dfs.core.windows.net/models/path.bin?token=leak#frag",
        "wasb": "wasb://container:secret@workspace.blob.core.windows.net/models/path.bin?token=leak#frag",
        "wasbs": "wasbs://container:secret@workspace.blob.core.windows.net/models/path.bin?token=leak#frag",
    }
    test_file.write_text(json.dumps({"model_type": "bert", "download_urls": raw_urls}))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    cloud_storage_checks = [
        check
        for check in result.checks
        if check.name == "Cloud Storage URL Detection" and check.status == CheckStatus.FAILED
    ]
    urls_by_scheme = {check.details["url"].split(":", 1)[0]: check for check in cloud_storage_checks}

    assert set(raw_urls).issubset(urls_by_scheme)
    for scheme, raw_url in raw_urls.items():
        check = urls_by_scheme[scheme]
        redacted_url = check.details["url"]
        expected_url = raw_url.replace("container:secret", "<credentials-redacted>").split("?", 1)[0]
        assert redacted_url == expected_url
        assert "container:secret@" not in redacted_url
        assert "<credentials-redacted>" in redacted_url
        assert "token=leak" not in redacted_url
        assert "frag" not in redacted_url
        assert "container:secret@" not in check.message
        assert "token=leak" not in check.message
        assert "frag" not in check.message


def test_manifest_scanner_tunnel_service_flagged(tmp_path):
    """Test that tunnel services (ngrok, localtunnel) are flagged (not in allowlist)."""
    test_file = tmp_path / "config.json"
    config_with_tunnel = {
        "model_type": "gpt2",
        "callback_url": "https://abc123.ngrok.io/webhook",
        "hidden_size": 768,
    }

    test_file.write_text(json.dumps(config_with_tunnel))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should flag tunnel service as untrusted domain
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1
    assert "ngrok.io" in failed_url_checks[0].details.get("url", "")


def test_manifest_scanner_trusted_urls_not_flagged(tmp_path):
    """Test that URLs from trusted domains (huggingface, github, etc.) are NOT flagged as untrusted."""
    test_file = tmp_path / "config.json"
    config_with_trusted_urls = {
        "model_type": "bert",
        "_name_or_path": "https://huggingface.co/bert-base-uncased",
        "repository": "https://github.com/huggingface/transformers",
        "raw_config": "https://raw.githubusercontent.com/huggingface/transformers/main/config.json",
        "homepage": "https://pytorch.org/models",
        "weights": "https://s3.amazonaws.com/models/bert.bin",
        "storage": "https://storage.googleapis.com/models/bert",
        "dataset_docs": "https://openimages.github.io/dataset/",
    }

    test_file.write_text(json.dumps(config_with_trusted_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should have NO "Untrusted URL Check" failures (all are trusted domains)
    # Note: "Cloud Storage URL Detection" may still flag these as INFO for visibility
    untrusted_url_checks = [
        c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED
    ]
    assert len(untrusted_url_checks) == 0, f"Unexpected untrusted URL checks: {untrusted_url_checks}"


def test_manifest_scanner_regional_s3_urls_not_flagged(tmp_path: Path) -> None:
    """Legitimate S3 virtual-hosted regional endpoints should remain trusted."""
    test_file = tmp_path / "config.json"
    config_with_s3_urls = {
        "model_type": "bert",
        "legacy_virtual_hosted": _https_url("bucket.s3.amazonaws.com"),
        "regional_virtual_hosted": _https_url("bucket.s3.us-east-1.amazonaws.com"),
        "legacy_regional_virtual_hosted": _https_url("bucket.s3-us-west-2.amazonaws.com"),
    }

    test_file.write_text(json.dumps(config_with_s3_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True
    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert failed_url_checks == []
    cloud_storage_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
    detected_urls = {c.details.get("url", "") for c in cloud_storage_checks}
    assert detected_urls == {
        config_with_s3_urls["legacy_virtual_hosted"],
        config_with_s3_urls["regional_virtual_hosted"],
        config_with_s3_urls["legacy_regional_virtual_hosted"],
    }


def test_manifest_scanner_redacts_cloud_url_query_credentials(tmp_path: Path) -> None:
    """Cloud URL findings should not store signed query strings."""
    test_file = tmp_path / "config.json"
    raw_url = "https://bucket.s3.amazonaws.com/model.bin?X-Amz-Credential=leaky-cred&X-Amz-Signature=leaky-sig"
    test_file.write_text(json.dumps({"model_type": "bert", "weights": raw_url}))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    cloud_storage_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
    assert len(cloud_storage_checks) == 1

    check = cloud_storage_checks[0]
    assert check.details["url"] == "https://bucket.s3.amazonaws.com/model.bin"
    assert "leaky-cred" not in check.message
    assert "leaky-sig" not in check.message
    assert "leaky-cred" not in check.details["url"]
    assert "leaky-sig" not in check.details["url"]


def test_manifest_scanner_non_s3_amazonaws_hosts_flagged(tmp_path: Path) -> None:
    """Non-S3 amazonaws.com hosts should not become implicitly trusted."""
    test_file = tmp_path / "config.json"
    bucket_root_url = _https_url("bucket.amazonaws.com")
    ec2_api_url = _https_url("ec2.us-east-1.amazonaws.com", "/")
    s3_control_url = _https_url("s3-control.us-east-1.amazonaws.com", "/v20180820/accesspoint/example")
    config_with_non_s3_amazonaws_urls = {
        "model_type": "bert",
        "bucket_root": bucket_root_url,
        "ec2_api": ec2_api_url,
        "s3_control": s3_control_url,
    }

    test_file.write_text(json.dumps(config_with_non_s3_amazonaws_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True
    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 3

    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert bucket_root_url in detected_urls
    assert ec2_api_url in detected_urls
    assert s3_control_url in detected_urls


def test_manifest_scanner_path_style_regional_s3_hosts_flagged(tmp_path: Path) -> None:
    """Bare S3 service hosts without a bucket prefix must stay untrusted."""
    test_file = tmp_path / "config.json"
    path_style_urls = {
        "regional_path_style": _https_url("s3.us-east-1.amazonaws.com", "/bucket/model.bin"),
        "legacy_regional_path_style": _https_url("s3-us-west-2.amazonaws.com", "/bucket/model.bin"),
    }
    test_file.write_text(json.dumps(path_style_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert {c.details.get("url", "") for c in failed_url_checks} == set(path_style_urls.values())


def test_manifest_scanner_official_registry_subdomains_not_flagged(tmp_path: Path) -> None:
    """Official registry service subdomains should remain trusted."""
    test_file = tmp_path / "config.json"
    config_with_registry_urls = {
        "model_type": "bert",
        "docker_registry": "https://registry-1.docker.io/v2/library/python/manifests/latest",
        "gcr_registry": "https://us.gcr.io/project/image:latest",
    }

    test_file.write_text(json.dumps(config_with_registry_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert failed_url_checks == []


def test_manifest_scanner_broad_hosting_subdomains_flagged(tmp_path):
    """Attacker-controlled subdomains on broad hosting domains should not be trusted."""
    test_file = tmp_path / "config.json"
    config_with_hosting_urls = {
        "model_type": "bert",
        "github_pages": "https://attacker.github.io/model.bin",
        "cloudfront": "https://d111111abcdef8.cloudfront.net/model.bin",
        "googleusercontent": "https://evil.googleusercontent.com/model.bin",
    }

    test_file.write_text(json.dumps(config_with_hosting_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 3

    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert "https://attacker.github.io/model.bin" in detected_urls
    assert "https://d111111abcdef8.cloudfront.net/model.bin" in detected_urls
    assert "https://evil.googleusercontent.com/model.bin" in detected_urls


def test_manifest_scanner_untrusted_domain_flagged(tmp_path):
    """Test that URLs from untrusted/unknown domains ARE flagged."""
    test_file = tmp_path / "config.json"
    config_with_untrusted_url = {
        "model_type": "bert",
        "download_url": "https://totally-legit-models.com/model.bin",
        "callback": "https://unknown-server.net/webhook",
    }

    test_file.write_text(json.dumps(config_with_untrusted_url))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should flag untrusted domains
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 2, f"Expected 2 untrusted URLs, got {len(failed_url_checks)}"

    # Verify URLs were detected
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("totally-legit-models.com" in url for url in detected_urls)
    assert any("unknown-server.net" in url for url in detected_urls)


def test_manifest_scanner_domain_substring_bypass_flagged(tmp_path):
    """URLs with trusted-domain substrings in the path/host should still be flagged."""
    test_file = tmp_path / "config.json"
    config_with_spoofed_url = {
        "model_type": "bert",
        "download_url": "https://evil.example/huggingface.co/backdoor.bin",
        "mirror_url": "https://huggingface.co.evil.example/model.bin",
    }

    test_file.write_text(json.dumps(config_with_spoofed_url))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 2, f"Expected 2 untrusted URLs, got {len(failed_url_checks)}"

    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("evil.example/huggingface.co" in url for url in detected_urls)
    assert any("huggingface.co.evil.example" in url for url in detected_urls)


def test_manifest_scanner_nested_untrusted_url(tmp_path):
    """Test that untrusted URLs in nested config structures are detected."""
    test_file = tmp_path / "config.json"
    config_with_nested_url = {
        "model_type": "bert",
        "training": {
            "callbacks": {
                "webhook_url": "https://tinyurl.com/malicious",
            }
        },
        "pipelines": [
            {"name": "inference", "endpoint": "https://localtunnel.me/api"},
        ],
    }

    test_file.write_text(json.dumps(config_with_nested_url))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should detect both untrusted URLs
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 2

    # Verify both URLs were detected
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("tinyurl.com" in url for url in detected_urls)
    assert any("localtunnel.me" in url for url in detected_urls)


def test_manifest_scanner_duplicate_urls_not_repeated(tmp_path):
    """Test that the same untrusted URL appearing multiple times is only reported once."""
    test_file = tmp_path / "config.json"
    config_with_duplicate_urls = {
        "model_type": "bert",
        "primary_url": "https://bit.ly/same123",
        "backup_url": "https://bit.ly/same123",
        "fallback_url": "https://bit.ly/same123",
    }

    test_file.write_text(json.dumps(config_with_duplicate_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should only have ONE untrusted URL check (deduplication)
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1


def test_manifest_scanner_top_level_list_weak_hash_detected(tmp_path: Path) -> None:
    """Top-level manifest arrays should receive the same hash checks as objects."""
    test_file = tmp_path / "config.json"
    sha1_hash = "0" * 40
    test_file.write_text(json.dumps([{"model_type": "bert", "checksum": sha1_hash}]))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_hash_checks = [
        check for check in result.checks if check.name == "Weak Hash Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert result.metadata["root_type"] == "list"
    assert result.metadata["entry_count"] == 1
    assert len(failed_hash_checks) == 1
    assert failed_hash_checks[0].details["key"] == "[0].checksum"
    assert failed_hash_checks[0].details["algorithm"] == "SHA1"

    aggregate = scan_model_directory_or_file(str(test_file), cache_scan_results=False)
    assert determine_exit_code(aggregate) == 1


def test_manifest_scanner_top_level_list_untrusted_url_detected(tmp_path: Path) -> None:
    """Top-level manifest arrays should not bypass URL allowlist checks."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps([{"download_url": "https://evil.invalid/model.bin"}]))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [
        check for check in result.checks if check.name == "Untrusted URL Check" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert result.metadata["root_type"] == "list"
    assert len(failed_url_checks) == 1
    assert failed_url_checks[0].details["key_path"] == "[0].download_url"

    aggregate = scan_model_directory_or_file(str(test_file), cache_scan_results=False)
    assert determine_exit_code(aggregate) == 0


def test_manifest_scanner_malformed_manifest_is_inconclusive(tmp_path: Path) -> None:
    """Malformed manifests should fail closed when no security finding was recovered."""
    test_file = tmp_path / "config.json"
    test_file.write_text('{"model_type": "bert", "checksum": "0000",')

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["manifest_parse_failed"]
    assert any(check.name == "Manifest Parse Coverage" for check in result.checks)

    aggregate = scan_model_directory_or_file(str(test_file), cache_scan_results=False)
    metadata = aggregate.file_metadata[str(test_file)]
    assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "manifest_parse_failed" in metadata["scan_outcome_reasons"]
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2


def test_manifest_scanner_scalar_root_is_inconclusive(tmp_path: Path) -> None:
    """Scalar manifest roots cannot receive structured checks and should fail closed."""
    test_file = tmp_path / "config.json"
    test_file.write_text("null")

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    structure_checks = [
        check for check in result.checks if check.name == "Manifest Structure" and check.status == CheckStatus.FAILED
    ]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["manifest_unsupported_root_type"]
    assert len(structure_checks) == 1
    assert structure_checks[0].details["root_type"] == "NoneType"

    aggregate = scan_model_directory_or_file(str(test_file), cache_scan_results=False)
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 2


def test_manifest_scanner_inconclusive_parse_preserves_security_exit(tmp_path: Path) -> None:
    """Recovered blacklist findings should still produce security exit code 1."""
    test_file = tmp_path / "config.json"
    test_file.write_text('{"model_name": "unsafe-model",')

    scanner = ManifestScanner(config={"blacklist_patterns": ["unsafe"]})
    result = scanner.scan(str(test_file))

    assert result.success is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    aggregate = scan_model_directory_or_file(
        str(test_file),
        blacklist_patterns=["unsafe"],
        cache_scan_results=False,
    )
    assert aggregate.success is False
    assert determine_exit_code(aggregate) == 1


def test_manifest_scanner_parses_toml_manifest_for_weak_hash(tmp_path: Path) -> None:
    """Supported TOML manifests should receive structured weak-hash checks."""
    test_file = tmp_path / "model_config.toml"
    test_file.write_text('model_type = "bert"\nchecksum = "0000000000000000000000000000000000000000"\n')

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_hash_checks = [
        check for check in result.checks if check.name == "Weak Hash Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert result.metadata["root_type"] == "dict"
    assert len(failed_hash_checks) == 1
    assert failed_hash_checks[0].details["key"] == "checksum"
    assert failed_hash_checks[0].details["algorithm"] == "SHA1"


def test_manifest_scanner_parses_ini_manifest_for_weak_hash(tmp_path: Path) -> None:
    """Supported INI manifests should receive structured weak-hash checks."""
    test_file = tmp_path / "model_config.ini"
    test_file.write_text("[model]\nmodel_type = bert\nchecksum = 0000000000000000000000000000000000000000\n")

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_hash_checks = [
        check for check in result.checks if check.name == "Weak Hash Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert result.metadata["root_type"] == "dict"
    assert len(failed_hash_checks) == 1
    assert failed_hash_checks[0].details["key"] == "model.checksum"
    assert failed_hash_checks[0].details["algorithm"] == "SHA1"


def test_manifest_scanner_parses_config_ini_manifest_for_weak_hash(tmp_path: Path) -> None:
    """INI-style .config manifests should not be mistaken for JSON arrays."""
    test_file = tmp_path / "model.config"
    test_file.write_text("[model]\nmodel_type = bert\nchecksum = 0000000000000000000000000000000000000000\n")

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_hash_checks = [
        check for check in result.checks if check.name == "Weak Hash Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert result.metadata["root_type"] == "dict"
    assert len(failed_hash_checks) == 1
    assert failed_hash_checks[0].details["key"] == "model.checksum"
    assert failed_hash_checks[0].details["algorithm"] == "SHA1"


def test_manifest_scanner_parses_config_json_array_for_weak_hash(tmp_path: Path) -> None:
    """JSON array .config manifests should continue using JSON parsing."""
    test_file = tmp_path / "model.config"
    sha1_hash = "0" * 40
    test_file.write_text(json.dumps([{"model_type": "bert", "checksum": sha1_hash}]))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_hash_checks = [
        check for check in result.checks if check.name == "Weak Hash Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert result.metadata["root_type"] == "list"
    assert len(failed_hash_checks) == 1
    assert failed_hash_checks[0].details["key"] == "[0].checksum"
    assert failed_hash_checks[0].details["algorithm"] == "SHA1"


def test_manifest_scanner_enforces_size_limit(tmp_path):
    """Manifest scans should stop when max_file_read_size is exceeded."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "description": "x" * 64}))

    scanner = ManifestScanner(config={"max_file_read_size": 16})
    result = scanner.scan(str(test_file))

    assert result.success is False
    size_checks = [check for check in result.checks if check.name == "File Size Limit"]
    assert len(size_checks) == 1
    assert size_checks[0].status == CheckStatus.FAILED
    assert result.metadata["file_size"] == test_file.stat().st_size


def test_manifest_scanner_enforces_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest scans should stop when the scanner timeout is exceeded."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1})

    def expire_timeout(_path: str, _result: ScanResult) -> None:
        scanner.scan_start_time = 0

    monkeypatch.setattr(scanner, "_check_file_for_blacklist", expire_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "manifest_scan_timeout"
    assert result.metadata["analysis_incomplete"] is True
    timeout_checks = [check for check in result.checks if check.name == "Manifest Scan Timeout"]
    assert len(timeout_checks) == 1
    assert timeout_checks[0].status == CheckStatus.FAILED
    assert timeout_checks[0].severity == IssueSeverity.INFO
    assert timeout_checks[0].details == {
        "timeout_seconds": 1,
        "analysis_incomplete": True,
        "scan_outcome_reason": "manifest_scan_timeout",
    }
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_manifest_scanner_blacklist_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts in blacklist checks should not be converted to blacklist errors."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1, "blacklist_patterns": ["bert"]})
    timeout_calls = 0

    def raise_on_helper_timeout(*_args: object, **_kwargs: object) -> bool:
        nonlocal timeout_calls
        timeout_calls += 1
        if timeout_calls == 2:
            raise TimeoutError("blacklist helper timed out")
        return False

    monkeypatch.setattr(scanner, "_check_timeout", raise_on_helper_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "manifest_scan_timeout"
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]


def test_manifest_scanner_parse_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts in manifest parsing should not be converted to parse errors."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1})
    monkeypatch.setattr(scanner, "_check_file_for_blacklist", lambda _path, _result: None)
    monkeypatch.setattr(scanner, "_check_cloud_storage_urls", lambda _path, _result: None)

    def raise_timeout(_content: str) -> dict:
        raise TimeoutError("parse helper timed out")

    monkeypatch.setattr(json, "loads", raise_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "manifest_scan_timeout"
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]
    assert not any(check.name == "File Parse Error" for check in result.checks)
    assert not any(check.name == "Manifest Parse Attempt" for check in result.checks)


def test_manifest_scanner_cloud_url_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts in cloud URL checks should not be swallowed."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1})
    timeout_calls = 0

    def raise_on_helper_timeout(*_args: object, **_kwargs: object) -> bool:
        nonlocal timeout_calls
        timeout_calls += 1
        if timeout_calls == 3:
            raise TimeoutError("cloud URL helper timed out")
        return False

    monkeypatch.setattr(scanner, "_check_file_for_blacklist", lambda _path, _result: None)
    monkeypatch.setattr(scanner, "_check_timeout", raise_on_helper_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "manifest_scan_timeout"
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]
    assert not any(check.name == "Manifest File Scan" for check in result.checks)


def test_manifest_scanner_timeout_preserves_weak_hash_finding_and_is_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts must preserve prior findings while remaining operational failures."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "checksum": "e3b0c44298fc1c149afbf4c8996fb924"}))
    cache_dir = tmp_path / "cache"

    original_check_weak_hashes = ManifestScanner._check_weak_hashes

    def detect_then_expire(self: ManifestScanner, content: object, result: ScanResult) -> None:
        original_check_weak_hashes(self, content, result)
        self.scan_start_time = 0

    monkeypatch.setattr(ManifestScanner, "_check_weak_hashes", detect_then_expire)
    scanner = ManifestScanner(config={"timeout": 1})

    result = scanner.scan(str(test_file))

    assert result.success is False
    assert result.metadata["operational_error_reason"] == "manifest_scan_timeout"
    failed_checks = [check for check in result.checks if check.status == CheckStatus.FAILED]
    assert [check.name for check in failed_checks] == ["Weak Hash Detection", "Manifest Scan Timeout"]
    assert failed_checks[0].severity == IssueSeverity.WARNING
    assert failed_checks[0].details["algorithm"] == "MD5"
    assert failed_checks[1].severity == IssueSeverity.INFO
    assert not any(check.name == "Manifest File Scan" for check in result.checks)

    monkeypatch.setattr(
        cache_decorator,
        "should_bypass_cache_for_read_failure_aware_file",
        lambda _path: False,
    )
    reset_cache_manager()
    try:
        aggregates = [
            scan_model_directory_or_file(
                str(test_file),
                timeout=1,
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]

        for aggregate in aggregates:
            assert aggregate.success is False
            assert aggregate.file_metadata[str(test_file)]["operational_error_reason"] == "manifest_scan_timeout"
            assert any(
                issue.severity == IssueSeverity.WARNING and issue.details.get("algorithm") == "MD5"
                for issue in aggregate.issues
            )
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_manifest_scanner_timeout_keeps_strong_hash_near_match_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "checksum": "0" * 64}))
    original_check_weak_hashes = ManifestScanner._check_weak_hashes

    def detect_then_expire(self: ManifestScanner, content: object, result: ScanResult) -> None:
        original_check_weak_hashes(self, content, result)
        self.scan_start_time = 0

    monkeypatch.setattr(ManifestScanner, "_check_weak_hashes", detect_then_expire)

    result = ManifestScanner(config={"timeout": 1}).scan(str(test_file))

    assert result.success is False
    strong_hash_checks = [check for check in result.checks if check.name == "Weak Hash Detection"]
    assert len(strong_hash_checks) == 1
    assert strong_hash_checks[0].status == CheckStatus.PASSED
    assert strong_hash_checks[0].details["algorithm"] == "SHA256"
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


# ---------------------------------------------------------------------------
# Unit tests for _is_trusted_url_domain
# ---------------------------------------------------------------------------


class TestIsTrustedUrlDomain:
    """Direct tests for the module-level domain trust function."""

    def test_exact_trusted_domain(self) -> None:
        assert _is_trusted_url_domain("https://github.com/repo") is True
        assert _is_trusted_url_domain("https://huggingface.co/model") is True

    def test_exact_trusted_domain_skips_suffix_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(manifest_scanner, "_TRUSTED_URL_SUBDOMAIN_SUFFIXES", ())
        assert _is_trusted_url_domain("https://github.com/repo") is True

    def test_s3_endpoint_host_patterns_trusted(self) -> None:
        assert _is_trusted_url_domain("https://bucket.s3.amazonaws.com/model.bin") is True
        assert _is_trusted_url_domain("https://bucket.s3.us-east-1.amazonaws.com/model.bin") is True
        assert _is_trusted_url_domain("https://bucket.s3-us-west-2.amazonaws.com/model.bin") is True

    def test_subdomain_of_trusted_domain(self) -> None:
        assert _is_trusted_url_domain("https://raw.githubusercontent.com/f") is True
        assert _is_trusted_url_domain("https://sub.pytorch.org/w") is True

    def test_non_s3_amazonaws_hosts_untrusted(self) -> None:
        assert _is_trusted_url_domain("https://bucket.amazonaws.com/model.bin") is False
        assert _is_trusted_url_domain("https://ec2.us-east-1.amazonaws.com/") is False
        assert _is_trusted_url_domain("https://s3-control.us-east-1.amazonaws.com/v20180820/accesspoint/example") is (
            False
        )

    def test_exact_match_domains_block_subdomains(self) -> None:
        """Subdomains of exact-match hosting domains must NOT be trusted."""
        assert _is_trusted_url_domain("https://attacker.github.io/p") is False
        assert _is_trusted_url_domain("https://evil.cloudfront.net/p") is False
        assert _is_trusted_url_domain("https://evil.googleusercontent.com/p") is False
        assert _is_trusted_url_domain("https://evil.readthedocs.io/p") is False
        assert _is_trusted_url_domain("https://evil.gitbook.io/p") is False
        assert _is_trusted_url_domain("https://evil.streamlit.io/p") is False
        assert _is_trusted_url_domain("https://evil.gradio.app/p") is False
        assert _is_trusted_url_domain("https://evil.fastly.net/p") is False
        assert _is_trusted_url_domain("https://evil.azureedge.net/p") is False
        # sourceforge.net is exact-match only; attacker-controlled subdomains stay untrusted.
        assert _is_trusted_url_domain("https://evil.sourceforge.net/p") is False
        assert _is_trusted_url_domain("https://evil.quay.io/p") is False

    def test_official_registry_subdomains_trusted(self) -> None:
        assert _is_trusted_url_domain("https://registry-1.docker.io/v2/library/python/manifests/latest") is True
        assert _is_trusted_url_domain("https://us.gcr.io/project/image:latest") is True

    def test_exact_match_domain_itself_trusted(self) -> None:
        """The bare exact-match domain should still be trusted."""
        assert _is_trusted_url_domain("https://github.io/page") is True
        assert _is_trusted_url_domain("https://cloudfront.net/res") is True
        assert _is_trusted_url_domain("https://readthedocs.io/docs") is True
        assert _is_trusted_url_domain("https://sourceforge.net/project") is True

    def test_userinfo_bypass_blocked(self) -> None:
        """URLs with userinfo (user@host) must NOT be trusted."""
        assert _is_trusted_url_domain("https://evil.com@github.com/payload") is False
        assert _is_trusted_url_domain("https://evil.com@huggingface.co/model") is False
        assert _is_trusted_url_domain("https://user:pass@pytorch.org/w") is False

    def test_untrusted_domain(self) -> None:
        assert _is_trusted_url_domain("https://evil-site.com/payload") is False
        assert _is_trusted_url_domain("https://not-github.com/repo") is False

    def test_empty_and_malformed(self) -> None:
        assert _is_trusted_url_domain("") is False
        assert _is_trusted_url_domain("not-a-url") is False
        assert _is_trusted_url_domain("https://") is False

    def test_trailing_dot_normalization(self) -> None:
        assert _is_trusted_url_domain("https://github.com./repo") is True


def test_manifest_scanner_userinfo_url_flagged(tmp_path: Path) -> None:
    """URLs with userinfo should be flagged as untrusted even if hostname is trusted."""
    test_file = tmp_path / "config.json"
    config = {
        "model_type": "bert",
        "download": "https://evil.com@huggingface.co/model.bin",
    }
    test_file.write_text(json.dumps(config))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) >= 1
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert "https://<credentials-redacted>@huggingface.co/model.bin" in detected_urls


def test_manifest_scanner_expanded_exact_domains_flagged(tmp_path: Path) -> None:
    """Newly added exact-match domains should flag attacker subdomains."""
    test_file = tmp_path / "config.json"
    config = {
        "model_type": "bert",
        "docs": "https://evil.readthedocs.io/payload",
        "cdn": "https://evil.fastly.net/payload",
        "app": "https://evil.streamlit.io/payload",
    }
    test_file.write_text(json.dumps(config))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 3
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert "https://evil.readthedocs.io/payload" in detected_urls
    assert "https://evil.fastly.net/payload" in detected_urls
    assert "https://evil.streamlit.io/payload" in detected_urls
