from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cache.batch_operations import BatchCacheOperations
from modelaudit.cache.optimized_config import (
    ConfigurationExtractor,
    build_cache_version_context,
    get_config_extractor,
    normalize_material_scan_config,
)
from modelaudit.cache.scan_results_cache import ScanResultsCache
from modelaudit.config.rule_config import ModelAuditConfig, get_config, reset_config, set_config
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, ScanResult
from modelaudit.utils.helpers.cache_decorator import cached_scan


@pytest.fixture(autouse=True)
def reset_cache_state() -> Iterator[None]:
    reset_cache_manager()
    reset_config()
    extractor = get_config_extractor()
    extractor._config_cache.clear()
    extractor._result_cache.clear()
    extractor._last_cleanup = time.monotonic()
    yield
    reset_cache_manager()
    reset_config()
    extractor._config_cache.clear()
    extractor._result_cache.clear()
    extractor._last_cleanup = time.monotonic()


def _make_cacheable_file(tmp_path: Path, name: str = "model.cache") -> Path:
    file_path = tmp_path / name
    file_path.write_bytes(b"x" * 2048)
    return file_path


def test_cached_scan_persists_miss_and_hits_on_second_call(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"call_count": calls["count"], "timeout": config["timeout"]}

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == {"call_count": 1, "timeout": 30}
    assert second == first
    assert calls["count"] == 1

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 1


def test_cached_scan_restores_private_metadata_for_internal_scan_results(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}
    fingerprint_metadata = {
        "reusable": True,
        "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
        "fingerprints": {},
    }

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        assert config is not None
        calls["count"] += 1
        result = ScanResult(scanner_name="pickle")
        result._private_metadata["call_graph_source_fingerprints"] = fingerprint_metadata
        result.finish()
        return result

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert calls["count"] == 1
    assert first._private_metadata["call_graph_source_fingerprints"] == fingerprint_metadata
    assert second._private_metadata["call_graph_source_fingerprints"] == fingerprint_metadata
    assert "_private_metadata" not in second.to_dict()


def test_cached_scan_invalidates_on_material_scan_config_change(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        assert config is not None
        calls["count"] += 1
        return {"call_count": calls["count"], "timeout": config["timeout"]}

    base_config = {"cache_enabled": True, "cache_dir": str(cache_dir), "timeout": 30}
    changed_config = {**base_config, "timeout": 5}

    first = scan(str(file_path), base_config)
    second = scan(str(file_path), changed_config)
    third = scan(str(file_path), changed_config)

    assert first == {"call_count": 1, "timeout": 30}
    assert second == {"call_count": 2, "timeout": 5}
    assert third == second
    assert calls["count"] == 2


def test_normalize_material_scan_config_ignores_nested_scan_callback() -> None:
    def scan_nested_file(path: str, config: dict[str, Any] | None = None) -> None:
        return None

    assert normalize_material_scan_config(
        {
            "timeout": 30,
            "_archive_nested_scan_callback": scan_nested_file,
        }
    ) == {"timeout": 30}


def test_cached_scan_invalidates_on_rule_config_change(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {"call_count": calls["count"], "suppress_count": len(get_config().suppress)}

    first = scan(str(file_path), config)
    set_config(ModelAuditConfig(suppress={"S710"}))
    second = scan(str(file_path), config)
    third = scan(str(file_path), config)

    assert first == {"call_count": 1, "suppress_count": 0}
    assert second == {"call_count": 2, "suppress_count": 1}
    assert third == second
    assert calls["count"] == 2


def test_scan_cache_invalidates_call_graph_source_fingerprint_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_path = source_root / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(source_root))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source_fingerprint = hashlib.sha256(source_path.read_bytes()).hexdigest()
    fingerprint_metadata = {
        "reusable": True,
        "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
        "fingerprints": {
            str(source_path.absolute()): source_fingerprint,
            str((source_root / "missing.py").absolute()): None,
        },
    }
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {"call_graph_source_fingerprints": fingerprint_metadata},
    }
    expected_cached_result: dict[str, Any] = {"checks": [], "issues": [], "metadata": {}}

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)
    assert cache.get_cached_result(str(file_path), version_context=version_context) == expected_cached_result
    internal_cached_result = cache.get_cached_result(
        str(file_path),
        version_context=version_context,
        include_private_metadata=True,
    )
    assert internal_cached_result is not None
    assert "call_graph_source_fingerprints" not in internal_cached_result["metadata"]
    assert internal_cached_result["_private_metadata"]["call_graph_source_fingerprints"] == fingerprint_metadata

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_call_graph_missing_source_appears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    missing_path = source_root / "helper.py"
    monkeypatch.syspath_prepend(str(source_root))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "call_graph_source_fingerprints": {
                "reusable": True,
                "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
                "fingerprints": {str(missing_path.absolute()): None},
            }
        },
    }
    expected_cached_result: dict[str, Any] = {"checks": [], "issues": [], "metadata": {}}

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)
    assert cache.get_cached_result(str(file_path), version_context=version_context) == expected_cached_result

    missing_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_invalidates_legacy_pickle_call_graph_metadata_without_fingerprints(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [{"module": "helper", "name": "entrypoint"}],
            "callable_invocations": [{"module": "helper", "name": "entrypoint"}],
        },
    }

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_accepts_empty_call_graph_source_fingerprint_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(tmp_path))
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
            "call_graph_source_fingerprints": {
                "reusable": True,
                "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
                "fingerprints": {},
            },
        },
    }
    expected_cached_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
        },
    }

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)

    assert cache.get_cached_result(str(file_path), version_context=version_context) == expected_cached_result


def test_scan_cache_uses_private_call_graph_source_fingerprints_without_returning_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_path = source_root / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")
    monkeypatch.syspath_prepend(str(source_root))

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    source_fingerprint = hashlib.sha256(source_path.read_bytes()).hexdigest()
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [{"module": "helper", "name": "entrypoint"}],
            "callable_invocations": [{"module": "helper", "name": "entrypoint"}],
        },
        "_private_metadata": {
            "call_graph_source_fingerprints": {
                "reusable": True,
                "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
                "fingerprints": {str(source_path.absolute()): source_fingerprint},
            }
        },
    }
    expected_cached_result = {key: value for key, value in scan_result.items() if key != "_private_metadata"}

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)
    assert cached_result is not None
    assert cached_result == expected_cached_result
    assert "_private_metadata" not in cached_result
    assert "call_graph_source_fingerprints" not in cached_result["metadata"]

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result(str(file_path), version_context=version_context) is None


def test_scan_cache_by_key_invalidates_private_call_graph_source_fingerprint_change(tmp_path: Path) -> None:
    source_path = tmp_path / "helper.py"
    source_path.write_text("def entrypoint():\n    return 1\n")

    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [{"module": "helper", "name": "entrypoint"}],
            "callable_invocations": [{"module": "helper", "name": "entrypoint"}],
        },
        "_private_metadata": {
            "call_graph_source_fingerprints": {
                "reusable": True,
                "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
                "fingerprints": {str(source_path.absolute()): hashlib.sha256(source_path.read_bytes()).hexdigest()},
            }
        },
    }

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)
    cache_key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    assert cache.get_cached_result_by_key(cache_key) is not None

    source_path.write_text("import os\n\ndef entrypoint():\n    return os.system('id')\n")

    assert cache.get_cached_result_by_key(cache_key) is None


def test_scan_cache_private_metadata_cannot_override_cache_bookkeeping(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, "model.pkl")
    cache = ScanResultsCache(str(tmp_path / "cache"))
    version_context = build_cache_version_context({})
    fingerprint_metadata = {
        "reusable": True,
        "search_context": [str(Path(entry or os.getcwd()).absolute()) for entry in sys.path],
        "fingerprints": {},
    }
    scan_result = {
        "checks": [],
        "issues": [],
        "metadata": {
            "pickle_report_status": "complete",
            "pickle_verdict": "clean",
            "import_references": [],
            "callable_invocations": [],
        },
        "_private_metadata": {
            "call_graph_source_fingerprints": fingerprint_metadata,
            "access_count": "invalid",
            "scanned_at": 0,
            "unrecognized": "private",
        },
    }

    assert cache.store_result(str(file_path), scan_result, version_context=version_context)
    cache_key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_entry = json.loads(cache._get_cache_file_path(cache_key).read_text(encoding="utf-8"))

    assert cache_entry["cache_metadata"]["call_graph_source_fingerprints"] == fingerprint_metadata
    assert cache_entry["cache_metadata"]["access_count"] == 1
    assert cache_entry["cache_metadata"]["scanned_at"] > 0
    assert "unrecognized" not in cache_entry["cache_metadata"]


def test_cached_scan_skips_persisting_operational_failures(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scan timeout after 1 seconds", "severity": "warning"}],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_operational_failures_from_checks(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [{"message": "Scan timeout after 1 seconds", "status": "failed"}],
            "issues": [],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2

    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    assert cache_manager.get_stats()["total_entries"] == 0


@pytest.mark.parametrize(
    "metadata",
    [
        {"scan_outcome": INCONCLUSIVE_SCAN_OUTCOME},
        {"analysis_incomplete": True},
        {"operational_error": True},
    ],
)
def test_cached_scan_skips_persisting_incomplete_metadata(
    tmp_path: Path,
    metadata: dict[str, Any],
) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [],
            "metadata": metadata,
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_bare_unsuccessful_results(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [],
            "success": False,
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_normalizes_and_skips_persisting_bare_unsuccessful_scan_result(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        calls["count"] += 1
        result = ScanResult(scanner_name="numpy")
        result.finish(success=False)
        return result

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert isinstance(first, ScanResult)
    assert isinstance(second, ScanResult)
    assert first.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert second.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert first.metadata["scan_outcome_reasons"] == ["scanner_reported_unsuccessful_without_outcome"]
    assert second.metadata["scan_outcome_reasons"] == ["scanner_reported_unsuccessful_without_outcome"]
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_does_not_serialize_known_uncacheable_scan_result(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}

    class UnserializableFailedResult(ScanResult):
        def to_dict(self, *, include_private_metadata: bool = False) -> dict[str, Any]:
            raise AssertionError("known uncacheable results should not be serialized")

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> ScanResult:
        result = UnserializableFailedResult(scanner_name="pickle")
        result.finish(success=False)
        return result

    result = scan(str(file_path), config)

    assert isinstance(result, ScanResult)
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_scan_timed_out_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scan timed out: metadata helper exceeded limit", "severity": "warning"}],
            "timeout_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["timeout_count"] == 1
    assert second["timeout_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_package_not_installed_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [
                {
                    "message": "paddlepaddle package not installed. Install with 'pip install paddlepaddle'",
                    "status": "failed",
                }
            ],
            "issues": [],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_os_level_errors(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "No such file or directory while opening sidecar", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_scanning_error_messages(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": "Scanning error: failed to read shard 0", "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


def test_cached_scan_skips_persisting_memory_mapped_scan_errors(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [{"message": "Memory-mapped scan error: invalid mapping", "status": "failed"}],
            "issues": [],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert calls["count"] == 2
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0


@pytest.mark.parametrize(
    "message",
    [
        "Associated .bin weights file not found",
        "Not a valid zip file: /tmp/example.zip",
    ],
)
def test_cached_scan_persists_deterministic_validation_findings(tmp_path: Path, message: str) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    config = {"cache_enabled": True, "cache_dir": str(cache_dir)}
    calls = {"count": 0}

    @cached_scan()
    def scan(path: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        calls["count"] += 1
        return {
            "checks": [],
            "issues": [{"message": message, "severity": "warning"}],
            "scan_count": calls["count"],
        }

    first = scan(str(file_path), config)
    second = scan(str(file_path), config)

    assert first == second
    assert calls["count"] == 1
    assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 1


def test_configuration_extractor_rebuilds_cached_config_after_mutation() -> None:
    extractor = ConfigurationExtractor()
    config = {"cache_enabled": True, "timeout": 30}

    first, _ = extractor.extract_fast(("file.bin", config), {})
    config["timeout"] = 5
    second, _ = extractor.extract_fast(("file.bin", config), {})

    assert first is not None
    assert second is not None
    assert first is not second
    assert first.get_version_context() != second.get_version_context()


def test_get_cache_manager_reinitializes_for_new_cache_dir(tmp_path: Path) -> None:
    first = get_cache_manager(str(tmp_path / "cache-a"), enabled=True)
    second = get_cache_manager(str(tmp_path / "cache-b"), enabled=True)

    assert first is not second
    assert second.cache is not None
    assert second.cache.cache_dir == tmp_path / "cache-b"


def test_get_cache_manager_reenables_cache_subsystems(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    disabled_manager = get_cache_manager(str(cache_dir), enabled=False)
    assert disabled_manager.enabled is False

    enabled_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(enabled_manager)

    assert enabled_manager.enabled is True
    assert enabled_manager.cache is not None
    assert enabled_manager.key_generator is not None
    assert batch_ops.get_batch_stats()["enabled"] is True


def test_batch_lookup_returns_cached_entries(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    cache_manager.store_result(
        str(file_path),
        expected,
        10,
        version_context=version_context,
    )

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] == expected


def test_batch_lookup_rejects_stale_cache_entries(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache_manager.store_result(str(file_path), expected, 10, version_context=version_context) is True
    assert cache_manager.cache is not None

    cache_key = cache_manager.cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache_manager.cache._get_cache_file_path(cache_key)
    cache_entry = json.loads(cache_file_path.read_text(encoding="utf-8"))
    cache_entry["cache_metadata"]["scanned_at"] = time.time() - (31 * 24 * 60 * 60)
    cache_file_path.write_text(json.dumps(cache_entry, indent=2), encoding="utf-8")

    cached_results = batch_ops.batch_lookup([str(file_path)], version_context=version_context)

    assert cached_results[str(file_path)] is None
    assert not cache_file_path.exists()


def test_batch_store_skips_operational_failures(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)

    stored_count = batch_ops.batch_store(
        [
            (
                str(file_path),
                {
                    "scanner": "test",
                    "success": False,
                    "issues": [{"message": "Scan timed out: metadata helper exceeded limit", "severity": "warning"}],
                    "checks": [],
                    "metadata": {},
                },
                10,
            )
        ]
    )

    assert stored_count == 0
    assert cache_manager.get_stats()["total_entries"] == 0


def test_batch_store_counts_only_persisted_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    batch_ops = BatchCacheOperations(cache_manager)

    assert cache_manager.cache is not None
    monkeypatch.setattr(cache_manager.cache, "_generate_cache_key_material", lambda *args, **kwargs: (None, None))

    stored_count = batch_ops.batch_store(
        [
            (
                str(file_path),
                {
                    "scanner": "test",
                    "success": True,
                    "issues": [],
                    "checks": [],
                    "metadata": {},
                },
                10,
            )
        ]
    )

    assert stored_count == 0
    assert cache_manager.get_stats()["total_entries"] == 0


def test_cache_entry_omits_raw_version_context(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path)
    cache_dir = tmp_path / "cache"
    cache_manager = get_cache_manager(str(cache_dir), enabled=True)
    version_context = build_cache_version_context({"timeout": 30, "api_token": "super-secret-token"})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    cache_manager.store_result(
        str(file_path),
        expected,
        10,
        version_context=version_context,
    )

    assert cache_manager.cache is not None
    cache_key = cache_manager.cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache_manager.cache._get_cache_file_path(cache_key)

    raw_cache_text = cache_file_path.read_text(encoding="utf-8")
    cache_entry = json.loads(raw_cache_text)

    assert "super-secret-token" not in raw_cache_text
    assert "version_context" not in cache_entry["version_info"]


def test_cache_key_is_none_when_scanner_versions_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When scanner versions cannot be resolved, caching must be disabled
    entirely to avoid key collisions between different scanner versions."""
    file_path = _make_cacheable_file(tmp_path)
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})

    def raise_scanner_versions() -> dict[str, str]:
        raise RuntimeError("scanner registry unavailable")

    monkeypatch.setattr(cache, "_get_scanner_versions", raise_scanner_versions)

    key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert key is None


def test_cache_key_generation_avoids_full_hash_for_medium_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = _make_cacheable_file(tmp_path, name="medium.cache")
    file_path.write_bytes(b"x" * (2 * 1024 * 1024))
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))

    def fail_hash(_: str) -> str:
        raise AssertionError("content hash should not be used for medium-file cache lookups")

    monkeypatch.setattr(cache.key_generator.hasher, "hash_file", fail_hash)

    cache_key = cache.generate_cache_key(str(file_path), version_context=build_cache_version_context({"timeout": 30}))

    assert cache_key is not None


def test_large_file_store_reuses_cache_key_content_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = _make_cacheable_file(tmp_path, name="large.cache")
    file_path.write_bytes(b"x" * (11 * 1024 * 1024))
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected_hash = "secure:" + ("a" * 64)
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    monkeypatch.setattr(cache.key_generator.hasher, "hash_file", lambda _path: expected_hash)

    def fail_hash(_path: str, _stat: os.stat_result) -> str:
        raise AssertionError("large-file cache store should reuse the cache-key content hash")

    monkeypatch.setattr(cache.hasher, "hash_file_with_stat", fail_hash)

    assert cache.store_result(str(file_path), expected, 10, version_context=version_context) is True

    cache_key = cache.generate_cache_key(str(file_path), version_context=version_context)
    assert cache_key is not None
    cache_file_path = cache._get_cache_file_path(cache_key)
    cache_entry = json.loads(cache_file_path.read_text(encoding="utf-8"))

    assert cache_entry["file_info"]["hash"] == expected_hash


def test_same_size_rewrite_with_high_resolution_mtime_invalidates_cache(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="medium.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache.store_result(str(file_path), expected, 10, version_context=version_context) is True

    original_stat = file_path.stat()
    file_path.write_bytes(b"y" * 2048)
    base_second_ns = (original_stat.st_mtime_ns // 1_000_000_000) * 1_000_000_000
    original_offset_ns = original_stat.st_mtime_ns % 1_000_000_000
    new_offset_ns = 123_456_789 if original_offset_ns != 123_456_789 else 123_456_790
    os.utime(file_path, ns=(original_stat.st_atime_ns, base_second_ns + new_offset_ns))

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)

    assert cached_result is None


def test_same_size_rewrite_with_restored_mtime_invalidates_cache(tmp_path: Path) -> None:
    file_path = _make_cacheable_file(tmp_path, name="small.cache")
    cache = ScanResultsCache(str(tmp_path / "scan-cache"))
    version_context = build_cache_version_context({"timeout": 30})
    expected = {"checks": [], "issues": [], "metadata": {}, "scanner": "test", "success": True}

    assert cache.store_result(str(file_path), expected, 10, version_context=version_context) is True

    original_stat = file_path.stat()
    file_path.write_bytes(b"y" * 2048)
    os.utime(file_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    cached_result = cache.get_cached_result(str(file_path), version_context=version_context)

    assert cached_result is None
