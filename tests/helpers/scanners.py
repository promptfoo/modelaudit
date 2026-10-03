"""Shared scanner callbacks for orchestration regression tests."""

import builtins
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import pytest

from modelaudit.analysis.unified_context import UnifiedMLContext
from modelaudit.scanners.base import BaseScanner, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.zip_scanner import ZipScanner
from modelaudit.whitelists import POPULAR_MODELS


def scan_with_whitelisted_finding(self: ZipScanner, path: str) -> ScanResult:
    self.context = UnifiedMLContext(
        file_path=Path(path),
        file_size=Path(path).stat().st_size,
        file_type=".keras",
        model_id=next(iter(POPULAR_MODELS)),
        model_source="huggingface",
    )
    result = self._create_result()
    result.add_check(
        name="Fallback Security Finding",
        passed=False,
        message="High confidence fallback anomaly",
        severity=IssueSeverity.CRITICAL,
        rule_code="CUSTOM001",
    )
    result.finish(success=True)
    assert result.issues[0].severity == IssueSeverity.INFO
    return result


def scan_nested_critical_finding(path: str, _config: dict[str, Any]) -> ScanResult:
    nested_result = ScanResult(scanner_name="test_nested")
    nested_result.add_check(
        name="Nested Critical Finding",
        passed=False,
        message="Nested member is malicious",
        severity=IssueSeverity.CRITICAL,
        location=path,
    )
    nested_result.finish(success=False)
    return nested_result


def without_keras_zip_scanner(
    original: Callable[[str], type[BaseScanner] | None],
) -> Callable[[str], type[BaseScanner] | None]:
    def load_scanner(scanner_id: str) -> type[BaseScanner] | None:
        if scanner_id == "keras_zip":
            return None
        return original(scanner_id)

    return load_scanner


def fail_onnx_bounded_discovery(*_args: Any, **_kwargs: Any) -> Any:
    from modelaudit.scanners import onnx_scanner

    raise onnx_scanner._OnnxStructureParseError(
        "retained_object_limit_exceeded",
        "bounded discovery exhausted its retained-object budget",
    )


def scan_nested_unsuccessful(_path: str, _config: dict[str, Any]) -> ScanResult:
    nested_result = ScanResult(scanner_name="test_nested")
    nested_result.finish(success=False)
    return nested_result


def assert_preflighted_archive_survives_replacement(
    monkeypatch: pytest.MonkeyPatch,
    model_path: Path,
    replacement_path: Path,
    scanner_type: type[BaseScanner],
    zip_scanner_type: type[ZipScanner],
) -> None:
    original_scan_archive_members = zip_scanner_type.scan_archive_members
    original_open = builtins.open
    path_reopened = False

    def redirect_path_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal path_reopened
        if str(file) == str(model_path):
            path_reopened = True
            file = replacement_path
        return original_open(file, *args, **kwargs)

    def replace_then_scan(
        scanner: ZipScanner,
        path: str,
        archive: zipfile.ZipFile | None = None,
    ) -> ScanResult:
        assert archive is not None
        with monkeypatch.context() as path_swap:
            path_swap.setattr(builtins, "open", redirect_path_open)
            return original_scan_archive_members(scanner, path, archive=archive)

    monkeypatch.setattr(zip_scanner_type, "scan_archive_members", replace_then_scan)

    result = scanner_type().scan(str(model_path))

    assert path_reopened is False
    assert not any(issue.details.get("zip_entry") == "payload.pkl" for issue in result.issues)
    assert any(entry.get("path", "").endswith(":safe.txt") for entry in result.metadata["contents"])
    assert not any(entry.get("path", "").endswith(":payload.pkl") for entry in result.metadata["contents"])


def install_zip_open_failure(
    monkeypatch: pytest.MonkeyPatch,
    original_open: Callable[..., Any],
    matches: Callable[[str | zipfile.ZipInfo], bool],
    make_error: Callable[[], Exception],
    *,
    positional_mode: bool = True,
) -> None:
    def open_with_failure(
        archive: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: Literal["r", "w"] = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> Any:
        if matches(name):
            raise make_error()
        if positional_mode:
            return original_open(archive, name, mode, pwd, force_zip64=force_zip64)
        return original_open(archive, name, mode=mode, pwd=pwd, force_zip64=force_zip64)

    monkeypatch.setattr(zipfile.ZipFile, "open", open_with_failure)


def assert_skops_cve_clean(scanner: BaseScanner, skops_file: Path, check_name: str) -> None:
    result = scanner.scan(str(skops_file))

    cve_checks = [c for c in result.checks if check_name in c.name]
    assert not [c for c in cve_checks if c.status == CheckStatus.FAILED]


def track_bytesio_close(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    import io

    closed: dict[str, bool] = {}

    class TrackedBytesIO(io.BytesIO):
        def close(self) -> None:
            closed["closed"] = True
            super().close()

    monkeypatch.setattr(io, "BytesIO", TrackedBytesIO)
    return closed
