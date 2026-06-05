"""SBOM symlink containment regressions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from modelaudit.integrations.sbom_generator import generate_sbom, generate_sbom_pydantic
from modelaudit.models import FileHashesModel, FileMetadataModel, create_initial_audit_result


def _component_named(sbom_data: dict[str, Any], name: str) -> dict[str, Any]:
    components = sbom_data.get("components", [])
    assert isinstance(components, list)
    for component in components:
        if isinstance(component, dict) and component.get("name") == name:
            return component
    raise AssertionError(f"missing SBOM component {name!r}")


def _sha256_values(component: dict[str, Any]) -> list[str]:
    hashes = component.get("hashes", [])
    assert isinstance(hashes, list)
    return [entry["content"] for entry in hashes if isinstance(entry, dict) and entry.get("alg") == "SHA-256"]


def _property_value(component: dict[str, Any], name: str) -> str:
    properties = component.get("properties", [])
    assert isinstance(properties, list)
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == name:
            value = prop.get("value")
            assert isinstance(value, str)
            return value
    raise AssertionError(f"missing SBOM property {name!r}")


def test_sbom_does_not_hash_outside_root_symlink(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    outside_root = tmp_path / "outside-root"
    outside_root.mkdir()

    outside_file = outside_root / "secret.bin"
    outside_content = b"outside target must not be hashed into the SBOM"
    outside_file.write_bytes(outside_content)
    outside_hash = hashlib.sha256(outside_content).hexdigest()

    link = scan_root / "external.bin"
    link.symlink_to(outside_file)
    fake_metadata = {
        "file_size": len(outside_content),
        "file_hashes": {"sha256": outside_hash},
    }

    dict_sbom: dict[str, Any] = json.loads(
        generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {str(link): fake_metadata}})
    )
    dict_component = _component_named(dict_sbom, "external.bin")
    assert _sha256_values(dict_component) == []
    assert _property_value(dict_component, "size") == str(os.lstat(link).st_size)

    pydantic_result = create_initial_audit_result()
    pydantic_result.file_metadata[str(link)] = FileMetadataModel(
        file_size=len(outside_content),
        file_hashes=FileHashesModel(sha256=outside_hash),
    )
    pydantic_sbom: dict[str, Any] = json.loads(generate_sbom_pydantic([str(scan_root)], pydantic_result))
    pydantic_component = _component_named(pydantic_sbom, "external.bin")
    assert _sha256_values(pydantic_component) == []
    assert _property_value(pydantic_component, "size") == str(os.lstat(link).st_size)


def test_sbom_hashes_ordinary_files(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    model_file = scan_root / "model.bin"
    content = b"ordinary model content remains covered"
    model_file.write_bytes(content)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}}))
    component = _component_named(sbom_data, "model.bin")

    assert _sha256_values(component) == [hashlib.sha256(content).hexdigest()]
    assert _property_value(component, "size") == str(len(content))


def test_sbom_hashes_in_root_symlink_targets(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    target = scan_root / "weights.bin"
    content = b"in-root target remains covered"
    target.write_bytes(content)

    link = scan_root / "weights-link.bin"
    link.symlink_to(target)

    pydantic_result = create_initial_audit_result()
    sbom_data: dict[str, Any] = json.loads(generate_sbom_pydantic([str(scan_root)], pydantic_result))
    component = _component_named(sbom_data, "weights-link.bin")

    assert _sha256_values(component) == [hashlib.sha256(content).hexdigest()]
    assert _property_value(component, "size") == str(len(content))


def test_sbom_omits_hash_when_in_root_symlink_target_changes_during_validation(
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    inside_file = scan_root / "inside.bin"
    inside_content = b"contained target selected before the symlink swap"
    inside_file.write_bytes(inside_content)
    outside_file = tmp_path / "outside.bin"
    outside_content = b"outside target must never be hashed after the symlink swap"
    outside_file.write_bytes(outside_content)

    link = scan_root / "swapped.bin"
    link.symlink_to(inside_file)
    real_realpath = os.path.realpath
    swapped = False

    def _swap_link_after_resolution(path: str) -> str:
        nonlocal swapped
        resolved = real_realpath(path)
        if path == str(link) and not swapped:
            swapped = True
            link.unlink()
            link.symlink_to(outside_file)
        return resolved

    monkeypatch.setattr(os.path, "realpath", _swap_link_after_resolution)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}}))
    component = _component_named(sbom_data, "swapped.bin")

    assert _sha256_values(component) == []
    assert hashlib.sha256(outside_content).hexdigest() not in _sha256_values(component)
    assert _property_value(component, "size") == str(os.lstat(link).st_size)


def test_sbom_omits_hash_when_regular_file_becomes_outside_root_symlink_before_open(
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    model_file = scan_root / "swapped.bin"
    model_file.write_bytes(b"ordinary file before the swap")
    outside_file = tmp_path / "outside.bin"
    outside_content = b"outside target must never be hashed after the file swap"
    outside_file.write_bytes(outside_content)

    real_open = os.open
    swapped = False

    def _swap_file_before_open(path: str, flags: int, mode: int = 0o777) -> int:
        nonlocal swapped
        if path == str(model_file) and not swapped:
            swapped = True
            model_file.unlink()
            model_file.symlink_to(outside_file)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", _swap_file_before_open)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}}))
    component = _component_named(sbom_data, "swapped.bin")

    assert _sha256_values(component) == []
    assert hashlib.sha256(outside_content).hexdigest() not in _sha256_values(component)
    assert _property_value(component, "size") == str(os.lstat(model_file).st_size)


def test_sbom_omits_recorded_hash_when_listed_symlink_disappears_after_containment_check(
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    inside_file = scan_root / "inside.bin"
    inside_file.write_bytes(b"contained target selected before deletion")
    outside_content = b"recorded outside digest must not survive a lost binding"
    outside_hash = hashlib.sha256(outside_content).hexdigest()

    link = scan_root / "disappearing.bin"
    link.symlink_to(inside_file)
    real_realpath = os.path.realpath
    removed = False

    def _remove_link_after_resolution(path: str) -> str:
        nonlocal removed
        resolved = real_realpath(path)
        if path == str(link) and not removed:
            removed = True
            link.unlink()
        return resolved

    monkeypatch.setattr(os.path, "realpath", _remove_link_after_resolution)
    fake_metadata = {
        "file_size": len(outside_content),
        "file_hashes": {"sha256": outside_hash},
    }

    sbom_data: dict[str, Any] = json.loads(
        generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {str(link): fake_metadata}})
    )
    component = _component_named(sbom_data, "disappearing.bin")

    assert _sha256_values(component) == []
    assert outside_hash not in _sha256_values(component)
    assert _property_value(component, "size") == "0"


def test_sbom_preserves_recorded_hash_for_input_missing_before_generation(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.bin"
    recorded_content = b"metadata-only component"
    recorded_hash = hashlib.sha256(recorded_content).hexdigest()
    metadata = {
        "file_size": len(recorded_content),
        "file_hashes": {"sha256": recorded_hash},
    }

    sbom_data: dict[str, Any] = json.loads(
        generate_sbom([str(missing_file)], {"issues": [], "file_metadata": {str(missing_file): metadata}})
    )
    component = _component_named(sbom_data, "missing.bin")

    assert _sha256_values(component) == [recorded_hash]
    assert _property_value(component, "size") == str(len(recorded_content))
