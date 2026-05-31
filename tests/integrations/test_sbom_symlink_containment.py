"""SBOM symlink containment regressions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

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
