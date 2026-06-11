"""SBOM symlink containment regressions."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from modelaudit.integrations.sbom_generator import (
    _supports_descriptor_walk,
    generate_sbom,
    generate_sbom_pydantic,
)
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
    assert _property_value(dict_component, "size") == "0"

    pydantic_result = create_initial_audit_result()
    pydantic_result.file_metadata[str(link)] = FileMetadataModel(
        file_size=len(outside_content),
        file_hashes=FileHashesModel(sha256=outside_hash),
    )
    pydantic_sbom: dict[str, Any] = json.loads(generate_sbom_pydantic([str(scan_root)], pydantic_result))
    pydantic_component = _component_named(pydantic_sbom, "external.bin")
    assert _sha256_values(pydantic_component) == []
    assert _property_value(pydantic_component, "size") == "0"


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


def test_sbom_normalizes_top_level_component_metadata_path(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    model_file = scan_root / "model.bin"
    model_file.write_bytes(b"top-level model content")
    results = {
        "issues": [{"location": str(model_file), "severity": "critical"}],
        "file_metadata": {str(model_file): {"is_model": True}},
    }

    component = _component_named(json.loads(generate_sbom([str(scan_root)], results)), model_file.name)

    assert component["bom-ref"] == str(model_file)
    assert _property_value(component, "ml:is_model") == "true"
    assert _property_value(component, "risk_score") == "5"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported on this platform")
@pytest.mark.parametrize("use_pydantic", [False, True])
def test_sbom_rejects_fifo_without_opening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    use_pydantic: bool,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    fifo_path = scan_root / "model.bin"
    os.mkfifo(fifo_path)
    real_open = os.open

    def reject_fifo_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path in {str(fifo_path), fifo_path.name}:
            raise AssertionError("SBOM hashing must reject a known FIFO before opening it")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", reject_fifo_open)

    if use_pydantic:
        sbom_text = generate_sbom_pydantic([str(scan_root)], create_initial_audit_result())
    else:
        sbom_text = generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}})

    component = _component_named(json.loads(sbom_text), fifo_path.name)
    assert _sha256_values(component) == []
    assert _property_value(component, "size") == "0"


@pytest.mark.parametrize("use_pydantic", [False, True])
def test_sbom_omits_hash_when_file_becomes_directory_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    use_pydantic: bool,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    model_file = scan_root / "model.bin"
    model_file.write_bytes(b"regular before enumeration")
    real_open = os.open
    replaced = False

    def _replace_file_before_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == model_file.name and dir_fd is not None and not replaced:
            replaced = True
            model_file.unlink()
            model_file.mkdir()
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _replace_file_before_open)

    if use_pydantic:
        sbom_text = generate_sbom_pydantic([str(scan_root)], create_initial_audit_result())
    else:
        sbom_text = generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}})

    component = _component_named(json.loads(sbom_text), model_file.name)
    assert replaced is True
    assert _sha256_values(component) == []
    assert _property_value(component, "size") == "0"


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
    link.symlink_to(target.name)

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
    real_readlink = os.readlink
    swapped = False

    def _swap_link_before_read(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> str:
        nonlocal swapped
        if path == link.name and dir_fd is not None and not swapped:
            swapped = True
            link.unlink()
            link.symlink_to(outside_file)
        return real_readlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "readlink", _swap_link_before_read)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}}))
    component = _component_named(sbom_data, "swapped.bin")

    assert _sha256_values(component) == []
    assert hashlib.sha256(outside_content).hexdigest() not in _sha256_values(component)
    assert _property_value(component, "size") == "0"


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

    def _swap_file_before_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path in {str(model_file), model_file.name} and not swapped:
            swapped = True
            model_file.unlink()
            model_file.symlink_to(outside_file)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _swap_file_before_open)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}}))
    component = _component_named(sbom_data, "swapped.bin")

    assert _sha256_values(component) == []
    assert hashlib.sha256(outside_content).hexdigest() not in _sha256_values(component)
    assert _property_value(component, "size") == "0"


def test_sbom_hashing_stays_bound_to_open_parent_directory_during_swap(
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_root = tmp_path / "scan-root"
    parent = scan_root / "models"
    parent.mkdir(parents=True)
    model_file = parent / "model.bin"
    inside_content = b"descriptor-bound in-root model"
    model_file.write_bytes(inside_content)

    outside_parent = tmp_path / "outside-models"
    outside_parent.mkdir()
    outside_content = b"outside model selected by a parent symlink swap"
    (outside_parent / model_file.name).write_bytes(outside_content)
    moved_parent = scan_root / "models-original"

    real_open = os.open
    swapped = False

    def _swap_parent_before_file_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == model_file.name and dir_fd is not None and not swapped:
            swapped = True
            parent.rename(moved_parent)
            parent.symlink_to(outside_parent, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _swap_parent_before_file_open)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}}))
    component = _component_named(sbom_data, model_file.name)

    if _supports_descriptor_walk():
        assert _sha256_values(component) == [hashlib.sha256(inside_content).hexdigest()]
    else:
        assert _sha256_values(component) == []
    assert hashlib.sha256(outside_content).hexdigest() not in _sha256_values(component)


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
    real_readlink = os.readlink
    removed = False

    def _remove_link_before_read(
        path: str,
        *,
        dir_fd: int | None = None,
    ) -> str:
        nonlocal removed
        if path == link.name and dir_fd is not None and not removed:
            removed = True
            link.unlink()
        return real_readlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "readlink", _remove_link_before_read)
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


def test_sbom_omits_recorded_hash_for_local_input_missing_before_generation(tmp_path: Path) -> None:
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

    assert _sha256_values(component) == []
    assert _property_value(component, "size") == "0"


def test_sbom_omits_recorded_hash_for_removed_outside_symlink(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    outside_file = tmp_path / "outside.bin"
    outside_content = b"outside symlink target scanned before the link disappeared"
    outside_file.write_bytes(outside_content)
    outside_hash = hashlib.sha256(outside_content).hexdigest()
    link = tmp_path / "removed-link.bin"
    link.symlink_to(outside_file)
    link.unlink()

    metadata = {
        "file_size": len(outside_content),
        "file_hashes": {"sha256": outside_hash},
    }
    sbom_data: dict[str, Any] = json.loads(
        generate_sbom([str(link)], {"issues": [], "file_metadata": {str(link): metadata}})
    )
    component = _component_named(sbom_data, "removed-link.bin")

    assert _sha256_values(component) == []
    assert _property_value(component, "size") == "0"


def test_sbom_preserves_recorded_hash_for_remote_identifier() -> None:
    remote_path = "s3://model-bucket/model.bin"
    recorded_content = b"remote metadata-only component"
    recorded_hash = hashlib.sha256(recorded_content).hexdigest()
    metadata = {
        "file_size": len(recorded_content),
        "file_hashes": {"sha256": recorded_hash},
    }

    sbom_data: dict[str, Any] = json.loads(
        generate_sbom([remote_path], {"issues": [], "file_metadata": {remote_path: metadata}})
    )
    component = _component_named(sbom_data, "model.bin")

    assert _sha256_values(component) == [recorded_hash]
    assert _property_value(component, "size") == str(len(recorded_content))


def test_sbom_omits_partial_sha256_prefix_for_remote_identifier() -> None:
    remote_path = "s3://model-bucket/model.pt"
    metadata = {
        "file_size": 2048,
        "file_hashes": {"sha256_prefix": "c" * 64},
    }

    sbom_data: dict[str, Any] = json.loads(
        generate_sbom([remote_path], {"issues": [], "file_metadata": {remote_path: metadata}})
    )
    component = _component_named(sbom_data, "model.pt")

    assert _sha256_values(component) == []
    assert _property_value(component, "size") == "2048"


def test_sbom_preserves_recorded_hash_for_trusted_streamed_asset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streamed_path = tmp_path / "streamed.bin"
    recorded_content = b"ephemeral streamed component"
    recorded_hash = hashlib.sha256(recorded_content).hexdigest()
    metadata = {
        "file_size": len(recorded_content),
        "file_hashes": {"sha256": recorded_hash},
    }
    results = {
        "issues": [],
        "assets": [{"path": str(streamed_path), "type": "pickle", "is_streamed": True}],
        "file_metadata": {str(streamed_path): metadata},
    }
    real_open = os.open

    def _reject_late_streamed_path_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == str(streamed_path):
            raise AssertionError("missing streamed paths must use trusted metadata without reopening")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _reject_late_streamed_path_open)

    sbom_data: dict[str, Any] = json.loads(generate_sbom([str(streamed_path)], results))
    component = _component_named(sbom_data, streamed_path.name)

    assert _sha256_values(component) == [recorded_hash]
    assert _property_value(component, "size") == str(len(recorded_content))


@pytest.mark.parametrize("use_pydantic", [False, True])
def test_sbom_enumeration_stays_bound_to_replaced_scan_root(
    tmp_path: Path,
    requires_symlinks: None,
    monkeypatch: pytest.MonkeyPatch,
    use_pydantic: bool,
) -> None:
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    (scan_root / "inside.bin").write_bytes(b"original contained file")
    inside_hash = hashlib.sha256(b"original contained file").hexdigest()
    moved_root = tmp_path / "moved-root"
    outside_root = tmp_path / "outside-root"
    outside_root.mkdir()
    outside_content = b"outside directory content must not be hashed"
    (outside_root / "secret.bin").write_bytes(outside_content)
    outside_hash = hashlib.sha256(outside_content).hexdigest()
    real_walk = os.walk
    real_fwalk = os.fwalk
    swapped = False

    def _replace_root() -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            scan_root.rename(moved_root)
            scan_root.symlink_to(outside_root, target_is_directory=True)

    def _replace_root_before_walk(path: str) -> Any:
        if path == str(scan_root):
            _replace_root()
        return real_walk(path)

    def _replace_root_before_fwalk(*args: Any, **kwargs: Any) -> Any:
        _replace_root()
        return real_fwalk(*args, **kwargs)

    monkeypatch.setattr(os, "walk", _replace_root_before_walk)
    monkeypatch.setattr(os, "fwalk", _replace_root_before_fwalk)

    if use_pydantic:
        sbom_text = generate_sbom_pydantic([str(scan_root)], create_initial_audit_result())
    else:
        sbom_text = generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}})
    sbom_data: dict[str, Any] = json.loads(sbom_text)

    assert outside_hash not in json.dumps(sbom_data)
    if _supports_descriptor_walk():
        component = _component_named(sbom_data, "inside.bin")
        assert _sha256_values(component) == [inside_hash]
        assert all(entry.get("name") != "secret.bin" for entry in sbom_data.get("components", []))
    else:
        component = _component_named(sbom_data, "secret.bin")
        assert _sha256_values(component) == []
        assert _property_value(component, "size") == "0"


@pytest.mark.skipif(
    os.name == "nt" or not (hasattr(os, "O_PATH") or hasattr(os, "O_SEARCH")),
    reason="execute-only directory descriptors are unavailable",
)
@pytest.mark.parametrize("use_pydantic", [False, True])
def test_sbom_hashes_single_file_beneath_execute_only_parent(
    tmp_path: Path,
    use_pydantic: bool,
) -> None:
    parent = tmp_path / "execute-only"
    parent.mkdir()
    model_file = parent / "model.bin"
    content = b"readable file beneath an execute-only parent"
    model_file.write_bytes(content)
    parent.chmod(0o111)
    try:
        if use_pydantic:
            sbom_text = generate_sbom_pydantic([str(model_file)], create_initial_audit_result())
        else:
            sbom_text = generate_sbom([str(model_file)], {"issues": [], "file_metadata": {}})
    finally:
        parent.chmod(0o700)

    component = _component_named(json.loads(sbom_text), model_file.name)
    assert _sha256_values(component) == [hashlib.sha256(content).hexdigest()]
    assert _property_value(component, "size") == str(len(content))


@pytest.mark.skipif(
    os.name == "nt" or not (hasattr(os, "O_PATH") or hasattr(os, "O_SEARCH")),
    reason="execute-only directory descriptors are unavailable",
)
@pytest.mark.parametrize("use_pydantic", [False, True])
def test_sbom_hashes_directory_beneath_execute_only_parent(
    tmp_path: Path,
    use_pydantic: bool,
) -> None:
    parent = tmp_path / "execute-only"
    scan_root = parent / "models"
    scan_root.mkdir(parents=True)
    model_file = scan_root / "model.bin"
    content = b"readable scan root beneath an execute-only parent"
    model_file.write_bytes(content)
    parent.chmod(0o111)
    try:
        if use_pydantic:
            sbom_text = generate_sbom_pydantic([str(scan_root)], create_initial_audit_result())
        else:
            sbom_text = generate_sbom([str(scan_root)], {"issues": [], "file_metadata": {}})
    finally:
        parent.chmod(0o700)

    component = _component_named(json.loads(sbom_text), model_file.name)
    assert _sha256_values(component) == [hashlib.sha256(content).hexdigest()]
    assert _property_value(component, "size") == str(len(content))
