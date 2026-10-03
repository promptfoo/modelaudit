"""Framework package fixtures shared with root adapter regressions."""

import os
import subprocess
import sys
from collections.abc import Callable
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pytest


def _assert_shadow_framework_unpickle_executes(
    payload_path: Path,
    tmp_path: Path,
    *,
    mode: str,
    extension_code: int | None,
) -> None:
    marker = tmp_path / f"{payload_path.stem}.marker"
    package_root = tmp_path / f"{payload_path.stem}.shadow"
    _write_shadow_transformers_package(package_root, marker)
    code_arg = "none" if extension_code is None else str(extension_code)
    script = (
        "import copyreg, io, pickle, sys\n"
        "from pathlib import Path\n"
        "payload = Path(sys.argv[1]).read_bytes()\n"
        "mode = sys.argv[2]\n"
        "code_arg = sys.argv[3]\n"
        "if code_arg != 'none':\n"
        "    copyreg.add_extension('transformers.training_args', 'TrainingArguments', int(code_arg))\n"
        "if mode == 'nested':\n"
        "    pickle.loads(pickle.loads(payload))\n"
        "elif mode == 'concatenated':\n"
        "    stream = io.BytesIO(payload)\n"
        "    while stream.tell() < len(payload):\n"
        "        pickle.load(stream)\n"
        "else:\n"
        "    pickle.loads(payload)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(payload_path), mode, code_arg],
        check=False,
        env={**os.environ, "PYTHONPATH": str(package_root)},
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (completed.returncode, completed.stderr)
    assert marker.exists(), f"Missing execution marker: {marker}"


def _write_shadow_transformers_package(package_root: Path, marker: Path) -> None:
    package_dir = package_root / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "training_args.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                f"_MARKER = Path({str(marker)!r})",
                "class TrainingArguments:",
                "    __slots__ = ('payload',)",
                "    def __new__(cls, *args, **kwargs):",
                "        return object.__new__(cls)",
                "    def __setstate__(self, state):",
                "        _MARKER.write_text('setstate', encoding='utf-8')",
                "    def __setattr__(self, name, value):",
                "        _MARKER.write_text(f'setattr:{name}', encoding='utf-8')",
                "        object.__setattr__(self, name, value)",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_init_heavy_trusted_transformers_package(site_packages: Path) -> None:
    package_dir = site_packages / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "training_args.py").write_text(
        "\n".join(
            [
                "HELPER = object()",
                "class TrainingArguments:",
                "    def __new__(cls):",
                "        return object.__new__(cls)",
                "    def __init__(self):",
                "        self.helper = HELPER",
                "    def __setstate__(self, state):",
                "        self.__dict__.update(state)",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_sitecustomize_trusting_site_packages(customize_dir: Path, site_packages: Path) -> None:
    customize_dir.mkdir(parents=True, exist_ok=True)
    (customize_dir / "sitecustomize.py").write_text(
        "\n".join(
            [
                "import sysconfig",
                f"_TRUSTED_SITE_PACKAGES = {str(site_packages)!r}",
                "_ORIGINAL_GET_PATH = sysconfig.get_path",
                "def _patched_get_path(name, scheme=None, vars=None, expand=True):",
                "    if name in {'purelib', 'platlib'}:",
                "        return _TRUSTED_SITE_PACKAGES",
                "    if scheme is None and vars is None and expand is True:",
                "        return _ORIGINAL_GET_PATH(name)",
                "    return _ORIGINAL_GET_PATH(name, scheme=scheme, vars=vars, expand=expand)",
                "sysconfig.get_path = _patched_get_path",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_init_inert_setstate_transformers_package(site_packages: Path, marker: Path) -> None:
    package_dir = site_packages / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "training_args.py").write_text(
        "\n".join(
            [
                f"MARKER = {str(marker)!r}",
                "class TrainingArguments:",
                "    def __new__(cls, *args, **kwargs):",
                "        return object.__new__(cls)",
                "    def __setstate__(self, state):",
                "        with open(MARKER, 'w', encoding='utf-8') as handle:",
                "            handle.write('setstate')",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_rebindable_trusted_transformers_package(site_packages: Path) -> None:
    package_dir = site_packages / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "training_args.py").write_text(
        "\n".join(
            [
                "class TrainingArguments:",
                "    def __new__(cls):",
                "        return object.__new__(cls)",
                "",
                "class OptimizerNames:",
                "    def __new__(cls, value=''):",
                "        return object.__new__(cls)",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_import_side_effect_transformers_package(site_packages: Path, marker: Path) -> None:
    package_dir = site_packages / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "training_args.py").write_text(
        "\n".join(
            [
                f"MARKER = {str(marker)!r}",
                "with open(MARKER, 'w', encoding='utf-8') as handle:",
                "    handle.write('import')",
                "class OptimizerNames:",
                "    pass",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_runtime_mutable_trusted_transformers_package(site_packages: Path) -> None:
    package_dir = site_packages / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "training_args.py").write_text(
        "\n".join(
            [
                "def OptimizerNames(value, callback=None):",
                "    if callback is not None:",
                "        return callback(value)",
                "    return None",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_enum_trusted_transformers_package(site_packages: Path) -> None:
    package_dir = site_packages / "transformers"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "trainer_utils.py").write_text(
        "\n".join(
            [
                "from enum import Enum",
                "class IntervalStrategy(str, Enum):",
                "    STEPS = 'steps'",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_rebindable_trusted_torch_utils_package(site_packages: Path) -> None:
    package_dir = site_packages / "torch"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "_utils.py").write_text(
        "\n".join(
            [
                "def _rebuild_tensor(arg):",
                "    return None",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_cross_module_rebind_target_package(site_packages: Path) -> None:
    (site_packages / "trusted_target.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "def rebound_optimizer(path):",
                "    Path(path).write_text('cross-module', encoding='utf-8')",
                "    return None",
                "",
            ]
        ),
        encoding="utf-8",
    )


class SystemCommandPayload:
    """Serializable shell-command reducer for malicious scanner regression fixtures."""

    def __init__(self, command: str, system_getter: Callable[[], Any] | None = None) -> None:
        self.command = command
        self.system_getter = system_getter

    def __reduce__(self) -> tuple[Any, tuple[str]]:
        # Preserve reducer-time imports or the caller's deferred module lookup.
        if self.system_getter is None:
            import os

            system = os.system
        else:
            system = self.system_getter()
        return (system, (self.command,))


_SHADOW_FRAMEWORK_MODULE = "transformers.training_args"
_SHADOW_FRAMEWORK_NAME = "TrainingArguments"


def _pickle_binint(value: int) -> bytes:
    if 0 <= value <= 0xFF:
        return b"K" + bytes([value])
    return b"J" + value.to_bytes(4, "little", signed=True)


def _float_storage_element_count_for_bytes(data: bytes) -> int:
    assert len(data) % 4 == 0, f"Unaligned float storage length: {len(data)}"
    return len(data) // 4


def _pickle_int_tuple(values: tuple[int, ...]) -> bytes:
    payload = b"".join(_pickle_binint(value) for value in values)
    if len(values) == 0:
        return b")"
    if len(values) == 1:
        return payload + b"\x85"
    if len(values) == 2:
        return payload + b"\x86"
    if len(values) == 3:
        return payload + b"\x87"
    return b"(" + payload + b"t"


def _force_framework_metadata_unresolved(monkeypatch: "pytest.MonkeyPatch") -> None:
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._trusted_module_origin_kind",
        lambda _module_name: "unresolved",
    )
    monkeypatch.setattr("modelaudit_picklescan.call_graph._resolve_module_source", lambda _module_name: None)
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._find_module_spec_without_imports",
        lambda _module_name: None,
    )


def _shadow_newobj_build_payload(protocol: int = 4) -> bytes:
    return _stack_global_reference_payload(protocol) + b")\x81}b."


def _shadow_memo_alias_payload() -> bytes:
    return _stack_global_reference_payload(4) + b"\x94" + b"0" + b"h\x02)\x81}b."


def _shadow_newobj_ex_payload() -> bytes:
    return _stack_global_reference_payload(4) + b")}\x92}b."


def _bytes_literal_payload(payload: bytes) -> bytes:
    return b"\x80\x04B" + len(payload).to_bytes(4, "little") + payload + b"."


def _extension_reconstruction_payload(opcode: bytes, encoded_code: bytes) -> bytes:
    return b"\x80\x04" + opcode + encoded_code + b")\x81}b."


def _shadow_framework_divergence_cases() -> tuple[object, ...]:
    import pytest

    nested = _shadow_newobj_build_payload(4)
    return (
        pytest.param("protocol4_stack_global", _shadow_newobj_build_payload(4), "single", None, id="protocol4"),
        pytest.param("protocol5_stack_global", _shadow_newobj_build_payload(5), "single", None, id="protocol5"),
        pytest.param("memo_alias", _shadow_memo_alias_payload(), "single", None, id="memo-alias"),
        pytest.param("newobj_ex", _shadow_newobj_ex_payload(), "single", None, id="newobj-ex"),
        pytest.param("slot_state_build", _shadow_slot_state_build_payload(), "single", None, id="slot-state-build"),
        pytest.param("nested_stream", _bytes_literal_payload(nested), "nested", None, id="nested"),
        pytest.param("concatenated_stream", b"\x80\x04N." + nested, "concatenated", None, id="concatenated"),
        pytest.param("ext1_control", _extension_reconstruction_payload(b"\x82", b"\x01"), "single", 1, id="ext1"),
        pytest.param(
            "ext2_control",
            _extension_reconstruction_payload(b"\x83", (256).to_bytes(2, "little")),
            "single",
            256,
            id="ext2",
        ),
        pytest.param(
            "ext4_control",
            _extension_reconstruction_payload(b"\x84", (70_000).to_bytes(4, "little")),
            "single",
            70_000,
            id="ext4",
        ),
    )


def _large_proto0_system_payload() -> bytes:
    return b"cposix\nsystem\n(S'" + (b"A" * 10_000) + b"'\ntR."


def _frame_first_large_malicious_eval_pickle_payload() -> bytes:
    benign_prefix = b"N0" * 2100
    dangerous_suffix = b"cbuiltins\neval\n(S'print(1)'\ntR."
    body = benign_prefix + dangerous_suffix
    payload = b"\x95" + len(body).to_bytes(8, "little") + body
    assert payload[0] == 0x95, "Payload must start with FRAME"
    assert int.from_bytes(payload[1:9], "little") > 4 * 1024, "Frame must exceed the probe window"
    assert payload.find(b"cbuiltins\neval\n") > 4 * 1024, "Eval must follow the probe window"
    assert payload.rfind(b".") > 4 * 1024, "STOP must follow the probe window"
    return payload


def _frame_first_raw_storage_bytes() -> bytes:
    return b"\x95" + (10_000).to_bytes(8, "little") + (b"\x00" * 4095)


def _pytorch_storage_protocol0_persistent_id_payload(
    key: str,
    *,
    storage_qualname: str = "torch.FloatStorage",
    size: int | str = 1,
) -> bytes:
    return f"(dp0\nVx\np1\nP('storage', <class '{storage_qualname}'>, '{key}', 'cpu', {size})\ns.".encode("ascii")


def _pytorch_storage_then_arbitrary_protocol0_persistent_id_payload(key: str) -> bytes:
    payload = _pytorch_storage_protocol0_persistent_id_payload(key)
    assert payload.endswith(b"."), "Persistent storage payload must end with STOP"
    return payload[:-1] + b"Parbitrary-storage-key\n0."


def _pickleish_tensor_storage_bytes() -> bytes:
    # Minimal prefix from pinned PiD raw tensor storage that looks like a pickle FRAME crossing STOP.
    return bytes.fromhex("478727be61f70dbd70953cbd09b996bd5c7a2ebe") + (b"\x00" * 128)


def _yolov5n6_tensor_storage_prefix_bytes() -> bytes:
    # First 64 bytes of Ultralytics/YOLOv5 yolov5n6.pt archive/data/195 at
    # revision 5bca797074771ecdfd6267d6e9be32ee201d937b.
    return bytes.fromhex(
        "4dae5b2ed9a78527072fd82ac529db2d822f181d76258832bd2f39a63527ad2e"
        "ba2d3eacd9247fb0a32b1525682aa0253831dc2c4c3085296c2cbcb1f52bea31"
    )


def _binary_magic_tensor_storage_bytes() -> bytes:
    return b"\x80\x04\x00" + (b"\x00" * 129)


def _require_torch_distribution() -> None:
    try:
        importlib_metadata.distribution("torch")
    except importlib_metadata.PackageNotFoundError:
        import pytest

        pytest.skip("torch distribution not installed")


def _static_getattr_protocol0_unicode_payload() -> bytes:
    return b"c__builtin__\ngetattr\ncultralytics.nn.modules.head\nDetect\nVforward\n\x86R."


def _clear_ultralytics_modules() -> None:
    for module_name in tuple(sys.modules):
        if module_name == "ultralytics" or module_name.startswith("ultralytics."):
            sys.modules.pop(module_name, None)


def _stack_global_reference_payload(protocol: int) -> bytes:
    return (
        bytes((0x80, protocol))
        + _short_binunicode(_SHADOW_FRAMEWORK_MODULE.encode("ascii"))
        + b"\x94"
        + _short_binunicode(_SHADOW_FRAMEWORK_NAME.encode("ascii"))
        + b"\x94\x93"
    )


def _shadow_slot_state_build_payload() -> bytes:
    return (
        _stack_global_reference_payload(4)
        + b")\x81N}"
        + _short_binunicode(b"payload")
        + _short_binunicode(b"owned")
        + b"s\x86b."
    )


def _make_memo_expansion_pickle(iterations: int, *, inert_writes: int = 0) -> bytes:
    total_writes = iterations + inert_writes
    if not 1 <= iterations <= 255 or total_writes > 255:
        raise ValueError("iterations + inert_writes must fit in BINPUT/BINGET opcodes")

    payload = bytearray(b"\x80\x02)q\x000")
    for memo_index in range(1, iterations + 1):
        previous_index = memo_index - 1
        payload += b"h" + bytes([previous_index])
        payload += b"h" + bytes([previous_index])
        payload += b"\x86"
        payload += b"q" + bytes([memo_index])
        payload += b"0"
    for memo_index in range(iterations + 1, total_writes + 1):
        payload += b"K\x01"
        payload += b"q" + bytes([memo_index])
        payload += b"0"
    payload += b"h" + bytes([iterations]) + b"."
    return bytes(payload)


def _make_pre_memoized_post_budget_stack_global_payload(tail: bytes) -> bytes:
    payload = bytearray(b"\x80\x04")
    payload += _short_binunicode(b"subprocess") + b"\x94"
    payload += _short_binunicode(b"run") + b"\x94"
    payload += b"\x880" * 4
    payload += tail
    return bytes(payload)


def _make_dup_heavy_pickle(iterations: int) -> bytes:
    payload = bytearray(b"\x80\x02]q\x00")
    for _ in range(iterations):
        payload += b"h\x002a0"
    payload += b"."
    return bytes(payload)


def _short_binunicode(data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(data)]) + data


def _replace_source_on_read(
    monkeypatch: "pytest.MonkeyPatch", source_path: Path, displaced_path: Path, replacement_path: Path
) -> None:
    original_read = os.read
    replaced = False

    def replace_after_first_read(file_descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(file_descriptor, size)
        if chunk and not replaced:
            replaced = True
            source_path.rename(displaced_path)
            replacement_path.rename(source_path)
        return chunk

    monkeypatch.setattr(os, "read", replace_after_first_read)


def _replace_source_after_fstat(
    monkeypatch: "pytest.MonkeyPatch", extension_path: Path, displaced_path: Path, replacement_path: Path
) -> None:
    original_fstat = os.fstat
    fstat_calls = 0

    def replace_after_second_fstat(file_descriptor: int) -> os.stat_result:
        nonlocal fstat_calls
        file_stat = original_fstat(file_descriptor)
        fstat_calls += 1
        if fstat_calls == 2:
            extension_path.rename(displaced_path)
            replacement_path.rename(extension_path)
        return file_stat

    monkeypatch.setattr(os, "fstat", replace_after_second_fstat)
