from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from modelaudit_picklescan import SafetyVerdict, call_graph, scan_bytes


def _record_files(package: Path) -> None:
    lines = []
    for path in sorted(package.glob("*.py")):
        content = path.read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        lines.append(f"transformers/{path.name},sha256={digest},{len(content)}\n")
    (package.parent / "transformers-1.0.dist-info" / "RECORD").write_text("".join(lines))


@pytest.fixture
def transformers_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    site = tmp_path / "site-packages"
    package = site / "transformers"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "trainer_utils.py").write_text(
        "from enum import Enum\nclass SchedulerType(str, Enum):\n    LINEAR = 'linear'\n"
    )
    (package / "training_args.py").write_text("class TrainingArguments:\n    pass\n")
    metadata = site / "transformers-1.0.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text("Metadata-Version: 2.1\nName: transformers\nVersion: 1.0\n")
    _record_files(package)
    monkeypatch.setattr(call_graph, "_TRUSTED_SITE_PACKAGE_PATHS", (site.resolve(),))
    monkeypatch.syspath_prepend(str(site))
    call_graph._clear_source_sensitive_caches()
    yield package
    call_graph._clear_source_sensitive_caches()


def _text(value: bytes) -> bytes:
    return b"X" + len(value).to_bytes(4, "little") + value


def test_trusted_enum_value_is_clean_but_reuse_with_invalid_value_still_warns(transformers_install: Path) -> None:
    global_ref = b"ctransformers.trainer_utils\nSchedulerType\nq\x00"
    valid = global_ref + _text(b"linear") + b"\x85R"
    assert scan_bytes(b"\x80\x02" + valid + b".").verdict == SafetyVerdict.CLEAN
    report = scan_bytes(b"\x80\x02" + valid + b"0h\x00" + _text(b"unknown") + b"\x85R.")
    assert report.verdict == SafetyVerdict.SUSPICIOUS


def test_checkpoint_class_with_setstate_hook_is_not_suppressed(transformers_install: Path) -> None:
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(payload).verdict == SafetyVerdict.CLEAN
    (transformers_install / "training_args.py").write_text(
        "class TrainingArguments:\n    def __setstate__(self, state):\n        print(state)\n"
    )
    call_graph._clear_source_sensitive_caches()
    assert scan_bytes(payload).verdict in {SafetyVerdict.SUSPICIOUS, SafetyVerdict.MALICIOUS}


def test_real_dangerous_call_survives_normal_framework_reconstruction(transformers_install: Path) -> None:
    payload = (
        b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n"
        + _text(b"linear")
        + b"\x85R0cos\nsystem\n"
        + _text(b"echo malicious")
        + b"\x85R."
    )
    report = scan_bytes(payload)
    assert report.verdict == SafetyVerdict.MALICIOUS
    assert any(f.rule_code == "DANGEROUS_CALL" for f in report.findings)


def test_checkpoint_enum_alias_cannot_hide_invalid_reuse(transformers_install: Path) -> None:
    payload = (
        b"\x80\x02ctransformers.trainer_utils\nSchedulerType\nq\x002q\x010"
        + _text(b"linear")
        + b"\x85R0h\x01"
        + _text(b"unknown")
        + b"\x85R."
    )
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_class_with_assigned_setstate_is_not_suppressed(transformers_install: Path) -> None:
    (transformers_install / "training_args.py").write_text(
        "def restore(self, state):\n    print(state)\nclass TrainingArguments:\n    __setstate__ = restore\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_class_with_conditional_setstate_is_not_suppressed(transformers_install: Path) -> None:
    (transformers_install / "training_args.py").write_text(
        "class TrainingArguments:\n    if True:\n        def __setstate__(self, state):\n            print(state)\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


@pytest.mark.parametrize(
    ("method", "tail"),
    [
        ("def __del__(self):\n        print('finalizer')", b"0N."),
        ("def __hash__(self):\n        print('hash')\n        return 1", b"K\x01s."),
        ("def __setitem__(self, key, value):\n        print(key)", b"K\x01K\x02s."),
        ("def append(self, value):\n        print(value)", b"K\x01a."),
    ],
)
def test_checkpoint_class_runtime_hooks_are_not_suppressed(
    transformers_install: Path, method: str, tail: bytes
) -> None:
    (transformers_install / "training_args.py").write_text(f"class TrainingArguments:\n    {method}\n")
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    prefix = b"}" if "__hash__" in method else b""
    payload = b"\x80\x02" + prefix + b"ctransformers.training_args\nTrainingArguments\n)\x81}b" + tail
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_dynamic_restore_hook_is_not_suppressed(transformers_install: Path) -> None:
    (transformers_install / "training_args.py").write_text(
        "class TrainingArguments:\n    def __getattr__(self, name):\n        return lambda value: print(value)\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


@pytest.mark.parametrize(
    "binding", ["for __setstate__ in [restore]:\n        pass", "if (__setstate__ := restore):\n        pass"]
)
def test_checkpoint_class_unresolved_binding_is_not_suppressed(transformers_install: Path, binding: str) -> None:
    (transformers_install / "training_args.py").write_text(
        f"def restore(self, state):\n    print(state)\nclass TrainingArguments:\n    {binding}\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_changed_checkpoint_module_is_not_suppressed(transformers_install: Path) -> None:
    (transformers_install / "trainer_utils.py").write_text(
        "from enum import Enum\n"
        "print('module initialization')\n"
        "class SchedulerType(str, Enum):\n    LINEAR = 'linear'\n"
    )
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n" + _text(b"linear") + b"\x85R."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_enum_base_must_be_real_enum(transformers_install: Path) -> None:
    (transformers_install / "trainer_utils.py").write_text(
        "class ExplicitEnum:\n"
        "    def __init__(self, value):\n        print(value)\n"
        "class SchedulerType(ExplicitEnum):\n    LINEAR = 'linear'\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n" + _text(b"linear") + b"\x85R."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_enum_ignored_value_is_not_trusted(transformers_install: Path) -> None:
    (transformers_install / "trainer_utils.py").write_text(
        "from enum import Enum\nclass SchedulerType(str, Enum):\n"
        "    _ignore_ = 'LINEAR'\n    LINEAR = 'linear'\n"
        "    @classmethod\n    def _missing_(cls, value):\n        print(value)\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n" + _text(b"linear") + b"\x85R."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_enum_dunder_is_not_a_member(transformers_install: Path) -> None:
    (transformers_install / "trainer_utils.py").write_text(
        "from enum import Enum\nclass ExplicitEnum(str, Enum):\n"
        "    @classmethod\n    def _missing_(cls, value):\n        print(value)\n"
        "class SchedulerType(ExplicitEnum):\n    OTHER = 'other'\n    __FAKE__ = 'linear'\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n" + _text(b"linear") + b"\x85R."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_checkpoint_enum_base_cannot_rewrite_values(transformers_install: Path) -> None:
    (transformers_install / "trainer_utils.py").write_text(
        "from enum import Enum\nclass ExplicitEnum(str, Enum):\n"
        "    def __new__(cls, value):\n        obj = str.__new__(cls, value)\n"
        "        obj._value_ = 'changed'\n        return obj\n"
        "    @classmethod\n    def _missing_(cls, value):\n        print(value)\n"
        "class SchedulerType(ExplicitEnum):\n    LINEAR = 'linear'\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n" + _text(b"linear") + b"\x85R."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN
