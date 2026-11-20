from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from modelaudit_picklescan import SafetyVerdict, call_graph, scan_bytes


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
    (metadata / "RECORD").write_text(
        "transformers/__init__.py,,\ntransformers/trainer_utils.py,,\ntransformers/training_args.py,,\n"
    )
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
