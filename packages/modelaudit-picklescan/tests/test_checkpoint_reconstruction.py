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


def test_trusted_checkpoint_reconstruction_is_clean(transformers_install: Path) -> None:
    enum = b"\x80\x02ctransformers.trainer_utils\nSchedulerType\n" + _text(b"linear") + b"\x85R."
    instance = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(enum).verdict == SafetyVerdict.CLEAN
    assert scan_bytes(instance).verdict == SafetyVerdict.CLEAN


def test_changed_installed_source_keeps_warning(transformers_install: Path) -> None:
    (transformers_install / "training_args.py").write_text(
        "class TrainingArguments:\n    def __setstate__(self, state):\n        print(state)\n"
    )
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN


def test_installed_distribution_is_the_trust_boundary(transformers_install: Path) -> None:
    (transformers_install / "training_args.py").write_text(
        "def restore(self, state):\n    print(state)\n"
        "class TrainingArguments:\n    ignored = locals().update(__setstate__=restore)\n"
    )
    _record_files(transformers_install)
    call_graph._clear_source_sensitive_caches()
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)\x81}b."
    # A matching RECORD is deliberately trusted, even if the installed package is malicious.
    assert scan_bytes(payload).verdict == SafetyVerdict.CLEAN


def test_dangerous_call_survives_trusted_reconstruction(transformers_install: Path) -> None:
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


def test_unusual_invocation_retains_warning(transformers_install: Path) -> None:
    payload = b"\x80\x02ctransformers.training_args\nTrainingArguments\n)R."
    assert scan_bytes(payload).verdict != SafetyVerdict.CLEAN
    constructor = b"\x80\x02ctransformers.training_args\nTrainingArguments\n" + _text(b"config.json") + b"\x85R."
    assert scan_bytes(constructor).verdict != SafetyVerdict.CLEAN
