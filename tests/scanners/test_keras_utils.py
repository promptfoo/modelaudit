"""Tests for shared Keras scanner helpers."""

import json
import marshal

import pytest

from modelaudit.scanners import keras_utils
from modelaudit.scanners.base import ScanResult
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner
from modelaudit.scanners.keras_utils import (
    check_lambda_list_function,
    check_subclassed_model,
    find_case_insensitive_substrings,
    find_lambda_dangerous_patterns,
    is_known_safe_keras_layer_class,
)


@pytest.mark.parametrize(
    ("module_name", "function_name"),
    [("math", "eval"), ("math", "EVAL"), ("numpy", "system")],
)
def test_h5_lambda_function_names_require_dangerous_module_context(module_name: str, function_name: str) -> None:
    """A safe module must not become critical solely from an unresolved attribute name."""
    assert KerasH5Scanner._is_lambda_module_reference_dangerous(module_name, function_name) is False


@pytest.mark.parametrize(
    ("module_name", "function_name"),
    [(None, "eval"), ("", "open"), ("os", "identity"), ("subprocess", "run")],
)
def test_h5_lambda_unqualified_dangerous_functions_and_risky_modules_are_flagged(
    module_name: str | None,
    function_name: str,
) -> None:
    """Unqualified builtins and risky module roots must remain critical."""
    assert KerasH5Scanner._is_lambda_module_reference_dangerous(module_name, function_name) is True


class _LowerCountingText(str):
    lower_calls: int

    def __new__(cls, value: str) -> "_LowerCountingText":
        instance = super().__new__(cls, value)
        instance.lower_calls = 0
        return instance

    def lower(self) -> str:
        self.lower_calls += 1
        return super().lower()


def test_find_case_insensitive_substrings_reuses_lowered_text() -> None:
    text = _LowerCountingText("Exec once, leave eval absent")

    assert find_case_insensitive_substrings(text, ("exec", "eval", "marshal")) == ["exec", "eval"]
    assert text.lower_calls == 1


def test_find_lambda_dangerous_patterns_ignores_marshaled_filename_paths() -> None:
    text = "\x00/private/tmp/modelaudit-open-prs/tests/scanners/test_keras_h5_scanner.pyz\x08<lambda>"

    assert find_lambda_dangerous_patterns(text, ("open", "exec")) == []


def test_find_lambda_dangerous_patterns_preserves_real_open_calls() -> None:
    text = "lambda body: open('/private/tmp/modelaudit-open-prs/payload.py')"

    assert find_lambda_dangerous_patterns(text, ("open", "exec")) == ["open"]


def test_find_lambda_dangerous_patterns_ignores_substrings_inside_identifiers() -> None:
    text = "opened executor evaluation ecosystem.systemic os + system osésystem"

    assert find_lambda_dangerous_patterns(text, ("open", "exec", "eval", "os.system")) == []


def test_find_lambda_dangerous_patterns_preserves_real_dotted_calls() -> None:
    text = "lambda body: os.system('id')"

    assert find_lambda_dangerous_patterns(text, ("os.system", "os.popen")) == ["os.system"]


def test_find_lambda_dangerous_patterns_detects_marshaled_dotted_symbols() -> None:
    code = compile("import os\nos.system('id')", "<lambda>", "exec")
    text = marshal.dumps(code).decode("utf-8", errors="replace")

    assert find_lambda_dangerous_patterns(text, ("open", "os.system", "os.popen")) == ["os.system"]


def test_known_safe_keras_layer_class_accepts_trusted_qualified_names() -> None:
    for layer_class in (
        "keras.layers.Dense",
        "keras.models.Sequential",
        "tensorflow.keras.layers.TimeDistributed",
        "tensorflow.python.keras.layers.InputLayer",
        "tf_keras.models.Functional",
        "tf_keras.layers.Bidirectional",
    ):
        assert is_known_safe_keras_layer_class(layer_class)


def test_known_safe_keras_layer_class_rejects_non_public_or_untrusted_qualified_names() -> None:
    for layer_class in (
        "keras.evil.Dense",
        "keras.Dense",
        "keras.layers.evil.Dense",
        "keras.src.layers.evil.Dense",
        "keras.src.layers.core.dense.Dense",
        "keras.src.engine.evil.Sequential",
        "keras.layers.Sequential",
        "keras.models.Dense",
        "tensorflow.python.keras.layers.evil.Dense",
        "tensorflow.keras_evil.layers.Dense",
        "tf_keras.evil.Dense",
        "tf_keras.src.layers.evil.Dense",
        "tf_keras.src.engine.evil.Functional",
        "myproject.keras.layers.Dense",
    ):
        assert not is_known_safe_keras_layer_class(layer_class)


def test_lambda_list_findings_redact_layer_names(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "LAMBDA_LAYER_SECRET"
    layer_name = f"token={secret}"

    missing_code_result = ScanResult("keras_test")
    assert check_lambda_list_function([], missing_code_result, "model.h5", layer_name)

    monkeypatch.setattr(keras_utils, "_MAX_LAMBDA_CODE_B64_CHARS", 4)
    oversized_code_result = ScanResult("keras_test")
    assert check_lambda_list_function(["AAAAA"], oversized_code_result, "model.h5", layer_name)

    serialized = json.dumps(
        [
            *[check.model_dump() for check in missing_code_result.checks],
            *[check.model_dump() for check in oversized_code_result.checks],
        ],
        default=str,
    )
    assert secret not in serialized
    assert "token=<redacted>" in serialized


def test_subclassed_model_finding_redacts_secret_assignment_without_redacting_identifier_words() -> None:
    secret = "MODEL_CLASS_SECRET"
    secret_result = ScanResult("keras_test")
    check_subclassed_model(f"token={secret}", secret_result, "model.keras")

    benign_result = ScanResult("keras_test")
    check_subclassed_model("CustomTokenLayer", benign_result, "model.keras")

    assert secret_result.checks[0].details["model_class"] == "token=<redacted>"
    assert secret not in secret_result.checks[0].message
    assert benign_result.checks[0].details["model_class"] == "CustomTokenLayer"
