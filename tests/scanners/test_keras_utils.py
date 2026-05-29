"""Tests for shared Keras scanner helpers."""

from modelaudit.scanners.keras_utils import find_case_insensitive_substrings, find_lambda_dangerous_patterns


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
