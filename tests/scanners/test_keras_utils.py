"""Focused tests for shared Keras scanner helpers."""

from modelaudit.scanners.keras_utils import find_lambda_dangerous_patterns


class _CountingLowerString(str):
    lower_calls = 0

    def lower(self) -> str:
        type(self).lower_calls += 1
        return super().lower()


def test_find_lambda_dangerous_patterns_lowers_once() -> None:
    text = _CountingLowerString("Eval and os.system")
    _CountingLowerString.lower_calls = 0

    patterns = find_lambda_dangerous_patterns(text, ["eval", "os.system", "pickle"])

    assert patterns == ["eval", "os.system"]
    assert _CountingLowerString.lower_calls == 1
