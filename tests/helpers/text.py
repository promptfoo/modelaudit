"""Text instrumentation shared by scanner tests."""


class LowerCountingText(str):
    lower_calls: int

    def __new__(cls, value: str) -> "LowerCountingText":
        instance = super().__new__(cls, value)
        instance.lower_calls = 0
        return instance

    def lower(self) -> str:
        self.lower_calls += 1
        return super().lower()
