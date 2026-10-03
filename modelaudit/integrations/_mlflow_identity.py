"""Historical bounded source identity for MLflow acquisition findings."""

import re
from urllib.parse import unquote

from modelaudit.detectors.network_comm import _redact_urls_in_text
from modelaudit.integrations._sarif_identity_urls import redact_cloud_error_for_display, redact_url_for_display
from modelaudit.scanners._evidence_redaction import (
    MAX_PERCENT_DECODE_PASSES,
    MAX_REDACTION_VALUE_DEPTH,
    SENSITIVE_CONTAINER_KEY,
    redact_evidence_string,
)

_MAX_MLFLOW_ERROR_DISPLAY_CHARS = 512
_MLFLOW_SENSITIVE_KEY = rf"(?:{SENSITIVE_CONTAINER_KEY}|credentials?|jwt|session)"
_MLFLOW_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])[\"']?"
    rf"{_MLFLOW_SENSITIVE_KEY}"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|(?:(?:bearer|basic|token)\s+)?[^\s,;&}\]]+)"
)
_MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])(?:[a-z_][\w-]*\.)*(?:headers?|params?|query)\s*\[\s*[\"']?"
    rf"(?:{_MLFLOW_SENSITIVE_KEY}|key)[\"']?\s*\]\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|(?:(?:bearer|basic|token)\s+)?[^\s,;&}\]]+)"
)
_MLFLOW_SENSITIVE_CONTAINER_PREFIX_RE = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?<![\w-])[\"']?"
    rf"{_MLFLOW_SENSITIVE_KEY}"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<open>[({\[])",
)
_MLFLOW_PROTOCOL_RELATIVE_URL_RE = re.compile(
    r"(?i)(?:(?:[\\/]|%(?:25)*(?:2f|5c)){2,})[^\s\"'<>]+",
)
_MLFLOW_BENIGN_AUTH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:bearer|basic|token)(?=\s+(?:authentication|endpoint|refresh|service)\b)",
)


def _redact_mlflow_error_for_display(error: object) -> str:
    def _replace_sensitive_value(match: re.Match[str]) -> str:
        value = match.group("value")
        quote = value[0] if value[:1] in {'"', "'"} else ""
        return f"{match.group('prefix')}{quote}<redacted>{quote}"

    def _redact_protocol_relative_url(match: re.Match[str]) -> str:
        candidate = match.group(0)
        decoded = candidate
        for _ in range(MAX_PERCENT_DECODE_PASSES):
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded

        normalized = decoded.replace("\\/", "/").replace("\\", "/")
        if len(normalized) - len(normalized.lstrip("/")) < 2:
            return candidate
        normalized = f"//{normalized.lstrip('/')}"
        authority = normalized[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" not in authority:
            return candidate

        safe_url = redact_url_for_display(f"https:{normalized}")
        return safe_url.removeprefix("https:")

    def _redact_sensitive_containers(text: str) -> str:
        parts: list[str] = []
        cursor = 0
        closing_delimiters = {"(": ")", "[": "]", "{": "}"}

        while match := _MLFLOW_SENSITIVE_CONTAINER_PREFIX_RE.search(text, cursor):
            parts.append(text[cursor : match.start()])
            parts.append(f"{match.group('prefix')}<redacted>")
            stack = [closing_delimiters[match.group("open")]]
            quote: str | None = None
            escaped = False
            index = match.end()

            while index < len(text) and stack:
                character = text[index]
                if quote is not None:
                    if escaped:
                        escaped = False
                    elif character == "\\":
                        escaped = True
                    elif character == quote:
                        quote = None
                elif character in {'"', "'"}:
                    quote = character
                elif character in closing_delimiters:
                    if len(stack) >= MAX_REDACTION_VALUE_DEPTH:
                        index = len(text)
                        break
                    stack.append(closing_delimiters[character])
                elif character == stack[-1]:
                    stack.pop()
                index += 1

            if stack:
                cursor = len(text)
                break
            cursor = index

        parts.append(text[cursor:])
        return "".join(parts)

    redacted = _MLFLOW_PROTOCOL_RELATIVE_URL_RE.sub(_redact_protocol_relative_url, str(error))
    redacted = _redact_sensitive_containers(redacted)
    redacted = _MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    redacted = _MLFLOW_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    contains_url = bool(
        re.search(r"(?i)(?:\b[a-z][a-z0-9+.-]*://|\bmodels:/)", redacted)
        or _MLFLOW_PROTOCOL_RELATIVE_URL_RE.search(redacted)
    )
    if contains_url:
        redacted = redact_cloud_error_for_display(_redact_urls_in_text(redacted))
    redacted = _MLFLOW_PROTOCOL_RELATIVE_URL_RE.sub(_redact_protocol_relative_url, redacted)
    redacted = _MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)
    redacted = _MLFLOW_SENSITIVE_ASSIGNMENT_RE.sub(_replace_sensitive_value, redacted)

    benign_auth_contexts: list[tuple[str, str]] = []

    def _protect_benign_auth_context(match: re.Match[str]) -> str:
        placeholder = f"MODELAUDITMLFLOWSAFECONTEXT{len(benign_auth_contexts)}"
        benign_auth_contexts.append((placeholder, match.group(0)))
        return placeholder

    redacted = _MLFLOW_BENIGN_AUTH_CONTEXT_RE.sub(_protect_benign_auth_context, redacted)
    if contains_url:
        redacted = redact_evidence_string(redacted, max_chars=None)
    else:
        redacted = "&".join(redact_evidence_string(part, max_chars=None) for part in redacted.split("&"))
    for placeholder, original in benign_auth_contexts:
        redacted = redacted.replace(placeholder, original)

    if len(redacted) <= _MAX_MLFLOW_ERROR_DISPLAY_CHARS:
        return redacted
    return f"{redacted[: _MAX_MLFLOW_ERROR_DISPLAY_CHARS - 3]}..."


def _mlflow_text_requires_specialized_redaction(text: str) -> bool:
    if "models:/" in text.lower():
        return True
    if _MLFLOW_BRACKETED_SENSITIVE_ASSIGNMENT_RE.search(text) or _MLFLOW_SENSITIVE_CONTAINER_PREFIX_RE.search(text):
        return True
    for match in _MLFLOW_PROTOCOL_RELATIVE_URL_RE.finditer(text):
        candidate = match.group(0)
        if candidate.startswith("//") and re.search(r"(?i)[a-z][a-z0-9+.-]*:$", text[: match.start()]):
            continue
        decoded = candidate
        for _ in range(MAX_PERCENT_DECODE_PASSES):
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        normalized = decoded.replace("\\/", "/").replace("\\", "/")
        authority = normalized.lstrip("/").split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in authority:
            return True
    return False


def mlflow_source_identity(value: str) -> str:
    specialized = (
        _redact_mlflow_error_for_display(value) if _mlflow_text_requires_specialized_redaction(value) else value
    )
    return redact_evidence_string(specialized, max_chars=_MAX_MLFLOW_ERROR_DISPLAY_CHARS)
