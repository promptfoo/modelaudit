"""Network Communication Detection for ML models.

This module detects potential network communication capabilities in model files
that could be used for data exfiltration or command & control operations.
"""

import ast
import ipaddress
import math
import re
import tokenize
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterator
from contextlib import suppress
from functools import lru_cache
from importlib.resources import files
from io import BytesIO
from typing import Any, ClassVar
from urllib.parse import unquote, unquote_plus, urlsplit, urlunsplit

_REDACTED_PATH_TOKEN = "<redacted>"
_URL_IN_TEXT_PATTERN = re.compile(
    r"(?:https?|ftp|ftps|ssh|telnet|ws|wss|s3|gs|az|wasbs?|abfss?)://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)
_URL_IN_BYTES_PATTERN = re.compile(_URL_IN_TEXT_PATTERN.pattern.encode("ascii"), re.IGNORECASE)
_URI_IN_TEXT_PATTERN = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)
_URI_IN_BYTES_PATTERN = re.compile(_URI_IN_TEXT_PATTERN.pattern.encode("ascii"), re.IGNORECASE)
_BARE_IPV4_PATTERN = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_BARE_DOMAIN_PATTERN = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_BARE_PORT_SUFFIX_PATTERN = re.compile(rb"^\s*[\"']?\s*[,):]\s*[\"']?(\d{1,5})\b")
_ENCODED_URI_SCHEME_PATTERN = re.compile(
    r"[a-z][a-z0-9+.-]{0,31}%(?:25)*3a%(?:25)*2f%(?:25)*2f",
    re.IGNORECASE,
)
_SENSITIVE_PATH_KEY_PATTERN = re.compile(
    r"^(?:"
    r"api_?key|x_?api_?key|(?:aws_?)?access_?key(?:_?id)?|(?:aws_?)?secret_?access_?key|"
    r"aws_?session_?token|"
    r"access_?token|auth|auth_?token|authorization|proxy_?authorization|bearer|"
    r"client_?secret|credential|private_?key|password|passwd|pwd|refresh_?token|sas|"
    r"secret|secret_?key|session|session_?id|cookie|set_?cookie|token|signature|sig|"
    r"x_?amz_?(?:credential|signature|security_?token)|x_?goog_?(?:credential|signature)"
    r")$",
    re.IGNORECASE,
)
_URL_ASSIGNMENT_PREFIX_PATTERN = re.compile(
    rb"(?:\"\"\"|'''|[\"'])?\s*[:=]\s*(?:[rRuUbBfF]{0,3})?(?:\"\"\"|'''|[\"'])?\s*"
)
_SENSITIVE_PATH_TOKEN_PATTERN = re.compile(
    r"(?i)^(?:"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[opsur]_[A-Za-z0-9]{36}|"
    r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|"
    r"hf_[A-Za-z0-9]{30,}|"
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*|"
    r"sk-(?:proj-)?[A-Za-z0-9]{24,}|"
    r"xox[baprs]-[0-9A-Za-z-]{20,}"
    r")$"
)
_HEX_PATH_TOKEN_PATTERN = re.compile(r"(?i)^[a-f0-9]{32,}$")
_PATH_TOKEN_CHARACTER_CLASS_PATTERNS = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"\d"),
    re.compile(r"[._~+/=\-]"),
)
_ARTIFACT_FILENAME_PATTERN = re.compile(r"(?i)^.+\.[a-z0-9]{1,20}$")
_KNOWN_ARTIFACT_FILENAME_EXTENSIONS = frozenset(
    {
        "bin",
        "ckpt",
        "gguf",
        "h5",
        "hdf5",
        "index",
        "json",
        "jsonl",
        "md",
        "mlmodel",
        "npy",
        "npz",
        "onnx",
        "pb",
        "pickle",
        "pkl",
        "pt",
        "pth",
        "safetensors",
        "tflite",
        "txt",
        "yaml",
        "yml",
    }
)
_TRAILING_PATH_DELIMITERS = ".,;:)]}'\""
_URL_TEXT_BOUNDARY_BYTES = b" \t\r\n\"'<>`()"
_PROVEN_BARE_QUERY_COMPONENTS = frozenset({"_debug", "debug"})
_PROVEN_BARE_PROSE_COMPONENTS = frozenset({"section"})
_PATH_TOKEN_BOUNDARY_PATTERN = re.compile(r"&amp;|[&,'\"?#\s]")
_MATRIX_PARAMETER_SEPARATOR_PATTERN = re.compile(r"(?<!&amp);", re.IGNORECASE)
_URL_COMPONENT_SEPARATOR_PATTERN = re.compile(r"&amp;|[&;]", re.IGNORECASE)
_URL_SHELL_COMPONENT_BOUNDARY_PATTERN = re.compile(r"[&;]")
_AUTHORIZATION_SCHEME_PATTERN = re.compile(r"[a-z][a-z0-9!#$%&'*+.^_`|~-]*", re.IGNORECASE)
_STRONG_HOSTNAME_AUTHORIZATION_SCHEMES = frozenset(
    {"aws4-hmac-sha256", "basic", "bearer", "digest", "negotiate", "oauth"}
)
_CHAINABLE_AUTHORIZATION_SCHEMES = _STRONG_HOSTNAME_AUTHORIZATION_SCHEMES | {"api-key", "apikey", "jwt", "token"}
_NON_CREDENTIAL_AUTHORIZATION_VALUES = frozenset(
    {
        "anonymous",
        "auto",
        "default",
        "disabled",
        "enabled",
        "false",
        "inherit",
        "no",
        "none",
        "null",
        "off",
        "optional",
        "required",
        "true",
        "yes",
    }
)
_RESERVED_EXAMPLE_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_PUBLIC_SUFFIX_LIST_PATH = ("config", "data", "public_suffix_list.dat")
_SENSITIVE_EVIDENCE_HINT_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9])"
    rb"(?:api[_-]?key|auth(?:orization)?|credential|password|passwd|proxy[_-]?authorization|pwd|secret|token)"
    rb"\b(?![_-](?:cache|count|hint)\b)",
    re.IGNORECASE,
)
_DIRECT_AUTH_SCHEME_VALUE_PATTERN = re.compile(
    rb"(?:^|[^A-Za-z0-9])(?:basic|bearer|token)[ \t]+[\"']?\s*$",
    re.IGNORECASE,
)
_EVIDENCE_MATCH_START_MARKER = "__MODELAUDIT_ENDPOINT_MATCH_START__"
_EVIDENCE_MATCH_END_MARKER = "__MODELAUDIT_ENDPOINT_MATCH_END__"
_SENSITIVE_NESTED_URL = "redacted://redacted.invalid/sensitive-endpoint"
_OVER_ENCODED_NESTED_URL = "overencoded://redacted.invalid/nested-endpoint"
_MAX_URL_TEXT_LOOKUP_BYTES = 4096
_MAX_SNIPPET_URL_EXPANSION_BYTES = 4096
_MAX_SNIPPET_CHARS = 200
_MAX_PATH_TOKEN_DECODE_PASSES = 8
_MAX_EVIDENCE_REDACTION_CLASSIFICATIONS = 32
_PATH_TOKEN_DECODE_LIMIT_SENTINEL = "\0path-decode-limit"
_MIN_CAPABILITY_TOKEN_ENTROPY = 3.5
_MIN_URLSAFE_FILENAME_STEM_ENTROPY = 4.0
_PUBLIC_MODEL_REPOSITORY_HOSTS = frozenset({"huggingface.co", "hf.co"})
_PUBLIC_MODEL_API_REPOSITORY_TYPES = frozenset({"datasets", "models", "spaces"})
_PUBLIC_MODEL_REPOSITORY_MARKERS = frozenset({"blob", "resolve", "tree"})
_PUBLIC_MODEL_REPOSITORY_PREFIXES = frozenset({"datasets", "spaces"})
_PUBLIC_SOURCE_REPOSITORY_HOSTS = frozenset({"github.com", "www.github.com", "raw.githubusercontent.com"})
_PATH_STYLE_CLOUD_HOSTS = frozenset({"s3.amazonaws.com", "storage.googleapis.com", "storage.cloud.google.com"})
_S3_REGIONAL_HOST_PATTERN = re.compile(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$")
_AZURE_STORAGE_HOST_SUFFIXES = (".blob.core.windows.net", ".dfs.core.windows.net")
_AZURE_AUTHORITY_CONTAINER_SCHEMES = frozenset({"wasb", "wasbs", "abfs", "abfss"})
_AZURE_CONTAINER_NAME_PATTERN = re.compile(r"^(?:\$root|[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?)$")


def _split_trailing_path_delimiters(segment: str) -> tuple[str, str]:
    stripped = segment.rstrip(_TRAILING_PATH_DELIMITERS)
    return stripped, segment[len(stripped) :]


def _split_path_token_boundary(decoded: str) -> tuple[str, str] | None:
    match = _PATH_TOKEN_BOUNDARY_PATTERN.search(decoded)
    if match is None or match.start() == 0:
        return None
    return decoded[: match.start()], decoded[match.start() :]


def _decode_path_token(value: str) -> str:
    """Decode nested path escaping with a small fixed work bound."""
    for _ in range(_MAX_PATH_TOKEN_DECODE_PASSES):
        decoded = unquote(value)
        if decoded == value:
            return value
        value = decoded
    if unquote(value) != value:
        return _PATH_TOKEN_DECODE_LIMIT_SENTINEL
    return value


def _decode_query_component(value: str) -> str:
    """Decode nested query escaping, including form-style plus separators."""
    for _ in range(_MAX_PATH_TOKEN_DECODE_PASSES):
        decoded = unquote_plus(value)
        if decoded == value:
            return value
        value = decoded
    if unquote_plus(value) != value:
        return _PATH_TOKEN_DECODE_LIMIT_SENTINEL
    return value


def _shannon_entropy_per_char(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_high_entropy_filename_stem(stem: str) -> bool:
    if len(stem) < 20 or not re.fullmatch(r"[A-Za-z0-9_-]+", stem):
        return False

    character_classes = sum(bool(pattern.search(stem)) for pattern in _PATH_TOKEN_CHARACTER_CLASS_PATTERNS[:3])
    if re.search(r"[-_]", stem) and not re.search(r"[A-Z]", stem):
        return character_classes >= 2 and _shannon_entropy_per_char(stem) >= _MIN_URLSAFE_FILENAME_STEM_ENTROPY

    return character_classes >= 2 and _shannon_entropy_per_char(stem) >= _MIN_CAPABILITY_TOKEN_ENTROPY


def _redact_known_token_filename(segment: str) -> str | None:
    token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    if not _ARTIFACT_FILENAME_PATTERN.fullmatch(decoded):
        return None

    stem, separator, suffix = decoded.rpartition(".")
    if separator and (
        _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(stem)
        or (suffix.lower() in _KNOWN_ARTIFACT_FILENAME_EXTENSIONS and _looks_like_high_entropy_filename_stem(stem))
    ):
        return f"{_REDACTED_PATH_TOKEN}.{suffix}{trailing_delimiters}"
    return None


def _looks_like_known_artifact_filename(decoded: str) -> bool:
    if not _ARTIFACT_FILENAME_PATTERN.fullmatch(decoded):
        return False

    _stem, separator, suffix = decoded.rpartition(".")
    return bool(separator and suffix.lower() in _KNOWN_ARTIFACT_FILENAME_EXTENSIONS)


def _looks_like_capability_path_token(segment: str) -> bool:
    token_candidate, _trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return True
    if "/" in decoded:
        return any(_looks_like_capability_path_token(part) for part in decoded.split("/") if part)
    if ":" in decoded:
        return any(_looks_like_capability_path_token(part) for part in decoded.split(":") if part)
    boundary_parts = _split_path_token_boundary(decoded)
    if boundary_parts is not None:
        prefix, _suffix = boundary_parts
        return _looks_like_capability_path_token(prefix)
    if _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(decoded):
        return True
    if _redact_known_token_filename(segment) is not None:
        return True

    if _looks_like_known_artifact_filename(decoded):
        return False
    if len(decoded) < 20:
        return False
    if _HEX_PATH_TOKEN_PATTERN.fullmatch(decoded):
        return _shannon_entropy_per_char(decoded) >= _MIN_CAPABILITY_TOKEN_ENTROPY
    invalid_character_match = re.search(r"[^A-Za-z0-9._~+/=\-]", decoded)
    if invalid_character_match is not None:
        prefix = decoded[: invalid_character_match.start()]
        return bool(prefix and _looks_like_capability_path_token(prefix))

    character_classes = sum(bool(pattern.search(decoded)) for pattern in _PATH_TOKEN_CHARACTER_CLASS_PATTERNS)
    return character_classes >= 2 and _shannon_entropy_per_char(decoded) >= _MIN_CAPABILITY_TOKEN_ENTROPY


def _redact_encoded_path_separator_tokens(segment: str) -> str | None:
    token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    if "/" not in decoded:
        return None

    parts = decoded.split("/")
    if (
        len(parts) > 1
        and all(re.fullmatch(r"=*", part) for part in parts[1:])
        and parts[0]
        and _looks_like_capability_path_token(parts[0])
    ):
        return f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"

    changed = _redact_delimited_path_components(parts)

    if not changed:
        return None
    if any(
        part
        and part != _REDACTED_PATH_TOKEN
        and not _is_sensitive_path_key(_split_trailing_path_delimiters(part)[0])
        and not _looks_like_known_artifact_filename(part)
        for part in parts
    ):
        return f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
    return f"{'%2F'.join(parts)}{trailing_delimiters}"


def _redact_colon_delimited_path_tokens(segment: str) -> str | None:
    token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    if ":" not in decoded:
        return None

    key, separator, value = decoded.partition(":")
    if separator and _is_sensitive_path_key(key) and _URI_IN_TEXT_PATTERN.match(value) is not None:
        return f"{key}:{_REDACTED_PATH_TOKEN}{trailing_delimiters}"

    parts = decoded.split(":")
    changed = _redact_delimited_path_components(parts)

    if not changed:
        return None
    return f"{':'.join(parts)}{trailing_delimiters}"


def _redact_delimited_path_components(parts: list[str]) -> bool:
    """Redact assignments and sensitive key/value pairs split by a path delimiter."""
    changed = False
    redact_next_value = False
    authorization_value_pending = False
    for index, part in enumerate(parts):
        if not part:
            continue

        token_candidate, trailing_delimiters = _split_trailing_path_delimiters(part)
        if redact_next_value:
            parts[index] = f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
            following_value = next((candidate for candidate in parts[index + 1 :] if candidate), None)
            redact_next_value = (
                authorization_value_pending
                and _is_chainable_authorization_scheme(token_candidate)
                and _authorization_scheme_has_payload(token_candidate, following_value)
            )
            authorization_value_pending = redact_next_value
            changed = True
            continue

        empty_assignment_key = _empty_sensitive_path_assignment_key(part)
        if empty_assignment_key is not None:
            redacted_assignment = _redact_sensitive_path_assignment(part, preserve_key=True)
            assert redacted_assignment is not None
            parts[index] = redacted_assignment
            redact_next_value = True
            authorization_value_pending = _is_authorization_path_key(empty_assignment_key)
            changed = True
            continue

        if _is_sensitive_path_key(token_candidate):
            redact_next_value = True
            authorization_value_pending = _is_authorization_path_key(token_candidate)
            continue

        redacted_part, part_changed = _redact_boundary_component(part)
        if part_changed:
            parts[index] = redacted_part
            authorization_scheme = _authorization_assignment_scheme(part)
            following_value = next((candidate for candidate in parts[index + 1 :] if candidate), None)
            if authorization_scheme is not None:
                redact_next_value = _authorization_scheme_has_payload(authorization_scheme, following_value)
                authorization_value_pending = redact_next_value
            changed = True
    return changed


def _redact_boundary_component(component: str) -> tuple[str, bool]:
    if not component:
        return component, False

    sensitive_assignment = _redact_sensitive_path_assignment(component, preserve_key=True)
    if sensitive_assignment is not None:
        return sensitive_assignment, True

    key, separator, value = component.partition("=")
    if separator:
        changed = False
        if key and _looks_like_capability_path_token(key):
            key = _REDACTED_PATH_TOKEN
            changed = True
        if value and _looks_like_capability_path_token(value):
            value = _REDACTED_PATH_TOKEN
            changed = True
        if changed:
            return f"{key}{separator}{value}", True

    if _looks_like_capability_path_token(component):
        return _REDACTED_PATH_TOKEN, True
    return component, False


def _redact_boundary_delimited_path_tokens(segment: str) -> str | None:
    token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    if _PATH_TOKEN_BOUNDARY_PATTERN.search(decoded) is None:
        return None

    boundary_matches = list(_PATH_TOKEN_BOUNDARY_PATTERN.finditer(decoded))
    components: list[str] = []
    cursor = 0
    for match in boundary_matches:
        components.append(decoded[cursor : match.start()])
        cursor = match.end()
    components.append(decoded[cursor:])

    def carries_sensitive_value(boundary: str) -> bool:
        return boundary.lower() in {"&", "&amp;", ","} or boundary.isspace()

    changed = False
    redacted_parts: list[str] = []
    redact_next_value = False
    authorization_value_pending = False
    for index, component in enumerate(components):
        following_boundary = boundary_matches[index].group() if index < len(boundary_matches) else ""
        token_component, component_delimiters = _split_trailing_path_delimiters(component)
        if redact_next_value and component:
            redacted_component = f"{_REDACTED_PATH_TOKEN}{component_delimiters}"
            component_changed = True
            following_value = next((candidate for candidate in components[index + 1 :] if candidate), None)
            redact_next_value = (
                authorization_value_pending
                and carries_sensitive_value(following_boundary)
                and _is_chainable_authorization_scheme(token_component)
                and _authorization_scheme_has_payload(token_component, following_value)
            )
            authorization_value_pending = redact_next_value
        else:
            empty_assignment_key = _empty_sensitive_path_assignment_key(component)
            if empty_assignment_key is not None and carries_sensitive_value(following_boundary):
                redacted_assignment = _redact_sensitive_path_assignment(component, preserve_key=True)
                assert redacted_assignment is not None
                redacted_component = redacted_assignment
                component_changed = True
                redact_next_value = True
                authorization_value_pending = _is_authorization_path_key(empty_assignment_key)
            else:
                redacted_component, component_changed = _redact_boundary_component(component)
                authorization_scheme = _authorization_assignment_scheme(component)
                following_value = next((candidate for candidate in components[index + 1 :] if candidate), None)
                if (
                    component_changed
                    and authorization_scheme is not None
                    and carries_sensitive_value(following_boundary)
                ):
                    redact_next_value = _authorization_scheme_has_payload(authorization_scheme, following_value)
                    authorization_value_pending = redact_next_value
            if (
                empty_assignment_key is None
                and component
                and _is_sensitive_path_key(token_component)
                and carries_sensitive_value(following_boundary)
            ):
                redact_next_value = True
                authorization_value_pending = _is_authorization_path_key(token_component)
        redacted_parts.append(redacted_component)
        changed = changed or component_changed
        if index < len(boundary_matches):
            redacted_parts.append(following_boundary)
        if following_boundary and not carries_sensitive_value(following_boundary):
            redact_next_value = False
            authorization_value_pending = False
    if not changed:
        return None
    return f"{''.join(redacted_parts)}{trailing_delimiters}"


def _is_public_model_repository_segment(hostname: str, segments: list[str], index: int) -> bool:
    if hostname not in _PUBLIC_MODEL_REPOSITORY_HOSTS:
        return False

    path_segments = [segment.lower() for segment in segments[1:] if segment]
    if len(path_segments) == 1:
        return index == 1

    has_repository_prefix = bool(path_segments and path_segments[0] in _PUBLIC_MODEL_REPOSITORY_PREFIXES)
    repository_indexes = {1, 2, 3} if has_repository_prefix else {1, 2}
    if len(path_segments) == len(repository_indexes):
        return index in repository_indexes

    if not any(segment.lower() in _PUBLIC_MODEL_REPOSITORY_MARKERS for segment in segments[index + 1 :]):
        return False
    return index in repository_indexes


def _is_public_model_api_repository_segment(hostname: str, segments: list[str], index: int) -> bool:
    if hostname not in _PUBLIC_MODEL_REPOSITORY_HOSTS or len(segments) < 4:
        return False
    if segments[1].lower() != "api" or segments[2].lower() not in _PUBLIC_MODEL_API_REPOSITORY_TYPES:
        return False
    return index in {3, 4}


def _is_public_model_revision_segment(hostname: str, segments: list[str], index: int) -> bool:
    if hostname not in _PUBLIC_MODEL_REPOSITORY_HOSTS or index == 0:
        return False
    return segments[index - 1].lower() in _PUBLIC_MODEL_REPOSITORY_MARKERS


def _is_public_source_repository_segment(hostname: str, segments: list[str], index: int) -> bool:
    if hostname not in _PUBLIC_SOURCE_REPOSITORY_HOSTS or index not in {1, 2}:
        return False
    if len(segments) <= 3:
        return False
    if hostname == "raw.githubusercontent.com":
        return True
    return any(segment.lower() in {"blob", "raw", "releases", "tree"} for segment in segments[3:])


def _is_public_source_ref_segment(hostname: str, segments: list[str], index: int) -> bool:
    if hostname not in _PUBLIC_SOURCE_REPOSITORY_HOSTS:
        return False
    if hostname == "raw.githubusercontent.com":
        return index == 3 and len(segments) > 4
    if len(segments) <= 4:
        return False

    route = segments[3].lower()
    if route in {"blob", "raw", "tree"}:
        return index == 4
    return route == "releases" and len(segments) > 5 and segments[4].lower() == "download" and index == 5


def _is_path_style_cloud_bucket_segment(scheme: str, hostname: str, index: int) -> bool:
    if index != 1:
        return False
    if hostname in _PATH_STYLE_CLOUD_HOSTS or _S3_REGIONAL_HOST_PATTERN.fullmatch(hostname) is not None:
        return True
    return scheme in {"http", "https"} and hostname.endswith(_AZURE_STORAGE_HOST_SUFFIXES)


def _is_gcs_api_bucket_segment(hostname: str, segments: list[str], index: int) -> bool:
    if hostname != "storage.googleapis.com" or index == 0 or segments[index - 1].lower() != "b":
        return False

    route = [segment.lower() for segment in segments[1 : index - 1] if segment]
    return route in (["storage", "v1"], ["download", "storage", "v1"])


def _is_azure_authority_container(container: str) -> bool:
    decoded = unquote(container)
    return decoded == container and _AZURE_CONTAINER_NAME_PATTERN.fullmatch(container) is not None


def _is_azure_container_authority(scheme: str, hostname: str, authority: str) -> bool:
    return (
        scheme in _AZURE_AUTHORITY_CONTAINER_SCHEMES
        and hostname.lower().endswith(_AZURE_STORAGE_HOST_SUFFIXES)
        and _is_azure_authority_container(authority)
    )


def _redact_path_parameter_tokens(segment: str) -> str | None:
    token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    if _MATRIX_PARAMETER_SEPARATOR_PATTERN.search(decoded) is None:
        return None

    parts = _MATRIX_PARAMETER_SEPARATOR_PATTERN.split(decoded)
    changed = _redact_delimited_path_components(parts)

    if changed:
        return f"{';'.join(parts)}{trailing_delimiters}"
    return None


def _is_sensitive_path_key(key: str) -> bool:
    decoded = _decode_path_token(key).strip()
    if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return True
    normalized = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", decoded)
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized).replace("-", "_")
    parts = [part for part in re.split(r"[.\s_\[\]]+", normalized) if part]
    return any(
        _SENSITIVE_PATH_KEY_PATTERN.fullmatch("_".join(parts[index:])) is not None for index in range(len(parts))
    )


def _is_endpoint_location_key(key: str) -> bool:
    """Return whether a field explicitly names a network destination rather than a credential."""
    decoded = _decode_query_component(key).strip()
    if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return False
    normalized = re.sub(r"[^a-z0-9]+", "", decoded.casefold())
    return normalized in {"destination", "next", "redirect", "redirectto", "target"} or normalized.endswith(
        ("endpoint", "url", "uri")
    )


def _is_authorization_path_key(key: str) -> bool:
    decoded = _decode_path_token(key).strip()
    if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return False
    normalized = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", decoded)
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized).replace("-", "_")
    parts = [part.lower() for part in re.split(r"[.\s_\[\]]+", normalized) if part]
    return any(
        "_".join(parts[index:]) in {"auth", "authorization", "proxy_authorization"} for index in range(len(parts))
    )


def _authorization_assignment_scheme(segment: str) -> str | None:
    token_candidate, _trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    assignment_parts = decoded.split("=")
    key_index = next(
        (index for index, key in enumerate(assignment_parts[:-1]) if _is_authorization_path_key(key)),
        None,
    )
    if key_index is None:
        return None

    value = "=".join(assignment_parts[key_index + 1 :]).strip()
    return value if _is_authorization_scheme(value) else None


def _is_authorization_scheme(value: str) -> bool:
    return (
        _AUTHORIZATION_SCHEME_PATTERN.fullmatch(value) is not None
        and value.casefold() not in _NON_CREDENTIAL_AUTHORIZATION_VALUES
    )


def _is_chainable_authorization_scheme(value: str) -> bool:
    return value.casefold() in _CHAINABLE_AUTHORIZATION_SCHEMES


def _is_bare_ip_path_endpoint(value: str) -> bool:
    decoded = _decode_path_token(value).lstrip("/")
    candidate = decoded.split("/", 1)[0]
    host = candidate
    if candidate.startswith("["):
        closing_bracket = candidate.find("]")
        if closing_bracket < 0:
            return False
        remainder = candidate[closing_bracket + 1 :]
        if remainder and (re.fullmatch(r":\d{1,5}", remainder) is None or not 0 < int(remainder[1:]) <= 65535):
            return False
        host = candidate[1:closing_bracket]
    elif candidate.count(":") == 1:
        possible_host, possible_port = candidate.rsplit(":", 1)
        if possible_port.isdigit() and 0 < int(possible_port) <= 65535:
            host = possible_host
    with suppress(ValueError):
        ipaddress.ip_address(host)
        return True
    return False


def _is_bare_domain_path_endpoint(value: str) -> bool:
    decoded = _decode_path_token(value).lstrip("/")
    candidate = decoded.split("/", 1)[0].rstrip(".")
    if candidate.count(":") == 1:
        possible_host, possible_port = candidate.rsplit(":", 1)
        if possible_port.isdigit() and 0 < int(possible_port) <= 65535:
            candidate = possible_host
    try:
        encoded_candidate = candidate.encode("ascii")
    except UnicodeEncodeError:
        return False
    if _BARE_DOMAIN_PATTERN.fullmatch(encoded_candidate) is None:
        return False
    first_label = candidate.split(".", 1)[0]
    return not _looks_like_hostname_credential_value(first_label)


def _authorization_scheme_has_payload(scheme: str, following_value: str | None) -> bool:
    if following_value is None or not _is_authorization_scheme(scheme):
        return False
    decoded_following_value = _decode_path_token(following_value)
    endpoint_key, separator, _endpoint_value = decoded_following_value.partition("=")
    if separator and _is_endpoint_location_key(endpoint_key):
        return False
    if _is_bare_ip_path_endpoint(following_value) or _is_bare_domain_path_endpoint(following_value):
        return False
    return not _looks_like_known_artifact_filename(following_value)


@lru_cache(maxsize=1)
def _public_suffix_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    exact_rules: set[str] = set()
    wildcard_rules: set[str] = set()
    exception_rules: set[str] = set()
    resource = files("modelaudit")
    for path_component in _PUBLIC_SUFFIX_LIST_PATH:
        resource = resource.joinpath(path_component)
    for raw_line in resource.read_text(encoding="utf-8").splitlines():
        rule = raw_line.partition("//")[0].strip().casefold()
        if not rule:
            continue
        if rule.startswith("!"):
            exception_rules.add(rule[1:])
        elif rule.startswith("*."):
            wildcard_rules.add(rule[2:])
        else:
            exact_rules.add(rule)
    return frozenset(exact_rules), frozenset(wildcard_rules), frozenset(exception_rules)


def _hostname_public_suffix_label_count(normalized_labels: list[str]) -> int:
    labels = normalized_labels[:-1] if normalized_labels and not normalized_labels[-1] else normalized_labels
    if not labels:
        return 1

    exact_rules, wildcard_rules, exception_rules = _public_suffix_rules()
    suffix_labels = 1
    for start_index in range(len(labels)):
        suffix = ".".join(labels[start_index:])
        rule_label_count = len(labels) - start_index
        if suffix in exception_rules:
            return max(1, rule_label_count - 1)
        if suffix in exact_rules:
            suffix_labels = max(suffix_labels, rule_label_count)
        if start_index + 1 < len(labels) and ".".join(labels[start_index + 1 :]) in wildcard_rules:
            suffix_labels = max(suffix_labels, rule_label_count)
    return suffix_labels


def _hostname_authorization_scheme_has_payload(
    scheme: str,
    following_value: str | None,
    labels: list[str],
    scheme_index: int,
) -> bool:
    if not _authorization_scheme_has_payload(scheme, following_value):
        return False
    assert following_value is not None
    if _looks_like_hostname_credential_value(following_value):
        return True

    normalized_labels = [label.casefold() for label in labels]
    if normalized_labels and not normalized_labels[-1]:
        normalized_labels.pop()
    remaining_hostname = ".".join(normalized_labels[scheme_index + 1 :])
    public_suffix_labels = _hostname_public_suffix_label_count(normalized_labels)
    labels_after_scheme = len(normalized_labels) - (scheme_index + 1)
    if scheme.casefold() in _STRONG_HOSTNAME_AUTHORIZATION_SCHEMES:
        if remaining_hostname in _RESERVED_EXAMPLE_DOMAINS:
            return False
        return not (public_suffix_labels > 1 and labels_after_scheme == public_suffix_labels + 1)

    # Retain one registrable label plus the PSL suffix before treating an earlier
    # label as an authorization payload.
    labels_after_payload = len(normalized_labels) - (scheme_index + 2)
    return labels_after_payload >= public_suffix_labels + 1


def _compound_path_segment_ends_with_sensitive_key(segment: str) -> bool:
    """Return whether a compound segment leaves a credential key awaiting its value."""
    parts = [part for part in re.split(r"(?i)&amp;|[/,:;&\s]", segment) if part]
    return len(parts) > 1 and _is_sensitive_path_key(parts[-1])


def _empty_sensitive_path_assignment_key(segment: str) -> str | None:
    """Return the sensitive key when an assignment leaves its value to a later segment."""
    token_candidate, _trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    assignment_parts = decoded.split("=")
    if len(assignment_parts) < 2 or assignment_parts[-1].strip():
        return None
    return next((key for key in assignment_parts[:-1] if _is_sensitive_path_key(key)), None)


def _redact_sensitive_path_assignment(segment: str, *, preserve_key: bool = False) -> str | None:
    token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = _decode_path_token(token_candidate)
    assignment_parts = decoded.split("=")
    sensitive_key_index = next(
        (index for index, key in enumerate(assignment_parts[:-1]) if _is_sensitive_path_key(key)),
        None,
    )
    if sensitive_key_index is None:
        return None
    if preserve_key and sensitive_key_index == 0:
        return f"{assignment_parts[0]}={_REDACTED_PATH_TOKEN}{trailing_delimiters}"
    return f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"


def _is_cloud_authority_identifier(labels: list[str], index: int) -> bool:
    """Preserve bucket/account labels that are part of known cloud storage authorities."""
    if index != 0 or len(labels) < 2:
        return False
    label = labels[index]
    decoded = _decode_path_token(label)
    if (
        decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL
        or _redact_sensitive_path_assignment(label) is not None
        or _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(decoded) is not None
    ):
        return False
    provider_host = ".".join(labels[1:]).lower()
    return (
        provider_host in _PATH_STYLE_CLOUD_HOSTS
        or provider_host in {suffix.removeprefix(".") for suffix in _AZURE_STORAGE_HOST_SUFFIXES}
        or _S3_REGIONAL_HOST_PATTERN.fullmatch(provider_host) is not None
    )


def _looks_like_hostname_credential_value(label: str) -> bool:
    """Identify credential-like values in otherwise ambiguous three-label hostnames."""
    decoded = _decode_path_token(label)
    if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return True
    normalized = re.sub(r"[^a-z0-9]+", "", decoded.casefold())
    sensitive_markers = ("apikey", "auth", "credential", "password", "secret", "token")
    return (
        _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(decoded) is not None
        or _looks_like_capability_path_token(decoded)
        or any(character.isdigit() for character in decoded)
        or any(normalized.startswith(marker) or normalized.endswith(marker) for marker in sensitive_markers)
    )


def _redact_hostname_tokens(hostname: str) -> str:
    with suppress(ValueError):
        ipaddress.ip_address(hostname)
        return hostname

    labels = hostname.split(".")
    redact_next_value = False
    authorization_value_pending = False
    for index, label in enumerate(labels):
        decoded = _decode_path_token(label)
        if _is_cloud_authority_identifier(labels, index):
            continue
        if redact_next_value:
            labels[index] = _REDACTED_PATH_TOKEN
            following_value = next((candidate for candidate in labels[index + 1 :] if candidate), None)
            redact_next_value = (
                authorization_value_pending
                and _is_chainable_authorization_scheme(decoded)
                and _hostname_authorization_scheme_has_payload(decoded, following_value, labels, index)
            )
            authorization_value_pending = redact_next_value
            continue
        remaining_labels = len(labels) - index
        short_hostname_value_is_sensitive = remaining_labels == 3 and _looks_like_hostname_credential_value(
            labels[index + 1]
        )
        if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
            labels[index] = _REDACTED_PATH_TOKEN
            redact_next_value = remaining_labels >= 4 or short_hostname_value_is_sensitive
            continue
        if _is_sensitive_path_key(decoded) and (remaining_labels >= 4 or short_hostname_value_is_sensitive):
            redact_next_value = True
            authorization_value_pending = _is_authorization_path_key(decoded)
            continue
        if _redact_sensitive_path_assignment(label) is not None or _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(decoded):
            labels[index] = _REDACTED_PATH_TOKEN
    return ".".join(labels)


def _redact_url_path_tokens(scheme: str, hostname: str, path: str) -> str:
    segments = path.split("/")
    redact_next_value = False
    authorization_value_pending = False
    for index, segment in enumerate(segments):
        if not segment:
            continue
        if redact_next_value:
            _token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
            segments[index] = f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
            following_value = next((candidate for candidate in segments[index + 1 :] if candidate), None)
            redact_next_value = (
                authorization_value_pending
                and _is_chainable_authorization_scheme(_token_candidate)
                and _authorization_scheme_has_payload(_token_candidate, following_value)
            )
            authorization_value_pending = redact_next_value
            continue

        token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
        decoded_segment = _decode_path_token(token_candidate)
        if decoded_segment == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
            segments[index] = f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
            redact_next_value = True
            continue
        if _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(decoded_segment):
            segments[index] = f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
            continue

        is_public_identifier = (
            _is_public_model_repository_segment(hostname, segments, index)
            or _is_public_model_api_repository_segment(hostname, segments, index)
            or _is_public_model_revision_segment(hostname, segments, index)
            or _is_public_source_repository_segment(hostname, segments, index)
            or _is_public_source_ref_segment(hostname, segments, index)
            or _is_path_style_cloud_bucket_segment(scheme, hostname, index)
            or _is_gcs_api_bucket_segment(hostname, segments, index)
        )
        if not is_public_identifier and (
            _is_sensitive_path_key(decoded_segment) or _compound_path_segment_ends_with_sensitive_key(decoded_segment)
        ):
            redact_next_value = True
            authorization_value_pending = _is_authorization_path_key(decoded_segment)
            continue
        is_slack_webhook_secret = (
            hostname == "hooks.slack.com" and len(segments) > 2 and segments[1].lower() == "services" and index > 1
        )
        filename_redaction = _redact_known_token_filename(segment)
        if filename_redaction is not None:
            segments[index] = filename_redaction
            continue
        sensitive_assignment_redaction = _redact_sensitive_path_assignment(segment)
        if sensitive_assignment_redaction is not None:
            segments[index] = sensitive_assignment_redaction
            empty_assignment_key = _empty_sensitive_path_assignment_key(segment)
            if empty_assignment_key is not None:
                redact_next_value = True
                authorization_value_pending = _is_authorization_path_key(empty_assignment_key)
            continue
        encoded_separator_redaction = _redact_encoded_path_separator_tokens(segment)
        if encoded_separator_redaction is not None:
            segments[index] = encoded_separator_redaction
            continue
        colon_redaction = _redact_colon_delimited_path_tokens(segment)
        if colon_redaction is not None:
            segments[index] = colon_redaction
            continue
        boundary_redaction = _redact_boundary_delimited_path_tokens(segment)
        if boundary_redaction is not None:
            segments[index] = boundary_redaction
            continue
        parameter_redaction = _redact_path_parameter_tokens(segment)
        if parameter_redaction is not None:
            segments[index] = parameter_redaction
            continue

        if is_public_identifier:
            continue
        if is_slack_webhook_secret or _looks_like_capability_path_token(segment):
            _token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
            segments[index] = f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
    return "/".join(segments)


def _source_quote_before_url(data: bytes, url_start: int) -> str | None:
    if url_start <= 0 or data[url_start - 1] not in {ord("'"), ord('"')}:
        return None
    if url_start > 1 and data[url_start - 2] not in b"\t\r\n" and not 0x20 <= data[url_start - 2] <= 0x7E:
        return None
    return chr(data[url_start - 1])


def _trim_source_literal_url(
    url: str,
    source_quote: str | None = None,
    source_suffix: str = "",
    source_prefix: str = "",
    *,
    fail_closed_ambiguous_shell_boundary: bool = False,
) -> str:
    """Remove a closing quote only when the URL came from that source literal."""
    if source_quote == "'":
        authority_start = url.find("://") + 3
        authority_end = min(
            (index for delimiter in "/?#" if (index := url.find(delimiter, authority_start)) >= 0),
            default=len(url),
        )
        escaped = False
        for index, character in enumerate(url):
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == source_quote:
                if authority_start <= index < authority_end and url[index + 1 :].startswith("@"):
                    continue
                return url[:index]
        return url

    if fail_closed_ambiguous_shell_boundary:
        explicit_prose = bool(_EXPLICIT_PROSE_PREFIX_PATTERN.match(source_prefix.encode("ascii", errors="ignore")))
        prose_suffix = re.fullmatch(r"\s+for details[.!]?\s*", source_suffix, re.IGNORECASE)
        query_start = url.find("?")
        cursor = 0
        while (boundary := _URL_SHELL_COMPONENT_BOUNDARY_PATTERN.search(url, cursor)) is not None:
            component_start = boundary.end()
            next_boundary = _URL_SHELL_COMPONENT_BOUNDARY_PATTERN.search(url, component_start)
            component_end = len(url) if next_boundary is None else next_boundary.start()
            component = url[component_start:component_end]
            key, assignment, _value = component.partition("=")
            shaped = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*(?:=[^&;]*)?", component) is not None
            assignment_is_url = bool(assignment) and (
                not source_suffix.strip() or (explicit_prose and prose_suffix is not None)
            )
            bare_component = (
                boundary.group() == "&"
                and 0 <= query_start < boundary.start()
                and key.lower() in _PROVEN_BARE_QUERY_COMPONENTS
            ) or (explicit_prose and prose_suffix is not None and key.lower() in _PROVEN_BARE_PROSE_COMPONENTS)
            if not shaped or not (assignment_is_url or bare_component):
                url = url[: boundary.start()]
                break
            cursor = component_end

    code_boundary = re.search(
        r"""&&|[&;](?=[\t\r\n \\"'!%(])|\$\(|'(?=[+\-/%*|](?:\(*[A-Za-z_][A-Za-z0-9_.]*)\()""",
        url + source_suffix[:_MAX_PROSE_LINE_CONTEXT_BYTES],
    )
    if code_boundary is not None and code_boundary.start() < len(url):
        url = url[: code_boundary.start()]
    if url.endswith(")") and re.search(r"\$\([^)]*$", source_prefix) is not None:
        url = url[:-1]
    return url.rstrip("'")


def _trim_matched_source_url(data: bytes, match: re.Match[bytes]) -> str:
    prefix = data[max(0, match.start() - _MAX_PROSE_LINE_CONTEXT_BYTES) : match.start()]
    suffix = data[match.end() : match.end() + _MAX_PROSE_LINE_CONTEXT_BYTES]
    return _trim_source_literal_url(
        match.group().decode("utf-8", errors="ignore"),
        _source_quote_before_url(data, match.start()),
        re.split(rb"[^\t\r\n\x20-\x7e]", suffix, maxsplit=1)[0].decode("ascii"),
        re.split(rb"[^\t\x20-\x7e]", prefix)[-1].decode("ascii"),
    )


def redact_url_for_finding(url: str) -> str:
    """Return a URL safe for findings by removing credentials and sensitive tokens."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.netloc:
        return "[invalid-url]"

    raw_hostname = parsed.hostname
    if not raw_hostname:
        return "[invalid-url]"
    hostname = _redact_hostname_tokens(raw_hostname)
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    try:
        port = parsed.port
    except ValueError:
        port = None

    netloc_host = f"{hostname}:{port}" if port is not None else hostname
    netloc = netloc_host
    scheme = parsed.scheme.lower()
    if "@" in parsed.netloc:
        container, _separator, _host = parsed.netloc.rpartition("@")
        if _is_azure_container_authority(scheme, hostname, container):
            netloc = f"{container}@{netloc_host}"

    safe_path = _redact_url_path_tokens(scheme, raw_hostname.lower(), parsed.path)
    return urlunsplit((parsed.scheme, netloc, safe_path, "", ""))


def _redact_network_evidence(text: str) -> str:
    """Apply the shared evidence redactor after the detector module is fully loaded."""
    from modelaudit.scanners._evidence_redaction import redact_evidence_string

    safe_urls = _URL_IN_TEXT_PATTERN.sub(lambda match: redact_url_for_finding(match.group()), text)
    return redact_evidence_string(safe_urls, max_chars=None)


def _redact_urls_in_text(text: str) -> str:
    """Preserve the integration-facing URL redaction and formatting contract."""
    return _URL_IN_TEXT_PATTERN.sub(lambda match: redact_url_for_finding(match.group()), text)


def _url_is_likely_call_endpoint(data: bytes, match_end: int, url_start: int) -> bool:
    cursor = match_end
    while cursor < url_start and data[cursor : cursor + 1] in {b" ", b"\t", b"\r", b"\n"}:
        cursor += 1
    if cursor >= url_start or data[cursor : cursor + 1] != b"(":
        return False

    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    quote: int | None = None
    escaped = False
    current_argument_start = cursor + 1
    for index in range(cursor, url_start):
        byte = data[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == quote:
                quote = None
            continue
        if byte in {ord("'"), ord('"')}:
            quote = byte
        elif byte == ord("("):
            paren_depth += 1
        elif byte == ord(")"):
            paren_depth -= 1
            if paren_depth <= 0:
                return False
        elif byte == ord("["):
            bracket_depth += 1
        elif byte == ord("]"):
            bracket_depth -= 1
        elif byte == ord("{"):
            brace_depth += 1
        elif byte == ord("}"):
            brace_depth -= 1
        elif byte == ord(",") and paren_depth == 1 and bracket_depth == 0 and brace_depth == 0:
            current_argument_start = index + 1

    if paren_depth != 1 or bracket_depth != 0 or brace_depth != 0:
        return False

    argument_prefix = data[current_argument_start:url_start].strip()
    if b"#" in argument_prefix:
        return False
    string_prefix = rb"(?:[rRuUbBfF]{0,3})?(?:\"\"\"|'''|[\"'])"
    if re.fullmatch(string_prefix, argument_prefix) is not None:
        return True
    return re.fullmatch(rb"(?i:(?:url|uri|endpoint))\s*=\s*" + string_prefix, argument_prefix) is not None


def _is_url_associated_with_match(
    data: bytes,
    *,
    match_start: int,
    match_end: int,
    url_start: int,
    url_end: int,
) -> bool:
    if url_start <= match_start and match_end <= url_end:
        return True
    if url_start < match_end:
        return False
    if _url_is_likely_call_endpoint(data, match_end, url_start):
        return True
    assignment_prefix = data[match_end:url_start]
    return _URL_ASSIGNMENT_PREFIX_PATTERN.fullmatch(
        assignment_prefix
    ) is not None or _is_structured_assignment_endpoint_prefix(assignment_prefix)


def _is_structured_assignment_endpoint_prefix(prefix: bytes) -> bool:
    """Recognize an endpoint nested inside one bounded assignment expression."""
    stripped = prefix.lstrip()
    if not stripped.startswith((b"=", b":")) or any(delimiter in prefix for delimiter in (b"\n", b"\r", b"#", b";")):
        return False
    allowed_punctuation = b" \t_=:{[(),.'\"-"
    if not all(chr(byte).isalnum() or byte in allowed_punctuation for byte in prefix):
        return False

    delimiter_stack: list[int] = []
    quote: int | None = None
    escaped = False
    closing_delimiters = {ord(")"): ord("("), ord("]"): ord("["), ord("}"): ord("{")}
    for byte in stripped[1:]:
        if quote is not None:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == quote:
                quote = None
            continue
        if byte in {ord("'"), ord('"')}:
            quote = byte
        elif byte in {ord("("), ord("["), ord("{")}:
            delimiter_stack.append(byte)
        elif byte in closing_delimiters:
            if not delimiter_stack or delimiter_stack.pop() != closing_delimiters[byte]:
                return False
        elif byte == ord(",") and not delimiter_stack:
            return False
    return True


def _is_first_call_argument_endpoint(data: bytes, call_end: int, endpoint_start: int) -> bool:
    """Return whether an endpoint occurs inside the first argument of the matched call."""
    prefix = data[call_end:endpoint_start]
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    quote: int | None = None
    escaped = False

    for byte in prefix:
        if quote is not None:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == quote:
                quote = None
            continue
        if byte in {ord("'"), ord('"')}:
            quote = byte
        elif byte == ord("("):
            paren_depth += 1
        elif byte == ord(")"):
            paren_depth -= 1
            if paren_depth <= 0:
                return False
        elif byte == ord("["):
            bracket_depth += 1
        elif byte == ord("]"):
            bracket_depth -= 1
        elif byte == ord("{"):
            brace_depth += 1
        elif byte == ord("}"):
            brace_depth -= 1
        elif (
            byte == ord("#")
            or byte in {ord("\n"), ord("\r")}
            or (byte == ord(",") and paren_depth == 1 and bracket_depth == 0 and brace_depth == 0)
            or (paren_depth == 0 and not chr(byte).isspace())
        ):
            return False

    return paren_depth >= 1 and bracket_depth >= 0 and brace_depth >= 0


def _is_bare_endpoint_associated_with_match(
    data: bytes,
    *,
    match_end: int,
    endpoint_start: int,
) -> bool:
    if endpoint_start < match_end:
        return False
    if _is_first_call_argument_endpoint(data, match_end, endpoint_start):
        return True
    return _is_structured_assignment_endpoint_prefix(data[match_end:endpoint_start])


def _bare_endpoint_with_optional_port(data: bytes, endpoint_start: int, endpoint_end: int, scan_end: int) -> str:
    endpoint = data[endpoint_start:endpoint_end].decode("utf-8", errors="ignore")
    port_match = _BARE_PORT_SUFFIX_PATTERN.match(data[endpoint_end : min(scan_end, endpoint_end + 32)])
    if port_match is None:
        return endpoint
    port = int(port_match.group(1))
    return f"{endpoint}:{port}" if port <= 65535 else endpoint


def _redacted_snippet_for_match(data: bytes, match_start: int, match_end: int, *, before: int, after: int) -> str:
    scan_start = max(0, match_start - before - _MAX_SNIPPET_URL_EXPANSION_BYTES)
    scan_end = min(len(data), match_end + after + _MAX_SNIPPET_URL_EXPANSION_BYTES)

    match_text = data[match_start:match_end].decode("utf-8", errors="ignore")
    snippet_parts = [match_text]
    uri_spans: list[tuple[int, int]] = []
    for url_match in _URI_IN_BYTES_PATTERN.finditer(data, scan_start, scan_end):
        uri_spans.append((url_match.start(), url_match.end()))
        trimmed_url = _trim_matched_source_url(data, url_match)
        trimmed_url_end = url_match.start() + len(trimmed_url.encode("utf-8"))
        if not _is_url_associated_with_match(
            data,
            match_start=match_start,
            match_end=match_end,
            url_start=url_match.start(),
            url_end=trimmed_url_end,
        ):
            continue
        for nested_url in _decoded_nested_urls(trimmed_url):
            redacted_nested_url = redact_url_for_finding(nested_url)
            if redacted_nested_url not in snippet_parts:
                snippet_parts.append(redacted_nested_url)
        redacted_url = redact_url_for_finding(trimmed_url)
        if redacted_url not in snippet_parts:
            snippet_parts.append(redacted_url)

    bare_endpoint_matches = sorted(
        (
            endpoint_match.start(),
            endpoint_match.end(),
            endpoint_match.group().decode("utf-8", errors="ignore"),
        )
        for pattern in (_BARE_IPV4_PATTERN, _BARE_DOMAIN_PATTERN)
        for endpoint_match in pattern.finditer(data, scan_start, scan_end)
    )
    for endpoint_start, endpoint_end, endpoint in bare_endpoint_matches:
        if any(uri_start <= endpoint_start < uri_end for uri_start, uri_end in uri_spans):
            continue
        if not _is_bare_endpoint_associated_with_match(
            data,
            match_end=match_end,
            endpoint_start=endpoint_start,
        ):
            continue
        if (
            _is_match_redacted_from_url(data, endpoint_start, endpoint)
            or _is_split_sensitive_url_value(data, endpoint_start)
            or _is_redacted_evidence_value(data, endpoint_start, endpoint)
        ):
            continue
        endpoint_with_port = _bare_endpoint_with_optional_port(data, endpoint_start, endpoint_end, scan_end)
        if endpoint_with_port not in snippet_parts:
            snippet_parts.append(endpoint_with_port)

    snippet = " ".join(snippet_parts)
    if len(snippet) <= _MAX_SNIPPET_CHARS:
        return snippet
    return f"{snippet[: _MAX_SNIPPET_CHARS - 3]}..."


def _uri_text_bounds_containing_offset(
    data: bytes,
    offset: int,
    pattern: re.Pattern[bytes],
) -> tuple[str, int] | None:
    scan_start = max(0, offset - _MAX_URL_TEXT_LOOKUP_BYTES)
    scan_end = min(len(data), offset + _MAX_URL_TEXT_LOOKUP_BYTES)
    for match in pattern.finditer(data, scan_start, scan_end):
        if not (match.start() <= offset < match.end()):
            continue
        if match.end() == scan_end and scan_end < len(data) and data[scan_end] not in _URL_TEXT_BOUNDARY_BYTES:
            return None

        url = _trim_matched_source_url(data, match)
        if offset >= match.start() + len(url.encode("utf-8")):
            return None
        return url, match.start()
    return None


def _url_text_bounds_containing_offset(data: bytes, offset: int) -> tuple[str, int] | None:
    return _uri_text_bounds_containing_offset(data, offset, _URL_IN_BYTES_PATTERN)


def _url_text_containing_offset(data: bytes, offset: int) -> str | None:
    url_context = _url_text_bounds_containing_offset(data, offset)
    return url_context[0] if url_context is not None else None


def _bounded_url_lookup_starts_mid_token(data: bytes, offset: int) -> bool:
    """Return whether a bounded lookup may have begun inside one long URL token."""
    scan_start = max(0, offset - _MAX_URL_TEXT_LOOKUP_BYTES)
    bounded_prefix = data[scan_start:offset]
    return (
        scan_start > 0
        and data[scan_start - 1] not in _URL_TEXT_BOUNDARY_BYTES
        and not any(byte in _URL_TEXT_BOUNDARY_BYTES for byte in bounded_prefix)
    )


def _match_starts_inside_percent_escape(data: bytes, match_start: int) -> bool:
    """Reject domain prefixes made from an encoded URL separator's hex bytes."""
    if (
        match_start <= 0
        or data[match_start - 1 : match_start] != b"%"
        or match_start + 1 >= len(data)
        or not all(byte in b"0123456789abcdefABCDEF" for byte in data[match_start : match_start + 2])
    ):
        return False
    return int(data[match_start : match_start + 2], 16) in b"/=?&#;:@,'\" \t\r\n"


def _is_match_redacted_from_url(data: bytes, match_start: int, value: str) -> bool:
    url_context = _url_text_bounds_containing_offset(data, match_start)
    if url_context is None:
        url_context = _uri_text_bounds_containing_offset(data, match_start, _URI_IN_BYTES_PATTERN)
    if url_context is None:
        return False
    url, url_start = url_context

    return _is_match_redacted_from_url_context(url, url_start, match_start, value)


def _is_match_redacted_from_url_context(url: str, url_start: int, match_start: int, value: str) -> bool:
    """Return whether a matched value is removed from a known URL's safe representation."""

    try:
        parsed = urlsplit(url)
        safe_parsed = urlsplit(redact_url_for_finding(url))
    except ValueError:
        return False

    scheme_end = url.find("://") + 3
    authority_end = scheme_end + len(parsed.netloc)
    path_end = authority_end + len(parsed.path)
    relative_start = match_start - url_start
    value_lower = value.lower()
    path_awaits_sensitive_value = _url_path_awaits_sensitive_value(url)

    if relative_start < authority_end:
        return value_lower in parsed.netloc.lower() and value_lower not in safe_parsed.netloc.lower()
    if relative_start < path_end:
        return value_lower in parsed.path.lower() and value_lower not in safe_parsed.path.lower()

    if parsed.query:
        query_start = path_end + 1
        query_end = query_start + len(parsed.query)
        if query_start <= relative_start < query_end:
            return _is_match_redacted_from_url_component(
                parsed.query,
                relative_start - query_start,
                value,
                path_awaits_sensitive_value=path_awaits_sensitive_value,
            )

    if parsed.fragment:
        fragment_start = path_end + (len(parsed.query) + 1 if parsed.query else 0) + 1
        if fragment_start <= relative_start:
            return _is_match_redacted_from_url_component(
                parsed.fragment,
                relative_start - fragment_start,
                value,
                path_awaits_sensitive_value=path_awaits_sensitive_value,
            )
    return False


def _is_match_redacted_from_url_component(
    component: str,
    match_start: int,
    value: str,
    *,
    path_awaits_sensitive_value: bool = False,
) -> bool:
    """Distinguish redacted credential material from nested endpoints in a query or fragment."""
    field_start = 0
    field_end = len(component)
    for separator_match in _URL_COMPONENT_SEPARATOR_PATTERN.finditer(component):
        if separator_match.end() <= match_start:
            field_start = separator_match.end()
        elif separator_match.start() > match_start:
            field_end = separator_match.start()
            break

    key, separator, field_value = component[field_start:field_end].partition("=")
    value_lower = value.lower()
    if _query_prefix_awaits_sensitive_value(component[:field_start]):
        return True
    if path_awaits_sensitive_value and not (separator and _is_endpoint_location_key(key)):
        return True
    if separator and _is_sensitive_path_key(_decode_query_component(key)):
        return True
    nested_url_candidates = (field_value, _decode_path_token(field_value))
    for candidate in nested_url_candidates:
        if candidate == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
            continue
        for nested_url_match in _URI_IN_TEXT_PATTERN.finditer(candidate):
            nested_url = nested_url_match.group()
            if value_lower not in nested_url.lower():
                continue
            if _query_prefix_awaits_sensitive_value(candidate[: nested_url_match.start()]):
                return True
            safe_nested_url = redact_url_for_finding(nested_url)
            if value_lower not in safe_nested_url.lower():
                return True

        for decoded_field in _URL_COMPONENT_SEPARATOR_PATTERN.split(candidate):
            decoded_key, decoded_separator, decoded_value = decoded_field.partition("=")
            if decoded_separator and value_lower in decoded_value.lower() and _is_sensitive_path_key(decoded_key):
                return True

    field = component[field_start:field_end]
    decoded_field = _decode_query_component(field)
    if decoded_field == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return True
    delimited_parts = [part for part in re.split(r"(?i)&amp;|[/,:;&\s]", decoded_field) if part]
    redact_next_value = False
    authorization_value_pending = False
    for index, part in enumerate(delimited_parts):
        if redact_next_value:
            if value_lower in part.lower():
                return True
            following_value = next((candidate for candidate in delimited_parts[index + 1 :] if candidate), None)
            redact_next_value = (
                authorization_value_pending
                and _is_chainable_authorization_scheme(part)
                and _authorization_scheme_has_payload(part, following_value)
            )
            authorization_value_pending = redact_next_value
            continue
        if _is_sensitive_path_key(part):
            redact_next_value = True
            authorization_value_pending = _is_authorization_path_key(part)

    for redacted_field in (
        _redact_encoded_path_separator_tokens(field),
        _redact_colon_delimited_path_tokens(field),
        _redact_boundary_delimited_path_tokens(field),
        _redact_path_parameter_tokens(field),
    ):
        if redacted_field is not None and value_lower in field.lower():
            return value_lower not in redacted_field.lower()

    return bool(separator and _is_sensitive_path_key(key))


def _url_path_awaits_sensitive_value(url: str) -> bool:
    """Return whether a truncated URL path ends just before a credential value."""
    try:
        segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    except ValueError:
        return False
    if not segments:
        return False

    final_segment = _decode_path_token(_split_trailing_path_delimiters(segments[-1])[0])
    if _is_sensitive_path_key(final_segment) or _compound_path_segment_ends_with_sensitive_key(final_segment):
        return True
    return (
        len(segments) > 1
        and _AUTHORIZATION_SCHEME_PATTERN.fullmatch(final_segment) is not None
        and _is_sensitive_path_key(_decode_path_token(segments[-2]))
    )


def _is_split_sensitive_url_value(data: bytes, match_start: int) -> bool:
    """Recognize credentials after bounded source or UTF-8 URL-path splits."""
    scan_start = max(0, match_start - _MAX_URL_TEXT_LOOKUP_BYTES)
    preceding_url_match = None
    for candidate in _URL_IN_BYTES_PATTERN.finditer(data, scan_start, match_start):
        preceding_url_match = candidate
    if preceding_url_match is None:
        return False

    gap = data[preceding_url_match.end() : match_start]
    if not gap:
        return False
    gap_without_comments = re.sub(rb"#[^\r\n]*", b"", gap)
    source_composition = all(
        byte >= 128 or byte in b"\\\"' +(){}[]\t\r\n" or byte in b"rRuUbBfF" for byte in gap_without_comments
    )
    path_continuation = all(byte >= 128 or byte in b"\\\"'" for byte in gap)
    continuation_evidence = (
        b"+" in gap_without_comments
        or b"\\" in gap
        or b"{" in gap
        or sum(gap.count(quote) for quote in (b"'", b'"')) >= 2
        or any(byte >= 128 for byte in gap)
    )
    if (not source_composition and not path_continuation) or not continuation_evidence:
        return False

    url = _trim_matched_source_url(data, preceding_url_match)
    return _url_path_awaits_sensitive_value(url)


def _is_redacted_evidence_value(data: bytes, match_start: int, value: str) -> bool:
    """Use the shared redactor to reject endpoint-shaped credential values."""
    direct_decision = _direct_evidence_redaction_decision(data, match_start)
    if direct_decision is not None:
        return direct_decision
    before = max(0, match_start - _MAX_URL_TEXT_LOOKUP_BYTES)
    match_end = match_start + len(value.encode("utf-8"))
    after = min(len(data), match_end + _MAX_URL_TEXT_LOOKUP_BYTES)
    evidence = data[before:after]
    if _SENSITIVE_EVIDENCE_HINT_PATTERN.search(evidence) is None:
        return False

    marked_text = "".join(
        (
            data[before:match_start].decode("utf-8", errors="ignore"),
            _EVIDENCE_MATCH_START_MARKER,
            data[match_start:match_end].decode("utf-8", errors="ignore"),
            _EVIDENCE_MATCH_END_MARKER,
            data[match_end:after].decode("utf-8", errors="ignore"),
        )
    )
    redacted = _redact_network_evidence(marked_text)
    return _EVIDENCE_MATCH_START_MARKER not in redacted or _EVIDENCE_MATCH_END_MARKER not in redacted


def _direct_evidence_redaction_decision(data: bytes, match_start: int) -> bool | None:
    """Classify immediate auth values and direct network-location assignments."""
    prefix = data[max(0, match_start - 512) : match_start]
    if _DIRECT_AUTH_SCHEME_VALUE_PATTERN.search(prefix) is not None:
        return True

    trimmed = prefix.rstrip(b" \t\"'")
    if not trimmed or trimmed[-1:] not in {b"=", b":"}:
        return None

    key_prefix = trimmed[:-1].rstrip()
    if key_prefix[-1:] in {b'"', b"'"}:
        key_prefix = key_prefix[:-1].rstrip()
    record_start = max(
        (
            key_prefix.rfind(delimiter)
            for delimiter in (b"\r", b"\n", b",", b";", b"?", b"&", b"#", b"{", b"}", b"[", b"]", b"(", b")")
        ),
        default=-1,
    )
    key = key_prefix[record_start + 1 :].strip().strip(b"\"'")
    if not key or b"=" in key or b":" in key:
        return None

    if _is_endpoint_location_key(key.decode("utf-8", errors="ignore")):
        return False
    return None


def _query_prefix_awaits_sensitive_value(prefix: str) -> bool:
    """Return whether decoded query fields leave a credential key pending."""
    awaiting_value = False
    for field in _URL_COMPONENT_SEPARATOR_PATTERN.split(prefix):
        if not field:
            continue
        if awaiting_value:
            awaiting_value = False
            continue

        key, separator, field_value = field.partition("=")
        if separator:
            awaiting_value = not field_value and _is_sensitive_path_key(_decode_query_component(key))
            continue

        decoded_field = _decode_query_component(field)
        if decoded_field == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
            awaiting_value = True
            continue
        parts = [part for part in re.split(r"[=/,:\s]+", decoded_field) if part]
        awaiting_value = any(_is_sensitive_path_key("_".join(parts[index:])) for index in range(len(parts)))
    return awaiting_value


def _decoded_nested_urls(url: str) -> Iterator[str]:
    """Yield nested URLs that only become visible after bounded component decoding."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return

    seen: set[str] = set()
    path_awaits_sensitive_value = _url_path_awaits_sensitive_value(url)
    for component, decoder in ((parsed.path, unquote), (parsed.query, unquote_plus), (parsed.fragment, unquote_plus)):
        pending_sensitive_value = False
        for field in _URL_COMPONENT_SEPARATOR_PATTERN.split(component):
            inherited_sensitive_value = pending_sensitive_value and bool(field)
            if field:
                pending_sensitive_value = False
            key, separator, value = field.partition("=")
            candidate = value if separator else field
            decoded_key = _decode_query_component(key)
            path_key = decoded_key.rsplit("/", maxsplit=1)[-1]
            sensitive_key = bool(
                separator and (_is_sensitive_path_key(decoded_key) or _is_sensitive_path_key(path_key))
            )
            sensitive_field = inherited_sensitive_value or sensitive_key
            if separator:
                pending_sensitive_value = sensitive_key and not value
            elif _query_prefix_awaits_sensitive_value(field):
                pending_sensitive_value = True
            decoded = candidate
            decode_limit_exhausted = False
            for _ in range(_MAX_PATH_TOKEN_DECODE_PASSES):
                next_decoded = decoder(decoded)
                if next_decoded == decoded:
                    break
                decoded = next_decoded
            else:
                next_decoded = decoder(decoded)
                if next_decoded != decoded:
                    decoded = next_decoded
                    decode_limit_exhausted = True

            found_nested_url = False
            for match in _URI_IN_TEXT_PATTERN.finditer(decoded):
                redact_nested_url = (
                    (path_awaits_sensitive_value and not (separator and _is_endpoint_location_key(key)))
                    or sensitive_field
                    or _query_prefix_awaits_sensitive_value(decoded[: match.start()])
                )
                nested_url = _SENSITIVE_NESTED_URL if redact_nested_url else match.group()
                if nested_url not in seen:
                    seen.add(nested_url)
                    found_nested_url = True
                    yield nested_url
            if (
                decode_limit_exhausted
                and not found_nested_url
                and _ENCODED_URI_SCHEME_PATTERN.search(decoded) is not None
                and _OVER_ENCODED_NESTED_URL not in seen
            ):
                seen.add(_OVER_ENCODED_NESTED_URL)
                yield _OVER_ENCODED_NESTED_URL


_DOC_CONTEXT_EXTENSIONS: tuple[str, ...] = (
    ".md",
    ".rst",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
)
_DOC_CONTEXT_NAMES: frozenset[str] = frozenset(
    {
        "readme",
        "metadata",
        "description",
        "model_card",
        "manifest",
    }
)
_DOC_CONTEXT_SEGMENTS: frozenset[str] = frozenset(
    {
        "metadata",
        "description",
        "model_card",
        "manifest",
    }
)
_DOC_CONTEXT_NAME_PREFIXES: tuple[str, ...] = (
    "readme",
    "model_card",
)
_PROSE_MARKERS: tuple[str, ...] = (
    " example",
    " examples",
    " documentation",
    " readme",
    " description",
    " metadata",
    " says",
    " mentions",
    " includes",
)
_EXPLICIT_PROSE_PREFIX_PATTERN = re.compile(
    rb"^\s*#?\s*(?:see|use|docs?|documentation|readme|description|metadata|author(?:'s|s')?\s+docs?)\b",
    re.IGNORECASE,
)
_MAX_PROSE_LINE_CONTEXT_BYTES = 512
_MAX_README_IMAGE_EXAMPLE_BYTES = 64 * 1024
_MAX_README_IMAGE_EXAMPLE_AST_NODES = 1024
_MAX_README_IMAGE_EXAMPLE_FENCE_OPENINGS = 64
_MAX_README_IMAGE_EXAMPLE_FENCES = 256
_PYTHON_README_FENCE_PATTERN = re.compile(rb"(?m)^[ \t]{0,3}(?P<fence>`{3,}|~{3,})(?:python|py)[ \t]*\r?\n")
_README_FENCE_END_PATTERN = re.compile(rb"(?m)^[ \t]{0,3}(?:`{3,}|~{3,})[ \t]*\r?$")
_QUALIFIED_REQUESTS_CALL_PATTERN = re.compile(rb"\brequests\s*\.\s*[A-Za-z_][A-Za-z_0-9]*\s*\(")
_DOCUMENTED_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp")
_WORD_PATTERN = re.compile(rb"[A-Za-z]{2,}")
_CALL_SYNTAX_SUFFIX_PATTERN = re.compile(rb"(?:[\s)]|#[^\n]*\n)*\(")
_CODE_LINE_PREFIXES: tuple[bytes, ...] = (
    b"import ",
    b"from ",
    b"def ",
    b"class ",
    b"if ",
)
_CODE_LINE_MARKERS: tuple[bytes, ...] = (
    b"=",
    b";",
    b"lambda ",
)
_DOWNLOADER_COMMAND_TOKEN_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_.-])(?:curl|wget)(?:\.exe)?(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_INLINE_COMPOUND_STATEMENT_PATTERN = re.compile(
    rb"^\s*(?:if|elif|else|for|while|with|try|except|finally|match|case)\b[^#\n]*:\s*\S"
)
_STRUCTURED_METADATA_PREFIXES: tuple[bytes, ...] = (b"{", b"[", b'"', b"'")
_EXPLICIT_VERSION_LITERAL_CONTEXT_PATTERN = re.compile(
    rb"\b(?:version|ver|release|build)\s*[:=]\s*[\"']?"
    rb"(?P<value>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[\"']?",
    re.IGNORECASE,
)
_PLAIN_VERSION_LITERAL_CONTEXT_PATTERN = re.compile(
    rb"(?:(?:^|[\r\n])\s*version|model\s+version|release|build)\s+[\"']?"
    rb"(?P<value>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[\"']?",
    re.IGNORECASE,
)
_ML_LAYER_DOMAIN_PATTERN = re.compile(
    r"^(?:layer\d+|conv\d*d?|bn\d+|norm\d+|fc\d+|dense\d+)\.(?:weight|bias)$",
    re.IGNORECASE,
)


def _is_metadata_context(context: str) -> bool:
    """Return whether the scan context appears to be documentation or metadata."""
    context_lower = context.lower()
    context_segments = [segment for segment in context_lower.replace("\\", "/").split("/") if segment]
    filename = context_segments[-1] if context_segments else context_lower
    stem = filename.rsplit(".", 1)[0]

    if filename.endswith(_DOC_CONTEXT_EXTENSIONS):
        return True
    if stem in _DOC_CONTEXT_NAMES or stem.startswith(_DOC_CONTEXT_NAME_PREFIXES):
        return True
    return any(segment in _DOC_CONTEXT_SEGMENTS for segment in context_segments[:-1])


def _iter_pattern_matches(data: bytes, pattern: bytes) -> Iterator[int]:
    """Yield non-overlapping match positions for a byte pattern."""
    start = 0
    while True:
        match_index = data.find(pattern, start)
        if match_index < 0:
            break
        yield match_index
        start = match_index + max(1, len(pattern))


def _has_call_syntax(data: bytes, match_index: int, token_len: int) -> bool:
    """Return whether a token is followed by call syntax after optional whitespace."""
    cursor = match_index + token_len
    suffix = data[cursor : cursor + _MAX_PROSE_LINE_CONTEXT_BYTES]
    return _CALL_SYNTAX_SUFFIX_PATTERN.match(suffix) is not None


def _is_version_literal_context(surrounding_bytes: bytes, token: bytes) -> bool:
    """Return whether the matched token is explicitly presented as a version literal."""
    return any(
        match.group("value") == token
        for pattern in (_EXPLICIT_VERSION_LITERAL_CONTEXT_PATTERN, _PLAIN_VERSION_LITERAL_CONTEXT_PATTERN)
        for match in pattern.finditer(surrounding_bytes)
    )


def _is_doc_only_network_reference(
    data: bytes,
    *,
    match_index: int,
    token_len: int,
    context: str,
    requires_call: bool,
    requires_explicit_prefix: bool = False,
) -> bool:
    """Return whether a raw network token appears in prose instead of executable code."""
    if requires_call and _has_call_syntax(data, match_index, token_len):
        return False

    source_line_start = data.rfind(b"\n", 0, match_index) + 1
    source_line_end = data.find(b"\n", match_index)
    if source_line_end < 0:
        source_line_end = len(data)
    continued_prefix = data[max(0, source_line_start - 3) : source_line_start]
    continued_suffix = data[match_index + token_len : source_line_end].rstrip()
    if (
        match_index - source_line_start > _MAX_PROSE_LINE_CONTEXT_BYTES
        or source_line_end - (match_index + token_len) > _MAX_PROSE_LINE_CONTEXT_BYTES
        or continued_prefix.endswith((b"\\\n", b"\\\r\n"))
        or continued_suffix.endswith(b"\\")
    ):
        return False

    line = data[source_line_start:source_line_end]
    line_lower = line.lower()
    stripped = line_lower.lstrip()
    word_count = len(_WORD_PATTERN.findall(line))
    metadata_context = _is_metadata_context(context)
    match_offset = match_index - source_line_start
    line_without_match = line[:match_offset] + b" " + line[match_offset + token_len :]
    prefix_before_match = line[:match_offset].strip()
    explicit_prefix = _EXPLICIT_PROSE_PREFIX_PATTERN.match(prefix_before_match) is not None
    if requires_explicit_prefix and prefix_before_match and not explicit_prefix:
        return False

    if any(stripped.startswith(prefix) for prefix in _CODE_LINE_PREFIXES):
        return False
    if _INLINE_COMPOUND_STATEMENT_PATTERN.match(line_lower):
        return False
    if any(marker in line_lower for marker in _CODE_LINE_MARKERS):
        return False
    if _DOWNLOADER_COMMAND_TOKEN_PATTERN.search(line_without_match):
        return False
    if metadata_context and stripped.startswith(_STRUCTURED_METADATA_PREFIXES):
        return False

    text = line.decode("utf-8", errors="ignore").lower()
    has_prose_marker = (requires_explicit_prefix and explicit_prefix) or any(
        marker in text for marker in _PROSE_MARKERS
    )
    if not has_prose_marker:
        return False
    return (metadata_context and word_count >= 4) or word_count >= 6


def _is_official_readme_sample_image_request(
    data: bytes,
    *,
    match_index: int,
    context: str,
    fence_cache: list[tuple[int, int, bool]],
    preindexed: bool = False,
) -> bool:
    if not _is_readme_image_example_context(context):
        return False
    if preindexed:
        fence_index = bisect_right(fence_cache, (match_index, len(data), True)) - 1
        if fence_index < 0:
            return False
        fence_start, fence_end, is_safe = fence_cache[fence_index]
        return fence_start <= match_index < fence_end and is_safe
    for fence_start, fence_end, is_safe in reversed(fence_cache):
        if fence_start <= match_index < fence_end:
            return is_safe

    example: bytes | None = None
    example_start = 0
    example_end = 0
    window_start = max(0, match_index - _MAX_README_IMAGE_EXAMPLE_BYTES)
    openings: list[re.Match[bytes]] = []
    for opening in _PYTHON_README_FENCE_PATTERN.finditer(data, window_start, match_index + 1):
        if len(openings) >= _MAX_README_IMAGE_EXAMPLE_FENCE_OPENINGS:
            return False
        openings.append(opening)
    for opening in openings:
        if opening.end() > match_index:
            break
        closing = _matching_readme_image_fence_end(
            data,
            opening,
            opening.end(),
            min(len(data), opening.end() + _MAX_README_IMAGE_EXAMPLE_BYTES),
        )
        if closing is not None and opening.end() <= match_index < closing.start():
            example = data[opening.end() : closing.start()]
            example_start = opening.end()
            example_end = closing.start()
            break
    if example is None:
        return False
    is_safe = _is_valid_official_readme_sample_image_example(example)
    if len(fence_cache) >= 64:
        fence_cache.pop(0)
    fence_cache.append((example_start, example_end, is_safe))
    return is_safe


def _index_official_readme_sample_image_fences(
    data: bytes,
    context: str,
) -> tuple[list[tuple[int, int, bool]], bool]:
    if not _is_readme_image_example_context(context) or b"requests" not in data:
        return [], False

    fences: list[tuple[int, int, bool]] = []
    unvalidated_requests = False
    cursor = 0
    while opening := _PYTHON_README_FENCE_PATTERN.search(data, cursor):
        if len(fences) >= _MAX_README_IMAGE_EXAMPLE_FENCES:
            return [], True
        closing = _matching_readme_image_fence_end(
            data,
            opening,
            opening.end(),
            min(len(data), opening.end() + _MAX_README_IMAGE_EXAMPLE_BYTES),
        )
        if closing is None:
            unvalidated_requests = True
            cursor = min(len(data), opening.end() + _MAX_README_IMAGE_EXAMPLE_BYTES)
            continue
        example = data[opening.end() : closing.start()]
        is_safe = (
            b"import requests" in example
            and b"requests.get" in example
            and _is_valid_official_readme_sample_image_example(example)
        )
        if not is_safe and _contains_executable_requests_reference(example):
            unvalidated_requests = True
        fences.append((opening.end(), closing.start(), is_safe))
        cursor = closing.end()
    outside_start = 0
    for fence_start, fence_end, _is_safe in fences:
        if _contains_executable_requests_reference(data[outside_start:fence_start]):
            unvalidated_requests = True
            break
        outside_start = fence_end
    if not unvalidated_requests and _contains_executable_requests_reference(data[outside_start:]):
        unvalidated_requests = True
    return fences, unvalidated_requests


def _contains_executable_requests_reference(data: bytes) -> bool:
    if b"requests" not in data:
        return False
    if len(data) <= _MAX_README_IMAGE_EXAMPLE_BYTES:
        try:
            tree = ast.parse(data.decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError, RecursionError, ValueError):
            pass
        else:
            return any(
                isinstance(node, ast.Name) and node.id == "requests" and isinstance(node.ctx, ast.Load)
                for node in ast.walk(tree)
            )

    for checked_matches, match in enumerate(_QUALIFIED_REQUESTS_CALL_PATTERN.finditer(data)):
        if checked_matches >= _MAX_README_IMAGE_EXAMPLE_AST_NODES:
            return True
        line_start = data.rfind(b"\n", 0, match.start()) + 1
        line_end = data.find(b"\n", match.end())
        line = data[line_start : len(data) if line_end < 0 else line_end]
        if len(line) > _MAX_README_IMAGE_EXAMPLE_BYTES:
            return True
        try:
            tokens = list(tokenize.tokenize(BytesIO(line).readline))
        except (tokenize.TokenError, UnicodeDecodeError, SyntaxError):
            return True
        if any(token.type == tokenize.NAME and token.string == "requests" for token in tokens):
            return True
    return False


def _is_readme_image_example_context(context: str) -> bool:
    filename = context.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return filename == "readme" or (
        filename.startswith("readme.") and filename.rsplit(".", 1)[-1] in {"txt", "md", "markdown", "rst", "env"}
    )


def _matching_readme_image_fence_end(
    data: bytes,
    opening: re.Match[bytes],
    start: int,
    end: int,
) -> re.Match[bytes] | None:
    opening_width = len(opening.group("fence"))
    cursor = start
    while closing := _README_FENCE_END_PATTERN.search(data, cursor, end):
        delimiter = data[closing.start() : closing.end()].strip(b" \t\r")
        if delimiter[:1] == opening.group("fence")[:1] and len(delimiter) >= opening_width:
            return closing
        cursor = closing.end()
    return None


# Transformers keywords that cause Hub-hosted Python to be fetched and executed.
_REMOTE_CODE_KEYWORDS = frozenset({"custom_generate", "trust_remote_code"})


def _remote_code_option_is_disabled(name: str, value: ast.expr) -> bool:
    if not isinstance(value, ast.Constant):
        return False
    if name == "trust_remote_code":
        return value.value is False
    if name == "custom_generate":
        return value.value is None
    return True


def _generate_positional_remote_code_is_disabled(arguments: list[ast.expr]) -> bool:
    if len(arguments) <= 10:
        return True

    position_ten = arguments[10]
    position_ten_is_disabled_or_v4_default = isinstance(position_ten, ast.Constant) and (
        position_ten.value is None or isinstance(position_ten.value, bool)
    )
    if len(arguments) == 11:
        return position_ten_is_disabled_or_v4_default

    return position_ten_is_disabled_or_v4_default and _remote_code_option_is_disabled(
        "custom_generate",
        arguments[11],
    )


def _remote_code_mapping_is_proven_safe(
    value: ast.expr,
    *,
    bindings: dict[str, list[tuple[int, ast.expr]]],
    binding_counts: Counter[str],
    unsafe_names: frozenset[str],
    proven_mapping_call_ids: frozenset[int],
    call_position: int,
) -> bool:
    memo: dict[int, bool] = {}
    remaining_steps = _MAX_README_IMAGE_EXAMPLE_AST_NODES

    def visit(current: ast.expr, resolving: frozenset[str]) -> bool:
        nonlocal remaining_steps

        node_id = id(current)
        if node_id in memo:
            return memo[node_id]
        if remaining_steps <= 0:
            return False
        remaining_steps -= 1

        if isinstance(current, ast.Name):
            if current.id in resolving or current.id in unsafe_names or binding_counts[current.id] != 1:
                result = False
            else:
                candidates = bindings.get(current.id, [])
                if len(candidates) != 1:
                    result = False
                else:
                    binding_position, binding_value = candidates[0]
                    result = binding_position < call_position and visit(
                        binding_value,
                        resolving | {current.id},
                    )
        elif isinstance(current, ast.Call):
            result = node_id in proven_mapping_call_ids
        elif isinstance(current, ast.Dict):
            result = True
            for key, item_value in zip(current.keys, current.values, strict=True):
                if key is None:
                    if not visit(item_value, resolving):
                        result = False
                        break
                    continue
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    result = False
                    break
                if key.value in _REMOTE_CODE_KEYWORDS and not _remote_code_option_is_disabled(
                    key.value,
                    item_value,
                ):
                    result = False
                    break
        else:
            result = False

        memo[node_id] = result
        return result

    try:
        return visit(value, frozenset())
    except RecursionError:
        return False


def _is_valid_official_readme_sample_image_example(example: bytes) -> bool:
    if b"import requests" not in example or b"requests.get" not in example:
        return False
    try:
        tree = ast.parse(example.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError, RecursionError, ValueError):
        return False

    nodes: list[ast.AST] = []
    for node in ast.walk(tree):
        if len(nodes) >= _MAX_README_IMAGE_EXAMPLE_AST_NODES:
            return False
        nodes.append(node)
    parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    imports = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if alias.name == "requests" and alias.asname is None
    ]
    if len(imports) != 1:
        return False

    requests_calls: list[ast.Call] = []
    for node in nodes:
        if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name) or node.value.id != "requests":
            continue
        parent = parents.get(id(node))
        if (
            node.attr != "get"
            or not isinstance(node.ctx, ast.Load)
            or not isinstance(parent, ast.Call)
            or parent.func is not node
        ):
            return False
    for node in nodes:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "requests"
            and node.func.attr == "get"
        ):
            requests_calls.append(node)
    if not requests_calls:
        return False
    if any(imports[0].lineno >= call.lineno for call in requests_calls):
        return False

    protected_names = {"requests"}
    protected_names.update(
        call.args[0].id for call in requests_calls if len(call.args) == 1 and isinstance(call.args[0], ast.Name)
    )
    callable_assignments = {
        target.id
        for statement in tree.body
        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    documented_builtin_names = {"enumerate", "len", "print", "range", "round", "zip"}
    imported_names = {"requests"}
    transformers_factory_names: set[str] = set()
    transformers_mapping_factory_names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None or alias.name not in {"requests", "torch"}:
                    return False
                imported_names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or node.module not in {"PIL", "transformers"}:
                return False
            for alias in node.names:
                if (
                    alias.asname is not None
                    or alias.name == "*"
                    or (node.module == "PIL" and alias.name != "Image")
                    or (node.module == "transformers" and not alias.name[:1].isupper())
                ):
                    return False
                imported_names.add(alias.name)
                if node.module == "transformers":
                    transformers_factory_names.add(alias.name)
                    if alias.name.endswith(("Processor", "Tokenizer", "TokenizerFast", "FeatureExtractor")):
                        transformers_mapping_factory_names.add(alias.name)
    known_names = (
        imported_names
        | documented_builtin_names
        | {"Image", "str", "torch"}
        | {node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
        | {node.arg for node in nodes if isinstance(node, ast.arg)}
        | {node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    )
    requests_response_names: set[str] = set()
    binding_nodes = sorted(
        (node for node in nodes if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.withitem))),
        key=lambda node: (
            getattr(node, "lineno", getattr(node.context_expr, "lineno", 0))
            if isinstance(node, ast.withitem)
            else node.lineno
        ),
    )
    for node in binding_nodes:
        response_bindings: list[tuple[ast.expr, ast.expr | None]] = []
        if isinstance(node, ast.Assign):
            response_bindings.extend((target, node.value) for target in node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            response_bindings.append((node.target, node.value))
        elif node.optional_vars is not None:
            response_bindings.append((node.optional_vars, node.context_expr))
        for target, response_value in response_bindings:
            if not isinstance(target, ast.Name) or response_value is None:
                continue
            is_documented_image_open = (
                isinstance(response_value, ast.Call)
                and isinstance(response_value.func, ast.Attribute)
                and isinstance(response_value.func.value, ast.Name)
                and response_value.func.value.id == "Image"
                and response_value.func.attr == "open"
            )
            if not is_documented_image_open and any(
                child in requests_calls
                or (
                    isinstance(child, ast.Name)
                    and isinstance(child.ctx, ast.Load)
                    and child.id in requests_response_names
                )
                for child in ast.walk(response_value)
            ):
                requests_response_names.add(target.id)
    documented_attribute_calls = {
        "batch_decode",
        "convert",
        "from_pretrained",
        "generate",
        "is_available",
        "item",
        "no_grad",
        "open",
        "post_process_generation",
        "post_process_object_detection",
        "tensor",
        "to",
        "tolist",
    }
    allowed_targets: set[int] = set()
    mapping_bindings: dict[str, list[tuple[ast.AST, ast.expr]]] = {}
    mapping_aliases: list[tuple[ast.AST, str, str]] = []
    name_write_nodes: dict[str, list[ast.AST]] = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            name_write_nodes.setdefault(node.id, []).append(node)
        elif isinstance(node, ast.arg):
            name_write_nodes.setdefault(node.arg, []).append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name_write_nodes.setdefault(node.name, []).append(node)
    assignments: dict[str, list[tuple[int, str | None]]] = {}
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target in targets:
            if isinstance(target, ast.Name) and statement.value is not None:
                mapping_bindings.setdefault(target.id, []).append((statement, statement.value))
            if isinstance(target, ast.Name) and target.id in protected_names and target.id != "requests":
                if isinstance(statement, ast.AnnAssign) and not isinstance(statement.value, ast.Constant):
                    continue
                allowed_targets.add(id(target))
                value = statement.value.value if isinstance(statement.value, ast.Constant) else None
                assignments.setdefault(target.id, []).append(
                    (statement.lineno, value if isinstance(value, str) else None)
                )
    for binding_node in nodes:
        if not isinstance(binding_node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = binding_node.targets if isinstance(binding_node, ast.Assign) else [binding_node.target]
        if (
            not isinstance(parents.get(id(binding_node)), ast.Module)
            and isinstance(binding_node.value, ast.Call)
            and len(targets) == 1
            and isinstance(targets[0], ast.Name)
        ):
            mapping_bindings.setdefault(targets[0].id, []).append((binding_node, binding_node.value))
        identity_names = [target.id for target in targets if isinstance(target, ast.Name)]
        if isinstance(binding_node.value, ast.Name):
            identity_names.append(binding_node.value.id)
        if identity_names:
            root_name = identity_names[0]
            for alias_name in identity_names[1:]:
                if alias_name == root_name:
                    continue
                mapping_aliases.append((binding_node, root_name, alias_name))
    for candidates in mapping_bindings.values():
        candidates.sort(key=lambda item: (getattr(item[0], "lineno", 0), getattr(item[0], "col_offset", 0)))

    top_level_statement_indices = {
        id(descendant): statement_index
        for statement_index, statement in enumerate(tree.body)
        for descendant in ast.walk(statement)
    }
    statement_memberships = {
        id(statement): (parent, field_name, statement_index, statement)
        for parent in nodes
        for field_name, field_value in ast.iter_fields(parent)
        if isinstance(field_value, list)
        for statement_index, statement in enumerate(field_value)
        if isinstance(statement, ast.stmt)
    }

    def top_level_statement_precedes(candidate: ast.AST, reference: ast.AST) -> bool:
        candidate_index = top_level_statement_indices.get(id(candidate))
        reference_index = top_level_statement_indices.get(id(reference))
        return candidate_index is not None and reference_index is not None and candidate_index < reference_index

    def is_single_name_binding(binding: ast.AST | None, value: ast.expr, expected_name: str | None = None) -> bool:
        if isinstance(binding, ast.Assign):
            if binding.value is not value or len(binding.targets) != 1:
                return False
            target = binding.targets[0]
        elif isinstance(binding, ast.AnnAssign):
            if binding.value is not value:
                return False
            target = binding.target
        else:
            return False
        return isinstance(target, ast.Name) and (expected_name is None or target.id == expected_name)

    def name_writes_match_binding_chain(write_nodes: list[ast.AST], binding_chain: tuple[int, ...]) -> bool:
        write_indices = [top_level_statement_indices.get(id(write_node)) for write_node in write_nodes]
        binding_indices = [top_level_statement_indices.get(binding_id) for binding_id in binding_chain]
        return (
            None not in write_indices
            and None not in binding_indices
            and Counter(write_indices) == Counter(binding_indices)
        )

    def call_execution_may_be_deferred(call: ast.Call) -> bool:
        current: ast.AST = call
        while parent := parents.get(id(current)):
            if isinstance(parent, ast.GeneratorExp):
                return True
            if isinstance(parent, ast.Lambda) and current is parent.body:
                return True
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                current is statement for statement in parent.body
            ):
                return True
            current = parent
        return False

    def direct_statement_membership(node: ast.AST) -> tuple[ast.AST, str, int, ast.stmt] | None:
        current = node
        while parent := parents.get(id(current)):
            membership = statement_memberships.get(id(current))
            if membership is not None:
                return membership
            current = parent
        return None

    def is_canonical_no_grad_with(node: ast.With) -> bool:
        if len(node.items) != 1 or node.items[0].optional_vars is not None:
            return False
        context = node.items[0].context_expr
        return (
            isinstance(context, ast.Call)
            and not context.args
            and not context.keywords
            and isinstance(context.func, ast.Attribute)
            and context.func.attr == "no_grad"
            and isinstance(context.func.value, ast.Name)
            and context.func.value.id == "torch"
        )

    def is_single_execution_body(container: ast.AST, field_name: str) -> bool:
        if isinstance(container, ast.If):
            return field_name in {"body", "orelse"}
        return isinstance(container, ast.With) and field_name == "body" and is_canonical_no_grad_with(container)

    def nested_mapping_binding_precedes_call(binding: ast.AST, call: ast.Call) -> bool:
        if call_execution_may_be_deferred(call):
            return False
        binding_membership = direct_statement_membership(binding)
        call_membership = direct_statement_membership(call)
        if binding_membership is None or call_membership is None:
            return False
        binding_container, binding_field, binding_index, binding_statement = binding_membership
        call_container, call_field, call_index, call_statement = call_membership
        if (
            binding_container is not call_container
            or binding_field != call_field
            or binding_statement is not binding
            or not isinstance(call_statement, ast.Expr)
            or call_statement.value is not call
            or binding_index >= call_index
            or not is_single_execution_body(binding_container, binding_field)
        ):
            return False

        container = binding_container
        while not isinstance(container, ast.Module):
            container_membership = direct_statement_membership(container)
            if container_membership is None:
                return False
            parent, field_name, _statement_index, statement = container_membership
            if statement is not container:
                return False
            if isinstance(parent, ast.Module):
                return True
            if not is_single_execution_body(parent, field_name):
                return False
            container = parent
        return True

    def mapping_binding_position_at_call(binding: ast.AST, call: ast.Call) -> int:
        binding_position = top_level_statement_indices[id(binding)]
        call_position = top_level_statement_indices[id(call)]
        if not isinstance(parents.get(id(binding)), ast.Module):
            return call_position - 1 if nested_mapping_binding_precedes_call(binding, call) else call_position
        return binding_position

    def mapping_operation_may_affect_call(operation: ast.AST, call: ast.Call) -> bool:
        if call_execution_may_be_deferred(call):
            return True
        if getattr(operation, "lineno", None) == call.lineno:
            return True
        operation_index = top_level_statement_indices.get(id(operation))
        call_index = top_level_statement_indices.get(id(call))
        return operation_index is None or call_index is None or operation_index <= call_index

    aliased_mapping_names = set(mapping_bindings)
    for _binding_node, first_name, second_name in mapping_aliases:
        aliased_mapping_names.update((first_name, second_name))

    def is_proven_mapping_use(node: ast.Name, proven_mapping_transfer_call_ids: frozenset[int]) -> bool:
        parent = parents.get(id(node))
        if (
            isinstance(parent, ast.Call)
            and len(parent.args) == 1
            and parent.args[0] is node
            and not parent.keywords
            and isinstance(parent.func, ast.Name)
            and parent.func.id == "len"
            and not any(
                mapping_operation_may_affect_call(write_node, parent) for write_node in name_write_nodes.get("len", [])
            )
        ):
            return True
        if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr == "to":
            transfer_call = parents.get(id(parent))
            return isinstance(transfer_call, ast.Call) and id(transfer_call) in proven_mapping_transfer_call_ids
        if isinstance(parent, ast.keyword):
            return parent.arg is None and parent.value is node
        if isinstance(parent, ast.Dict):
            return any(
                key is None and item_value is node for key, item_value in zip(parent.keys, parent.values, strict=True)
            )
        if isinstance(parent, ast.Assign):
            return parent.value is node and all(isinstance(target, ast.Name) for target in parent.targets)
        return isinstance(parent, ast.AnnAssign) and parent.value is node and isinstance(parent.target, ast.Name)

    def unsafe_mapping_operations_for(
        proven_mapping_transfer_call_ids: frozenset[int],
    ) -> list[tuple[str, ast.AST]]:
        operations: list[tuple[str, ast.AST]] = [
            (node.id, node)
            for node in nodes
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in aliased_mapping_names
            and not is_proven_mapping_use(node, proven_mapping_transfer_call_ids)
        ]
        operations.extend(
            (node.target.id, node)
            for node in nodes
            if isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id in aliased_mapping_names
        )
        return operations

    def remote_code_mapping_is_proven_safe_at_call(
        value: ast.expr,
        call: ast.Call,
        *,
        proven_mapping_call_ids: frozenset[int] = frozenset(),
        proven_mapping_binding_chains: dict[int, tuple[int, ...]] | None = None,
        proven_mapping_transfer_call_ids: frozenset[int] = frozenset(),
    ) -> bool:
        binding_chains = proven_mapping_binding_chains or {}
        relevant_binding_nodes = {
            name: [
                (binding_node, binding_value)
                for binding_node, binding_value in candidates
                if mapping_operation_may_affect_call(binding_node, call)
            ]
            for name, candidates in mapping_bindings.items()
        }
        relevant_name_writes = {
            name: [write_node for write_node in write_nodes if mapping_operation_may_affect_call(write_node, call)]
            for name, write_nodes in name_write_nodes.items()
        }
        relevant_bindings: dict[str, list[tuple[int, ast.expr]]] = {}
        relevant_binding_counts: Counter[str] = Counter()
        for name, candidates in relevant_binding_nodes.items():
            logical_candidates = candidates
            logical_write_count = len(relevant_name_writes.get(name, []))
            if candidates:
                binding_chain = binding_chains.get(id(candidates[-1][0]))
                if (
                    binding_chain is not None
                    and tuple(id(binding_node) for binding_node, _binding_value in candidates) == binding_chain
                    and name_writes_match_binding_chain(relevant_name_writes.get(name, []), binding_chain)
                ):
                    logical_candidates = [candidates[-1]]
                    logical_write_count = 1
            relevant_bindings[name] = [
                (mapping_binding_position_at_call(binding_node, call), binding_value)
                for binding_node, binding_value in logical_candidates
            ]
            relevant_binding_counts[name] = logical_write_count
        for name, write_nodes in relevant_name_writes.items():
            relevant_binding_counts.setdefault(name, len(write_nodes))
        relevant_aliases: dict[str, set[str]] = {}
        for binding_node, first_name, second_name in mapping_aliases:
            if not mapping_operation_may_affect_call(binding_node, call):
                continue
            relevant_aliases.setdefault(first_name, set()).add(second_name)
            relevant_aliases.setdefault(second_name, set()).add(first_name)
        unsafe_names = {
            name
            for name, operation in unsafe_mapping_operations_for(proven_mapping_transfer_call_ids)
            if mapping_operation_may_affect_call(operation, call)
        }
        pending_unsafe_names = list(unsafe_names)
        while pending_unsafe_names:
            unsafe_name = pending_unsafe_names.pop()
            for alias_name in relevant_aliases.get(unsafe_name, set()):
                if alias_name in unsafe_names:
                    continue
                unsafe_names.add(alias_name)
                pending_unsafe_names.append(alias_name)

        return _remote_code_mapping_is_proven_safe(
            value,
            bindings=relevant_bindings,
            binding_counts=relevant_binding_counts,
            unsafe_names=frozenset(unsafe_names),
            proven_mapping_call_ids=proven_mapping_call_ids,
            call_position=top_level_statement_indices[id(call)],
        )

    def call_has_only_proven_safe_mapping_arguments(value: ast.Call) -> bool:
        return (
            not any(isinstance(argument, ast.Starred) for argument in value.args)
            and not any(
                keyword.arg is None and not remote_code_mapping_is_proven_safe_at_call(keyword.value, value)
                for keyword in value.keywords
            )
            and not any(
                keyword.arg in _REMOTE_CODE_KEYWORDS and not _remote_code_option_is_disabled(keyword.arg, keyword.value)
                for keyword in value.keywords
            )
        )

    def trusted_transformers_instance_is_proven_safe(
        instance_name: str,
        binding_node: ast.AST,
        allowed_factory_names: set[str],
    ) -> bool:
        def operation_may_affect_reference(operation: ast.AST) -> bool:
            if isinstance(binding_node, ast.Call):
                if call_execution_may_be_deferred(binding_node):
                    return True
                operation_index = top_level_statement_indices.get(id(operation))
                reference_index = top_level_statement_indices.get(id(binding_node))
                return operation_index is None or reference_index is None or operation_index <= reference_index
            if not isinstance(parents.get(id(binding_node)), ast.Module):
                operation_index = top_level_statement_indices.get(id(operation))
                reference_index = top_level_statement_indices.get(id(binding_node))
                return operation_index is None or reference_index is None or operation_index <= reference_index
            return top_level_statement_precedes(operation, binding_node)

        instance_bindings = [
            (instance_binding, factory_call)
            for instance_binding, factory_call in mapping_bindings.get(instance_name, [])
            if operation_may_affect_reference(instance_binding)
        ]
        relevant_write_count = sum(
            operation_may_affect_reference(write_node) for write_node in name_write_nodes.get(instance_name, [])
        )
        if len(instance_bindings) != 1 or relevant_write_count != 1:
            return False
        instance_binding, factory_call = instance_bindings[0]
        return (
            isinstance(factory_call, ast.Call)
            and call_has_only_proven_safe_mapping_arguments(factory_call)
            and is_single_name_binding(instance_binding, factory_call, instance_name)
            and isinstance(factory_call.func, ast.Attribute)
            and factory_call.func.attr == "from_pretrained"
            and isinstance(factory_call.func.value, ast.Name)
            and factory_call.func.value.id in allowed_factory_names
        )

    def is_allowed_local_device(value: ast.expr) -> bool:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return False
        device = value.value
        return device in {"cpu", "cuda", "mps"} or (
            device.startswith("cuda:") and device.removeprefix("cuda:").isdecimal()
        )

    def mapping_device_is_proven_safe(value: ast.expr, binding_node: ast.AST) -> bool:
        if is_allowed_local_device(value):
            return True
        if isinstance(value, ast.Attribute) and value.attr == "device" and isinstance(value.value, ast.Name):
            return trusted_transformers_instance_is_proven_safe(
                value.value.id,
                binding_node,
                transformers_factory_names,
            )
        if not isinstance(value, ast.Name):
            return False
        device_bindings = [
            (device_binding, device_value)
            for device_binding, device_value in mapping_bindings.get(value.id, [])
            if top_level_statement_precedes(device_binding, binding_node)
        ]
        prior_write_count = sum(
            top_level_statement_precedes(write_node, binding_node) for write_node in name_write_nodes.get(value.id, [])
        )
        if len(device_bindings) != 1 or prior_write_count != 1:
            return False
        device_binding, device_value = device_bindings[0]
        return is_single_name_binding(device_binding, device_value, value.id) and is_allowed_local_device(device_value)

    def unwrap_safe_mapping_device_transfers(
        value: ast.expr,
        binding_node: ast.AST,
    ) -> tuple[ast.expr, tuple[ast.Call, ...]] | None:
        transfers: list[ast.Call] = []
        mapping_value = value
        while (
            isinstance(mapping_value, ast.Call)
            and isinstance(mapping_value.func, ast.Attribute)
            and mapping_value.func.attr == "to"
        ):
            if len(mapping_value.args) == 1 and not mapping_value.keywords:
                device_value = mapping_value.args[0]
            elif (
                not mapping_value.args
                and len(mapping_value.keywords) == 1
                and mapping_value.keywords[0].arg == "device"
            ):
                device_value = mapping_value.keywords[0].value
            else:
                return None
            if not mapping_device_is_proven_safe(device_value, binding_node):
                return None
            transfers.append(mapping_value)
            mapping_value = mapping_value.func.value
        return mapping_value, tuple(transfers)

    def trusted_mapping_factory_call_is_proven_safe(binding_node: ast.AST, mapping_value: ast.expr) -> bool:
        if (
            not isinstance(mapping_value, ast.Call)
            or not isinstance(mapping_value.func, ast.Name)
            or not call_has_only_proven_safe_mapping_arguments(mapping_value)
        ):
            return False
        return trusted_transformers_instance_is_proven_safe(
            mapping_value.func.id,
            binding_node,
            transformers_mapping_factory_names,
        )

    proven_mapping_call_id_set: set[int] = set()
    proven_mapping_transfer_call_id_set: set[int] = set()
    proven_mapping_binding_chains: dict[int, tuple[int, ...]] = {}
    ordered_mapping_bindings = sorted(
        (
            (binding_node, binding_name, binding_value)
            for binding_name, candidates in mapping_bindings.items()
            for binding_node, binding_value in candidates
        ),
        key=lambda item: (
            top_level_statement_indices.get(id(item[0]), len(tree.body)),
            getattr(item[0], "lineno", 0),
            getattr(item[0], "col_offset", 0),
        ),
    )
    for binding_node, binding_name, binding_value in ordered_mapping_bindings:
        if not isinstance(binding_value, ast.Call) or not is_single_name_binding(
            binding_node,
            binding_value,
            binding_name,
        ):
            continue
        unwrapped_mapping = unwrap_safe_mapping_device_transfers(binding_value, binding_node)
        if unwrapped_mapping is None:
            continue
        mapping_value, transfer_calls = unwrapped_mapping
        binding_chain: tuple[int, ...] | None = None
        if trusted_mapping_factory_call_is_proven_safe(binding_node, mapping_value):
            binding_chain = (id(binding_node),)
        elif transfer_calls and isinstance(mapping_value, ast.Name) and mapping_value.id == binding_name:
            prior_bindings = [
                prior_binding
                for prior_binding, _prior_value in mapping_bindings.get(binding_name, [])
                if top_level_statement_precedes(prior_binding, binding_node)
            ]
            if prior_bindings:
                prior_chain = proven_mapping_binding_chains.get(id(prior_bindings[-1]))
                prior_writes = [
                    write_node
                    for write_node in name_write_nodes.get(binding_name, [])
                    if top_level_statement_precedes(write_node, binding_node)
                ]
                if (
                    prior_chain is not None
                    and tuple(id(prior_binding) for prior_binding in prior_bindings) == prior_chain
                    and name_writes_match_binding_chain(prior_writes, prior_chain)
                ):
                    binding_chain = (*prior_chain, id(binding_node))
        if binding_chain is None:
            continue
        proven_mapping_binding_chains[id(binding_node)] = binding_chain
        proven_mapping_call_id_set.add(id(binding_value))
        proven_mapping_transfer_call_id_set.update(id(transfer_call) for transfer_call in transfer_calls)

    standalone_transfer_calls = sorted(
        (node.value for node in nodes if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)),
        key=lambda call: top_level_statement_indices.get(id(call), len(tree.body)),
    )
    for transfer_call in standalone_transfer_calls:
        if call_execution_may_be_deferred(transfer_call):
            continue
        unwrapped_mapping = unwrap_safe_mapping_device_transfers(transfer_call, transfer_call)
        if unwrapped_mapping is None:
            continue
        mapping_value, transfer_calls = unwrapped_mapping
        if not transfer_calls or not isinstance(mapping_value, ast.Name):
            continue
        prior_bindings = [
            prior_binding
            for prior_binding, _prior_value in mapping_bindings.get(mapping_value.id, [])
            if top_level_statement_precedes(prior_binding, transfer_call)
        ]
        if not prior_bindings or id(prior_bindings[-1]) not in proven_mapping_binding_chains:
            continue
        candidate_transfer_call_ids = frozenset(
            proven_mapping_transfer_call_id_set | {id(candidate) for candidate in transfer_calls}
        )
        if not remote_code_mapping_is_proven_safe_at_call(
            mapping_value,
            transfer_call,
            proven_mapping_call_ids=frozenset(proven_mapping_call_id_set),
            proven_mapping_binding_chains=proven_mapping_binding_chains,
            proven_mapping_transfer_call_ids=candidate_transfer_call_ids,
        ):
            continue
        proven_mapping_transfer_call_id_set.update(id(candidate) for candidate in transfer_calls)

    for generate_call in nodes:
        if (
            not isinstance(generate_call, ast.Call)
            or not isinstance(generate_call.func, ast.Attribute)
            or generate_call.func.attr != "generate"
            or call_execution_may_be_deferred(generate_call)
        ):
            continue
        for keyword in generate_call.keywords:
            if keyword.arg is not None or not isinstance(keyword.value, ast.Call):
                continue
            unwrapped_mapping = unwrap_safe_mapping_device_transfers(keyword.value, generate_call)
            if unwrapped_mapping is None:
                continue
            mapping_value, transfer_calls = unwrapped_mapping
            if not trusted_mapping_factory_call_is_proven_safe(generate_call, mapping_value):
                continue
            proven_mapping_call_id_set.add(id(keyword.value))
            proven_mapping_transfer_call_id_set.update(id(transfer_call) for transfer_call in transfer_calls)

    proven_mapping_call_ids = frozenset(proven_mapping_call_id_set)
    proven_mapping_transfer_call_ids = frozenset(proven_mapping_transfer_call_id_set)

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                if (
                    alias.name.split(".", maxsplit=1)[0] in {"builtins", "importlib", "sys"}
                    or (imported_name in protected_names and not (alias.name == "requests" and node in imports))
                    or (alias.name == "requests" and node not in imports)
                ):
                    return False
        if isinstance(node, ast.ImportFrom) and (
            (node.module or "").split(".", maxsplit=1)[0] in {"builtins", "importlib", "requests", "sys"}
            or any(alias.name == "*" or (alias.asname or alias.name) in protected_names for alias in node.names)
        ):
            return False
        if isinstance(node, ast.Match):
            return False
        if isinstance(node, (ast.Assert, ast.Lambda, ast.Raise, ast.Try)):
            return False
        if isinstance(node, ast.ClassDef):
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.name in protected_names or node.decorator_list
        ):
            return False
        if isinstance(node, (ast.Global, ast.Nonlocal)) and any(name in protected_names for name in node.names):
            return False
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(not isinstance(target, ast.Name) for target in targets):
                return False
        if (
            isinstance(node, ast.Name)
            and node.id in protected_names | imported_names | documented_builtin_names
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in allowed_targets
        ):
            return False
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in known_names:
            return False
        if (
            isinstance(node, ast.Name)
            and node.id == "requests"
            and isinstance(node.ctx, ast.Load)
            and (
                not isinstance(parent := parents.get(id(node)), ast.Attribute)
                or parent.value is not node
                or parent.attr != "get"
            )
        ):
            return False
        if isinstance(node, ast.arg) and node.arg in protected_names:
            return False
        if isinstance(node, ast.ExceptHandler) and node.name in protected_names:
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id not in callable_assignments | documented_builtin_names
        ):
            return False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node not in requests_calls and node.func.attr not in documented_attribute_calls:
                return False
            if any(
                keyword.arg in _REMOTE_CODE_KEYWORDS and not _remote_code_option_is_disabled(keyword.arg, keyword.value)
                for keyword in node.keywords
            ):
                return False
            if node.func.attr == "generate":
                if any(isinstance(argument, ast.Starred) for argument in node.args):
                    return False
                if not _generate_positional_remote_code_is_disabled(node.args):
                    return False
            for keyword in node.keywords:
                if keyword.arg is not None:
                    continue
                requires_proof = node.func.attr in {"from_pretrained", "generate"} or isinstance(
                    keyword.value,
                    ast.Dict,
                )
                if requires_proof and not remote_code_mapping_is_proven_safe_at_call(
                    keyword.value,
                    node,
                    proven_mapping_call_ids=proven_mapping_call_ids,
                    proven_mapping_binding_chains=proven_mapping_binding_chains,
                    proven_mapping_transfer_call_ids=proven_mapping_transfer_call_ids,
                ):
                    return False
            attribute_root = node.func.value
            while isinstance(attribute_root, (ast.Attribute, ast.Subscript, ast.Call)):
                if isinstance(attribute_root, ast.Call) and attribute_root in requests_calls:
                    return False
                attribute_root = attribute_root.func if isinstance(attribute_root, ast.Call) else attribute_root.value
            if isinstance(attribute_root, ast.Name) and attribute_root.id in (
                requests_response_names | documented_builtin_names
            ):
                return False
            if (
                node.func.attr == "open"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "Image"
                and not (
                    len(node.args) == 1
                    and isinstance(node.args[0], ast.Attribute)
                    and node.args[0].attr == "raw"
                    and node.args[0].value in requests_calls
                )
            ):
                return False
        if isinstance(node, ast.Call) and not isinstance(node.func, (ast.Attribute, ast.Name)):
            return False
        if isinstance(node, ast.Attribute) and (
            node.attr.startswith("_")
            or node.attr in {"eval", "exec", "load_library"}
            or (
                isinstance(node.value, ast.Name)
                and node.value.id == "torch"
                and node.attr in {"classes", "compile", "hub", "jit", "ops", "package", "serialization", "utils"}
            )
        ):
            return False
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in {"eval", "exec", "__import__"}
        ):
            return False
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id
            in {
                "eval",
                "exec",
                "globals",
                "locals",
                "setattr",
                "getattr",
                "delattr",
                "vars",
                "__import__",
                "__builtins__",
            }
        ):
            return False

    for call in requests_calls:
        if (
            len(call.args) != 1
            or len(call.keywords) != 1
            or any(
                keyword.arg != "stream"
                or not isinstance(keyword.value, ast.Constant)
                or keyword.value.value is not True
                for keyword in call.keywords
            )
        ):
            return False
        argument = call.args[0]
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            url = argument.value
        elif isinstance(argument, ast.Name):
            bindings = assignments.get(argument.id, [])
            if len(bindings) != 1 or bindings[0][0] >= call.lineno or bindings[0][1] is None:
                return False
            url = bindings[0][1]
        else:
            return False
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return False
        segments = parsed.path.split("/")
        if (
            parsed.scheme != "https"
            or parsed.hostname != "huggingface.co"
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.netloc.lower() != parsed.hostname
            or parsed.fragment
            or parsed.query not in {"", "download=true"}
            or "resolve" not in segments
            or any(segment in {".", ".."} for segment in segments)
            or not parsed.path.lower().endswith(_DOCUMENTED_IMAGE_SUFFIXES)
        ):
            return False
    return True


class NetworkCommDetector:
    """Detector for network communication patterns in model files."""

    # URL patterns - also match ftp, ftps, ssh, etc.
    URL_PATTERN = re.compile(
        rb"(?:https?|ftp|ftps|ssh|telnet|ws|wss)://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+", re.IGNORECASE
    )

    # Cloud storage URL patterns for detecting external resource references
    # These patterns detect references to cloud storage that could indicate
    # external dependencies or potential data exfiltration vectors
    CLOUD_STORAGE_PATTERNS: ClassVar[list[tuple[re.Pattern[bytes], str, str]]] = [
        # AWS S3
        (re.compile(rb"s3://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "AWS S3 URI", "s3"),
        (
            re.compile(rb"https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "AWS S3 URL",
            "s3",
        ),
        (
            re.compile(rb"https?://s3\.amazonaws\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "AWS S3 URL",
            "s3",
        ),
        (
            re.compile(rb"https?://s3\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "AWS S3 Regional URL",
            "s3",
        ),
        # Google Cloud Storage
        (re.compile(rb"gs://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "Google Cloud Storage URI", "gcs"),
        (
            re.compile(rb"https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "Google Cloud Storage URL",
            "gcs",
        ),
        (
            re.compile(rb"https?://storage\.cloud\.google\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "Google Cloud Storage URL",
            "gcs",
        ),
        # Azure Blob Storage
        (
            re.compile(rb"https?://[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "Azure Blob Storage URL",
            "azure",
        ),
        (re.compile(rb"az://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "Azure Storage URI", "azure"),
        (
            re.compile(
                rb"wasbs?://[^\s\"'<>@]+@[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE
            ),
            "Azure WASB URI",
            "azure",
        ),
        (
            re.compile(
                rb"abfss?://[^\s\"'<>@]+@[a-zA-Z0-9.\-_]+\.dfs\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE
            ),
            "Azure ADLS Gen2 URI",
            "azure",
        ),
        # Hugging Face Hub (external model references)
        (
            re.compile(rb"https?://huggingface\.co/[a-zA-Z0-9.\-_]+/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "HuggingFace Hub URL",
            "huggingface",
        ),
    ]

    # IP address patterns (v4 and v6)
    IPV4_PATTERN = _BARE_IPV4_PATTERN

    IPV6_PATTERN = re.compile(rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")

    # Domain patterns
    DOMAIN_PATTERN = _BARE_DOMAIN_PATTERN

    NETWORK_COMMAND_LINE_PREFIX = (
        rb"^[ \t]*(?:(?:[-*+>]|[0-9]{1,9}[.)])[ \t]+){0,8}"
        rb"(?:`{1,3}[ \t]*)?(?:(?:[$>#]|[A-Za-z0-9._-]+[$#>])[ \t]*)?"
    )
    NETWORK_COMMAND_LINE_LIMIT = rb"(?=[^\r\n]{1,8192}(?:\r?$))"
    NETWORK_COMMAND_PATH_PREFIX = rb"(?:/(?:usr/)?bin/)?(?:(?:busybox|toybox)(?:\.exe)?[ \t]+)?"
    NETWORK_COMMAND_TERMINATOR = rb"(?=[ \t]*(?:\r?$|[;&|<>#]))"
    NETWORK_COMMAND_HOST = (
        rb"(?:"
        + IPV4_PATTERN.pattern.removeprefix(rb"\b").removesuffix(rb"\b")
        + rb"|"
        + DOMAIN_PATTERN.pattern.removeprefix(rb"\b").removesuffix(rb"\b")
        + rb"|\[(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\])"
    )
    NETCAT_OPTION_ARGUMENT = rb"[^\s\"']+"
    NETCAT_OPTION_WITH_ARGUMENT = (
        rb"(?:-(?:I|M|O|P|R|T|V|W|X|Z|c|e|i|m|p|q|s|w|x)|"
        rb"--(?:append-output|delay|exec|hex-dump|idle-timeout|lua-exec|max-conns|max-rate|output|proxy|"
        rb"proxy-auth|proxy-type|sh-exec|source|source-port|ssl-alpn|ssl-ciphers|ssl-servername|"
        rb"ssl-trustfile|wait))"
    )
    NETCAT_OPTION_WITHOUT_ARGUMENT = (
        rb"(?:-[46bCDdFhklNnStUuvz]+|--(?:allow|broker|chat|keep-open|listen|no-shutdown|recv-only|send-only|ssl))"
    )
    NETCAT_OPTION = (
        rb"(?:"
        + NETCAT_OPTION_WITH_ARGUMENT
        + rb"(?:="
        + NETCAT_OPTION_ARGUMENT
        + rb"|[ \t]+"
        + NETCAT_OPTION_ARGUMENT
        + rb")|"
        + NETCAT_OPTION_WITHOUT_ARGUMENT
        + rb")"
    )
    NETCAT_COMMAND_PATTERN = re.compile(
        NETWORK_COMMAND_LINE_PREFIX + rb"(?P<command>" + NETWORK_COMMAND_PATH_PREFIX + rb"(?:nc|ncat|netcat)(?:\.exe)?)"
        rb"(?:[ \t]+" + NETCAT_OPTION + rb"){0,8}[ \t]+"
        rb"(?P<destination>" + NETWORK_COMMAND_HOST + rb")"
        rb"[ \t]+(?P<port>[0-9]{1,5})(?:[ \t]+" + NETCAT_OPTION + rb"){0,8}" + NETWORK_COMMAND_TERMINATOR,
        re.IGNORECASE | re.MULTILINE,
    )
    SSH_OPTION_WITH_ARGUMENT = rb"-(?:B|b|c|D|E|F|I|i|J|L|l|m|O|o|p|Q|R|S|W|w)(?:=|[ \t]+)?[^\s]{1,4096}"
    SSH_OPTION_WITHOUT_ARGUMENT = rb"-[46AaCfGgKkMNnqsTtVvXxYy]+"
    SSH_OPTION = rb"(?:" + SSH_OPTION_WITH_ARGUMENT + rb"|" + SSH_OPTION_WITHOUT_ARGUMENT + rb")"
    SSH_COMMAND_PATTERN = re.compile(
        NETWORK_COMMAND_LINE_PREFIX
        + rb"(?P<command>"
        + NETWORK_COMMAND_PATH_PREFIX
        + rb"ssh(?:\.exe)?)(?:[ \t]+"
        + SSH_OPTION
        + rb"){0,8}[ \t]+(?P<destination>(?:[A-Za-z0-9._-]+@)?"
        + NETWORK_COMMAND_HOST
        + rb")"
        + NETWORK_COMMAND_TERMINATOR,
        re.IGNORECASE | re.MULTILINE,
    )
    GIT_CLONE_OPTION_WITH_ARGUMENT = (
        rb"(?:-(?:b|c|j|o|u)|--(?:branch|config|depth|filter|jobs|origin|reference|reference-if-able|"
        rb"separate-git-dir|shallow-exclude|shallow-since|template|upload-pack))(?:=|[ \t]+)[^\s]{1,4096}"
    )
    GIT_CLONE_OPTION = (
        rb"(?:" + GIT_CLONE_OPTION_WITH_ARGUMENT + rb"|-[lnqsv]+|--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]{1,4096})?)"
    )
    GIT_CLONE_DESTINATION = (
        rb"(?:[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]{1,4096}|(?:[A-Za-z0-9._-]+@)?"
        + NETWORK_COMMAND_HOST
        + rb":[^\s\"'<>]{1,4096})"
    )
    GIT_CLONE_COMMAND_PATTERN = re.compile(
        NETWORK_COMMAND_LINE_PREFIX
        + NETWORK_COMMAND_LINE_LIMIT
        + rb"(?P<command>"
        + NETWORK_COMMAND_PATH_PREFIX
        + rb"git(?:\.exe)?)[ \t]+clone"
        rb"(?:[ \t]+" + GIT_CLONE_OPTION + rb"){0,8}[ \t]+(?:--[ \t]+)?"
        rb"(?P<destination>" + GIT_CLONE_DESTINATION + rb")"
        rb"(?:[ \t]+[^\s;&|#]{1,4096})?" + NETWORK_COMMAND_TERMINATOR,
        re.IGNORECASE | re.MULTILINE,
    )
    DOCKER_PULL_OPTION_WITH_ARGUMENT = rb"--(?:disable-content-trust|platform)(?:=|[ \t]+)[^\s]{1,4096}"
    DOCKER_PULL_OPTION = (
        rb"(?:" + DOCKER_PULL_OPTION_WITH_ARGUMENT + rb"|-[aq]+|--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]{1,4096})?)"
    )
    DOCKER_PULL_COMMAND_PATTERN = re.compile(
        NETWORK_COMMAND_LINE_PREFIX + rb"(?P<command>docker(?:\.exe)?)[ \t]+(?:image[ \t]+)?pull"
        rb"(?:[ \t]+" + DOCKER_PULL_OPTION + rb"){0,8}[ \t]+"
        rb"(?P<destination>"
        + DOMAIN_PATTERN.pattern.removeprefix(rb"\b").removesuffix(rb"\b")
        + rb"(?::[1-9][0-9]{0,3}|:[1-5][0-9]{4}|:6[0-4][0-9]{3}|:65[0-4][0-9]{2}|:655[0-2][0-9]|:6553[0-5])?"
        + rb"/[^\s\"'<>]{1,4096})"
        + NETWORK_COMMAND_TERMINATOR,
        re.IGNORECASE | re.MULTILINE,
    )

    # Network library imports
    NETWORK_LIBRARIES: ClassVar[list[bytes]] = [
        b"socket",
        b"urllib",
        b"requests",
        b"httplib",
        b"http.client",
        b"ftplib",
        b"telnetlib",
        b"smtplib",
        b"poplib",
        b"imaplib",
        b"paramiko",
        b"pycurl",
        b"aiohttp",
        b"tornado",
        b"twisted",
        b"httpx",
        b"websocket",
        b"websockets",
        b"grpc",
        b"zeromq",
        b"paho.mqtt",
        b"redis",
        b"pymongo",
        b"psycopg2",
        b"mysql.connector",
    ]
    NETWORK_LIBRARY_PATTERNS: ClassVar[dict[bytes, tuple[bytes, ...]]] = {
        lib: (b"import " + lib, b"from " + lib, lib + b".connect", lib + b".request", lib + b".__init__")
        for lib in NETWORK_LIBRARIES
    }

    # Network functions
    NETWORK_FUNCTIONS: ClassVar[list[bytes]] = [
        b"urlopen",
        b"urlretrieve",
        b"socket.connect",
        b"socket.create_connection",
        b"requests.get",
        b"requests.post",
        b"requests.put",
        b"requests.delete",
        b"http.request",
        b"ftp.connect",
        b"ssh.connect",
        b"telnet.open",
        b"smtp.connect",
        b"imap.login",
        b"redis.connect",
        b"mongo.connect",
        b"getaddrinfo",
        b"gethostbyname",
        b"gethostbyaddr",
        b"dns.resolver",
    ]

    # Known C&C patterns. Keep this list to high-signal indicators; ordinary
    # metadata keys like download_url or heartbeat are common in model cards.
    CC_PATTERNS: ClassVar[list[bytes]] = [
        b"beacon_url",
        b"callback_url",
        b"c2_server",
        b"command_server",
        b"exfil_endpoint",
        b"malware",
        b"backdoor",
        b"trojan",
        b"botnet",
        b"zombie",
        b"phone_home",
        b"check_in",
    ]

    # Suspicious ports
    SUSPICIOUS_PORTS: ClassVar[list[int]] = [
        22,  # SSH
        23,  # Telnet
        135,  # RPC
        139,  # NetBIOS
        445,  # SMB
        1337,  # Common backdoor
        1433,  # MSSQL
        1434,  # MSSQL Browser
        3128,  # Proxy
        3306,  # MySQL
        3389,  # RDP
        4444,  # Metasploit
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP Proxy
        8443,  # HTTPS Alt
        9200,  # Elasticsearch
        27017,  # MongoDB
        31337,  # Back Orifice
    ]

    # Precompile port patterns to avoid repeated compilation during scanning
    PORT_PATTERNS: ClassVar[dict[int, list[bytes]]] = {
        port: [
            f":{port}".encode(),
            f"port={port}".encode(),
            f"port {port}".encode(),
            f"PORT={port}".encode(),
        ]
        for port in SUSPICIOUS_PORTS
    }
    PORT_NAMES: ClassVar[dict[int, str]] = {
        22: "SSH",
        23: "Telnet",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        1337: "Common Backdoor",
        1433: "MSSQL",
        3128: "Proxy",
        3306: "MySQL",
        3389: "RDP",
        4444: "Metasploit",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
        31337: "Back Orifice",
    }

    EXPLICIT_PORT_PATTERNS: ClassVar[dict[int, list[re.Pattern]]] = {
        port: [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in [
                f"connect.*:{port}".encode(),
                f"socket.*port={port}".encode(),
                f"http://.*:{port}".encode(),
                f"https://.*:{port}".encode(),
                f"ssh.*:{port}".encode(),
                f"telnet.*:{port}".encode(),
            ]
        ]
        for port in SUSPICIOUS_PORTS
    }

    # Blacklisted domains - empty by default, should be configured by user
    # via config parameter if they have specific domains to block
    BLACKLISTED_DOMAINS: ClassVar[list[bytes]] = []

    INFORMATIONAL_DOMAIN_SUFFIXES: ClassVar[tuple[str, ...]] = (
        "huggingface.co",
        "amazonaws.com",
        "storage.googleapis.com",
        "storage.cloud.google.com",
        "blob.core.windows.net",
        "dfs.core.windows.net",
    )

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the detector with optional configuration."""
        self.config = config or {}
        self.findings: list[dict[str, Any]] = []
        configured_max_findings = self.config.get("max_findings")
        self.max_findings = (
            configured_max_findings
            if isinstance(configured_max_findings, int)
            and not isinstance(configured_max_findings, bool)
            and configured_max_findings > 0
            else None
        )
        self.findings_truncated = False
        self.truncated_finding_type: str | None = None
        self.truncated_finding: dict[str, Any] | None = None
        self._url_contexts: list[tuple[int, int, str]] = []
        self._url_context_starts: list[int] = []
        self._url_context_iterator: Iterator[tuple[int, int, str]] | None = None
        self._pending_url_context: tuple[int, int, str] | None = None
        self._url_context_scan_complete = False
        self._evidence_redaction_classifications = 0
        self._evidence_redaction_limit_reached = False
        self._cloud_nested_url_findings: set[str] = set()
        self._official_readme_image_fences: list[tuple[int, int, bool]] = []
        self._official_readme_image_unvalidated_requests = False

        # Clone class-level patterns to avoid cross-instance leakage
        self.cc_patterns: list[bytes] = self.CC_PATTERNS.copy()
        self.blacklisted_domains: list[bytes] = self.BLACKLISTED_DOMAINS.copy()

        def _to_lower_bytes(value: bytes | str) -> bytes:
            return value.lower() if isinstance(value, bytes) else value.encode().lower()

        # Add custom patterns from config, normalizing to lowercase bytes
        if "custom_cc_patterns" in self.config:
            self.cc_patterns.extend(_to_lower_bytes(p) for p in self.config["custom_cc_patterns"])
        if "custom_blacklist" in self.config:
            self.blacklisted_domains.extend(_to_lower_bytes(d) for d in self.config["custom_blacklist"])

    def scan(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan data for network communication patterns.

        Args:
            data: Binary data to scan
            context: Context information (e.g., filename)

        Returns:
            List of findings with details about detected patterns
        """
        self.findings = []
        self.findings_truncated = False
        self.truncated_finding_type = None
        self.truncated_finding = None
        self._evidence_redaction_classifications = 0
        self._evidence_redaction_limit_reached = False
        self._cloud_nested_url_findings = set()
        (
            self._official_readme_image_fences,
            self._official_readme_image_unvalidated_requests,
        ) = _index_official_readme_sample_image_fences(data, context)
        if self.max_findings is None:
            self._url_contexts = self._index_url_contexts(data)
            self._url_context_starts = [start for start, _end, _url in self._url_contexts]
            self._url_context_iterator = None
            self._url_context_scan_complete = True
        else:
            self._url_contexts = []
            self._url_context_starts = []
            self._url_context_iterator = self._iter_url_contexts(data)
            self._url_context_scan_complete = False
        self._pending_url_context = None

        scanners = (
            (
                self._check_blacklist,
                self._scan_cc_patterns,
                self._scan_network_commands,
                self._scan_network_functions,
                self._scan_network_libraries,
                self._scan_suspicious_ports,
                self._scan_cloud_storage_urls,
                self._scan_urls,
                self._scan_ip_addresses,
                self._scan_domains,
            )
            if self.max_findings is not None
            else (
                self._scan_network_commands,
                self._scan_urls,
                self._scan_cloud_storage_urls,
                self._scan_ip_addresses,
                self._scan_domains,
                self._scan_network_libraries,
                self._scan_network_functions,
                self._scan_cc_patterns,
                self._scan_suspicious_ports,
                self._check_blacklist,
            )
        )
        for scanner in scanners:
            scanner(data, context)
            if self.findings_truncated:
                break

        if self.findings_truncated:
            self.findings.append(
                {
                    "type": "detector_finding_limit",
                    "detector": "network_communication",
                    "severity": "INFO",
                    "message": "Network communication findings exceeded the configured reporting limit",
                    "max_findings": self.max_findings,
                    "truncated_finding_type": self.truncated_finding_type,
                    "truncated_finding": self.truncated_finding,
                    "analysis_incomplete": True,
                    "context": context,
                    **(
                        {
                            "redaction_analysis_incomplete": True,
                            "max_classifications": _MAX_EVIDENCE_REDACTION_CLASSIFICATIONS,
                        }
                        if self._evidence_redaction_limit_reached
                        else {}
                    ),
                }
            )
        elif self._evidence_redaction_limit_reached:
            self.findings.append(
                {
                    "type": "detector_finding_limit",
                    "detector": "network_communication",
                    "severity": "INFO",
                    "message": "Network endpoint redaction classification exceeded the safe work limit",
                    "max_classifications": _MAX_EVIDENCE_REDACTION_CLASSIFICATIONS,
                    "truncated_finding_type": "endpoint_redaction_classification",
                    "truncated_finding": None,
                    "analysis_incomplete": True,
                    "context": context,
                }
            )

        return self.findings

    def _record_finding(self, finding: dict[str, Any]) -> bool:
        if self.max_findings is not None and len(self.findings) >= self.max_findings:
            self.findings_truncated = True
            finding_type = finding.get("type")
            self.truncated_finding_type = finding_type if isinstance(finding_type, str) else None
            self.truncated_finding = dict(finding)
            return False
        self.findings.append(finding)
        return True

    def _index_url_contexts(self, data: bytes) -> list[tuple[int, int, str]]:
        return list(self._iter_url_contexts(data))

    @staticmethod
    def _iter_url_contexts(data: bytes) -> Iterator[tuple[int, int, str]]:
        for match in _URL_IN_BYTES_PATTERN.finditer(data):
            url = _trim_matched_source_url(data, match)
            yield match.start(), match.start() + len(url.encode("utf-8")), url

    @classmethod
    def _iter_generic_url_contexts(cls, data: bytes) -> Iterator[tuple[int, int, str]]:
        """Yield only schemes handled by generic URL findings."""
        for match in cls.URL_PATTERN.finditer(data):
            url = _trim_matched_source_url(data, match)
            yield match.start(), match.start() + len(url.encode("utf-8")), url

    def _is_redacted_url_value(self, data: bytes, match_start: int, value: str) -> bool:
        if self.max_findings is not None:
            local_uri_context = _url_text_bounds_containing_offset(data, match_start)
            if local_uri_context is None:
                local_uri_context = _uri_text_bounds_containing_offset(data, match_start, _URI_IN_BYTES_PATTERN)
            if local_uri_context is not None:
                url, url_start = local_uri_context
                if _is_match_redacted_from_url_context(url, url_start, match_start, value):
                    return True

            if _bounded_url_lookup_starts_mid_token(data, match_start):
                lazy_url_context = self._lazy_url_context_containing(match_start)
                if lazy_url_context is not None:
                    url_start, _url_end, url = lazy_url_context
                    if _is_match_redacted_from_url_context(url, url_start, match_start, value):
                        return True
            return _is_split_sensitive_url_value(data, match_start) or self._is_redacted_evidence_value(
                data, match_start, value
            )
        context_index = bisect_right(self._url_context_starts, match_start) - 1
        if context_index >= 0:
            url_start, url_end, url = self._url_contexts[context_index]
            if match_start < url_end:
                return _is_match_redacted_from_url_context(url, url_start, match_start, value)
        return (
            _is_match_redacted_from_url(data, match_start, value)
            or _is_split_sensitive_url_value(data, match_start)
            or self._is_redacted_evidence_value(data, match_start, value)
        )

    def _is_redacted_evidence_value(self, data: bytes, match_start: int, value: str) -> bool:
        """Bound expensive shared-redactor classifications and fail closed on exhaustion."""
        direct_decision = _direct_evidence_redaction_decision(data, match_start)
        if direct_decision is not None:
            return direct_decision
        before = max(0, match_start - _MAX_URL_TEXT_LOOKUP_BYTES)
        match_end = match_start + len(value.encode("utf-8"))
        after = min(len(data), match_end + _MAX_URL_TEXT_LOOKUP_BYTES)
        if _SENSITIVE_EVIDENCE_HINT_PATTERN.search(data[before:after]) is None:
            return False
        if self._evidence_redaction_classifications >= _MAX_EVIDENCE_REDACTION_CLASSIFICATIONS:
            self._evidence_redaction_limit_reached = True
            return True
        self._evidence_redaction_classifications += 1
        return _is_redacted_evidence_value(data, match_start, value)

    def _lazy_url_context_containing(self, match_start: int) -> tuple[int, int, str] | None:
        """Advance the bounded lazy URL index only far enough to classify one match."""
        context_index = bisect_right(self._url_context_starts, match_start) - 1
        if context_index >= 0:
            cached = self._url_contexts[context_index]
            if match_start < cached[1]:
                return cached

        while not self._url_context_scan_complete:
            if self._pending_url_context is None:
                if self._url_context_iterator is None:
                    self._url_context_scan_complete = True
                    break
                try:
                    self._pending_url_context = next(self._url_context_iterator)
                except StopIteration:
                    self._url_context_iterator = None
                    self._url_context_scan_complete = True
                    break

            context = self._pending_url_context
            if context[0] > match_start:
                break
            _start, _end, url = context
            cache_limit = (self.max_findings or 0) + 1
            recordable_url = self.URL_PATTERN.fullmatch(url.encode("utf-8")) is not None or any(
                _decoded_nested_urls(url)
            )
            contains_match = match_start < context[1]
            context_cached = False
            if (recordable_url or contains_match) and len(self._url_contexts) < cache_limit:
                self._url_contexts.append(context)
                self._url_context_starts.append(context[0])
                context_cached = True
            if contains_match:
                if context_cached:
                    self._pending_url_context = None
                return context
            self._pending_url_context = None
        return None

    def _iter_indexed_url_contexts(self) -> Iterator[tuple[int, int, str]]:
        """Yield cached URL contexts followed by the remaining lazy index."""
        yield from self._url_contexts
        while not self._url_context_scan_complete:
            if self._pending_url_context is None:
                if self._url_context_iterator is None:
                    self._url_context_scan_complete = True
                    return
                try:
                    self._pending_url_context = next(self._url_context_iterator)
                except StopIteration:
                    self._url_context_iterator = None
                    self._url_context_scan_complete = True
                    return

            context = self._pending_url_context
            self._pending_url_context = None
            self._url_contexts.append(context)
            self._url_context_starts.append(context[0])
            yield context

    def _scan_network_commands(self, data: bytes, context: str) -> None:
        """Scan for explicit network client commands with concrete destinations."""
        for match in self.NETCAT_COMMAND_PATTERN.finditer(data):
            port = int(match.group("port"))
            if not 1 <= port <= 65535:
                continue
            command = match.group("command").decode("utf-8", errors="ignore")
            destination = match.group("destination").decode("utf-8", errors="ignore")
            if ":" in destination:
                try:
                    ipaddress.ip_address(destination.removeprefix("[").removesuffix("]"))
                except ValueError:
                    continue
            if not self._record_finding(
                {
                    "type": "network_command",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "message": f"Netcat network command detected: {destination}:{port}",
                    "command": command,
                    "destination": destination,
                    "port": port,
                    "position": match.start("destination"),
                    "context": context,
                }
            ):
                return
        for command_type, pattern in (
            ("SSH", self.SSH_COMMAND_PATTERN),
            ("Git clone", self.GIT_CLONE_COMMAND_PATTERN),
            ("Docker pull", self.DOCKER_PULL_COMMAND_PATTERN),
        ):
            for match in pattern.finditer(data):
                command = match.group("command").decode("utf-8", errors="ignore")
                destination = match.group("destination").decode("utf-8", errors="ignore")
                safe_destination = redact_url_for_finding(destination) if "://" in destination else destination
                if not self._record_finding(
                    {
                        "type": "network_command",
                        "severity": "HIGH",
                        "confidence": 0.9,
                        "message": f"{command_type} network command detected: {safe_destination}",
                        "command": command,
                        "command_type": command_type.casefold().replace(" ", "_"),
                        "destination": safe_destination,
                        "position": match.start("destination"),
                        "context": context,
                    }
                ):
                    return

    def _scan_urls(self, data: bytes, context: str) -> None:
        """Scan for URL patterns."""
        url_contexts = iter(self._url_contexts) if self.max_findings is None else self._iter_generic_url_contexts(data)
        seen_cloud_urls: set[str] = set()
        for url_start, _url_end, url in url_contexts:
            if self.max_findings is not None:
                is_cloud_url = self._is_cloud_storage_url(url)
                if is_cloud_url and url in seen_cloud_urls:
                    continue
                if is_cloud_url:
                    seen_cloud_urls.add(url)
                for nested_url in _decoded_nested_urls(url):
                    if nested_url in self._cloud_nested_url_findings:
                        continue
                    if not self._record_url_finding(nested_url, url_start, context):
                        return
                    self._cloud_nested_url_findings.add(nested_url)
            if self.URL_PATTERN.fullmatch(url.encode("utf-8")) is not None and not self._record_url_finding(
                url, url_start, context
            ):
                return
            if self.max_findings is None:
                for nested_url in _decoded_nested_urls(url):
                    if not self._record_url_finding(nested_url, url_start, context):
                        return

    def _record_url_finding(self, url: str, position: int, context: str) -> bool:
        safe_url = redact_url_for_finding(url)

        confidence = 0.5
        severity = "MEDIUM"
        if any(pattern in url.lower() for pattern in ["eval", "exec", "cmd", "shell"]):
            confidence = 0.9
            severity = "HIGH"
        elif self._url_uses_suspicious_port(url):
            confidence = 0.8
            severity = "HIGH"
        elif "://" in url and not url.startswith(("http://", "https://")):
            confidence = 0.7
        elif self._is_cloud_storage_url(url):
            severity = "INFO"

        return self._record_finding(
            {
                "type": "url_detected",
                "severity": severity,
                "confidence": confidence,
                "message": f"URL detected in model: {safe_url[:100]}",
                "url": safe_url,
                "position": position,
                "context": context,
            }
        )

    def _url_uses_suspicious_port(self, url: str) -> bool:
        with suppress(ValueError):
            return urlsplit(url).port in self.SUSPICIOUS_PORTS
        return False

    def _scan_cloud_storage_urls(self, data: bytes, context: str) -> None:
        """Scan for cloud storage URL patterns (S3, GCS, Azure, etc.).

        These patterns detect references to external cloud storage that could indicate:
        - External model dependencies
        - Potential data exfiltration vectors
        - Supply chain risks from external resources
        """
        seen_urls: set[str] = set()

        for pattern, description, provider in self.CLOUD_STORAGE_PATTERNS:
            for match in pattern.finditer(data):
                url = match.group().decode("utf-8", errors="ignore")

                # Skip duplicate wrappers before their nested destinations consume the budget.
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                if self.max_findings is not None:
                    for nested_url in _decoded_nested_urls(url):
                        if nested_url in self._cloud_nested_url_findings:
                            continue
                        if not self._record_url_finding(nested_url, match.start(), context):
                            return
                        self._cloud_nested_url_findings.add(nested_url)

                safe_url = redact_url_for_finding(url)

                # Determine severity based on context
                # INFO for HuggingFace (common and usually legitimate)
                # INFO for other cloud URLs (informational - may be legitimate)
                severity = "INFO"
                confidence = 0.9  # High confidence - pattern is specific

                # Check for suspicious indicators that might elevate severity
                url_lower = url.lower()
                suspicious_indicators = ["malware", "exploit", "hack", "evil", "backdoor", "exfil"]
                if any(indicator in url_lower for indicator in suspicious_indicators):
                    severity = "WARNING"
                    confidence = 0.95

                if not self._record_finding(
                    {
                        "type": "cloud_storage_url",
                        "severity": severity,
                        "confidence": confidence,
                        "message": f"{description} detected: {safe_url[:150]}",
                        "url": safe_url,
                        "provider": provider,
                        "description": description,
                        "position": match.start(),
                        "context": context,
                    }
                ):
                    return

    def _scan_ip_addresses(self, data: bytes, context: str) -> None:
        """Scan for IP address patterns."""
        # IPv4
        for match in self.IPV4_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")

            if self._is_redacted_url_value(data, match.start(), ip):
                continue

            # Check for common false positives (version numbers) only when the
            # matched token itself is the version literal.
            start = max(0, match.start() - 20)
            end = min(len(data), match.end() + 20)
            surrounding_bytes = data[start:end]
            surrounding = surrounding_bytes.decode("utf-8", errors="ignore").lower()

            if _is_version_literal_context(surrounding_bytes, match.group()):
                continue

            # Skip if surrounded by quotes and has typical version patterns
            if '"' + ip + '"' in surrounding or "'" + ip + "'" in surrounding:
                parts = ip.split(".")
                # Version numbers typically have small numbers
                if all(int(p) < 100 for p in parts):
                    continue

            # Skip patterns that look like array indices or numeric data
            # e.g., [1.0, 2.0, 3.0, 4.0] or similar
            if (("[" in surrounding and "]" in surrounding) or ("{" in surrounding and "}" in surrounding)) and (
                ".0" in surrounding or "float" in surrounding or "weight" in surrounding or "bias" in surrounding
            ):
                continue

            # Validate it's a real IP
            with suppress(ipaddress.AddressValueError):
                ip_obj = ipaddress.IPv4Address(ip)

                # Check if it's private/reserved
                confidence = 0.4
                if ip_obj.is_private:
                    confidence = 0.3  # Lower confidence for private IPs
                elif ip_obj.is_global:
                    confidence = 0.7  # Higher for public IPs

                if not self._record_finding(
                    {
                        "type": "ipv4_address",
                        "severity": "MEDIUM",
                        "confidence": confidence,
                        "message": f"IPv4 address detected: {ip}",
                        "ip": ip,
                        "is_private": ip_obj.is_private,
                        "is_global": ip_obj.is_global,
                        "position": match.start(),
                        "context": context,
                    }
                ):
                    return

        # IPv6
        for match in self.IPV6_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")
            if self._is_redacted_url_value(data, match.start(), ip):
                continue
            with suppress(ipaddress.AddressValueError):
                ip6_obj = ipaddress.IPv6Address(ip)

                if not self._record_finding(
                    {
                        "type": "ipv6_address",
                        "severity": "MEDIUM",
                        "confidence": 0.6,
                        "message": f"IPv6 address detected: {ip}",
                        "ip": ip,
                        "is_private": ip6_obj.is_private,
                        "is_global": ip6_obj.is_global,
                        "position": match.start(),
                        "context": context,
                    }
                ):
                    return

    def _scan_domains(self, data: bytes, context: str) -> None:
        """Scan for domain name patterns."""
        seen_domains = set()

        # Skip domain detection in binary ML model files to avoid false positives
        # Binary weights can randomly match domain patterns
        if context and any(ext in context.lower() for ext in [".bin", ".pt", ".pth", ".ckpt", ".h5", ".pb", ".onnx"]):
            # For ML model files, only look for very explicit domain references
            # that are unlikely to occur randomly
            explicit_domain_patterns = [
                rb"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}",  # Full URLs only
                # Config-like patterns
                rb'["\'](?:api|webhook|callback|endpoint)["\']:\s*["\'][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}',
            ]

            for pattern in explicit_domain_patterns:
                for match in re.finditer(pattern, data, re.IGNORECASE):
                    domain_match = match.group()
                    if b"://" in domain_match:
                        # Extract domain from URL
                        parts = domain_match.split(b"://", 1)[1].split(b"/")[0]
                        domain = parts.decode("utf-8", errors="ignore").lower()
                    else:
                        domain = match.group().decode("utf-8", errors="ignore").lower()

                    if domain not in seen_domains:
                        if self._is_redacted_url_value(data, match.start(), domain):
                            continue
                        seen_domains.add(domain)
                        severity = "INFO" if self._is_informational_domain(domain) else "MEDIUM"
                        confidence = 0.3 if severity == "INFO" else 0.8
                        if not self._record_finding(
                            {
                                "type": "domain",
                                "severity": severity,
                                "confidence": confidence,
                                "message": f"Domain name detected: {domain}",
                                "domain": domain,
                                "position": match.start(),
                                "context": context,
                            }
                        ):
                            return
            return

        for match in self.DOMAIN_PATTERN.finditer(data):
            if _match_starts_inside_percent_escape(data, match.start()):
                continue
            domain = match.group().decode("utf-8", errors="ignore").lower()

            # Skip common false positives
            if domain in seen_domains:
                continue
            if self._is_redacted_url_value(data, match.start(), domain):
                continue
            if domain.endswith((".pkl", ".pt", ".h5", ".pb", ".onnx", ".json")):
                continue  # File extensions
            if domain in ["numpy.org", "pytorch.org", "tensorflow.org"]:
                continue  # ML framework domains

            # Skip actual layer-name grammar (e.g., layer1.weight), not any
            # attacker-controlled DNS name that happens to contain ML words.
            if _ML_LAYER_DOMAIN_PATTERN.fullmatch(domain):
                continue
            # Bare method calls such as weight.to(device) are code tokens, not DNS names.
            if _has_call_syntax(data, match.start(), len(match.group())):
                continue

            # Skip very short domain names in binary files (likely false positives)
            # e.g., "8.to", "9.cc" are probably random bytes, not real domains
            domain_parts = domain.split(".")
            if len(domain_parts) < 2:
                continue

            # Skip single character subdomains with short TLDs (common false positive in binary data)
            if len(domain_parts) == 2 and len(domain_parts[0]) <= 2 and len(domain_parts[1]) <= 2:
                continue  # Skip patterns like "8.to", "h8.cc", etc.
            tld = domain_parts[-1]
            # Common TLDs (not exhaustive, but covers most)
            valid_tlds = [
                "com",
                "org",
                "net",
                "edu",
                "gov",
                "mil",
                "int",
                "io",
                "co",
                "uk",
                "de",
                "fr",
                "jp",
                "cn",
                "au",
                "us",
                "ru",
                "ch",
                "it",
                "nl",
                "se",
                "no",
                "es",
                "ca",
                "tk",
                "ml",
                "ga",
                "cf",
                "cc",
                "to",
                "pw",
                "ai",
                "app",
                "dev",
                "example",
                "xyz",
            ]
            if tld not in valid_tlds:
                continue

            seen_domains.add(domain)

            # Check TLD for suspicious domains
            suspicious_tlds = ["tk", "ml", "ga", "cf", "cc", "to", "pw"]

            confidence = 0.3
            if tld in suspicious_tlds:
                confidence = 0.7
            if any(sus in domain for sus in ["malware", "evil", "hack", "exploit"]):
                confidence = 0.9

            if confidence > 0.2:  # Only report domains with reasonable confidence
                severity = "INFO" if self._is_informational_domain(domain) else "MEDIUM"
                if confidence >= 0.7:
                    severity = "HIGH"
                if not self._record_finding(
                    {
                        "type": "domain_name",
                        "severity": severity,
                        "confidence": confidence,
                        "message": f"Domain name detected: {domain}",
                        "domain": domain,
                        "tld": tld,
                        "position": match.start(),
                        "context": context,
                    }
                ):
                    return

    @classmethod
    def _is_cloud_storage_url(cls, url: str) -> bool:
        """Return whether a URL is already covered by specific informational cloud URL detection."""
        url_bytes = url.encode()
        return any(pattern.fullmatch(url_bytes) for pattern, _, _ in cls.CLOUD_STORAGE_PATTERNS)

    @classmethod
    def _is_informational_domain(cls, domain: str) -> bool:
        """Return whether a generic domain hit is covered by informational model/cloud URL handling."""
        return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in cls.INFORMATIONAL_DOMAIN_SUFFIXES)

    def _scan_network_libraries(self, data: bytes, context: str) -> None:
        """Scan for network library imports."""
        for lib in self.NETWORK_LIBRARIES:
            for pattern in self.NETWORK_LIBRARY_PATTERNS[lib]:
                for match_index in _iter_pattern_matches(data, pattern):
                    if _is_doc_only_network_reference(
                        data,
                        match_index=match_index,
                        token_len=len(pattern),
                        context=context,
                        requires_call=not pattern.startswith((b"import ", b"from ")),
                    ) or (
                        lib == b"requests"
                        and not self._official_readme_image_unvalidated_requests
                        and _is_official_readme_sample_image_request(
                            data,
                            match_index=match_index,
                            context=context,
                            fence_cache=self._official_readme_image_fences,
                            preindexed=True,
                        )
                    ):
                        continue

                    confidence = 0.7
                    severity = "HIGH"

                    # Some libraries are more suspicious than others
                    if lib in [b"socket", b"paramiko", b"pycurl"]:
                        confidence = 0.8
                        severity = "CRITICAL"

                    if not self._record_finding(
                        {
                            "type": "network_library",
                            "severity": severity,
                            "confidence": confidence,
                            "message": f"Network library detected: {lib.decode()}",
                            "library": lib.decode(),
                            "pattern": pattern.decode("utf-8", errors="ignore"),
                            "position": match_index,
                            "context": context,
                        }
                    ):
                        return
                    break  # One finding per library
                else:
                    continue
                break

    def _scan_network_functions(self, data: bytes, context: str) -> None:
        """Scan for network function calls."""
        for func in self.NETWORK_FUNCTIONS:
            for idx in _iter_pattern_matches(data, func):
                if _is_doc_only_network_reference(
                    data,
                    match_index=idx,
                    token_len=len(func),
                    context=context,
                    requires_call=True,
                ) or (
                    func == b"requests.get"
                    and _is_official_readme_sample_image_request(
                        data,
                        match_index=idx,
                        context=context,
                        fence_cache=self._official_readme_image_fences,
                        preindexed=True,
                    )
                ):
                    continue

                # Try to get some context around the function call
                snippet = _redacted_snippet_for_match(data, idx, idx + len(func), before=50, after=100)

                confidence = 0.6
                severity = "HIGH"

                # Higher confidence for certain functions
                if b"socket.connect" in func or b"requests." in func:
                    confidence = 0.8
                    severity = "CRITICAL"

                if not self._record_finding(
                    {
                        "type": "network_function",
                        "severity": severity,
                        "confidence": confidence,
                        "message": f"Network function call detected: {func.decode()}",
                        "function": func.decode(),
                        "snippet": snippet,
                        "position": idx,
                        "context": context,
                    }
                ):
                    return
                break

    def _scan_cc_patterns(self, data: bytes, context: str) -> None:
        """Scan for command & control patterns."""
        lowered_data = data.lower()
        for pattern in self.cc_patterns:
            idx = lowered_data.find(pattern)
            if idx < 0:
                continue

            snippet = _redacted_snippet_for_match(data, idx, idx + len(pattern), before=30, after=30)

            confidence = 0.8
            severity = "CRITICAL"

            # Very suspicious patterns
            if pattern in [b"malware", b"backdoor", b"trojan", b"botnet"]:
                confidence = 0.95

            if not self._record_finding(
                {
                    "type": "cc_pattern",
                    "severity": severity,
                    "confidence": confidence,
                    "message": f"C&C pattern detected: {pattern.decode()}",
                    "pattern": pattern.decode(),
                    "snippet": snippet,
                    "position": idx,
                    "context": context,
                }
            ):
                return

    def _scan_suspicious_ports(self, data: bytes, context: str) -> None:
        """Scan for references to suspicious ports."""
        ml_extensions = [
            ".bin",
            ".pt",
            ".pth",
            ".ckpt",
            ".h5",
            ".pb",
            ".onnx",
            ".safetensors",
            ".pkl",
            ".pickle",
            ".joblib",
        ]
        is_ml_model = context and any(ext in context.lower() for ext in ml_extensions)

        # For ML models, we need to be much more conservative to avoid false positives
        # Binary model weights can contain random byte sequences that match port patterns
        if is_ml_model:
            # Only scan for very explicit network patterns in ML models
            # Skip port scanning for pure binary model files to avoid false positives
            self._scan_explicit_network_patterns_in_ml_models(data, context)
            return

        # For non-ML files, use the original port detection logic
        for port in self.SUSPICIOUS_PORTS:
            port_bytes = str(port).encode()
            matched = False
            for pattern_bytes in self.PORT_PATTERNS[port]:
                for pattern_start in _iter_pattern_matches(data, pattern_bytes):
                    port_start = pattern_start + pattern_bytes.rfind(port_bytes)
                    if self._is_redacted_url_value(data, port_start, str(port)):
                        continue
                    matched = True
                    break
                if matched:
                    break
            if matched:
                port_name = self._get_port_name(port)
                if not self._record_finding(
                    {
                        "type": "suspicious_port",
                        "severity": "MEDIUM",
                        "confidence": 0.6,
                        "message": f"Suspicious port detected: {port} ({port_name})",
                        "port": port,
                        "service": port_name,
                        "context": context,
                    }
                ):
                    return

    def _scan_explicit_network_patterns_in_ml_models(self, data: bytes, context: str) -> None:
        """Scan for very explicit network patterns in ML models with high confidence."""
        # Only look for very explicit network communication patterns that are unlikely
        # to occur in legitimate model weights. These patterns require clear context.

        explicit_network_patterns = [
            # Very explicit URL patterns that are unlikely in model weights
            (rb"https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+", "url"),
            # Explicit socket connection patterns with clear text context
            (rb'socket\.connect\s*\(\s*["\']?[a-zA-Z0-9.-]+["\']?\s*,\s*\d+', "socket_connection"),
            # Clear HTTP request patterns
            (rb"(GET|POST|PUT|DELETE)\s+\/[^\s]*\s+HTTP\/1\.[01]", "http_request"),
            # Explicit network library imports in clear text
            (rb"import\s+(socket|urllib|requests|httplib)", "network_import"),
        ]

        for pattern, pattern_type in explicit_network_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = regex.finditer(data)

            for match in matches:
                if pattern_type == "network_import" and _is_doc_only_network_reference(
                    data,
                    match_index=match.start(),
                    token_len=len(match.group()),
                    context=context,
                    requires_call=False,
                ):
                    continue

                # Get context around the match to validate it's not in binary weights
                start_pos = max(0, match.start() - 100)
                end_pos = min(len(data), match.end() + 100)
                context_data = data[start_pos:end_pos]

                # Check if this looks like legitimate text (not binary weights)
                try:
                    context_str = context_data.decode("utf-8", errors="strict")
                    printable_ratio = sum(c.isprintable() for c in context_str) / len(context_str)
                except UnicodeDecodeError:
                    printable_ratio = sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in context_data) / len(
                        context_data
                    )

                if printable_ratio <= 0.7:
                    continue
                raw_matched_text = (
                    _trim_matched_source_url(data, match)
                    if pattern_type == "url"
                    else match.group().decode("utf-8", errors="ignore")
                )
                matched_text = _redact_network_evidence(raw_matched_text)
                if not self._record_finding(
                    {
                        "type": "explicit_network_pattern",
                        "severity": "CRITICAL",
                        "confidence": 0.95,
                        "message": f"Explicit network pattern in ML model: {matched_text[:100]}",
                        "pattern_type": pattern_type,
                        "matched_text": matched_text[:200],
                        "position": match.start(),
                        "context": context,
                    }
                ):
                    return

    def _check_blacklist(self, data: bytes, context: str) -> None:
        """Check against blacklisted domains/IPs."""
        if not self.blacklisted_domains:
            return

        lowered_data = data.lower()
        for blacklisted in self.blacklisted_domains:
            if blacklisted in lowered_data and not self._record_finding(
                {
                    "type": "blacklisted_domain",
                    "severity": "CRITICAL",
                    "confidence": 1.0,
                    "message": f"Blacklisted domain detected: {blacklisted.decode()}",
                    "domain": blacklisted.decode(),
                    "context": context,
                }
            ):
                return

    def _get_port_name(self, port: int) -> str:
        """Get common service name for a port."""
        return self.PORT_NAMES.get(port, "Unknown")


def detect_network_communication(file_path: str, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Convenience function to scan a file for network communication patterns.

    Args:
        file_path: Path to the file to scan
        config: Optional configuration dictionary

    Returns:
        List of findings
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        detector = NetworkCommDetector(config)
        return detector.scan(data, context=file_path)

    except FileNotFoundError:
        return [{"type": "error", "severity": "ERROR", "message": f"File not found: {file_path}"}]
    except Exception as e:
        return [{"type": "error", "severity": "ERROR", "message": f"Error scanning file: {e!s}"}]
