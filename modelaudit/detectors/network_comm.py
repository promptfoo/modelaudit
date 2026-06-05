"""Network Communication Detection for ML models.

This module detects potential network communication capabilities in model files
that could be used for data exfiltration or command & control operations.
"""

import ipaddress
import math
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Iterator
from contextlib import suppress
from typing import Any, ClassVar
from urllib.parse import unquote, urlsplit, urlunsplit

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
_PATH_TOKEN_BOUNDARY_PATTERN = re.compile(r"&amp;|[&,'\"?#\s]")
_MATRIX_PARAMETER_SEPARATOR_PATTERN = re.compile(r"(?<!&amp);", re.IGNORECASE)
_URL_COMPONENT_SEPARATOR_PATTERN = re.compile(r"&amp;|[&;]", re.IGNORECASE)
_AUTHORIZATION_SCHEME_PATTERN = re.compile(r"[a-z][a-z0-9!#$%&'*+.^_`|~-]*", re.IGNORECASE)
_SENSITIVE_EVIDENCE_HINT_PATTERN = re.compile(
    rb"(?:api[_-]?key|auth(?:orization)?|credential|password|passwd|proxy[_-]?authorization|pwd|secret|token)"
    rb"(?![_-](?:cache|count|hint)\b)",
    re.IGNORECASE,
)
_EVIDENCE_MATCH_START_MARKER = "__MODELAUDIT_ENDPOINT_MATCH_START__"
_EVIDENCE_MATCH_END_MARKER = "__MODELAUDIT_ENDPOINT_MATCH_END__"
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
            redact_next_value = authorization_value_pending and _authorization_scheme_has_payload(
                token_candidate, following_value
            )
            authorization_value_pending = False
            changed = True
            continue

        if _is_sensitive_path_key(token_candidate):
            redact_next_value = True
            authorization_value_pending = _is_authorization_path_key(token_candidate)
            continue

        redacted_part, part_changed = _redact_boundary_component(part)
        if part_changed:
            parts[index] = redacted_part
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
                and _authorization_scheme_has_payload(token_component, following_value)
            )
            authorization_value_pending = False
        else:
            redacted_component, component_changed = _redact_boundary_component(component)
            if component and _is_sensitive_path_key(token_component) and carries_sensitive_value(following_boundary):
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
    parts = [part for part in re.split(r"[._\[\]]+", normalized) if part]
    return any(
        _SENSITIVE_PATH_KEY_PATTERN.fullmatch("_".join(parts[index:])) is not None for index in range(len(parts))
    )


def _is_authorization_path_key(key: str) -> bool:
    decoded = _decode_path_token(key).strip()
    if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
        return False
    normalized = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", decoded)
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized).replace("-", "_")
    parts = [part.lower() for part in re.split(r"[._\[\]]+", normalized) if part]
    return any(
        "_".join(parts[index:]) in {"auth", "authorization", "proxy_authorization"} for index in range(len(parts))
    )


def _authorization_scheme_has_payload(scheme: str, following_value: str | None) -> bool:
    if following_value is None or _AUTHORIZATION_SCHEME_PATTERN.fullmatch(scheme) is None:
        return False
    return not _looks_like_known_artifact_filename(following_value)


def _compound_path_segment_ends_with_sensitive_key(segment: str) -> bool:
    """Return whether a compound segment leaves a credential key awaiting its value."""
    parts = [part for part in re.split(r"(?i)&amp;|[/,:;&]", segment) if part]
    return len(parts) > 1 and _is_sensitive_path_key(parts[-1])


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


def _redact_hostname_tokens(hostname: str) -> str:
    with suppress(ValueError):
        ipaddress.ip_address(hostname)
        return hostname

    labels = hostname.split(".")
    redact_next_value = False
    authorization_value_pending = False
    for index, label in enumerate(labels):
        decoded = _decode_path_token(label)
        if redact_next_value:
            labels[index] = _REDACTED_PATH_TOKEN
            following_value = next((candidate for candidate in labels[index + 1 :] if candidate), None)
            redact_next_value = authorization_value_pending and _authorization_scheme_has_payload(
                decoded, following_value
            )
            authorization_value_pending = False
            continue
        if decoded == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
            labels[index] = _REDACTED_PATH_TOKEN
            redact_next_value = len(labels) - index >= 4
            continue
        if _is_sensitive_path_key(decoded) and len(labels) - index >= 4:
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
            redact_next_value = authorization_value_pending and _authorization_scheme_has_payload(
                _token_candidate, following_value
            )
            authorization_value_pending = False
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
    return chr(data[url_start - 1])


def _trim_source_literal_url(url: str, source_quote: str | None = None) -> str:
    """Remove a closing quote only when the URL came from that source literal."""
    if source_quote != "'":
        return url

    authority_start = url.find("://") + 3
    authority_end = len(url)
    if authority_start >= 3:
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


def _bounded_url_start_before_match(data: bytes, match_start: int, scan_start: int) -> int | None:
    scheme_marker = data.rfind(b"://", scan_start, match_start)
    if scheme_marker < 0:
        return None

    url_start = scheme_marker
    while url_start > scan_start and data[url_start - 1] not in _URL_TEXT_BOUNDARY_BYTES:
        url_start -= 1
    return url_start


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
    return _URL_ASSIGNMENT_PREFIX_PATTERN.fullmatch(data[match_end:url_start]) is not None


def _redacted_snippet_for_match(data: bytes, match_start: int, match_end: int, *, before: int, after: int) -> str:
    start = max(0, match_start - before)
    end = min(len(data), match_end + after)
    scan_start = max(0, start - _MAX_SNIPPET_URL_EXPANSION_BYTES)
    scan_end = min(len(data), end + _MAX_SNIPPET_URL_EXPANSION_BYTES)

    url_start = _bounded_url_start_before_match(data, match_start, scan_start)
    if url_start is not None:
        start = min(start, url_start)
        url_end = match_end
        while url_end < scan_end and data[url_end] not in _URL_TEXT_BOUNDARY_BYTES:
            url_end += 1
        end = max(end, url_end)
    else:
        scheme_marker = data.find(b"://", match_end, min(len(data), match_end + after))
        if scheme_marker >= 0:
            url_start = scheme_marker
            while url_start > scan_start and data[url_start - 1] not in _URL_TEXT_BOUNDARY_BYTES:
                url_start -= 1
            url_end = scheme_marker + 3
            while url_end < scan_end and data[url_end] not in _URL_TEXT_BOUNDARY_BYTES:
                url_end += 1
            start = min(start, url_start)
            end = max(end, url_end)

    match_text = data[match_start:match_end].decode("utf-8", errors="ignore")
    snippet_parts = [match_text]
    for url_match in _URL_IN_BYTES_PATTERN.finditer(data, start, end):
        raw_url = url_match.group().decode("utf-8", errors="ignore")
        source_quote = _source_quote_before_url(data, url_match.start())
        trimmed_url = _trim_source_literal_url(raw_url, source_quote)
        trimmed_url_end = url_match.start() + len(trimmed_url.encode("utf-8"))
        if not _is_url_associated_with_match(
            data,
            match_start=match_start,
            match_end=match_end,
            url_start=url_match.start(),
            url_end=trimmed_url_end,
        ):
            continue
        redacted_url = redact_url_for_finding(trimmed_url)
        if redacted_url not in snippet_parts:
            snippet_parts.append(redacted_url)

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

        raw_url = match.group().decode("utf-8", errors="ignore")
        source_quote = _source_quote_before_url(data, match.start())
        url = _trim_source_literal_url(raw_url, source_quote)
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
    return int(data[match_start : match_start + 2], 16) in b"/=?&#;:@"


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

    if relative_start < authority_end:
        return value_lower in parsed.netloc.lower() and value_lower not in safe_parsed.netloc.lower()
    if relative_start < path_end:
        return value_lower in parsed.path.lower() and value_lower not in safe_parsed.path.lower()

    if parsed.query:
        query_start = path_end + 1
        query_end = query_start + len(parsed.query)
        if query_start <= relative_start < query_end:
            return _is_match_redacted_from_url_component(parsed.query, relative_start - query_start, value)

    if parsed.fragment:
        fragment_start = path_end + (len(parsed.query) + 1 if parsed.query else 0) + 1
        if fragment_start <= relative_start:
            return _is_match_redacted_from_url_component(parsed.fragment, relative_start - fragment_start, value)
    return False


def _is_match_redacted_from_url_component(component: str, match_start: int, value: str) -> bool:
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
    nested_url_candidates = (field_value, _decode_path_token(field_value))
    for candidate in nested_url_candidates:
        if candidate == _PATH_TOKEN_DECODE_LIMIT_SENTINEL:
            continue
        for nested_url_match in _URI_IN_TEXT_PATTERN.finditer(candidate):
            nested_url = nested_url_match.group()
            if value_lower not in nested_url.lower():
                continue
            safe_nested_url = redact_url_for_finding(nested_url)
            return value_lower not in safe_nested_url.lower()

        for decoded_field in _URL_COMPONENT_SEPARATOR_PATTERN.split(candidate):
            decoded_key, decoded_separator, decoded_value = decoded_field.partition("=")
            if decoded_separator and value_lower in decoded_value.lower() and _is_sensitive_path_key(decoded_key):
                return True

    field = component[field_start:field_end]
    redacted_colon_field = _redact_colon_delimited_path_tokens(field)
    if redacted_colon_field is not None and value_lower in field.lower():
        return value_lower not in redacted_colon_field.lower()

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
    if not source_composition and not path_continuation:
        return False

    url = preceding_url_match.group().decode("utf-8", errors="ignore")
    return _url_path_awaits_sensitive_value(url)


def _is_redacted_evidence_value(data: bytes, match_start: int, value: str) -> bool:
    """Use the shared redactor to reject endpoint-shaped credential values."""
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


def _decoded_nested_urls(url: str) -> Iterator[str]:
    """Yield nested URLs that only become visible after bounded component decoding."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return

    seen: set[str] = set()
    for component in (parsed.query, parsed.fragment):
        for field in _URL_COMPONENT_SEPARATOR_PATTERN.split(component):
            _key, separator, value = field.partition("=")
            candidate = value if separator else field
            decoded = _decode_path_token(candidate)
            if decoded in {candidate, _PATH_TOKEN_DECODE_LIMIT_SENTINEL}:
                continue
            for match in _URI_IN_TEXT_PATTERN.finditer(decoded):
                nested_url = match.group()
                if nested_url not in seen:
                    seen.add(nested_url)
                    yield nested_url


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
_MAX_PROSE_LINE_CONTEXT_BYTES = 512
_WORD_PATTERN = re.compile(rb"[A-Za-z]{2,}")
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


def _extract_line(data: bytes, match_index: int) -> bytes:
    """Extract the line containing a matched network token."""
    line_start = max(data.rfind(b"\n", 0, match_index) + 1, match_index - _MAX_PROSE_LINE_CONTEXT_BYTES)
    line_end = data.find(b"\n", match_index)
    if line_end == -1:
        line_end = len(data)
    line_end = min(line_end, match_index + _MAX_PROSE_LINE_CONTEXT_BYTES)
    return data[line_start:line_end]


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
    while cursor < len(data) and data[cursor : cursor + 1] in {b" ", b"\t", b"\r", b"\n"}:
        cursor += 1
    return cursor < len(data) and data[cursor : cursor + 1] == b"("


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
) -> bool:
    """Return whether a raw network token appears in prose instead of executable code."""
    if requires_call and _has_call_syntax(data, match_index, token_len):
        return False

    line = _extract_line(data, match_index)
    line_lower = line.lower()
    stripped = line_lower.lstrip()
    word_count = len(_WORD_PATTERN.findall(line))
    metadata_context = _is_metadata_context(context)

    if any(stripped.startswith(prefix) for prefix in _CODE_LINE_PREFIXES):
        return False
    if _INLINE_COMPOUND_STATEMENT_PATTERN.match(line_lower):
        return False
    if any(marker in line_lower for marker in _CODE_LINE_MARKERS):
        return False
    if metadata_context and stripped.startswith(_STRUCTURED_METADATA_PREFIXES):
        return False

    text = line.decode("utf-8", errors="ignore").lower()
    has_prose_marker = any(marker in text for marker in _PROSE_MARKERS)
    if not has_prose_marker:
        return False
    return (metadata_context and word_count >= 4) or word_count >= 6


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
    IPV4_PATTERN = re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    IPV6_PATTERN = re.compile(rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")

    # Domain patterns
    DOMAIN_PATTERN = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

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
            raw_url = match.group().decode("utf-8", errors="ignore")
            source_quote = _source_quote_before_url(data, match.start())
            url = _trim_source_literal_url(raw_url, source_quote)
            yield match.start(), match.start() + len(url.encode("utf-8")), url

    @classmethod
    def _iter_generic_url_contexts(cls, data: bytes) -> Iterator[tuple[int, int, str]]:
        """Yield only schemes handled by generic URL findings."""
        for match in cls.URL_PATTERN.finditer(data):
            raw_url = match.group().decode("utf-8", errors="ignore")
            source_quote = _source_quote_before_url(data, match.start())
            url = _trim_source_literal_url(raw_url, source_quote)
            yield match.start(), match.start() + len(url.encode("utf-8")), url

    def _is_redacted_url_value(self, data: bytes, match_start: int, value: str) -> bool:
        if self.max_findings is not None:
            local_uri_context = _url_text_bounds_containing_offset(data, match_start)
            if local_uri_context is None:
                local_uri_context = _uri_text_bounds_containing_offset(data, match_start, _URI_IN_BYTES_PATTERN)
            if local_uri_context is not None:
                url, url_start = local_uri_context
                return _is_match_redacted_from_url_context(url, url_start, match_start, value)

            if _bounded_url_lookup_starts_mid_token(data, match_start):
                lazy_url_context = self._lazy_url_context_containing(match_start)
                if lazy_url_context is not None:
                    url_start, _url_end, url = lazy_url_context
                    return _is_match_redacted_from_url_context(url, url_start, match_start, value)
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
        before = max(0, match_start - _MAX_URL_TEXT_LOOKUP_BYTES)
        match_end = match_start + len(value.encode("utf-8"))
        after = min(len(data), match_end + _MAX_URL_TEXT_LOOKUP_BYTES)
        if _SENSITIVE_EVIDENCE_HINT_PATTERN.search(data[before:after]) is None:
            return False
        if self._evidence_redaction_classifications >= _MAX_EVIDENCE_REDACTION_CLASSIFICATIONS:
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
            self._pending_url_context = None
            _start, _end, url = context
            cache_limit = (self.max_findings or 0) + 1
            recordable_url = self.URL_PATTERN.fullmatch(url.encode("utf-8")) is not None or any(
                _decoded_nested_urls(url)
            )
            if recordable_url and len(self._url_contexts) < cache_limit:
                self._url_contexts.append(context)
                self._url_context_starts.append(context[0])
            if match_start < context[1]:
                return context
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

    def _scan_urls(self, data: bytes, context: str) -> None:
        """Scan for URL patterns."""
        url_contexts = iter(self._url_contexts) if self.max_findings is None else self._iter_generic_url_contexts(data)
        for url_start, _url_end, url in url_contexts:
            if self.URL_PATTERN.fullmatch(url.encode("utf-8")) is not None and not self._record_url_finding(
                url, url_start, context
            ):
                return
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
                safe_url = redact_url_for_finding(url)

                if self.max_findings is not None and self.URL_PATTERN.fullmatch(match.group()) is None:
                    for nested_url in _decoded_nested_urls(url):
                        if not self._record_url_finding(nested_url, match.start(), context):
                            return

                # Skip duplicates
                if url in seen_urls:
                    continue
                seen_urls.add(url)

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
                        requires_call=False,
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
                    # If we can decode it as UTF-8, it's likely text-based and suspicious
                    printable_ratio = sum(c.isprintable() for c in context_str) / len(context_str)

                    if printable_ratio > 0.7:  # High ratio of printable characters
                        raw_matched_text = match.group().decode("utf-8", errors="ignore")
                        if pattern_type == "url":
                            source_quote = _source_quote_before_url(data, match.start())
                            raw_matched_text = _trim_source_literal_url(raw_matched_text, source_quote)
                        matched_text = _redact_network_evidence(raw_matched_text)
                        if not self._record_finding(
                            {
                                "type": "explicit_network_pattern",
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "message": f"Explicit network pattern in ML model: {matched_text[:100]}",
                                "pattern_type": pattern_type,
                                "matched_text": matched_text[:200],
                                "context": context,
                            }
                        ):
                            return
                except UnicodeDecodeError:
                    # If it can't be decoded as UTF-8, it's likely binary data
                    # Skip to avoid false positives in model weights
                    continue

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
