"""HuggingFace URL and local-cache provenance parsing helpers."""

import json
import os
import re
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse, urlunparse

from ._huggingface_cache import _find_hf_cache_root, _resolve_hf_cache_path

HUGGINGFACE_URL_IN_TEXT_PATTERN = re.compile(
    r"(?i)\b(?:https?://(?:[^\s\"'<>/@]+(?::[^\s\"'<>/@]*)?@)?(?:huggingface\.co|hf\.co)|hf://)"
    r"[^\s\"'<>]*"
)
_SENSITIVE_URL_QUERY_PARAM_PATTERN = re.compile(
    (
        r"([?&][^=\s&]*(?:signature|credential|security-token|access-key|access_key|token|"
        r"secret|api-key|api_key|apikey|sig|sas)[^=\s&]*=)[^\s&#]+"
    ),
    re.IGNORECASE,
)
_URL_USERINFO_PATTERN = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)
_OPAQUE_URL_USERINFO_PATTERN = re.compile(r"^([a-z][a-z0-9+.-]*:)([^/@\s]+)@", re.IGNORECASE)
_HF_REPO_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_MALFORMED_PERCENT_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HF_REPO_ID_MAX_LENGTH = 96
_IS_WINDOWS = os.name == "nt"
_WINDOWS_RESERVED_FILE_STEMS = {
    "AUX",
    "CON",
    "CONIN$",
    "CONOUT$",
    "NUL",
    "PRN",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
    *(f"COM{index}" for index in ("\u00b9", "\u00b2", "\u00b3")),
    *(f"LPT{index}" for index in ("\u00b9", "\u00b2", "\u00b3")),
}


def _decode_huggingface_url_component(raw_component: str, field_name: str) -> str:
    """Decode one URL component without silently replacing malformed UTF-8."""
    if _MALFORMED_PERCENT_ESCAPE_PATTERN.search(raw_component):
        raise ValueError(f"Invalid HuggingFace {field_name} encoding")
    try:
        decoded = unquote(raw_component, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Invalid HuggingFace {field_name} encoding") from exc
    if any(unicodedata.category(character) in {"Cc", "Cs"} for character in decoded):
        raise ValueError(f"Invalid HuggingFace {field_name} control character")
    return decoded


def _validate_huggingface_url_input(url: str) -> None:
    """Reject characters that URL parsing would silently discard."""
    if url[:1].isspace() or any(unicodedata.category(character) in {"Cc", "Cs"} for character in url):
        raise ValueError("Invalid HuggingFace URL control character")


def _validate_huggingface_repo_component(component: str, field_name: str) -> str:
    """Validate one HuggingFace repo-id component before using it in paths."""
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        or component.endswith(".git")
        or component[0] in {".", "-"}
        or component[-1] in {".", "-"}
        or ".." in component
        or "--" in component
        or not _HF_REPO_COMPONENT_PATTERN.fullmatch(component)
    ):
        raise ValueError(f"Invalid HuggingFace {field_name}: {component!r}")
    return component


def _decode_huggingface_repo_component(raw_component: str, field_name: str) -> str:
    decoded = _decode_huggingface_url_component(raw_component, field_name)
    return _validate_huggingface_repo_component(decoded, field_name)


def _validate_huggingface_windows_path_component(component: str, field_name: str) -> None:
    if _IS_WINDOWS:
        reserved_stem = component.split(".", 1)[0].rstrip(" .").upper()
        if (
            component[-1] in {" ", "."}
            or any(character in '<>:"/\\|?*' for character in component)
            or reserved_stem in _WINDOWS_RESERVED_FILE_STEMS
        ):
            raise ValueError(f"Invalid HuggingFace {field_name} path component on Windows: {component!r}")


def _decode_huggingface_file_path_component(raw_component: str, field_name: str) -> str:
    decoded = _decode_huggingface_url_component(raw_component, field_name)
    if not decoded or decoded in {".", ".."} or "/" in decoded:
        raise ValueError(f"Invalid HuggingFace {field_name} path component: {decoded!r}")
    _validate_huggingface_windows_path_component(decoded, field_name)
    return decoded


def _decode_huggingface_revision(raw_component: str) -> str:
    decoded = _decode_huggingface_url_component(raw_component, "revision")
    revision_parts = decoded.split("/")
    if "\\" in decoded or any(not part or part in {".", ".."} for part in revision_parts):
        raise ValueError(f"Invalid HuggingFace revision path component: {decoded!r}")
    for revision_part in revision_parts:
        _validate_huggingface_windows_path_component(revision_part, "revision")
    return decoded


def _extract_huggingface_revision_query(raw_query: str) -> str | None:
    """Return an optional revision query value without trusting decoded query parsing."""
    if not raw_query:
        return None

    revisions: list[str] = []
    for raw_pair in raw_query.split("&"):
        if not raw_pair:
            continue
        raw_key, separator, raw_value = raw_pair.partition("=")
        key = _decode_huggingface_url_component(raw_key, "query parameter")
        if key != "revision":
            continue
        if not separator or not raw_value:
            raise ValueError("Invalid HuggingFace revision query")
        revisions.append(_decode_huggingface_revision(raw_value))

    if not revisions:
        return None
    if len(set(revisions)) != 1:
        raise ValueError("Ambiguous HuggingFace revision query")
    return revisions[0]


def _split_huggingface_repo_path(raw_path: str) -> tuple[str, str, list[str]]:
    stripped = raw_path.strip("/")
    if not stripped:
        raise ValueError("Invalid HuggingFace URL format")

    raw_parts = stripped.split("/")
    if any(not part for part in raw_parts):
        raise ValueError("Invalid HuggingFace URL format")

    namespace = _decode_huggingface_repo_component(raw_parts[0], "namespace")
    repo_name = ""
    if len(raw_parts) >= 2:
        repo_name = _decode_huggingface_repo_component(raw_parts[1], "repository")
    return namespace, repo_name, raw_parts


def is_huggingface_url(url: str) -> bool:
    """Check if a URL is a HuggingFace model URL."""
    patterns = [
        r"^https?://(?:[^\s\"'<>/@?#]+(?::[^\s\"'<>/@?#]*)?@)?huggingface\.co/[^/?#]+(/[^/?#]+)?/?([?#].*)?$",
        r"^https?://(?:[^\s\"'<>/@?#]+(?::[^\s\"'<>/@?#]*)?@)?hf\.co/[^/?#]+(/[^/?#]+)?/?([?#].*)?$",
        r"^hf://[^/?#]+(/[^/?#]+)?/?([?#].*)?$",
    ]
    if not any(re.match(pattern, url) for pattern in patterns):
        return False
    try:
        parse_huggingface_url(url)
    except ValueError:
        return False
    return True


def redact_huggingface_url_for_display(url: str) -> str:
    """Remove credentials, query strings, and fragments from HuggingFace URLs for display."""
    try:
        parsed = urlparse(url)
    except ValueError:
        redacted = _URL_USERINFO_PATTERN.sub(r"\1<credentials-redacted>@", url)
        if "://" in redacted:
            scheme, remainder = redacted.split("://", 1)
            _, separator, path = remainder.partition("/")
            redacted = f"{scheme}://<invalid-authority>"
            if separator:
                redacted = f"{redacted}/{path}"
        return redacted.split("#", 1)[0].split("?", 1)[0]
    if not parsed.netloc:
        if parsed.scheme in {"ftp", "hf", "http", "https"}:
            redacted = _URL_USERINFO_PATTERN.sub(r"\1<credentials-redacted>@", url)
            return redacted.split("#", 1)[0].split("?", 1)[0]
        return url

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


def _redact_huggingface_url_for_validation_error(url: str) -> str:
    """Redact URL-like input before including it in a validation error."""
    redacted = redact_huggingface_url_for_display(url)
    redacted = _URL_USERINFO_PATTERN.sub(r"\1<credentials-redacted>@", redacted)
    redacted = _OPAQUE_URL_USERINFO_PATTERN.sub(r"\1<credentials-redacted>@", redacted)
    return redacted.split("#", 1)[0].split("?", 1)[0]


def redact_huggingface_urls_in_text(text: str) -> str:
    """Redact Hugging Face and signed transport URLs in display text."""
    redacted = HUGGINGFACE_URL_IN_TEXT_PATTERN.sub(
        lambda match: redact_huggingface_url_for_display(match.group(0)),
        text,
    )
    redacted = _URL_USERINFO_PATTERN.sub(r"\1<credentials-redacted>@", redacted)
    return _SENSITIVE_URL_QUERY_PARAM_PATTERN.sub(r"\1<redacted>", redacted)


def is_huggingface_file_url(url: str) -> bool:
    """Check if a URL is a direct HuggingFace file URL."""
    try:
        parse_huggingface_file_url(url)
        return True
    except ValueError:
        return False


def parse_huggingface_file_url(url: str) -> tuple[str, str, str]:
    """Parse a HuggingFace file URL to extract repo_id, branch, and filename."""
    _validate_huggingface_url_input(url)
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ValueError(f"Invalid HuggingFace URL: {_redact_huggingface_url_for_validation_error(url)}") from exc
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {_redact_huggingface_url_for_validation_error(url)}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            f"Invalid HuggingFace URL authority: {_redact_huggingface_url_for_validation_error(url)}"
        ) from exc
    expected_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != expected_port:
        raise ValueError(f"Invalid HuggingFace URL authority: {_redact_huggingface_url_for_validation_error(url)}")

    raw_path = parsed.path[1:] if parsed.path.startswith("/") else parsed.path
    if not raw_path or raw_path.startswith("/") or raw_path.endswith("/") or "//" in raw_path:
        raise ValueError(f"Invalid HuggingFace file URL format: {_redact_huggingface_url_for_validation_error(url)}")

    path_parts = raw_path.split("/")
    if len(path_parts) >= 5 and path_parts[1:3] == ["resolve", "resolve"]:
        raise ValueError(f"Ambiguous HuggingFace file URL format: {_redact_huggingface_url_for_validation_error(url)}")
    if len(path_parts) >= 5 and path_parts[2] == "resolve":
        resolve_index = 2
    elif len(path_parts) >= 4 and path_parts[1] == "resolve":
        resolve_index = 1
    else:
        raise ValueError(f"Invalid HuggingFace file URL format: {_redact_huggingface_url_for_validation_error(url)}")

    if resolve_index == 2:
        namespace = _decode_huggingface_repo_component(path_parts[0], "namespace")
        repo_name = _decode_huggingface_repo_component(path_parts[1], "repository")
        repo_id = f"{namespace}/{repo_name}"
    else:
        repo_id = _decode_huggingface_repo_component(path_parts[0], "repository")
    if len(repo_id) > _HF_REPO_ID_MAX_LENGTH:
        raise ValueError(f"Invalid HuggingFace repository ID length: {len(repo_id)}")

    branch = _decode_huggingface_revision(path_parts[resolve_index + 1])
    filename = "/".join(
        _decode_huggingface_file_path_component(part, "filename") for part in path_parts[resolve_index + 2 :]
    )

    return repo_id, branch, filename


def parse_huggingface_url(url: str) -> tuple[str, str]:
    """Parse a HuggingFace model URL into namespace and repository name."""
    namespace, repo_name, _revision = parse_huggingface_url_with_revision(url)
    return namespace, repo_name


def parse_huggingface_url_with_revision(url: str) -> tuple[str, str, str | None]:
    """Parse a HuggingFace model URL into namespace, repository name, and optional revision."""
    _validate_huggingface_url_input(url)
    if url.startswith("hf://"):
        try:
            parsed = urlparse(url)
            raw_repo_path = parsed.netloc
            if parsed.path:
                raw_repo_path = f"{raw_repo_path}{parsed.path}"
            namespace, repo_name, raw_parts = _split_huggingface_repo_path(raw_repo_path)
            revision = _extract_huggingface_revision_query(parsed.query)
        except ValueError as exc:
            raise ValueError(f"Invalid HuggingFace URL format: {redact_huggingface_url_for_display(url)}") from exc
        if len(raw_parts) == 1:
            return namespace, "", revision
        if len(raw_parts) == 2:
            return namespace, repo_name, revision
        raise ValueError(f"Invalid HuggingFace URL format: {redact_huggingface_url_for_display(url)}")

    parsed = urlparse(url)
    if parsed.hostname not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {redact_huggingface_url_for_display(url)}")

    try:
        namespace, repo_name, raw_parts = _split_huggingface_repo_path(parsed.path)
    except ValueError as exc:
        raise ValueError(f"Invalid HuggingFace URL format: {redact_huggingface_url_for_display(url)}") from exc
    if len(raw_parts) == 1:
        return namespace, "", _extract_huggingface_revision_query(parsed.query)
    if len(raw_parts) == 2:
        return namespace, repo_name, _extract_huggingface_revision_query(parsed.query)
    raise ValueError(f"Invalid HuggingFace URL format: {redact_huggingface_url_for_display(url)}")


def is_huggingface_cache_path(path: str | Path) -> bool:
    """Return True if a path is inside a HuggingFace cache layout."""
    path_obj = Path(path)
    cache_root = _find_hf_cache_root(path_obj)
    if cache_root is None:
        return False

    try:
        relative_parts = _resolve_hf_cache_path(path_obj).relative_to(cache_root).parts
    except ValueError:
        return False

    return bool(relative_parts and relative_parts[0] in {"snapshots", "blobs", "refs"})


def extract_model_id_from_path(path: str) -> tuple[str | None, str | None]:
    """Extract HuggingFace model ID and source from a local path or URL."""
    if is_huggingface_file_url(path):
        try:
            repo_id, _, _ = parse_huggingface_file_url(path)
            return repo_id, "huggingface"
        except ValueError:
            pass
    if is_huggingface_url(path):
        try:
            namespace, repo_name = parse_huggingface_url(path)
            model_id = f"{namespace}/{repo_name}" if repo_name else namespace
            return model_id, "huggingface"
        except ValueError:
            pass

    path_obj = Path(path)
    if is_huggingface_cache_path(path_obj):
        cache_root = _find_hf_cache_root(path_obj)
        if cache_root is not None:
            parts = cache_root.name[len("models--") :].split("--")
            if len(parts) >= 2:
                model_id = f"{parts[0]}/{parts[1]}"
                return model_id, "huggingface_cache"

    current_path = path_obj if path_obj.is_dir() else path_obj.parent
    for _ in range(3):
        config_file = current_path / "config.json"
        if config_file.exists():
            try:
                with open(config_file, encoding="utf-8") as f:
                    config = json.load(f)
                    model_id = config.get("_name_or_path") or config.get("model_name") or config.get("name")
                    if model_id and "/" in model_id:
                        return model_id, "local"
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                # Optional local metadata may be absent or malformed; continue walking parent directories.
                pass

        model_index = current_path / "model_index.json"
        if model_index.exists():
            try:
                with open(model_index, encoding="utf-8") as f:
                    config = json.load(f)
                    model_id = config.get("_name_or_path") or config.get("name")
                    if model_id and "/" in model_id:
                        return model_id, "local"
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                # Optional local metadata may be absent or malformed; continue walking parent directories.
                pass

        if current_path.parent == current_path:
            break
        current_path = current_path.parent

    return None, None
