"""HuggingFace URL and local-cache provenance parsing helpers."""

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse, urlunparse

from ._huggingface_cache import _find_hf_cache_root, _resolve_hf_cache_path

HUGGINGFACE_URL_IN_TEXT_PATTERN = re.compile(
    r"(?i)\b(?:https?://(?:[^\s\"'<>/@]+(?::[^\s\"'<>/@]*)?@)?(?:huggingface\.co|hf\.co)|hf://)"
    r"[^\s\"'<>]*"
)


def is_huggingface_url(url: str) -> bool:
    """Check if a URL is a HuggingFace model URL."""
    patterns = [
        r"^https?://(?:[^\s\"'<>/@?#]+(?::[^\s\"'<>/@?#]*)?@)?huggingface\.co/[^/?#]+(/[^/?#]+)?/?([?#].*)?$",
        r"^https?://(?:[^\s\"'<>/@?#]+(?::[^\s\"'<>/@?#]*)?@)?hf\.co/[^/?#]+(/[^/?#]+)?/?([?#].*)?$",
        r"^hf://[^/?#]+(/[^/?#]+)?/?([?#].*)?$",
    ]
    return any(re.match(pattern, url) for pattern in patterns)


def redact_huggingface_url_for_display(url: str) -> str:
    """Remove credentials, query strings, and fragments from HuggingFace URLs for display."""
    parsed = urlparse(url)
    if parsed.scheme == "hf":
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    if parsed.hostname not in {"huggingface.co", "hf.co"}:
        return url

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


def redact_huggingface_urls_in_text(text: str) -> str:
    """Redact HuggingFace URLs embedded inside a larger display string."""
    return HUGGINGFACE_URL_IN_TEXT_PATTERN.sub(
        lambda match: redact_huggingface_url_for_display(match.group(0)),
        text,
    )


def is_huggingface_file_url(url: str) -> bool:
    """Check if a URL is a direct HuggingFace file URL."""
    try:
        parse_huggingface_file_url(url)
        return True
    except ValueError:
        return False


def parse_huggingface_file_url(url: str) -> tuple[str, str, str]:
    """Parse a HuggingFace file URL to extract repo_id, branch, and filename."""
    parsed = urlparse(url)
    if parsed.hostname not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {redact_huggingface_url_for_display(url)}")

    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) < 5 or path_parts[2] != "resolve":
        raise ValueError(f"Invalid HuggingFace file URL format: {redact_huggingface_url_for_display(url)}")

    repo_id = f"{path_parts[0]}/{path_parts[1]}"
    branch = unquote(path_parts[3])
    filename = "/".join(unquote(part) for part in path_parts[4:])

    return repo_id, branch, filename


def parse_huggingface_url(url: str) -> tuple[str, str]:
    """Parse a HuggingFace model URL into namespace and repository name."""
    if url.startswith("hf://"):
        path = unquote(url[5:])
        parts = path.strip("/").split("/")
        if len(parts) == 1 and parts[0]:
            return parts[0], ""
        if len(parts) == 2:
            return parts[0], parts[1]
        raise ValueError(f"Invalid HuggingFace URL format: {redact_huggingface_url_for_display(url)}")

    parsed = urlparse(url)
    if parsed.hostname not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {redact_huggingface_url_for_display(url)}")

    path = unquote(parsed.path)
    path_parts = path.strip("/").split("/")
    if len(path_parts) == 1 and path_parts[0]:
        return path_parts[0], ""
    if len(path_parts) >= 2:
        return path_parts[0], path_parts[1]
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
    if is_huggingface_url(path) or is_huggingface_file_url(path):
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
