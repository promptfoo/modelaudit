"""HuggingFace URL and local-cache provenance parsing helpers."""

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse


def is_huggingface_url(url: str) -> bool:
    """Check if a URL is a HuggingFace model URL."""
    patterns = [
        r"^https?://huggingface\.co/[^/]+(/[^/]+)?/?$",
        r"^https?://hf\.co/[^/]+(/[^/]+)?/?$",
        r"^hf://[^/]+(/[^/]+)?/?$",
    ]
    return any(re.match(pattern, url) for pattern in patterns)


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
    if parsed.netloc not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {url}")

    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) < 5 or path_parts[2] != "resolve":
        raise ValueError(f"Invalid HuggingFace file URL format: {url}")

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
        raise ValueError(f"Invalid HuggingFace URL format: {url}")

    parsed = urlparse(url)
    if parsed.netloc not in ["huggingface.co", "hf.co"]:
        raise ValueError(f"Not a HuggingFace URL: {url}")

    path = unquote(parsed.path)
    path_parts = path.strip("/").split("/")
    if len(path_parts) == 1 and path_parts[0]:
        return path_parts[0], ""
    if len(path_parts) >= 2:
        return path_parts[0], path_parts[1]
    raise ValueError(f"Invalid HuggingFace URL format: {url}")


def _path_has_part(path: Path, part: str) -> bool:
    """Return True if any path segment matches part (case-insensitive)."""
    part_lower = part.lower()
    return any(segment.lower() == part_lower for segment in path.parts)


def _find_hf_cache_root(path: Path) -> Path | None:
    """Return the HuggingFace cache root containing models--* if present."""
    for index, segment in enumerate(path.parts):
        if (
            segment.lower().startswith("models--")
            and index >= 3
            and [part.lower() for part in path.parts[index - 3 : index]] == [".cache", "huggingface", "hub"]
        ):
            return Path(*path.parts[: index + 1])
    return None


def is_huggingface_cache_path(path: str | Path) -> bool:
    """Return True if a path is inside a HuggingFace cache layout."""
    path_obj = Path(path)
    cache_root = _find_hf_cache_root(path_obj)
    if cache_root is None:
        return False

    try:
        relative_parts = path_obj.relative_to(cache_root).parts
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
            except Exception:
                pass

        model_index = current_path / "model_index.json"
        if model_index.exists():
            try:
                with open(model_index, encoding="utf-8") as f:
                    config = json.load(f)
                    model_id = config.get("_name_or_path") or config.get("name")
                    if model_id and "/" in model_id:
                        return model_id, "local"
            except Exception:
                pass

        if current_path.parent == current_path:
            break
        current_path = current_path.parent

    return None, None
