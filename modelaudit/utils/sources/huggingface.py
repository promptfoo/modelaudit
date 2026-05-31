"""Utilities for handling HuggingFace model downloads."""

import logging
import os
from collections.abc import Iterator
from glob import escape as escape_glob
from pathlib import Path
from typing import Any

from ..helpers.disk_space import check_disk_space
from .huggingface_paths import (
    extract_model_id_from_path,
    is_huggingface_cache_path,
    is_huggingface_file_url,
    is_huggingface_url,
    parse_huggingface_file_url,
    parse_huggingface_url,
    redact_huggingface_url_for_display,
    redact_huggingface_urls_in_text,
)

logger = logging.getLogger(__name__)

__all__ = [
    "download_file_from_hf",
    "download_model",
    "extract_model_id_from_path",
    "get_model_info",
    "get_model_size",
    "is_huggingface_cache_path",
    "is_huggingface_file_url",
    "is_huggingface_url",
    "parse_huggingface_file_url",
    "parse_huggingface_url",
    "redact_huggingface_url_for_display",
    "redact_huggingface_urls_in_text",
]


def _get_model_extensions() -> set[str]:
    """
    Lazy-load model extensions to avoid circular imports.

    Returns all file extensions that ModelAudit can scan - dynamically loaded from scanner registry.
    This ensures we download and scan everything we have scanners for.
    """
    from ..model_extensions import get_model_extensions

    return get_model_extensions()


def _build_extension_allow_patterns() -> list[str]:
    """Build conservative glob patterns for scannable files."""
    extensions = _get_model_extensions()
    patterns = {f"*{ext}" for ext in extensions}
    patterns.update(f"**/*{ext}" for ext in extensions)
    return sorted(patterns)


def _build_literal_allow_patterns(filenames: list[str]) -> list[str]:
    """Escape repository filenames before passing them to the Hub glob filter."""
    return [escape_glob(filename) for filename in filenames]


def _extract_huggingface_repo_files(repo_info: Any) -> list[str] | None:
    """Extract repository filenames from a Hugging Face repository response."""
    siblings = getattr(repo_info, "siblings", None)
    if siblings is None:
        return None

    files: list[str] = []
    for sibling in siblings:
        if isinstance(sibling, dict):
            file_name = sibling.get("rfilename") or sibling.get("path")
        else:
            file_name = getattr(sibling, "rfilename", None) or getattr(sibling, "path", None)

        if isinstance(file_name, str) and file_name:
            files.append(file_name)
    return files


def _get_hf_cache_root() -> Path:
    """Return the HuggingFace hub cache root."""
    try:
        from huggingface_hub.constants import HF_HUB_CACHE

        return Path(HF_HUB_CACHE)
    except Exception:
        return Path.home() / ".cache" / "huggingface" / "hub"


def _is_within_directory(base_dir: Path, target: Path) -> bool:
    """Return True when target resolves inside base_dir."""
    base_path = base_dir.resolve()
    target_path = target.resolve()
    if os.name == "nt":
        base_norm = os.path.normcase(os.path.normpath(str(base_path)))
        target_norm = os.path.normcase(os.path.normpath(str(target_path)))
        try:
            return os.path.commonpath([target_norm, base_norm]) == base_norm
        except ValueError:
            return False
    return target_path.is_relative_to(base_path)


def _build_huggingface_download_path(cache_dir: Path, namespace: str, repo_name: str) -> Path:
    """Build and containment-check the local HuggingFace download path."""
    cache_root = (cache_dir / "huggingface").resolve()
    download_path = cache_root / namespace
    if repo_name:
        download_path = download_path / repo_name
    resolved_download_path = download_path.resolve()
    if not _is_within_directory(cache_root, resolved_download_path):
        raise ValueError(f"HuggingFace cache path escaped cache directory: {resolved_download_path}")
    return resolved_download_path


def _list_repo_files_with_timeout(repo_id: str, timeout_seconds: float = 30) -> tuple[list[str] | None, str | None]:
    """Return repository files or a failure reason if listing times out/errors."""
    from huggingface_hub import HfApi

    try:
        repo_info = HfApi().repo_info(repo_id, timeout=timeout_seconds, files_metadata=False)
    except Exception as exc:
        return None, str(exc)

    files = _extract_huggingface_repo_files(repo_info)
    if files is None:
        return None, "repository listing unavailable"

    return files, None


def _list_huggingface_repo_files_at_revision(repo_id: str, timeout_seconds: float = 30) -> tuple[list[str], str]:
    """Return repository filenames and the revision that produced the listing."""
    from huggingface_hub import HfApi

    repo_info = HfApi().repo_info(repo_id, timeout=timeout_seconds, files_metadata=False)
    raw_revision = getattr(repo_info, "sha", None)
    if not isinstance(raw_revision, str) or not raw_revision:
        raise Exception(f"Cannot enforce max-size for {repo_id}: repository revision unavailable")

    files = _extract_huggingface_repo_files(repo_info)
    if files is None:
        raise Exception(f"Cannot enforce max-size for {repo_id}: repository listing unavailable")
    return files, raw_revision


def _get_huggingface_path_sizes(
    repo_id: str,
    filenames: list[str],
    *,
    requested_revision: str | None = None,
    resolved_revision: str | None = None,
) -> tuple[dict[str, int | None], str]:
    """Return exact Hugging Face sizes for selected files and the checked revision."""
    if not filenames:
        return {}, ""

    from huggingface_hub import HfApi

    api = HfApi()
    if resolved_revision is None:
        repo_info_kwargs: dict[str, Any] = {"files_metadata": False}
        if requested_revision is not None:
            repo_info_kwargs["revision"] = requested_revision
        repo_info = api.repo_info(repo_id, **repo_info_kwargs)
        raw_revision = getattr(repo_info, "sha", None)
        if not isinstance(raw_revision, str) or not raw_revision:
            raise Exception(f"Cannot enforce max-size for {repo_id}: repository revision unavailable")
        resolved_revision = raw_revision

    path_info = api.get_paths_info(repo_id, filenames, revision=resolved_revision)
    sizes: dict[str, int | None] = {}
    for item in path_info:
        path = getattr(item, "path", None)
        if not isinstance(path, str):
            continue
        raw_size = getattr(item, "size", None)
        sizes[path] = raw_size if isinstance(raw_size, int) and raw_size >= 0 else None
    return sizes, resolved_revision


def _ensure_huggingface_selection_within_max_size(
    repo_id: str,
    filenames: list[str],
    max_size: int | None,
    *,
    requested_revision: str | None = None,
    resolved_revision: str | None = None,
) -> str | None:
    """Fail before transfer when selected Hugging Face files exceed the download budget."""
    if max_size is None or not filenames:
        return None

    sizes, revision = _get_huggingface_path_sizes(
        repo_id,
        filenames,
        requested_revision=requested_revision,
        resolved_revision=resolved_revision,
    )
    total_size = 0
    for filename in filenames:
        size = sizes.get(filename)
        if size is None:
            raise Exception(f"Cannot download {repo_id}: unknown size for selected file {filename}")
        total_size += size
        if total_size > max_size:
            raise Exception(
                f"Cannot download {repo_id}: selected Hugging Face files total {total_size} bytes "
                f"exceeds max size {max_size} bytes"
            )
    return revision


def get_model_info(url: str) -> dict:
    """Get information about a HuggingFace model without downloading it.

    Args:
        url: HuggingFace model URL

    Returns:
        Dictionary with model information including size
    """
    try:
        from huggingface_hub import HfApi
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)

    api = HfApi()
    try:
        # Get model info for metadata
        model_info = api.model_info(repo_id)

        # Use list_repo_tree to get accurate file sizes
        # (model_info.siblings often returns None for size)
        total_size = 0
        files = []
        try:
            repo_files = api.list_repo_tree(repo_id, recursive=False)
            for item in repo_files:
                # Skip metadata files
                if hasattr(item, "path") and item.path not in [".gitattributes", "README.md"]:
                    file_size = getattr(item, "size", 0) or 0
                    total_size += file_size
                    files.append({"name": item.path, "size": file_size})
        except Exception as e:
            # If list_repo_tree fails, return 0 (will show as "Unknown size" in CLI)
            logger.debug(f"list_repo_tree failed for {repo_id}, falling back to unknown size: {e}")
            total_size = 0
            # Still try to get file count from siblings
            siblings = model_info.siblings or []
            for sibling in siblings:
                if sibling.rfilename not in [".gitattributes", "README.md"]:
                    files.append({"name": sibling.rfilename, "size": 0})

        return {
            "repo_id": repo_id,
            "total_size": total_size,
            "file_count": len(files),
            "files": files,
            "model_id": getattr(model_info, "modelId", repo_id),
            "author": getattr(model_info, "author", ""),
        }
    except Exception as e:
        raise Exception(f"Failed to get model info for {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e


def get_model_size(repo_id: str) -> int | None:
    """Get the total size of a HuggingFace model repository.

    Args:
        repo_id: Repository ID (e.g., "namespace/model-name")

    Returns:
        Total size in bytes, or None if size cannot be determined
    """
    try:
        from huggingface_hub import HfApi

        api = HfApi()
        model_info = api.model_info(repo_id)

        # Calculate total size from all files
        total_size = 0
        if hasattr(model_info, "siblings") and model_info.siblings:
            for file_info in model_info.siblings:
                if hasattr(file_info, "size") and file_info.size:
                    total_size += file_info.size

        return total_size if total_size > 0 else None
    except Exception:
        # If we can't get the size, return None and proceed with download
        return None


def download_model(
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    max_size: int | None = None,
) -> Path:
    """Download a model from HuggingFace.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress
        max_size: Optional maximum total selected download size in bytes

    Returns:
        Path to the downloaded model directory

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)

    # Disk space check and path setup
    model_size = get_model_size(repo_id)
    download_path = None  # Will be set only if cache_dir is provided
    disk_check_path = None
    download_path_preexisting = False

    if cache_dir is not None:
        # Create a structured, containment-checked cache directory.
        download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
        download_path_preexisting = download_path.exists()
        download_path.mkdir(parents=True, exist_ok=True)
        disk_check_path = download_path

    else:
        disk_check_path = _get_hf_cache_root()
        disk_check_path.mkdir(parents=True, exist_ok=True)

    if model_size and disk_check_path is not None:
        has_space, message = check_disk_space(disk_check_path, model_size)
        if not has_space:
            raise Exception(f"Cannot download model from {display_url}: {redact_huggingface_urls_in_text(message)}")

    try:
        # Configure progress display based on environment
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Enable/disable progress bars based on parameter
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            # Force progress bar to show even in non-TTY environments
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # Resolve capped listings and transfers against one immutable revision.
        budget_revision = None
        if max_size is not None:
            try:
                repo_files, budget_revision = _list_huggingface_repo_files_at_revision(repo_id)
            except Exception as exc:
                raise Exception(f"Cannot enforce max-size for {repo_id}: repository listing failed: {exc}") from exc
            repo_listing_failed = False
            repo_listing_error = None
        else:
            listed_repo_files, repo_listing_error = _list_repo_files_with_timeout(repo_id)
            if listed_repo_files is None:
                repo_listing_failed = True
                logger.debug("Hugging Face repo listing failed for %s: %s", repo_id, repo_listing_error)
                repo_files = []
            else:
                repo_listing_failed = False
                repo_files = listed_repo_files

        # Find model files in the repository (using centralized model extensions)
        model_extensions = _get_model_extensions()
        model_files = [f for f in repo_files if any(f.endswith(ext) for ext in model_extensions)]

        # Download strategy:
        # - When cache_dir is provided: Use local_dir to place files directly there (safer)
        # - When cache_dir is None: Use HF's default caching mechanism (avoid interfering)

        download_kwargs: dict[str, Any] = {
            "repo_id": repo_id,
            "tqdm_class": None,  # Use default tqdm
        }

        if cache_dir is not None:
            # User provided cache directory - use local_dir for direct placement
            download_kwargs["local_dir"] = str(download_path)
        else:
            # No cache directory provided - let HF use its default cache
            # This is safer as it doesn't risk deleting user's global cache
            pass

        # If we found specific model files, download them
        if model_files:
            revision = _ensure_huggingface_selection_within_max_size(
                repo_id,
                model_files,
                max_size,
                resolved_revision=budget_revision,
            )
            download_kwargs["allow_patterns"] = _build_literal_allow_patterns(model_files)
            if revision is not None:
                download_kwargs["revision"] = revision
        elif repo_listing_failed:
            if max_size is not None:
                raise Exception(
                    f"Cannot enforce max-size for {repo_id}: repository listing failed: {repo_listing_error}"
                )
            extension_allow_patterns = _build_extension_allow_patterns()
            if not extension_allow_patterns:
                raise Exception(
                    f"Refusing to download full snapshot for {repo_id}: no selective allowlist patterns available"
                )
            download_kwargs["allow_patterns"] = extension_allow_patterns
        else:
            if max_size is not None and not repo_files:
                raise Exception(f"Cannot download {repo_id}: repository contains no files")
            revision = _ensure_huggingface_selection_within_max_size(
                repo_id,
                repo_files,
                max_size,
                resolved_revision=budget_revision,
            )
            if revision is not None:
                download_kwargs["revision"] = revision
                download_kwargs["allow_patterns"] = _build_literal_allow_patterns(repo_files)

        if "allow_patterns" in download_kwargs:
            local_path = snapshot_download(**download_kwargs)  # type: ignore[call-arg]
        else:
            # Fallback: download everything if no model files identified
            local_path = snapshot_download(**download_kwargs)  # type: ignore[call-arg]

        # Verify we actually got model files
        downloaded_path = Path(local_path)
        model_extensions = _get_model_extensions()
        found_models = any(downloaded_path.glob(f"*{ext}") for ext in model_extensions)

        if not found_models and not any(downloaded_path.glob("config.json")):
            # If no model files and no config, warn the user
            import warnings

            warnings.warn(
                f"No model files found in {repo_id}. "
                "The repository may not contain model weights or uses an unsupported format.",
                UserWarning,
                stacklevel=2,
            )

        return Path(local_path)
    except Exception as e:
        # Clean up directory on failure only if we created a custom cache directory
        # When cache_dir is None, we use HF's default cache and shouldn't clean it up
        if (
            cache_dir is not None
            and download_path is not None
            and not download_path_preexisting
            and download_path.exists()
            and _is_within_directory(cache_dir / "huggingface", download_path)
        ):
            import shutil

            shutil.rmtree(download_path)
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_model_streaming(
    url: str,
    cache_dir: Path | None = None,
    show_progress: bool = True,
    max_size: int | None = None,
) -> Iterator[tuple[Path, bool]]:
    """Download a model from HuggingFace one file at a time (streaming mode).

    This generator yields (file_path, is_last_file) tuples as each file is downloaded.
    Designed for streaming workflows to minimize disk usage.

    Args:
        url: HuggingFace model URL
        cache_dir: Optional cache directory for downloads
        show_progress: Whether to show download progress
        max_size: Optional maximum total selected download size in bytes

    Yields:
        Tuple of (Path, bool) - (downloaded file path, is_last_file flag)

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    namespace, repo_name = parse_huggingface_url(url)
    repo_id = f"{namespace}/{repo_name}" if repo_name else namespace
    display_url = redact_huggingface_url_for_display(url)

    try:
        # List all files in the repository
        import os

        from huggingface_hub.utils import disable_progress_bars, enable_progress_bars

        # Configure progress display
        if not show_progress:
            disable_progress_bars()
        else:
            enable_progress_bars()
            os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "0"

        # Resolve capped listings and transfers against one immutable revision.
        budget_revision = None
        if max_size is not None:
            try:
                repo_files, budget_revision = _list_huggingface_repo_files_at_revision(repo_id)
            except Exception as exc:
                raise Exception(f"Cannot enforce max-size for {repo_id}: repository listing failed: {exc}") from exc
        else:
            listed_repo_files, repo_listing_error = _list_repo_files_with_timeout(repo_id)
            if listed_repo_files is None:
                if repo_listing_error and repo_listing_error.startswith("timed out after"):
                    raise Exception(f"Timeout listing files in repository {repo_id}")
                raise Exception(f"Failed listing files in repository {repo_id}: {repo_listing_error}")
            repo_files = listed_repo_files

        # Filter for model files
        model_extensions = _get_model_extensions()
        model_files = [f for f in repo_files if any(f.endswith(ext) for ext in model_extensions)]

        if not model_files:
            # Fallback: download all files if no recognized extensions found
            # This maintains parity with download_model() behavior
            model_files = repo_files
        revision = _ensure_huggingface_selection_within_max_size(
            repo_id,
            model_files,
            max_size,
            resolved_revision=budget_revision,
        )

        # Setup cache directory
        download_path = None
        if cache_dir is not None:
            download_path = _build_huggingface_download_path(cache_dir, namespace, repo_name)
            download_path.mkdir(parents=True, exist_ok=True)

        # Download each file one at a time
        total_files = len(model_files)
        for idx, filename in enumerate(model_files):
            is_last = idx == total_files - 1

            # Download single file
            download_kwargs: dict[str, Any] = {
                "repo_id": repo_id,
                "filename": filename,
            }
            if revision is not None:
                download_kwargs["revision"] = revision
            if cache_dir is not None and download_path is not None:
                # Use specific cache dir for local placement
                download_kwargs["cache_dir"] = str(cache_dir / "huggingface")
                download_kwargs["local_dir"] = str(download_path)
                local_path = hf_hub_download(**download_kwargs)
            else:
                # Use HF default cache
                local_path = hf_hub_download(**download_kwargs)

            yield (Path(local_path), is_last)

    except Exception as e:
        raise Exception(
            f"Failed to download model from {display_url}: {redact_huggingface_urls_in_text(str(e))}"
        ) from e


def download_file_from_hf(url: str, cache_dir: Path | None = None, max_size: int | None = None) -> Path:
    """Download a single file from HuggingFace using direct file URL.

    Args:
        url: Direct HuggingFace file URL (e.g., https://huggingface.co/user/repo/resolve/main/file.bin)
        cache_dir: Optional cache directory for downloads
        max_size: Optional maximum download size in bytes

    Returns:
        Path to the downloaded file

    Raises:
        ValueError: If URL is invalid
        Exception: If download fails
    """
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        raise ImportError(
            "huggingface-hub package is required for HuggingFace URL support. "
            "Install with 'pip install modelaudit[huggingface]'"
        ) from e

    repo_id, branch, filename = parse_huggingface_file_url(url)
    display_url = redact_huggingface_url_for_display(url)

    try:
        resolved_revision = _ensure_huggingface_selection_within_max_size(
            repo_id,
            [filename],
            max_size,
            requested_revision=branch,
        )
        # Use hf_hub_download for single file downloads
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            revision=resolved_revision or branch,
            cache_dir=str(cache_dir) if cache_dir else None,
        )
        return Path(local_path)
    except Exception as e:
        raise Exception(f"Failed to download file from {display_url}: {redact_huggingface_urls_in_text(str(e))}") from e
