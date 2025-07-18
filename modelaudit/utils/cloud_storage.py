import asyncio
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import click
from yaspin import yaspin


def is_cloud_url(url: str) -> bool:
    """Return True if the URL points to a supported cloud storage provider."""
    patterns = [
        r"^s3://.+",
        r"^gs://.+",
        r"^gcs://.+",
        r"^r2://.+",
        r"^https?://[^/]+\.s3\.amazonaws\.com/.+",
        r"^https?://storage.googleapis.com/.+",
        r"^https?://[^/]+\.r2\.cloudflarestorage\.com/.+",
    ]
    return any(re.match(p, url) for p in patterns)


def get_fs_protocol(url: str) -> str:
    """Get the fsspec protocol for a given URL."""
    parsed = urlparse(url)
    scheme = parsed.scheme

    if scheme in {"http", "https"}:
        if parsed.netloc.endswith(".s3.amazonaws.com"):
            return "s3"
        elif parsed.netloc == "storage.googleapis.com":
            return "gcs"
        elif parsed.netloc.endswith(".r2.cloudflarestorage.com"):
            return "s3"
        else:
            raise ValueError(f"Unsupported cloud storage URL: {url}")
    elif scheme == "gcs" or scheme == "gs":
        return "gcs"
    elif scheme in {"s3", "r2"}:
        return "s3"
    else:
        raise ValueError(f"Unsupported cloud storage URL: {url}")


def estimate_download_time(size_bytes: int, bandwidth_mbps: float = 10.0) -> str:
    """Estimate download time based on file size and bandwidth."""
    if size_bytes == 0:
        return "instant"

    # Convert to seconds
    bandwidth_bps = bandwidth_mbps * 1_000_000 / 8  # Convert Mbps to bytes/second
    seconds = size_bytes / bandwidth_bps

    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


async def analyze_cloud_target(url: str) -> dict[str, Any]:
    """Analyze cloud target before downloading."""
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. Install with 'pip install modelaudit[cloud]'"
        ) from e

    fs_protocol = get_fs_protocol(url)
    # Use anonymous access for public buckets
    fs = fsspec.filesystem(fs_protocol, token="anon") if fs_protocol == "gcs" else fsspec.filesystem(fs_protocol)

    try:
        # Get info about the target
        info = fs.info(url)

        # Check if it's a file or directory
        if info.get("type") == "file" or (info.get("type") != "directory" and "size" in info):
            return {
                "type": "file",
                "size": info.get("size", 0),
                "name": Path(url).name,
                "estimated_time": estimate_download_time(info.get("size", 0)),
                "human_size": format_size(info.get("size", 0)),
            }
        else:
            # It's a directory, list contents
            files = []
            total_size = 0

            # List all files recursively
            # Ensure URL ends with / for proper globbing
            glob_pattern = f"{url.rstrip('/')}/**"
            for item in fs.glob(glob_pattern):
                try:
                    item_info = fs.info(item)
                    if item_info.get("type") == "file" or "size" in item_info:
                        size = item_info.get("size", 0)
                        files.append(
                            {"path": item, "name": Path(item).name, "size": size, "human_size": format_size(size)}
                        )
                        total_size += size
                except Exception:
                    continue

            return {
                "type": "directory",
                "file_count": len(files),
                "total_size": total_size,
                "human_size": format_size(total_size),
                "files": files,
                "estimated_time": estimate_download_time(total_size),
            }
    except Exception as e:
        # If we can't get info, assume it's a file
        return {"type": "unknown", "error": str(e)}


def prompt_for_large_download(metadata: dict[str, Any]) -> bool:
    """Prompt user before large downloads."""
    size = metadata.get("total_size", metadata.get("size", 0))

    if size > 1_000_000_000:  # 1GB
        click.echo("\n⚠️  Large download detected:")
        click.echo(f"   Size: {metadata['human_size']}")
        click.echo(f"   Estimated time: {metadata['estimated_time']}")

        if metadata["type"] == "directory":
            click.echo(f"   Files: {metadata['file_count']} files")

        return click.confirm("\nContinue with download?", default=False)

    return True


class GCSCache:
    """Smart caching system for cloud downloads."""

    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir is None:
            self.cache_dir = Path.home() / ".modelaudit" / "cache"
        else:
            self.cache_dir = Path(cache_dir)

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> dict[str, Any]:
        """Load cache metadata from disk."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_metadata(self):
        """Save cache metadata to disk."""
        with open(self.metadata_file, "w") as f:
            json.dump(self.metadata, f, indent=2)

    def get_cache_key(self, url: str) -> str:
        """Generate cache key for URL."""
        return hashlib.sha256(url.encode()).hexdigest()

    def get_cached_path(self, url: str, etag: Optional[str] = None) -> Optional[Path]:
        """Return cached file if still valid."""
        cache_key = self.get_cache_key(url)

        if cache_key in self.metadata:
            cached = self.metadata[cache_key]
            cached_path = Path(cached["path"])

            # Check if file still exists
            if not cached_path.exists():
                del self.metadata[cache_key]
                self._save_metadata()
                return None

            # Check if etag matches (if provided)
            if etag and cached.get("etag") != etag:
                return None

            # Update last accessed time
            cached["last_accessed"] = datetime.now().isoformat()
            self._save_metadata()

            return cached_path

        return None

    def cache_file(self, url: str, local_path: Path, etag: Optional[str] = None):
        """Cache downloaded file with metadata."""
        cache_key = self.get_cache_key(url)

        # Create cache subdirectory
        cache_subdir = self.cache_dir / cache_key[:2] / cache_key[2:4]
        cache_subdir.mkdir(parents=True, exist_ok=True)

        # Determine cache path
        if local_path.is_file():
            cache_path = cache_subdir / local_path.name
            # Don't copy if it's already in the cache directory
            if not str(local_path).startswith(str(self.cache_dir)):
                shutil.copy2(local_path, cache_path)
            else:
                cache_path = local_path
        else:
            # It's a directory
            cache_path = cache_subdir / "content"
            # Don't copy if it's already in the cache directory
            if not str(local_path).startswith(str(self.cache_dir)):
                if cache_path.exists():
                    shutil.rmtree(cache_path)
                shutil.copytree(local_path, cache_path)
            else:
                cache_path = local_path

        # Update metadata
        self.metadata[cache_key] = {
            "url": url,
            "path": str(cache_path),
            "etag": etag,
            "size": cache_path.stat().st_size if cache_path.is_file() else 0,
            "cached_at": datetime.now().isoformat(),
            "last_accessed": datetime.now().isoformat(),
        }
        self._save_metadata()

    def clean_old_cache(self, max_age_days: int = 7):
        """Clean cache entries older than max_age_days."""
        now = datetime.now()
        keys_to_remove = []

        for key, cached in self.metadata.items():
            last_accessed = datetime.fromisoformat(cached["last_accessed"])
            if now - last_accessed > timedelta(days=max_age_days):
                # Remove cached file
                cached_path = Path(cached["path"])
                if cached_path.exists():
                    if cached_path.is_file():
                        cached_path.unlink()
                    else:
                        shutil.rmtree(cached_path)
                keys_to_remove.append(key)

        # Update metadata
        for key in keys_to_remove:
            del self.metadata[key]

        if keys_to_remove:
            self._save_metadata()
            click.echo(f"Cleaned {len(keys_to_remove)} old cache entries")


def filter_scannable_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter files to only include scannable model types."""
    SCANNABLE_EXTENSIONS = {
        ".pkl",
        ".pickle",
        ".joblib",
        ".pt",
        ".pth",
        ".h5",
        ".hdf5",
        ".keras",
        ".onnx",
        ".pb",
        ".pbtxt",
        ".tflite",
        ".lite",
        ".safetensors",
        ".msgpack",
        ".bin",
        ".ckpt",
        ".pdmodel",
        ".pdparams",
        ".pdopt",
        ".ot",
        ".ort",
        ".gguf",
        ".ggml",
        ".pmml",
        ".mar",
        ".model",
        ".mlmodel",
        ".ov",
    }

    scannable = []
    for file in files:
        path = Path(file["path"])
        if path.suffix.lower() in SCANNABLE_EXTENSIONS:
            scannable.append(file)

    return scannable


def download_from_cloud(
    url: str,
    cache_dir: Optional[Path] = None,
    max_size: Optional[int] = None,
    use_cache: bool = True,
    show_progress: bool = True,
    selective: bool = True,
) -> Path:
    """Download a file or directory from cloud storage to a local path."""
    try:
        import fsspec
    except ImportError as e:
        raise ImportError(
            "fsspec package is required for cloud storage URL support. Install with 'pip install modelaudit[cloud]'"
        ) from e

    # Initialize cache
    cache = GCSCache(cache_dir) if use_cache else None

    # Check cache first
    if cache:
        cached_path = cache.get_cached_path(url)
        if cached_path:
            if show_progress:
                click.echo(f"✓ Using cached version from {cached_path}")
            return cached_path

    # Analyze target
    metadata = asyncio.run(analyze_cloud_target(url))

    # Check size limits
    size = metadata.get("total_size", metadata.get("size", 0))
    if max_size and size > max_size:
        raise ValueError(f"File size ({format_size(size)}) exceeds maximum allowed size ({format_size(max_size)})")

    # Show warning for large files
    if size > 100_000_000 and show_progress:  # 100MB
        click.echo(f"⚠️  Downloading {metadata['human_size']} (estimated time: {metadata['estimated_time']})")

    # Create download directory
    if cache and cache_dir:
        # When using cache, download directly to cache location
        cache_key = cache.get_cache_key(url)
        cache_subdir = cache.cache_dir / cache_key[:2] / cache_key[2:4]
        cache_subdir.mkdir(parents=True, exist_ok=True)
        download_path = cache_subdir
    elif cache_dir is None:
        download_path = Path(tempfile.mkdtemp(prefix="modelaudit_cloud_"))
    else:
        download_path = Path(cache_dir)
        download_path.mkdir(parents=True, exist_ok=True)

    # Get filesystem
    fs_protocol = get_fs_protocol(url)
    # Use anonymous access for public buckets
    fs = fsspec.filesystem(fs_protocol, token="anon") if fs_protocol == "gcs" else fsspec.filesystem(fs_protocol)

    # Download based on type
    if metadata["type"] == "directory":
        # Handle directory download
        files = metadata.get("files", [])

        if selective:
            # Filter to only scannable files
            files = filter_scannable_files(files)
            if show_progress:
                click.echo(f"Found {len(files)} scannable files out of {metadata['file_count']} total files")

        if not files:
            raise ValueError("No scannable model files found in directory")

        # Download files
        for file_info in files:
            file_url = file_info["path"]
            relative_path = file_url.replace(url.rstrip("/") + "/", "")
            local_path = download_path / relative_path
            local_path.parent.mkdir(parents=True, exist_ok=True)

            if show_progress:
                click.echo(f"Downloading {file_info['name']} ({file_info['human_size']})")

            fs.get(file_url, str(local_path))
    else:
        # Single file download
        file_name = Path(url).name
        local_file = download_path / file_name

        if show_progress and size > 10_000_000:  # Show progress for files > 10MB
            with yaspin(text=f"Downloading {file_name}") as spinner:
                fs.get(url, str(local_file))
                spinner.ok("✓")
        else:
            fs.get(url, str(local_file))

    # Cache the download
    if cache:
        cache.cache_file(url, download_path)

    return download_path
