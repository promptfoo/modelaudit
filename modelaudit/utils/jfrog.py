"""Utilities for handling JFrog Artifactory downloads and folder operations."""

import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click
import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables from .env file if it exists
load_dotenv()


def is_jfrog_url(url: str) -> bool:
    """Check if a URL points to a JFrog Artifactory file or folder."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    return parsed.netloc.endswith(".jfrog.io") or "/artifactory/" in parsed.path


def download_artifact(
    url: str,
    cache_dir: Path | None = None,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
) -> Path:
    """
    Download an artifact from JFrog Artifactory with proper authentication.

    Authentication methods (in order of precedence):
    1. API Token via X-JFrog-Art-Api header (recommended)
    2. Access Token via Authorization: Bearer header
    3. Environment variables: JFROG_API_TOKEN, JFROG_ACCESS_TOKEN
    4. .env file variables: JFROG_API_TOKEN, JFROG_ACCESS_TOKEN

    Args:
        url: JFrog Artifactory URL to download from
        cache_dir: Optional directory to cache the download
        api_token: JFrog API token (recommended)
        access_token: JFrog access token
        timeout: Request timeout in seconds

    Returns:
        Path to the downloaded file

    Raises:
        ValueError: If URL is not a valid JFrog URL
        requests.HTTPError: If authentication fails or download fails
        Exception: For other download errors
    """
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {url}")

    filename = os.path.basename(urlparse(url).path)
    if cache_dir is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_"))
        dest_path = temp_dir / filename
    else:
        temp_dir = cache_dir
        dest_path = cache_dir / filename
        dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Prepare authentication headers
    headers = {}

    # 1. Check for API token (highest precedence)
    if api_token:
        headers["X-JFrog-Art-Api"] = api_token
    else:
        env_api_token = os.getenv("JFROG_API_TOKEN")
        if env_api_token:
            headers["X-JFrog-Art-Api"] = env_api_token

    # 2. Check for access token (only if API token not found)
    if "X-JFrog-Art-Api" not in headers:
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        else:
            env_access_token = os.getenv("JFROG_ACCESS_TOKEN")
            if env_access_token:
                headers["Authorization"] = f"Bearer {env_access_token}"

    # If no authentication is provided, proceed without auth (for public repos)
    if not headers:
        message = "No JFrog authentication provided. Attempting anonymous access."
        try:
            ctx = click.get_current_context(silent=True)
            if ctx:
                click.echo(f"⚠️  {message}")
            else:
                logger.warning(message)
        except Exception:
            logger.warning(message)

    try:
        # Use requests for proper authentication and error handling
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            stream=True,  # Stream for large files
        )

        # Raise an exception for HTTP error responses
        response.raise_for_status()

        # Download the file in chunks
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:  # Filter out keep-alive chunks
                    f.write(chunk)

        return dest_path

    except requests.exceptions.HTTPError as e:  # type: ignore[attr-defined]
        if cache_dir is None and temp_dir.exists():
            shutil.rmtree(temp_dir)
        if e.response.status_code == 401:
            raise Exception(
                f"Authentication failed for JFrog URL {url}. Please provide a valid API token or access token."
            ) from e
        if e.response.status_code == 403:
            raise Exception(f"Access denied for JFrog URL {url}. Please check your permissions.") from e
        if e.response.status_code == 404:
            raise Exception(f"Artifact not found at {url}") from e

        raise Exception(f"HTTP error {e.response.status_code} downloading from {url}: {e}") from e
    except requests.exceptions.RequestException as e:  # type: ignore[attr-defined]
        if cache_dir is None and temp_dir.exists():
            shutil.rmtree(temp_dir)
        raise Exception(f"Network error downloading from {url}: {e}") from e
    except Exception as e:
        if cache_dir is None and temp_dir.exists():
            shutil.rmtree(temp_dir)
        raise Exception(f"Failed to download artifact from {url}: {e!s}") from e


def get_jfrog_base_url(url: str) -> str:
    """Extract the base JFrog URL from an artifact URL."""
    parsed = urlparse(url)

    # Find the artifactory part in the path
    path_parts = parsed.path.split("/")
    try:
        artifactory_index = path_parts.index("artifactory")
        # Base URL includes scheme, netloc, and path up to artifactory
        base_path = "/".join(path_parts[: artifactory_index + 1])
        return f"{parsed.scheme}://{parsed.netloc}{base_path}"
    except ValueError as e:
        raise ValueError(f"Invalid JFrog Artifactory URL format: {url}") from e


def get_storage_api_url(url: str) -> str:
    """Convert a JFrog artifact URL to its Storage API equivalent."""
    parsed = urlparse(url)
    path_parts = parsed.path.split("/")

    try:
        artifactory_index = path_parts.index("artifactory")
        # Replace 'artifactory' with 'api/storage' in the path
        api_parts = [*path_parts[:artifactory_index], "api", "storage", *path_parts[artifactory_index + 1 :]]
        api_path = "/".join(api_parts)
        return f"{parsed.scheme}://{parsed.netloc}{api_path}"
    except (ValueError, IndexError) as e:
        raise ValueError(f"Invalid JFrog Artifactory URL format: {url}") from e


def format_size(size_bytes: int) -> str:
    """Format size in human-readable format."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


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
        ".pdiparams",
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
        ".tar",
        ".tar.gz",
        ".tgz",
    }
    scannable = []
    for file in files:
        path = Path(file["path"])
        suffixes = [s.lower() for s in path.suffixes]
        for i in range(1, len(suffixes) + 1):
            if "".join(suffixes[-i:]) in SCANNABLE_EXTENSIONS:
                scannable.append(file)
                break
    return scannable


def detect_jfrog_target_type(
    url: str, api_token: str | None = None, access_token: str | None = None, timeout: int = 30
) -> dict[str, Any]:
    """Detect if a JFrog URL points to a file or folder using Storage API.

    Args:
        url: JFrog Artifactory URL
        api_token: JFrog API token
        access_token: JFrog access token
        timeout: Request timeout in seconds

    Returns:
        Dictionary with target info: {"type": "file"|"folder", "children": [...]}

    Raises:
        ValueError: If URL is not a valid JFrog URL
        Exception: If API request fails
    """
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {url}")

    storage_api_url = get_storage_api_url(url)

    # Prepare authentication headers
    headers = {}
    if api_token:
        headers["X-JFrog-Art-Api"] = api_token
    elif access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    else:
        # Check environment variables
        env_api_token = os.getenv("JFROG_API_TOKEN")
        if env_api_token:
            headers["X-JFrog-Art-Api"] = env_api_token
        else:
            env_access_token = os.getenv("JFROG_ACCESS_TOKEN")
            if env_access_token:
                headers["Authorization"] = f"Bearer {env_access_token}"

    try:
        response = requests.get(storage_api_url, headers=headers, timeout=timeout)
        response.raise_for_status()

        data = response.json()

        # If it has children, it's a folder
        if "children" in data:
            return {
                "type": "folder",
                "children": data["children"],
                "path": data.get("path", ""),
                "repo": data.get("repo", ""),
            }
        else:
            # It's a file
            return {
                "type": "file",
                "size": data.get("size", 0),
                "path": data.get("path", ""),
                "repo": data.get("repo", ""),
            }

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            raise Exception(f"JFrog artifact not found at {url}") from e
        elif e.response.status_code in {401, 403}:
            raise Exception(f"Authentication failed for JFrog URL {url}. Please provide valid credentials.") from e
        else:
            raise Exception(f"HTTP error {e.response.status_code} accessing {storage_api_url}: {e}") from e
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error accessing {storage_api_url}: {e}") from e


def list_jfrog_folder_contents(
    url: str,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    recursive: bool = True,
    selective: bool = True,
) -> list[dict[str, Any]]:
    """Recursively list all files in a JFrog folder.

    Args:
        url: JFrog folder URL
        api_token: JFrog API token
        access_token: JFrog access token
        timeout: Request timeout in seconds
        recursive: Whether to traverse subfolders
        selective: Whether to filter only scannable model files

    Returns:
        List of file dictionaries with keys: name, path, size, human_size

    Raises:
        ValueError: If URL is not a JFrog folder
        Exception: If API requests fail
    """
    target_info = detect_jfrog_target_type(url, api_token, access_token, timeout)

    if target_info["type"] != "folder":
        raise ValueError(f"URL is not a JFrog folder: {url}")

    files = []
    base_url = url.rstrip("/")

    def _collect_files(folder_url: str, depth: int = 0) -> None:
        """Recursively collect files from folder."""
        if depth > 10:  # Prevent infinite recursion
            logger.warning(f"Maximum recursion depth reached for {folder_url}")
            return

        try:
            folder_info = detect_jfrog_target_type(folder_url, api_token, access_token, timeout)

            if folder_info["type"] != "folder":
                return

            for child in folder_info["children"]:
                child_name = child["uri"].lstrip("/")
                child_url = f"{folder_url.rstrip('/')}/{child_name}"

                if child["folder"]:
                    # It's a subfolder
                    if recursive:
                        _collect_files(child_url, depth + 1)
                else:
                    # It's a file
                    size = child.get("size", 0)
                    files.append(
                        {
                            "name": child_name,
                            "path": child_url,
                            "size": size,
                            "human_size": format_size(size),
                        }
                    )

        except Exception as e:
            logger.warning(f"Failed to list contents of {folder_url}: {e}")

    _collect_files(base_url)

    if selective:
        files = filter_scannable_files(files)

    return files


def download_jfrog_folder(
    url: str,
    cache_dir: Path | None = None,
    api_token: str | None = None,
    access_token: str | None = None,
    timeout: int = 30,
    selective: bool = True,
    show_progress: bool = True,
) -> Path:
    """Download all files from a JFrog folder.

    Args:
        url: JFrog folder URL
        cache_dir: Directory to download files to
        api_token: JFrog API token
        access_token: JFrog access token
        timeout: Request timeout in seconds
        selective: Whether to filter only scannable model files
        show_progress: Whether to show download progress

    Returns:
        Path to directory containing downloaded files

    Raises:
        ValueError: If URL is not a valid JFrog folder
        Exception: If downloads fail
    """
    if not is_jfrog_url(url):
        raise ValueError(f"Not a JFrog URL: {url}")

    # List all files in the folder
    files = list_jfrog_folder_contents(url, api_token, access_token, timeout, recursive=True, selective=selective)

    if not files:
        raise ValueError("No scannable model files found in JFrog folder")

    # Create download directory
    if cache_dir is None:
        download_dir = Path(tempfile.mkdtemp(prefix="modelaudit_jfrog_folder_"))
    else:
        download_dir = cache_dir
        download_dir.mkdir(parents=True, exist_ok=True)

    if show_progress:
        total_size = sum(f["size"] for f in files)
        click.echo(f"Found {len(files)} scannable files ({format_size(total_size)}) in JFrog folder")

    # Download each file
    base_url_parsed = urlparse(url)
    base_path_parts = base_url_parsed.path.strip("/").split("/")

    try:
        artifactory_index = base_path_parts.index("artifactory")
        base_repo_path = "/".join(base_path_parts[artifactory_index + 1 :])
    except (ValueError, IndexError):
        base_repo_path = ""

    for file_info in files:
        try:
            if show_progress:
                click.echo(f"Downloading {file_info['name']} ({file_info['human_size']})")

            # Calculate relative path for local storage
            file_url_parsed = urlparse(file_info["path"])
            file_path_parts = file_url_parsed.path.strip("/").split("/")

            try:
                file_artifactory_index = file_path_parts.index("artifactory")
                file_repo_path = "/".join(file_path_parts[file_artifactory_index + 1 :])

                if base_repo_path and file_repo_path.startswith(base_repo_path + "/"):
                    relative_path = file_repo_path[len(base_repo_path) + 1 :]
                elif base_repo_path and file_repo_path == base_repo_path:
                    relative_path = Path(file_info["name"]).name
                else:
                    relative_path = Path(file_info["name"]).name
            except (ValueError, IndexError):
                relative_path = Path(file_info["name"]).name

            local_file = download_dir / relative_path
            local_file.parent.mkdir(parents=True, exist_ok=True)

            # Download the individual file
            download_artifact(
                file_info["path"],
                cache_dir=local_file.parent,
                api_token=api_token,
                access_token=access_token,
                timeout=timeout,
            )

            # Move to correct location if needed
            downloaded_file = local_file.parent / Path(file_info["path"]).name
            if downloaded_file != local_file and downloaded_file.exists():
                if local_file.exists():
                    local_file.unlink()
                downloaded_file.rename(local_file)

        except Exception as e:
            logger.warning(f"Failed to download {file_info['name']}: {e}")
            continue

    return download_dir
