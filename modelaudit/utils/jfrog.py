"""Utilities for handling JFrog Artifactory downloads."""

import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import click
import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables from .env file if it exists
load_dotenv()


def is_jfrog_url(url: str) -> bool:
    """Check if a URL points to a JFrog Artifactory file."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    return parsed.netloc.endswith(".jfrog.io") or "/artifactory/" in parsed.path


def download_artifact(
    url: str,
    cache_dir: Optional[Path] = None,
    api_token: Optional[str] = None,
    access_token: Optional[str] = None,
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

    except requests.exceptions.HTTPError as e:
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
    except requests.exceptions.RequestException as e:
        if cache_dir is None and temp_dir.exists():
            shutil.rmtree(temp_dir)
        raise Exception(f"Network error downloading from {url}: {e}") from e
    except Exception as e:
        if cache_dir is None and temp_dir.exists():
            shutil.rmtree(temp_dir)
        raise Exception(f"Failed to download artifact from {url}: {e!s}") from e
