"""Smart detection utilities for CLI flag consolidation."""

import os
import sys
from pathlib import Path
from typing import Any


def detect_input_type(path: str) -> str:
    """Detect the type of input path.

    Returns:
        One of: 'cloud_s3', 'cloud_gcs', 'cloud_azure', 'huggingface', 'pytorch_hub',
                'mlflow', 'jfrog', 'local_file', 'local_directory'
    """
    # Cloud storage detection
    if path.startswith(("s3://", "gs://", "az://")) or ".blob.core.windows.net" in path:
        if path.startswith("s3://"):
            return "cloud_s3"
        elif path.startswith("gs://"):
            return "cloud_gcs"
        else:
            return "cloud_azure"

    # HuggingFace detection
    if path.startswith(("hf://", "https://huggingface.co/", "https://hf.co/")):
        return "huggingface"

    # PyTorch Hub detection
    if "pytorch.org/hub/" in path:
        return "pytorch_hub"

    # MLflow detection
    if path.startswith("models:/"):
        return "mlflow"

    # JFrog detection
    if ".jfrog.io/" in path or "/artifactory/" in path:
        return "jfrog"

    # Local path detection
    if os.path.exists(path):
        return "local_directory" if os.path.isdir(path) else "local_file"

    # Default to local file for non-existent paths (will be handled by validation)
    return "local_file"


def detect_file_size(path: str) -> int:
    """Detect file size in bytes. Returns 0 if not a local file or can't determine size."""
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        elif os.path.isdir(path):
            # Rough estimate of directory size
            total_size = 0
            for root, _dirs, files in os.walk(path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        total_size += os.path.getsize(file_path)
                    except OSError:
                        continue
            return total_size
    except OSError:
        pass
    return 0


def detect_tty_capabilities() -> dict[str, bool]:
    """Detect terminal capabilities for UI decisions."""
    return {
        "is_tty": sys.stdout.isatty(),
        "colors_supported": sys.stdout.isatty() and not os.getenv("NO_COLOR"),
        "spinner_supported": sys.stdout.isatty(),
    }


def detect_ci_environment() -> bool:
    """Detect if running in CI environment."""
    ci_indicators = [
        "CI",
        "CONTINUOUS_INTEGRATION",
        "BUILD_NUMBER",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "TRAVIS",
        "CIRCLECI",
        "BUILDKITE",
    ]
    return any(os.getenv(var) for var in ci_indicators)


def generate_smart_defaults(paths: list[str]) -> dict[str, Any]:
    """Generate smart defaults based on input analysis.

    Args:
        paths: List of input paths to analyze

    Returns:
        Dictionary of smart default settings
    """
    if not paths:
        return {}

    # Analyze all paths
    input_types = [detect_input_type(path) for path in paths]
    file_sizes = [detect_file_size(path) for path in paths]
    max_file_size = max(file_sizes) if file_sizes else 0

    tty_caps = detect_tty_capabilities()
    is_ci = detect_ci_environment()

    # Generate defaults
    use_cache = _should_use_cache(input_types)
    defaults = {
        # Progress settings
        "show_progress": _should_show_progress(input_types, max_file_size, tty_caps, is_ci),
        "large_model_support": max_file_size > (1024 * 1024 * 1024),  # >1GB
        # Caching settings
        "use_cache": use_cache,
        # Download settings
        "selective_download": _should_use_selective_download(input_types),
        "stream_analysis": max_file_size > (10 * 1024 * 1024 * 1024),  # >10GB
        # File processing settings
        "skip_non_model_files": not _has_strict_mode_inputs(input_types),
        # Timeout settings
        "timeout": _calculate_smart_timeout(input_types, max_file_size),
        # Size limits
        "max_file_size": _calculate_smart_size_limit(input_types),
        # Output settings
        "format": "json" if is_ci else "text",
        "colors": tty_caps["colors_supported"] and not is_ci,
        "verbose": False,  # Keep explicit control
    }

    # Only set cache_dir if caching is enabled
    if use_cache:
        defaults["cache_dir"] = _get_default_cache_dir()

    return defaults


def _should_show_progress(input_types: list[str], max_size: int, tty_caps: dict[str, bool], is_ci: bool) -> bool:
    """Determine if progress should be shown by default."""
    if is_ci or not tty_caps["is_tty"]:
        return False

    # Show progress for cloud operations or large files
    has_cloud = any(t.startswith("cloud_") for t in input_types)
    has_remote = any(t in ["huggingface", "pytorch_hub", "mlflow", "jfrog"] for t in input_types)
    is_large = max_size > (100 * 1024 * 1024)  # >100MB

    return has_cloud or has_remote or is_large


def _should_use_cache(input_types: list[str]) -> bool:
    """Determine if caching should be enabled by default."""
    # Enable caching for any remote/cloud operations
    remote_types = ["cloud_s3", "cloud_gcs", "cloud_azure", "huggingface", "pytorch_hub", "mlflow", "jfrog"]
    return any(t in remote_types for t in input_types)


def _get_default_cache_dir() -> str:
    """Get default cache directory."""
    return str(Path.home() / ".modelaudit" / "cache")


def _should_use_selective_download(input_types: list[str]) -> bool:
    """Determine if selective download should be used."""
    # Use selective download for cloud directories and HuggingFace models
    return any(t in ["cloud_s3", "cloud_gcs", "cloud_azure", "huggingface"] for t in input_types)


def _has_strict_mode_inputs(input_types: list[str]) -> bool:
    """Determine if inputs suggest strict mode should be default."""
    # Local directories might have mixed file types, so don't be strict by default
    return any(t == "local_directory" for t in input_types)


def _calculate_smart_timeout(input_types: list[str], max_size: int) -> int:
    """Calculate smart timeout based on input characteristics."""
    base_timeout = 3600  # 1 hour default

    # Increase timeout for cloud operations
    if any(t.startswith("cloud_") for t in input_types):
        base_timeout *= 2  # 2 hours for cloud

    # Increase timeout for very large files
    if max_size > (10 * 1024 * 1024 * 1024):  # >10GB
        base_timeout *= 3  # 3 hours for very large files
    elif max_size > (1 * 1024 * 1024 * 1024):  # >1GB
        base_timeout = int(base_timeout * 1.5)  # 1.5 hours for large files

    return base_timeout


def _calculate_smart_size_limit(input_types: list[str]) -> int:
    """Calculate smart size limits based on input type."""
    # No limit by default (0 = unlimited)
    if any(t.startswith("cloud_") for t in input_types):
        # 50GB limit for cloud to prevent runaway downloads
        return 50 * 1024 * 1024 * 1024

    # No limits for local files
    return 0


def apply_smart_overrides(user_args: dict[str, Any], smart_defaults: dict[str, Any]) -> dict[str, Any]:
    """Apply smart defaults while respecting user overrides.

    Args:
        user_args: User-provided arguments (non-None values)
        smart_defaults: Smart defaults from detection

    Returns:
        Final configuration with smart defaults + user overrides
    """
    config = smart_defaults.copy()

    # Apply user overrides for any non-None values
    for key, value in user_args.items():
        if value is not None:
            config[key] = value

    # If caching is disabled, remove cache_dir to ensure cleanup happens
    if not config.get("use_cache", True):
        config.pop("cache_dir", None)

    return config


def parse_size_string(size_str: str) -> int:
    """Parse size string like '10GB', '500MB' into bytes.

    Args:
        size_str: Size string with optional unit (B, KB, MB, GB, TB)

    Returns:
        Size in bytes

    Raises:
        ValueError: If size string is invalid
    """
    if not size_str:
        return 0

    size_str = size_str.upper().strip()

    # Handle raw numbers (assume bytes)
    if size_str.isdigit():
        return int(size_str)

    # Parse with units (process longest units first to avoid conflicts)
    units = [
        ("TB", 1024**4),
        ("GB", 1024**3),
        ("MB", 1024**2),
        ("KB", 1024),
        ("B", 1),
    ]

    for unit, multiplier in units:
        if size_str.endswith(unit):
            try:
                number_part = size_str[: -len(unit)]
                return int(float(number_part) * multiplier)
            except ValueError:
                break

    raise ValueError(f"Invalid size format: {size_str}. Use format like '10GB', '500MB', etc.")
