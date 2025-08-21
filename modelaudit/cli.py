import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Optional, cast

import click
from yaspin import yaspin
from yaspin.spinners import Spinners

from . import __version__
from .auth.client import auth_client
from .auth.config import cloud_config, config, get_user_email, is_delegated_from_promptfoo, set_user_email
from .core import determine_exit_code, scan_model_directory_or_file
from .interrupt_handler import interruptible_scan
from .jfrog_integration import scan_jfrog_artifact
from .utils import resolve_dvc_file
from .utils.cloud_storage import download_from_cloud, is_cloud_url
from .utils.huggingface import download_model, is_huggingface_url
from .utils.jfrog import is_jfrog_url
from .utils.pytorch_hub import download_pytorch_hub_model, is_pytorch_hub_url

logger = logging.getLogger("modelaudit")


def should_use_color() -> bool:
    """Check if colors should be used in output."""
    # Respect NO_COLOR environment variable
    if os.getenv("NO_COLOR"):
        return False
    # Only use colors if output is a TTY
    return sys.stdout.isatty()


def should_show_spinner() -> bool:
    """Check if spinners should be shown."""
    # Only show spinners if output is a TTY
    return sys.stdout.isatty()


def style_text(text: str, **kwargs) -> str:
    """Style text only if colors are enabled."""
    if should_use_color():
        return click.style(text, **kwargs)
    return text


def is_mlflow_uri(path: str) -> bool:
    """Check if a path is an MLflow model URI."""
    return path.startswith("models:/")


class DefaultCommandGroup(click.Group):
    """Custom group that makes 'scan' the default command"""

    def get_command(self, ctx, cmd_name):
        """Get command by name, return None if not found"""
        # Simply delegate to parent's get_command - no default logic here
        return click.Group.get_command(self, ctx, cmd_name)

    def resolve_command(self, ctx, args):
        """Resolve command, using 'scan' as default when paths are provided"""
        # If we have args and the first arg is not a known command, use 'scan' as default
        if args and args[0] not in self.list_commands(ctx):
            # Insert 'scan' at the beginning
            args = ["scan", *list(args)]

        return super().resolve_command(ctx, args)

    def format_help(self, ctx, formatter):
        """Show help with both commands but emphasize scan as primary"""
        formatter.write_text("ModelAudit - Security scanner for ML model files")
        formatter.write_paragraph()

        formatter.write_text("Usage:")
        with formatter.indentation():
            formatter.write_text("modelaudit [OPTIONS] PATHS...  # Scan files (default command)")
            formatter.write_text("modelaudit scan [OPTIONS] PATHS...  # Explicit scan command")

        formatter.write_paragraph()
        formatter.write_text("Examples:")
        with formatter.indentation():
            formatter.write_text("modelaudit model.pkl")
            formatter.write_text("modelaudit /path/to/models/")
            formatter.write_text("modelaudit https://huggingface.co/user/model")
            formatter.write_text("modelaudit https://pytorch.org/hub/pytorch_vision_resnet/")

        formatter.write_paragraph()
        formatter.write_text("Other commands:")
        with formatter.indentation():
            formatter.write_text("modelaudit doctor  # Diagnose scanner compatibility")

        formatter.write_paragraph()
        formatter.write_text("For detailed help on scanning:")
        with formatter.indentation():
            formatter.write_text("modelaudit scan --help")

        formatter.write_paragraph()
        formatter.write_text("Options:")
        self.format_options(ctx, formatter)


@click.group(cls=DefaultCommandGroup)
@click.version_option(__version__)
def cli() -> None:
    """Static scanner for ML models"""
    pass


@cli.group()
def auth():
    """Manage authentication"""
    pass


@auth.command()
@click.option("-o", "--org", "org_id", help="The organization id to login to.")
@click.option(
    "-h",
    "--host",
    help="The host of the promptfoo instance. This needs to be the url of the API if different from the app url.",
)
@click.option("-k", "--api-key", help="Login using an API key.")
def login(org_id, host, api_key):
    """Login"""
    try:
        token = None
        api_host = host or cloud_config.get_api_host()

        # Record telemetry (stub for now)
        # telemetry.record('command_used', {'name': 'auth login'})

        if api_key:
            token = api_key
            result = auth_client.validate_and_set_api_token(token, api_host)
            user = result["user"]

            # Store token in global config and handle email sync
            existing_email = get_user_email()
            if existing_email and existing_email != user.email:
                click.echo(
                    style_text(f"Updating local email configuration from {existing_email} to {user.email}", fg="yellow")
                )
            set_user_email(user.email)
            click.echo(style_text("Successfully logged in", fg="green"))
            return
        else:
            click.echo(
                f"Please login or sign up at {style_text('https://promptfoo.app', fg='green')} to get an API key."
            )
            click.echo(
                f"After logging in, you can get your api token at "
                f"{style_text('https://promptfoo.app/welcome', fg='green')}"
            )

        return

    except Exception as error:
        error_message = str(error)
        click.echo(f"Authentication failed: {error_message}", err=True)
        sys.exit(1)


@auth.command()
def logout():
    """Logout"""
    email = get_user_email()
    api_key = cloud_config.get_api_key()

    if not email and not api_key:
        click.echo(style_text("You're already logged out - no active session to terminate", fg="yellow"))
        return

    cloud_config.delete()
    # Always unset email on logout
    set_user_email("")
    click.echo(style_text("Successfully logged out", fg="green"))
    return


@auth.command()
def whoami():
    """Show current user information"""
    try:
        email = get_user_email()
        api_key = cloud_config.get_api_key()

        if not email or not api_key:
            click.echo(f"Not logged in. Run {style_text('modelaudit auth login', bold=True)} to login.")
            return

        user_info = auth_client.get_user_info()
        user = user_info.get("user", {})
        organization = user_info.get("organization", {})

        click.echo(style_text("Currently logged in as:", fg="green", bold=True))
        click.echo(f"User: {style_text(user.get('email', 'Unknown'), fg='cyan')}")
        click.echo(f"Organization: {style_text(organization.get('name', 'Unknown'), fg='cyan')}")
        click.echo(f"App URL: {style_text(cloud_config.get_app_url(), fg='cyan')}")

        # Record telemetry (stub for now)
        # telemetry.record('command_used', {'name': 'auth whoami'})

    except Exception as error:
        error_message = str(error)
        click.echo(f"Failed to get user info: {error_message}", err=True)
        sys.exit(1)


@cli.command("delegate-info", hidden=True)
def delegate_info():
    """Internal command to show delegation status"""

    from .auth.config import config

    is_delegated = config.is_delegated()
    auth_source = config.get_auth_source()
    api_key_available = config.is_authenticated()

    info = {"delegated": is_delegated, "auth_source": auth_source, "api_key_available": api_key_available}

    click.echo(json.dumps(info, indent=2))


@cli.command("scan")
@click.argument("paths", nargs=-1, type=str, required=True)
@click.option(
    "--blacklist",
    "-b",
    multiple=True,
    help="Additional blacklist patterns to check against model names",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format [default: text]",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (prints to stdout if not specified)",
)
@click.option(
    "--sbom",
    type=click.Path(),
    help="Write CycloneDX SBOM to the specified file",
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=3600,
    help="Scan timeout in seconds [default: 3600]",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--max-file-size",
    type=int,
    default=0,
    help="Maximum file size to scan in bytes [default: unlimited]",
)
@click.option(
    "--max-total-size",
    type=int,
    default=0,
    help="Maximum total bytes to scan before stopping [default: unlimited]",
)
@click.option(
    "--registry-uri",
    type=str,
    help="MLflow registry URI (only used for MLflow model URIs)",
)
@click.option(
    "--jfrog-api-token",
    type=str,
    help="JFrog API token for authentication (can also use JFROG_API_TOKEN env var or .env file)",
)
@click.option(
    "--jfrog-access-token",
    type=str,
    help="JFrog access token for authentication (can also use JFROG_ACCESS_TOKEN env var or .env file)",
)
@click.option(
    "--max-download-size",
    type=str,
    help="Maximum download size for cloud storage (e.g., 500MB, 2GB)",
)
@click.option(
    "--cache/--no-cache",
    default=True,
    help="Use cache for downloaded cloud storage files [default: cache]",
)
@click.option(
    "--cache-dir",
    type=click.Path(exists=False, file_okay=False, dir_okay=True, resolve_path=True),
    help="Directory for caching downloaded files [default: ~/.modelaudit/cache]",
)
@click.option(
    "--no-skip-files/--skip-files",
    default=False,
    help="Whether to skip non-model file types during directory scans (default: skip)",
)
@click.option(
    "--strict-license",
    is_flag=True,
    help="Fail scan when incompatible or deprecated licenses are detected",
)
@click.option(
    "--preview",
    is_flag=True,
    help="Preview what would be downloaded without actually downloading",
)
@click.option(
    "--selective/--all-files",
    default=True,
    help="Download only scannable files from directories [default: selective]",
)
@click.option(
    "--stream",
    is_flag=True,
    help="Use streaming analysis for large cloud files (experimental)",
)
@click.option(
    "--large-model-support/--no-large-model-support",
    default=True,
    help="Enable optimized scanning for large models (≈10GB+) [default: enabled]",
)
@click.option(
    "--progress/--no-progress",
    default=True,
    help="Enable progress reporting for large model scans [default: enabled]",
)
@click.option(
    "--progress-log",
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
    help="Write progress information to log file",
)
@click.option(
    "--progress-format",
    type=click.Choice(["tqdm", "simple", "json"]),
    default="tqdm",
    help="Progress display format [default: tqdm]",
)
@click.option(
    "--progress-interval",
    type=float,
    default=2.0,
    help="Progress update interval in seconds [default: 2.0]",
)
def scan_command(
    paths: tuple[str, ...],
    blacklist: tuple[str, ...],
    format: str,
    output: Optional[str],
    sbom: Optional[str],
    timeout: int,
    verbose: bool,
    max_file_size: int,
    max_total_size: int,
    registry_uri: Optional[str],
    jfrog_api_token: Optional[str],
    jfrog_access_token: Optional[str],
    max_download_size: Optional[str],
    cache: bool,
    cache_dir: Optional[str],
    no_skip_files: bool,
    strict_license: bool,
    preview: bool,
    selective: bool,
    stream: bool,
    large_model_support: bool,
    progress: bool,
    progress_log: Optional[str],
    progress_format: str,
    progress_interval: float,
) -> None:
    """Scan files, directories, HuggingFace models, MLflow models, cloud storage,
    or JFrog artifacts for security issues.

    \b
    Usage:
        modelaudit scan /path/to/model1 /path/to/model2 ...
        modelaudit scan https://huggingface.co/user/model
        modelaudit scan https://pytorch.org/hub/pytorch_vision_resnet/
        modelaudit scan hf://user/model
        modelaudit scan s3://my-bucket/models/
        modelaudit scan gs://my-bucket/model.pt
        modelaudit scan models:/MyModel/1
        modelaudit scan models:/MyModel/Production
        modelaudit scan https://mycompany.jfrog.io/artifactory/repo/model.pt

    \b
    JFrog Authentication (choose one method):
        --jfrog-api-token      API token (recommended)
        --jfrog-access-token   Access token

    You can also set environment variables or create a .env file:
        JFROG_API_TOKEN, JFROG_ACCESS_TOKEN

    You can specify additional blacklist patterns with ``--blacklist`` or ``-b``:

        modelaudit scan /path/to/model1 /path/to/model2 -b llama -b alpaca

    \b
    Advanced options:
        --format, -f       Output format (text or json)
        --output, -o       Write results to a file instead of stdout
        --sbom             Write CycloneDX SBOM to file
        --timeout, -t      Set scan timeout in seconds
        --verbose, -v      Show detailed information during scanning
        --max-file-size    Maximum file size to scan in bytes
        --max-total-size   Maximum total bytes to scan before stopping
        --registry-uri     MLflow registry URI (for MLflow models only)

    \b
    Exit codes:
        0 - Success, no security issues found
        1 - Security issues found (scan completed successfully)
        2 - Errors occurred during scanning
    """
    # Expand DVC pointer files before scanning
    expanded_paths = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".dvc"):
            targets = resolve_dvc_file(p)
            if targets:
                expanded_paths.extend(targets)
            else:
                expanded_paths.append(p)
        else:
            expanded_paths.append(p)

    # Print a nice header if not in JSON mode and not writing to a file
    if format == "text" and not output:
        # Add delegation indicator if running via promptfoo
        delegation_note = ""
        if is_delegated_from_promptfoo():
            delegation_note = style_text(" (via promptfoo)", dim=True)

        header = [
            "─" * 80,
            style_text("ModelAudit Security Scanner", fg="blue", bold=True) + delegation_note,
            style_text(
                "Scanning for potential security issues in ML model files",
                fg="cyan",
            ),
            "─" * 80,
        ]
        click.echo("\n".join(header))
        click.echo(f"Paths to scan: {style_text(', '.join(expanded_paths), fg='green')}")
        if blacklist:
            click.echo(
                f"Additional blacklist patterns: {style_text(', '.join(blacklist), fg='yellow')}",
            )
        click.echo("─" * 80)
        click.echo("")

    # Set logging level based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("modelaudit.core").setLevel(logging.DEBUG)
    else:
        # Suppress INFO logs from core module in normal mode
        logging.getLogger("modelaudit.core").setLevel(logging.WARNING)

    # Setup progress tracking
    progress_tracker = None
    progress_reporters: list[Any] = []

    if progress and len(expanded_paths) > 0:
        try:
            # Prevent circular imports during scanner loading
            import sys

            if "modelaudit.scanners" in sys.modules:
                if verbose:
                    click.echo("Progress tracking disabled during scanner initialization", err=True)
                progress = False
                progress_tracker = None
            else:
                from .progress import (
                    ConsoleProgressReporter,
                    FileProgressReporter,
                    ProgressPhase,
                    ProgressTracker,
                    SimpleConsoleReporter,
                )

                # Create progress tracker
                progress_tracker = ProgressTracker(
                    update_interval=progress_interval,
                )

            # Add console reporter based on format preference
            if progress_tracker and format == "text" and not output:
                if progress_format == "tqdm":
                    # Use tqdm progress bars if available and appropriate
                    console_reporter = ConsoleProgressReporter(
                        update_interval=progress_interval,
                        disable_on_non_tty=True,
                        show_bytes=True,
                        show_items=True,
                    )
                else:
                    # Use simple console reporter
                    console_reporter = SimpleConsoleReporter(  # type: ignore[assignment]
                        update_interval=progress_interval,
                        show_percentage=True,
                        show_speed=True,
                        show_eta=True,
                    )
                progress_reporters.append(console_reporter)
                progress_tracker.add_reporter(console_reporter)

            # Add file logger if specified
            if progress_tracker and progress_log:
                log_format = "json" if progress_format == "json" else "text"
                file_reporter = FileProgressReporter(
                    log_file=progress_log,
                    update_interval=progress_interval * 2,  # Less frequent for file logging
                    format_type=log_format,
                    append_mode=True,
                )
                progress_reporters.append(file_reporter)
                progress_tracker.add_reporter(file_reporter)

                if verbose:
                    click.echo(f"Progress will be logged to: {progress_log}")

        except (ImportError, RecursionError) as e:
            if verbose:
                if isinstance(e, RecursionError):
                    click.echo("Progress tracking disabled due to import cycle", err=True)
                else:
                    click.echo("Progress tracking not available (missing dependencies)", err=True)
            progress = False

    # Aggregated results
    aggregated_results: dict[str, Any] = {
        "bytes_scanned": 0,
        "issues": [],
        "checks": [],  # Track all security checks performed
        "files_scanned": 0,
        "assets": [],
        "has_errors": False,
        "scanner_names": [],
        "file_metadata": {},  # Track metadata from each file
        "start_time": time.time(),
    }

    # Scan each path with interrupt handling
    with interruptible_scan() as interrupt_handler:
        for path in expanded_paths:
            # Track temp directory for cleanup
            temp_dir = None
            actual_path = path
            should_break = False

            try:
                # Check if this is a HuggingFace URL
                if is_huggingface_url(path):
                    # Show initial message and get model info
                    if format == "text" and not output:
                        click.echo(f"\n📥 Preparing to download from {style_text(path, fg='cyan')}")

                        # Get model info for size preview
                        try:
                            from .utils.huggingface import get_model_info

                            model_info = get_model_info(path)

                            # Format size
                            size_bytes = model_info["total_size"]
                            if size_bytes >= 1024 * 1024 * 1024:
                                size_str = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
                            elif size_bytes >= 1024 * 1024:
                                size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
                            else:
                                size_str = f"{size_bytes / 1024:.2f} KB"

                            click.echo(f"   Model: {model_info['model_id']}")
                            click.echo(f"   Size: {size_str} ({model_info['file_count']} files)")
                        except Exception:
                            # Don't fail if we can't get model info
                            pass

                    # Show download progress with spinner if appropriate
                    download_spinner = None
                    if format == "text" and not output and should_show_spinner():
                        download_spinner = yaspin(Spinners.dots, text="Downloading model files...")
                        download_spinner.start()

                    try:
                        # Convert cache_dir string to Path if provided
                        hf_cache_dir = None
                        if cache and cache_dir:
                            hf_cache_dir = Path(cache_dir)
                        elif cache:
                            # Use default cache directory
                            hf_cache_dir = Path.home() / ".modelaudit" / "cache"

                        # Download with caching support and progress bar
                        download_path = download_model(
                            path, cache_dir=hf_cache_dir, show_progress=(format == "text" and not output)
                        )
                        actual_path = str(download_path)
                        # Only track for cleanup if not using cache
                        temp_dir = str(download_path) if not cache else None

                        if download_spinner:
                            download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
                        elif format == "text" and not output:
                            click.echo(style_text("✅ Download complete", fg="green", bold=True))

                    except Exception as e:
                        if download_spinner:
                            download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
                        elif format == "text" and not output:
                            click.echo(style_text("❌ Download failed", fg="red", bold=True))

                        error_msg = str(e)
                        # Provide more helpful message for disk space errors
                        if "insufficient disk space" in error_msg.lower():
                            logger.error(f"Disk space error for {path}: {error_msg}")
                            click.echo(style_text(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                            click.echo(
                                style_text(
                                    "💡 Tip: Free up disk space or use --cache-dir to specify a "
                                    "directory with more space",
                                    fg="cyan",
                                ),
                                err=True,
                            )
                        else:
                            logger.error(f"Failed to download model from {path}: {error_msg}", exc_info=verbose)
                            click.echo(f"Error downloading model from {path}: {error_msg}", err=True)

                        aggregated_results["has_errors"] = True
                        continue

                # Check if this is a PyTorch Hub URL
                elif is_pytorch_hub_url(path):
                    download_spinner = None
                    if format == "text" and not output and should_show_spinner():
                        download_spinner = yaspin(Spinners.dots, text=f"Downloading from {style_text(path, fg='cyan')}")
                        download_spinner.start()
                    elif format == "text" and not output:
                        click.echo(f"Downloading from {path}...")

                    try:
                        download_path = download_pytorch_hub_model(
                            path,
                            cache_dir=Path(cache_dir) if cache_dir else None,
                        )
                        actual_path = str(download_path)
                        temp_dir = str(download_path)

                        if download_spinner:
                            download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
                        elif format == "text" and not output:
                            click.echo("Downloaded successfully")

                    except Exception as e:
                        if download_spinner:
                            download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
                        elif format == "text" and not output:
                            click.echo("Download failed")

                        error_msg = str(e)
                        if "insufficient disk space" in error_msg.lower():
                            logger.error(f"Disk space error for {path}: {error_msg}")
                            click.echo(style_text(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                            click.echo(
                                style_text(
                                    (
                                        "💡 Tip: Free up disk space or use --cache-dir "
                                        "to specify a directory with more space"
                                    ),
                                    fg="cyan",
                                ),
                                err=True,
                            )
                        else:
                            logger.error(f"Failed to download model from {path}: {error_msg}", exc_info=verbose)
                            click.echo(f"Error downloading model from {path}: {error_msg}", err=True)

                        aggregated_results["has_errors"] = True
                        continue

                # Check if this is a cloud storage URL
                elif is_cloud_url(path):
                    # Parse max download size if provided
                    max_download_bytes = None
                    if max_download_size:
                        size_map = {"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}
                        for unit, multiplier in size_map.items():
                            if max_download_size.upper().endswith(unit):
                                max_download_bytes = int(float(max_download_size[: -len(unit)]) * multiplier)
                                break
                        if max_download_bytes is None:
                            # Try parsing as raw number
                            try:
                                max_download_bytes = int(max_download_size)
                            except ValueError:
                                click.echo(f"Invalid max download size: {max_download_size}", err=True)
                                aggregated_results["has_errors"] = True
                                continue

                    # Handle preview mode
                    if preview:
                        import asyncio

                        from .utils.cloud_storage import analyze_cloud_target

                        try:
                            metadata = asyncio.run(analyze_cloud_target(path))
                            click.echo(f"\n📊 Preview for {style_text(path, fg='cyan')}:")
                            click.echo(f"   Type: {metadata['type']}")

                            if metadata["type"] == "file":
                                click.echo(f"   Size: {metadata.get('human_size', 'unknown')}")
                                click.echo(f"   Estimated download time: {metadata.get('estimated_time', 'unknown')}")
                            elif metadata["type"] == "directory":
                                click.echo(f"   Files: {metadata.get('file_count', 0)}")
                                click.echo(f"   Total size: {metadata.get('human_size', 'unknown')}")
                                click.echo(f"   Estimated download time: {metadata.get('estimated_time', 'unknown')}")

                                if selective:
                                    from .utils.cloud_storage import filter_scannable_files

                                    scannable = filter_scannable_files(metadata.get("files", []))
                                    click.echo(
                                        f"   Scannable files: {len(scannable)} of {metadata.get('file_count', 0)}"
                                    )

                            # Skip actual download in preview mode
                            continue

                        except Exception as e:
                            click.echo(f"Error analyzing {path}: {e!s}", err=True)
                            aggregated_results["has_errors"] = True
                            continue

                    # Normal download mode
                    download_spinner = None
                    if format == "text" and not output and should_show_spinner():
                        download_spinner = yaspin(Spinners.dots, text=f"Downloading from {style_text(path, fg='cyan')}")
                        download_spinner.start()
                    elif format == "text" and not output:
                        click.echo(f"Downloading from {path}...")

                    try:
                        # Convert cache_dir string to Path if provided
                        cache_path = Path(cache_dir) if cache_dir else None

                        download_path = download_from_cloud(
                            path,
                            cache_dir=cache_path,
                            max_size=max_download_bytes,
                            use_cache=cache,
                            show_progress=verbose,
                            selective=selective,
                            stream_analyze=stream,
                        )
                        actual_path = str(download_path)
                        temp_dir = str(download_path) if not cache else None  # Don't clean up cached files

                        if download_spinner:
                            download_spinner.ok(style_text("✅ Downloaded", fg="green", bold=True))
                        elif format == "text" and not output:
                            click.echo("Downloaded successfully")

                    except Exception as e:
                        if download_spinner:
                            download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
                        elif format == "text" and not output:
                            click.echo("Download failed")

                        error_msg = str(e)
                        # Provide more helpful message for disk space errors
                        if "insufficient disk space" in error_msg.lower():
                            logger.error(f"Disk space error for {path}: {error_msg}")
                            click.echo(style_text(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                            click.echo(
                                style_text(
                                    "💡 Tip: Free up disk space or use --cache-dir to specify a "
                                    "directory with more space",
                                    fg="cyan",
                                ),
                                err=True,
                            )
                        else:
                            logger.error(f"Failed to download from {path}: {error_msg}", exc_info=verbose)
                            click.echo(f"Error downloading from {path}: {error_msg}", err=True)

                        aggregated_results["has_errors"] = True
                        continue

                # Check if this is an MLflow URI
                elif is_mlflow_uri(path):
                    # Show download progress if in text mode
                    download_spinner = None
                    if format == "text" and not output and should_show_spinner():
                        download_spinner = yaspin(Spinners.dots, text=f"Downloading from {style_text(path, fg='cyan')}")
                        download_spinner.start()
                    elif format == "text" and not output:
                        click.echo(f"Downloading from {path}...")

                    try:
                        from .mlflow_integration import scan_mlflow_model

                        # Use scan_mlflow_model to download and get scan results directly
                        results = scan_mlflow_model(
                            path,
                            registry_uri=registry_uri,
                            timeout=timeout,
                            blacklist_patterns=list(blacklist) if blacklist else None,
                            max_file_size=max_file_size,
                            max_total_size=max_total_size,
                        )

                        if download_spinner:
                            download_spinner.ok(style_text("✅ Downloaded & Scanned", fg="green", bold=True))
                        elif format == "text" and not output:
                            click.echo("Downloaded and scanned successfully")

                        # Aggregate results directly from MLflow scan
                        aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
                        aggregated_results["issues"].extend(results.get("issues", []))
                        aggregated_results["checks"].extend(results.get("checks", []))
                        aggregated_results["files_scanned"] += results.get("files_scanned", 1)
                        aggregated_results["assets"].extend(results.get("assets", []))
                        if results.get("has_errors", False):
                            aggregated_results["has_errors"] = True
                        # Aggregate file metadata
                        if "file_metadata" in results:
                            aggregated_results["file_metadata"].update(results["file_metadata"])

                        # Track scanner names
                        for scanner in results.get("scanners", []):
                            if scanner and scanner not in aggregated_results["scanner_names"] and scanner != "unknown":
                                aggregated_results["scanner_names"].append(scanner)

                        # Skip the normal scanning logic since we already have results
                        continue

                    except Exception as e:
                        if download_spinner:
                            download_spinner.fail(style_text("❌ Download failed", fg="red", bold=True))
                        elif format == "text" and not output:
                            click.echo("Download failed")

                        logger.error(f"Failed to download model from {path}: {e!s}", exc_info=verbose)
                        click.echo(f"Error downloading model from {path}: {e!s}", err=True)
                        aggregated_results["has_errors"] = True
                        continue

                # Check if this is a JFrog URL
                elif is_jfrog_url(path):
                    download_spinner = None
                    if format == "text" and not output and should_show_spinner():
                        download_spinner = yaspin(
                            Spinners.dots, text=f"Downloading and scanning from {style_text(path, fg='cyan')}"
                        )
                        download_spinner.start()
                    elif format == "text" and not output:
                        click.echo(f"Downloading and scanning from {path}...")

                    try:
                        # Use the integrated JFrog scanning function
                        results = scan_jfrog_artifact(
                            path,
                            api_token=jfrog_api_token,
                            access_token=jfrog_access_token,
                            timeout=timeout,
                            blacklist_patterns=list(blacklist) if blacklist else None,
                            max_file_size=max_file_size,
                            max_total_size=max_total_size,
                            strict_license=strict_license,
                            skip_file_types=not no_skip_files,
                        )

                        if download_spinner:
                            download_spinner.ok(style_text("✅ Downloaded and scanned", fg="green", bold=True))
                        elif format == "text" and not output:
                            click.echo("Downloaded and scanned successfully")

                        # Aggregate results
                        aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
                        aggregated_results["issues"].extend(results.get("issues", []))
                        aggregated_results["checks"].extend(results.get("checks", []))
                        aggregated_results["files_scanned"] += results.get("files_scanned", 1)
                        aggregated_results["assets"].extend(results.get("assets", []))
                        if results.get("has_errors", False):
                            aggregated_results["has_errors"] = True
                        # Aggregate file metadata
                        if "file_metadata" in results:
                            aggregated_results["file_metadata"].update(results["file_metadata"])

                        continue  # Skip the regular scanning flow

                    except Exception as e:
                        if download_spinner:
                            download_spinner.fail(style_text("❌ Download/scan failed", fg="red", bold=True))
                        elif format == "text" and not output:
                            click.echo("Download/scan failed")

                        logger.error(f"Failed to download/scan model from {path}: {e!s}", exc_info=verbose)
                        click.echo(f"Error downloading/scanning model from {path}: {e!s}", err=True)
                        aggregated_results["has_errors"] = True
                        continue

                else:
                    # For local paths, check if they exist
                    if not os.path.exists(path):
                        click.echo(f"Error: Path does not exist: {path}", err=True)
                        aggregated_results["has_errors"] = True
                        continue

                # Early exit for common non-model file extensions
                # Note: Allow .json, .yaml, .yml as they can be model config files
                if os.path.isfile(path):
                    _, ext = os.path.splitext(path)
                    ext = ext.lower()
                    if ext in (
                        ".md",
                        ".txt",
                        ".py",
                        ".js",
                        ".html",
                        ".css",
                    ):
                        if verbose:
                            logger.debug(f"Skipped: {path} (non-model file)")
                        click.echo(f"Skipping non-model file: {path}")
                        continue

                # Show progress indicator if in text mode and not writing to a file
                spinner = None
                if format == "text" and not output and should_show_spinner():
                    spinner_text = f"Scanning {style_text(path, fg='cyan')}"
                    spinner = yaspin(Spinners.dots, text=spinner_text)
                    spinner.start()
                elif format == "text" and not output:
                    click.echo(f"Scanning {path}...")

                # Perform the scan with the specified options
                try:
                    # Define progress callback for legacy spinner support
                    progress_callback = None
                    if spinner and not progress_tracker:

                        def update_progress(message, percentage, spinner=spinner):
                            spinner.text = f"{message} ({percentage:.1f}%)"

                        progress_callback = update_progress

                    # Setup progress tracking for this path
                    if progress_tracker:
                        try:
                            from .progress import ProgressPhase

                            # Estimate file/directory size for progress tracking
                            if os.path.isfile(actual_path):
                                total_bytes = os.path.getsize(actual_path)
                                total_items = 1
                            elif os.path.isdir(actual_path):
                                # Estimate directory size (rough approximation)
                                total_bytes = sum(f.stat().st_size for f in Path(actual_path).rglob("*") if f.is_file())
                                total_items = len(list(Path(actual_path).rglob("*")))
                            else:
                                total_bytes = 0
                                total_items = 1

                            progress_tracker.stats.total_bytes = total_bytes
                            progress_tracker.stats.total_items = total_items
                            progress_tracker.set_phase(ProgressPhase.INITIALIZING, f"Starting scan: {actual_path}")
                        except (ImportError, RecursionError):
                            # Skip progress tracking if import fails due to circular dependency
                            progress_tracker = None

                        # Create enhanced progress callback using factory pattern to bind variables
                        def create_enhanced_progress_callback(progress_tracker_bound, total_bytes_bound, spinner_bound):
                            def enhanced_progress_callback(message, percentage):
                                if progress_tracker_bound:
                                    # Update progress based on percentage
                                    bytes_processed = (
                                        int((percentage / 100.0) * total_bytes_bound) if total_bytes_bound > 0 else 0
                                    )
                                    progress_tracker_bound.update_bytes(bytes_processed, message)

                                    # Update phase based on message content
                                    message_lower = message.lower()
                                    if "loading" in message_lower:
                                        progress_tracker_bound.set_phase(ProgressPhase.LOADING, message)
                                    elif "analyzing" in message_lower or "scanning" in message_lower:
                                        progress_tracker_bound.set_phase(ProgressPhase.ANALYZING, message)
                                    elif "checking" in message_lower:
                                        progress_tracker_bound.set_phase(ProgressPhase.CHECKING, message)

                                # Also update spinner if present
                                if spinner_bound:
                                    spinner_bound.text = f"{message} ({percentage:.1f}%)"

                            return enhanced_progress_callback

                        progress_callback = create_enhanced_progress_callback(progress_tracker, total_bytes, spinner)

                    # Run the scan with progress reporting
                    config_overrides = {
                        "enable_progress": bool(progress_tracker),
                        "progress_update_interval": progress_interval,
                    }

                    results = scan_model_directory_or_file(
                        actual_path,
                        blacklist_patterns=list(blacklist) if blacklist else None,
                        timeout=timeout,
                        max_file_size=max_file_size,
                        max_total_size=max_total_size,
                        strict_license=strict_license,
                        progress_callback=progress_callback,
                        skip_file_types=not no_skip_files,  # CLI flag is inverted (--no-skip-files)
                        **config_overrides,
                    )

                    # Aggregate results
                    aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
                    aggregated_results["issues"].extend(results.get("issues", []))
                    aggregated_results["checks"].extend(results.get("checks", []))
                    aggregated_results["files_scanned"] += results.get(
                        "files_scanned",
                        1,
                    )  # Count each file scanned
                    aggregated_results["assets"].extend(results.get("assets", []))
                    if results.get("has_errors", False):
                        aggregated_results["has_errors"] = True

                    # Aggregate file metadata
                    if "file_metadata" in results:
                        aggregated_results["file_metadata"].update(results["file_metadata"])

                    # Track scanner names
                    for scanner in results.get("scanners", []):
                        if scanner and scanner not in aggregated_results["scanner_names"] and scanner != "unknown":
                            aggregated_results["scanner_names"].append(scanner)

                    # Show completion status if in text mode and not writing to a file
                    if results.get("issues", []):
                        # Filter out DEBUG severity issues when not in verbose mode
                        visible_issues = [
                            issue
                            for issue in results.get("issues", [])
                            if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
                        ]
                        issue_count = len(visible_issues)

                        if issue_count > 0:
                            # Determine severity for coloring
                            has_critical = any(
                                issue.get("severity") == "critical"
                                for issue in visible_issues
                                if isinstance(issue, dict)
                            )
                            if spinner:
                                spinner.text = f"Scanned {style_text(path, fg='cyan')}"
                                if has_critical:
                                    spinner.fail(
                                        style_text(
                                            f"🚨 Found {issue_count} issue{'s' if issue_count > 1 else ''} (CRITICAL)",
                                            fg="red",
                                            bold=True,
                                        ),
                                    )
                                else:
                                    spinner.ok(
                                        style_text(
                                            f"⚠️  Found {issue_count} issue{'s' if issue_count > 1 else ''}",
                                            fg="yellow",
                                            bold=True,
                                        ),
                                    )
                            elif format == "text" and not output:
                                issues_str = "issue" if issue_count == 1 else "issues"
                                if has_critical:
                                    click.echo(f"Scanned {path}: Found {issue_count} {issues_str} (CRITICAL)")
                                else:
                                    click.echo(f"Scanned {path}: Found {issue_count} {issues_str}")
                        else:
                            # No issues after filtering (all were DEBUG)
                            if spinner:
                                spinner.text = f"Scanned {style_text(path, fg='cyan')}"
                                spinner.ok(style_text("✅ Clean", fg="green", bold=True))
                            elif format == "text" and not output:
                                click.echo(f"Scanned {path}: Clean")
                    else:
                        # No issues at all
                        if spinner:
                            spinner.text = f"Scanned {style_text(path, fg='cyan')}"
                            spinner.ok(style_text("✅ Clean", fg="green", bold=True))
                        elif format == "text" and not output:
                            click.echo(f"Scanned {path}: Clean")

                except Exception as e:
                    # Show error if in text mode and not writing to a file
                    if spinner:
                        spinner.text = f"Error scanning {style_text(path, fg='cyan')}"
                        spinner.fail(style_text("❌ Error", fg="red", bold=True))
                    elif format == "text" and not output:
                        click.echo(f"Error scanning {path}")

                    logger.error(f"Error during scan of {path}: {e!s}", exc_info=verbose)
                    click.echo(f"Error scanning {path}: {e!s}", err=True)
                    aggregated_results["has_errors"] = True

                    # Report error to progress tracker
                    if progress_tracker:
                        progress_tracker.report_error(e)

            except Exception as e:
                # Catch any other exceptions from the outer try block
                logger.error(f"Unexpected error processing {path}: {e!s}", exc_info=verbose)
                click.echo(f"Unexpected error processing {path}: {e!s}", err=True)
                aggregated_results["has_errors"] = True

                # Report error to progress tracker
                if progress_tracker:
                    progress_tracker.report_error(e)

            finally:
                # Clean up temporary directory if we downloaded a model
                # Only clean up if we didn't use a user-specified cache directory
                if temp_dir and os.path.exists(temp_dir) and not cache_dir:
                    try:
                        shutil.rmtree(temp_dir)
                        if verbose:
                            logger.debug(f"Temporary directory removed: {temp_dir}")
                    except Exception as e:
                        logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e!s}")

                # Check if we were interrupted and should stop processing more paths
                if interrupt_handler.is_interrupted():
                    logger.info("Scan interrupted by user")
                    aggregated_results["success"] = False
                    issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
                    if not any(issue.get("message") == "Scan interrupted by user" for issue in issues_list):
                        issues_list.append(
                            {
                                "message": "Scan interrupted by user",
                                "severity": "info",
                                "details": {"interrupted": True},
                            }
                        )
                    should_break = True

            # Break outside of finally block if interrupted
            if should_break:
                break

    # Complete progress tracking
    if progress_tracker:
        try:
            from .progress import ProgressPhase

            progress_tracker.set_phase(ProgressPhase.FINALIZING, "Completing scan and generating report")
            progress_tracker.complete()
        except (ImportError, RecursionError):
            # Skip progress completion if import fails due to circular dependency
            if verbose:
                click.echo("Progress tracking completion skipped due to import issues", err=True)
        except Exception as e:
            logger.warning(f"Error completing progress tracking: {e}")

    # Cleanup progress reporters
    for reporter in progress_reporters:
        try:
            if hasattr(reporter, "cleanup"):
                reporter.cleanup()
            elif hasattr(reporter, "close"):
                reporter.close()
        except Exception as e:
            logger.warning(f"Error cleaning up progress reporter: {e}")

    # Calculate total duration
    aggregated_results["duration"] = time.time() - aggregated_results["start_time"]

    # Calculate check statistics
    total_checks = len(aggregated_results.get("checks", []))
    passed_checks = sum(1 for c in aggregated_results.get("checks", []) if c.get("status") == "passed")
    failed_checks = sum(1 for c in aggregated_results.get("checks", []) if c.get("status") == "failed")
    aggregated_results["total_checks"] = total_checks
    aggregated_results["passed_checks"] = passed_checks
    aggregated_results["failed_checks"] = failed_checks

    # Deduplicate issues based on message, severity, and location
    seen_issues = set()
    deduplicated_issues = []
    for issue in aggregated_results["issues"]:
        if isinstance(issue, dict):
            # Include location in the deduplication key to avoid hiding issues in different files
            issue_key = (
                issue.get("message", ""),
                issue.get("severity", ""),
                issue.get("location", ""),
            )
            if issue_key not in seen_issues:
                seen_issues.add(issue_key)
                deduplicated_issues.append(issue)
        else:
            # Non-dict issues should be preserved as-is
            deduplicated_issues.append(issue)

    aggregated_results["issues"] = deduplicated_issues

    # Generate SBOM if requested
    if sbom:
        from .sbom import generate_sbom

        sbom_text = generate_sbom(expanded_paths, aggregated_results)
        with open(sbom, "w", encoding="utf-8") as f:
            f.write(sbom_text)

    # Format the output
    if format == "json":
        # Use Pydantic models for type-safe JSON output that matches original format
        from .models import create_audit_result_model
        
        output_data = aggregated_results.copy()
        
        # Filter out DEBUG issues unless verbose mode is enabled
        if not verbose and "issues" in output_data:
            output_data["issues"] = [
                issue
                for issue in output_data["issues"]
                if not isinstance(issue, dict) or issue.get("severity") != "debug"
            ]
        # Also filter DEBUG checks unless verbose
        if not verbose and "checks" in output_data:
            output_data["checks"] = [
                check
                for check in output_data["checks"]
                if not isinstance(check, dict) or check.get("severity") != "debug"
            ]
        
        # Create Pydantic model and serialize to JSON
        audit_result = create_audit_result_model(output_data)
        output_text = audit_result.model_dump_json(indent=2, exclude_none=True)
    else:
        # Text format
        output_text = format_text_output(aggregated_results, verbose)

    # Send output to the specified destination
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(output_text)

        # Always confirm file was written (expected by tests and users)
        click.echo(f"Results written to {output}")

        # Show summary in verbose mode for better UX
        if verbose:
            issues = aggregated_results.get("issues", [])
            visible_issues = issues  # In verbose mode, show all issues including debug
            if visible_issues:
                critical_count = len(
                    [i for i in visible_issues if isinstance(i, dict) and i.get("severity") == "critical"]
                )
                warning_count = len(
                    [i for i in visible_issues if isinstance(i, dict) and i.get("severity") == "warning"]
                )
                if critical_count > 0:
                    click.echo(f"Found {critical_count} critical issue(s), {warning_count} warning(s)")
                elif warning_count > 0:
                    click.echo(f"Found {warning_count} warning(s)")
                else:
                    click.echo(f"Found {len(visible_issues)} informational issue(s)")
            else:
                click.echo("No security issues found")
    else:
        # Add a separator line between debug output and scan results
        if format == "text":
            click.echo("\n" + "─" * 80)
        click.echo(output_text)

    # Exit with appropriate error code based on scan results
    exit_code = determine_exit_code(aggregated_results)
    sys.exit(exit_code)


def format_text_output(results: dict[str, Any], verbose: bool = False) -> str:
    """Format scan results as human-readable text with colors"""
    output_lines = []

    # Add scan summary header
    output_lines.append(style_text("\n📊 SCAN SUMMARY", fg="white", bold=True))
    output_lines.append("" + "─" * 60)

    # Add scan metrics in a grid format
    metrics = []

    # Scanner info
    if results.get("scanner_names"):
        scanner_names = results["scanner_names"]
        if len(scanner_names) == 1:
            metrics.append(("Scanner", scanner_names[0], "blue"))
        else:
            metrics.append(("Scanners", ", ".join(scanner_names), "blue"))

    # Duration
    if "duration" in results:
        duration = results["duration"]
        duration_str = f"{duration:.3f}s" if duration < 0.01 else f"{duration:.2f}s"
        metrics.append(("Duration", duration_str, "cyan"))

    # Files scanned
    if "files_scanned" in results:
        metrics.append(("Files", str(results["files_scanned"]), "cyan"))

    # Data size
    if "bytes_scanned" in results:
        bytes_scanned = results["bytes_scanned"]
        if bytes_scanned >= 1024 * 1024 * 1024:
            size_str = f"{bytes_scanned / (1024 * 1024 * 1024):.2f} GB"
        elif bytes_scanned >= 1024 * 1024:
            size_str = f"{bytes_scanned / (1024 * 1024):.2f} MB"
        elif bytes_scanned >= 1024:
            size_str = f"{bytes_scanned / 1024:.2f} KB"
        else:
            size_str = f"{bytes_scanned} bytes"
        metrics.append(("Size", size_str, "cyan"))

    # Display metrics in a formatted grid
    for label, value, color in metrics:
        label_str = style_text(f"  {label}:", fg="bright_black")
        value_str = style_text(value, fg=color, bold=True)
        output_lines.append(f"{label_str} {value_str}")

    # Add authentication status (inspired by semgrep's approach)
    from .scanners import _registry

    available_scanners = _registry.get_available_scanners()
    total_scanners = len(_registry.get_scanner_classes())  # Total possible scanners
    authenticated = config.is_authenticated()

    if authenticated:
        auth_label = style_text("  Authentication:", fg="bright_black")
        auth_value = style_text("Logged in", fg="green", bold=True)
        output_lines.append(f"{auth_label} {auth_value}")
        # Show enhanced scanner count for authenticated users
        scanner_label = style_text("  Enhanced Scanners:", fg="bright_black")
        scanner_value = style_text(f"{len(available_scanners)}/{total_scanners}", fg="green", bold=True)
        output_lines.append(f"{scanner_label} {scanner_value}")
    else:
        auth_label = style_text("  Authentication:", fg="bright_black")
        auth_value = style_text("Anonymous", fg="yellow", bold=True)
        output_lines.append(f"{auth_label} {auth_value}")
        # Show limited scanner info for unauthenticated users
        scanner_label = style_text("  Basic Scanners:", fg="bright_black")
        scanner_value = style_text(f"{len(available_scanners)}/{total_scanners}", fg="yellow", bold=True)
        output_lines.append(f"{scanner_label} {scanner_value}")

        # Add gentle encouragement to login (only if we have failures or limited functionality)
        if len(available_scanners) < total_scanners:
            output_lines.append("")
            tip_icon = "💡"
            tip_text = "Login for enhanced scanning with cloud models and fewer false positives"
            login_cmd = style_text("modelaudit auth login", fg="cyan", bold=True)
            output_lines.append(f"  {tip_icon} {tip_text}")
            output_lines.append(f"     Run {login_cmd} to get started")

    # Add model information if available
    if "file_metadata" in results:
        for _file_path, metadata in results["file_metadata"].items():
            if metadata.get("model_info"):
                model_info = metadata["model_info"]
                output_lines.append("")
                output_lines.append(style_text("  Model Information:", fg="bright_black"))

                if "model_type" in model_info:
                    output_lines.append(f"  • Type: {style_text(model_info['model_type'], fg='cyan')}")
                if "architectures" in model_info:
                    arch_str = (
                        ", ".join(model_info["architectures"])
                        if isinstance(model_info["architectures"], list)
                        else model_info["architectures"]
                    )
                    output_lines.append(f"  • Architecture: {style_text(arch_str, fg='cyan')}")
                if "num_layers" in model_info:
                    output_lines.append(f"  • Layers: {style_text(str(model_info['num_layers']), fg='cyan')}")
                if "hidden_size" in model_info:
                    output_lines.append(f"  • Hidden Size: {style_text(str(model_info['hidden_size']), fg='cyan')}")
                if "vocab_size" in model_info:
                    vocab_str = f"{model_info['vocab_size']:,}"
                    output_lines.append(f"  • Vocab Size: {style_text(vocab_str, fg='cyan')}")
                if "framework_version" in model_info:
                    output_lines.append(f"  • Framework: {style_text(model_info['framework_version'], fg='cyan')}")
                break  # Only show the first model info found

    # Add security check statistics
    if "total_checks" in results and results["total_checks"] > 0:
        total = results["total_checks"]
        passed = results.get("passed_checks", 0)
        failed = results.get("failed_checks", 0)
        success_rate = (passed / total * 100) if total > 0 else 0

        output_lines.append("")
        output_lines.append(style_text("  Security Checks:", fg="bright_black"))

        # Show check counts with visual indicator
        check_str = f"  ✅ {passed} passed / "
        if failed > 0:
            check_str += style_text(f"❌ {failed} failed", fg="red")
        else:
            check_str += style_text(f"✅ {failed} failed", fg="green")
        check_str += f" (Total: {total})"
        output_lines.append(check_str)

        # Show success rate with color coding
        if success_rate >= 95:
            rate_color = "green"
            rate_icon = "✅"
        elif success_rate >= 80:
            rate_color = "yellow"
            rate_icon = "⚠️"
        else:
            rate_color = "red"
            rate_icon = "🚨"

        rate_str = style_text(f"  {rate_icon} Success Rate: {success_rate:.1f}%", fg=rate_color, bold=True)
        output_lines.append(rate_str)

    # Show failed checks if any exist
    failed_checks_list = [c for c in results.get("checks", []) if c.get("status") == "failed"]
    if failed_checks_list:
        output_lines.append("")
        output_lines.append(style_text("  Failed Checks (non-critical):", fg="yellow"))
        # Group failed checks by name to avoid repetition
        check_groups: dict[str, list[str]] = {}
        for check in failed_checks_list:
            check_name = check.get("name", "Unknown check")
            if check_name not in check_groups:
                check_groups[check_name] = []
            check_groups[check_name].append(check.get("message", ""))

        # Show unique failed check types
        for check_name, messages in list(check_groups.items())[:5]:  # Show first 5 types
            unique_msg = messages[0] if messages else ""
            if len(messages) > 1:
                output_lines.append(f"    • {check_name} ({len(messages)} occurrences)")
            else:
                output_lines.append(f"    • {check_name}: {unique_msg}")
        if len(check_groups) > 5:
            output_lines.append(f"    ... and {len(check_groups) - 5} more check types")

    # Add issue summary
    issues = results.get("issues", [])
    # Filter out DEBUG severity issues when not in verbose mode
    visible_issues = [
        issue for issue in issues if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
    ]

    # Count issues by severity
    severity_counts = {
        "critical": 0,
        "warning": 0,
        "info": 0,
        "debug": 0,
    }

    for issue in issues:
        if isinstance(issue, dict):
            severity = issue.get("severity", "warning")
            if severity in severity_counts:
                severity_counts[severity] += 1

    # Display issue summary
    output_lines.append("")
    output_lines.append(style_text("\n🔍 SECURITY FINDINGS", fg="white", bold=True))
    output_lines.append("" + "─" * 60)

    if visible_issues:
        # Show issue counts with icons
        summary_parts = []
        if severity_counts["critical"] > 0:
            summary_parts.append(
                "  "
                + style_text(
                    f"🚨 {severity_counts['critical']} Critical",
                    fg="red",
                    bold=True,
                ),
            )
        if severity_counts["warning"] > 0:
            summary_parts.append(
                "  "
                + style_text(
                    f"⚠️  {severity_counts['warning']} Warning{'s' if severity_counts['warning'] > 1 else ''}",
                    fg="yellow",
                ),
            )
        if severity_counts["info"] > 0:
            summary_parts.append(
                "  " + style_text(f"[i] {severity_counts['info']} Info", fg="blue"),
            )
        if verbose and severity_counts["debug"] > 0:
            summary_parts.append(
                "  " + style_text(f"🐛 {severity_counts['debug']} Debug", fg="cyan"),
            )

        output_lines.extend(summary_parts)

        # Group issues by severity for better organization
        output_lines.append("")

        # Display critical issues first
        critical_issues = [
            issue for issue in visible_issues if isinstance(issue, dict) and issue.get("severity") == "critical"
        ]
        if critical_issues:
            output_lines.append(
                style_text("  🚨 Critical Issues", fg="red", bold=True),
            )
            output_lines.append("  " + "─" * 40)
            for issue in critical_issues:
                _format_issue(issue, output_lines, "critical")
                output_lines.append("")

        # Display warnings
        warning_issues = [
            issue for issue in visible_issues if isinstance(issue, dict) and issue.get("severity") == "warning"
        ]
        if warning_issues:
            if critical_issues:
                output_lines.append("")
            output_lines.append(style_text("  ⚠️  Warnings", fg="yellow", bold=True))
            output_lines.append("  " + "─" * 40)
            for issue in warning_issues:
                _format_issue(issue, output_lines, "warning")
                output_lines.append("")

        # Display info issues
        info_issues = [issue for issue in visible_issues if isinstance(issue, dict) and issue.get("severity") == "info"]
        if info_issues:
            if critical_issues or warning_issues:
                output_lines.append("")
            output_lines.append(style_text("  [i] Information", fg="blue", bold=True))
            output_lines.append("  " + "─" * 40)
            for issue in info_issues:
                _format_issue(issue, output_lines, "info")
                output_lines.append("")

        # Display debug issues if verbose
        if verbose:
            debug_issues = [
                issue for issue in visible_issues if isinstance(issue, dict) and issue.get("severity") == "debug"
            ]
            if debug_issues:
                if critical_issues or warning_issues or info_issues:
                    output_lines.append("")
                output_lines.append(style_text("  🐛 Debug", fg="cyan", bold=True))
                output_lines.append("  " + "─" * 40)
                for issue in debug_issues:
                    _format_issue(issue, output_lines, "debug")
                    output_lines.append("")
    else:
        # Check if no files were scanned to show appropriate message
        files_scanned = results.get("files_scanned", 0)
        if files_scanned == 0:
            output_lines.append(
                "  " + style_text("⚠️  No model files found to scan", fg="yellow", bold=True),
            )
        else:
            output_lines.append(
                "  " + style_text("✅ No security issues detected", fg="green", bold=True),
            )
        output_lines.append("")

    # Add a footer with final status
    output_lines.append("")
    output_lines.append("═" * 80)

    # Check if no files were scanned
    files_scanned = results.get("files_scanned", 0)
    if files_scanned == 0:
        status_icon = "❌"
        status_msg = "NO FILES SCANNED"
        status_color = "red"
        output_lines.append(f"  {style_text(f'{status_icon} {status_msg}', fg=status_color, bold=True)}")
        output_lines.append(
            f"  {style_text('Warning: No model files were found at the specified location.', fg='yellow')}"
        )
    # Determine overall status
    elif visible_issues:
        if any(isinstance(issue, dict) and issue.get("severity") == "critical" for issue in visible_issues):
            status_icon = "❌"
            status_msg = "CRITICAL SECURITY ISSUES FOUND"
            status_color = "red"
        elif any(isinstance(issue, dict) and issue.get("severity") == "warning" for issue in visible_issues):
            status_icon = "⚠️"
            status_msg = "WARNINGS DETECTED"
            status_color = "yellow"
        else:
            # Only info/debug issues
            status_icon = "[i]"
            status_msg = "INFORMATIONAL FINDINGS"
            status_color = "blue"
        status_line = style_text(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")
    else:
        status_icon = "✅"
        status_msg = "NO ISSUES FOUND"
        status_color = "green"
        status_line = style_text(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")

    output_lines.append("═" * 80)

    # Add encouragement message for unauthenticated users after successful scans
    # (similar to promptfoo's approach)
    if not config.is_authenticated() and not visible_issues:
        output_lines.append("")
        encouragement_msg = "» Want enhanced scanning with cloud models and team sharing?"
        signup_link = style_text("https://promptfoo.app", fg="green", bold=True)
        encouragement_line = f"  {encouragement_msg} Sign up at {signup_link}"
        output_lines.append(encouragement_line)

    return "\n".join(output_lines)


def _format_issue(
    issue: dict[str, Any],
    output_lines: list[str],
    severity: str,
) -> None:
    """Format a single issue with proper indentation and styling"""
    message = issue.get("message", "Unknown issue")
    location = issue.get("location", "")

    # Icon based on severity
    icons = {
        "critical": "    └─ 🚨",
        "warning": "    └─ ⚠️ ",
        "info": "    └─ [i] ",
        "debug": "    └─ 🐛",
    }

    # Build the issue line
    icon = icons.get(severity, "    └─ ")

    if location:
        location_str = style_text(f"[{location}]", fg="cyan", bold=True)
        output_lines.append(f"{icon} {location_str}")
        output_lines.append(f"       {style_text(message, fg='bright_white')}")
    else:
        output_lines.append(f"{icon} {style_text(message, fg='bright_white')}")

    # Add "Why" explanation if available
    why = issue.get("why")
    if why:
        why_label = style_text("Why:", fg="magenta", bold=True)
        # Wrap long explanations
        import textwrap

        wrapped_why = textwrap.fill(
            why,
            width=65,
            initial_indent="",
            subsequent_indent="           ",
        )
        output_lines.append(f"       {why_label} {wrapped_why}")

    # Add details if available
    details = issue.get("details", {})
    if details:
        for key, value in details.items():
            if value:  # Only show non-empty values
                detail_label = style_text(f"{key}:", fg="bright_black")
                detail_value = style_text(str(value), fg="bright_white")
                output_lines.append(f"       {detail_label} {detail_value}")


@cli.command()
@click.option(
    "--show-failed",
    is_flag=True,
    help="Show detailed information about failed scanners",
)
def doctor(show_failed: bool):
    """Diagnose scanner compatibility and system status"""
    import sys

    from .scanners import _registry

    click.echo("ModelAudit System Diagnostics")
    click.echo("=" * 40)

    # System information
    click.echo(f"Python version: {sys.version.split()[0]}")

    # NumPy status
    numpy_compatible, numpy_status = _registry.get_numpy_status()
    numpy_color = "green" if numpy_compatible else "yellow"
    click.echo("NumPy status: ", nl=False)
    click.secho(numpy_status, fg=numpy_color)

    # Scanner status
    available_scanners = _registry.get_available_scanners()
    failed_scanners = _registry.get_failed_scanners()
    loaded_count = len(available_scanners) - len(failed_scanners)

    click.echo("\nScanner Status:")
    click.echo(f"  Available: {len(available_scanners)} total")
    click.echo(f"  Loaded: {loaded_count}")
    click.echo(f"  Failed: {len(failed_scanners)}")

    if show_failed and failed_scanners:
        click.echo("\nFailed Scanners:")
        for scanner_id, error_msg in failed_scanners.items():
            click.echo(f"  {scanner_id}: {error_msg}")

    # Recommendations
    if failed_scanners:
        click.echo("\nRecommendations:")

        # Check for NumPy compatibility issues
        numpy_sensitive_failed = []
        for scanner_id in failed_scanners:
            scanner_info = _registry.get_scanner_info(scanner_id)
            if scanner_info and scanner_info.get("numpy_sensitive", False):
                numpy_sensitive_failed.append(scanner_id)

        if numpy_sensitive_failed and not numpy_compatible:
            click.echo("• NumPy compatibility issues detected:")
            click.echo("  For NumPy 1.x compatibility: pip install 'numpy<2.0'")
            click.echo("  Then reinstall ML frameworks: pip install --force-reinstall tensorflow torch h5py")

        # Check for missing dependencies
        missing_deps = set()
        for scanner_id in failed_scanners:
            scanner_info = _registry.get_scanner_info(scanner_id)
            if scanner_info:
                deps = scanner_info.get("dependencies", [])
                missing_deps.update(deps)

        if missing_deps:
            click.echo(f"• Install missing dependencies: pip install modelaudit[{','.join(missing_deps)}]")

    if not failed_scanners:
        click.secho("✓ All scanners loaded successfully!", fg="green")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    cli()


if __name__ == "__main__":
    main()
