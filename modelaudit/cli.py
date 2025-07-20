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
from .core import determine_exit_code, scan_model_directory_or_file
from .interrupt_handler import interruptible_scan
from .utils import resolve_dvc_file
from .utils.cloud_storage import download_from_cloud, is_cloud_url
from .utils.huggingface import download_model, is_huggingface_url
from .utils.jfrog import download_artifact, is_jfrog_url

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("modelaudit")


def is_mlflow_uri(path: str) -> bool:
    """Check if a path is an MLflow model URI."""
    return path.startswith("models:/") or path.startswith("mlflow://")


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
@click.version_option(version=__version__)
def cli() -> None:
    """ModelAudit CLI - Security scanner for AI/ML models.

    ModelAudit helps you identify potential security risks in AI/ML model files
    before deployment. It supports various model formats and can scan both local
    files and remote models from HuggingFace, cloud storage, and MLflow.
    """
    pass


@cli.command(name="doctor")
@click.option("--show-failed/--no-show-failed", default=False, help="Show failed checks instead of compatible ones")
@click.option(
    "--no-system-info",
    is_flag=True,
    help="Skip system information output",
)
def doctor_command(show_failed: bool, no_system_info: bool) -> None:
    """Check which scanners can run on your system.

    This command performs a system compatibility check to determine which
    model file formats can be scanned on your current environment.
    """
    from .scanners import _registry

    click.echo("ModelAudit System Diagnostics")
    click.echo("=" * 40)

    if not no_system_info:
        # System information
        click.echo(f"Python version: {sys.version.split()[0]}")

        # NumPy status
        numpy_compatible, numpy_status = _registry.get_numpy_status()
        numpy_color = "green" if numpy_compatible else "yellow"
        click.echo("NumPy status: ", nl=False)
        click.echo(click.style(numpy_status, fg=numpy_color))

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
        click.echo(click.style("✓ All scanners loaded successfully!", fg="green"))

    sys.exit(0)


@cli.command(name="scan")
@click.argument("paths", nargs=-1, required=True, type=str)
@click.option(
    "--output",
    "-o",
    type=str,
    help="Output file path for results",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "yaml", "jsonl", "text"]),
    default="text",
    help="Output format [default: text]",
)
@click.option(
    "--blacklist",
    "-b",
    multiple=True,
    help="Blacklist model name patterns to check against",
)
@click.option(
    "--sbom",
    type=str,
    help="Generate and save SBOM to the specified file (experimental)",
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=300,
    help="Timeout for individual file scans in seconds [default: 300]",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output with detailed logging")
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
    help="Maximum total size to scan across all files in bytes [default: unlimited]",
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
    "--cache-dir",
    type=click.Path(exists=False, file_okay=False, dir_okay=True, resolve_path=True),
    help="Directory to use for caching downloaded models (default: system temp directory)",
)
@click.option(
    "--concurrency",
    "-j",
    type=int,
    default=None,
    help="Number of worker processes for parallel scanning [default: CPU count]",
)
@click.option(
    "--no-parallel",
    is_flag=True,
    default=False,
    help="Disable parallel scanning (scan files sequentially)",
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
    cache_dir: Optional[str],
    concurrency: Optional[int],
    no_parallel: bool,
) -> None:
    """Scan files, directories, HuggingFace models, MLflow models, cloud storage,
    or JFrog artifacts for security issues.

    \b
    Usage:
        modelaudit scan /path/to/model1 /path/to/model2 ...
        modelaudit scan https://huggingface.co/user/model
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

    You can control parallelism with ``--concurrency`` or ``-j``:

        modelaudit scan /large/directory -j 8  # Use 8 workers
        modelaudit scan /path/to/model --no-parallel  # Disable parallel scanning
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Load environment variables from .env file if present
    if os.path.exists(".env"):
        from dotenv import load_dotenv

        load_dotenv()
        if verbose:
            logger.debug("Loaded environment variables from .env file")

    # Check for auth tokens in environment if not provided via CLI
    if not jfrog_api_token:
        jfrog_api_token = os.environ.get("JFROG_API_TOKEN")
    if not jfrog_access_token:
        jfrog_access_token = os.environ.get("JFROG_ACCESS_TOKEN")

    # Determine parallel settings
    parallel = not no_parallel
    max_workers = concurrency

    # Print a nice header if not in JSON mode and not writing to a file
    if format == "text" and not output:
        header = [
            "─" * 80,
            click.style("ModelAudit Security Scanner", fg="blue", bold=True),
            click.style(
                "Scanning for potential security issues in ML model files",
                fg="cyan",
            ),
            "─" * 80,
        ]
        click.echo("\n".join(header))
        click.echo(f"Paths to scan: {click.style(', '.join(paths), fg='green')}")
        if blacklist:
            click.echo(
                f"Additional blacklist patterns: {click.style(', '.join(blacklist), fg='yellow')}",
            )
        click.echo("─" * 80)
        click.echo("")

    # Expand any directories in paths
    expanded_paths = []
    for path in paths:
        # Check if it's a URL (HuggingFace, cloud storage, MLflow, or JFrog)
        if any(
            check(path) for check in [is_huggingface_url, is_cloud_url, is_mlflow_uri, is_jfrog_url]
        ) or path.startswith(("http://", "https://", "s3://", "gs://", "gcs://", "r2://", "models:/", "mlflow://")):
            expanded_paths.append(path)
        # Check if it's a DVC file
        elif path.endswith(".dvc"):
            try:
                dvc_paths = resolve_dvc_file(path)
                if dvc_paths:
                    expanded_paths.extend(dvc_paths)
                    if verbose:
                        logger.info(f"Resolved DVC file {path} to {dvc_paths}")
                else:
                    click.echo(f"Warning: Could not resolve DVC file: {path}", err=True)
            except Exception as e:
                click.echo(f"Error resolving DVC file {path}: {e!s}", err=True)
        elif os.path.isdir(path):
            # For directories, just add as-is (scanning will handle recursion)
            expanded_paths.append(path)
        else:
            # Single file
            expanded_paths.append(path)

    if not expanded_paths:
        click.echo("Error: No valid paths to scan", err=True)
        sys.exit(1)

    # Initialize aggregated results
    aggregated_results: dict[str, Any] = {
        "success": True,
        "bytes_scanned": 0,
        "issues": [],
        "files_scanned": 0,
        "assets": [],
        "has_errors": False,
        "scanner_names": [],
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
                    # Show download progress if in text mode
                    if format == "text" and not output:
                        download_spinner = yaspin(
                            Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}"
                        )
                        download_spinner.start()

                    try:
                        # Download to cache directory or temporary directory
                        download_path = download_model(path, cache_dir=Path(cache_dir) if cache_dir else None)
                        actual_path = str(download_path)
                        # Track the temp directory for cleanup
                        temp_dir = str(download_path)

                        if format == "text" and not output:
                            download_spinner.ok(click.style("✅ Downloaded", fg="green", bold=True))

                    except Exception as e:
                        if format == "text" and not output:
                            download_spinner.fail(click.style("❌ Download failed", fg="red", bold=True))

                        error_msg = str(e)
                        # Provide more helpful message for disk space errors
                        if "insufficient disk space" in error_msg.lower():
                            logger.error(f"Disk space error for {path}: {error_msg}")
                            click.echo(click.style(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                            click.echo(
                                click.style(
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

                # Check if this is a cloud storage URL
                elif is_cloud_url(path):
                    if format == "text" and not output:
                        download_spinner = yaspin(
                            Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}"
                        )
                        download_spinner.start()

                    try:
                        download_path = download_from_cloud(path, cache_dir=Path(cache_dir) if cache_dir else None)
                        actual_path = str(download_path)
                        temp_dir = str(download_path)

                        if format == "text" and not output:
                            download_spinner.ok(click.style("✅ Downloaded", fg="green", bold=True))

                    except Exception as e:
                        if format == "text" and not output:
                            download_spinner.fail(click.style("❌ Download failed", fg="red", bold=True))

                        error_msg = str(e)
                        # Provide more helpful message for disk space errors
                        if "insufficient disk space" in error_msg.lower():
                            logger.error(f"Disk space error for {path}: {error_msg}")
                            click.echo(click.style(f"\n⚠️  {error_msg}", fg="yellow"), err=True)
                            click.echo(
                                click.style(
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
                    if format == "text" and not output:
                        download_spinner = yaspin(
                            Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}"
                        )
                        download_spinner.start()

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

                        if format == "text" and not output:
                            download_spinner.ok(click.style("✅ Downloaded & Scanned", fg="green", bold=True))

                        # Aggregate results directly from MLflow scan
                        aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
                        issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
                        issues_list.extend(results.get("issues", []))
                        aggregated_results["files_scanned"] += results.get("files_scanned", 1)
                        assets_list = cast(list[dict[str, Any]], aggregated_results["assets"])
                        assets_list.extend(results.get("assets", []))
                        if results.get("has_errors", False):
                            aggregated_results["has_errors"] = True

                        # Track scanner names
                        scanner_names = cast(list[str], aggregated_results["scanner_names"])
                        for scanner in results.get("scanners", []):
                            if scanner and scanner not in scanner_names and scanner != "unknown":
                                scanner_names.append(scanner)

                        # Skip the normal scanning logic since we already have results
                        continue

                    except Exception as e:
                        if format == "text" and not output:
                            download_spinner.fail(click.style("❌ Download failed", fg="red", bold=True))

                        logger.error(f"Failed to download model from {path}: {e!s}", exc_info=verbose)
                        click.echo(f"Error downloading model from {path}: {e!s}", err=True)
                        aggregated_results["has_errors"] = True
                        continue

                # Check if this is a JFrog URL
                elif is_jfrog_url(path):
                    if format == "text" and not output:
                        download_spinner = yaspin(
                            Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}"
                        )
                        download_spinner.start()

                    try:
                        download_path = download_artifact(
                            path,
                            cache_dir=Path(cache_dir) if cache_dir else None,
                            api_token=jfrog_api_token,
                            access_token=jfrog_access_token,
                        )
                        actual_path = str(download_path)
                        temp_dir = str(download_path.parent if download_path.is_file() else download_path)

                        if format == "text" and not output:
                            download_spinner.ok(click.style("✅ Downloaded", fg="green", bold=True))

                    except Exception as e:
                        if format == "text" and not output:
                            download_spinner.fail(click.style("❌ Download failed", fg="red", bold=True))

                        logger.error(f"Failed to download model from {path}: {e!s}", exc_info=verbose)
                        click.echo(f"Error downloading model from {path}: {e!s}", err=True)
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
                        ".ts",
                        ".java",
                        ".cpp",
                        ".c",
                        ".h",
                        ".go",
                        ".rs",
                        ".sh",
                        ".bat",
                        ".exe",
                        ".dll",
                        ".so",
                        ".dylib",
                        ".log",
                        ".csv",
                        ".tsv",
                        ".xml",
                        ".html",
                        ".css",
                    ):
                        if verbose:
                            logger.info(f"Skipping non-model file: {path}")
                        click.echo(f"Skipping non-model file: {path}")
                        continue

                # Show progress indicator if in text mode and not writing to a file
                spinner = None
                if format == "text" and not output:
                    spinner_text = f"Scanning {click.style(path, fg='cyan')}"
                    spinner = yaspin(Spinners.dots, text=spinner_text)
                    spinner.start()

                # Perform the scan with the specified options
                try:
                    # Define progress callback if using spinner
                    progress_callback = None
                    if spinner:

                        def update_progress(message, percentage, spinner=spinner):
                            spinner.text = f"{message} ({percentage:.1f}%)"

                        progress_callback = update_progress

                    # Run the scan with progress reporting
                    results = scan_model_directory_or_file(
                        actual_path,
                        blacklist_patterns=list(blacklist) if blacklist else None,
                        timeout=timeout,
                        max_file_size=max_file_size,
                        max_total_size=max_total_size,
                        progress_callback=progress_callback,
                        parallel=parallel,
                        max_workers=max_workers,
                    )

                    # Aggregate results
                    aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
                    issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
                    issues_list.extend(results.get("issues", []))
                    aggregated_results["files_scanned"] += results.get(
                        "files_scanned",
                        1,
                    )  # Count each file scanned
                    assets_list = cast(list[dict[str, Any]], aggregated_results["assets"])
                    assets_list.extend(results.get("assets", []))
                    if results.get("has_errors", False):
                        aggregated_results["has_errors"] = True

                    # Track scanner names
                    scanner_names = cast(list[str], aggregated_results["scanner_names"])
                    for scanner in results.get("scanners", []):
                        if scanner and scanner not in scanner_names and scanner != "unknown":
                            scanner_names.append(scanner)

                    # Preserve parallel scan markers if present
                    if results.get("parallel_scan"):
                        aggregated_results["parallel_scan"] = True
                        aggregated_results["worker_count"] = results.get("worker_count")

                    # Show completion status if in text mode and not writing to a file
                    if spinner:
                        if results.get("issues", []):
                            # Filter out DEBUG severity issues when not in verbose mode
                            visible_issues = [
                                issue
                                for issue in results.get("issues", [])
                                if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
                            ]
                            issue_count = len(visible_issues)
                            spinner.text = f"Scanned {click.style(path, fg='cyan')}"
                            if issue_count > 0:
                                # Determine severity for coloring
                                has_critical = any(
                                    issue.get("severity") == "critical"
                                    for issue in visible_issues
                                    if isinstance(issue, dict)
                                )
                                if has_critical:
                                    spinner.fail(
                                        click.style(
                                            f"🚨 Found {issue_count} issue{'s' if issue_count > 1 else ''} (CRITICAL)",
                                            fg="red",
                                            bold=True,
                                        ),
                                    )
                                else:
                                    spinner.ok(
                                        click.style(
                                            f"⚠️  Found {issue_count} issue{'s' if issue_count > 1 else ''}",
                                            fg="yellow",
                                            bold=True,
                                        ),
                                    )
                            else:
                                spinner.ok(click.style("✅ Clean", fg="green", bold=True))
                        else:
                            spinner.text = f"Scanned {click.style(path, fg='cyan')}"
                            spinner.ok(click.style("✅ Clean", fg="green", bold=True))

                except FileNotFoundError as e:
                    # Show error if in text mode and not writing to a file
                    if spinner:
                        spinner.text = f"Path not found: {click.style(path, fg='cyan')}"
                        spinner.fail(click.style("❌ Not Found", fg="red", bold=True))

                    logger.error(f"Path does not exist: {path}")
                    click.echo(str(e), err=True)
                    aggregated_results["has_errors"] = True

                except Exception as e:
                    # Show error if in text mode and not writing to a file
                    if spinner:
                        spinner.text = f"Error scanning {click.style(path, fg='cyan')}"
                        spinner.fail(click.style("❌ Error", fg="red", bold=True))

                    logger.error(f"Error during scan of {path}: {e!s}", exc_info=verbose)
                    click.echo(f"Error scanning {path}: {e!s}", err=True)
                    aggregated_results["has_errors"] = True

            except Exception as e:
                # Catch any other exceptions from the outer try block
                logger.error(f"Unexpected error processing {path}: {e!s}", exc_info=verbose)
                click.echo(f"Unexpected error processing {path}: {e!s}", err=True)
                aggregated_results["has_errors"] = True

            finally:
                # Clean up temporary directory if we downloaded a model
                # Only clean up if we didn't use a user-specified cache directory
                if temp_dir and os.path.exists(temp_dir) and not cache_dir:
                    try:
                        shutil.rmtree(temp_dir)
                        if verbose:
                            logger.info(f"Cleaned up temporary directory: {temp_dir}")
                    except Exception as e:
                        logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e!s}")

                # Check if we were interrupted and should stop processing more paths
                if interrupt_handler.is_interrupted():
                    logger.info("Stopping scan due to interrupt")
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

    # Calculate total duration
    aggregated_results["duration"] = time.time() - aggregated_results["start_time"]

    # Generate SBOM if requested
    if sbom:
        from .sbom import generate_sbom

        sbom_text = generate_sbom(expanded_paths, aggregated_results)
        try:
            with open(sbom, "w", encoding="utf-8") as f:
                f.write(sbom_text)
            if verbose:
                logger.info(f"SBOM written to {sbom}")
        except Exception as e:
            logger.error(f"Failed to write SBOM to {sbom}: {e!s}")
            aggregated_results["has_errors"] = True

    # Determine if the scan succeeded overall (operational success, not security findings)
    # Success should only be False if there were operational errors, not if security issues were found
    aggregated_results["success"] = not aggregated_results["has_errors"]

    # Add summary information
    issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
    scanner_names = cast(list[str], aggregated_results["scanner_names"])
    aggregated_results["summary"] = {
        "total_files": aggregated_results["files_scanned"],
        "total_issues": len(issues_list),
        "scanners_used": scanner_names,
    }

    # Output results based on format
    if format == "text" and not output:
        # Display summary in console
        click.echo()
        click.echo(click.style("=== Scan Summary ===", fg="cyan", bold=True))
        click.echo(f"Files scanned: {aggregated_results['files_scanned']}")
        click.echo(f"Total size: {aggregated_results['bytes_scanned'] / (1024 * 1024):.1f} MB")
        issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
        click.echo(f"Total issues: {len(issues_list)}")
        if aggregated_results.get("parallel_scan"):
            click.echo(f"Parallel scan: Enabled ({aggregated_results.get('worker_count', 'N/A')} workers)")
        click.echo(f"Duration: {aggregated_results['duration']:.1f}s")

        # Show all issues in detail
        issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
        issues = list(issues_list)
        # Filter out DEBUG severity issues when not in verbose mode
        if not verbose:
            issues = [issue for issue in issues if not isinstance(issue, dict) or issue.get("severity") != "debug"]

        if issues:
            click.echo()
            click.echo(click.style("=== Issues Found ===", fg="red", bold=True))
            for i, issue in enumerate(issues, 1):
                severity = issue.get("severity", "unknown")
                severity_colors = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "green",
                    "debug": "white",
                }
                color = severity_colors.get(severity, "white")
                click.echo(
                    f"\n{i}. {click.style(f'[{severity.upper()}]', fg=color, bold=True)} "
                    f"{issue.get('message', 'Unknown issue')}"
                )
                if "file_path" in issue:
                    click.echo(f"   File: {issue['file_path']}")
                if "scanner" in issue:
                    click.echo(f"   Scanner: {issue['scanner']}")
                if "details" in issue and isinstance(issue["details"], dict):
                    for key, value in issue["details"].items():
                        click.echo(f"   {key}: {value}")

    else:
        # Convert results to the requested format
        if format == "json":
            output_text = json.dumps(aggregated_results, indent=2)
        elif format == "yaml":
            import yaml

            output_text = yaml.dump(aggregated_results, default_flow_style=False)
        elif format == "jsonl":
            # Output each issue as a separate JSON line
            lines = []
            issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
            for issue in issues_list:
                lines.append(json.dumps(issue))
            output_text = "\n".join(lines)
        else:  # text format with output file
            lines = ["=== ModelAudit Scan Results ==="]
            lines.append(f"Files scanned: {aggregated_results['files_scanned']}")
            lines.append(f"Total size: {aggregated_results['bytes_scanned'] / (1024 * 1024):.1f} MB")
            issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
            lines.append(f"Total issues: {len(issues_list)}")
            if aggregated_results.get("parallel_scan"):
                lines.append(f"Parallel scan: Enabled ({aggregated_results.get('worker_count', 'N/A')} workers)")
            lines.append(f"Duration: {aggregated_results['duration']:.1f}s")
            lines.append("")

            issues_list = cast(list[dict[str, Any]], aggregated_results["issues"])
            if issues_list:
                lines.append("=== Issues Found ===")
                for i, issue in enumerate(issues_list, 1):
                    lines.append(
                        f"\n{i}. [{issue.get('severity', 'unknown').upper()}] {issue.get('message', 'Unknown issue')}"
                    )
                    if "file_path" in issue:
                        lines.append(f"   File: {issue['file_path']}")
                    if "scanner" in issue:
                        lines.append(f"   Scanner: {issue['scanner']}")
                    if "details" in issue and isinstance(issue["details"], dict):
                        for key, value in issue["details"].items():
                            lines.append(f"   {key}: {value}")
            output_text = "\n".join(lines)

        # Write to file if output path specified
        if output:
            try:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(output_text)
                if format == "text":
                    click.echo(f"Results written to {output}")
            except Exception as e:
                logger.error(f"Failed to write output to {output}: {e!s}")
                sys.exit(1)
        else:
            # Print to stdout
            click.echo(output_text)

    # Exit with appropriate code
    sys.exit(determine_exit_code(aggregated_results))


def format_text_output(results: dict[str, Any], verbose: bool = False) -> str:
    """Format scan results as human-readable text with colors"""
    output_lines = []

    # Add scan summary header
    output_lines.append(click.style("\n📊 SCAN SUMMARY", fg="white", bold=True))
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
        label_str = click.style(f"  {label}:", fg="bright_black")
        value_str = click.style(value, fg=color, bold=True)
        output_lines.append(f"{label_str} {value_str}")

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
    output_lines.append(click.style("\n🔍 SECURITY FINDINGS", fg="white", bold=True))
    output_lines.append("" + "─" * 60)

    if visible_issues:
        # Show issue counts with icons
        summary_parts = []
        if severity_counts["critical"] > 0:
            summary_parts.append(
                "  "
                + click.style(
                    f"🚨 {severity_counts['critical']} Critical",
                    fg="red",
                    bold=True,
                ),
            )
        if severity_counts["warning"] > 0:
            summary_parts.append(
                "  "
                + click.style(
                    f"⚠️  {severity_counts['warning']} Warning{'s' if severity_counts['warning'] > 1 else ''}",
                    fg="yellow",
                ),
            )
        if severity_counts["info"] > 0:
            summary_parts.append(
                "  " + click.style(f"[i] {severity_counts['info']} Info", fg="blue"),
            )
        if verbose and severity_counts["debug"] > 0:
            summary_parts.append(
                "  " + click.style(f"🐛 {severity_counts['debug']} Debug", fg="cyan"),
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
                click.style("  🚨 Critical Issues", fg="red", bold=True),
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
            output_lines.append(click.style("  ⚠️  Warnings", fg="yellow", bold=True))
            output_lines.append("  " + "─" * 40)
            for issue in warning_issues:
                _format_issue(issue, output_lines, "warning")
                output_lines.append("")

        # Display info issues
        info_issues = [issue for issue in visible_issues if isinstance(issue, dict) and issue.get("severity") == "info"]
        if info_issues:
            if critical_issues or warning_issues:
                output_lines.append("")
            output_lines.append(click.style("  [i] Information", fg="blue", bold=True))
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
                output_lines.append(click.style("  🐛 Debug", fg="cyan", bold=True))
                output_lines.append("  " + "─" * 40)
                for issue in debug_issues:
                    _format_issue(issue, output_lines, "debug")
                    output_lines.append("")
    else:
        # Check if no files were scanned to show appropriate message
        files_scanned = results.get("files_scanned", 0)
        if files_scanned == 0:
            output_lines.append(
                "  " + click.style("⚠️  No model files found to scan", fg="yellow", bold=True),
            )
        else:
            output_lines.append(
                "  " + click.style("✅ No security issues detected", fg="green", bold=True),
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
        output_lines.append(f"  {click.style(f'{status_icon} {status_msg}', fg=status_color, bold=True)}")
        output_lines.append(
            f"  {click.style('Warning: No model files were found at the specified location.', fg='yellow')}"
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
        status_line = click.style(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")
    else:
        status_icon = "✅"
        status_msg = "NO ISSUES FOUND"
        status_color = "green"
        status_line = click.style(f"{status_icon} {status_msg}", fg=status_color, bold=True)
        output_lines.append(f"  {status_line}")

    output_lines.append("═" * 80)

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
        location_str = click.style(f"[{location}]", fg="cyan", bold=True)
        output_lines.append(f"{icon} {location_str}")
        output_lines.append(f"       {click.style(message, fg='bright_white')}")
    else:
        output_lines.append(f"{icon} {click.style(message, fg='bright_white')}")

    # Add "Why" explanation if available
    why = issue.get("why")
    if why:
        why_label = click.style("Why:", fg="magenta", bold=True)
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
                detail_label = click.style(f"{key}:", fg="bright_black")
                detail_value = click.style(str(value), fg="bright_white")
                output_lines.append(f"       {detail_label} {detail_value}")


def main() -> None:
    """Main entry point"""
    cli()


if __name__ == "__main__":
    cli()
