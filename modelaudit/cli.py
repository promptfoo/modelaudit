import json
import logging
import os
import shutil
import sys
import time
from typing import Any, Optional

import click
from yaspin import yaspin
from yaspin.spinners import Spinners

from . import __version__
from .core import determine_exit_code, scan_model_directory_or_file
from .utils.cloud_storage import download_from_cloud, is_cloud_url
from .utils.huggingface import download_model, is_huggingface_url

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("modelaudit")


def is_mlflow_uri(path: str) -> bool:
    """Check if a path is an MLflow model URI."""
    return path.startswith("models:/")


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """Static scanner for ML models"""
    pass


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
    default=300,
    help="Scan timeout in seconds [default: 300]",
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
) -> None:
    """Scan files, directories, HuggingFace models, or MLflow models for malicious content.

    \b
    Usage:
        modelaudit scan /path/to/model1 /path/to/model2 ...
        modelaudit scan https://huggingface.co/user/model
        modelaudit scan hf://user/model
        modelaudit scan s3://my-bucket/models/
        modelaudit scan gs://my-bucket/model.pt
        modelaudit scan models:/MyModel/1
        modelaudit scan models:/MyModel/Production

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

    # Set logging level based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Aggregated results
    aggregated_results: dict[str, Any] = {
        "bytes_scanned": 0,
        "issues": [],
        "files_scanned": 0,
        "assets": [],
        "has_errors": False,
        "scanner_names": [],
        "start_time": time.time(),
    }

    # Scan each path
    for path in paths:
        # Track temp directory for cleanup
        temp_dir = None
        actual_path = path

        try:
            # Check if this is a HuggingFace URL
            if is_huggingface_url(path):
                # Show download progress if in text mode
                if format == "text" and not output:
                    download_spinner = yaspin(Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}")
                    download_spinner.start()

                try:
                    # Download to a temporary directory
                    download_path = download_model(path, cache_dir=None)
                    actual_path = str(download_path)
                    # Track the temp directory for cleanup
                    temp_dir = str(download_path)

                    if format == "text" and not output:
                        download_spinner.ok(click.style("✅ Downloaded", fg="green", bold=True))

                except Exception as e:
                    if format == "text" and not output:
                        download_spinner.fail(click.style("❌ Download failed", fg="red", bold=True))

                    logger.error(f"Failed to download model from {path}: {e!s}", exc_info=verbose)
                    click.echo(f"Error downloading model from {path}: {e!s}", err=True)
                    aggregated_results["has_errors"] = True
                    continue
            
            # Check if this is a cloud storage URL
            elif is_cloud_url(path):
                if format == "text" and not output:
                    download_spinner = yaspin(Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}")
                    download_spinner.start()

                try:
                    download_path = download_from_cloud(path, cache_dir=None)
                    actual_path = str(download_path)
                    temp_dir = str(download_path)

                    if format == "text" and not output:
                        download_spinner.ok(click.style("✅ Downloaded", fg="green", bold=True))

                except Exception as e:
                    if format == "text" and not output:
                        download_spinner.fail(click.style("❌ Download failed", fg="red", bold=True))

                    logger.error(f"Failed to download from {path}: {e!s}", exc_info=verbose)
                    click.echo(f"Error downloading from {path}: {e!s}", err=True)
                    aggregated_results["has_errors"] = True
                    continue

            # Check if this is an MLflow URI
            elif is_mlflow_uri(path):
                # Show download progress if in text mode
                if format == "text" and not output:
                    download_spinner = yaspin(Spinners.dots, text=f"Downloading from {click.style(path, fg='cyan')}")
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
                    aggregated_results["issues"].extend(results.get("issues", []))
                    aggregated_results["files_scanned"] += results.get("files_scanned", 1)
                    aggregated_results["assets"].extend(results.get("assets", []))
                    if results.get("has_errors", False):
                        aggregated_results["has_errors"] = True

                    # Track scanner names
                    for scanner in results.get("scanners", []):
                        if scanner and scanner not in aggregated_results["scanner_names"] and scanner != "unknown":
                            aggregated_results["scanner_names"].append(scanner)

                    # Skip the normal scanning logic since we already have results
                    continue

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
                )

                # Aggregate results
                aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
                aggregated_results["issues"].extend(results.get("issues", []))
                aggregated_results["files_scanned"] += results.get(
                    "files_scanned",
                    1,
                )  # Count each file scanned
                aggregated_results["assets"].extend(results.get("assets", []))
                if results.get("has_errors", False):
                    aggregated_results["has_errors"] = True

                # Track scanner names
                for scanner in results.get("scanners", []):
                    if scanner and scanner not in aggregated_results["scanner_names"] and scanner != "unknown":
                        aggregated_results["scanner_names"].append(scanner)

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
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    if verbose:
                        logger.info(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e!s}")

    # Calculate total duration
    aggregated_results["duration"] = time.time() - aggregated_results["start_time"]

    # Generate SBOM if requested
    if sbom:
        from .sbom import generate_sbom

        sbom_text = generate_sbom(paths, aggregated_results)
        with open(sbom, "w") as f:
            f.write(sbom_text)

    # Format the output
    if format == "json":
        output_data = aggregated_results
        output_text = json.dumps(output_data, indent=2)
    else:
        # Text format
        output_text = format_text_output(aggregated_results, verbose)

    # Send output to the specified destination
    if output:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Results written to {output}")
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
        output_lines.append(
            "  " + click.style("✅ No security issues detected", fg="green", bold=True),
        )
        output_lines.append("")

    # Add a footer with final status
    output_lines.append("")
    output_lines.append("═" * 80)

    # Determine overall status
    if visible_issues:
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
    else:
        status_icon = "✅"
        status_msg = "NO ISSUES FOUND"
        status_color = "green"

    # Display final status
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
    cli()
