import json
import logging
import os
import sys
import time

import click
from yaspin import yaspin
from yaspin.spinners import Spinners

from . import __version__
from .core import determine_exit_code, scan_model_directory_or_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("modelaudit")


@click.group()
@click.version_option(__version__)
def cli():
    """Static scanner for ML models"""
    pass


@cli.command("scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True), required=True)
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
def scan_command(paths, blacklist, format, output, timeout, verbose, max_file_size):
    """Scan files or directories for malicious content.

    \b
    Usage:
        modelaudit scan /path/to/model1 /path/to/model2 ...

    You can specify additional blacklist patterns with ``--blacklist`` or ``-b``:

        modelaudit scan /path/to/model1 /path/to/model2 -b llama -b alpaca

    \b
    Advanced options:
        --format, -f       Output format (text or json)
        --output, -o       Write results to a file instead of stdout
        --timeout, -t      Set scan timeout in seconds
        --verbose, -v      Show detailed information during scanning
        --max-file-size    Maximum file size to scan in bytes

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
                f"Additional blacklist patterns: "
                f"{click.style(', '.join(blacklist), fg='yellow')}",
            )
        click.echo("─" * 80)
        click.echo("")

    # Set logging level based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Aggregated results
    aggregated_results = {
        "scanner_names": [],  # Track all scanner names used
        "start_time": time.time(),
        "bytes_scanned": 0,
        "issues": [],
        "has_errors": False,
        "files_scanned": 0,
    }

    # Scan each path
    for path in paths:
        # Early exit for common non-model file extensions
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
                ".json",
                ".yaml",
                ".yml",
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

                def update_progress(message, percentage):
                    spinner.text = f"{message} ({percentage:.1f}%)"

                progress_callback = update_progress

            # Run the scan with progress reporting
            results = scan_model_directory_or_file(
                path,
                blacklist_patterns=list(blacklist) if blacklist else None,
                timeout=timeout,
                max_file_size=max_file_size,
                progress_callback=progress_callback,
            )

            # Aggregate results
            aggregated_results["bytes_scanned"] += results.get("bytes_scanned", 0)
            aggregated_results["issues"].extend(results.get("issues", []))
            aggregated_results["files_scanned"] += results.get(
                "files_scanned",
                1,
            )  # Count each file scanned
            if results.get("has_errors", False):
                aggregated_results["has_errors"] = True

            # Track scanner names
            for scanner in results.get("scanners", []):
                if (
                    scanner
                    and scanner not in aggregated_results["scanner_names"]
                    and scanner != "unknown"
                ):
                    aggregated_results["scanner_names"].append(scanner)

            # Show completion status if in text mode and not writing to a file
            if spinner:
                if results.get("issues", []):
                    # Filter out DEBUG severity issues when not in verbose mode
                    visible_issues = [
                        issue
                        for issue in results.get("issues", [])
                        if verbose
                        or not isinstance(issue, dict)
                        or issue.get("severity") != "debug"
                    ]
                    issue_count = len(visible_issues)
                    spinner.text = f"Scanned {click.style(path, fg='cyan')}"
                    if issue_count > 0:
                        spinner.ok(
                            click.style(
                                f"✓ Found {issue_count} issues!",
                                fg="yellow",
                                bold=True,
                            ),
                        )
                    else:
                        spinner.ok(click.style("✓", fg="green", bold=True))
                else:
                    spinner.text = f"Scanned {click.style(path, fg='cyan')}"
                    spinner.ok(click.style("✓", fg="green", bold=True))

        except Exception as e:
            # Show error if in text mode and not writing to a file
            if spinner:
                spinner.text = f"Error scanning {click.style(path, fg='cyan')}"
                spinner.fail(click.style("✗", fg="red", bold=True))

            logger.error(f"Error during scan of {path}: {str(e)}", exc_info=verbose)
            click.echo(f"Error scanning {path}: {str(e)}", err=True)
            aggregated_results["has_errors"] = True

    # Calculate total duration
    aggregated_results["duration"] = time.time() - aggregated_results["start_time"]

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


def format_text_output(results, verbose=False):
    """Format scan results as human-readable text with colors"""
    output_lines = []

    # Add summary information with styling
    if "scanner_names" in results and results["scanner_names"]:
        scanner_names = results["scanner_names"]
        if len(scanner_names) == 1:
            output_lines.append(
                click.style(
                    f"Active Scanner: {scanner_names[0]}", fg="blue", bold=True
                ),
            )
        else:
            output_lines.append(
                click.style(
                    f"Active Scanners: {', '.join(scanner_names)}",
                    fg="blue",
                    bold=True,
                ),
            )
    if "duration" in results:
        duration = results["duration"]
        if duration < 0.01:
            # For very fast scans, show more precision
            output_lines.append(
                click.style(
                    f"Scan completed in {duration:.3f} seconds",
                    fg="cyan",
                ),
            )
        else:
            output_lines.append(
                click.style(
                    f"Scan completed in {duration:.2f} seconds",
                    fg="cyan",
                ),
            )
    if "files_scanned" in results:
        output_lines.append(
            click.style(f"Files scanned: {results['files_scanned']}", fg="cyan"),
        )
    if "bytes_scanned" in results:
        # Format bytes in a more readable way
        bytes_scanned = results["bytes_scanned"]
        if bytes_scanned >= 1024 * 1024 * 1024:
            size_str = f"{bytes_scanned / (1024 * 1024 * 1024):.2f} GB"
        elif bytes_scanned >= 1024 * 1024:
            size_str = f"{bytes_scanned / (1024 * 1024):.2f} MB"
        elif bytes_scanned >= 1024:
            size_str = f"{bytes_scanned / 1024:.2f} KB"
        else:
            size_str = f"{bytes_scanned} bytes"
        output_lines.append(click.style(f"Scanned {size_str}", fg="cyan"))

    # Add issue details with color-coded severity
    issues = results.get("issues", [])
    # Filter out DEBUG severity issues when not in verbose mode
    visible_issues = [
        issue
        for issue in issues
        if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
    ]

    if visible_issues:
        # Count issues by severity (excluding DEBUG when not in verbose mode)
        error_count = sum(
            1
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "critical"
        )
        warning_count = sum(
            1
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "warning"
        )
        info_count = sum(
            1
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "info"
        )
        debug_count = sum(
            1
            for issue in issues
            if isinstance(issue, dict) and issue.get("severity") == "debug"
        )

        # Only show debug count in verbose mode
        issue_summary = []
        if error_count:
            issue_summary.append(
                click.style(f"{error_count} critical", fg="red", bold=True),
            )
        if warning_count:
            issue_summary.append(click.style(f"{warning_count} warnings", fg="yellow"))
        if info_count:
            issue_summary.append(click.style(f"{info_count} info", fg="blue"))
        if verbose and debug_count:
            issue_summary.append(click.style(f"{debug_count} debug", fg="cyan"))

        if issue_summary:
            output_lines.append(
                click.style("Issues found: ", fg="white") + ", ".join(issue_summary),
            )

        # Only display visible issues
        for i, issue in enumerate(visible_issues, 1):
            severity = issue.get("severity", "warning").lower()

            # Skip debug issues if verbose is not enabled
            if severity == "debug" and not verbose:
                continue

            message = issue.get("message", "Unknown issue")
            location = issue.get("location", "")

            # Color-code based on severity
            if severity == "critical":
                severity_style = click.style("[CRITICAL]", fg="red", bold=True)
            elif severity == "warning":
                severity_style = click.style("[WARNING]", fg="yellow")
            elif severity == "info":
                severity_style = click.style("[INFO]", fg="blue")
            elif severity == "debug":
                severity_style = click.style("[DEBUG]", fg="bright_black")

            # Format the issue line
            issue_num = click.style(f"{i}.", fg="white", bold=True)
            if location:
                location_str = click.style(f"{location}", fg="cyan", bold=True)
                output_lines.append(
                    f"{issue_num} {location_str}: {severity_style} {message}",
                )
            else:
                output_lines.append(f"{issue_num} {severity_style} {message}")

            # Add a small separator between issues for readability
            if i < len(visible_issues):
                output_lines.append("")
    else:
        output_lines.append(
            "\n" + click.style("✓ No issues found", fg="green", bold=True),
        )

    # Add a footer
    output_lines.append("─" * 80)
    if visible_issues:
        if any(
            isinstance(issue, dict) and issue.get("severity") == "critical"
            for issue in visible_issues
        ):
            status = click.style("✗ Scan completed with findings", fg="red", bold=True)
        else:
            status = click.style(
                "⚠ Scan completed with warnings",
                fg="yellow",
                bold=True,
            )
    else:
        status = click.style("✓ Scan completed successfully", fg="green", bold=True)
    output_lines.append(status)

    return "\n".join(output_lines)


def main():
    cli()
