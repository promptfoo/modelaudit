import json
import logging
import os
import sys
import time
from typing import Any

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
def scan_command(
    paths,
    blacklist,
    format,
    output,
    sbom,
    timeout,
    verbose,
    max_file_size,
    max_total_size,
):
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
        --sbom             Write CycloneDX SBOM to file
        --timeout, -t      Set scan timeout in seconds
        --verbose, -v      Show detailed information during scanning
        --max-file-size    Maximum file size to scan in bytes
        --max-total-size   Maximum total bytes to scan before stopping

    \b
    Exit codes:
        0 - Success, no security issues found
        1 - Security issues found (scan completed successfully)
        2 - Errors occurred during scanning
    """
    # Print a nice header if not in JSON mode and not writing to a file
    if format == "text" and not output:
        # Create a stylish header
        click.echo("")
        click.echo("╔" + "═" * 78 + "╗")
        click.echo("║" + " " * 78 + "║")

        # Title with icon
        title = "🔐 ModelAudit Security Scanner"
        title_styled = click.style(title, fg="blue", bold=True)
        padding = (78 - len(title)) // 2
        click.echo(
            "║" + " " * padding + title_styled + " " * (78 - padding - len(title)) + "║"
        )

        # Subtitle
        subtitle = "Scanning for potential security issues in ML model files"
        subtitle_styled = click.style(subtitle, fg="cyan")
        padding = (78 - len(subtitle)) // 2
        click.echo(
            "║"
            + " " * padding
            + subtitle_styled
            + " " * (78 - padding - len(subtitle))
            + "║"
        )

        click.echo("║" + " " * 78 + "║")
        click.echo("╚" + "═" * 78 + "╝")
        click.echo("")

        # Scan configuration
        click.echo(click.style("🎯 TARGET FILES", fg="white", bold=True))
        click.echo("─" * 40)
        for path in paths:
            click.echo(f"  📄 {click.style(path, fg='green')}")

        if blacklist:
            click.echo("")
            click.echo(click.style("🚫 BLACKLIST PATTERNS", fg="white", bold=True))
            click.echo("─" * 40)
            for pattern in blacklist:
                click.echo(f"  • {click.style(pattern, fg='yellow')}")

        click.echo("")
        click.echo("═" * 80)
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
        "assets": [],  # Track all assets encountered
    }

    # Scan each path
    for path in paths:
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

                def update_progress(message, percentage):
                    spinner.text = f"{message} ({percentage:.1f}%)"

                progress_callback = update_progress

            # Run the scan with progress reporting
            results = scan_model_directory_or_file(
                path,
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

    # Generate SBOM if requested
    if sbom:
        from .sbom import generate_sbom

        sbom_text = generate_sbom(paths, aggregated_results)
        with open(sbom, "w") as f:
            f.write(sbom_text)

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
    if "scanner_names" in results and results["scanner_names"]:
        scanner_names = results["scanner_names"]
        if len(scanner_names) == 1:
            metrics.append(("Scanner", scanner_names[0], "blue"))
        else:
            metrics.append(("Scanners", ", ".join(scanner_names), "blue"))

    # Duration
    if "duration" in results:
        duration = results["duration"]
        if duration < 0.01:
            duration_str = f"{duration:.3f}s"
        else:
            duration_str = f"{duration:.2f}s"
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
        issue
        for issue in issues
        if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
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
                    f"🚨 {severity_counts['critical']} Critical", fg="red", bold=True
                )
            )
        if severity_counts["warning"] > 0:
            summary_parts.append(
                "  "
                + click.style(
                    f"⚠️  {severity_counts['warning']} Warning{'s' if severity_counts['warning'] > 1 else ''}",
                    fg="yellow",
                )
            )
        if severity_counts["info"] > 0:
            summary_parts.append(
                "  " + click.style(f"ℹ️  {severity_counts['info']} Info", fg="blue")
            )
        if verbose and severity_counts["debug"] > 0:
            summary_parts.append(
                "  " + click.style(f"🐛 {severity_counts['debug']} Debug", fg="cyan")
            )

        output_lines.extend(summary_parts)

        # Group issues by severity for better organization
        output_lines.append("")

        # Display critical issues first
        critical_issues = [
            issue
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "critical"
        ]
        if critical_issues:
            output_lines.append(
                click.style("  🚨 Critical Issues", fg="red", bold=True)
            )
            output_lines.append("  " + "─" * 40)
            for issue in critical_issues:
                _format_issue(issue, output_lines, "critical")
                output_lines.append("")

        # Display warnings
        warning_issues = [
            issue
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "warning"
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
        info_issues = [
            issue
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "info"
        ]
        if info_issues:
            if critical_issues or warning_issues:
                output_lines.append("")
            output_lines.append(click.style("  ℹ️  Information", fg="blue", bold=True))
            output_lines.append("  " + "─" * 40)
            for issue in info_issues:
                _format_issue(issue, output_lines, "info")
                output_lines.append("")

        # Display debug issues if verbose
        if verbose:
            debug_issues = [
                issue
                for issue in visible_issues
                if isinstance(issue, dict) and issue.get("severity") == "debug"
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

    # Asset list - simplified
    assets = results.get("assets", [])
    if assets:
        output_lines.append(click.style("\n📦 SCANNED FILES", fg="white", bold=True))
        output_lines.append("" + "─" * 60)

        def render_assets(items, indent=1):
            lines = []
            for asset in items:
                prefix = "  " * indent
                path_str = asset.get("path", "")

                # Add size if available
                size_info = ""
                if asset.get("size"):
                    size = asset["size"]
                    if size >= 1024 * 1024:
                        size_info = f" ({size / (1024 * 1024):.1f} MB)"
                    elif size >= 1024:
                        size_info = f" ({size / 1024:.1f} KB)"
                    else:
                        size_info = f" ({size} bytes)"

                line = f"{prefix}• {click.style(path_str, fg='cyan')}{click.style(size_info, fg='bright_black')}"
                lines.append(line)

                # Recursively show contents for archives
                if asset.get("contents"):
                    lines.extend(render_assets(asset["contents"], indent + 1))
            return lines

        output_lines.extend(render_assets(assets))

    # Add a footer with final status
    output_lines.append("")
    output_lines.append("═" * 80)

    # Determine overall status
    if visible_issues:
        if any(
            isinstance(issue, dict) and issue.get("severity") == "critical"
            for issue in visible_issues
        ):
            status_icon = "❌"
            status_msg = "CRITICAL SECURITY ISSUES FOUND"
            status_color = "red"
        elif any(
            isinstance(issue, dict) and issue.get("severity") == "warning"
            for issue in visible_issues
        ):
            status_icon = "⚠️"
            status_msg = "WARNINGS DETECTED"
            status_color = "yellow"
        else:
            # Only info/debug issues
            status_icon = "ℹ️"
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
    issue: dict[str, Any], output_lines: list[str], severity: str
) -> None:
    """Format a single issue with proper indentation and styling"""
    message = issue.get("message", "Unknown issue")
    location = issue.get("location", "")

    # Icon based on severity
    icons = {
        "critical": "    └─ 🚨",
        "warning": "    └─ ⚠️ ",
        "info": "    └─ ℹ️ ",
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
            why, width=65, initial_indent="", subsequent_indent="           "
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


def main():
    cli()
