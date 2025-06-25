import io
import json
import logging
import os
import sys
import time
from typing import Any, Optional

import click
from rich.console import Console
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
def cli() -> None:
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
    paths: tuple[str, ...],
    blacklist: tuple[str, ...],
    format: str,
    output: Optional[str],
    sbom: Optional[str],
    timeout: int,
    verbose: bool,
    max_file_size: int,
    max_total_size: int,
) -> None:
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

    # Set logging level based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Aggregated results
    aggregated_results: dict[str, Any] = {
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

    # Add paths to results for formatting
    aggregated_results["paths"] = list(paths)

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
    """Format scan results as clean, focused text output."""
    console = Console(file=io.StringIO(), record=True)

    # Get basic info
    files_scanned = results.get("files_scanned", 0)
    bytes_scanned = results.get("bytes_scanned", 0)
    duration = results.get("duration", 0)
    scanner_names = results.get("scanner_names", [])

    # Format file size
    if bytes_scanned >= 1024 * 1024 * 1024:
        size_str = f"{bytes_scanned / (1024 * 1024 * 1024):.1f}GB"
    elif bytes_scanned >= 1024 * 1024:
        size_str = f"{bytes_scanned / (1024 * 1024):.1f}MB"
    elif bytes_scanned >= 1024:
        size_str = f"{bytes_scanned / 1024:.1f}KB"
    else:
        size_str = f"{bytes_scanned}B"

    # Determine scan target info
    paths = results.get("paths", [])
    if len(paths) == 1:
        path = paths[0]
        if os.path.isdir(path):
            scan_target = (
                f"📁 {os.path.basename(path)}/ ({files_scanned} files, {size_str})"
            )
        elif path.endswith(".zip") or path.endswith(".tar.gz"):
            scan_target = f"📦 {os.path.basename(path)} ({size_str})"
        else:
            scan_target = f"📄 {os.path.basename(path)} ({size_str})"
    else:
        scan_target = f"📁 {files_scanned} files ({size_str})"

    console.print("🔐 ModelAudit Security Scanner")
    console.print()
    console.print(scan_target)
    console.print()

    # Process issues
    issues = results.get("issues", [])
    visible_issues = [
        issue
        for issue in issues
        if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
    ]

    # Count issues by severity
    critical_issues = [
        i
        for i in visible_issues
        if isinstance(i, dict) and i.get("severity") == "critical"
    ]
    warning_issues = [
        i
        for i in visible_issues
        if isinstance(i, dict) and i.get("severity") == "warning"
    ]
    info_issues = [
        i for i in visible_issues if isinstance(i, dict) and i.get("severity") == "info"
    ]

    if not visible_issues:
        # Clean scan - very concise
        console.print("✅ [bold green]NO SECURITY ISSUES FOUND[/bold green]")
        console.print("─" * 42)
        console.print()

        # Brief summary for clean scans
        console.print("📊 [bold]SUMMARY[/bold]")
        console.print("─" * 20)

        scanner_text = ", ".join(scanner_names) if scanner_names else "unknown"
        duration_str = f"{duration:.3f}s" if duration < 0.01 else f"{duration:.2f}s"

        console.print(
            f"✓ Scanned: {files_scanned} file{'s' if files_scanned != 1 else ''} ({scanner_text})"
        )
        console.print(f"⏱️  Duration: {duration_str}")
        if scanner_names:
            console.print(
                f"🔍 Scanner{'s' if len(scanner_names) > 1 else ''}: {scanner_text}"
            )

        console.print()
        console.print("✅ [bold green]Scan completed successfully[/bold green]")
        console.print("─" * 80)

    else:
        # Issues found - show detailed breakdown
        issue_summary = []
        if critical_issues:
            count = len(critical_issues)
            issue_summary.append(f"{count} CRITICAL ISSUE{'S' if count > 1 else ''}")
        if warning_issues:
            count = len(warning_issues)
            issue_summary.append(f"{count} WARNING{'S' if count > 1 else ''}")
        if info_issues:
            count = len(info_issues)
            issue_summary.append(f"{count} INFO")

        console.print(f"🚨 [bold red]{', '.join(issue_summary)} FOUND[/bold red]")
        console.print("─" * 42)
        console.print()

        # Show critical issues first
        if critical_issues:
            console.print("🚨 [bold red]CRITICAL[/bold red]")
            for i, issue in enumerate(critical_issues):
                symbol = "├─" if i < len(critical_issues) - 1 else "└─"
                _format_issue_tree(console, issue, symbol, True)
            console.print()

        # Show warnings
        if warning_issues:
            console.print("⚠️  [bold yellow]WARNINGS[/bold yellow]")
            for i, issue in enumerate(warning_issues):
                symbol = "├─" if i < len(warning_issues) - 1 else "└─"
                _format_issue_tree(console, issue, symbol, False)
            console.print()

        # Show info in verbose mode
        if info_issues and verbose:
            console.print("ℹ️  [bold blue]INFO[/bold blue]")
            for i, issue in enumerate(info_issues):
                symbol = "├─" if i < len(info_issues) - 1 else "└─"
                _format_issue_tree(console, issue, symbol, False)
            console.print()

        # Show archive contents for complex scans (only in verbose or when relevant)
        show_contents = verbose or any(
            (issue.get("location") or "").count(":") > 0 for issue in visible_issues
        )
        if show_contents and results.get("assets"):
            _format_archive_contents(console, results["assets"], visible_issues)

        # Summary
        console.print("📊 [bold]SUMMARY[/bold]")
        console.print("─" * 20)

        scanner_text = ", ".join(scanner_names) if scanner_names else "unknown"
        duration_str = f"{duration:.3f}s" if duration < 0.01 else f"{duration:.2f}s"

        if any(":" in (issue.get("location") or "") for issue in visible_issues):
            # Archive scan
            nested_files = len(
                [i for i in visible_issues if ":" in (i.get("location") or "")]
            )
            console.print(f"✓ Scanned: 1 archive → {nested_files} nested files")
        else:
            console.print(
                f"✓ Scanned: {files_scanned} file{'s' if files_scanned != 1 else ''} ({scanner_text})"
            )

        console.print(f"⏱️  Duration: {duration_str}")
        if scanner_names:
            scanner_display = (
                " → ".join(scanner_names)
                if len(scanner_names) > 1
                else scanner_names[0]
            )
            console.print(
                f"🔍 Scanner{'s' if len(scanner_names) > 1 else ''}: {scanner_display}"
            )

        console.print()

        # Final status
        if critical_issues:
            console.print(
                "🚨 [bold red]Scan completed with CRITICAL findings[/bold red]"
            )
        elif warning_issues:
            console.print("⚠️  [bold yellow]Scan completed with warnings[/bold yellow]")
        else:
            console.print("✅ [bold green]Scan completed successfully[/bold green]")
        console.print("─" * 80)

    return console.export_text()


def _format_issue_tree(
    console: Console, issue: dict[str, Any], symbol: str, is_critical: bool
) -> None:
    """Format a single issue in tree structure with smart path handling."""
    message = issue.get("message", "Unknown issue")
    location = issue.get("location", "")

    # Smart path handling
    if location:
        if ":" in location:
            # Archive path like "archive.zip:file.pkl" or "archive.zip:file.pkl (pos 123)"
            parts = location.split(":")
            if len(parts) >= 2:
                inner_path = ":".join(parts[1:])

                # Clean up position info
                if " (pos " in inner_path:
                    inner_path = inner_path.split(" (pos ")[0]

                # Determine file type icon
                if inner_path.startswith("../"):
                    icon = "📁"  # Malicious path
                elif inner_path.endswith((".pkl", ".pt", ".pth")):
                    icon = "📄"
                else:
                    icon = "📄"

                file_context = f"{icon} {inner_path}"
            else:
                file_context = location
        else:
            # Regular file path - use basename
            import os

            file_context = os.path.basename(location)
    else:
        file_context = ""

    # Extract key information from message
    short_message = _shorten_message(message)

    # Format the main line
    if file_context:
        console.print(f"{symbol} {file_context}: {short_message}")
    else:
        console.print(f"{symbol} {short_message}")

    # Add explanation if available and important
    why = issue.get("why")
    if why and is_critical:
        # Shorten explanation for tree format
        short_why = _shorten_explanation(why)
        console.print(f"   💡 {short_why}")


def _format_archive_contents(
    console: Console, assets: list[dict], issues: list[dict]
) -> None:
    """Format archive contents when relevant."""
    # Only show if we have archives with nested content
    archive_assets = [a for a in assets if a.get("type") == "zip" and a.get("contents")]
    if not archive_assets:
        return

    console.print("📦 [bold]ARCHIVE CONTENTS[/bold]")
    for asset in archive_assets:
        contents = asset.get("contents", [])
        if contents:
            for i, content in enumerate(contents[:5]):  # Limit to first 5
                symbol = "├─" if i < min(len(contents), 5) - 1 else "└─"
                path = content.get("path", "")
                size = content.get("size", 0)

                # Check if this file has issues
                has_issues = any(path in issue.get("location", "") for issue in issues)

                if path.startswith("../"):
                    console.print(f"{symbol} 📁 {path} [red](MALICIOUS PATH)[/red]")
                else:
                    size_str = f"{size}B" if size < 1024 else f"{size // 1024}KB"
                    file_type = content.get("type", "unknown")
                    status = " [red](ISSUES)[/red]" if has_issues else ""
                    console.print(
                        f"{symbol} 📄 {path} ({file_type}, {size_str}){status}"
                    )

            if len(contents) > 5:
                console.print(f"    ... and {len(contents) - 5} more files")
        console.print()


def _shorten_message(message: str) -> str:
    """Shorten common message patterns for tree display."""
    # Common patterns to shorten
    replacements = {
        "Found REDUCE opcode - potential __reduce__ method execution": "REDUCE opcode (code execution risk)",
        "Found NEWOBJ opcode - potential code execution": "NEWOBJ opcode detected",
        "Suspicious module reference found: ": "",
        "Archive entry ": "",
        " attempted path traversal outside the archive": ": Path traversal attack",
        "Suspicious configuration pattern: ": "",
    }

    short = message
    for old, new in replacements.items():
        short = short.replace(old, new)

    # Truncate if still too long
    if len(short) > 60:
        short = short[:57] + "..."

    return short


def _shorten_explanation(explanation: str) -> str:
    """Shorten explanations for tree display."""
    # Take first sentence or up to 80 chars
    sentences = explanation.split(". ")
    if len(sentences[0]) <= 80:
        return sentences[0] + ("." if not sentences[0].endswith(".") else "")
    else:
        return explanation[:77] + "..." if len(explanation) > 80 else explanation


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
