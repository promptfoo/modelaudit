import io
import json
import logging
import os
import sys
import time
from typing import Any

import click
from rich import box
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
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
    """Format scan results as human-readable text using Rich."""
    console = Console(file=io.StringIO(), record=True)

    summary = Table(show_header=False, box=box.SIMPLE)

    scanners = results.get("scanner_names")
    if scanners:
        label = "Active Scanner" if len(scanners) == 1 else "Active Scanners"
        summary.add_row(label, ", ".join(scanners))

    duration = results.get("duration")
    if duration is not None:
        if duration < 0.01:
            summary.add_row("Duration", f"{duration:.3f} seconds")
        else:
            summary.add_row("Duration", f"{duration:.2f} seconds")

    if "files_scanned" in results:
        summary.add_row("Files scanned", str(results["files_scanned"]))

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
        summary.add_row("Scanned", size_str)

    console.print(summary)

    issues = results.get("issues", [])
    visible_issues = [
        issue
        for issue in issues
        if verbose or not isinstance(issue, dict) or issue.get("severity") != "debug"
    ]

    if visible_issues:
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

        summary_parts = []
        if error_count:
            summary_parts.append(f"[red bold]{error_count} critical[/]")
        if warning_count:
            summary_parts.append(f"[yellow]{warning_count} warnings[/]")
        if info_count:
            summary_parts.append(f"[blue]{info_count} info[/]")
        if verbose and debug_count:
            summary_parts.append(f"[cyan]{debug_count} debug[/]")
        if summary_parts:
            console.print("Issues found: " + ", ".join(summary_parts))

        issue_table = Table(box=box.SIMPLE)
        issue_table.add_column("#", style="bold")
        issue_table.add_column("Severity")
        issue_table.add_column("Location")
        issue_table.add_column("Message")

        for i, issue in enumerate(visible_issues, 1):
            severity = issue.get("severity", "warning").lower()
            if severity == "critical":
                severity_text = "[bold red]CRITICAL[/]"
            elif severity == "warning":
                severity_text = "[yellow]WARNING[/]"
            elif severity == "info":
                severity_text = "[blue]INFO[/]"
            else:
                severity_text = "[cyan]DEBUG[/]"

            location = issue.get("location", "")
            message = issue.get("message", "Unknown issue")

            issue_table.add_row(str(i), severity_text, location, message)

            why = issue.get("why")
            if why:
                issue_table.add_row("", "", "", f"[magenta]Why:[/] {why}")

        console.print(issue_table)
    else:
        console.print("[bold green]✓ No issues found")

    assets = results.get("assets", [])
    if assets:
        tree = Tree("Assets encountered:")

        def add_assets(node: Tree, items: list[dict[str, Any]]):
            for asset in items:
                label = asset.get("path", "")
                if asset.get("type"):
                    label += f" ({asset['type']})"
                if asset.get("size"):
                    label += f" [{asset['size']} bytes]"
                child = node.add(label)
                if asset.get("tensors"):
                    child.add("Tensors: " + ", ".join(asset["tensors"]))
                if asset.get("keys"):
                    child.add("Keys: " + ", ".join(map(str, asset["keys"])))
                if asset.get("contents"):
                    add_assets(child, asset["contents"])

        add_assets(tree, assets)
        console.print(tree)

    console.rule()

    if visible_issues:
        if any(
            isinstance(issue, dict) and issue.get("severity") == "critical"
            for issue in visible_issues
        ):
            status = "[bold red]✗ Scan completed with findings[/]"
        elif any(
            isinstance(issue, dict) and issue.get("severity") == "warning"
            for issue in visible_issues
        ):
            status = "[bold yellow]⚠ Scan completed with warnings[/]"
        else:
            status = "[bold green]✓ Scan completed successfully[/]"
    else:
        status = "[bold green]✓ Scan completed successfully[/]"

    console.print(status)

    return console.export_text()


def main():
    cli()
