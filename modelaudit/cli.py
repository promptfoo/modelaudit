import io
import json
import logging
import os
import sys
import time
from typing import Any, Optional

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

    # Add scan summary header with emoji
    console.print("\n📊 [bold white]SCAN SUMMARY[/bold white]")
    console.print("─" * 60)

    # Create summary table
    summary = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))

    scanners = results.get("scanner_names")
    if scanners:
        label = "🔍 Active Scanner" if len(scanners) == 1 else "🔍 Active Scanners"
        summary.add_row(label, "[blue]" + ", ".join(scanners) + "[/blue]")

    duration = results.get("duration")
    if duration is not None:
        if duration < 0.01:
            duration_str = f"{duration:.3f}s"
        else:
            duration_str = f"{duration:.2f}s"
        summary.add_row("⏱️  Duration", f"[cyan]{duration_str}[/cyan]")

    if "files_scanned" in results:
        summary.add_row("📁 Files scanned", f"[cyan]{results['files_scanned']}[/cyan]")

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
        summary.add_row("💾 Data scanned", f"[cyan]{size_str}[/cyan]")

    console.print(summary)

    # Add security findings section
    issues = results.get("issues", [])
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

    console.print("\n🔍 [bold white]SECURITY FINDINGS[/bold white]")
    console.print("─" * 60)

    if visible_issues:
        # Show issue counts with rich formatting
        count_table = Table(show_header=False, box=None, padding=(0, 2))
        
        if severity_counts["critical"] > 0:
            count_table.add_row(
                "🚨",
                f"[bold red]{severity_counts['critical']} Critical[/bold red]"
            )
        if severity_counts["warning"] > 0:
            count_table.add_row(
                "⚠️",
                f"[yellow]{severity_counts['warning']} Warning{'s' if severity_counts['warning'] > 1 else ''}[/yellow]"
            )
        if severity_counts["info"] > 0:
            count_table.add_row(
                "ℹ️",
                f"[blue]{severity_counts['info']} Info[/blue]"
            )
        if verbose and severity_counts["debug"] > 0:
            count_table.add_row(
                "🐛",
                f"[cyan]{severity_counts['debug']} Debug[/cyan]"
            )
            
        console.print(count_table)
        console.print()

        # Group and display issues by severity
        critical_issues = [
            issue
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "critical"
        ]
        if critical_issues:
            console.print("🚨 [bold red]Critical Issues[/bold red]")
            console.print("─" * 40)
            for issue in critical_issues:
                _format_issue_rich(console, issue, "critical")
            console.print()

        warning_issues = [
            issue
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "warning"
        ]
        if warning_issues:
            if critical_issues:
                console.print()
            console.print("⚠️  [bold yellow]Warnings[/bold yellow]")
            console.print("─" * 40)
            for issue in warning_issues:
                _format_issue_rich(console, issue, "warning")
            console.print()

        info_issues = [
            issue
            for issue in visible_issues
            if isinstance(issue, dict) and issue.get("severity") == "info"
        ]
        if info_issues:
            if critical_issues or warning_issues:
                console.print()
            console.print("ℹ️  [bold blue]Information[/bold blue]")
            console.print("─" * 40)
            for issue in info_issues:
                _format_issue_rich(console, issue, "info")
            console.print()

        if verbose:
            debug_issues = [
                issue
                for issue in issues
                if isinstance(issue, dict) and issue.get("severity") == "debug"
            ]
            if debug_issues:
                console.print("🐛 [bold cyan]Debug Information[/bold cyan]")
                console.print("─" * 40)
                for issue in debug_issues:
                    _format_issue_rich(console, issue, "debug")
                console.print()

    else:
        console.print("✅ [bold green]No security issues found[/bold green]")

    # Asset inventory (keep existing Rich tree implementation)
    if "assets" in results and results["assets"]:
        console.print("\n📦 [bold white]ASSET INVENTORY[/bold white]")
        console.print("─" * 60)

        # Group assets by scanner type
        assets_by_scanner: dict[str, list[dict[str, Any]]] = {}
        for asset in results["assets"]:
            scanner = asset.get("scanner", "unknown")
            if scanner not in assets_by_scanner:
                assets_by_scanner[scanner] = []
            assets_by_scanner[scanner].append(asset)

        # Create tree structure
        tree = Tree("📦 [bold]Discovered Assets[/bold]")

        def add_assets(node: Tree, items: list[dict[str, Any]]):
            for asset in items[:10]:  # Limit to first 10 per scanner
                asset_name = asset.get("path", "Unknown")
                asset_type = asset.get("type", "unknown")
                asset_size = asset.get("size")

                # Format the asset entry
                if asset_size:
                    if asset_size >= 1024 * 1024:
                        size_str = f"{asset_size / (1024 * 1024):.1f}MB"
                    elif asset_size >= 1024:
                        size_str = f"{asset_size / 1024:.1f}KB"
                    else:
                        size_str = f"{asset_size}B"
                    asset_info = f"[cyan]{asset_name}[/cyan] ([dim]{asset_type}, {size_str}[/dim])"
                else:
                    asset_info = f"[cyan]{asset_name}[/cyan] ([dim]{asset_type}[/dim])"

                node.add(asset_info)

            if len(items) > 10:
                node.add(f"[dim]... and {len(items) - 10} more[/dim]")

        for scanner, assets in assets_by_scanner.items():
            scanner_node = tree.add(f"🔍 [blue]{scanner}[/blue] ({len(assets)} assets)")
            add_assets(scanner_node, assets)

        console.print(tree)

    # Final status
    console.print("\n" + "─" * 80)
    if visible_issues:
        if any(
            isinstance(issue, dict) and issue.get("severity") == "critical"
            for issue in visible_issues
        ):
            console.print("[bold red]✗ Scan completed with critical findings[/bold red]")
        elif any(
            isinstance(issue, dict) and issue.get("severity") == "warning"
            for issue in visible_issues
        ):
            console.print("[bold yellow]⚠ Scan completed with warnings[/bold yellow]")
        else:
            console.print("[bold green]✓ Scan completed successfully[/bold green]")
    else:
        console.print("[bold green]✓ Scan completed successfully[/bold green]")

    return console.export_text()


def _format_issue_rich(console: Console, issue: dict[str, Any], severity: str) -> None:
    """Format a single issue using Rich."""
    message = issue.get("message", "Unknown issue")
    location = issue.get("location", "")
    
    # Color coding by severity
    severity_colors = {
        "critical": "red",
        "warning": "yellow",
        "info": "blue",
        "debug": "cyan"
    }
    color = severity_colors.get(severity, "white")
    
    if location:
        console.print(f"  📍 [bold {color}]{location}[/bold {color}]")
        console.print(f"     {message}")
    else:
        console.print(f"  • [{color}]{message}[/{color}]")
    
    # Add "Why" explanation if available
    why = issue.get("why")
    if why:
        console.print(f"     [dim]💡 {why}[/dim]")
    
    console.print()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
