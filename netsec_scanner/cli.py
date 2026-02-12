"""CLI interface for netsec-scanner."""

import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.text import Text

from netsec_scanner import __version__, Severity, SEVERITY_ORDER
from netsec_scanner.scanner import NetworkScanner
from netsec_scanner.report import generate_report

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


def print_banner():
    banner = Text()
    banner.append("╔══════════════════════════════════════╗\n", style="cyan")
    banner.append("║       ", style="cyan")
    banner.append("netsec-scanner", style="bold bright_cyan")
    banner.append(f" v{__version__}", style="cyan")
    banner.append("       ║\n", style="cyan")
    banner.append("║  ", style="cyan")
    banner.append("Network Security Assessment Tool", style="white")
    banner.append("   ║\n", style="cyan")
    banner.append("╚══════════════════════════════════════╝", style="cyan")
    console.print(banner)
    console.print()


@click.group()
@click.version_option(version=__version__)
def cli():
    """netsec-scanner — Network device security scanner."""
    pass


@cli.command()
@click.argument("target")
@click.option("--ports", default="top-1000", help="Port range: top-100, top-1000, all, or custom (e.g. 1-1024,8080)")
@click.option("--deep", is_flag=True, help="Deep scan: all ports, OS detection, aggressive checks")
@click.option("--modules", default="all", help="Comma-separated modules: discovery,vulns,checks (default: all)")
@click.option("--format", "fmt", type=click.Choice(["md", "html", "json"]), default=None, help="Report format")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("--timeout", default=300, type=int, help="Per-host timeout in seconds")
@click.option("--i-own-this", is_flag=True, help="Acknowledge you have permission to scan the target")
def scan(target, ports, deep, modules, fmt, output, timeout, i_own_this):
    """Scan a target (IP, hostname, or CIDR) for security issues."""
    print_banner()

    if not i_own_this:
        console.print("[bold yellow]⚠  LEGAL WARNING[/bold yellow]")
        console.print("Scanning networks without authorization is illegal in most jurisdictions.")
        console.print("Only scan systems you own or have explicit written permission to test.\n")
        if not click.confirm("Do you have authorization to scan this target?"):
            console.print("[red]Scan aborted.[/red]")
            sys.exit(1)
        console.print()

    is_root = os.geteuid() == 0
    if not is_root:
        console.print("[yellow]⚠  Not running as root — SYN scan unavailable, falling back to connect scan.[/yellow]")
        console.print("[dim]  Run with sudo for SYN scanning and OS detection.[/dim]\n")

    if deep:
        ports = "all"

    module_list = [m.strip() for m in modules.split(",")] if modules != "all" else ["discovery", "vulns", "checks"]

    scanner = NetworkScanner(
        target=target,
        ports=ports,
        deep=deep,
        modules=module_list,
        timeout=timeout,
        is_root=is_root,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {target}...", total=100)

        def on_progress(pct, msg):
            progress.update(task, completed=pct, description=msg)

        results = scanner.run(progress_callback=on_progress)

    console.print()

    # Display results
    for host in results:
        host.calculate_risk()
        risk_color = SEVERITY_COLORS.get(host.risk_score.value, "white")

        header = f"[bold]{host.ip}[/bold]"
        if host.hostname:
            header += f" ({host.hostname})"
        if host.os_guess:
            header += f" — {host.os_guess}"

        console.print(Panel(header, title=f"[{risk_color}]{host.risk_score.value} RISK[/{risk_color}]", border_style=risk_color))

        # Port table
        if host.ports:
            pt = Table(title="Open Ports", show_header=True, header_style="bold")
            pt.add_column("Port", style="cyan", width=8)
            pt.add_column("Protocol", width=8)
            pt.add_column("Service", style="green")
            pt.add_column("Version")
            for p in host.ports:
                pt.add_row(str(p.get("port", "")), p.get("protocol", "tcp"), p.get("service", ""), p.get("version", ""))
            console.print(pt)
            console.print()

        # Findings table
        if host.findings:
            sorted_findings = sorted(host.findings, key=lambda f: SEVERITY_ORDER[f.severity])
            ft = Table(title="Findings", show_header=True, header_style="bold")
            ft.add_column("Severity", width=10)
            ft.add_column("Port", width=8)
            ft.add_column("Title")
            ft.add_column("CVE", width=16)
            for f in sorted_findings:
                sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
                ft.add_row(
                    f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                    str(f.port) if f.port else "",
                    f.title,
                    f.cve or "",
                )
            console.print(ft)
        else:
            console.print("[green]No findings.[/green]")

        console.print()

    # Summary
    total_findings = sum(len(h.findings) for h in results)
    counts = {s.value: 0 for s in Severity}
    for h in results:
        for f in h.findings:
            counts[f.severity.value] += 1

    summary = Table(title="Summary", show_header=True, header_style="bold")
    summary.add_column("Severity")
    summary.add_column("Count", justify="right")
    for s in Severity:
        c = SEVERITY_COLORS.get(s.value, "white")
        summary.add_row(f"[{c}]{s.value}[/{c}]", str(counts[s.value]))
    summary.add_row("[bold]TOTAL[/bold]", f"[bold]{total_findings}[/bold]")
    console.print(summary)

    # Report generation
    if fmt or output:
        fmt = fmt or "md"
        output = output or f"netsec-report.{fmt}"
        report = generate_report(results, target, fmt)
        with open(output, "w") as f:
            f.write(report)
        console.print(f"\n[green]Report saved to {output}[/green]")


def main():
    cli()


if __name__ == "__main__":
    main()
