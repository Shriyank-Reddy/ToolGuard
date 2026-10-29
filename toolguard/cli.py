"""Command line interface:  toolguard scan | lock | diff"""
import argparse
import json
import sys

from rich.console import Console
from rich.table import Table

from .checks import reveal
from .loader import load_path
from .lockfile import create_lock, load_lock, save_lock
from .scoring import ServerReport, scan_server

COLORS = {"Low": "green", "Medium": "yellow", "High": "bold red"}
SEV_COLORS = {"low": "green", "medium": "yellow", "high": "red"}
DEFAULT_LOCK = "toolguard.lock.json"
console = Console()


def print_report(report: ServerReport, only_check: str | None = None) -> None:
    color = COLORS[report.level]
    console.rule(f"[bold]{report.name}[/bold]  v{report.version or '?'}  -  server risk: "
                 f"[{color}]{report.level}[/{color}] ({report.score:.1f}/10)")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Risk")
    table.add_column("Score", justify="right")
    table.add_column("Flags")
    for t in report.tools:
        flags = sorted({f.check for f in t.findings if f.is_flag})
        table.add_row(t.name, f"[{COLORS[t.level]}]{t.level}[/]", f"{t.score:.0f}", ", ".join(flags) or "-")
    console.print(table)
    for t in report.tools:
        for f in t.findings:
            if only_check and f.check != only_check:
                continue
            c = SEV_COLORS[f.severity]
            console.print(f"  [{c}]{f.severity.upper():6}[/] [bold]{t.name}[/] [{f.check}] {f.reason}", highlight=False)
            if f.evidence:
                for line in reveal(f.evidence).splitlines():
                    console.print("           > " + line[:200], style="dim", markup=False, highlight=False)
    for f in report.notes:
        console.print(f"  [dim]{f.severity.upper():6} {f.tool}: {f.reason}[/dim]")


def cmd_scan(args) -> int:
    lock = load_lock(args.lock) if args.lock else None
    reports = [scan_server(s, lock) for s in load_path(args.path)]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        for r in reports:
            print_report(r)
        high = sum(r.level == "High" for r in reports)
        console.print(f"\nScanned {len(reports)} server(s): {high} High, "
                      f"{sum(r.level == 'Medium' for r in reports)} Medium, {sum(r.level == 'Low' for r in reports)} Low.")
    return 1 if any(r.level == "High" for r in reports) else 0


def cmd_lock(args) -> int:
    servers = load_path(args.path)
    save_lock(create_lock(servers), args.output)
    console.print(f"Locked {sum(len(s.tools) for s in servers)} tool(s) from {len(servers)} server(s) -> {args.output}")
    return 0


def cmd_diff(args) -> int:
    lock = load_lock(args.lock)
    changed = 0
    for server in load_path(args.path):
        report = scan_server(server, lock)
        findings = [f for t in report.tools for f in t.findings if f.check == "rug_pull"] + report.notes
        if not findings:
            console.print(f"[green]{server.name}: matches the lockfile[/green]")
            continue
        changed += 1
        console.rule(f"[bold]{server.name}[/bold] changed since it was locked")
        for f in findings:
            console.print(f"  [{SEV_COLORS[f.severity]}]{f.severity.upper():6}[/] [bold]{f.tool}[/] {f.reason}", highlight=False)
            for line in f.evidence.splitlines():
                console.print("      " + line, markup=False, highlight=False)
    return 1 if changed else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="toolguard", description="Static security scanner for AI-agent tools.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="scan a tool-definition file or folder")
    p.add_argument("path")
    p.add_argument("--json", action="store_true", help="print a JSON report instead of a table")
    p.add_argument("--lock", help="also compare against this lockfile (check 6, rug pull)")
    p.set_defaults(func=cmd_scan)
    p = sub.add_parser("lock", help="save fingerprints of the current tool definitions")
    p.add_argument("path")
    p.add_argument("-o", "--output", default=DEFAULT_LOCK)
    p.set_defaults(func=cmd_lock)
    p = sub.add_parser("diff", help="show what changed since the lockfile was written")
    p.add_argument("path")
    p.add_argument("--lock", default=DEFAULT_LOCK)
    p.set_defaults(func=cmd_diff)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as err:
        console.print(f"[red]error:[/red] {err}", highlight=False)
        return 2


if __name__ == "__main__":
    sys.exit(main())
