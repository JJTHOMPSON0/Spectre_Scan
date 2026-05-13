import argparse
import asyncio
import os
import time
from rich.console import Console

from core.discovery import discover_live_hosts
from core.plugin_manager import load_plugins, run_plugins
from core.reporter import save_report
from core.scanner import run_scan
from core.scripts import run_scripts
from core.syn import syn_scan
from core.utils import parse_ports
from rich.table import Table

console = Console()
parser = argparse.ArgumentParser(description="SpectreScan")

parser.add_argument("target", nargs="?", help="Target IP or CIDR")
parser.add_argument("-P", "--ports", default="1-1024", help="Port range or list, e.g. 22,80,443,1000-2000")
parser.add_argument("-M", "--scan-type", choices=["auto", "tcp", "syn", "udp", "all"], default="auto", help="Scan type to perform (auto uses SYN if root else TCP)")
parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Connection timeout in seconds")
parser.add_argument("-c", "--concurrency", type=int, default=500, help="Maximum concurrent probes")
parser.add_argument("-n", "--no-discovery", action="store_true", help="Skip host discovery and scan the provided target directly")
parser.add_argument("-sS", "--syn", action="store_true", help="Perform TCP SYN scan (requires root)")
parser.add_argument("-sU", "--udp", action="store_true", help="Perform UDP scan")
parser.add_argument("-O", "--os", action="store_true", help="Enable OS detection via TTL")
parser.add_argument("-sV", "--version", action="store_true", help="Probe open ports for service/version info")
parser.add_argument("-sC", "--scripts", action="store_true", help="Run built-in Nmap-style scripts")
parser.add_argument("-C", "--script-categories", default="default", help="Comma-separated script categories to run")
parser.add_argument("-p", "--plugins", action="store_true", help="Run service plugins from the plugins folder")
parser.add_argument("-o", "--save", metavar="FILE", help="Save report to JSON")
parser.add_argument("-H", "--help-brief", action="store_true", help="List compact arguments and one-line usage notes")

args = parser.parse_args()

def is_root():
    return getattr(os, "geteuid", lambda: 1)() == 0


def print_help_brief():
    print("Usage: main.py [options] target\n")
    print("TARGET SPECIFICATION:")
    print("  target                Target IP or CIDR")
    print("HOST DISCOVERY:")
    print("  -n, --no-discovery    Skip discovery and scan target directly")
    print("SCAN TYPES:")
    print("  -M, --scan-type       auto, tcp, syn, udp, all")
    print("                         auto uses SYN if root else TCP")
    print("  -sS, --syn            TCP SYN scan (requires root)")
    print("  -sU, --udp            UDP scan")
    print("  -O, --os              OS detection via TTL (requires root)")
    print("SERVICE/VERSION DETECTION:")
    print("  -sV, --version        Probe open ports for service/version info")
    print("SCRIPTS & PLUGINS:")
    print("  -sC, --scripts        Run built-in Nmap-style scripts")
    print("  -C, --script-categories  Script categories to run")
    print("  -p, --plugins         Run service plugins")
    print("PERFORMANCE:")
    print("  -P, --ports           Port range/list, e.g. 22,80,443,1000-2000")
    print("  -T, --timeout         Connection timeout in seconds")
    print("  -c, --concurrency     Maximum concurrent probes")
    print("OUTPUT:")
    print("  -o, --save FILE       Save report to JSON")
    print("  -H, --help-brief      Show this compact help")

if args.help_brief:
    print_help_brief()
    raise SystemExit(0)

if not args.target:
    parser.error("the following arguments are required: target")

if args.scan_type == "auto":
    if is_root():
        args.scan_type = "syn"
        console.print("[green]Auto scan selected: running SYN scan because root privileges are available.[/green]")
    else:
        args.scan_type = "tcp"
        console.print("[yellow]Auto scan selected: running TCP connect scan because root privileges are not available.[/yellow]")

if args.scan_type == "syn" and not is_root():
    console.print("[yellow]Warning: scan-type syn requires root. Switching to tcp scan.[/yellow]")
    args.scan_type = "tcp"

if args.scan_type == "all" and not is_root():
    console.print("[yellow]Warning: scan-type all requires root for SYN/OS detection. SYN and OS detection will be skipped.[/yellow]")
    args.os = False
    args.scan_type = "tcp"

if args.syn and not is_root():
    console.print("[yellow]Warning: SYN scan (-sS) requires root. SYN scan will be disabled.[/yellow]")
    args.syn = False

if args.os and not is_root():
    console.print("[yellow]Warning: OS detection (-O) requires root. OS detection will be disabled.[/yellow]")
    args.os = False

try:
    ports = parse_ports(args.ports)
except ValueError as exc:
    console.print(f"[red]Invalid port specification: {exc}[/red]")
    raise SystemExit(1)

if args.no_discovery:
    live_hosts = [args.target]
elif "/" in args.target:
    live_hosts = discover_live_hosts(args.target)
else:
    live_hosts = [args.target]

if not live_hosts:
    console.print("[-] No live hosts discovered. Exiting.")
    raise SystemExit(1)

results = []
plugins = load_plugins() if args.plugins else []
os_detect = args.os and is_root()

scan_start = time.time()

if args.scan_type in ("syn", "all") or args.syn:
    console.print("\n[+] Running SYN scan...")
    syn_results = syn_scan(live_hosts, ports, os_detect=os_detect)
    results.extend(syn_results)

if args.scan_type in ("tcp", "all"):
    console.print(f"\n[+] Running TCP connect scan on {len(live_hosts)} host(s)...")
    tcp_results = asyncio.run(
        run_scan(
            live_hosts,
            ports,
            version_detect=args.version,
            os_detect=os_detect,
            concurrency=args.concurrency,
            timeout=args.timeout,
        )
    )
    results.extend(tcp_results)

if args.scan_type in ("udp", "all") or args.udp:
    from core.udp import udp_scan

    console.print(f"\n[+] Running UDP scan on {len(live_hosts)} host(s)...")
    udp_results = udp_scan(live_hosts, ports, timeout=args.timeout)
    results.extend(udp_results)

if results:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("HOST")
    table.add_column("PORT")
    table.add_column("STATE")
    table.add_column("SERVICE/VERSION")
    table.add_column("OS")

    for row in sorted(results, key=lambda item: (item.get("host", ""), item.get("port", 0))):
        service = row.get("banner", "-")
        if isinstance(service, dict):
            service = ", ".join(f"{k}: {v}" for k, v in service.items())
        os_info = row.get("os", "-")
        table.add_row(
            row.get("host", ""),
            f"{row.get('port', '')}/{row.get('protocol', 'tcp')}",
            row.get("status", ""),
            service,
            os_info,
        )

    console.print("\n[bold green]Scan results:[/bold green]")
    console.print(table)

scan_end = time.time()
scan_duration = scan_end - scan_start
console.print(f"\n[cyan]SpectreScan done at {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(scan_end))}[/cyan]")
console.print(f"[cyan]SpectreScan scan report for {args.target}[/cyan]")
console.print(f"[cyan]Scan time: {scan_duration:.2f} seconds[/cyan]")

if args.scripts:
    console.print("\n[*] Initiating Script Engine (-sC)...")
    for host_data in results:
        script_output = run_scripts(
            host_data["host"],
            host_data["port"],
            host_data.get("banner", ""),
            categories=args.script_categories,
        )
        if script_output:
            host_data["script_results"] = script_output
            for script_name, script_data in script_output:
                console.print(f"    [cyan]|_ {script_name}: {script_data}[/cyan]")

if args.plugins and plugins:
    console.print("\n[*] Running service plugins...")
    for host_data in results:
        plugin_output = run_plugins(plugins, host_data["host"], host_data["port"], host_data.get("banner", ""))
        if plugin_output:
            host_data["plugins"] = plugin_output
            for plugin_name, plugin_data in plugin_output.items():
                console.print(f"    [magenta]{plugin_name} returned {plugin_data}[/magenta]")

if args.save:
    save_report(args.target, results, args.save)
