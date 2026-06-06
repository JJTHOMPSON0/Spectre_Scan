import argparse
import asyncio
import os
import sys
import time
from dotenv import load_dotenv
from rich.console import Console

from core.discovery import discover_live_hosts
from core.plugin_manager import load_plugins, run_plugins
from core.reporter import save_report
from core.scanner import run_scan
from core.scripts import run_scripts
from core.syn import syn_scan
from core.utils import parse_ports
from core.target_validation import validate_target
from core.interactive import interactive_menu
from core.timing import get_timing_profile, describe_timing_profile
from core.proxy import proxy_manager
from core.cve_engine import cve_engine
from core.lua_scripts import script_library
from core.fingerprinting import AggressiveFingerprinting
from rich.table import Table

# Load environment variables from .env
load_dotenv()

console = Console()
parser = argparse.ArgumentParser(description="SpectreScan")

parser.add_argument("target", nargs="?", help="Target IP or CIDR")
parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive menu mode")
parser.add_argument("-P", "--ports", default="1-65535", help="Port range or list, e.g. 22,80,443,1000-2000")
parser.add_argument("-M", "--scan-type", choices=["auto", "tcp", "syn", "udp", "all"], default="auto", help="Scan type to perform (auto uses SYN if root else TCP)")
parser.add_argument("-T", "--timing-template", type=int, choices=[0, 1, 2, 3, 4, 5], default=3, help="Timing template: 0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal (default), 4=Aggressive, 5=Insane")
parser.add_argument("--timeout", type=float, default=None, help="Connection timeout in seconds (overrides timing template)")
parser.add_argument("-c", "--concurrency", type=int, default=None, help="Maximum concurrent probes (overrides timing template)")
parser.add_argument("-n", "--no-discovery", action="store_true", help="Skip host discovery and scan the provided target directly")
parser.add_argument("-sS", "--syn", action="store_true", help="Perform TCP SYN scan (requires root)")
parser.add_argument("-sU", "--udp", action="store_true", help="Perform UDP scan")
parser.add_argument("-O", "--os", action="store_true", help="Enable OS detection via TTL")
parser.add_argument("--aggressive-fingerprinting", action="store_true", help="Enable aggressive OS fingerprinting (TCP window, SYN cookies, etc.)")
parser.add_argument("-sV", "--version", action="store_true", help="Probe open ports for service/version info")
parser.add_argument("--check-cve", action="store_true", help="Check detected services for known CVEs")
parser.add_argument("-sC", "--scripts", action="store_true", help="Run built-in Nmap-style scripts")
parser.add_argument("-C", "--script-categories", default="default", help="Comma-separated script categories to run")
parser.add_argument("-p", "--plugins", action="store_true", help="Run service plugins from the plugins folder")
parser.add_argument("--proxy", metavar="PROXY_URL", help="Use proxy (e.g., http://host:port, socks5://host:port)")
parser.add_argument("-o", "--save", metavar="FILE", help="Save report to JSON")

args = parser.parse_args()

if len(sys.argv) == 2 and sys.argv[1].lower() == "help":
    parser.print_help()
    raise SystemExit(0)

def is_root():
    return getattr(os, "geteuid", lambda: 1)() == 0


# Apply timing template if no manual overrides
timing_profile = get_timing_profile(args.timing_template)
if args.timeout is None:
    args.timeout = timing_profile.timeout
if args.concurrency is None:
    args.concurrency = timing_profile.concurrency

console.print(f"[cyan]Timing template: {timing_profile.name} (T{args.timing_template})[/cyan]")
console.print(f"[cyan]Timeout: {args.timeout}s, Concurrency: {args.concurrency}[/cyan]")

# Configure proxy if provided
if args.proxy:
    proxy_manager.enable_proxy(args.proxy)

# If target is not provided, default to interactive console mode
if not args.target:
    args.interactive = True

if args.interactive:
    interactive_menu()
    raise SystemExit(0)

if not validate_target(args.target):
    parser.error("invalid target: must be an IP address, CIDR, or hostname")

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

# Aggressive OS fingerprinting
if args.aggressive_fingerprinting and results:
    console.print("\n[+] Running aggressive OS fingerprinting...")
    for result in results:
        host = result.get("host")
        if host:
            fp_results = AggressiveFingerprinting.run_aggressive_fingerprinting(host, ports[:3])
            if fp_results["techniques"]:
                result["aggressive_fingerprinting"] = fp_results
                console.print(f"    [cyan]{host}: {fp_results['best_guess']} ({fp_results['confidence']}%)[/cyan]")

# CVE checking
if args.check_cve and results:
    console.print("\n[+] Checking for CVEs...")
    for result in results:
        service = result.get("banner", "").split("/")[0] if result.get("banner") else ""
        version = result.get("version", "")
        if service:
            cve_engine.check_service_vulnerabilities(result.get("host"), result.get("port"), service, version)
            cves = cve_engine.lookup_service_cves(service, version)
            if cves:
                result["cves"] = [cve.get("cve", {}).get("id") for cve in cves[:3]]

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
    
    # Advanced Lua-style scripting
    console.print("\n[*] Initiating Advanced NSE-style Scripts...")
    for host_data in results:
        port = host_data.get("port")
        scripts = script_library.get_scripts_by_port(port)
        for script in scripts:
            result = script_library.execute_script(
                script.name,
                host_data["host"],
                port,
            )
            if result:
                console.print(f"    [cyan]|_ {script.name}: {result.get('result')}[/cyan]")

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
