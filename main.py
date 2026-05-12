import argparse
import asyncio
from rich.console import Console

from core.discovery import discover_live_hosts
from core.scanner import run_scan
from core.syn import syn_scan
from core.reporter import save_report
# We will create this script runner next
from core.scripts import run_default_scripts 

console = Console()
parser = argparse.ArgumentParser(description="SpectreScan")

parser.add_argument("target", help="Target IP or CIDR")
parser.add_argument("--start", type=int, default=1)
parser.add_argument("--end", type=int, default=1024)
parser.add_argument("--syn", action="store_true", help="Requires sudo/root privileges")
parser.add_argument("-sU", "--udp", action="store_true", help="Perform UDP Scan")
parser.add_argument("-O", "--os", action="store_true", help="Enable OS detection via TTL")
parser.add_argument("-sV", "--version", action="store_true", help="Probe open ports for service/version info")
parser.add_argument("-sC", "--scripts", action="store_true", help="Run default Nmap-style scripts")
parser.add_argument("--save", metavar="FILE", help="Save report to JSON")

args = parser.parse_args()

live_hosts = discover_live_hosts(args.target)
if not live_hosts:
    print("[-] No live hosts discovered. Exiting.")
    exit()

results = []

# --- HYBRID LOGIC ---
if args.os and args.version:
    console.print("\n[+] Hybrid Scan Initiated (OS + Version Detection)...")
    # Phase 1: Fast SYN scan for open ports and OS
    syn_results = syn_scan(live_hosts, args.start, args.end, os_detect=True)
    
    # Phase 2: Feed ONLY the open ports to the async version detector
    # (This requires a slight modification to run_scan, which we'll do below)
    results = asyncio.run(
        run_scan(live_hosts, args.start, args.end, version_detect=True, target_ports=[r['port'] for r in syn_results])
    )
    
    # Merge the OS info from Phase 1 into the Phase 2 results
    for res in results:
        for syn_res in syn_results:
            if res['port'] == syn_res['port']:
                res['os'] = syn_res.get('os', 'Unknown')
                
elif args.syn or args.os:
    results = syn_scan(live_hosts, args.start, args.end, os_detect=args.os)
elif args.udp:
    from core.udp import udp_scan
    results = udp_scan(live_hosts, args.start, args.end)
else:
    results = asyncio.run(
        run_scan(live_hosts, args.start, args.end, version_detect=args.version)
    )

# --- SCRIPTING ENGINE (-sC) ---
if args.scripts:
    console.print("\n[*] Initiating Default Scripts (-sC)...")
    for host_data in results:
        script_output = run_default_scripts(host_data['host'], host_data['port'], host_data.get('banner', ''))
        if script_output:
            host_data['script_results'] = script_output
            for line in script_output:
                console.print(f"    [cyan]{line}[/cyan]")

if args.save:
    save_report(args.target, results, args.save)
