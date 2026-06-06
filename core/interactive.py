import cmd
import sys
import os
import time
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt

# Import core scanning libraries
from core.discovery import discover_live_hosts
from core.plugin_manager import load_plugins, run_plugins
from core.reporter import save_report
from core.scanner import run_scan
from core.scripts import run_scripts
from core.syn import syn_scan
from core.utils import parse_ports
from core.target_validation import validate_target
from core.timing import get_timing_profile
from core.proxy import proxy_manager
from core.cve_engine import cve_engine
from core.lua_scripts import script_library
from core.fingerprinting import AggressiveFingerprinting

console = Console()

def is_root():
    return getattr(os, "geteuid", lambda: 1)() == 0

class SpectreShell(cmd.Cmd):
    intro = ""
    prompt = "spectre ❯ "

    def __init__(self):
        super().__init__()
        # Scan configuration dictionary
        self.config = {
            "target": "",
            "ports": "22,80,443",
            "scan_type": "auto",
            "version_detect": True,
            "os_detect": False,
            "aggressive_fingerprinting": False,
            "scripts": False,
            "script_categories": "default",
            "plugins": False,
            "timeout": 1.0,
            "concurrency": 500,
            "no_discovery": False,
            "save": ""
        }
        self.last_results = []
        self.print_banner()

    def print_banner(self):
        banner_text = """
[bold red]
  _________                    __           _________                     
 /   _____/_____   ____  _____/  |_________/   _____/ ____ _____    ____  
 \\_____  \\\\____ \\_/ __ \\/ ___/\\   __\\_  __ \\_____  \\_/ ___\\\\__  \\  /    \\ 
 /        \\  |_> >  ___/\\  \\___|  |  |  | \\/        \\  \\___ / __ \\|   |  \\
/_______  /   __/ \\___  >\\___  >__|  |__| /_______  /\\___  >____  /___|  /
        \\/|__|        \\/     \\/                   \\/     \\/     \\/     \\/ 
[/bold red]
                     [bold cyan]SpectreScan Console v2.0[/bold cyan]
      Type [green]help[/green] to list commands or [green]scan[/green] to execute configured scan.
"""
        console.print(Panel.fit(banner_text, border_style="cyan"))

    def emptyline(self):
        # Do nothing on empty line entry
        pass

    def do_set(self, arg):
        """Set a configuration option. Usage: set <option> <value>"""
        parts = arg.split(None, 1)
        if len(parts) < 2:
            console.print("[red][-] Error: Usage: set <option> <value>[/red]")
            return
        
        option, value = parts[0].lower(), parts[1]
        
        if option not in self.config:
            console.print(f"[red][-] Error: Unknown option '{option}'.[/red]")
            return

        # Handle type conversion
        try:
            if option in ["version_detect", "os_detect", "aggressive_fingerprinting", "scripts", "plugins", "no_discovery"]:
                # Boolean options
                self.config[option] = value.lower() in ("true", "yes", "1", "on")
            elif option in ["timeout"]:
                self.config[option] = float(value)
            elif option in ["concurrency"]:
                self.config[option] = int(value)
            else:
                self.config[option] = value
                
            console.print(f"[green][+] Set {option} ❯ {self.config[option]}[/green]")
        except ValueError:
            console.print(f"[red][-] Error: Invalid value for option '{option}'.[/red]")

    def complete_set(self, text, line, begidx, endidx):
        options = list(self.config.keys())
        if not text:
            return options
        return [o for o in options if o.startswith(text.lower())]

    def do_show(self, arg):
        """Show configurations, results, scripts, or plugins. Usage: show <options|results|scripts|plugins>"""
        arg = arg.strip().lower()
        if not arg or arg == "options":
            self.show_options()
        elif arg == "results":
            self.show_results()
        elif arg == "scripts":
            self.show_scripts()
        elif arg == "plugins":
            self.show_plugins()
        else:
            console.print("[red][-] Error: Invalid argument. Use: show <options|results|scripts|plugins>[/red]")

    def complete_show(self, text, line, begidx, endidx):
        options = ["options", "results", "scripts", "plugins"]
        if not text:
            return options
        return [o for o in options if o.startswith(text.lower())]

    def show_options(self):
        table = Table(title="SpectreScan Current Configuration", show_header=True, header_style="bold cyan")
        table.add_column("Option", style="yellow")
        table.add_column("Value", style="white")
        table.add_column("Description", style="dim")

        descriptions = {
            "target": "Target IP address, hostname, or CIDR (e.g. 192.168.1.1/24)",
            "ports": "Port range or list, e.g. 22,80,443,1000-2000",
            "scan_type": "Scan type: auto, tcp, syn, udp, all",
            "version_detect": "Probe service versions (-sV)",
            "os_detect": "Enable OS detection via TTL (requires root)",
            "aggressive_fingerprinting": "Enable aggressive OS fingerprinting",
            "scripts": "Run built-in Nmap-style scripts (-sC)",
            "script_categories": "Comma-separated script categories to run",
            "plugins": "Run service plugins from the plugins folder",
            "timeout": "Connection timeout in seconds",
            "concurrency": "Maximum concurrent TCP probes",
            "no_discovery": "Skip host discovery and scan the target directly",
            "save": "File path to save JSON scan results (leave empty to skip)"
        }

        for key, val in self.config.items():
            table.add_row(key, str(val), descriptions.get(key, ""))
        
        console.print(table)

    def show_results(self):
        if not self.last_results:
            console.print("[yellow][*] No scan results available yet. Run 'scan' first.[/yellow]")
            return
        
        table = Table(title="Scan Results", show_header=True, header_style="bold cyan")
        table.add_column("HOST", style="green")
        table.add_column("PORT", style="cyan")
        table.add_column("STATE", style="white")
        table.add_column("SERVICE/VERSION", style="magenta")
        table.add_column("OS", style="blue")

        for row in sorted(self.last_results, key=lambda item: (item.get("host", ""), item.get("port", 0))):
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
        console.print(table)

    def show_scripts(self):
        scripts = script_library.list_scripts()
        table = Table(title="Nmap-Style Script Library", show_header=True, header_style="bold cyan")
        table.add_column("Name", style="yellow")
        table.add_column("Category", style="green")
        table.add_column("Description", style="white")

        for s in scripts:
            table.add_row(s["name"], s["categories"], s["description"])
        console.print(table)

    def show_plugins(self):
        plugins = load_plugins()
        table = Table(title="Service Plugins", show_header=True, header_style="bold cyan")
        table.add_column("Plugin Name", style="yellow")
        table.add_column("Target Ports", style="green")
        
        for p in plugins:
            ports_str = ", ".join(str(port) for port in getattr(p, "PORTS", []))
            table.add_row(getattr(p, "PLUGIN_NAME", "Unknown"), ports_str)
        console.print(table)

    def do_cvecheck(self, arg):
        """Manually query CVE details for a service. Usage: cvecheck <service> [version]"""
        parts = arg.split(None, 1)
        if not parts:
            console.print("[red][-] Error: Usage: cvecheck <service> [version][/red]")
            return
        
        service = parts[0]
        version = parts[1] if len(parts) > 1 else None
        
        console.print(f"[cyan][*] Fetching CVEs for service: {service} (Version: {version or 'Any'})...[/cyan]")
        cve_engine.display_cves(service, version)

    def do_scan(self, arg):
        """Execute network scan using current configurations."""
        if not self.config["target"]:
            console.print("[red][-] Error: Target is not set. Use 'set target <IP/CIDR>' first.[/red]")
            return

        # Perform target validation
        if not validate_target(self.config["target"]):
            console.print("[red][-] Error: Invalid target format.[/red]")
            return

        try:
            ports = parse_ports(self.config["ports"])
        except ValueError as exc:
            console.print(f"[red][-] Error: Invalid ports configuration: {exc}[/red]")
            return

        console.print(f"\n[bold green][*] Initiating SpectreScan...[/bold green]")
        console.print(f"[cyan]Target: {self.config['target']}[/cyan]")
        console.print(f"[cyan]Ports: {self.config['ports']}[/cyan]")

        # Determine scan type
        scan_type = self.config["scan_type"]
        if scan_type == "auto":
            scan_type = "syn" if is_root() else "tcp"
            console.print(f"[dim]Auto scan resolved to: {scan_type}[/dim]")

        # Verify root privileges for SYN/OS detection
        os_detect = self.config["os_detect"]
        if os_detect and not is_root():
            console.print("[yellow][!] Warning: OS detection requires root privileges. OS detection will be disabled.[/yellow]")
            os_detect = False

        if scan_type == "syn" and not is_root():
            console.print("[yellow][!] Warning: SYN scan requires root. Falling back to TCP connect scan.[/yellow]")
            scan_type = "tcp"

        # Host discovery
        if self.config["no_discovery"]:
            live_hosts = [self.config["target"]]
        elif "/" in self.config["target"]:
            live_hosts = discover_live_hosts(self.config["target"])
        else:
            live_hosts = [self.config["target"]]

        if not live_hosts:
            console.print("[red][-] No live hosts found. Scan aborted.[/red]")
            return

        results = []
        scan_start = time.time()

        # Execute scan phases
        if scan_type == "syn":
            console.print("\n[+] Running TCP SYN scan...")
            syn_results = syn_scan(live_hosts, ports, os_detect=os_detect)
            results.extend(syn_results)
        
        elif scan_type == "tcp":
            console.print(f"\n[+] Running TCP connect scan on {len(live_hosts)} host(s)...")
            results.extend(asyncio.run(
                run_scan(
                    live_hosts,
                    ports,
                    version_detect=self.config["version_detect"],
                    os_detect=os_detect,
                    concurrency=self.config["concurrency"],
                    timeout=self.config["timeout"]
                )
            ))
            
        elif scan_type == "all":
            # Run both
            if is_root():
                console.print("\n[+] Running TCP SYN scan...")
                results.extend(syn_scan(live_hosts, ports, os_detect=os_detect))
            console.print(f"\n[+] Running TCP connect scan on {len(live_hosts)} host(s)...")
            results.extend(asyncio.run(
                run_scan(
                    live_hosts,
                    ports,
                    version_detect=self.config["version_detect"],
                    os_detect=os_detect,
                    concurrency=self.config["concurrency"],
                    timeout=self.config["timeout"]
                )
            ))

        # Check UDP scan if scan_type is udp or all
        if scan_type in ("udp", "all"):
            from core.udp import udp_scan
            console.print(f"\n[+] Running UDP scan on {len(live_hosts)} host(s)...")
            results.extend(udp_scan(live_hosts, ports, timeout=self.config["timeout"]))

        # Aggressive fingerprinting
        if self.config["aggressive_fingerprinting"] and results:
            console.print("\n[+] Running aggressive OS fingerprinting...")
            for res in results:
                host = res.get("host")
                if host:
                    fp_results = AggressiveFingerprinting.run_aggressive_fingerprinting(host, ports[:3])
                    if fp_results["techniques"]:
                        res["aggressive_fingerprinting"] = fp_results
                        console.print(f"    [cyan]{host}: {fp_results['best_guess']} ({fp_results['confidence']}%)[/cyan]")

        # CVE checking
        if results:
            console.print("\n[+] Checking for service CVEs...")
            for res in results:
                service = res.get("banner", "").split("/")[0] if res.get("banner") else ""
                version = res.get("version", "")
                if service and service != "Unknown Service":
                    cve_engine.check_service_vulnerabilities(res.get("host"), res.get("port"), service, version)
                    cves = cve_engine.lookup_service_cves(service, version)
                    if cves:
                        res["cves"] = [cve.get("cve", {}).get("id") for cve in cves[:3]]

        self.last_results = results
        scan_duration = time.time() - scan_start

        # Display Summary Table
        self.show_results()
        console.print(f"\n[cyan][+] Scan completed in {scan_duration:.2f} seconds. Loaded results in memory.[/cyan]")

        # Run Scripts Engine
        if self.config["scripts"] and results:
            console.print("\n[*] Initiating Script Engine (-sC)...")
            for host_data in results:
                script_output = run_scripts(
                    host_data["host"],
                    host_data["port"],
                    host_data.get("banner", ""),
                    categories=self.config["script_categories"]
                )
                if script_output:
                    host_data["script_results"] = script_output
                    for name, data in script_output:
                        console.print(f"    [cyan]|_ {name}: {data}[/cyan]")

            # Advanced NSE scripts
            console.print("\n[*] Running advanced NSE-style scripts...")
            for host_data in results:
                port = host_data.get("port")
                scripts = script_library.get_scripts_by_port(port)
                for script in scripts:
                    res = script_library.execute_script(script.name, host_data["host"], port)
                    if res:
                        console.print(f"    [cyan]|_ {script.name}: {res.get('result')}[/cyan]")

        # Run Plugins
        if self.config["plugins"] and results:
            plugins = load_plugins()
            if plugins:
                console.print("\n[*] Running service plugins...")
                for host_data in results:
                    plugin_output = run_plugins(plugins, host_data["host"], host_data["port"], host_data.get("banner", ""))
                    if plugin_output:
                        host_data["plugins"] = plugin_output
                        for name, data in plugin_output.items():
                            console.print(f"    [magenta]{name} returned: {data}[/magenta]")

        # Save Report
        if self.config["save"] and results:
            save_report(self.config["target"], results, self.config["save"])

    def do_clear(self, arg):
        """Clear the console screen."""
        os.system('clear' if os.name == 'posix' else 'cls')

    def do_exit(self, arg):
        """Exit the SpectreScan console."""
        console.print("[bold yellow][*] Exiting SpectreScan console. Goodbye![/bold yellow]")
        return True

    def do_quit(self, arg):
        """Exit the SpectreScan console."""
        return self.do_exit(arg)

def interactive_menu():
    """Fallback function to match signature and launch console."""
    try:
        shell = SpectreShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] Interrupted. Exiting SpectreScan.[/bold yellow]")
    return None

