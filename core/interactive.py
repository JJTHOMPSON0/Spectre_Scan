from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

console = Console()


def interactive_menu():
    """Interactive menu for SpectreScan configuration."""
    console.print("\n[bold cyan]SpectreScan - Interactive Mode[/bold cyan]\n")

    target = Prompt.ask("[yellow]Target IP or CIDR[/yellow]")

    ports = Prompt.ask("[yellow]Port range or list[/yellow]", default="1-65535")

    console.print("\n[cyan]Scan Types:[/cyan]")
    console.print("  1. auto     (SYN if root, else TCP)")
    console.print("  2. tcp      (TCP connect scan)")
    console.print("  3. syn      (TCP SYN scan - requires root)")
    console.print("  4. udp      (UDP scan)")
    console.print("  5. all      (TCP + SYN + UDP)")
    scan_type_choice = Prompt.ask("[yellow]Select scan type[/yellow]", default="1", choices=["1", "2", "3", "4", "5"])
    scan_type_map = {"1": "auto", "2": "tcp", "3": "syn", "4": "udp", "5": "all"}
    scan_type = scan_type_map[scan_type_choice]

    version_detect = Confirm.ask("[yellow]Probe service versions (-sV)?[/yellow]", default=False)
    os_detect = Confirm.ask("[yellow]Enable OS detection (-O)?[/yellow]", default=False)
    scripts = Confirm.ask("[yellow]Run Nmap-style scripts (-sC)?[/yellow]", default=False)
    plugins = Confirm.ask("[yellow]Run service plugins?[/yellow]", default=False)

    timeout = float(Prompt.ask("[yellow]Connection timeout (seconds)[/yellow]", default="1.0"))
    concurrency = int(Prompt.ask("[yellow]Concurrent probes[/yellow]", default="500"))
    no_discovery = Confirm.ask("[yellow]Skip host discovery (-n)?[/yellow]", default=False)

    save_report = Prompt.ask("[yellow]Save report to file? (leave empty to skip)[/yellow]", default="")

    config = {
        "target": target,
        "ports": ports,
        "scan_type": scan_type,
        "version_detect": version_detect,
        "os_detect": os_detect,
        "scripts": scripts,
        "plugins": plugins,
        "timeout": timeout,
        "concurrency": concurrency,
        "no_discovery": no_discovery,
        "save": save_report if save_report else None,
    }

    console.print("\n[bold cyan]Scan Configuration:[/bold cyan]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Option")
    table.add_column("Value")
    for key, value in config.items():
        table.add_row(key, str(value))
    console.print(table)

    if Confirm.ask("\n[yellow]Proceed with scan?[/yellow]", default=True):
        return config
    else:
        console.print("[red]Scan cancelled.[/red]")
        return None
