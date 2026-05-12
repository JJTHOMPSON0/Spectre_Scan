import asyncio
from rich.console import Console
from core.banner import grab_banner
from core.version import active_probe  # <-- Import your new version detector

console = Console()

async def scan_port(ip, port, results, sem, version_detect=False):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port),
                timeout=1
            )

            # Check if the user passed the -sV flag
            if version_detect:
                banner = await active_probe(reader, writer, port)
            else:
                banner = await grab_banner(reader, writer)

            result = {
                "host": str(ip),
                "port": port,
                "status": "open",
                "banner": banner
            }
            results.append(result)

            console.print(f"[green][+] {ip}:{port}/tcp OPEN[/green] {banner}")

            writer.close()
            await writer.wait_closed()
        except:
            pass

# Add target_ports=None to the arguments
async def run_scan(live_hosts, start, end, version_detect=False, target_ports=None):
    results = []
    tasks = []
    sem = asyncio.Semaphore(500)

    print(f"[*] Starting async TCP connect scan on {len(live_hosts)} host(s)...")
    for host in live_hosts:
        # If we already know the open ports from a SYN scan, only scan those!
        ports_to_scan = target_ports if target_ports else range(start, end + 1)
        
        for port in ports_to_scan:
            tasks.append(scan_port(host, port, results, sem, version_detect))

    await asyncio.gather(*tasks)
    return results
