import asyncio
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from core.banner import grab_banner
from core.version import active_probe

console = Console()

from core.os_detect import get_os_guess

async def scan_port(ip, port, results, sem, progress, task_id, version_detect=False, os_detect=False, timeout=1.0):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port),
                timeout=timeout
            )

            if version_detect:
                banner = await active_probe(reader, writer, port)
            else:
                banner = await grab_banner(reader, writer)

            result = {
                "host": str(ip),
                "port": port,
                "protocol": "tcp",
                "status": "open",
                "banner": banner,
            }

            if os_detect:
                try:
                    result["os"] = get_os_guess(str(ip), port)
                except PermissionError:
                    result["os"] = "Permission denied"

            results.append(result)
            console.print(f"[green][+] {ip}:{port}/tcp OPEN[/green] {banner}")

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return
        except Exception:
            return
        finally:
            if progress is not None and task_id is not None:
                progress.advance(task_id)

async def run_scan(live_hosts, ports, version_detect=False, os_detect=False, concurrency=500, timeout=1.0):
    results = []
    tasks = []
    sem = asyncio.Semaphore(concurrency)
    total = len(live_hosts) * len(ports)

    print(f"[*] Starting async TCP connect scan on {len(live_hosts)} host(s)...")
    with Progress(
        TextColumn("{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Scanning", total=total)

        for host in live_hosts:
            for port in ports:
                tasks.append(scan_port(host, port, results, sem, progress, task_id, version_detect, os_detect, timeout))

        await asyncio.gather(*tasks)

    return results
