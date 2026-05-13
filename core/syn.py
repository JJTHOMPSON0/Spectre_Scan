from scapy.all import IP, TCP, sr1
from core.os_detect import analyze_ttl
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn, TimeRemainingColumn


def syn_scan(live_hosts, ports, os_detect=False):
    results = []
    total = len(live_hosts) * len(ports)

    print(f"[*] Starting TCP SYN scan on {len(live_hosts)} host(s)...")
    with Progress(
        TextColumn("{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task_id = progress.add_task("SYN scanning", total=total)

        for host in live_hosts:
            for port in ports:
                packet = IP(dst=str(host)) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=0.5, verbose=0)

                if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                    host_result = {
                        "host": str(host),
                        "port": port,
                        "protocol": "tcp",
                        "status": "open",
                    }

                    if os_detect and response.haslayer(IP):
                        os_guess = analyze_ttl(response[IP])
                        host_result["os"] = os_guess
                        print(f"[+] {host}:{port}/tcp OPEN [OS: {os_guess}]")
                    else:
                        print(f"[+] {host}:{port}/tcp OPEN")

                    results.append(host_result)

                progress.advance(task_id)

    return results
