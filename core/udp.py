from scapy.all import IP, UDP, ICMP, sr1
from rich.console import Console

console = Console()

def udp_scan(live_hosts, ports, timeout=1.0):
    results = []
    print(f"[*] Starting UDP scan on {len(live_hosts)} host(s)...")
    
    for host in live_hosts:
        for port in ports:
            packet = IP(dst=str(host)) / UDP(dport=port)
            response = sr1(packet, timeout=timeout, verbose=0)

            if response is None:
                console.print(f"[yellow][?] {host}:{port}/udp OPEN|FILTERED[/yellow]")
                results.append({
                    "host": str(host),
                    "port": port,
                    "protocol": "udp",
                    "status": "open|filtered",
                })
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                    continue

    return results
