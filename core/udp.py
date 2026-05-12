from scapy.all import IP, UDP, ICMP, sr1
from rich.console import Console

console = Console()

def udp_scan(live_hosts, start, end):
    results = []
    print(f"[*] Starting UDP scan on {len(live_hosts)} host(s)...")
    
    for host in live_hosts:
        for port in range(start, end + 1):
            packet = IP(dst=str(host)) / UDP(dport=port)
            # We wait for an ICMP response. No response *might* mean open/filtered.
            response = sr1(packet, timeout=1, verbose=0)

            if response is None:
                # No response could mean the UDP packet was dropped (filtered) 
                # or it was accepted by an open port that just doesn't reply.
                console.print(f"[yellow][?] {host}:{port}/udp OPEN|FILTERED[/yellow]")
                results.append({"host": str(host), "port": port, "status": "open|filtered", "protocol": "udp"})
            
            elif response.haslayer(ICMP):
                # ICMP Type 3, Code 3 is "Destination Port Unreachable"
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                    pass # Port is definitely closed
