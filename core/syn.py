from scapy.all import IP, TCP, sr1
from core.os_detect import analyze_ttl  # <-- Import your OS detector

def syn_scan(live_hosts, start, end, os_detect=False):
    results = []
    
    print(f"[*] Starting TCP SYN scan on {len(live_hosts)} host(s)...")
    for host in live_hosts:
        for port in range(start, end + 1):
            
            packet = IP(dst=str(host)) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=0.5, verbose=0)

            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                
                os_info = ""
                # If -O was used, check the TTL of the returned IP packet
                if os_detect and response.haslayer(IP):
                    os_guess = analyze_ttl(response[IP])
                    os_info = f" [OS: {os_guess}]"

                print(f"[+] {host}:{port}/tcp OPEN{os_info}")

                results.append({
                    "host": str(host),
                    "port": port,
                    "status": "open"
                })

    return results
