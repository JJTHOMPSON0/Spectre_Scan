from scapy.all import ARP, Ether, srp

def discover_live_hosts(target):
    # If it's a single IP, just return it. If it's a subnet, sweep it.
    if "/" in target:
        print(f"[*] Performing ARP sweep on {target} to find live hosts...")
        # Craft an ARP request packet broadcasted to the network
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        
        # Send packets and listen for replies (timeout of 2 seconds)
        answered, _ = srp(packet, timeout=2, verbose=0)
        
        live_hosts = [received.psrc for sent, received in answered]
        print(f"[+] Found {len(live_hosts)} live hosts.")
        return live_hosts
    else:
        return [target]
