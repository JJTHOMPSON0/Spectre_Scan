def analyze_ttl(ip_header):
    ttl = ip_header.ttl
    
    # TTLs decrease as they hop through routers, so we check ranges.
    if ttl <= 64:
        return "Linux/Unix/macOS"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network Device"
    else:
        return "Unknown OS"

# You would integrate this into your existing core/syn.py like this:
# response = sr1(packet, timeout=0.5, verbose=0)
# if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
#     os_guess = analyze_ttl(response[IP])
#     print(f"[+] {host}:{port}/tcp OPEN (Guessed OS: {os_guess})")
