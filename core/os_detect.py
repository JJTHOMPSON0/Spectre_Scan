from scapy.all import IP, TCP, sr1


def analyze_ttl(ip_header):
    """Analyze TTL and return most likely OS with confidence percentage."""
    ttl = ip_header.ttl
    
    if ttl <= 64:
        confidence = max(0, 100 - abs(ttl - 64) * 3)
        if ttl <= 32:
            return f"Linux (Router/NAT adjusted) ({int(confidence)}%)"
        else:
            return f"Linux ({int(confidence)}%)"
    
    elif ttl <= 128:
        confidence = max(0, 100 - abs(ttl - 128) * 3)
        return f"Windows ({int(confidence)}%)"
    
    elif ttl > 128 and ttl <= 255:
        confidence = max(0, 100 - abs(ttl - 255) * 3)
        return f"Cisco/Network Device ({int(confidence)}%)"
    
    else:
        return "Unknown OS"


def get_os_guess(host, port, timeout=0.5):
    response = sr1(IP(dst=host) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
    if response and response.haslayer(IP):
        return analyze_ttl(response[IP])
    return "Unknown"
