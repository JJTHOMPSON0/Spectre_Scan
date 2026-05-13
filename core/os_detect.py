from scapy.all import IP, TCP, sr1


def analyze_ttl(ip_header):
    """Analyze TTL and return OS guess with confidence percentage."""
    ttl = ip_header.ttl
    
    os_guesses = []
    
    if ttl <= 64:
        confidence = max(0, 100 - abs(ttl - 64) * 2)
        os_guesses.append(("Linux/Unix/macOS", confidence))
    if 60 <= ttl <= 68:
        confidence = max(0, 100 - abs(ttl - 64) * 2)
        os_guesses.append(("Linux/Unix/macOS", confidence))
    
    if ttl <= 128 and ttl > 64:
        confidence = max(0, 100 - abs(ttl - 128) * 2)
        os_guesses.append(("Windows", confidence))
    if 120 <= ttl <= 128:
        confidence = max(0, 100 - abs(ttl - 128) * 2)
        os_guesses.append(("Windows", confidence))
    
    if ttl > 128 and ttl <= 255:
        confidence = max(0, 100 - abs(ttl - 255) * 2)
        os_guesses.append(("Cisco/Network Device", confidence))
    
    if not os_guesses:
        return "Unknown OS"
    
    best_guess = max(os_guesses, key=lambda x: x[1])
    os_name, confidence = best_guess
    return f"{os_name} ({int(confidence)}%)"


def get_os_guess(host, port, timeout=0.5):
    response = sr1(IP(dst=host) / TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
    if response and response.haslayer(IP):
        return analyze_ttl(response[IP])
    return "Unknown"
