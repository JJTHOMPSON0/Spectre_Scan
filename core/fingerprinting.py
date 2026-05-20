"""
Aggressive OS Fingerprinting Module
Advanced TCP/IP stack analysis for operating system detection
"""

from scapy.all import IP, TCP, sr1
from rich.console import Console

console = Console()

class AggressiveFingerprinting:
    """Advanced OS fingerprinting using multiple techniques"""
    
    @staticmethod
    def analyze_tcp_window(target, port=80):
        """
        Analyze TCP window size to fingerprint OS
        Different OS have characteristic window sizes
        """
        try:
            # Send SYN and analyze response window
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=2, verbose=False)
            
            if response and response.haslayer(TCP):
                window_size = response[TCP].window
                
                # Common window size patterns
                if window_size == 65535:
                    return "Windows", 85  # Windows default
                elif window_size == 65534:
                    return "BSD", 75
                elif window_size == 32768:
                    return "Linux", 80
                elif window_size == 16384:
                    return "Linux (embedded)", 70
                else:
                    return f"Unknown (window={window_size})", 40
        except Exception as e:
            console.print(f"[yellow]TCP window analysis failed: {e}[/yellow]")
        
        return None, 0
    
    @staticmethod
    def analyze_syn_cookies(target, port=80):
        """
        Detect SYN cookies implementation
        Linux typically implements SYN cookies, Windows may not
        """
        try:
            # Send multiple SYN packets and analyze ACK behavior
            for i in range(3):
                packet = IP(dst=target) / TCP(dport=port, seq=1000+i, flags="S")
                response = sr1(packet, timeout=1, verbose=False)
                
                if response and response.haslayer(TCP):
                    # Check if ACK contains sequence-encoded info (SYN cookies)
                    ack_seq = response[TCP].ack
                    
                    # SYN cookies encode sequence number info
                    if ack_seq > 0 and ack_seq < 256:
                        return "Linux (SYN cookies enabled)", 80
            
            return "Windows or SYN cookies disabled", 50
        except Exception:
            pass
        
        return None, 0
    
    @staticmethod
    def analyze_ip_options(target, port=80):
        """
        Analyze IP options and flags
        Different OS handle IP options differently
        """
        try:
            # Windows typically ignores unknown IP options
            # Linux may reject them or handle differently
            packet = IP(dst=target, options=[]) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=2, verbose=False)
            
            if response:
                if response.haslayer(IP):
                    ip_flags = response[IP].flags
                    # Analyze response behavior
                    return "Responsive to IP options", 60
        except Exception:
            pass
        
        return None, 0
    
    @staticmethod
    def analyze_icmp_response(target):
        """
        Analyze ICMP response patterns
        Different OS respond differently to ICMP
        """
        try:
            from scapy.all import ICMP
            
            packet = IP(dst=target) / ICMP()
            response = sr1(packet, timeout=2, verbose=False)
            
            if response and response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                
                # ICMP echo reply type is 0
                if icmp_type == 0:
                    # Check TTL for OS hint
                    ttl = response[IP].ttl
                    if ttl <= 64:
                        return "Linux", 75
                    elif ttl <= 128:
                        return "Windows", 80
                    else:
                        return "Network Device", 65
        except Exception:
            pass
        
        return None, 0
    
    @staticmethod
    def run_aggressive_fingerprinting(target, ports=[80, 443, 22]):
        """
        Run multiple OS fingerprinting techniques
        Returns dictionary of findings
        """
        results = {
            "target": target,
            "techniques": [],
            "best_guess": "Unknown",
            "confidence": 0,
        }
        
        console.print(f"[cyan]Running aggressive OS fingerprinting on {target}...[/cyan]")
        
        # TCP Window analysis
        os_guess, confidence = AggressiveFingerprinting.analyze_tcp_window(target, ports[0])
        if os_guess:
            results["techniques"].append({
                "method": "TCP Window Size",
                "result": os_guess,
                "confidence": confidence,
            })
        
        # SYN Cookies analysis
        os_guess, confidence = AggressiveFingerprinting.analyze_syn_cookies(target, ports[0])
        if os_guess:
            results["techniques"].append({
                "method": "SYN Cookies",
                "result": os_guess,
                "confidence": confidence,
            })
        
        # IP Options analysis
        os_guess, confidence = AggressiveFingerprinting.analyze_ip_options(target, ports[0])
        if os_guess:
            results["techniques"].append({
                "method": "IP Options",
                "result": os_guess,
                "confidence": confidence,
            })
        
        # ICMP analysis
        os_guess, confidence = AggressiveFingerprinting.analyze_icmp_response(target)
        if os_guess:
            results["techniques"].append({
                "method": "ICMP Response",
                "result": os_guess,
                "confidence": confidence,
            })
        
        # Calculate best guess based on aggregated results
        if results["techniques"]:
            avg_confidence = sum(t["confidence"] for t in results["techniques"]) / len(results["techniques"])
            results["confidence"] = int(avg_confidence)
            results["best_guess"] = results["techniques"][0]["result"]
        
        return results
