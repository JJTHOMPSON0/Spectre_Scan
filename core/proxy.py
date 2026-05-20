"""
Proxy Routing Module
Supports HTTP, HTTPS, and SOCKS5 proxies for network requests
"""

import os
from urllib.parse import urlparse
from rich.console import Console

console = Console()

class ProxyManager:
    """Manages proxy configuration and routing"""
    
    def __init__(self):
        self.http_proxy = os.getenv("PROXY_HTTP", "")
        self.https_proxy = os.getenv("PROXY_HTTPS", "")
        self.socks5_proxy = os.getenv("PROXY_SOCKS5", "")
        self.use_proxy = False
    
    def get_proxies(self):
        """Return requests-compatible proxy dict"""
        proxies = {}
        if self.http_proxy:
            proxies["http"] = self.http_proxy
        if self.https_proxy:
            proxies["https"] = self.https_proxy
        if self.socks5_proxy:
            # SOCKS5 requires 'requests[socks]' package
            proxies["socks5"] = self.socks5_proxy
        return proxies if proxies else None
    
    def validate_proxy(self, proxy_url):
        """Validate proxy URL format"""
        try:
            result = urlparse(proxy_url)
            if result.scheme not in ["http", "https", "socks5"]:
                console.print(f"[red]Invalid proxy scheme: {result.scheme}[/red]")
                return False
            if not result.netloc:
                console.print("[red]Invalid proxy URL: missing host[/red]")
                return False
            return True
        except Exception as e:
            console.print(f"[red]Proxy validation error: {e}[/red]")
            return False
    
    def enable_proxy(self, proxy_url):
        """Enable a specific proxy"""
        if not self.validate_proxy(proxy_url):
            return False
        
        parsed = urlparse(proxy_url)
        if parsed.scheme == "socks5":
            self.socks5_proxy = proxy_url
        elif parsed.scheme == "https":
            self.https_proxy = proxy_url
        else:
            self.http_proxy = proxy_url
        
        self.use_proxy = True
        console.print(f"[green]✓ Proxy enabled: {proxy_url}[/green]")
        return True
    
    def disable_proxy(self):
        """Disable all proxies"""
        self.use_proxy = False
        console.print("[yellow]Proxies disabled[/yellow]")
    
    def get_socket_proxy(self):
        """Return socket-compatible proxy tuple for raw socket ops"""
        if self.socks5_proxy:
            parsed = urlparse(self.socks5_proxy)
            port = parsed.port or 1080
            return (parsed.hostname, port)
        return None


# Global proxy manager instance
proxy_manager = ProxyManager()
