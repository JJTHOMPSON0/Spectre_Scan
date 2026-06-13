"""
CVE Integration Module
Looks up vulnerabilities for detected services
"""

import os
import json
import requests
from rich.console import Console
from rich.table import Table

console = Console()

class CVEEngine:
    """CVE lookup and vulnerability correlation"""
    
    def __init__(self):
        self.nvd_api_url = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.cve_api_key = os.getenv("CVE_API_KEY", "")
        self.cache = {}
    
    def lookup_service_cves(self, service_name, version=None):
        """
        Look up CVEs for a service. Queries NVD API first, and falls back to CIRCL CVE API.
        service_name: e.g., "Apache", "OpenSSH", "nginx"
        version: optional version string
        """
        try:
            cache_key = f"{service_name}:{version}" if version else service_name
            if cache_key in self.cache:
                return self.cache[cache_key]
            
            cves = []
            # 1. Query NVD API
            query = f"{service_name}"
            if version:
                query += f" {version}"
            
            params = {
                "keywordSearch": query,
                "resultsPerPage": 10,
            }
            
            if self.cve_api_key:
                params["apiKey"] = self.cve_api_key
            
            nvd_success = False
            try:
                response = requests.get(
                    self.nvd_api_url,
                    params=params,
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    cves = data.get("vulnerabilities", [])
                    nvd_success = True
            except Exception as e:
                console.print(f"[yellow]NVD lookup warning: {e}. Trying fallback API...[/yellow]")

            # 2. Fallback to CIRCL CVE API if NVD fails or returns no CVEs
            if not cves or not nvd_success:
                fallback_url = f"https://cve.circl.lu/api/search/{service_name.lower()}"
                try:
                    response = requests.get(fallback_url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        # If a list is returned, parse entries
                        results_list = data if isinstance(data, list) else data.get("results", [])
                        for entry in results_list[:15]:
                            summary = entry.get("summary", "")
                            # If version is specified, filter by version string to avoid mismatch
                            if version and version not in summary:
                                continue
                            
                            cvss_score = entry.get("cvss")
                            severity = "MEDIUM"
                            if cvss_score is not None:
                                try:
                                    score = float(cvss_score)
                                    if score >= 9.0:
                                        severity = "CRITICAL"
                                    elif score >= 7.0:
                                        severity = "HIGH"
                                    elif score >= 4.0:
                                        severity = "MEDIUM"
                                    else:
                                        severity = "LOW"
                                except (ValueError, TypeError):
                                    pass
                            
                            cves.append({
                                "cve": {
                                    "id": entry.get("id", "N/A"),
                                    "descriptions": [{"value": summary}]
                                },
                                "impact": {
                                    "baseMetricV3": {
                                        "cvssV3": {
                                            "baseSeverity": severity
                                        }
                                    }
                                }
                            })
                except Exception as e:
                    console.print(f"[yellow]Fallback CVE lookup error: {e}[/yellow]")
            
            self.cache[cache_key] = cves
            return cves
        except Exception as e:
            console.print(f"[yellow]General CVE engine error: {e}[/yellow]")
        
        return []
    
    def display_cves(self, service_name, version=None):
        """Display CVEs in a formatted table"""
        cves = self.lookup_service_cves(service_name, version)
        
        if not cves:
            console.print(f"[green]No CVEs found for {service_name}[/green]")
            return
        
        table = Table(title=f"CVEs for {service_name}")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Score", style="yellow")
        
        for cve in cves[:5]:  # Show top 5
            cve_id = cve.get("cve", {}).get("id", "N/A")
            description = cve.get("cve", {}).get("descriptions", [{}])[0].get("value", "N/A")[:50]
            severity = cve.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "N/A")
            
            table.add_row(cve_id, description, severity)
        
        console.print(table)
    
    def check_service_vulnerabilities(self, host, port, service, version):
        """Check if a detected service has known vulnerabilities"""
        cves = self.lookup_service_cves(service, version)
        
        if cves:
            console.print(f"[red]⚠ {service} {version} has {len(cves)} known CVEs[/red]")
            return True
        else:
            console.print(f"[green]✓ No known CVEs for {service} {version}[/green]")
            return False
    
    def export_cves(self, results_dict):
        """
        Enrich scan results with CVE data
        """
        enriched = results_dict.copy()
        
        for host_data in enriched.get("hosts", []):
            for port_data in host_data.get("ports", []):
                service = port_data.get("service", "")
                version = port_data.get("version", "")
                
                if service:
                    cves = self.lookup_service_cves(service, version)
                    if cves:
                        port_data["cves"] = [
                            {
                                "id": cve.get("cve", {}).get("id"),
                                "severity": cve.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity"),
                            }
                            for cve in cves[:3]
                        ]
        
        return enriched


# Global CVE engine instance
cve_engine = CVEEngine()
