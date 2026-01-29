"""
VulnHawk CVE Lookup Module
Queries NVD (National Vulnerability Database) API for known CVEs
"""

import re
import time
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from rich.console import Console
from rich.table import Table

import config

console = Console()


@dataclass
class CVEEntry:
    """Data class for CVE information"""
    cve_id: str
    description: str
    cvss_score: float
    cvss_version: str
    severity: str
    published_date: str
    last_modified: str
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    vector_string: str = ""
    exploit_available: bool = False


class CVELookup:
    """Query NVD API for CVE information"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or config.NVD_API_KEY
        self.base_url = config.NVD_API_URL
        self.session = requests.Session()
        self.cache: Dict[str, List[CVEEntry]] = {}
        
        # Set headers
        self.headers = {
            "User-Agent": "VulnHawk Vulnerability Scanner/1.0"
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key
    
    def search_by_keyword(self, keyword: str, max_results: int = 20) -> List[CVEEntry]:
        """
        Search for CVEs by keyword (product name, service, etc.)
        
        Args:
            keyword: Search term (e.g., "Apache 2.4.49")
            max_results: Maximum number of results to return
        
        Returns:
            List of CVEEntry objects
        """
        # Check cache first
        cache_key = f"keyword:{keyword}"
        if cache_key in self.cache:
            return self.cache[cache_key][:max_results]
        
        console.print(f"[cyan]Searching NVD for: {keyword}[/cyan]")
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results
        }
        
        try:
            response = self.session.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_nvd_response(data)
            
            # Cache results
            self.cache[cache_key] = cves
            
            # Rate limiting (without API key: 5 requests per 30 seconds)
            if not self.api_key:
                time.sleep(6)
            else:
                time.sleep(0.6)  # With API key: 50 requests per 30 seconds
            
            return cves
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]NVD API error: {e}[/red]")
            return []
    
    def search_by_cpe(self, cpe: str, max_results: int = 20) -> List[CVEEntry]:
        """
        Search for CVEs by CPE (Common Platform Enumeration)
        
        Args:
            cpe: CPE string (e.g., "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
            max_results: Maximum number of results
        
        Returns:
            List of CVEEntry objects
        """
        cache_key = f"cpe:{cpe}"
        if cache_key in self.cache:
            return self.cache[cache_key][:max_results]
        
        console.print(f"[cyan]Searching NVD by CPE: {cpe}[/cyan]")
        
        params = {
            "cpeName": cpe,
            "resultsPerPage": max_results
        }
        
        try:
            response = self.session.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_nvd_response(data)
            
            self.cache[cache_key] = cves
            
            if not self.api_key:
                time.sleep(6)
            else:
                time.sleep(0.6)
            
            return cves
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]NVD API error: {e}[/red]")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
        
        Returns:
            CVEEntry object or None
        """
        cache_key = f"id:{cve_id}"
        if cache_key in self.cache:
            return self.cache[cache_key][0] if self.cache[cache_key] else None
        
        params = {"cveId": cve_id}
        
        try:
            response = self.session.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            cves = self._parse_nvd_response(data)
            
            self.cache[cache_key] = cves
            
            return cves[0] if cves else None
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]NVD API error: {e}[/red]")
            return None
    
    def _parse_nvd_response(self, data: Dict) -> List[CVEEntry]:
        """
        Parse NVD API response into CVEEntry objects
        
        Args:
            data: JSON response from NVD API
        
        Returns:
            List of CVEEntry objects
        """
        cves = []
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            
            # Extract CVE ID
            cve_id = cve_data.get("id", "Unknown")
            
            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS metrics
            cvss_score, cvss_version, severity, vector_string = self._extract_cvss(cve_data)
            
            # Extract dates
            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")
            
            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                references.append(ref.get("url", ""))
            
            # Extract affected products
            affected_products = self._extract_affected_products(cve_data)
            
            cve_entry = CVEEntry(
                cve_id=cve_id,
                description=description[:500] + "..." if len(description) > 500 else description,
                cvss_score=cvss_score,
                cvss_version=cvss_version,
                severity=severity,
                published_date=published,
                last_modified=modified,
                references=references[:5],  # Limit references
                affected_products=affected_products,
                vector_string=vector_string
            )
            
            cves.append(cve_entry)
        
        return cves
    
    def _extract_cvss(self, cve_data: Dict) -> tuple:
        """Extract CVSS score and severity from CVE data"""
        metrics = cve_data.get("metrics", {})
        
        # Try CVSS 3.1 first, then 3.0, then 2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0]
                
                if version in ["cvssMetricV31", "cvssMetricV30"]:
                    cvss_info = cvss_data.get("cvssData", {})
                    return (
                        cvss_info.get("baseScore", 0.0),
                        cvss_info.get("version", "3.x"),
                        cvss_info.get("baseSeverity", "UNKNOWN"),
                        cvss_info.get("vectorString", "")
                    )
                else:  # CVSS 2.0
                    cvss_info = cvss_data.get("cvssData", {})
                    score = cvss_info.get("baseScore", 0.0)
                    severity = self._cvss2_severity(score)
                    return (
                        score,
                        "2.0",
                        severity,
                        cvss_info.get("vectorString", "")
                    )
        
        return (0.0, "N/A", "UNKNOWN", "")
    
    def _cvss2_severity(self, score: float) -> str:
        """Convert CVSS 2.0 score to severity string"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "NONE"
    
    def _extract_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected products/CPEs from CVE data"""
        products = []
        
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    if cpe.get("vulnerable", False):
                        criteria = cpe.get("criteria", "")
                        products.append(criteria)
        
        return products[:10]  # Limit to 10 products
    
    def get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "NONE": "white",
            "UNKNOWN": "grey50"
        }
        return colors.get(severity.upper(), "white")
    
    def display_cve_table(self, cves: List[CVEEntry]):
        """
        Display CVEs in a formatted table
        
        Args:
            cves: List of CVEEntry objects
        """
        if not cves:
            console.print("[yellow]No CVEs found[/yellow]")
            return
        
        table = Table(title="Found CVEs", show_header=True, header_style="bold magenta")
        table.add_column("CVE ID", style="cyan", width=16)
        table.add_column("Score", justify="center", width=6)
        table.add_column("Severity", width=10)
        table.add_column("Description", width=60)
        
        for cve in cves:
            severity_color = self.get_severity_color(cve.severity)
            table.add_row(
                cve.cve_id,
                f"{cve.cvss_score:.1f}",
                f"[{severity_color}]{cve.severity}[/{severity_color}]",
                cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
            )
        
        console.print(table)
    
    def lookup_service_cves(self, service_name: str, version: str = "") -> List[CVEEntry]:
        """
        Lookup CVEs for a specific service and version
        
        Args:
            service_name: Name of the service (e.g., "OpenSSH", "Apache")
            version: Service version (e.g., "8.2", "2.4.49")
        
        Returns:
            List of CVEEntry objects
        """
        # Build search query
        if version:
            query = f"{service_name} {version}"
        else:
            query = service_name
        
        return self.search_by_keyword(query)
    
    def filter_by_severity(self, cves: List[CVEEntry], min_severity: str = "MEDIUM") -> List[CVEEntry]:
        """
        Filter CVEs by minimum severity level
        
        Args:
            cves: List of CVEEntry objects
            min_severity: Minimum severity to include
        
        Returns:
            Filtered list of CVEEntry objects
        """
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_index = severity_order.index(min_severity.upper()) if min_severity.upper() in severity_order else 0
        
        return [
            cve for cve in cves
            if severity_order.index(cve.severity.upper()) >= min_index
            if cve.severity.upper() in severity_order
        ]
    
    def export_cves(self, cves: List[CVEEntry]) -> List[Dict]:
        """
        Export CVEs as list of dictionaries
        
        Args:
            cves: List of CVEEntry objects
        
        Returns:
            List of CVE dictionaries
        """
        return [
            {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "cvss_version": cve.cvss_version,
                "severity": cve.severity,
                "published_date": cve.published_date,
                "last_modified": cve.last_modified,
                "references": cve.references,
                "affected_products": cve.affected_products,
                "vector_string": cve.vector_string
            }
            for cve in cves
        ]


def main():
    """Test CVE lookup"""
    lookup = CVELookup()
    
    # Search for Apache vulnerabilities
    cves = lookup.search_by_keyword("Apache HTTP Server 2.4", max_results=5)
    lookup.display_cve_table(cves)


if __name__ == "__main__":
    main()
