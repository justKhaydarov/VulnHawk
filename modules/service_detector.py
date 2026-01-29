"""
VulnHawk Service Detector Module
Detects and fingerprints services running on open ports
"""

import re
import socket
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from rich.console import Console

console = Console()


@dataclass
class ServiceInfo:
    """Data class for service information"""
    port: int
    protocol: str
    service_name: str
    product: str
    version: str
    extra_info: str
    cpe: str  # Common Platform Enumeration
    banner: str


class ServiceDetector:
    """Detects and fingerprints network services"""
    
    # Common service banners and patterns
    SERVICE_PATTERNS = {
        "ssh": {
            "pattern": r"SSH-(\d+\.\d+)-([^\s]+)",
            "name": "SSH"
        },
        "ftp": {
            "pattern": r"(\d{3})[- ].*?([\w\s]+FTP|vsftpd|ProFTPD|FileZilla)",
            "name": "FTP"
        },
        "http": {
            "pattern": r"HTTP/(\d+\.\d+)",
            "name": "HTTP"
        },
        "smtp": {
            "pattern": r"(\d{3})[- ].*?(SMTP|Postfix|Sendmail|Exchange)",
            "name": "SMTP"
        },
        "mysql": {
            "pattern": r"(\d+\.\d+\.\d+).*?MySQL",
            "name": "MySQL"
        },
        "postgresql": {
            "pattern": r"PostgreSQL",
            "name": "PostgreSQL"
        },
        "redis": {
            "pattern": r"REDIS|redis_version:(\d+\.\d+\.\d+)",
            "name": "Redis"
        },
        "mongodb": {
            "pattern": r"MongoDB|mongod",
            "name": "MongoDB"
        },
        "apache": {
            "pattern": r"Apache[/ ](\d+\.\d+\.\d+)",
            "name": "Apache HTTP Server"
        },
        "nginx": {
            "pattern": r"nginx[/ ](\d+\.\d+\.\d+)",
            "name": "Nginx"
        },
        "openssh": {
            "pattern": r"OpenSSH[_ ](\d+\.\d+)",
            "name": "OpenSSH"
        }
    }
    
    # Default ports for services
    DEFAULT_SERVICE_PORTS = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        27017: "mongodb"
    }
    
    def __init__(self):
        self.detected_services: List[ServiceInfo] = []
    
    def grab_banner(self, host: str, port: int, timeout: float = 5.0) -> Optional[str]:
        """
        Attempt to grab the service banner from a port
        
        Args:
            host: Target IP address or hostname
            port: Port number to connect to
            timeout: Connection timeout in seconds
        
        Returns:
            Banner string if successful, None otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send probe for HTTP services
            if port in [80, 8080, 443, 8443]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            else:
                # For other services, try sending a newline to trigger banner
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            
            return banner.strip()
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            console.print(f"[yellow]Banner grab error on {host}:{port}: {e}[/yellow]")
            return None
    
    def identify_service(self, banner: str, port: int) -> Tuple[str, str, str]:
        """
        Identify service from banner using pattern matching
        
        Args:
            banner: Service banner string
            port: Port number (used for fallback identification)
        
        Returns:
            Tuple of (service_name, product, version)
        """
        if not banner:
            # Fallback to port-based identification
            service = self.DEFAULT_SERVICE_PORTS.get(port, "unknown")
            return service, "", ""
        
        for service_key, service_data in self.SERVICE_PATTERNS.items():
            match = re.search(service_data["pattern"], banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex >= 1 else ""
                product = match.group(2) if match.lastindex >= 2 else service_data["name"]
                return service_data["name"], product, version
        
        # Fallback to port-based identification
        service = self.DEFAULT_SERVICE_PORTS.get(port, "unknown")
        return service, "", ""
    
    def detect_service(self, host: str, port: int, nmap_data: Dict = None) -> ServiceInfo:
        """
        Detect service running on a specific port
        
        Args:
            host: Target IP address or hostname
            port: Port number
            nmap_data: Optional Nmap scan data for this port
        
        Returns:
            ServiceInfo object with detected service details
        """
        # Start with Nmap data if available
        if nmap_data:
            service_info = ServiceInfo(
                port=port,
                protocol=nmap_data.get("protocol", "tcp"),
                service_name=nmap_data.get("service", "unknown"),
                product=nmap_data.get("product", ""),
                version=nmap_data.get("version", ""),
                extra_info=nmap_data.get("extrainfo", ""),
                cpe=self._extract_cpe(nmap_data),
                banner=""
            )
        else:
            service_info = ServiceInfo(
                port=port,
                protocol="tcp",
                service_name="unknown",
                product="",
                version="",
                extra_info="",
                cpe="",
                banner=""
            )
        
        # Try to grab banner for additional info
        banner = self.grab_banner(host, port)
        if banner:
            service_info.banner = banner
            
            # If Nmap didn't identify the service, use banner
            if service_info.service_name == "unknown" or not service_info.version:
                name, product, version = self.identify_service(banner, port)
                if name != "unknown":
                    service_info.service_name = name
                if product:
                    service_info.product = product
                if version:
                    service_info.version = version
        
        self.detected_services.append(service_info)
        return service_info
    
    def _extract_cpe(self, nmap_data: Dict) -> str:
        """Extract CPE string from Nmap data"""
        cpe_list = nmap_data.get("cpe", [])
        if isinstance(cpe_list, list) and cpe_list:
            return cpe_list[0]
        elif isinstance(cpe_list, str):
            return cpe_list
        return ""
    
    def detect_all_services(self, host: str, scan_results: Dict) -> List[ServiceInfo]:
        """
        Detect services on all open ports from scan results
        
        Args:
            host: Target IP address or hostname
            scan_results: Port scan results from PortScanner
        
        Returns:
            List of ServiceInfo objects
        """
        services = []
        
        console.print(f"\n[cyan]Detecting services on {host}...[/cyan]")
        
        for host_data in scan_results.get("hosts", []):
            for port_data in host_data.get("ports", []):
                service = self.detect_service(
                    host=host,
                    port=port_data["port"],
                    nmap_data=port_data
                )
                services.append(service)
                
                # Display detected service
                version_str = f"{service.product} {service.version}".strip()
                console.print(
                    f"  [green]Port {service.port}[/green]: "
                    f"{service.service_name} "
                    f"{'(' + version_str + ')' if version_str else ''}"
                )
        
        return services
    
    def get_version_string(self, service: ServiceInfo) -> str:
        """
        Get a normalized version string for CVE lookup
        
        Args:
            service: ServiceInfo object
        
        Returns:
            Normalized version string
        """
        if service.product and service.version:
            return f"{service.product} {service.version}"
        elif service.version:
            return f"{service.service_name} {service.version}"
        elif service.product:
            return service.product
        return service.service_name
    
    def export_services(self) -> List[Dict]:
        """
        Export detected services as list of dictionaries
        
        Returns:
            List of service dictionaries
        """
        return [
            {
                "port": s.port,
                "protocol": s.protocol,
                "service_name": s.service_name,
                "product": s.product,
                "version": s.version,
                "extra_info": s.extra_info,
                "cpe": s.cpe,
                "banner": s.banner
            }
            for s in self.detected_services
        ]


def main():
    """Test service detection"""
    detector = ServiceDetector()
    
    # Test banner grab on localhost
    banner = detector.grab_banner("127.0.0.1", 22)
    if banner:
        console.print(f"[green]SSH Banner:[/green] {banner}")
        name, product, version = detector.identify_service(banner, 22)
        console.print(f"Identified: {name} - {product} {version}")


if __name__ == "__main__":
    main()
