"""
VulnHawk Port Scanner Module
Handles TCP/UDP port scanning using Nmap
"""

import nmap
from typing import Dict, List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

import config

console = Console()


class PortScanner:
    """Network port scanner using python-nmap"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
    
    def scan_tcp(self, target: str, ports: str = None, aggressive: bool = False) -> Dict:
        """
        Perform TCP SYN scan on target
        
        Args:
            target: IP address or hostname to scan
            ports: Port range (e.g., "1-1024" or "22,80,443")
            aggressive: Enable aggressive scan (-A flag)
        
        Returns:
            Dictionary containing scan results
        """
        ports = ports or config.DEFAULT_PORTS
        
        # Build scan arguments
        arguments = "-sS -sV"  # SYN scan with version detection
        if aggressive:
            arguments = "-A"  # Aggressive scan (OS detection, version, scripts, traceroute)
        
        console.print(f"[cyan]Starting TCP scan on {target}...[/cyan]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Scanning {target}", total=None)
                
                self.nm.scan(
                    hosts=target,
                    ports=ports,
                    arguments=arguments,
                    timeout=config.SCAN_TIMEOUT
                )
                
                progress.update(task, completed=True)
            
            return self._parse_results(target)
            
        except nmap.PortScannerError as e:
            console.print(f"[red]Nmap error: {e}[/red]")
            return {}
        except Exception as e:
            console.print(f"[red]Scan error: {e}[/red]")
            return {}
    
    def scan_udp(self, target: str, ports: str = None) -> Dict:
        """
        Perform UDP scan on target
        
        Args:
            target: IP address or hostname to scan
            ports: Port range for UDP scan
        
        Returns:
            Dictionary containing scan results
        """
        # Use common UDP ports if not specified
        if ports is None:
            ports = ",".join(map(str, config.UDP_PORTS))
        
        console.print(f"[cyan]Starting UDP scan on {target}...[/cyan]")
        console.print("[yellow]Note: UDP scans are slower than TCP scans[/yellow]")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"UDP Scanning {target}", total=None)
                
                self.nm.scan(
                    hosts=target,
                    ports=ports,
                    arguments="-sU -sV",
                    timeout=config.SCAN_TIMEOUT
                )
                
                progress.update(task, completed=True)
            
            return self._parse_results(target, protocol="udp")
            
        except Exception as e:
            console.print(f"[red]UDP scan error: {e}[/red]")
            return {}
    
    def scan_common_ports(self, target: str) -> Dict:
        """
        Quick scan of commonly used ports
        
        Args:
            target: IP address or hostname to scan
        
        Returns:
            Dictionary containing scan results
        """
        ports = ",".join(map(str, config.COMMON_PORTS))
        return self.scan_tcp(target, ports=ports)
    
    def _parse_results(self, target: str, protocol: str = "tcp") -> Dict:
        """
        Parse Nmap scan results into structured format
        
        Args:
            target: The scanned target
            protocol: tcp or udp
        
        Returns:
            Parsed results dictionary
        """
        results = {
            "target": target,
            "hosts": [],
            "open_ports": [],
            "risky_ports": [],
            "services": []
        }
        
        for host in self.nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": self.nm[host].hostname(),
                "state": self.nm[host].state(),
                "ports": []
            }
            
            if protocol in self.nm[host].all_protocols():
                ports = self.nm[host][protocol].keys()
                
                for port in sorted(ports):
                    port_data = self.nm[host][protocol][port]
                    
                    port_info = {
                        "port": port,
                        "protocol": protocol,
                        "state": port_data["state"],
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                        "product": port_data.get("product", ""),
                        "extrainfo": port_data.get("extrainfo", "")
                    }
                    
                    if port_data["state"] == "open":
                        host_info["ports"].append(port_info)
                        results["open_ports"].append(port)
                        
                        # Check if it's a risky port
                        if port in config.RISKY_PORTS:
                            port_info["risk_reason"] = config.RISKY_PORTS[port]
                            results["risky_ports"].append(port_info)
                        
                        # Add service info
                        service_str = f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()
                        if service_str:
                            results["services"].append({
                                "port": port,
                                "service": port_data.get("name", "unknown"),
                                "version_string": service_str
                            })
            
            results["hosts"].append(host_info)
        
        self.results = results
        return results
    
    def get_os_detection(self, target: str) -> Optional[Dict]:
        """
        Attempt to detect the operating system of the target
        
        Args:
            target: IP address or hostname
        
        Returns:
            OS detection results or None
        """
        console.print(f"[cyan]Attempting OS detection on {target}...[/cyan]")
        
        try:
            self.nm.scan(hosts=target, arguments="-O")
            
            if target in self.nm.all_hosts():
                if "osmatch" in self.nm[target]:
                    os_matches = self.nm[target]["osmatch"]
                    if os_matches:
                        return {
                            "os_matches": os_matches[:3],  # Top 3 matches
                            "accuracy": os_matches[0].get("accuracy", "N/A") if os_matches else "N/A"
                        }
            
            return None
            
        except Exception as e:
            console.print(f"[red]OS detection error: {e}[/red]")
            return None
    
    def scan_subnet(self, subnet: str) -> List[Dict]:
        """
        Discover and scan all hosts in a subnet
        
        Args:
            subnet: CIDR notation (e.g., "192.168.1.0/24")
        
        Returns:
            List of scan results for each discovered host
        """
        console.print(f"[cyan]Discovering hosts in {subnet}...[/cyan]")
        
        all_results = []
        
        try:
            # Host discovery
            self.nm.scan(hosts=subnet, arguments="-sn")
            
            hosts_up = [host for host in self.nm.all_hosts() if self.nm[host].state() == "up"]
            
            console.print(f"[green]Found {len(hosts_up)} hosts up[/green]")
            
            for host in hosts_up:
                console.print(f"\n[cyan]Scanning {host}...[/cyan]")
                result = self.scan_tcp(host)
                all_results.append(result)
            
            return all_results
            
        except Exception as e:
            console.print(f"[red]Subnet scan error: {e}[/red]")
            return []


def main():
    """Test the port scanner"""
    scanner = PortScanner()
    
    # Example: scan localhost
    results = scanner.scan_common_ports("127.0.0.1")
    
    console.print("\n[bold green]Scan Results:[/bold green]")
    console.print(results)


if __name__ == "__main__":
    main()
