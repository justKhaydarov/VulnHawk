#!/usr/bin/env python3
"""
VulnHawk - Lightweight Network and Host Vulnerability Scanner
Main entry point for the vulnerability scanning tool
"""

import argparse
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

import config
from modules.port_scanner import PortScanner
from modules.service_detector import ServiceDetector
from modules.cve_lookup import CVELookup
from modules.misconfig_detector import MisconfigDetector
from modules.report_generator import ReportGenerator

console = Console()

BANNER = """
[red]
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝ 
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗ 
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
[/red]
[cyan]     Lightweight Network and Host Vulnerability Scanner v1.0[/cyan]
[dim]              Identify vulnerabilities before attackers do[/dim]
"""


class VulnHawk:
    """Main vulnerability scanner class"""
    
    def __init__(self, target: str, options: Dict = None):
        self.target = target
        self.options = options or {}
        self.scan_data = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "hosts": [],
            "open_ports": [],
            "risky_ports": [],
            "services": [],
            "cves": [],
            "misconfigurations": []
        }
        
        # Initialize modules
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.cve_lookup = CVELookup()
        self.misconfig_detector = MisconfigDetector()
        self.report_generator = ReportGenerator()
    
    def run_port_scan(self) -> Dict:
        """Execute port scanning phase"""
        console.print(Panel("[bold cyan]Phase 1: Port Scanning[/bold cyan]"))
        
        ports = self.options.get("ports", config.DEFAULT_PORTS)
        aggressive = self.options.get("aggressive", False)
        
        # TCP Scan
        results = self.port_scanner.scan_tcp(
            self.target,
            ports=ports,
            aggressive=aggressive
        )
        
        # UDP Scan if requested
        if self.options.get("udp", False):
            udp_results = self.port_scanner.scan_udp(self.target)
            # Merge UDP results
            if udp_results.get("hosts"):
                for host in udp_results["hosts"]:
                    for existing_host in results.get("hosts", []):
                        if existing_host["ip"] == host["ip"]:
                            existing_host["ports"].extend(host["ports"])
        
        # Update scan data
        self.scan_data["hosts"] = results.get("hosts", [])
        self.scan_data["open_ports"] = results.get("open_ports", [])
        self.scan_data["risky_ports"] = results.get("risky_ports", [])
        
        # Display results
        self._display_port_results(results)
        
        return results
    
    def run_service_detection(self) -> List:
        """Execute service detection phase"""
        console.print(Panel("[bold cyan]Phase 2: Service Detection[/bold cyan]"))
        
        services = self.service_detector.detect_all_services(
            self.target,
            {"hosts": self.scan_data["hosts"]}
        )
        
        self.scan_data["services"] = self.service_detector.export_services()
        
        return services
    
    def run_cve_lookup(self) -> List:
        """Execute CVE lookup phase"""
        console.print(Panel("[bold cyan]Phase 3: CVE Lookup[/bold cyan]"))
        
        all_cves = []
        
        # Skip if no services detected
        if not self.scan_data["services"]:
            console.print("[yellow]No services detected, skipping CVE lookup[/yellow]")
            return all_cves
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Looking up CVEs...", total=len(self.scan_data["services"]))
            
            for service in self.scan_data["services"]:
                version_string = self.service_detector.get_version_string(
                    type('obj', (object,), service)()
                )
                
                if version_string and version_string != "unknown":
                    # Search by CPE if available
                    if service.get("cpe"):
                        cves = self.cve_lookup.search_by_cpe(service["cpe"], max_results=5)
                    else:
                        # Fall back to keyword search
                        cves = self.cve_lookup.search_by_keyword(version_string, max_results=5)
                    
                    # Filter by severity if specified
                    min_severity = self.options.get("min_severity", "LOW")
                    cves = self.cve_lookup.filter_by_severity(cves, min_severity)
                    
                    all_cves.extend(cves)
                
                progress.advance(task)
        
        # Remove duplicates
        seen_cves = set()
        unique_cves = []
        for cve in all_cves:
            if cve.cve_id not in seen_cves:
                seen_cves.add(cve.cve_id)
                unique_cves.append(cve)
        
        self.scan_data["cves"] = self.cve_lookup.export_cves(unique_cves)
        
        # Display results
        if unique_cves:
            self.cve_lookup.display_cve_table(unique_cves)
        else:
            console.print("[green]No known CVEs found for detected services[/green]")
        
        return unique_cves
    
    def run_misconfig_checks(self) -> List:
        """Execute misconfiguration detection phase"""
        console.print(Panel("[bold cyan]Phase 4: Misconfiguration Detection[/bold cyan]"))
        
        # Only run on localhost or if explicitly requested
        if self.target in ["127.0.0.1", "localhost"] or self.options.get("local_checks", False):
            findings = self.misconfig_detector.run_all_checks()
            self.scan_data["misconfigurations"] = self.misconfig_detector.export_findings()
            
            self.misconfig_detector.display_findings()
            
            return findings
        else:
            console.print("[yellow]Misconfiguration checks are only available for localhost[/yellow]")
            console.print("[yellow]Use --local-checks to run on the local system[/yellow]")
            return []
    
    def generate_reports(self) -> Dict:
        """Generate scan reports"""
        console.print(Panel("[bold cyan]Phase 5: Report Generation[/bold cyan]"))
        
        report_format = self.options.get("report_format", "all")
        
        if report_format == "all":
            reports = self.report_generator.generate_all_reports(self.scan_data)
        elif report_format == "json":
            reports = {"json": self.report_generator.generate_json_report(self.scan_data)}
        elif report_format == "html":
            reports = {"html": self.report_generator.generate_html_report(self.scan_data)}
        elif report_format == "txt":
            reports = {"txt": self.report_generator.generate_text_report(self.scan_data)}
        else:
            reports = self.report_generator.generate_all_reports(self.scan_data)
        
        return reports
    
    def run_full_scan(self) -> Dict:
        """Execute complete vulnerability scan"""
        console.print(BANNER)
        console.print(f"\n[bold]Target:[/bold] {self.target}")
        console.print(f"[bold]Scan started at:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        try:
            # Phase 1: Port Scanning
            self.run_port_scan()
            
            # Phase 2: Service Detection
            if self.scan_data["open_ports"]:
                self.run_service_detection()
            
            # Phase 3: CVE Lookup
            if not self.options.get("skip_cve", False):
                self.run_cve_lookup()
            
            # Phase 4: Misconfiguration Checks
            if not self.options.get("skip_misconfig", False):
                self.run_misconfig_checks()
            
            # Phase 5: Generate Reports
            if not self.options.get("skip_report", False):
                reports = self.generate_reports()
            else:
                reports = {}
            
            # Display final summary
            self._display_summary()
            
            return {
                "scan_data": self.scan_data,
                "reports": reports
            }
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            return {"scan_data": self.scan_data, "reports": {}}
        except Exception as e:
            console.print(f"\n[red]Scan error: {e}[/red]")
            raise
    
    def _display_port_results(self, results: Dict):
        """Display port scan results"""
        if not results.get("hosts"):
            console.print("[yellow]No hosts found[/yellow]")
            return
        
        table = Table(title="Open Ports", show_header=True, header_style="bold magenta")
        table.add_column("Port", style="cyan", width=10)
        table.add_column("Protocol", width=10)
        table.add_column("State", width=10)
        table.add_column("Service", width=15)
        table.add_column("Version", width=30)
        table.add_column("Risk", width=10)
        
        risky_ports = [p["port"] for p in results.get("risky_ports", [])]
        
        for host in results.get("hosts", []):
            for port in host.get("ports", []):
                risk = "[red]⚠ HIGH[/red]" if port["port"] in risky_ports else "[green]OK[/green]"
                version = f"{port.get('product', '')} {port.get('version', '')}".strip()
                
                table.add_row(
                    str(port["port"]),
                    port.get("protocol", "tcp"),
                    port["state"],
                    port.get("service", "unknown"),
                    version or "-",
                    risk
                )
        
        console.print(table)
    
    def _display_summary(self):
        """Display final scan summary"""
        summary = self.report_generator.generate_summary(self.scan_data)
        
        console.print("\n")
        console.print(Panel("[bold green]Scan Complete[/bold green]", expand=False))
        
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Target", self.target)
        summary_table.add_row("Open Ports", str(summary.open_ports))
        summary_table.add_row("Risky Ports", str(summary.risky_ports))
        summary_table.add_row("Services Detected", str(summary.services_detected))
        summary_table.add_row("CVEs Found", str(summary.cves_found))
        summary_table.add_row("  Critical", str(summary.critical_cves))
        summary_table.add_row("  High", str(summary.high_cves))
        summary_table.add_row("  Medium", str(summary.medium_cves))
        summary_table.add_row("Misconfigurations", str(summary.misconfigs_found))
        
        # Color code risk level
        risk_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(summary.overall_risk_score, "white")
        summary_table.add_row("Overall Risk", f"[{risk_color}]{summary.overall_risk_score}[/{risk_color}]")
        
        console.print(summary_table)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="VulnHawk - Lightweight Network and Host Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnhawk 192.168.1.1                  # Basic scan of a single host
  vulnhawk 192.168.1.0/24               # Scan entire subnet
  vulnhawk 192.168.1.1 -p 1-65535       # Full port scan
  vulnhawk 192.168.1.1 -A               # Aggressive scan
  vulnhawk 127.0.0.1 --local-checks     # Include local misconfiguration checks
  vulnhawk 192.168.1.1 --format html    # Generate HTML report only
        """
    )
    
    parser.add_argument(
        "target",
        help="Target IP address, hostname, or CIDR subnet"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default=config.DEFAULT_PORTS,
        help=f"Port range to scan (default: {config.DEFAULT_PORTS})"
    )
    
    parser.add_argument(
        "-A", "--aggressive",
        action="store_true",
        help="Enable aggressive scan (OS detection, scripts, traceroute)"
    )
    
    parser.add_argument(
        "-U", "--udp",
        action="store_true",
        help="Include UDP port scan"
    )
    
    parser.add_argument(
        "--local-checks",
        action="store_true",
        help="Run local misconfiguration checks"
    )
    
    parser.add_argument(
        "--skip-cve",
        action="store_true",
        help="Skip CVE lookup phase"
    )
    
    parser.add_argument(
        "--skip-misconfig",
        action="store_true",
        help="Skip misconfiguration checks"
    )
    
    parser.add_argument(
        "--skip-report",
        action="store_true",
        help="Skip report generation"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "html", "txt", "all"],
        default="all",
        dest="report_format",
        help="Report format (default: all)"
    )
    
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum CVE severity to report (default: LOW)"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan of common ports only"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output directory for reports"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()


def check_requirements():
    """Check if required tools are available"""
    import shutil
    
    if not shutil.which("nmap"):
        console.print("[red]Error: Nmap is not installed[/red]")
        console.print("Install with: sudo apt install nmap")
        sys.exit(1)


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Check requirements
    check_requirements()
    
    # Build options dictionary
    options = {
        "ports": ",".join(map(str, config.COMMON_PORTS)) if args.quick else args.ports,
        "aggressive": args.aggressive,
        "udp": args.udp,
        "local_checks": args.local_checks,
        "skip_cve": args.skip_cve,
        "skip_misconfig": args.skip_misconfig,
        "skip_report": args.skip_report,
        "report_format": args.report_format,
        "min_severity": args.min_severity,
        "verbose": args.verbose
    }
    
    # Set output directory if specified
    if args.output:
        config.REPORT_OUTPUT_DIR = args.output
    
    # Check if running as root for full functionality
    if os.geteuid() != 0:
        console.print("[yellow]Warning: Running without root privileges. Some features may be limited.[/yellow]")
        console.print("[yellow]Run with sudo for full functionality.[/yellow]\n")
    
    # Create and run scanner
    scanner = VulnHawk(args.target, options)
    results = scanner.run_full_scan()
    
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
