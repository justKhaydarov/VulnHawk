"""
VulnHawk Report Generator Module
Generates structured vulnerability reports in multiple formats
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
from dataclasses import dataclass
from rich.console import Console

try:
    from jinja2 import Template
except ImportError:
    Template = None

import config

console = Console()


@dataclass
class ScanSummary:
    """Summary statistics for a scan"""
    target: str
    scan_time: str
    total_ports_scanned: int
    open_ports: int
    risky_ports: int
    services_detected: int
    cves_found: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    misconfigs_found: int
    critical_misconfigs: int
    overall_risk_score: str


class ReportGenerator:
    """Generates vulnerability scan reports in various formats"""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHawk Scan Report - {{ target }}</title>
    <style>
        :root {
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --accent: #0f3460;
            --highlight: #e94560;
            --text: #eaeaea;
            --success: #4ade80;
            --warning: #fbbf24;
            --danger: #ef4444;
            --info: #3b82f6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, var(--accent), var(--highlight));
            border-radius: 15px;
            margin-bottom: 30px;
        }
        header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        header .subtitle { opacity: 0.9; font-size: 1.1rem; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid var(--accent);
        }
        .summary-card.critical { border-left-color: var(--danger); }
        .summary-card.warning { border-left-color: var(--warning); }
        .summary-card.success { border-left-color: var(--success); }
        .summary-card h3 { font-size: 2rem; margin-bottom: 5px; }
        .summary-card p { opacity: 0.8; font-size: 0.9rem; }
        .section {
            background: var(--bg-card);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .section h2 {
            color: var(--highlight);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--accent);
        }
        th { background: var(--accent); font-weight: 600; }
        tr:hover { background: rgba(15, 52, 96, 0.5); }
        .severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity.critical { background: var(--danger); }
        .severity.high { background: #f97316; }
        .severity.medium { background: var(--warning); color: #000; }
        .severity.low { background: var(--success); color: #000; }
        .severity.info { background: var(--info); }
        .port-list { display: flex; flex-wrap: wrap; gap: 10px; }
        .port-badge {
            background: var(--accent);
            padding: 8px 15px;
            border-radius: 8px;
            font-family: monospace;
        }
        .port-badge.risky {
            background: var(--danger);
        }
        .remediation {
            background: rgba(74, 222, 128, 0.1);
            border-left: 4px solid var(--success);
            padding: 15px;
            margin-top: 10px;
            border-radius: 0 8px 8px 0;
        }
        .cve-card {
            background: var(--accent);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .cve-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .cve-id { font-weight: bold; font-size: 1.1rem; }
        .cve-score {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
        }
        .score-critical { background: var(--danger); }
        .score-high { background: #f97316; }
        .score-medium { background: var(--warning); color: #000; }
        .score-low { background: var(--success); color: #000; }
        footer {
            text-align: center;
            padding: 20px;
            opacity: 0.7;
            font-size: 0.9rem;
        }
        @media (max-width: 768px) {
            header h1 { font-size: 1.8rem; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🦅 VulnHawk Scan Report</h1>
            <p class="subtitle">Target: {{ target }} | Scan Date: {{ scan_time }}</p>
        </header>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>{{ summary.open_ports }}</h3>
                <p>Open Ports</p>
            </div>
            <div class="summary-card warning">
                <h3>{{ summary.risky_ports }}</h3>
                <p>Risky Ports</p>
            </div>
            <div class="summary-card">
                <h3>{{ summary.services_detected }}</h3>
                <p>Services Detected</p>
            </div>
            <div class="summary-card critical">
                <h3>{{ summary.cves_found }}</h3>
                <p>CVEs Found</p>
            </div>
            <div class="summary-card critical">
                <h3>{{ summary.critical_cves }}</h3>
                <p>Critical CVEs</p>
            </div>
            <div class="summary-card warning">
                <h3>{{ summary.misconfigs_found }}</h3>
                <p>Misconfigurations</p>
            </div>
        </div>

        <div class="section">
            <h2>📡 Open Ports</h2>
            <div class="port-list">
                {% for port in open_ports %}
                <span class="port-badge {% if port.risky %}risky{% endif %}">
                    {{ port.port }}/{{ port.protocol }} - {{ port.service }}
                </span>
                {% endfor %}
            </div>
        </div>

        {% if services %}
        <div class="section">
            <h2>🔍 Detected Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {% for service in services %}
                    <tr>
                        <td>{{ service.port }}</td>
                        <td>{{ service.service_name }}</td>
                        <td>{{ service.product }}</td>
                        <td>{{ service.version }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if cves %}
        <div class="section">
            <h2>🔓 Vulnerabilities (CVEs)</h2>
            {% for cve in cves %}
            <div class="cve-card">
                <div class="cve-header">
                    <span class="cve-id">{{ cve.cve_id }}</span>
                    <span class="cve-score score-{{ cve.severity|lower }}">
                        {{ cve.cvss_score }} ({{ cve.severity }})
                    </span>
                </div>
                <p>{{ cve.description }}</p>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if misconfigs %}
        <div class="section">
            <h2>⚠️ Misconfigurations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Issue</th>
                        <th>Description</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {% for misconfig in misconfigs %}
                    <tr>
                        <td><span class="severity {{ misconfig.severity|lower }}">{{ misconfig.severity }}</span></td>
                        <td>{{ misconfig.check_name }}</td>
                        <td>{{ misconfig.description }}</td>
                        <td>{{ misconfig.remediation }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <footer>
            <p>Generated by VulnHawk - Lightweight Network and Host Vulnerability Scanner</p>
            <p>Report generated on {{ scan_time }}</p>
        </footer>
    </div>
</body>
</html>
"""

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or config.REPORT_OUTPUT_DIR
        self.ensure_output_dir()
    
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_summary(self, scan_data: Dict) -> ScanSummary:
        """
        Generate scan summary statistics
        
        Args:
            scan_data: Complete scan data dictionary
        
        Returns:
            ScanSummary object
        """
        # Count CVE severities
        cves = scan_data.get("cves", [])
        critical_cves = len([c for c in cves if c.get("severity", "").upper() == "CRITICAL"])
        high_cves = len([c for c in cves if c.get("severity", "").upper() == "HIGH"])
        medium_cves = len([c for c in cves if c.get("severity", "").upper() == "MEDIUM"])
        low_cves = len([c for c in cves if c.get("severity", "").upper() == "LOW"])
        
        # Count misconfiguration severities
        misconfigs = scan_data.get("misconfigurations", [])
        critical_misconfigs = len([m for m in misconfigs if m.get("severity", "").upper() == "CRITICAL"])
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(scan_data)
        
        return ScanSummary(
            target=scan_data.get("target", "Unknown"),
            scan_time=scan_data.get("scan_time", datetime.now().isoformat()),
            total_ports_scanned=scan_data.get("total_ports_scanned", 0),
            open_ports=len(scan_data.get("open_ports", [])),
            risky_ports=len(scan_data.get("risky_ports", [])),
            services_detected=len(scan_data.get("services", [])),
            cves_found=len(cves),
            critical_cves=critical_cves,
            high_cves=high_cves,
            medium_cves=medium_cves,
            low_cves=low_cves,
            misconfigs_found=len(misconfigs),
            critical_misconfigs=critical_misconfigs,
            overall_risk_score=risk_score
        )
    
    def calculate_risk_score(self, scan_data: Dict) -> str:
        """
        Calculate overall risk score
        
        Args:
            scan_data: Complete scan data
        
        Returns:
            Risk level string (CRITICAL, HIGH, MEDIUM, LOW)
        """
        score = 0
        
        # Score based on CVEs
        for cve in scan_data.get("cves", []):
            cvss = cve.get("cvss_score", 0)
            if cvss >= 9.0:
                score += 10
            elif cvss >= 7.0:
                score += 7
            elif cvss >= 4.0:
                score += 4
            else:
                score += 1
        
        # Score based on misconfigurations
        severity_scores = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}
        for misconfig in scan_data.get("misconfigurations", []):
            score += severity_scores.get(misconfig.get("severity", "LOW"), 1)
        
        # Score based on risky ports
        score += len(scan_data.get("risky_ports", [])) * 3
        
        # Determine risk level
        if score >= 50:
            return "CRITICAL"
        elif score >= 30:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_json_report(self, scan_data: Dict, filename: str = None) -> str:
        """
        Generate JSON format report
        
        Args:
            scan_data: Complete scan data
            filename: Output filename (optional)
        
        Returns:
            Path to generated report
        """
        summary = self.generate_summary(scan_data)
        
        report = {
            "report_info": {
                "tool": "VulnHawk",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "target": scan_data.get("target", "Unknown")
            },
            "summary": {
                "open_ports": summary.open_ports,
                "risky_ports": summary.risky_ports,
                "services_detected": summary.services_detected,
                "cves_found": summary.cves_found,
                "critical_cves": summary.critical_cves,
                "high_cves": summary.high_cves,
                "medium_cves": summary.medium_cves,
                "low_cves": summary.low_cves,
                "misconfigs_found": summary.misconfigs_found,
                "risk_score": summary.overall_risk_score
            },
            "scan_results": scan_data
        }
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = scan_data.get("target", "unknown").replace(".", "_").replace("/", "_")
            filename = f"vulnhawk_{target_safe}_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        console.print(f"[green]JSON report saved to: {filepath}[/green]")
        return filepath
    
    def generate_html_report(self, scan_data: Dict, filename: str = None) -> str:
        """
        Generate HTML format report
        
        Args:
            scan_data: Complete scan data
            filename: Output filename (optional)
        
        Returns:
            Path to generated report
        """
        if Template is None:
            console.print("[yellow]Jinja2 not available, falling back to basic HTML[/yellow]")
            return self._generate_basic_html(scan_data, filename)
        
        summary = self.generate_summary(scan_data)
        
        # Prepare port data
        open_ports = []
        risky_port_numbers = [p.get("port") for p in scan_data.get("risky_ports", [])]
        
        for host in scan_data.get("hosts", []):
            for port in host.get("ports", []):
                open_ports.append({
                    "port": port.get("port"),
                    "protocol": port.get("protocol", "tcp"),
                    "service": port.get("service", "unknown"),
                    "risky": port.get("port") in risky_port_numbers
                })
        
        template = Template(self.HTML_TEMPLATE)
        html_content = template.render(
            target=scan_data.get("target", "Unknown"),
            scan_time=scan_data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            summary=summary,
            open_ports=open_ports,
            services=scan_data.get("services", []),
            cves=scan_data.get("cves", []),
            misconfigs=scan_data.get("misconfigurations", [])
        )
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = scan_data.get("target", "unknown").replace(".", "_").replace("/", "_")
            filename = f"vulnhawk_{target_safe}_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w") as f:
            f.write(html_content)
        
        console.print(f"[green]HTML report saved to: {filepath}[/green]")
        return filepath
    
    def _generate_basic_html(self, scan_data: Dict, filename: str = None) -> str:
        """Generate basic HTML without Jinja2"""
        summary = self.generate_summary(scan_data)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>VulnHawk Report - {scan_data.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #e94560; }}
        h2 {{ color: #0f3460; border-bottom: 2px solid #0f3460; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border: 1px solid #0f3460; }}
        th {{ background: #0f3460; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #fbbf24; }}
        .low {{ color: #4ade80; }}
    </style>
</head>
<body>
    <h1>VulnHawk Scan Report</h1>
    <p><strong>Target:</strong> {scan_data.get('target', 'Unknown')}</p>
    <p><strong>Scan Time:</strong> {scan_data.get('scan_time', 'N/A')}</p>
    
    <h2>Summary</h2>
    <ul>
        <li>Open Ports: {summary.open_ports}</li>
        <li>Risky Ports: {summary.risky_ports}</li>
        <li>Services Detected: {summary.services_detected}</li>
        <li>CVEs Found: {summary.cves_found} (Critical: {summary.critical_cves})</li>
        <li>Misconfigurations: {summary.misconfigs_found}</li>
        <li>Risk Score: {summary.overall_risk_score}</li>
    </ul>
</body>
</html>"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnhawk_report_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            f.write(html)
        
        return filepath
    
    def generate_text_report(self, scan_data: Dict, filename: str = None) -> str:
        """
        Generate plain text report
        
        Args:
            scan_data: Complete scan data
            filename: Output filename (optional)
        
        Returns:
            Path to generated report
        """
        summary = self.generate_summary(scan_data)
        
        lines = [
            "=" * 70,
            "VulnHawk Vulnerability Scan Report".center(70),
            "=" * 70,
            "",
            f"Target: {scan_data.get('target', 'Unknown')}",
            f"Scan Time: {scan_data.get('scan_time', 'N/A')}",
            f"Risk Level: {summary.overall_risk_score}",
            "",
            "-" * 70,
            "SUMMARY",
            "-" * 70,
            f"  Open Ports:        {summary.open_ports}",
            f"  Risky Ports:       {summary.risky_ports}",
            f"  Services Detected: {summary.services_detected}",
            f"  CVEs Found:        {summary.cves_found}",
            f"    - Critical:      {summary.critical_cves}",
            f"    - High:          {summary.high_cves}",
            f"    - Medium:        {summary.medium_cves}",
            f"    - Low:           {summary.low_cves}",
            f"  Misconfigurations: {summary.misconfigs_found}",
            "",
        ]
        
        # Open Ports Section
        lines.extend(["-" * 70, "OPEN PORTS", "-" * 70])
        for host in scan_data.get("hosts", []):
            for port in host.get("ports", []):
                lines.append(f"  {port.get('port')}/{port.get('protocol', 'tcp')} - {port.get('service', 'unknown')}")
        lines.append("")
        
        # CVEs Section
        if scan_data.get("cves"):
            lines.extend(["-" * 70, "VULNERABILITIES (CVEs)", "-" * 70])
            for cve in scan_data.get("cves", []):
                lines.append(f"  [{cve.get('severity', 'N/A')}] {cve.get('cve_id')} (CVSS: {cve.get('cvss_score', 'N/A')})")
                desc = cve.get('description', '')[:100]
                lines.append(f"    {desc}...")
                lines.append("")
        
        # Misconfigurations Section
        if scan_data.get("misconfigurations"):
            lines.extend(["-" * 70, "MISCONFIGURATIONS", "-" * 70])
            for misconfig in scan_data.get("misconfigurations", []):
                lines.append(f"  [{misconfig.get('severity')}] {misconfig.get('check_name')}")
                lines.append(f"    Description: {misconfig.get('description')}")
                lines.append(f"    Remediation: {misconfig.get('remediation')}")
                lines.append("")
        
        lines.extend(["=" * 70, "End of Report".center(70), "=" * 70])
        
        report_text = "\n".join(lines)
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = scan_data.get("target", "unknown").replace(".", "_").replace("/", "_")
            filename = f"vulnhawk_{target_safe}_{timestamp}.txt"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w") as f:
            f.write(report_text)
        
        console.print(f"[green]Text report saved to: {filepath}[/green]")
        return filepath
    
    def generate_all_reports(self, scan_data: Dict) -> Dict[str, str]:
        """
        Generate reports in all formats
        
        Args:
            scan_data: Complete scan data
        
        Returns:
            Dictionary mapping format to file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = scan_data.get("target", "unknown").replace(".", "_").replace("/", "_")
        base_name = f"vulnhawk_{target_safe}_{timestamp}"
        
        reports = {}
        
        reports["json"] = self.generate_json_report(scan_data, f"{base_name}.json")
        reports["html"] = self.generate_html_report(scan_data, f"{base_name}.html")
        reports["txt"] = self.generate_text_report(scan_data, f"{base_name}.txt")
        
        return reports


def main():
    """Test report generation"""
    # Sample scan data
    sample_data = {
        "target": "192.168.1.1",
        "scan_time": datetime.now().isoformat(),
        "total_ports_scanned": 1024,
        "open_ports": [22, 80, 443],
        "risky_ports": [{"port": 22, "reason": "SSH"}],
        "hosts": [
            {
                "ip": "192.168.1.1",
                "ports": [
                    {"port": 22, "protocol": "tcp", "service": "ssh"},
                    {"port": 80, "protocol": "tcp", "service": "http"},
                    {"port": 443, "protocol": "tcp", "service": "https"}
                ]
            }
        ],
        "services": [
            {"port": 22, "service_name": "ssh", "product": "OpenSSH", "version": "8.2"}
        ],
        "cves": [
            {
                "cve_id": "CVE-2021-28041",
                "cvss_score": 7.1,
                "severity": "HIGH",
                "description": "OpenSSH before 8.5 has a double free vulnerability"
            }
        ],
        "misconfigurations": [
            {
                "check_name": "SSH Root Login",
                "severity": "HIGH",
                "description": "Root login is enabled",
                "remediation": "Set PermitRootLogin no"
            }
        ]
    }
    
    generator = ReportGenerator()
    reports = generator.generate_all_reports(sample_data)
    
    console.print("\n[bold green]Reports generated:[/bold green]")
    for fmt, path in reports.items():
        console.print(f"  {fmt.upper()}: {path}")


if __name__ == "__main__":
    main()
