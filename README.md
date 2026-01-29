# 🦅 VulnHawk

**Lightweight Network and Host Vulnerability Scanner**

VulnHawk is a comprehensive vulnerability scanning tool designed to identify common vulnerabilities in Linux systems and networks. It combines port scanning, service detection, CVE lookup, and misconfiguration detection into a single, easy-to-use package.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)

## ✨ Features

### Core Features
- **🔍 Port Scanning** - TCP/UDP port scanning with Nmap integration
- **📡 Service Detection** - Identify running services and their versions
- **🔓 CVE Lookup** - Query NVD database for known vulnerabilities
- **⚠️ Misconfiguration Detection** - Check for common security misconfigurations
- **📊 Report Generation** - Export results in JSON, HTML, and text formats

### Stretch Features
- **🌐 Web Dashboard** - Modern web interface for running scans
- **📈 CVSS Scoring** - Severity scoring using CVSS metrics
- **💡 Remediation Suggestions** - Actionable fixes for found issues

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Nmap (`sudo apt install nmap`)
- Root/sudo access (for full functionality)

### Setup

```bash
# Clone the repository
cd /path/to/VulnHawk

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make the main script executable
chmod +x vulnhawk.py
```

### Optional: NVD API Key
For faster CVE lookups, obtain a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) and set it:

```bash
export NVD_API_KEY="your-api-key-here"
# Or add to .env file:
echo "NVD_API_KEY=your-api-key-here" > .env
```

## 📖 Usage

### Command Line Interface

```bash
# Basic scan of a single host
sudo python vulnhawk.py 192.168.1.1

# Scan specific ports
sudo python vulnhawk.py 192.168.1.1 -p 22,80,443,8080

# Full port scan
sudo python vulnhawk.py 192.168.1.1 -p 1-65535

# Quick scan of common ports
sudo python vulnhawk.py 192.168.1.1 --quick

# Aggressive scan (OS detection, scripts)
sudo python vulnhawk.py 192.168.1.1 -A

# Include UDP scanning
sudo python vulnhawk.py 192.168.1.1 -U

# Scan a subnet
sudo python vulnhawk.py 192.168.1.0/24

# Local system checks
sudo python vulnhawk.py 127.0.0.1 --local-checks

# Generate only HTML report
sudo python vulnhawk.py 192.168.1.1 --format html

# Filter CVEs by severity
sudo python vulnhawk.py 192.168.1.1 --min-severity HIGH
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-p, --ports` | Port range to scan (default: 1-1024) |
| `-A, --aggressive` | Enable aggressive scan |
| `-U, --udp` | Include UDP port scan |
| `--local-checks` | Run local misconfiguration checks |
| `--skip-cve` | Skip CVE lookup phase |
| `--skip-misconfig` | Skip misconfiguration checks |
| `--skip-report` | Skip report generation |
| `--format` | Report format: json, html, txt, all |
| `--min-severity` | Minimum CVE severity: LOW, MEDIUM, HIGH, CRITICAL |
| `--quick` | Quick scan of common ports only |
| `-o, --output` | Output directory for reports |
| `-v, --verbose` | Enable verbose output |

### Web Dashboard

Start the web interface:

```bash
python dashboard.py
# Or with custom settings:
python dashboard.py --host 0.0.0.0 --port 8080
```

Access the dashboard at `http://127.0.0.1:5000`

## 📁 Project Structure

```
VulnHawk/
├── vulnhawk.py          # Main entry point
├── config.py            # Configuration settings
├── port_scanner.py      # Port scanning module
├── service_detector.py  # Service detection module
├── cve_lookup.py        # CVE/NVD API module
├── misconfig_detector.py# Misconfiguration checks
├── report_generator.py  # Report generation
├── dashboard.py         # Web dashboard
├── requirements.txt     # Python dependencies
├── README.md           # This file
└── reports/            # Generated reports
```

## 🔍 Scan Phases

1. **Port Scanning**
   - TCP SYN scan for open ports
   - Optional UDP scanning
   - Service version detection
   - Risky port identification

2. **Service Detection**
   - Banner grabbing
   - Service fingerprinting
   - Version extraction
   - CPE identification

3. **CVE Lookup**
   - Query NVD API for known CVEs
   - Match service versions to vulnerabilities
   - CVSS score retrieval
   - Severity classification

4. **Misconfiguration Detection**
   - SSH configuration audit
   - Firewall status check
   - File permission analysis
   - SUID/SGID file detection
   - Password policy review
   - Running services audit

5. **Report Generation**
   - JSON format (machine-readable)
   - HTML format (visual report)
   - Text format (plain text)

## 📊 Output Example

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝ 
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗ 
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝

Target: 192.168.1.1
Scan started at: 2025-01-29 10:30:00

┌──────────────────────────────────────────────────────────────────────┐
│ Phase 1: Port Scanning                                               │
└──────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────── Open Ports ───────────────────────────┐
│ Port   │ Protocol │ State │ Service │ Version           │ Risk      │
│ 22     │ tcp      │ open  │ ssh     │ OpenSSH 8.2       │ ⚠ HIGH    │
│ 80     │ tcp      │ open  │ http    │ Apache 2.4.41     │ OK        │
│ 443    │ tcp      │ open  │ https   │ Apache 2.4.41     │ OK        │
└─────────────────────────────────────────────────────────────────────┘

Scan Complete
─────────────
Target            192.168.1.1
Open Ports        3
Risky Ports       1
Services          3
CVEs Found        5
  Critical        1
  High            2
  Medium          2
Misconfigurations 2
Overall Risk      HIGH
```

## ⚙️ Configuration

Edit `config.py` to customize:

```python
# Scan settings
DEFAULT_PORTS = "1-1024"
SCAN_TIMEOUT = 300

# CVE severity thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0

# Report settings
REPORT_OUTPUT_DIR = "reports"

# Dashboard settings
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
```

## 🛡️ Misconfiguration Checks

| Check | Description |
|-------|-------------|
| SSH Root Login | Checks if root login is permitted |
| SSH Password Auth | Checks if password authentication is enabled |
| Empty Passwords | Checks if empty passwords are allowed |
| Firewall Status | Verifies firewall is active |
| World-Writable Files | Finds files writable by anyone |
| SUID Files | Detects unusual SUID binaries |
| File Permissions | Checks sensitive file permissions |
| Password Policy | Reviews password aging settings |
| UID Zero Users | Finds non-root users with UID 0 |

## 📝 License

MIT License - See LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any systems you do not own. Unauthorized scanning may violate laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 📚 References

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [CVSS Scoring System](https://www.first.org/cvss/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
