"""
VulnHawk Configuration
Central configuration for the vulnerability scanner
"""

import os
from dotenv import load_dotenv

load_dotenv()

# API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # Optional: speeds up API requests

# Scan Configuration
DEFAULT_PORTS = "1-1024"
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900]

# Risky Ports (commonly exploited)
RISKY_PORTS = {
    21: "FTP - Often allows anonymous access or weak credentials",
    22: "SSH - Brute force target, check for weak passwords",
    23: "Telnet - Unencrypted, credentials sent in plaintext",
    25: "SMTP - Can be used for email relay attacks",
    53: "DNS - Zone transfer vulnerabilities possible",
    110: "POP3 - Unencrypted mail protocol",
    135: "MSRPC - Windows RPC, often exploited",
    139: "NetBIOS - SMB vulnerabilities",
    143: "IMAP - Unencrypted mail protocol",
    445: "SMB - EternalBlue and other exploits",
    1433: "MSSQL - Database attacks",
    3306: "MySQL - Database attacks",
    3389: "RDP - Brute force and BlueKeep vulnerabilities",
    5432: "PostgreSQL - Database attacks",
    5900: "VNC - Remote desktop, often weak auth",
    6379: "Redis - Often no authentication",
    27017: "MongoDB - Often no authentication"
}

# CVSS Severity Thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1

# Report Configuration
REPORT_OUTPUT_DIR = "reports"
REPORT_FORMATS = ["json", "html", "txt"]

# Scan Timeouts (seconds)
SCAN_TIMEOUT = 300
HOST_TIMEOUT = 60

# Misconfiguration Checks
MISCONFIG_CHECKS = [
    "ssh_config",
    "firewall_status",
    "running_services",
    "world_writable_files",
    "suid_files",
    "weak_permissions",
    "outdated_packages"
]

# Flask Dashboard Configuration
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = False
