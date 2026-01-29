"""
VulnHawk - Lightweight Network and Host Vulnerability Scanner
"""

__version__ = "1.0.0"
__author__ = "VulnHawk Team"

from .vulnhawk import VulnHawk
from .modules.port_scanner import PortScanner
from .modules.service_detector import ServiceDetector
from .modules.cve_lookup import CVELookup
from .modules.misconfig_detector import MisconfigDetector
from .modules.report_generator import ReportGenerator

__all__ = [
    "VulnHawk",
    "PortScanner",
    "ServiceDetector",
    "CVELookup",
    "MisconfigDetector",
    "ReportGenerator"
]
