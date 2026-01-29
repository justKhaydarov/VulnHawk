"""
VulnHawk Misconfiguration Detector Module
Detects common security misconfigurations on Linux systems
"""

import os
import subprocess
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class MisconfigFinding:
    """Data class for misconfiguration findings"""
    check_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    details: str
    remediation: str
    affected_items: List[str] = field(default_factory=list)


class MisconfigDetector:
    """Detects security misconfigurations on Linux systems"""
    
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2,
        "INFO": 1
    }
    
    def __init__(self):
        self.findings: List[MisconfigFinding] = []
        self.is_root = os.geteuid() == 0
    
    def run_command(self, command: List[str], timeout: int = 30) -> Optional[str]:
        """
        Run a shell command and return output
        
        Args:
            command: Command as list of strings
            timeout: Timeout in seconds
        
        Returns:
            Command output or None if failed
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Command timed out: {' '.join(command)}[/yellow]")
            return None
        except Exception as e:
            console.print(f"[yellow]Command failed: {e}[/yellow]")
            return None
    
    def check_ssh_config(self) -> List[MisconfigFinding]:
        """Check SSH server configuration for security issues"""
        findings = []
        ssh_config_path = "/etc/ssh/sshd_config"
        
        if not os.path.exists(ssh_config_path):
            return findings
        
        try:
            with open(ssh_config_path, "r") as f:
                config = f.read()
            
            # Check for root login
            if re.search(r"^\s*PermitRootLogin\s+(yes|without-password)", config, re.MULTILINE | re.IGNORECASE):
                findings.append(MisconfigFinding(
                    check_name="SSH Root Login Enabled",
                    severity="HIGH",
                    description="SSH allows root login, which is a security risk",
                    details="PermitRootLogin is set to yes or without-password",
                    remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                    affected_items=[ssh_config_path]
                ))
            
            # Check for password authentication
            if re.search(r"^\s*PasswordAuthentication\s+yes", config, re.MULTILINE | re.IGNORECASE):
                findings.append(MisconfigFinding(
                    check_name="SSH Password Authentication Enabled",
                    severity="MEDIUM",
                    description="SSH allows password authentication instead of key-based",
                    details="PasswordAuthentication is set to yes",
                    remediation="Set 'PasswordAuthentication no' and use SSH keys instead",
                    affected_items=[ssh_config_path]
                ))
            
            # Check for X11 forwarding
            if re.search(r"^\s*X11Forwarding\s+yes", config, re.MULTILINE | re.IGNORECASE):
                findings.append(MisconfigFinding(
                    check_name="SSH X11 Forwarding Enabled",
                    severity="LOW",
                    description="X11 forwarding is enabled which can be a security risk",
                    details="X11Forwarding is set to yes",
                    remediation="Set 'X11Forwarding no' unless required",
                    affected_items=[ssh_config_path]
                ))
            
            # Check for empty passwords
            if re.search(r"^\s*PermitEmptyPasswords\s+yes", config, re.MULTILINE | re.IGNORECASE):
                findings.append(MisconfigFinding(
                    check_name="SSH Empty Passwords Permitted",
                    severity="CRITICAL",
                    description="SSH allows empty passwords",
                    details="PermitEmptyPasswords is set to yes",
                    remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config",
                    affected_items=[ssh_config_path]
                ))
            
            # Check protocol version (if explicitly set to 1)
            if re.search(r"^\s*Protocol\s+1", config, re.MULTILINE):
                findings.append(MisconfigFinding(
                    check_name="SSH Protocol Version 1",
                    severity="CRITICAL",
                    description="SSH is using deprecated Protocol version 1",
                    details="Protocol is set to 1 (insecure)",
                    remediation="Remove Protocol line or set 'Protocol 2'",
                    affected_items=[ssh_config_path]
                ))
                
        except PermissionError:
            console.print("[yellow]Cannot read SSH config (need root privileges)[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Error reading SSH config: {e}[/yellow]")
        
        return findings
    
    def check_firewall_status(self) -> List[MisconfigFinding]:
        """Check if firewall is enabled and configured"""
        findings = []
        
        # Check for iptables
        iptables_output = self.run_command(["iptables", "-L", "-n"])
        
        # Check for ufw
        ufw_output = self.run_command(["ufw", "status"])
        
        # Check for firewalld
        firewalld_output = self.run_command(["firewall-cmd", "--state"])
        
        firewall_active = False
        
        if ufw_output and "Status: active" in ufw_output:
            firewall_active = True
        
        if firewalld_output and "running" in firewalld_output:
            firewall_active = True
        
        if iptables_output:
            # Check if there are any rules beyond default
            lines = iptables_output.strip().split("\n")
            rule_lines = [l for l in lines if l and not l.startswith("Chain") and not l.startswith("target")]
            if rule_lines:
                firewall_active = True
        
        if not firewall_active:
            findings.append(MisconfigFinding(
                check_name="No Active Firewall",
                severity="HIGH",
                description="No active firewall detected on the system",
                details="Neither ufw, firewalld, nor iptables rules are active",
                remediation="Enable and configure a firewall (ufw, firewalld, or iptables)",
                affected_items=["System firewall"]
            ))
        
        return findings
    
    def check_world_writable_files(self) -> List[MisconfigFinding]:
        """Check for world-writable files in sensitive directories"""
        findings = []
        sensitive_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        world_writable = []
        
        for dir_path in sensitive_dirs:
            if os.path.exists(dir_path):
                output = self.run_command(
                    ["find", dir_path, "-type", "f", "-perm", "-002", "-maxdepth", "2"],
                    timeout=60
                )
                if output:
                    files = [f.strip() for f in output.split("\n") if f.strip()]
                    world_writable.extend(files[:10])  # Limit to 10 per directory
        
        if world_writable:
            findings.append(MisconfigFinding(
                check_name="World-Writable Files in Sensitive Directories",
                severity="HIGH",
                description="Found files writable by any user in sensitive system directories",
                details=f"Found {len(world_writable)} world-writable files",
                remediation="Remove world-writable permission: chmod o-w <file>",
                affected_items=world_writable[:20]  # Limit to 20 total
            ))
        
        return findings
    
    def check_suid_files(self) -> List[MisconfigFinding]:
        """Check for unusual SUID/SGID files"""
        findings = []
        
        # Known safe SUID binaries
        known_suid = {
            "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
            "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
            "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
            "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/bin/at",
            "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping"
        }
        
        output = self.run_command(
            ["find", "/", "-type", "f", "-perm", "/4000", "-o", "-perm", "/2000"],
            timeout=120
        )
        
        if output:
            suid_files = [f.strip() for f in output.split("\n") if f.strip()]
            unusual_suid = [f for f in suid_files if f not in known_suid][:30]
            
            if unusual_suid:
                findings.append(MisconfigFinding(
                    check_name="Unusual SUID/SGID Files",
                    severity="MEDIUM",
                    description="Found SUID/SGID files outside of common system binaries",
                    details=f"Found {len(unusual_suid)} unusual SUID/SGID files",
                    remediation="Review these files and remove SUID bit if not needed: chmod u-s <file>",
                    affected_items=unusual_suid
                ))
        
        return findings
    
    def check_weak_permissions(self) -> List[MisconfigFinding]:
        """Check for sensitive files with weak permissions"""
        findings = []
        
        sensitive_files = {
            "/etc/shadow": "600",
            "/etc/gshadow": "600",
            "/etc/passwd": "644",
            "/etc/group": "644",
            "/etc/ssh/sshd_config": "600",
            "/etc/sudoers": "440",
            "/root/.ssh/authorized_keys": "600",
            "/root/.ssh/id_rsa": "600"
        }
        
        weak_files = []
        
        for file_path, expected_perm in sensitive_files.items():
            if os.path.exists(file_path):
                try:
                    stat_info = os.stat(file_path)
                    actual_perm = oct(stat_info.st_mode)[-3:]
                    
                    # Check if permissions are weaker than expected
                    if int(actual_perm, 8) > int(expected_perm, 8):
                        weak_files.append(f"{file_path} (current: {actual_perm}, expected: {expected_perm})")
                except PermissionError:
                    pass
        
        if weak_files:
            findings.append(MisconfigFinding(
                check_name="Sensitive Files with Weak Permissions",
                severity="HIGH",
                description="Sensitive system files have overly permissive permissions",
                details=f"Found {len(weak_files)} files with weak permissions",
                remediation="Correct file permissions using chmod",
                affected_items=weak_files
            ))
        
        return findings
    
    def check_running_services(self) -> List[MisconfigFinding]:
        """Check for potentially risky running services"""
        findings = []
        
        risky_services = {
            "telnet": "CRITICAL",
            "rsh": "CRITICAL",
            "rlogin": "CRITICAL",
            "rexec": "CRITICAL",
            "ftp": "MEDIUM",
            "tftp": "HIGH",
            "finger": "LOW",
            "rpcbind": "LOW"
        }
        
        output = self.run_command(["systemctl", "list-units", "--type=service", "--state=running"])
        
        if output:
            found_risky = []
            for service, severity in risky_services.items():
                if service in output.lower():
                    found_risky.append((service, severity))
            
            if found_risky:
                for service, severity in found_risky:
                    findings.append(MisconfigFinding(
                        check_name=f"Risky Service Running: {service}",
                        severity=severity,
                        description=f"The {service} service is running and poses security risks",
                        details=f"{service} is an insecure or legacy protocol",
                        remediation=f"Disable with: systemctl disable --now {service}",
                        affected_items=[service]
                    ))
        
        return findings
    
    def check_outdated_packages(self) -> List[MisconfigFinding]:
        """Check for available security updates"""
        findings = []
        
        # Check for apt (Debian/Ubuntu)
        if os.path.exists("/usr/bin/apt"):
            output = self.run_command(["apt", "list", "--upgradable"], timeout=120)
            if output:
                upgradable = [l for l in output.split("\n") if "/" in l and "security" in l.lower()]
                if upgradable:
                    findings.append(MisconfigFinding(
                        check_name="Security Updates Available",
                        severity="MEDIUM",
                        description=f"{len(upgradable)} security updates available",
                        details="Packages with security patches are available",
                        remediation="Run: apt update && apt upgrade",
                        affected_items=upgradable[:10]
                    ))
        
        # Check for yum/dnf (RHEL/CentOS/Fedora)
        elif os.path.exists("/usr/bin/dnf"):
            output = self.run_command(["dnf", "check-update", "--security"], timeout=120)
            if output and "No security updates" not in output:
                findings.append(MisconfigFinding(
                    check_name="Security Updates Available (DNF)",
                    severity="MEDIUM",
                    description="Security updates are available via DNF",
                    details="Run dnf for details",
                    remediation="Run: dnf update --security",
                    affected_items=["DNF security updates"]
                ))
        
        return findings
    
    def check_password_policy(self) -> List[MisconfigFinding]:
        """Check password policy configuration"""
        findings = []
        
        # Check /etc/login.defs
        login_defs = "/etc/login.defs"
        if os.path.exists(login_defs):
            try:
                with open(login_defs, "r") as f:
                    config = f.read()
                
                # Check password aging
                pass_max_match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", config, re.MULTILINE)
                if pass_max_match:
                    max_days = int(pass_max_match.group(1))
                    if max_days > 90 or max_days == 99999:
                        findings.append(MisconfigFinding(
                            check_name="Weak Password Aging Policy",
                            severity="MEDIUM",
                            description=f"Password expiration set to {max_days} days",
                            details="Password aging policy is too permissive",
                            remediation="Set PASS_MAX_DAYS to 90 or less in /etc/login.defs",
                            affected_items=[login_defs]
                        ))
                
                # Check minimum password length
                pass_min_match = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", config, re.MULTILINE)
                if pass_min_match:
                    min_len = int(pass_min_match.group(1))
                    if min_len < 8:
                        findings.append(MisconfigFinding(
                            check_name="Weak Minimum Password Length",
                            severity="MEDIUM",
                            description=f"Minimum password length is only {min_len} characters",
                            details="Minimum password length should be at least 8",
                            remediation="Set PASS_MIN_LEN to 8 or more in /etc/login.defs",
                            affected_items=[login_defs]
                        ))
                        
            except PermissionError:
                pass
        
        return findings
    
    def check_users_with_uid_zero(self) -> List[MisconfigFinding]:
        """Check for users with UID 0 (root privileges)"""
        findings = []
        
        try:
            with open("/etc/passwd", "r") as f:
                passwd = f.readlines()
            
            uid_zero_users = []
            for line in passwd:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                    uid_zero_users.append(parts[0])
            
            if uid_zero_users:
                findings.append(MisconfigFinding(
                    check_name="Non-root Users with UID 0",
                    severity="CRITICAL",
                    description="Found users other than root with UID 0",
                    details="These users have full root privileges",
                    remediation="Remove or change UID of these users",
                    affected_items=uid_zero_users
                ))
                
        except PermissionError:
            pass
        
        return findings
    
    def run_all_checks(self) -> List[MisconfigFinding]:
        """Run all misconfiguration checks"""
        console.print("\n[bold cyan]Running Misconfiguration Checks...[/bold cyan]\n")
        
        checks = [
            ("SSH Configuration", self.check_ssh_config),
            ("Firewall Status", self.check_firewall_status),
            ("World-Writable Files", self.check_world_writable_files),
            ("SUID/SGID Files", self.check_suid_files),
            ("File Permissions", self.check_weak_permissions),
            ("Running Services", self.check_running_services),
            ("Password Policy", self.check_password_policy),
            ("UID Zero Users", self.check_users_with_uid_zero),
        ]
        
        if self.is_root:
            checks.append(("Outdated Packages", self.check_outdated_packages))
        
        all_findings = []
        
        for check_name, check_func in checks:
            console.print(f"  [cyan]Checking:[/cyan] {check_name}")
            try:
                findings = check_func()
                all_findings.extend(findings)
                if findings:
                    console.print(f"    [yellow]Found {len(findings)} issue(s)[/yellow]")
                else:
                    console.print(f"    [green]✓ Passed[/green]")
            except Exception as e:
                console.print(f"    [red]Error: {e}[/red]")
        
        self.findings = all_findings
        return all_findings
    
    def display_findings(self):
        """Display findings in a formatted table"""
        if not self.findings:
            console.print("\n[bold green]No misconfigurations found![/bold green]")
            return
        
        # Sort by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.index(x.severity) if x.severity in severity_order else 99
        )
        
        table = Table(title="Misconfiguration Findings", show_header=True, header_style="bold magenta")
        table.add_column("Severity", width=10)
        table.add_column("Check", width=35)
        table.add_column("Description", width=50)
        
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue"
        }
        
        for finding in sorted_findings:
            color = severity_colors.get(finding.severity, "white")
            table.add_row(
                f"[{color}]{finding.severity}[/{color}]",
                finding.check_name,
                finding.description
            )
        
        console.print(table)
    
    def export_findings(self) -> List[Dict]:
        """Export findings as list of dictionaries"""
        return [
            {
                "check_name": f.check_name,
                "severity": f.severity,
                "description": f.description,
                "details": f.details,
                "remediation": f.remediation,
                "affected_items": f.affected_items
            }
            for f in self.findings
        ]
    
    def get_risk_score(self) -> int:
        """Calculate overall risk score based on findings"""
        return sum(self.SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)


def main():
    """Test misconfiguration detection"""
    detector = MisconfigDetector()
    detector.run_all_checks()
    detector.display_findings()
    
    score = detector.get_risk_score()
    console.print(f"\n[bold]Overall Risk Score: {score}[/bold]")


if __name__ == "__main__":
    main()
