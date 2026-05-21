"""
Vulnerability scanning module
"""

from typing import Dict, List, Optional
from datetime import datetime
from red_team_toolkit.utils import get_logger

logger = get_logger(__name__)


class VulnerabilityScanner:
    """General vulnerability scanner with common vulnerability checks"""

    # Known vulnerable service versions
    VULNERABLE_SERVICES = {
        "SSH": [
            {"version": "1.0", "cve": "CVE-2001-0554", "severity": "Critical"},
            {"version": "2.0", "cve": "CVE-2006-4924", "severity": "High"},
        ],
        "FTP": [
            {"service": "vsftpd 2.3.4", "cve": "CVE-2011-2523", "severity": "Critical"},
        ],
        "HTTP": [
            {"service": "Apache 1.x", "cve": "CVE-2002-0082", "severity": "High"},
        ],
        "MySQL": [
            {"version": "5.0", "cve": "CVE-2012-2122", "severity": "High"},
        ],
    }

    # Common weak configurations
    WEAK_CONFIGS = {
        "default_credentials": [
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": "root"},
            {"username": "admin", "password": "password"},
        ],
        "open_ports": [3389, 5900, 4444],  # RDP, VNC, common backdoor
    }

    def __init__(self, target: str):
        """
        Initialize vulnerability scanner

        Args:
            target: Target hostname or IP address
        """
        self.target = target
        self.vulnerabilities: List[Dict] = []

    def check_service_version(self, service: str, version: str) -> List[Dict]:
        """
        Check for known vulnerabilities in service version

        Args:
            service: Service name
            version: Service version

        Returns:
            List of matching vulnerabilities
        """
        found_vulns = []

        if service in self.VULNERABLE_SERVICES:
            for vuln in self.VULNERABLE_SERVICES[service]:
                if (
                    "version" in vuln
                    and version
                    and version in vuln.get("version", "")
                ):
                    found_vulns.append(
                        {
                            "type": "Service Version Vulnerability",
                            "service": service,
                            "version": version,
                            "cve": vuln.get("cve"),
                            "severity": vuln.get("severity", "Medium"),
                            "description": f"{service} version {version} has known vulnerabilities",
                        }
                    )

        return found_vulns

    def check_default_credentials(self, service: str) -> List[Dict]:
        """
        Check for default credentials

        Args:
            service: Service name

        Returns:
            List of potential default credential vulnerabilities
        """
        found_vulns = []

        # Common services with default credentials
        default_creds_services = ["HTTP", "FTP", "SSH", "MySQL", "PostgreSQL"]

        if service in default_creds_services:
            found_vulns.append(
                {
                    "type": "Default Credentials",
                    "service": service,
                    "severity": "High",
                    "description": f"{service} may have default credentials",
                    "recommendation": "Test for common default credentials",
                }
            )

        return found_vulns

    def check_open_dangerous_ports(self, open_ports: List[int]) -> List[Dict]:
        """
        Check for dangerous open ports

        Args:
            open_ports: List of open port numbers

        Returns:
            List of potential vulnerabilities
        """
        found_vulns = []

        for port in open_ports:
            if port in self.WEAK_CONFIGS["open_ports"]:
                service_map = {
                    3389: "RDP (Remote Desktop)",
                    5900: "VNC",
                    4444: "Common Backdoor Port",
                }
                found_vulns.append(
                    {
                        "type": "Dangerous Port Open",
                        "port": port,
                        "service": service_map.get(port, "Unknown"),
                        "severity": "High",
                        "description": f"Potentially dangerous service running on port {port}",
                        "recommendation": "Restrict access to this port if not required",
                    }
                )

        return found_vulns

    def check_ssl_tls_issues(self, port: int, service: str) -> List[Dict]:
        """
        Check for SSL/TLS issues (placeholder for actual SSL checking)

        Args:
            port: Port number
            service: Service name

        Returns:
            List of SSL/TLS vulnerabilities
        """
        found_vulns = []

        # This is a placeholder for actual SSL/TLS checking
        if service in ["HTTPS", "IMAPS", "POP3S", "SMTPS"]:
            found_vulns.append(
                {
                    "type": "SSL/TLS Configuration",
                    "port": port,
                    "service": service,
                    "severity": "Medium",
                    "description": "SSL/TLS configuration should be verified",
                    "recommendation": "Run SSL/TLS diagnostic tools to check for weak ciphers and protocols",
                }
            )

        return found_vulns

    def scan_services(
        self, services: Dict[int, Dict], open_ports: List[int]
    ) -> List[Dict]:
        """
        Scan enumerated services for vulnerabilities

        Args:
            services: Dictionary of enumerated services
            open_ports: List of open ports

        Returns:
            List of found vulnerabilities
        """
        self.vulnerabilities = []

        logger.info(f"Starting vulnerability scan on {self.target}")

        # Check service versions
        for port, service_info in services.items():
            service = service_info.get("service")
            version = service_info.get("version")

            if service != "Unknown":
                vulns = self.check_service_version(service, version)
                self.vulnerabilities.extend(vulns)

                # Check for default credentials
                cred_vulns = self.check_default_credentials(service)
                self.vulnerabilities.extend(cred_vulns)

                # Check SSL/TLS
                ssl_vulns = self.check_ssl_tls_issues(port, service)
                self.vulnerabilities.extend(ssl_vulns)

        # Check for dangerous ports
        dangerous_vulns = self.check_open_dangerous_ports(open_ports)
        self.vulnerabilities.extend(dangerous_vulns)

        logger.info(f"Found {len(self.vulnerabilities)} potential vulnerabilities")

        return self.vulnerabilities

    def get_vulnerabilities(
        self, severity: Optional[str] = None
    ) -> List[Dict]:
        """
        Get found vulnerabilities, optionally filtered by severity

        Args:
            severity: Filter by severity level (Critical, High, Medium, Low)

        Returns:
            List of vulnerabilities
        """
        if severity:
            return [v for v in self.vulnerabilities if v.get("severity") == severity]
        return self.vulnerabilities

    def get_summary(self) -> Dict:
        """
        Get vulnerability scan summary

        Returns:
            Vulnerability summary
        """
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": severity_counts,
            "vulnerabilities": self.vulnerabilities,
        }
