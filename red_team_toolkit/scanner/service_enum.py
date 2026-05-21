"""
Service enumeration and fingerprinting module
"""

import socket
import re
from typing import Dict, Optional, List
from red_team_toolkit.utils import get_logger

logger = get_logger(__name__)


class ServiceEnumeration:
    """Service identification and version detection"""

    # Service banners and version patterns
    SERVICE_PATTERNS = {
        "SSH": {
            "port": 22,
            "pattern": rb"SSH-",
            "version_pattern": r"SSH-([0-9.]+)",
        },
        "FTP": {
            "port": 21,
            "pattern": rb"220",
            "version_pattern": r"(\d+\.\d+)",
        },
        "HTTP": {
            "port": 80,
            "pattern": rb"HTTP/",
            "version_pattern": r"Server: ([^\r\n]+)",
        },
        "HTTPS": {
            "port": 443,
            "pattern": rb"HTTP/",
            "version_pattern": r"Server: ([^\r\n]+)",
        },
        "SMTP": {
            "port": 25,
            "pattern": rb"220",
            "version_pattern": r"(\d+\.\d+)",
        },
        "MySQL": {
            "port": 3306,
            "pattern": rb"mysql",
            "version_pattern": r"(\d+\.\d+\.\d+)",
        },
        "PostgreSQL": {
            "port": 5432,
            "pattern": rb"PostgreSQL",
            "version_pattern": r"PostgreSQL (\d+\.\d+)",
        },
    }

    def __init__(self, target: str, timeout: float = 3.0):
        """
        Initialize service enumeration

        Args:
            target: Target hostname or IP address
            timeout: Socket timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.services = {}

    def _grab_banner(self, port: int) -> Optional[bytes]:
        """
        Grab service banner from port

        Args:
            port: Port number

        Returns:
            Banner data or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            banner = sock.recv(4096)
            sock.close()
            return banner
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return None

    def _send_http_request(self, port: int) -> Optional[bytes]:
        """
        Send HTTP request to identify web server

        Args:
            port: Port number

        Returns:
            HTTP response or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            request = b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n"
            sock.send(request)
            response = sock.recv(4096)
            sock.close()
            return response
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return None

    def enumerate_port(self, port: int) -> Optional[Dict]:
        """
        Enumerate service on specific port

        Args:
            port: Port number

        Returns:
            Service information dictionary or None
        """
        service_info = {
            "port": port,
            "service": "Unknown",
            "version": None,
            "banner": None,
            "confidence": 0,
        }

        # Try standard banner grab
        banner = self._grab_banner(port)
        if not banner:
            # Try HTTP request for web services
            banner = self._send_http_request(port)

        if not banner:
            return None

        service_info["banner"] = banner[:200].decode("utf-8", errors="ignore")

        # Match against known patterns
        for service, config in self.SERVICE_PATTERNS.items():
            pattern = config["pattern"]
            if pattern in banner:
                service_info["service"] = service
                service_info["confidence"] = 90

                # Try to extract version
                version_pattern = config["version_pattern"]
                match = re.search(version_pattern, banner.decode("utf-8", errors="ignore"))
                if match:
                    service_info["version"] = match.group(1)

                break

        logger.info(
            f"Port {port}: {service_info['service']} "
            f"(v{service_info['version'] or 'Unknown'})"
        )
        return service_info

    def enumerate_ports(self, ports: List[int], verbose: bool = True) -> Dict[int, Dict]:
        """
        Enumerate services on multiple ports

        Args:
            ports: List of port numbers
            verbose: Print progress information

        Returns:
            Dictionary of service information by port
        """
        self.services = {}

        for port in ports:
            result = self.enumerate_port(port)
            if result:
                self.services[port] = result

        if verbose:
            logger.info(f"Enumerated {len(self.services)} services on {self.target}")

        return self.services

    def get_services(self) -> List[Dict]:
        """
        Get enumerated services

        Returns:
            List of service information
        """
        return sorted(self.services.values(), key=lambda x: x["port"])

    def get_service_summary(self) -> Dict:
        """
        Get summary of enumerated services

        Returns:
            Service summary
        """
        service_types = {}
        for port, info in self.services.items():
            service = info["service"]
            if service not in service_types:
                service_types[service] = []
            service_types[service].append(port)

        return {
            "target": self.target,
            "total_services": len(self.services),
            "services": service_types,
            "details": self.get_services(),
        }
