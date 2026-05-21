"""
Network port scanning module
"""

import socket
import threading
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from red_team_toolkit.utils import get_logger

logger = get_logger(__name__)


class PortScanner:
    """Multi-threaded port scanner with service detection"""

    # Common ports and their services
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5984: "CouchDB",
        6379: "Redis",
        7001: "MongoDB",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    def __init__(self, target: str, timeout: float = 2.0, max_workers: int = 50):
        """
        Initialize port scanner

        Args:
            target: Target hostname or IP address
            timeout: Socket timeout in seconds
            max_workers: Maximum number of worker threads
        """
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports: Dict[int, Optional[str]] = {}
        self.results = []

    def _check_port(self, port: int) -> bool:
        """
        Check if a single port is open

        Args:
            port: Port number to check

        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except socket.gaierror:
            logger.error(f"Hostname {self.target} could not be resolved")
            return False
        except socket.error as e:
            logger.error(f"Could not connect to {self.target}: {e}")
            return False

    def _get_service_name(self, port: int) -> Optional[str]:
        """
        Get service name for a port

        Args:
            port: Port number

        Returns:
            Service name if known, None otherwise
        """
        try:
            return socket.getservbyport(port)
        except OSError:
            return self.COMMON_PORTS.get(port)

    def scan(
        self,
        ports: Optional[List[int]] = None,
        top_ports: int = 1000,
        verbose: bool = True,
    ) -> Dict[int, Optional[str]]:
        """
        Scan target for open ports

        Args:
            ports: Specific ports to scan (if None, scan top ports)
            top_ports: Number of top ports to scan if ports not specified
            verbose: Print progress information

        Returns:
            Dictionary of open ports and their services
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())[:top_ports]

        if verbose:
            logger.info(f"Starting scan of {self.target} on {len(ports)} ports")

        self.open_ports = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._check_port, port): port for port in ports
            }

            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1

                try:
                    if future.result():
                        service = self._get_service_name(port)
                        self.open_ports[port] = service
                        if verbose:
                            logger.info(
                                f"[{completed}/{len(ports)}] Port {port} is open ({service})"
                            )
                except Exception as e:
                    logger.error(f"Error checking port {port}: {e}")

        if verbose:
            logger.info(f"Scan complete. Found {len(self.open_ports)} open ports")

        return self.open_ports

    def scan_range(
        self, start_port: int = 1, end_port: int = 65535, verbose: bool = True
    ) -> Dict[int, Optional[str]]:
        """
        Scan a range of ports

        Args:
            start_port: Starting port
            end_port: Ending port
            verbose: Print progress information

        Returns:
            Dictionary of open ports and their services
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan(ports=ports, verbose=verbose)

    def get_results(self) -> List[Dict]:
        """
        Get scan results as a list

        Returns:
            List of open port information
        """
        return [
            {"port": port, "service": service}
            for port, service in sorted(self.open_ports.items())
        ]

    def summary(self) -> Dict:
        """
        Get scan summary

        Returns:
            Dictionary with scan summary
        """
        return {
            "target": self.target,
            "total_open_ports": len(self.open_ports),
            "open_ports": sorted(self.open_ports.keys()),
            "services": list(self.open_ports.values()),
        }
