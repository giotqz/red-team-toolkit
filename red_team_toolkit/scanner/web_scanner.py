"""
Web application vulnerability scanning module
"""

import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from red_team_toolkit.utils import get_logger

logger = get_logger(__name__)


class WebScanner:
    """Web application vulnerability scanner"""

    # Common web vulnerabilities
    COMMON_VULNS = {
        "SQL Injection": {
            "payloads": ["' OR '1'='1", "'; DROP TABLE users--"],
            "severity": "Critical",
        },
        "XSS": {
            "payloads": ["<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"],
            "severity": "High",
        },
        "Command Injection": {
            "payloads": ["; whoami", "| id", "` cat /etc/passwd `"],
            "severity": "Critical",
        },
    }

    # Common endpoints to check
    COMMON_ENDPOINTS = [
        "/admin",
        "/admin.php",
        "/administrator",
        "/wp-admin",
        "/api",
        "/api/v1",
        "/login",
        "/signin",
        "/.git",
        "/.env",
        "/config.php",
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize web scanner

        Args:
            target_url: Target URL to scan
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.timeout = timeout
        self.vulnerabilities: List[Dict] = []
        self.discovered_endpoints: List[str] = []

        # Validate URL format
        if not target_url.startswith(("http://", "https://")):
            self.target_url = "http://" + target_url

    def _make_request(self, url: str, method: str = "GET", data: Dict = None) -> Optional[requests.Response]:
        """
        Make HTTP request safely

        Args:
            url: URL to request
            method: HTTP method
            data: Request data

        Returns:
            Response object or None
        """
        try:
            if method == "GET":
                response = requests.get(url, timeout=self.timeout, verify=False)
            else:
                response = requests.post(url, data=data, timeout=self.timeout, verify=False)
            return response
        except requests.RequestException as e:
            logger.debug(f"Request error: {e}")
            return None

    def discover_endpoints(self) -> List[str]:
        """
        Discover common endpoints

        Returns:
            List of discovered endpoints
        """
        logger.info(f"Discovering endpoints on {self.target_url}")
        self.discovered_endpoints = []

        for endpoint in self.COMMON_ENDPOINTS:
            url = urljoin(self.target_url, endpoint)
            response = self._make_request(url)

            if response and response.status_code != 404:
                self.discovered_endpoints.append(endpoint)
                logger.info(f"Found endpoint: {endpoint} (Status: {response.status_code})")
                self.vulnerabilities.append(
                    {
                        "type": "Information Disclosure",
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "severity": "Medium",
                        "description": f"Endpoint {endpoint} is accessible",
                    }
                )

        logger.info(f"Discovered {len(self.discovered_endpoints)} endpoints")
        return self.discovered_endpoints

    def check_default_pages(self) -> List[Dict]:
        """
        Check for default pages and files

        Returns:
            List of found default pages
        """
        default_files = [
            "/index.html",
            "/index.php",
            "/robots.txt",
            "/sitemap.xml",
            "/backup.zip",
            "/database.sql",
        ]

        found = []

        for file_path in default_files:
            url = urljoin(self.target_url, file_path)
            response = self._make_request(url)

            if response and response.status_code == 200:
                found.append(
                    {
                        "type": "Information Disclosure",
                        "file": file_path,
                        "severity": "Medium",
                        "description": f"Sensitive file {file_path} is accessible",
                    }
                )
                logger.info(f"Found sensitive file: {file_path}")

        return found

    def check_security_headers(self) -> List[Dict]:
        """
        Check for missing security headers

        Returns:
            List of missing security headers
        """
        required_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]

        response = self._make_request(self.target_url)
        if not response:
            return []

        found_issues = []
        headers = response.headers

        for header in required_headers:
            if header not in headers:
                found_issues.append(
                    {
                        "type": "Missing Security Header",
                        "header": header,
                        "severity": "Medium",
                        "description": f"Missing security header: {header}",
                    }
                )
                logger.info(f"Missing header: {header}")

        return found_issues

    def scan(self) -> List[Dict]:
        """
        Run full web application scan

        Returns:
            List of found vulnerabilities
        """
        logger.info(f"Starting web scan on {self.target_url}")

        # Discover endpoints
        self.discover_endpoints()

        # Check default pages
        default_page_vulns = self.check_default_pages()
        self.vulnerabilities.extend(default_page_vulns)

        # Check security headers
        header_vulns = self.check_security_headers()
        self.vulnerabilities.extend(header_vulns)

        logger.info(f"Web scan complete. Found {len(self.vulnerabilities)} issues")
        return self.vulnerabilities

    def get_vulnerabilities(self) -> List[Dict]:
        """
        Get found vulnerabilities

        Returns:
            List of vulnerabilities
        """
        return self.vulnerabilities

    def get_summary(self) -> Dict:
        """
        Get scan summary

        Returns:
            Scan summary
        """
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "target": self.target_url,
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": severity_counts,
            "discovered_endpoints": len(self.discovered_endpoints),
        }
