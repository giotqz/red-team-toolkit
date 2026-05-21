# Red Team Toolkit

A comprehensive Python-based penetration testing and vulnerability scanning automation framework designed for security professionals and red teams.

## Features

### 🔍 Vulnerability Scanning
- **Network Reconnaissance**: Port scanning, service enumeration, version detection
- **Web Application Scanning**: Endpoint discovery, parameter fuzzing, vulnerability detection
- **Service Enumeration**: Identify and fingerprint running services
- **Database Scanning**: Common database misconfigurations and weaknesses

### ⚡ Penetration Testing Automation
- **Credential Testing**: Automated credential stuffing and brute force attacks
- **Exploitation Patterns**: Common vulnerability exploitation workflows
- **Session Management**: Maintain and manage authenticated sessions
- **Payload Generation**: Dynamic payload creation for various attack vectors

### 📊 Reporting & Analysis
- **HTML Reports**: Professional security assessment reports
- **JSON Export**: Machine-readable output for integration
- **Finding Management**: Track and categorize vulnerabilities
- **Risk Scoring**: CVSS-based severity assessment

### 🧩 Modular Architecture
- Plugin system for custom modules
- Extensible configuration framework
- Chainable workflows for complex operations

## Quick Start

### Prerequisites
- Python 3.9+
- pip package manager

### Installation

```bash
git clone https://github.com/giotqz/red-team-toolkit.git
cd red-team-toolkit
pip install -r requirements.txt
```

### Basic Usage

```python
from red_team_toolkit.scanner import PortScanner, ServiceEnumeration
from red_team_toolkit.reporting import ReportGenerator

# Initialize scanner
scanner = PortScanner("192.168.1.1")
open_ports = scanner.scan(top_ports=1000)

# Enumerate services
service_enum = ServiceEnumeration("192.168.1.1")
services = service_enum.enumerate_ports(list(open_ports.keys()))

# Generate report
report = ReportGenerator("192.168.1.1")
report.add_vulnerabilities([])
report.generate_html("report.html")
```

## Project Structure

```
red-team-toolkit/
├── red_team_toolkit/
│   ├── __init__.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── port_scanner.py
│   │   ├── service_enum.py
│   │   ├── vuln_scanner.py
│   │   └── web_scanner.py
│   ├── pentest/
│   │   ├── __init__.py
│   │   ├── credential_tester.py
│   │   ├── exploit_engine.py
│   │   └── payload_generator.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   └── report_generator.py
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       └── helpers.py
├── examples/
│   ├── basic_scan.py
│   └── web_pentest.py
├── requirements.txt
├── setup.py
├── LICENSE
└── README.md
```

## Modules

### Scanner Module
- **PortScanner**: Fast multi-threaded port scanning with service detection
- **ServiceEnumeration**: Service version detection and fingerprinting
- **VulnerabilityScanner**: Known vulnerability checking against CVE databases
- **WebScanner**: Web application vulnerability scanning

### Penetration Testing Module
- **CredentialTester**: Automated credential validation (SSH, FTP, HTTP)
- **ExploitEngine**: Vulnerability exploitation framework
- **PayloadGenerator**: Dynamic payload creation for SQL injection, XSS, command injection, etc.

### Reporting Module
- **ReportGenerator**: Multi-format report generation (HTML, JSON, CSV)

## Examples

### Example 1: Network Reconnaissance
```python
from red_team_toolkit.scanner import PortScanner, ServiceEnumeration

scanner = PortScanner("target.com")
results = scanner.scan(top_ports=1000)
print(scanner.summary())
```

### Example 2: Web Application Testing
```python
from red_team_toolkit.scanner import WebScanner

web_scanner = WebScanner("https://target.com")
vulns = web_scanner.scan()
print(web_scanner.get_summary())
```

### Example 3: Credential Testing
```python
from red_team_toolkit.pentest import CredentialTester

tester = CredentialTester()
credentials = tester.test_credentials_ssh("192.168.1.1", 22, [("admin", "password")])
print(tester.get_successful_credentials())
```

## Safety & Legal

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Only use this tool on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Always obtain proper authorization before conducting any security assessments
- Follow all applicable laws and regulations in your jurisdiction

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided "as-is" for educational and authorized security testing purposes only. The author assumes no liability for misuse or damage caused by this tool. Users are responsible for ensuring their use complies with all applicable laws and regulations.

## Support

For issues, questions, or feature requests, please open an [issue on GitHub](https://github.com/giotqz/red-team-toolkit/issues).

---

**Created for cybersecurity professionals. Use responsibly.**