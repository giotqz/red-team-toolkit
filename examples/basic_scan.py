#!/usr/bin/env python3
"""
Basic network scanning example for Red Team Toolkit
"""

from red_team_toolkit.scanner import PortScanner, ServiceEnumeration, VulnerabilityScanner
from red_team_toolkit.reporting import ReportGenerator


def main():
    """Run basic scan example"""

    # Target to scan
    target = "192.168.1.1"

    print(f"[*] Starting Red Team Toolkit - Basic Scan on {target}")
    print("[*] This example demonstrates port scanning and service enumeration")
    print()

    # Step 1: Port Scanning
    print("[+] Step 1: Port Scanning")
    port_scanner = PortScanner(target, timeout=2.0, max_workers=50)
    open_ports = port_scanner.scan(top_ports=100, verbose=True)

    print(f"\n[+] Found {len(open_ports)} open ports")
    print(port_scanner.summary())
    print()

    # Step 2: Service Enumeration
    if open_ports:
        print("[+] Step 2: Service Enumeration")
        service_enum = ServiceEnumeration(target)
        services = service_enum.enumerate_ports(list(open_ports.keys()), verbose=True)

        print(f"\n[+] Enumerated {len(services)} services")
        print(service_enum.get_service_summary())
        print()

        # Step 3: Vulnerability Scanning
        print("[+] Step 3: Vulnerability Scanning")
        vuln_scanner = VulnerabilityScanner(target)
        vulnerabilities = vuln_scanner.scan_services(services, list(open_ports.keys()))

        print(f"\n[+] Found {len(vulnerabilities)} potential vulnerabilities")
        summary = vuln_scanner.get_summary()
        print(f"Severity Breakdown: {summary['by_severity']}")
        print()

        # Step 4: Generate Report
        print("[+] Step 4: Generating Report")
        report = ReportGenerator(target, assessor="Red Team Toolkit")
        report.add_vulnerabilities(vulnerabilities)

        # Generate reports in multiple formats
        report.generate_html("assessment_report.html")
        report.generate_json("assessment_report.json")

        print("[+] Reports generated:")
        print("  - assessment_report.html")
        print("  - assessment_report.json")
        print()
        print(report.generate_summary())
    else:
        print("[-] No open ports found. Skipping service enumeration and vulnerability scanning.")


if __name__ == "__main__":
    main()
