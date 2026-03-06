"""DoS vulnerability assessment module — detection only, no active attacks."""

import os
import re
import tempfile
from nmappilot.colors import Colors
from nmappilot.ui import print_status, print_section, print_subsection
from nmappilot.nmap_runner import run_nmap, run_searchsploit
from nmappilot.xml_parser import parse_nmap_xml, get_service_string
from nmappilot.analyzer import VulnFinding, extract_cves


# ─────────── DoS-related NSE scripts ──────────────────────────────

DOS_SCRIPTS = [
    "http-slowloris-check",
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-ccs-injection",
    "smb-vuln-ms06-025",
    "smb-vuln-ms07-029",
    "smb-vuln-ms08-067",
    "smb-vuln-ms10-054",
    "smb-vuln-ms10-061",
    "smb-vuln-ms17-010",
    "smb-vuln-regsvc-dos",
    "smb2-vuln-uptime",
    "ipmi-cipher-zero",
]

# Services commonly susceptible to amplification/reflection attacks
AMPLIFICATION_SERVICES = {
    "domain": {
        "name": "DNS",
        "issue": "DNS Amplification",
        "desc": "DNS service may be exploitable for amplification attacks if open resolver",
        "severity": "HIGH",
    },
    "ntp": {
        "name": "NTP",
        "issue": "NTP Amplification (monlist)",
        "desc": "NTP service may support monlist command for amplification attacks",
        "severity": "HIGH",
    },
    "snmp": {
        "name": "SNMP",
        "issue": "SNMP Amplification",
        "desc": "SNMP service may be exploitable for amplification attacks",
        "severity": "HIGH",
    },
    "memcache": {
        "name": "Memcached",
        "issue": "Memcached Amplification",
        "desc": "Memcached service exposed—can be used for massive amplification attacks",
        "severity": "CRITICAL",
    },
    "chargen": {
        "name": "Chargen",
        "issue": "Chargen Amplification",
        "desc": "Chargen service can be abused for amplification attacks",
        "severity": "HIGH",
    },
    "ssdp": {
        "name": "SSDP/UPnP",
        "issue": "SSDP Amplification",
        "desc": "SSDP service can be abused for amplification attacks",
        "severity": "HIGH",
    },
}

# Known DoS-related CVE patterns
DOS_CVE_KEYWORDS = [
    "denial of service", "dos", "crash", "infinite loop",
    "resource exhaustion", "memory leak", "memory exhaustion",
    "cpu exhaustion", "amplification", "flood",
    "hang", "unresponsive", "stack overflow",
]


class DoSChecker:
    """Assess DoS vulnerability risk — detection only."""

    def __init__(self, scan_result):
        self.scan_result = scan_result
        self.findings = []
        self._tmp_dir = tempfile.mkdtemp(prefix="nmappilot_dos_")

    def run(self):
        """Execute all DoS assessment checks."""
        print_section("DoS VULNERABILITY ASSESSMENT", "◎")
        print_status(
            f"{Colors.YELLOW}Note: Detection only — no actual DoS attacks are performed{Colors.RESET}",
            "info"
        )
        print()

        self._run_dos_nse_scripts()
        self._check_amplification_services()
        self._searchsploit_dos()
        self._analyze_dos_surface()

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        dos_count = len(self.findings)
        crit = sum(1 for f in self.findings if f.severity in ("CRITICAL", "HIGH"))

        print()
        if dos_count == 0:
            print_status("No DoS vulnerabilities detected", "ok")
        else:
            print_status(
                f"DoS assessment complete — {dos_count} finding(s), "
                f"{crit} critical/high severity",
                "warn" if crit > 0 else "ok"
            )

        return self.findings

    def _run_dos_nse_scripts(self):
        """Run DoS-related NSE scripts."""
        print_subsection("DoS-Related NSE Scripts")

        open_ports = self.scan_result.get_open_port_numbers()
        if not open_ports:
            print_status("No open ports to check", "warn")
            return

        port_str = ",".join(open_ports)
        script_str = ",".join(DOS_SCRIPTS)

        xml_out = os.path.join(self._tmp_dir, "dos_scripts.xml")
        args = [
            "-sV", "--script", script_str,
            "-p", port_str,
            "-T4",
            "-oX", xml_out,
            self.scan_result.target,
        ]

        rc, stdout, stderr = run_nmap(args, timeout=300)

        if os.path.exists(xml_out):
            parsed = parse_nmap_xml(xml_out)
            self._process_dos_nse(parsed)
        else:
            print_status("DoS NSE scan produced no output", "warn")

    def _process_dos_nse(self, parsed):
        """Extract DoS findings from NSE results."""
        for host in parsed.get("hosts", []):
            for port in host.get("ports", []):
                for script in port.get("scripts", []):
                    output = script.get("output", "").lower()
                    if any(kw in output for kw in [
                        "vulnerable", "likely", "state: vulnerable",
                        "not safe", "affected", "dos",
                    ]):
                        cves = extract_cves(script.get("output", ""))
                        self.findings.append(VulnFinding(
                            title=f"DoS: {script['id']}",
                            severity="HIGH",
                            source="nse-dos",
                            details=script.get("output", "").strip(),
                            cve=cves,
                            port=port.get("port_id"),
                            service=port.get("service", {}).get("name"),
                        ))

            # Host-level scripts
            for script in host.get("scripts", []):
                output = script.get("output", "").lower()
                if any(kw in output for kw in ["vulnerable", "dos", "affected"]):
                    cves = extract_cves(script.get("output", ""))
                    self.findings.append(VulnFinding(
                        title=f"DoS: {script['id']}",
                        severity="HIGH",
                        source="nse-dos",
                        details=script.get("output", "").strip(),
                        cve=cves,
                    ))

        count = sum(1 for f in self.findings if f.source == "nse-dos")
        print_status(f"NSE DoS scripts found {count} issue(s)", "ok")

    def _check_amplification_services(self):
        """Check for services susceptible to amplification attacks."""
        print_subsection("Amplification / Reflection Risk")

        for port in self.scan_result.all_ports:
            if port.get("state") != "open":
                continue

            svc_name = port.get("service", {}).get("name", "").lower()
            port_id = port.get("port_id", "")

            for key, info in AMPLIFICATION_SERVICES.items():
                if key in svc_name or svc_name == key:
                    self.findings.append(VulnFinding(
                        title=f"DoS: {info['issue']}",
                        severity=info["severity"],
                        source="amplification-check",
                        details=f"{info['desc']} (port {port_id})",
                        port=port_id,
                        service=info["name"],
                    ))
                    print_status(
                        f"Amplification risk: {Colors.YELLOW}{info['name']}{Colors.RESET} "
                        f"on port {port_id}",
                        "warn"
                    )

    def _searchsploit_dos(self):
        """Search ExploitDB specifically for DoS exploits."""
        print_subsection("ExploitDB DoS Exploit Search")

        services = self.scan_result.all_services
        if not services:
            print_status("No services to query", "warn")
            return

        queried = set()
        dos_count = 0

        for svc in services:
            query = get_service_string(svc)
            if not query or query in queried or len(query) < 3:
                continue
            queried.add(query)

            # Search for DoS-specific exploits
            dos_query = f"{query} denial of service"
            results = run_searchsploit(dos_query)

            for exp in results:
                title_lower = exp["title"].lower()
                if any(kw in title_lower for kw in DOS_CVE_KEYWORDS):
                    dos_count += 1
                    cves = extract_cves(exp["title"])

                    severity = "MEDIUM"
                    if any(kw in title_lower for kw in [
                        "remote", "unauthenticated", "crash", "critical"
                    ]):
                        severity = "HIGH"

                    self.findings.append(VulnFinding(
                        title=f"DoS Exploit: {exp['title']}",
                        severity=severity,
                        source="searchsploit-dos",
                        details=f"Path: {exp['path']}\nService: {query}",
                        cve=cves,
                        port=svc.get("port", ""),
                        service=query,
                    ))

        print_status(f"Found {dos_count} DoS-related exploit(s)", "ok")

    def _analyze_dos_surface(self):
        """Analyze the attack surface for DoS susceptibility."""
        print_subsection("DoS Attack Surface Analysis")

        # Check for high port count (larger attack surface)
        open_count = self.scan_result.open_port_count
        if open_count > 20:
            self.findings.append(VulnFinding(
                title="Large Attack Surface",
                severity="MEDIUM",
                source="dos-analysis",
                details=f"{open_count} open ports detected — large attack surface "
                        f"increases DoS risk",
            ))

        # Check for web servers (HTTP flood susceptibility)
        for port in self.scan_result.all_ports:
            if port.get("state") != "open":
                continue
            svc = port.get("service", {})
            name = svc.get("name", "").lower()

            if name in ("http", "https", "http-proxy"):
                product = svc.get("product", "")
                self.findings.append(VulnFinding(
                    title="HTTP Flood Susceptibility",
                    severity="LOW",
                    source="dos-analysis",
                    details=f"Web service {product} on port {port['port_id']} "
                            f"is inherently susceptible to HTTP flood attacks. "
                            f"Ensure rate limiting and WAF are configured.",
                    port=port["port_id"],
                    service=name,
                ))
                break  # Only flag once for web

        # Check for SSL/TLS (renegotiation attack surface)
        for port in self.scan_result.all_ports:
            if port.get("state") != "open":
                continue
            svc = port.get("service", {})
            if svc.get("tunnel") == "ssl" or svc.get("name", "").lower() == "https":
                self.findings.append(VulnFinding(
                    title="SSL/TLS Renegotiation DoS Risk",
                    severity="LOW",
                    source="dos-analysis",
                    details=f"SSL/TLS service on port {port['port_id']} may be "
                            f"susceptible to renegotiation-based DoS if "
                            f"client-initiated renegotiation is enabled.",
                    port=port["port_id"],
                    service="ssl",
                ))
                break

        count = sum(1 for f in self.findings if f.source == "dos-analysis")
        print_status(f"Attack surface analysis flagged {count} concern(s)", "ok")

    def cleanup(self):
        """Remove temp files."""
        import shutil
        try:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
        except Exception:
            pass
