"""Vulnerability analysis engine — NSE scripts + ExploitDB integration."""

import os
import re
import tempfile
from nmappilot.colors import Colors
from nmappilot.ui import print_status, print_section, print_subsection
from nmappilot.nmap_runner import run_nmap, run_searchsploit
from nmappilot.xml_parser import parse_nmap_xml, get_service_string


# ─────────── Known vulnerability NSE scripts ───────────────────────

VULN_SCRIPT_CATEGORIES = [
    "vuln",
    "exploit",
    "auth",
]

SPECIFIC_VULN_SCRIPTS = [
    "http-vuln-*",
    "smb-vuln-*",
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-dh-params",
    "ssl-ccs-injection",
    "samba-vuln-cve-2012-1182",
    "http-shellshock",
    "http-sql-injection",
    "http-csrf",
    "http-stored-xss",
    "http-dombased-xss",
    "http-phpself-xss",
    "http-xssed",
    "http-enum",
    "http-methods",
    "http-auth",
    "http-auth-finder",
    "http-config-backup",
    "http-backup-finder",
    "http-default-accounts",
    "http-headers",
    "http-security-headers",
    "http-cookie-flags",
    "http-cors",
    "http-open-redirect",
    "ftp-anon",
    "ftp-vsftpd-backdoor",
    "ftp-proftpd-backdoor",
    "ssh-auth-methods",
    "mysql-vuln-cve2012-2122",
    "mysql-empty-password",
    "ms-sql-info",
    "smtp-vuln-cve2010-4344",
    "smtp-vuln-cve2011-1720",
    "smtp-vuln-cve2011-1764",
    "smtp-open-relay",
]


class VulnFinding:
    """Represents a single vulnerability finding."""

    def __init__(self, title, severity, source, details="", cve=None, port=None, service=None):
        self.title = title
        self.severity = severity      # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.source = source          # "nse", "searchsploit", "analysis"
        self.details = details
        self.cve = cve or []
        self.port = port
        self.service = service

    def __repr__(self):
        return f"<VulnFinding: {self.severity} - {self.title}>"


class ExploitMatch:
    """Represents an ExploitDB match."""

    def __init__(self, title, path, exploit_type, platform, service, port):
        self.title = title
        self.path = path
        self.exploit_type = exploit_type
        self.platform = platform
        self.service = service
        self.port = port

    def __repr__(self):
        return f"<ExploitMatch: {self.title}>"


# ─────────── CVE Extraction ────────────────────────────────────────

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


def extract_cves(text):
    """Extract unique CVE IDs from text."""
    return list(set(CVE_PATTERN.findall(text.upper())))


# Patterns that indicate the script DIDN'T find anything
NEGATIVE_PATTERNS = [
    "couldn't find any",
    "could not find any",
    "no vulnerable",
    "not vulnerable",
    "no vuln",
    "no csrf",
    "no xss",
    "no sql injection",
    "no stored xss",
    "no dom based xss",
    "no dom-based xss",
    "didn't find any",
    "did not find any",
    "found no ",
    "none found",
    "0 found",
    "no results",
    "safe",
    "is not vulnerable",
    "are not vulnerable",
]

# Scripts that are purely informational and should never be HIGH/MEDIUM
INFO_ONLY_SCRIPTS = {
    "fingerprint-strings",
    "http-server-header",
    "http-title",
    "http-favicon",
    "http-robots.txt",
    "ssl-cert",
    "ssl-date",
    "http-methods",
    "ssh-hostkey",
    "http-headers",
    "banner",
    "http-ntlm-info",
    "nbstat",
    "smb-os-discovery",
    "smb-security-mode",
    "http-generator",
    "http-sitemap-generator",
    "dns-nsid",
    "asn-query",
}


def is_negative_result(output):
    """Check if NSE script output indicates it did NOT find a vulnerability."""
    output_lower = output.lower().strip()
    return any(neg in output_lower for neg in NEGATIVE_PATTERNS)


def classify_severity(script_id, output):
    """Classify vulnerability severity based on NSE script output."""
    output_lower = output.lower()

    # If the script says it didn't find anything, it's INFO
    if is_negative_result(output):
        return "INFO"

    # Info-only scripts are always INFO regardless of content
    if script_id in INFO_ONLY_SCRIPTS:
        return "INFO"

    # Critical indicators — must be confirmed positive
    if any(kw in output_lower for kw in [
        "remote code execution", "rce", "backdoor", "command injection",
        "arbitrary code", "unauthenticated",
    ]):
        # Double-check it's not a negation
        if "state: vulnerable" in output_lower or "is vulnerable" in output_lower:
            return "CRITICAL"
        return "HIGH"

    # High indicators — confirmed vulnerabilities
    if "state: vulnerable" in output_lower or "is vulnerable" in output_lower:
        return "HIGH"

    if any(kw in output_lower for kw in [
        "exploit", "overflow", "injection",
        "authentication bypass", "privilege escalation",
    ]):
        return "HIGH"

    # Medium indicators
    if any(kw in output_lower for kw in [
        "information disclosure",
        "directory listing", "default credentials",
        "weak", "deprecated",
    ]):
        return "MEDIUM"

    # Low indicators
    if any(kw in output_lower for kw in [
        "cookie", "missing", "configuration",
        "open redirect",
    ]):
        return "LOW"

    return "INFO"


# ─────────── Vulnerability Analyzer ────────────────────────────────

class VulnerabilityAnalyzer:
    """Run vulnerability analysis using NSE scripts and ExploitDB."""

    def __init__(self, scan_result):
        self.scan_result = scan_result
        self.findings = []
        self.exploits = []
        self._tmp_dir = tempfile.mkdtemp(prefix="nmappilot_vuln_")

    def run(self):
        """Execute all vulnerability analysis steps."""
        print_section("VULNERABILITY ANALYSIS", "◉")

        self._run_nse_vuln_scan()
        self._run_searchsploit()
        self._analyze_service_configs()

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        total_vulns = len(self.findings)
        crit = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        med = sum(1 for f in self.findings if f.severity == "MEDIUM")

        print()
        print_status(
            f"Analysis complete — "
            f"{Colors.CRITICAL} {crit} CRITICAL {Colors.RESET} "
            f"{Colors.HIGH} {high} HIGH {Colors.RESET} "
            f"{Colors.MEDIUM} {med} MEDIUM {Colors.RESET} "
            f"({total_vulns} total findings)",
            "ok"
        )

        return self.findings, self.exploits

    def _run_nse_vuln_scan(self):
        """Run NSE vulnerability scripts against the target."""
        print_subsection("NSE Vulnerability Scripts")

        open_ports = self.scan_result.get_open_port_numbers()
        if not open_ports:
            print_status("No open ports to scan", "warn")
            return

        port_str = ",".join(open_ports)

        # Build script list
        script_str = ",".join(VULN_SCRIPT_CATEGORIES)

        xml_out = os.path.join(self._tmp_dir, "vuln_scan.xml")
        args = [
            "-sV", "--script", script_str,
            "-p", port_str,
            "-T4",
            "-oX", xml_out,
            self.scan_result.target,
        ]

        rc, stdout, stderr = run_nmap(args, timeout=600)

        if os.path.exists(xml_out):
            parsed = parse_nmap_xml(xml_out)
            self._process_nse_results(parsed)
        else:
            print_status("NSE scan produced no output", "warn")

    def _process_nse_results(self, parsed):
        """Extract vulnerability findings from NSE script results."""
        for host in parsed.get("hosts", []):
            # Port-level scripts
            for port in host.get("ports", []):
                for script in port.get("scripts", []):
                    self._process_script_finding(script, port)

            # Host-level scripts
            for script in host.get("scripts", []):
                self._process_script_finding(script)

    def _process_script_finding(self, script, port=None):
        """Process a single NSE script result into a finding."""
        script_id = script.get("id", "")
        output = script.get("output", "")

        if not output.strip():
            return

        # Skip purely informational outputs
        if output.strip().lower() in ("", "false", "nil"):
            return

        # ---- KEY FIX: Detect negative results ("Couldn't find any...") ----
        negative = is_negative_result(output)

        # Skip entirely if negative result and script is a vuln-check script
        # These are scripts that report "Couldn't find any XSS/CSRF" etc.
        if negative and script_id in (
            "http-csrf", "http-stored-xss", "http-dombased-xss",
            "http-phpself-xss", "http-xssed", "http-sql-injection",
            "http-shellshock", "http-vuln-cve2006-3392",
            "http-vuln-cve2017-5638",
        ):
            return  # Don't report "not found" as a finding at all

        # Skip info-only scripts entirely — they clutter the report
        if script_id in INFO_ONLY_SCRIPTS:
            return

        # Check if this actually reports a confirmed vulnerability
        is_vuln = False
        output_lower = output.lower()
        if not negative:
            is_vuln = any(kw in output_lower for kw in [
                "state: vulnerable", "is vulnerable",
                "likely vulnerable", "potentially vulnerable",
                "not safe", "exploit", "insecure",
                "anonymous", "weak cipher",
            ])

        severity = classify_severity(script_id, output)
        cves = extract_cves(output)

        # Downgrade non-confirmed findings aggressively
        if not is_vuln:
            if severity in ("CRITICAL", "HIGH"):
                severity = "INFO"
            elif severity == "MEDIUM":
                severity = "INFO"

        # If it's a negative result but we still got here, force INFO
        if negative:
            severity = "INFO"

        port_id = port.get("port_id", "") if port else None
        service_name = port.get("service", {}).get("name", "") if port else None

        self.findings.append(VulnFinding(
            title=f"{script_id}",
            severity=severity,
            source="nse",
            details=output.strip(),
            cve=cves,
            port=port_id,
            service=service_name,
        ))

    def _run_searchsploit(self):
        """Query ExploitDB for known exploits matching discovered services."""
        print_subsection("ExploitDB / SearchSploit Lookup")

        services = self.scan_result.all_services
        if not services:
            print_status("No services to query", "warn")
            return

        queried = set()
        for svc in services:
            query = get_service_string(svc)
            if not query or query in queried or len(query) < 3:
                continue
            queried.add(query)

            print_status(f"Searching: {Colors.DIM}{query}{Colors.RESET}", "scan")
            results = run_searchsploit(query)

            for exp in results:
                self.exploits.append(ExploitMatch(
                    title=exp["title"],
                    path=exp["path"],
                    exploit_type=exp["type"],
                    platform=exp["platform"],
                    service=query,
                    port=svc.get("port", ""),
                ))

                # Also create a finding for critical exploits
                severity = "HIGH"
                exp_lower = exp["title"].lower()
                if any(kw in exp_lower for kw in [
                    "remote code", "rce", "buffer overflow",
                    "command execution", "arbitrary",
                ]):
                    severity = "CRITICAL"
                elif any(kw in exp_lower for kw in ["dos", "denial"]):
                    severity = "MEDIUM"
                elif any(kw in exp_lower for kw in ["info", "disclosure"]):
                    severity = "LOW"

                cves = extract_cves(exp["title"])
                self.findings.append(VulnFinding(
                    title=f"ExploitDB: {exp['title']}",
                    severity=severity,
                    source="searchsploit",
                    details=f"Path: {exp['path']}\nType: {exp['type']}\nPlatform: {exp['platform']}",
                    cve=cves,
                    port=svc.get("port", ""),
                    service=query,
                ))

        print_status(f"Found {len(self.exploits)} exploit(s) in ExploitDB", "ok")

    def _analyze_service_configs(self):
        """Analyze service configurations for common misconfigurations."""
        print_subsection("Service Configuration Analysis")

        for port in self.scan_result.all_ports:
            if port.get("state") != "open":
                continue

            svc = port.get("service", {})
            name = svc.get("name", "").lower()
            product = svc.get("product", "").lower()
            version = svc.get("version", "")
            port_id = port.get("port_id", "")

            # FTP anonymous access
            if name == "ftp":
                for script in port.get("scripts", []):
                    if "anon" in script.get("output", "").lower():
                        self.findings.append(VulnFinding(
                            title="FTP Anonymous Access Enabled",
                            severity="HIGH",
                            source="analysis",
                            details="FTP server allows anonymous login",
                            port=port_id,
                            service="ftp",
                        ))

            # Telnet (insecure by design)
            if name == "telnet":
                self.findings.append(VulnFinding(
                    title="Telnet Service Detected",
                    severity="MEDIUM",
                    source="analysis",
                    details="Telnet transmits data in plaintext including credentials",
                    port=port_id,
                    service="telnet",
                ))

            # Unencrypted HTTP
            if name == "http" and svc.get("tunnel", "") != "ssl":
                self.findings.append(VulnFinding(
                    title="Unencrypted HTTP Service",
                    severity="LOW",
                    source="analysis",
                    details="HTTP service without TLS encryption detected",
                    port=port_id,
                    service="http",
                ))

            # MySQL/MSSQL on default ports
            if name in ("mysql", "ms-sql-s", "postgresql"):
                self.findings.append(VulnFinding(
                    title=f"Database Service Exposed ({name})",
                    severity="MEDIUM",
                    source="analysis",
                    details=f"Database service {name} exposed on port {port_id}",
                    port=port_id,
                    service=name,
                ))

            # SMB
            if name in ("microsoft-ds", "netbios-ssn"):
                self.findings.append(VulnFinding(
                    title="SMB Service Exposed",
                    severity="MEDIUM",
                    source="analysis",
                    details=f"SMB/NetBIOS service exposed on port {port_id}",
                    port=port_id,
                    service="smb",
                ))

            # RDP
            if name == "ms-wbt-server" or port_id == "3389":
                self.findings.append(VulnFinding(
                    title="RDP Service Exposed",
                    severity="MEDIUM",
                    source="analysis",
                    details="Remote Desktop Protocol service exposed",
                    port=port_id,
                    service="rdp",
                ))

        count = sum(1 for f in self.findings if f.source == "analysis")
        print_status(f"Configuration analysis found {count} issue(s)", "ok")

    def cleanup(self):
        """Remove temp files."""
        import shutil
        try:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
        except Exception:
            pass
