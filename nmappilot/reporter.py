"""Rich CLI report generator for NmapPilot."""

import os
import re
import textwrap
from datetime import datetime
from nmappilot import __version__
from nmappilot.colors import Colors, colored, bold, severity_color
from nmappilot.ui import print_section, print_subsection
from nmappilot.helpers import timestamp


# ═══════════════════════════════════════════════════════════════════════
#  Report constants
# ═══════════════════════════════════════════════════════════════════════

HEADER_W = 64          # internal width of report section header boxes
RISK_W = 62            # internal width of the risk summary box


class ReportGenerator:
    """Generate a comprehensive CLI report from scan results."""

    def __init__(self, scan_result, vuln_findings, dos_findings, exploits, target_info):
        self.scan_result = scan_result
        self.vuln_findings = vuln_findings
        self.dos_findings = dos_findings
        self.exploits = exploits
        self.target_info = target_info
        self.report_lines = []

    def generate(self):
        """Generate and display the full report."""
        print_section("COMPREHENSIVE ANALYSIS REPORT", "📋")

        self._section_target_summary()
        self._section_port_table()
        self._section_os_detection()
        self._section_vulnerabilities()
        self._section_dos_assessment()
        self._section_exploitdb()
        self._section_attack_surface()
        self._section_recommendations()
        self._section_footer()

        report_path = self._save_report()
        return report_path

    # ─────────── Report Sections ───────────────────────────────────

    def _section_target_summary(self):
        self._print_and_log("")
        self._header("TARGET SUMMARY")

        rows = [
            ("Hostname",       self.target_info.get("hostname", "N/A")),
            ("IP Address",     self.target_info.get("ip", "N/A")),
            ("Scan Phases",    ", ".join(self.scan_result.phases_run) or "None"),
            ("Total Duration", f"{self.scan_result.scan_duration:.1f}s"),
            ("Open Ports",     str(self.scan_result.open_port_count)),
            ("Services Found", str(len(self.scan_result.all_services))),
            ("OS Matches",     str(len(self.scan_result.os_matches))),
        ]
        for label, value in rows:
            self._kv(label, value)

    def _section_port_table(self):
        self._header("OPEN PORTS & SERVICES")

        open_ports = [p for p in self.scan_result.all_ports if p.get("state") == "open"]
        if not open_ports:
            self._info("No open ports discovered")
            return

        hdr = f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'PRODUCT':<25} {'VERSION':<15} {'EXTRA'}"
        sep = f"  {'─' * 10} {'─' * 10} {'─' * 15} {'─' * 25} {'─' * 15} {'─' * 20}"

        print(f"  {Colors.BOLD}{Colors.CYAN}{hdr.strip()}{Colors.RESET}")
        print(f"  {Colors.GREY}{sep.strip()}{Colors.RESET}")
        self._log(hdr)
        self._log(sep)

        for port in sorted(open_ports, key=lambda p: int(p.get("port_id", 0))):
            pid = f"{port['port_id']}/{port['protocol']}"
            state = port.get("state", "")
            svc = port.get("service", {})
            name = svc.get("name", "")
            product = svc.get("product", "")
            version = svc.get("version", "")
            extra = svc.get("extra_info", "")

            line = f"  {pid:<10} {state:<10} {name:<15} {product:<25} {version:<15} {extra}"

            state_color = Colors.GREEN if state == "open" else Colors.YELLOW
            print(f"  {Colors.BOLD}{pid:<10}{Colors.RESET} "
                  f"{state_color}{state:<10}{Colors.RESET} "
                  f"{Colors.WHITE}{name:<15}{Colors.RESET} "
                  f"{Colors.CYAN}{product:<25}{Colors.RESET} "
                  f"{version:<15} "
                  f"{Colors.DIM}{extra}{Colors.RESET}")
            self._log(line)

        self._print_and_log(f"\n  Total: {len(open_ports)} open port(s)")

    def _section_os_detection(self):
        self._header("OS DETECTION")

        if not self.scan_result.os_matches:
            self._info("No OS fingerprint obtained (may require root/more aggressive scan)")
            return

        for i, os_match in enumerate(self.scan_result.os_matches[:5]):
            name = os_match.get("name", "Unknown")
            accuracy = os_match.get("accuracy", "0")
            try:
                acc_int = int(accuracy)
            except ValueError:
                acc_int = 0

            bar_len = 20
            filled = int(bar_len * acc_int / 100)
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"

            acc_color = (Colors.GREEN if acc_int >= 80
                         else Colors.YELLOW if acc_int >= 50
                         else Colors.RED)
            print(f"  {Colors.BOLD}#{i+1}{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
            print(f"     Accuracy: {acc_color}[{bar}] {accuracy}%{Colors.RESET}")
            self._log(f"  #{i+1} {name} (Accuracy: {accuracy}%)")

            for cls in os_match.get("os_classes", []):
                vendor = cls.get("vendor", "")
                family = cls.get("os_family", "")
                gen = cls.get("os_gen", "")
                if vendor or family:
                    print(f"     {Colors.DIM}{vendor} {family} {gen}{Colors.RESET}")
                    self._log(f"     {vendor} {family} {gen}")
            print()

    def _section_vulnerabilities(self):
        self._header("VULNERABILITY FINDINGS")

        findings = [f for f in self.vuln_findings
                     if f.source not in ("nse-dos", "searchsploit-dos", "dos-analysis", "amplification-check")]

        if not findings:
            self._info("No vulnerabilities detected")
            return

        crit = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        med  = sum(1 for f in findings if f.severity == "MEDIUM")
        low  = sum(1 for f in findings if f.severity == "LOW")
        info = sum(1 for f in findings if f.severity == "INFO")

        print(f"  {Colors.CRITICAL} CRITICAL: {crit} {Colors.RESET}  "
              f"{Colors.HIGH} HIGH: {high} {Colors.RESET}  "
              f"{Colors.MEDIUM} MEDIUM: {med} {Colors.RESET}  "
              f"{Colors.LOW} LOW: {low} {Colors.RESET}  "
              f"{Colors.INFO} INFO: {info} {Colors.RESET}")
        self._log(f"  CRITICAL: {crit}  HIGH: {high}  MEDIUM: {med}  LOW: {low}  INFO: {info}")
        print()

        for i, finding in enumerate(findings):
            self._print_finding(i + 1, finding)

    def _section_dos_assessment(self):
        self._header("DoS VULNERABILITY ASSESSMENT")

        if not self.dos_findings:
            self._info("No DoS vulnerabilities detected")
            return

        crit = sum(1 for f in self.dos_findings if f.severity in ("CRITICAL", "HIGH"))
        print(f"  {Colors.YELLOW}⚠ {crit} critical/high DoS risk(s) detected{Colors.RESET}")
        self._log(f"  {crit} critical/high DoS risk(s) detected")
        print()

        for i, finding in enumerate(self.dos_findings):
            self._print_finding(i + 1, finding)

    def _section_exploitdb(self):
        self._header("EXPLOITDB MATCHES")

        if not self.exploits:
            self._info("No known exploits found in ExploitDB")
            return

        self._print_and_log(f"  Found {len(self.exploits)} exploit(s):\n")

        for i, exp in enumerate(self.exploits):
            print(f"  {Colors.RED}{Colors.BOLD}[{i+1}]{Colors.RESET} "
                  f"{Colors.WHITE}{exp.title}{Colors.RESET}")
            print(f"      Service: {Colors.CYAN}{exp.service}{Colors.RESET} "
                  f"(Port {exp.port})")
            print(f"      Type: {exp.exploit_type}  │  Platform: {exp.platform}")
            print(f"      Path: {Colors.DIM}{exp.path}{Colors.RESET}")
            print()

            self._log(f"  [{i+1}] {exp.title}")
            self._log(f"      Service: {exp.service} (Port {exp.port})")
            self._log(f"      Type: {exp.exploit_type}  |  Platform: {exp.platform}")
            self._log(f"      Path: {exp.path}")
            self._log("")

    def _section_attack_surface(self):
        self._header("ATTACK SURFACE SUMMARY")

        all_findings = self.vuln_findings + self.dos_findings
        crit = sum(1 for f in all_findings if f.severity == "CRITICAL")
        high = sum(1 for f in all_findings if f.severity == "HIGH")
        med  = sum(1 for f in all_findings if f.severity == "MEDIUM")

        if crit > 0:
            risk, risk_color = "CRITICAL", Colors.CRITICAL
            risk_msg = "Target has CRITICAL vulnerabilities requiring immediate attention"
        elif high > 0:
            risk, risk_color = "HIGH", Colors.HIGH
            risk_msg = "Target has HIGH severity vulnerabilities that should be addressed"
        elif med > 2:
            risk, risk_color = "MEDIUM", Colors.MEDIUM
            risk_msg = "Target has moderate security concerns that should be reviewed"
        elif med > 0:
            risk, risk_color = "LOW", Colors.GREEN
            risk_msg = "Minor security concerns detected, generally acceptable risk"
        else:
            risk, risk_color = "LOW", Colors.GREEN
            risk_msg = "No significant vulnerabilities detected"

        # ── Risk summary box (fixed alignment) ──
        W = RISK_W
        risk_badge = f"{risk_color} {risk:^12} {Colors.RESET}"
        open_p = self.scan_result.open_port_count
        total_f = len(all_findings)
        exploit_m = len(self.exploits)
        phases = len(self.scan_result.phases_run)

        print(f"  ┌{'─' * W}┐")
        print(f"  │{' ' * W}│")
        print(f"  │   Overall Risk Level: {risk_badge}{' ' * (W - 39)}│")
        print(f"  │{' ' * W}│")
        print(f"  │   {risk_msg:<{W - 4}}│")
        print(f"  │{' ' * W}│")
        print(f"  │   Open Ports:      {str(open_p):<{W - 24}}│")
        print(f"  │   Total Findings:  {str(total_f):<{W - 24}}│")
        print(f"  │   Exploit Matches: {str(exploit_m):<{W - 24}}│")
        print(f"  │   Scan Phases:     {str(phases):<{W - 24}}│")
        print(f"  │{' ' * W}│")
        print(f"  └{'─' * W}┘")

        self._log(f"  Overall Risk Level: {risk}")
        self._log(f"  {risk_msg}")
        self._log(f"  Open Ports: {open_p}")
        self._log(f"  Total Findings: {total_f}")
        self._log(f"  Exploit Matches: {exploit_m}")

        # Attack vectors
        self._print_and_log("")
        print(f"  {Colors.BOLD}Attack Vectors:{Colors.RESET}")
        self._log("  Attack Vectors:")

        vectors = []
        svc_names = set(s.get("name", "").lower() for s in self.scan_result.all_services)

        if "http" in svc_names or "https" in svc_names:
            vectors.append("Web Application (HTTP/HTTPS)")
        if "ssh" in svc_names:
            vectors.append("Remote Access (SSH)")
        if "ftp" in svc_names:
            vectors.append("File Transfer (FTP)")
        if "smtp" in svc_names or "pop3" in svc_names or "imap" in svc_names:
            vectors.append("Email Services (SMTP/POP3/IMAP)")
        if any(n in svc_names for n in ["mysql", "ms-sql-s", "postgresql", "oracle"]):
            vectors.append("Database Services")
        if "microsoft-ds" in svc_names or "netbios-ssn" in svc_names:
            vectors.append("Windows Networking (SMB/NetBIOS)")
        if "domain" in svc_names:
            vectors.append("DNS Services")
        dos_real = sum(1 for f in self.dos_findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM"))
        if dos_real > 0:
            vectors.append("Denial of Service (DoS)")

        for v in vectors:
            print(f"    {Colors.YELLOW}►{Colors.RESET} {v}")
            self._log(f"    ► {v}")

        if not vectors:
            self._info("Minimal attack surface detected")

    def _section_recommendations(self):
        self._header("RECOMMENDATIONS")

        all_findings = self.vuln_findings + self.dos_findings
        recs = []

        severities = set(f.severity for f in all_findings)
        if "CRITICAL" in severities:
            recs.append(("URGENT", "Address all CRITICAL vulnerabilities immediately — "
                         "these may allow remote code execution or full system compromise"))
        if "HIGH" in severities:
            recs.append(("HIGH", "Patch or mitigate HIGH severity vulnerabilities — "
                         "these present significant security risks"))

        service_names = set()
        for f in all_findings:
            if f.service:
                service_names.add(f.service.lower())

        if "ftp" in service_names:
            recs.append(("MEDIUM", "Disable FTP and use SFTP/SCP instead for secure file transfer"))
        if "telnet" in service_names:
            recs.append(("HIGH", "Disable Telnet service — use SSH for secure remote access"))
        if "http" in service_names:
            recs.append(("MEDIUM", "Implement HTTPS with valid TLS certificate, "
                         "configure security headers (HSTS, CSP, X-Frame-Options)"))
        if any("amplification" in f.title.lower() for f in all_findings):
            recs.append(("HIGH", "Restrict or disable services susceptible to amplification "
                         "attacks (DNS, NTP, SNMP, memcached)"))
        if self.exploits:
            recs.append(("HIGH", f"Update vulnerable software — known public exploits exist "
                         f"({len(self.exploits)} matches in ExploitDB)"))

        recs.append(("INFO", "Implement a Web Application Firewall (WAF) for HTTP services"))
        recs.append(("INFO", "Enable rate limiting on all public-facing services"))
        recs.append(("INFO", "Regularly update all software and apply security patches"))
        recs.append(("INFO", "Implement network segmentation and principle of least privilege"))

        for priority, rec in recs:
            p_color = severity_color(priority)
            print(f"  {p_color}[{priority}]{Colors.RESET} {rec}")
            self._log(f"  [{priority}] {rec}")
            print()

    def _section_footer(self):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print()
        print(f"  {Colors.CYAN}{'═' * HEADER_W}{Colors.RESET}")
        print(f"  {Colors.DIM}Report generated by NmapPilot v{__version__}{Colors.RESET}")
        print(f"  {Colors.DIM}{now_str}{Colors.RESET}")
        print(f"  {Colors.CYAN}{'═' * HEADER_W}{Colors.RESET}")
        print()

        self._log(f"  Report generated by NmapPilot v{__version__}")
        self._log(f"  {now_str}")

    # ─────────── Helpers ───────────────────────────────────────────

    def _header(self, title):
        print()
        print(f"  {Colors.BOLD}{Colors.CYAN}╭{'─' * HEADER_W}╮{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.CYAN}│  {title:<{HEADER_W - 2}}│{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.CYAN}╰{'─' * HEADER_W}╯{Colors.RESET}")
        print()
        self._log(f"  ╭{'─' * HEADER_W}╮")
        self._log(f"  │  {title:<{HEADER_W - 2}}│")
        self._log(f"  ╰{'─' * HEADER_W}╯")
        self._log("")

    def _kv(self, key, value):
        print(f"  {Colors.BOLD}{key + ':':<20}{Colors.RESET} {Colors.WHITE}{value}{Colors.RESET}")
        self._log(f"  {key + ':':<20} {value}")

    def _info(self, msg):
        print(f"  {Colors.DIM}ℹ {msg}{Colors.RESET}")
        self._log(f"  ℹ {msg}")

    def _print_finding(self, num, finding):
        sev_color = severity_color(finding.severity)

        print(f"  {sev_color}[{finding.severity}]{Colors.RESET} "
              f"{Colors.BOLD}#{num}{Colors.RESET} — "
              f"{Colors.WHITE}{finding.title}{Colors.RESET}")

        if finding.port:
            print(f"    Port: {Colors.CYAN}{finding.port}{Colors.RESET}"
                  f"  Service: {Colors.CYAN}{finding.service or 'N/A'}{Colors.RESET}")

        if finding.cve:
            cve_str = ", ".join(finding.cve[:5])
            print(f"    CVEs: {Colors.RED}{cve_str}{Colors.RESET}")

        if finding.details:
            wrapped = textwrap.fill(finding.details, width=70,
                                     initial_indent="    ",
                                     subsequent_indent="    ")
            print(f"{Colors.DIM}{wrapped}{Colors.RESET}")

        print()

        self._log(f"  [{finding.severity}] #{num} — {finding.title}")
        if finding.port:
            self._log(f"    Port: {finding.port}  Service: {finding.service or 'N/A'}")
        if finding.cve:
            self._log(f"    CVEs: {', '.join(finding.cve[:5])}")
        if finding.details:
            for line in finding.details.split('\n')[:5]:
                self._log(f"    {line}")
        self._log("")

    def _print_and_log(self, text):
        print(text)
        plain = re.sub(r'\033\[[0-9;]*m', '', text)
        self.report_lines.append(plain)

    def _log(self, text):
        self.report_lines.append(text)

    def _save_report(self):
        target_clean = self.target_info.get("original", "target").replace("/", "_").replace(".", "_")
        filename = f"nmappilot_report_{target_clean}_{timestamp()}.txt"

        header = [
            "=" * 70,
            f"  NmapPilot — Comprehensive Analysis Report",
            f"  Target: {self.target_info.get('original', 'N/A')}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
            "",
        ]

        try:
            with open(filename, "w") as f:
                f.write("\n".join(header + self.report_lines))
            print(f"  {Colors.GREEN}[✔]{Colors.RESET} Report saved to: "
                  f"{Colors.BOLD}{os.path.abspath(filename)}{Colors.RESET}")
            return os.path.abspath(filename)
        except IOError as e:
            print(f"  {Colors.RED}[✘]{Colors.RESET} Could not save report: {e}")
            return None
