"""Progressive Nmap scan engine with automatic escalation."""

import os
import tempfile
from nmappilot.colors import Colors
from nmappilot.ui import (
    print_status, print_section,
    phase_header, phase_footer,
)
from nmappilot.nmap_runner import run_nmap
from nmappilot.xml_parser import parse_nmap_xml


# ─────────────── Scan Phase Definitions ─────────────────────────────

SCAN_PHASES = [
    {
        "name": "Quick Discovery",
        "description": "SYN scan · top 1000 ports",
        "args": ["-sS", "-T4", "--top-ports", "1000", "--open"],
        "timeout": 120,
    },
    {
        "name": "Service Detection",
        "description": "Version + script scan on discovered ports",
        "args_template": ["-sV", "-sC", "-T4", "-p{ports}"],
        "timeout": 300,
    },
    {
        "name": "Aggressive Scan",
        "description": "Full port range · OS detection · aggressive mode",
        "args": ["-A", "-T4", "-p-", "--open"],
        "timeout": 600,
    },
    {
        "name": "Comprehensive Scan",
        "description": "Full SYN + version + OS + default scripts",
        "args": ["-sS", "-sV", "-sC", "-O", "-T4", "-p-", "--open"],
        "timeout": 900,
    },
]


class ScanResult:
    """Holds merged results from all scan phases."""

    def __init__(self, target):
        self.target = target
        self.phases_run = []
        self.all_hosts = []
        self.all_ports = []
        self.all_services = []
        self.os_matches = []
        self.host_scripts = []
        self.raw_xmls = []
        self.scan_duration = 0
        self._seen_ports = set()

    def merge(self, parsed, phase_name):
        self.phases_run.append(phase_name)
        for host in parsed.get("hosts", []):
            for port in host.get("ports", []):
                key = (port["port_id"], port["protocol"])
                if key not in self._seen_ports:
                    self._seen_ports.add(key)
                    self.all_ports.append(port)
                else:
                    self._update_port(port)
            for os_match in host.get("os_matches", []):
                if os_match not in self.os_matches:
                    self.os_matches.append(os_match)
            for script in host.get("scripts", []):
                if script not in self.host_scripts:
                    self.host_scripts.append(script)
        self.all_services = self._extract_services()
        elapsed = parsed.get("run_stats", {}).get("elapsed", "0")
        try:
            self.scan_duration += float(elapsed)
        except ValueError:
            pass
        if parsed.get("raw_xml_path"):
            self.raw_xmls.append(parsed["raw_xml_path"])

    def _update_port(self, new_port):
        for existing in self.all_ports:
            if (existing["port_id"] == new_port["port_id"] and
                    existing["protocol"] == new_port["protocol"]):
                if (new_port.get("service", {}).get("product") and
                        not existing.get("service", {}).get("product")):
                    existing["service"] = new_port["service"]
                existing_ids = {s["id"] for s in existing.get("scripts", [])}
                for script in new_port.get("scripts", []):
                    if script["id"] not in existing_ids:
                        existing.setdefault("scripts", []).append(script)
                break

    def _extract_services(self):
        services = []
        for port in self.all_ports:
            if port.get("state") == "open" and port.get("service"):
                svc = port["service"].copy()
                svc["port"] = port["port_id"]
                svc["protocol"] = port["protocol"]
                services.append(svc)
        return services

    @property
    def open_port_count(self):
        return len([p for p in self.all_ports if p.get("state") == "open"])

    @property
    def has_service_versions(self):
        return any(s.get("product") or s.get("version") for s in self.all_services)

    @property
    def has_os_info(self):
        return len(self.os_matches) > 0

    def get_open_port_numbers(self):
        return [p["port_id"] for p in self.all_ports if p.get("state") == "open"]


# ─────────────── Satisfaction Criteria ──────────────────────────────

def is_satisfactory(scan_result, phase_index):
    if phase_index == 0:
        return scan_result.open_port_count >= 3 and scan_result.has_service_versions
    if phase_index == 1:
        return scan_result.has_service_versions and scan_result.open_port_count >= 1
    return True


# ─────────────── Scanner Engine ─────────────────────────────────────

class Scanner:
    """Progressive nmap scanner with automatic escalation."""

    def __init__(self, target_ip, target_hostname=None, max_phase=None):
        self.target_ip = target_ip
        self.target_hostname = target_hostname or target_ip
        self.max_phase = max_phase if max_phase is not None else len(SCAN_PHASES) - 1
        self.result = ScanResult(target_ip)
        self._tmp_dir = tempfile.mkdtemp(prefix="nmappilot_")

    def run(self):
        """Execute progressive scanning. Returns ScanResult."""
        print_section("SCANNING TARGET", "⟳")
        print_status(
            f"Target: {Colors.BOLD}{self.target_hostname}{Colors.RESET} "
            f"({Colors.CYAN}{self.target_ip}{Colors.RESET})",
            "info"
        )
        print_status(f"Max scan phases: {self.max_phase + 1}", "info")

        for i, phase in enumerate(SCAN_PHASES):
            if i > self.max_phase:
                break

            phase_num = i + 1
            total = min(self.max_phase + 1, len(SCAN_PHASES))

            # ── Phase header line ──
            phase_header(phase_num, total, phase["name"], phase["description"])

            # Build args
            args = self._build_args(phase, i)
            xml_out = os.path.join(self._tmp_dir, f"phase_{i}.xml")
            args.extend(["-oX", xml_out])
            args.append(self.target_ip)

            # Show the command
            cmd_str = "nmap " + " ".join(args)
            if len(cmd_str) > 70:
                cmd_str = cmd_str[:67] + "…"
            print_status(
                f"Running: {Colors.DIM}{cmd_str}{Colors.RESET}", "scan"
            )
            print_status(
                f"Press {Colors.BOLD}Enter{Colors.RESET} for live progress…", "info"
            )

            # Run scan
            rc, stdout, stderr = run_nmap(
                args, timeout=phase.get("timeout", 300)
            )

            if rc != 0 and rc != -1:
                print_status(f"Phase {phase_num} returned code {rc}", "warn")
                if stderr.strip():
                    for line in stderr.strip().split('\n')[:2]:
                        print_status(f"{Colors.DIM}{line}{Colors.RESET}", "warn")

            # Parse results
            if os.path.exists(xml_out):
                parsed = parse_nmap_xml(xml_out)
                self.result.merge(parsed, phase["name"])

                svc_count = sum(1 for s in self.result.all_services if s.get("product"))
                print_status(
                    f"Ports: {Colors.GREEN}{self.result.open_port_count}{Colors.RESET}  "
                    f"Services: {Colors.GREEN}{svc_count}{Colors.RESET}  "
                    f"OS: {Colors.GREEN}{len(self.result.os_matches)}{Colors.RESET}",
                    "ok"
                )
            else:
                print_status("No XML output generated", "warn")

            # ── Phase footer line ──
            phase_footer()

            # Check satisfaction
            if is_satisfactory(self.result, i):
                print_status(
                    f"{Colors.GREEN}Sufficient data gathered — "
                    f"skipping remaining phases{Colors.RESET}",
                    "ok"
                )
                break
            elif i < min(self.max_phase, len(SCAN_PHASES) - 1):
                print_status(
                    f"{Colors.YELLOW}Insufficient results — "
                    f"escalating to next phase{Colors.RESET}",
                    "warn"
                )

        print()
        print_status(
            f"Scanning complete — {len(self.result.phases_run)} phase(s) in "
            f"{Colors.BOLD}{self.result.scan_duration:.1f}s{Colors.RESET}",
            "ok"
        )

        return self.result

    def _build_args(self, phase, phase_index):
        if "args_template" in phase:
            open_ports = self.result.get_open_port_numbers()
            if not open_ports:
                return list(phase.get("args", ["-sV", "-sC", "-T4", "--top-ports", "1000"]))
            port_str = ",".join(open_ports)
            return [arg.replace("{ports}", port_str) for arg in phase["args_template"]]
        return list(phase["args"])

    def cleanup(self):
        import shutil
        try:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
        except Exception:
            pass
