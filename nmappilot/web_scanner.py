"""NmapPilot — Web-adapted scan orchestrator.

Wraps the existing CLI scanning pipeline for use by the web GUI,
capturing output and emitting progress via callbacks instead of printing.
"""

import io
import os
import sys
import json
import threading
import tempfile
import traceback
from datetime import datetime

from nmappilot.scanner import Scanner, ScanResult, SCAN_PHASES
from nmappilot.analyzer import VulnerabilityAnalyzer
from nmappilot.dos_checker import DoSChecker
from nmappilot.target import validate_target


# ═══════════════════════════════════════════════════════════════════════
#  Scan State
# ═══════════════════════════════════════════════════════════════════════

class ScanState:
    """Thread-safe scan state manager."""

    IDLE = "idle"
    VALIDATING = "validating"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    ERROR = "error"

    def __init__(self):
        self._lock = threading.Lock()
        self.status = self.IDLE
        self.phase = 0
        self.total_phases = 4
        self.progress = 0.0
        self.current_task = ""
        self.target_info = None
        self.scan_result = None
        self.vuln_findings = []
        self.dos_findings = []
        self.exploits = []
        self.output_lines = []
        self.error_message = None
        self.start_time = None
        self.end_time = None

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def to_dict(self):
        with self._lock:
            result_data = None
            if self.scan_result:
                result_data = self._serialize_scan_result(self.scan_result)

            return {
                "status": self.status,
                "phase": self.phase,
                "total_phases": self.total_phases,
                "progress": self.progress,
                "current_task": self.current_task,
                "target_info": self.target_info,
                "scan_result": result_data,
                "vuln_findings": [self._serialize_finding(f) for f in self.vuln_findings],
                "dos_findings": [self._serialize_finding(f) for f in self.dos_findings],
                "exploits": [self._serialize_exploit(e) for e in self.exploits],
                "error_message": self.error_message,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
            }

    @staticmethod
    def _serialize_scan_result(sr):
        return {
            "target": sr.target,
            "phases_run": sr.phases_run,
            "open_port_count": sr.open_port_count,
            "scan_duration": sr.scan_duration,
            "all_ports": sr.all_ports,
            "all_services": sr.all_services,
            "os_matches": sr.os_matches,
            "host_scripts": sr.host_scripts,
        }

    @staticmethod
    def _serialize_finding(f):
        return {
            "title": f.title,
            "severity": f.severity,
            "source": f.source,
            "details": f.details,
            "cve": f.cve,
            "port": f.port,
            "service": f.service,
        }

    @staticmethod
    def _serialize_exploit(e):
        return {
            "title": e.title,
            "path": e.path,
            "exploit_type": e.exploit_type,
            "platform": e.platform,
            "service": e.service,
            "port": e.port,
        }


# ═══════════════════════════════════════════════════════════════════════
#  Output Capture
# ═══════════════════════════════════════════════════════════════════════

class OutputCapture:
    """Captures stdout/stderr and forwards to a callback."""

    def __init__(self, callback=None, original=None):
        self.callback = callback
        self.original = original or sys.stdout
        self.buffer = []

    def write(self, text):
        if text.strip():
            self.buffer.append(text)
            if self.callback:
                # Strip ANSI codes for web display
                import re
                clean = re.sub(r'\033\[[0-9;]*m', '', text)
                self.callback(clean)
        self.original.write(text)

    def flush(self):
        self.original.flush()


# ═══════════════════════════════════════════════════════════════════════
#  Web Scanner
# ═══════════════════════════════════════════════════════════════════════

class WebScanner:
    """Runs NmapPilot scans in a background thread for the web GUI."""

    def __init__(self, emit_fn=None):
        self.state = ScanState()
        self.emit = emit_fn or (lambda event, data: None)
        self._thread = None

    @property
    def is_running(self):
        return self.state.status in (ScanState.VALIDATING, ScanState.SCANNING, ScanState.ANALYZING)

    def start_scan(self, target, max_phase=2, no_vuln=False, no_dos=False, ports=None):
        """Start a scan in a background thread."""
        if self.is_running:
            return {"error": "A scan is already running"}

        self.state = ScanState()
        self.state.update(
            status=ScanState.VALIDATING,
            start_time=datetime.now(),
            total_phases=max_phase,
            current_task=f"Validating target: {target}",
        )
        self._emit_state()

        self._thread = threading.Thread(
            target=self._run_scan,
            args=(target, max_phase, no_vuln, no_dos, ports),
            daemon=True,
        )
        self._thread.start()
        return {"status": "started", "target": target}

    def _emit_state(self):
        """Emit current state via WebSocket."""
        self.emit("scan_progress", self.state.to_dict())

    def _emit_output(self, line):
        """Emit a line of scan output."""
        self.state.output_lines.append(line)
        self.emit("scan_output", {"line": line})

    def _run_scan(self, target, max_phase, no_vuln, no_dos, ports):
        """Background scan execution."""
        # Capture stdout
        capture = OutputCapture(callback=self._emit_output, original=sys.stdout)
        old_stdout = sys.stdout

        try:
            # ── Validate target ──
            self._emit_output(f"⟳ Validating target: {target}")
            target_info = validate_target(target)

            if not target_info["is_valid"]:
                self.state.update(
                    status=ScanState.ERROR,
                    error_message=f"Invalid target: {target_info.get('error', 'Unknown error')}",
                    end_time=datetime.now(),
                )
                self._emit_state()
                return

            self.state.update(
                target_info=target_info,
                current_task="Target validated — starting scan",
            )
            self._emit_output(f"✔ Target resolved: {target_info['hostname']} ({target_info['ip']})")
            self._emit_state()

            # ── Phase 1: Scanning ──
            self.state.update(
                status=ScanState.SCANNING,
                current_task="Running progressive scan",
            )
            self._emit_state()

            sys.stdout = capture

            scanner = Scanner(
                target_ip=target_info["ip"],
                target_hostname=target_info["hostname"],
                max_phase=max_phase - 1,  # 0-indexed
            )

            try:
                scan_result = scanner.run()
            except Exception as e:
                self.state.update(
                    status=ScanState.ERROR,
                    error_message=f"Scanning failed: {str(e)}",
                    end_time=datetime.now(),
                )
                self._emit_state()
                scanner.cleanup()
                return

            sys.stdout = old_stdout

            self.state.update(
                scan_result=scan_result,
                current_task=f"Scan complete — {scan_result.open_port_count} open ports found",
                progress=50.0,
            )
            self._emit_output(f"✔ Scan complete: {scan_result.open_port_count} open ports, "
                            f"{len(scan_result.all_services)} services detected")
            self._emit_state()

            # ── Phase 2: Vulnerability Analysis ──
            vuln_findings = []
            exploits = []
            if not no_vuln and scan_result.open_port_count > 0:
                self.state.update(
                    status=ScanState.ANALYZING,
                    current_task="Running vulnerability analysis",
                    progress=60.0,
                )
                self._emit_state()

                sys.stdout = capture
                analyzer = VulnerabilityAnalyzer(scan_result)
                try:
                    vuln_findings, exploits = analyzer.run()
                except Exception as e:
                    self._emit_output(f"⚠ Vulnerability analysis error: {e}")
                finally:
                    analyzer.cleanup()
                sys.stdout = old_stdout

                self.state.update(
                    vuln_findings=vuln_findings,
                    exploits=exploits,
                    progress=75.0,
                    current_task=f"Vuln analysis: {len(vuln_findings)} findings",
                )
                self._emit_state()

            # ── Phase 3: DoS Assessment ──
            dos_findings = []
            if not no_dos and scan_result.open_port_count > 0:
                self.state.update(
                    current_task="Running DoS vulnerability assessment",
                    progress=80.0,
                )
                self._emit_state()

                sys.stdout = capture
                dos_checker = DoSChecker(scan_result)
                try:
                    dos_findings = dos_checker.run()
                except Exception as e:
                    self._emit_output(f"⚠ DoS assessment error: {e}")
                finally:
                    dos_checker.cleanup()
                sys.stdout = old_stdout

                self.state.update(dos_findings=dos_findings, progress=90.0)

            # ── Complete ──
            scanner.cleanup()
            self.state.update(
                status=ScanState.COMPLETE,
                progress=100.0,
                current_task="Scan complete",
                end_time=datetime.now(),
            )
            self._emit_output("✔ All scan phases complete!")
            self._emit_state()

        except Exception as e:
            sys.stdout = old_stdout
            self.state.update(
                status=ScanState.ERROR,
                error_message=f"Unexpected error: {str(e)}\n{traceback.format_exc()}",
                end_time=datetime.now(),
            )
            self._emit_state()

    def get_results_for_ai(self) -> dict:
        """Get scan results formatted for AI analysis."""
        data = self.state.to_dict()
        # Slim down for AI context
        return {
            "target": data.get("target_info"),
            "scan_result": data.get("scan_result"),
            "vuln_findings": data.get("vuln_findings", [])[:20],
            "dos_findings": data.get("dos_findings", [])[:10],
            "exploits": data.get("exploits", [])[:10],
        }
