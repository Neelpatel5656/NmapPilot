"""NmapPilot CLI — main orchestrator and interactive interface."""

import sys
import os
import signal
import argparse
from nmappilot import __version__
from nmappilot.colors import Colors, colored, bold
from nmappilot.ui import print_banner, print_section, print_status
from nmappilot.target import validate_target
from nmappilot.helpers import check_root
from nmappilot.scanner import Scanner
from nmappilot.analyzer import VulnerabilityAnalyzer
from nmappilot.dos_checker import DoSChecker
from nmappilot.reporter import ReportGenerator


# ═══════════════════════════════════════════════════════════════════════
#  Legal Disclaimer
# ═══════════════════════════════════════════════════════════════════════

DISCLAIMER = f"""
  {Colors.YELLOW}{Colors.BOLD}╔═════════════════════════════════════════════════════════════╗
  ║  ⚠  LEGAL DISCLAIMER                                       ║
  ║                                                             ║
  ║  This tool is intended for authorized security testing      ║
  ║  and network administration ONLY. Unauthorized scanning     ║
  ║  of systems you do not own or have explicit permission      ║
  ║  to test is ILLEGAL and may violate local, state, and       ║
  ║  federal laws.                                              ║
  ║                                                             ║
  ║  By using this tool, you confirm that you have proper       ║
  ║  authorization to scan the target system(s).                ║
  ╚═════════════════════════════════════════════════════════════╝{Colors.RESET}
"""


# ═══════════════════════════════════════════════════════════════════════
#  Signal handler
# ═══════════════════════════════════════════════════════════════════════

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print(f"\n\n  {Colors.YELLOW}[!]{Colors.RESET} Scan interrupted by user. Exiting…")
    sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════
#  Argument parser
# ═══════════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="nmappilot",
        description="NmapPilot — Automated Nmap Scanning & Vulnerability Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nmappilot                       Interactive mode
  nmappilot -t scanme.nmap.org    Scan a specific target
  nmappilot -t 192.168.1.1 -m 2  Quick scan (max 2 phases)
  nmappilot --no-dos              Skip DoS assessment
        """,
    )
    parser.add_argument("-t", "--target",
                        help="Target hostname or IP address")
    parser.add_argument("-m", "--max-phase", type=int, default=4,
                        choices=[1, 2, 3, 4],
                        help="Maximum scan phase (1-4, default: 4)")
    parser.add_argument("--no-dos", action="store_true",
                        help="Skip DoS vulnerability assessment")
    parser.add_argument("--no-vuln", action="store_true",
                        help="Skip vulnerability analysis (scan only)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--gui", action="store_true",
                        help="Launch the AI-powered web GUI")
    parser.add_argument("--port", type=int, default=1337,
                        help="Port for the web GUI (default: 1337)")
    parser.add_argument("-v", "--version", action="version",
                        version=f"NmapPilot v{__version__}")
    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════════
#  Interactive helpers
# ═══════════════════════════════════════════════════════════════════════

def get_target_interactive():
    """Prompt user for target in interactive mode."""
    print(f"\n  {Colors.BOLD}Enter target to scan:{Colors.RESET}")
    print(f"  {Colors.DIM}(domain name or IP address){Colors.RESET}\n")

    try:
        target = input(f"  {Colors.CYAN}► {Colors.RESET}Target: ").strip()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {Colors.YELLOW}Cancelled.{Colors.RESET}")
        sys.exit(0)

    if not target:
        print(f"  {Colors.RED}[✘]{Colors.RESET} No target specified. Exiting.")
        sys.exit(1)

    return target


def confirm_target(target_info):
    """Show resolved target info and ask for confirmation."""
    W = 46
    print(f"\n  {Colors.BOLD}Target resolved:{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}┏{'━' * W}┓{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}┃{Colors.RESET}  Hostname:  "
          f"{Colors.WHITE}{target_info['hostname']:<33}{Colors.RESET}"
          f"{Colors.CYAN}{Colors.BOLD}┃{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}┃{Colors.RESET}  IP:        "
          f"{Colors.WHITE}{target_info['ip']:<33}{Colors.RESET}"
          f"{Colors.CYAN}{Colors.BOLD}┃{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}┗{'━' * W}┛{Colors.RESET}")

    try:
        confirm = input(
            f"\n  {Colors.YELLOW}Proceed with scanning? [Y/n]: {Colors.RESET}"
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {Colors.YELLOW}Cancelled.{Colors.RESET}")
        sys.exit(0)

    if confirm in ("n", "no"):
        print(f"  {Colors.YELLOW}Scan cancelled.{Colors.RESET}")
        sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════
#  Main entry point
# ═══════════════════════════════════════════════════════════════════════

def main():
    """Main entry point for NmapPilot."""
    signal.signal(signal.SIGINT, signal_handler)

    args = parse_args()

    # ── GUI mode — launch web interface ──
    if args.gui:
        from nmappilot.web_server import run_server
        print_banner()
        print(f"\n  {Colors.CYAN}{Colors.BOLD}🚀 Launching AI-powered Web GUI...{Colors.RESET}")
        print(f"  {Colors.DIM}Open http://127.0.0.1:{args.port} in your browser{Colors.RESET}\n")
        run_server(host="0.0.0.0", port=args.port)
        return

    # ── Root check — auto-elevate with sudo if not root ──
    if not check_root():
        try:
            # Find the directory containing the 'nmappilot' package
            pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            # Use 'sudo -E env PYTHONPATH=...' to ensure root Python can find our module
            cmd = [
                "sudo", 
                "env", 
                f"PYTHONPATH={pkg_dir}:{os.environ.get('PYTHONPATH', '')}".strip(':'), 
                sys.executable, 
                "-m", 
                "nmappilot"
            ] + sys.argv[1:]
            
            os.execvp("sudo", cmd)
        except Exception as e:
            if args.no_color:
                Colors.disable()
            print_banner()
            print(DISCLAIMER)
            print_status(f"Could not elevate to root automatically: {e}", "error")
            print_status(f"Run manually: sudo nmappilot", "info")
            sys.exit(1)

    if args.no_color:
        Colors.disable()

    # Banner & Disclaimer
    print_banner()
    print(DISCLAIMER)

    # ── Get target ──
    if args.target:
        target = args.target
    else:
        target = get_target_interactive()

    # ── Validate target ──
    print_status(f"Validating target: {Colors.BOLD}{target}{Colors.RESET}", "scan")
    target_info = validate_target(target)

    if not target_info["is_valid"]:
        print_status(f"Invalid target: {target_info['error']}", "error")
        sys.exit(1)

    confirm_target(target_info)

    # ──── Phase 1: Progressive Scanning ────────────────────────────
    scanner = Scanner(
        target_ip=target_info["ip"],
        target_hostname=target_info["hostname"],
        max_phase=args.max_phase - 1,   # 0-indexed
    )

    try:
        scan_result = scanner.run()
    except Exception as e:
        print_status(f"Scanning failed: {e}", "error")
        scanner.cleanup()
        sys.exit(1)

    if scan_result.open_port_count == 0:
        print_status("No open ports found. The host may be firewalled or down.", "warn")
        print_status("Try running with sudo for SYN scan capabilities.", "info")

    # ──── Phase 2: Vulnerability Analysis ──────────────────────────
    vuln_findings = []
    exploits = []
    if not args.no_vuln and scan_result.open_port_count > 0:
        analyzer = VulnerabilityAnalyzer(scan_result)
        try:
            vuln_findings, exploits = analyzer.run()
        except Exception as e:
            print_status(f"Vulnerability analysis error: {e}", "error")
        finally:
            analyzer.cleanup()
    elif args.no_vuln:
        print_section("VULNERABILITY ANALYSIS", "◉")
        print_status("Skipped (--no-vuln flag)", "info")

    # ──── Phase 3: DoS Assessment ──────────────────────────────────
    dos_findings = []
    if not args.no_dos and scan_result.open_port_count > 0:
        dos_checker = DoSChecker(scan_result)
        try:
            dos_findings = dos_checker.run()
        except Exception as e:
            print_status(f"DoS assessment error: {e}", "error")
        finally:
            dos_checker.cleanup()
    elif args.no_dos:
        print_section("DoS VULNERABILITY ASSESSMENT", "◎")
        print_status("Skipped (--no-dos flag)", "info")

    # ──── Phase 4: Report Generation ───────────────────────────────
    reporter = ReportGenerator(
        scan_result=scan_result,
        vuln_findings=vuln_findings,
        dos_findings=dos_findings,
        exploits=exploits,
        target_info=target_info,
    )

    report_path = reporter.generate()

    # Cleanup
    scanner.cleanup()

    # Done
    print(f"\n  {Colors.GREEN}{Colors.BOLD}✔ NmapPilot scan complete!{Colors.RESET}")
    if report_path:
        print(f"  {Colors.DIM}Report file: {report_path}{Colors.RESET}")
    print()


if __name__ == "__main__":
    main()
