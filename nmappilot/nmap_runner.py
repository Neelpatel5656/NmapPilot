"""NmapPilot — Nmap PTY subprocess execution and searchsploit queries."""

import os
import re
import sys
import time
import threading
import subprocess

from nmappilot.colors import Colors


# ═══════════════════════════════════════════════════════════════════════
#  run_nmap — execute nmap inside a PTY for live progress
# ═══════════════════════════════════════════════════════════════════════

def run_nmap(args, timeout=600):
    """Run nmap with given arguments, showing live progress via PTY.

    Parameters
    ----------
    args : list[str]
        Nmap arguments (without the "nmap" binary itself).
    timeout : int
        Maximum seconds before killing the process.

    Returns
    -------
    tuple
        (return_code, stdout, stderr)
    """
    # Inject --stats-every so nmap publishes periodic progress lines
    if "--stats-every" not in " ".join(args):
        args = args + ["--stats-every", "5s"]

    cmd = ["nmap"] + args
    R = Colors.RESET

    # ── Open a PTY so nmap thinks it has an interactive terminal ──
    try:
        import pty
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            cmd,
            stdin=slave,
            stdout=slave,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        os.close(slave)
    except FileNotFoundError:
        print(f"  {Colors.RED}[✘]{R} nmap not found! Please install nmap.")
        return -1, "", "nmap not found"
    except Exception as e:
        print(f"  {Colors.RED}[✘]{R} Error starting nmap: {e}")
        return -1, "", str(e)

    # ── Shared state ──
    progress_state = {
        "percent": 0.0,
        "task": "Initializing",
        "done": False,
        "etc": "",
    }
    stdout_lines = []
    stderr_lines = []

    # ── Regex patterns for progress parsing ──
    pct_re = re.compile(r'About (\d+\.?\d*)% done')
    task_re = re.compile(r'undergoing (.+? Scan|.+? resolution)')
    etc_re = re.compile(r'ETC: \S+ \((.+?) remaining\)')

    # ── Background thread: read PTY output ──
    def read_output():
        buf = ""
        while not progress_state["done"]:
            try:
                data = os.read(master, 1024).decode("utf-8", errors="replace")
                if not data:
                    break
                buf += data

                while "\n" in buf or "\r" in buf:
                    idx_n = buf.find("\n")
                    idx_r = buf.find("\r")
                    if idx_n != -1 and idx_r != -1:
                        idx = min(idx_n, idx_r)
                    else:
                        idx = max(idx_n, idx_r)
                    line = buf[:idx]
                    buf = buf[idx + 1:]

                    if line.strip():
                        stdout_lines.append(line + "\n")
                        m = pct_re.search(line)
                        if m:
                            progress_state["percent"] = float(m.group(1))
                        m = task_re.search(line)
                        if m:
                            progress_state["task"] = m.group(1).strip()
                        m = etc_re.search(line)
                        if m:
                            progress_state["etc"] = m.group(1).strip()
            except (OSError, EOFError):
                break
        progress_state["done"] = True

    # ── Background thread: read stderr ──
    def read_stderr():
        for line in proc.stderr:
            stderr_lines.append(line)

    # ── Background thread: forward Enter key to PTY ──
    def wait_for_input():
        import select
        while not progress_state["done"]:
            try:
                r, _, _ = select.select([sys.stdin], [], [], 0.5)
                if r:
                    sys.stdin.readline()
                    os.write(master, b"\n")
                    input_state["pressed"] = True
            except (EOFError, KeyboardInterrupt, OSError):
                break

    input_state = {"pressed": False}

    out_thread = threading.Thread(target=read_output, daemon=True)
    err_thread = threading.Thread(target=read_stderr, daemon=True)
    inp_thread = threading.Thread(target=wait_for_input, daemon=True)
    out_thread.start()
    err_thread.start()
    inp_thread.start()

    start_time = time.time()

    try:
        while proc.poll() is None:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                proc.kill()
                print(f"  {Colors.YELLOW}[⚠]{R} Timed out after {timeout}s")
                return -1, "", "Timeout"

            if input_state["pressed"]:
                input_state["pressed"] = False
                pct = progress_state["percent"]
                task = progress_state["task"]
                bar_len = 25
                filled = int(bar_len * pct / 100)
                bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
                mins, secs = divmod(int(elapsed), 60)
                time_str = f"{mins:02d}:{secs:02d}"
                print(
                    f"  {Colors.CYAN}[{bar}]{R} "
                    f"{pct:5.1f}% "
                    f"{Colors.DIM}│ {time_str} │ {task}{R}"
                )

            time.sleep(0.1)
    except KeyboardInterrupt:
        proc.kill()
        raise

    # ── Cleanup ──
    progress_state["done"] = True
    out_thread.join(timeout=2)
    err_thread.join(timeout=2)
    try:
        os.close(master)
    except OSError:
        pass

    return proc.returncode, "".join(stdout_lines), "".join(stderr_lines)


# ═══════════════════════════════════════════════════════════════════════
#  run_searchsploit — query ExploitDB
# ═══════════════════════════════════════════════════════════════════════

def run_searchsploit(query, timeout=30):
    """Run searchsploit and return structured results.

    Returns
    -------
    list[dict]
        Each dict has keys: title, path, type, platform
    """
    results = []
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            try:
                data = json.loads(proc.stdout)
                for exp in data.get("RESULTS_EXPLOIT", []):
                    results.append({
                        "title": exp.get("Title", "Unknown"),
                        "path": exp.get("Path", ""),
                        "type": exp.get("Type", ""),
                        "platform": exp.get("Platform", ""),
                    })
            except (json.JSONDecodeError, KeyError):
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return results
