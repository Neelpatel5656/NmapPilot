"""NmapPilot — Banner, section headers, and progress display."""

import sys
import re as _re
from nmappilot import __version__
from nmappilot.colors import Colors

_ANSI_RE = _re.compile(r'\033\[[0-9;]*m')


# ═══════════════════════════════════════════════════════════════════════
#  Banner
# ═══════════════════════════════════════════════════════════════════════

def print_banner():
    """Display the NmapPilot launcher banner."""
    C = Colors.CYAN
    B = Colors.BOLD
    W = Colors.WHITE
    D = Colors.DIM
    Y = Colors.YELLOW
    A1 = Colors.ACCENT1
    A2 = Colors.ACCENT2
    R = Colors.RESET

    IW = 62
    bar = "═" * IW

    def row(content):
        visible = len(_ANSI_RE.sub("", content))
        pad = max(IW - visible, 0)
        return f"    {C}{B}║{R}{content}{' ' * pad}{C}{B}║{R}"

    top = f"    {C}{B}╔{bar}╗{R}"
    mid = f"    {C}{B}╠{bar}╣{R}"
    bot = f"    {C}{B}╚{bar}╝{R}"

    ver_str = f"v{__version__}"
    desc = "Automated Nmap Scanning & Vulnerability Analysis"

    # Standard figlet font for "NmapPilot"
    lines = [
        "",
        top,
        row(""),
        row(f"   {A1} _   _                       {A2}____  _ _       _   {R}"),
        row(f"   {A1}| \\ | |_ __ ___   __ _ _ __ {A2}|  _ \\(_) | ___ | |_ {R}"),
        row(f"   {A1}|  \\| | '_ ` _ \\ / _` | '_ \\{A2}| |_) | | |/ _ \\| __|{R}"),
        row(f"   {A1}| |\\  | | | | | | (_| | |_) {A2}|  __/| | | (_) | |_ {R}"),
        row(f"   {A1}|_| \\_|_| |_| |_|\\__,_| .__/{A2}|_|   |_|_|\\___/ \\__|{R}"),
        row(f"   {A1}                       |_|   {R}                      "),
        row(""),
        row(f"  {W}{desc}{R}"),
        mid,
        row(f"  {D}Version : {W}{ver_str}{R}"),
        row(f"  {D}Author  : {Y}Neel Patel{R}"),
        row(f"  {D}GitHub  : {Y}github.com/Neelpatel5656{R}"),
        bot,
        "",
    ]

    print("\n".join(lines))


# ═══════════════════════════════════════════════════════════════════════
#  Section / subsection headers
# ═══════════════════════════════════════════════════════════════════════

SECTION_W = 62          # visible inner width of section headers


def print_section(title, icon="═"):
    """Print a major section header."""
    C = Colors.CYAN
    B = Colors.BOLD
    R = Colors.RESET
    W = Colors.WHITE
    bar = "━" * SECTION_W
    print()
    print(f"  {C}{B}┏{bar}┓{R}")
    inner = f"  {icon}  {title}"
    pad = SECTION_W - len(inner)
    print(f"  {C}{B}┃{R}{W}{B}{inner}{' ' * pad}{R}{C}{B}┃{R}")
    print(f"  {C}{B}┗{bar}┛{R}")
    print()


def print_subsection(title):
    """Print a subsection header."""
    D = Colors.DIM
    Y = Colors.YELLOW
    B = Colors.BOLD
    R = Colors.RESET
    print(f"\n  {Y}{B}  ▸ {title}{R}")
    print(f"  {D}  {'─' * 50}{R}")


# ═══════════════════════════════════════════════════════════════════════
#  Phase header / footer (simple line style, no box)
# ═══════════════════════════════════════════════════════════════════════

PHASE_W = 60            # width of phase separator lines


def phase_header(phase_num, total, name, description):
    """Print a phase header line with title and description."""
    M = Colors.MAGENTA
    B = Colors.BOLD
    D = Colors.DIM
    R = Colors.RESET

    title = f" Phase {phase_num}/{total}: {name} "
    pad = PHASE_W - len(title)
    left = 2
    right = max(pad - left, 1)
    print(f"\n  {M}{B}{'─' * left}{title}{'─' * right}{R}")
    print(f"  {D}  {description}{R}")
    print()


def phase_footer():
    """Print a phase footer line."""
    M = Colors.MAGENTA
    D = Colors.DIM
    R = Colors.RESET
    print(f"  {D}{'─' * PHASE_W}{R}")


# ═══════════════════════════════════════════════════════════════════════
#  Status messages & progress
# ═══════════════════════════════════════════════════════════════════════

STATUS_ICONS = {
    "info":    ("ℹ", Colors.BLUE),
    "ok":      ("✔", Colors.GREEN),
    "warn":    ("⚠", Colors.YELLOW),
    "error":   ("✘", Colors.RED),
    "scan":    ("⟳", Colors.CYAN),
    "vuln":    ("◉", Colors.RED),
    "phase":   ("▶", Colors.MAGENTA),
}


def print_status(message, status="info"):
    """Print a status message with an icon."""
    icon_char, icon_color = STATUS_ICONS.get(status, STATUS_ICONS["info"])
    print(f"  {icon_color}[{icon_char}]{Colors.RESET} {message}")


def print_progress(current, total, label=""):
    """Print a single-line progress bar (overwrites the current line)."""
    bar_len = 30
    filled = int(bar_len * current / max(total, 1))
    bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
    pct = int(100 * current / max(total, 1))
    sys.stdout.write(f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} {pct}% {label}")
    sys.stdout.flush()
    if current >= total:
        print()
