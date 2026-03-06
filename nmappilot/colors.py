"""NmapPilot — ANSI color definitions and helpers."""


class Colors:
    """ANSI escape code helpers with severity palette."""

    # ── Text styles ──
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET     = "\033[0m"

    # ── Foreground colors ──
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    BLUE      = "\033[94m"
    MAGENTA   = "\033[95m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    GREY      = "\033[90m"

    # ── Severity badges ──
    CRITICAL  = "\033[1;97;41m"   # White on red bg
    HIGH      = "\033[1;91m"       # Bold red
    MEDIUM    = "\033[1;93m"       # Bold yellow
    LOW       = "\033[1;96m"       # Bold cyan
    INFO      = "\033[1;94m"       # Bold blue

    # ── Accent palette (for UI polish) ──
    ACCENT1   = "\033[38;5;39m"    # Bright sky-blue
    ACCENT2   = "\033[38;5;213m"   # Pink-magenta
    ACCENT3   = "\033[38;5;48m"    # Mint-green
    BG_DIM    = "\033[48;5;236m"   # Dark grey background

    @classmethod
    def disable(cls):
        """Turn off all color output."""
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


def colored(text, color):
    """Wrap text in ANSI color."""
    return f"{color}{text}{Colors.RESET}"


def bold(text):
    """Wrap text in bold."""
    return colored(text, Colors.BOLD)


def severity_color(severity):
    """Return ANSI color code for a severity string."""
    mapping = {
        "CRITICAL": Colors.CRITICAL,
        "HIGH":     Colors.HIGH,
        "MEDIUM":   Colors.MEDIUM,
        "LOW":      Colors.LOW,
        "INFO":     Colors.INFO,
        "URGENT":   Colors.CRITICAL,
    }
    return mapping.get(severity.upper(), Colors.WHITE)
