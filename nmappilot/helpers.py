"""NmapPilot — Miscellaneous helpers (timestamps, root check)."""

import os
from datetime import datetime


def timestamp():
    """Return current timestamp string for file names."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def check_root():
    """Check if the current process is running as root."""
    return os.geteuid() == 0
