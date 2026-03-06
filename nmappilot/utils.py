"""NmapPilot — Backward-compatible re-export shim.

All public symbols that other modules previously imported from
``nmappilot.utils`` are re-exported here so existing import lines
continue to work without changes.
"""

# ── Colors & text helpers ──
from nmappilot.colors import Colors, colored, bold, severity_color  # noqa: F401

# ── UI / display ──
from nmappilot.ui import (                                          # noqa: F401
    print_banner,
    print_section,
    print_subsection,
    print_status,
    print_progress,
)

# ── Target validation ──
from nmappilot.target import validate_target                        # noqa: F401

# ── Nmap execution ──
from nmappilot.nmap_runner import run_nmap, run_searchsploit        # noqa: F401

# ── XML parsing ──
from nmappilot.xml_parser import (                                  # noqa: F401
    parse_nmap_xml,
    get_open_ports,
    get_services,
    get_service_string,
)

# ── Misc helpers ──
from nmappilot.helpers import timestamp, check_root                 # noqa: F401
