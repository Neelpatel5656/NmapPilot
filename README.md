# NmapPilot 🧭

**Automated Nmap Scanning & Vulnerability Analysis Tool**

NmapPilot automates the entire nmap reconnaissance workflow — from initial port discovery through aggressive scanning to comprehensive vulnerability analysis. It progressively escalates scan intensity based on results quality, identifies vulnerabilities using NSE scripts and ExploitDB, assesses DoS risks, and generates a professional CLI report.

---

## ✨ Features

- **Progressive Scanning** — 4-phase auto-escalation (Quick → Service → Aggressive → Comprehensive)
- **Smart Escalation** — only runs deeper scans when initial results are insufficient
- **Vulnerability Analysis** — NSE vuln/exploit/auth scripts + CVE extraction
- **ExploitDB Integration** — automatic searchsploit queries for discovered services
- **DoS Assessment** — detects DoS-susceptible services and known DoS CVEs (safe checks only)
- **Rich CLI Report** — color-coded terminal output with severity ratings
- **Report Export** — saves plain-text report file for documentation
- **Zero Dependencies** — uses only Python standard library
- **Modular Architecture** — clean, maintainable codebase split into focused modules

## 📸 Screenshots

### 1. Quick Discovery Scan
![Feature 1](screenshots/ss1.png)

### 2. Service Detection
![Feature 2](screenshots/ss2.png)

### 3. Aggressive Scanning
![Feature 3](screenshots/ss3.png)

### 4. Vulnerability Analysis
![Feature 4](screenshots/ss4.png)

### 5. Comprehensive Report
![Feature 5](screenshots/ss5.png)

## 📋 Requirements

| Dependency | Required | Notes |
|------------|----------|-------|
| **Python** 3.8+ | ✅ | Standard library only |
| **Nmap** | ✅ | Must be in PATH |
| **SearchSploit** | ❌ | Optional — enables ExploitDB integration |
| **Root/sudo** | ✅ | Required for SYN scans and OS detection |

## 🚀 Installation

### One-Command Install (Recommended)

```bash
git clone https://github.com/Neelpatel5656/NmapPilot.git
cd NmapPilot
sudo bash install.sh
```

The installer will:
- Verify Python 3.8+ and nmap are available
- Install NmapPilot system-wide via pip
- Configure `sudo nmappilot` to work out of the box
- Add `~/.local/bin` to your shell PATH (fish/bash/zsh)

### Manual Install

```bash
cd NmapPilot
pip install .
```

## 🔧 Usage

### Interactive Mode
```bash
sudo nmappilot
```
Prompts for a target and runs a full scan with all analysis phases.

### CLI Mode
```bash
# Scan a specific target
sudo nmappilot -t scanme.nmap.org

# Quick scan (max 2 phases)
sudo nmappilot -t 192.168.1.1 -m 2

# Skip DoS assessment
sudo nmappilot -t example.com --no-dos

# Scan only (no vulnerability analysis)
sudo nmappilot -t example.com --no-vuln

# Disable colors
sudo nmappilot -t example.com --no-color
```

### Run as Module
```bash
sudo python -m nmappilot -t scanme.nmap.org
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target hostname or IP address |
| `-m, --max-phase` | Maximum scan phase (1–4, default: 4) |
| `--no-dos` | Skip DoS vulnerability assessment |
| `--no-vuln` | Skip vulnerability analysis (scan only) |
| `--no-color` | Disable colored output |
| `-v, --version` | Show version number |

## 📡 Scan Phases

| Phase | Name | Description | Escalation Trigger |
|-------|------|-------------|-------------------|
| 1 | Quick Discovery | SYN scan · top 1000 ports | Always runs first |
| 2 | Service Detection | Version + script scan on open ports | < 3 ports or no versions |
| 3 | Aggressive | Full port range · OS detection | Missing OS/service info |
| 4 | Comprehensive | Full SYN + version + OS + scripts | Last resort |

## 📊 Report Sections

1. **Target Summary** — IP, hostname, scan duration, phases used
2. **Port & Service Table** — all discovered open ports with service details
3. **OS Detection** — fingerprinted OS with accuracy ratings
4. **Vulnerability Findings** — color-coded by severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
5. **DoS Assessment** — dedicated DoS risk analysis
6. **ExploitDB Matches** — known public exploits from ExploitDB
7. **Attack Surface Summary** — overall risk rating with attack vectors
8. **Recommendations** — actionable remediation suggestions

## 🏗️ Project Structure

```
NmapPilot/
├── install.sh              # One-command installer
├── setup.py                # Package configuration
├── README.md
├── LICENSE
└── nmappilot/
    ├── __init__.py          # Version & package metadata
    ├── __main__.py          # python -m nmappilot entry point
    ├── cli.py               # Argument parsing & orchestration
    ├── scanner.py           # Progressive scan engine
    ├── analyzer.py          # Vulnerability analysis (NSE + ExploitDB)
    ├── dos_checker.py       # DoS vulnerability assessment
    ├── reporter.py          # CLI report generator
    ├── colors.py            # ANSI color definitions
    ├── ui.py                # Banner, headers, status messages
    ├── target.py            # Target validation & DNS resolution
    ├── nmap_runner.py       # PTY-based nmap execution
    ├── xml_parser.py        # Nmap XML output parser
    ├── helpers.py           # Timestamps, root check
    └── utils.py             # Backward-compatible re-export shim
```

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and network administration only**. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and may violate local, state, and federal laws. By using this tool, you confirm proper authorization.

## 📄 License

MIT
