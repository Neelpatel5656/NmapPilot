"""NmapPilot — AI Engine with OpenRouter (free models) + Ollama fallback."""

import json
import os
import re
import threading
import time
import requests
from typing import Optional, List, Dict


# ═══════════════════════════════════════════════════════════════════════
#  Config
# ═══════════════════════════════════════════════════════════════════════

CONFIG_DIR = os.path.expanduser("~/.config/nmappilot")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
OLLAMA_BASE = "http://localhost:11434"

# Hardcoded fallback list in case the API fetch fails
DEFAULT_FREE_MODELS = [
    "meta-llama/llama-3.1-8b-instruct:free",
    "google/gemma-2-9b-it:free",
    "mistralai/mistral-7b-instruct:free",
    "huggingfaceh4/zephyr-7b-beta:free",
    "openchat/openchat-7b:free",
    "qwen/qwen-2-7b-instruct:free",
]

SYSTEM_PROMPT = """You are NmapPilot AI — an expert cybersecurity assistant built into an automated Nmap scanning tool running on Kali Linux.

CRITICAL RESPONSE FORMAT RULES:
When the user asks you to scan something, suggest specific nmap commands, or requests reconnaissance:
1. Provide a clear markdown explanation of your plan
2. Then include a JSON block wrapped in ```json ... ``` with this EXACT structure:
```json
{
  "commands": [
    {"cmd": "nmap -sS -T4 --top-ports 1000 scanme.nmap.org", "description": "Quick SYN scan of top 1000 ports"},
    {"cmd": "nmap -sV -sC -p <open_ports> scanme.nmap.org", "description": "Service/version detection on discovered ports"}
  ]
}
```

CRITICAL — COMMAND FORMAT RULES:
- NEVER wrap hostnames/IPs in angle brackets. Write them plain: `scanme.nmap.org` NOT `<scanme.nmap.org>`
- The ONLY valid placeholder is `<open_ports>` which auto-fills with ports from a previous scan
- Always use real, valid nmap commands with proper flags
- Put the actual target IP/hostname directly in the command, never in brackets
- Order commands from quick/safe to aggressive/deep
- Explain WHAT each command does and WHY you chose those specific flags
- You can suggest multiple commands that build on each other
- Never auto-execute — the user will click Run on the commands they want

WRONG: `nmap -sS <example.com>`  ← angle brackets break the shell!
RIGHT: `nmap -sS example.com`    ← correct, no brackets

For FOLLOW-UP commands referencing previous scan results:
- `<open_ports>` — auto-replaced with comma-separated discovered open ports (e.g. 22,80,443)
- Use the actual target hostname/IP from the conversation, NOT a placeholder

WHEN ANALYZING PREVIOUS COMMAND OUTPUT:
If the conversation includes scan results, analyze them and suggest follow-up commands.
Example: after discovering ports 22,80,443 on example.com, suggest: `nmap -sV -sC -p <open_ports> example.com`

WHEN THE USER ASKS A QUESTION (not requesting a scan):
Respond normally in markdown format. Be concise, technical, and helpful. Do NOT include a commands JSON block.

WHEN ANALYZING RESULTS:
The current scan results will be provided as context. Provide:
1. Executive summary (1-2 sentences)
2. Key findings (critical issues first)
3. Risk assessment
4. Recommended next steps (can include follow-up nmap commands in the JSON block)

NMAP REFERENCE (from `nmap --help`, Nmap 7.98 — use ONLY these flags):
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2],...>: Exclude hosts/networks
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN, TCP ACK, UDP or SCTP discovery
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -n/-R: Never do DNS resolution/Always resolve
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude specified ports
  -F: Fast mode - Scan fewer ports than default
  -r: Scan ports sequentially
  --top-ports <number>: Scan <number> most common ports
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: comma separated list of scripts/categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  -T<0-5>: Set timing template (higher is faster)
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
  --max-retries <tries>: Caps number of port scan probe retransmissions
  --host-timeout <time>: Give up on target after this long
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --data-length <num>: Append random data to sent packets
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output in normal, XML, s|<rIpt kIddi3, Grepable format
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --privileged: Assume that the user is fully privileged

EXAMPLES OF VALID COMMANDS (note: NO angle brackets around targets!):
  nmap -v -A scanme.nmap.org
  nmap -sS -T4 --top-ports 1000 192.168.1.1
  nmap -sV -sC -p 22,80,443 10.0.0.1
  nmap -sS -sV --script=vuln -p 80,443 example.com
  nmap -sU --top-ports 50 -T4 192.168.1.0/24
  nmap -sV --script=http-enum,http-headers -p 80,443,8080 example.com

Always be direct and technical. You are running on Kali Linux for authorized penetration testing only."""


# ═══════════════════════════════════════════════════════════════════════
#  Config helpers
# ═══════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    """Load config from ~/.config/nmappilot/config.json."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_config(cfg: dict):
    """Save config to ~/.config/nmappilot/config.json."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════
#  AIEngine — OpenRouter (free models) + Ollama fallback
# ═══════════════════════════════════════════════════════════════════════

class AIEngine:
    """Unified AI interface: OpenRouter free models with auto-fallback, Ollama as last resort."""

    def __init__(self):
        self.conversation_history: List[Dict[str, str]] = []
        self._lock = threading.Lock()
        self._config = load_config()

        # OpenRouter
        self._api_key = self._config.get("openrouter_api_key", "")
        self._free_models: List[str] = self._config.get("free_models", [])
        self._current_model_idx = 0
        self._preferred_model = self._config.get("preferred_model", "")

        # Ollama fallback
        self._ollama_model = self._config.get("ollama_model", "")
        self._ollama_base = OLLAMA_BASE

        # Status
        self._backend = "none"  # "openrouter", "ollama", or "none"
        self._status_message = ""
        self._initialized = False

    # ── Initialize — discover free models ──────────────────────────

    def initialize(self):
        """Discover available free models and set up the backend."""
        if self._initialized:
            return

        print(f"[AIEngine] Initializing... API key set: {bool(self._api_key)}")

        # Try OpenRouter first (ALWAYS preferred when key is set)
        if self._api_key:
            self._discover_free_models()
            if self._free_models:
                self._backend = "openrouter"
                model_name = self._free_models[0]
                self._status_message = f"OpenRouter: {model_name}"
                print(f"[AIEngine] ✔ Using OpenRouter with {len(self._free_models)} free models. Primary: {model_name}")
                self._initialized = True
                return
            else:
                print(f"[AIEngine] ⚠ API key set but no free models found")

        # Only fall back to Ollama if NO API key is configured
        if not self._api_key and self._check_ollama():
            self._backend = "ollama"
            self._status_message = f"Ollama: {self._ollama_model}"
            print(f"[AIEngine] Using Ollama fallback: {self._ollama_model}")
            self._initialized = True
            return

        if self._api_key:
            self._backend = "openrouter"
            self._status_message = "OpenRouter: waiting for models"
            print("[AIEngine] API key set but model fetch failed — will retry on first request")
        else:
            self._backend = "none"
            self._status_message = "No AI backend — set API key in Settings"
            print("[AIEngine] No backend available")
        self._initialized = True

    def _discover_free_models(self):
        """Fetch all free models from OpenRouter API."""
        try:
            print("[AIEngine] Fetching free models from OpenRouter...")
            resp = requests.get(
                f"{OPENROUTER_BASE}/models",
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=15,
            )
            print(f"[AIEngine] OpenRouter /models response: {resp.status_code}")
            if resp.status_code == 200:
                models = resp.json().get("data", [])
                free = []
                for m in models:
                    pricing = m.get("pricing", {})
                    prompt_price = str(pricing.get("prompt", "1"))
                    completion_price = str(pricing.get("completion", "1"))
                    if prompt_price == "0" and completion_price == "0":
                        free.append(m["id"])

                print(f"[AIEngine] Found {len(free)} free models out of {len(models)} total")
                if free:
                    self._free_models = free
                    # Put preferred model first if it's in the list
                    if self._preferred_model and self._preferred_model in free:
                        free.remove(self._preferred_model)
                        free.insert(0, self._preferred_model)
                        self._free_models = free

                    # Cache to config
                    self._config["free_models"] = self._free_models
                    save_config(self._config)
                    return
            else:
                print(f"[AIEngine] OpenRouter API error: {resp.text[:200]}")
        except Exception as e:
            print(f"[AIEngine] Failed to fetch models: {e}")

        # Use cached or defaults
        if not self._free_models:
            cached = load_config().get("free_models", [])
            if cached:
                print(f"[AIEngine] Using {len(cached)} cached models")
                self._free_models = cached
            else:
                print(f"[AIEngine] Using {len(DEFAULT_FREE_MODELS)} default models")
                self._free_models = list(DEFAULT_FREE_MODELS)

    def _check_ollama(self) -> bool:
        """Check if Ollama is running and find available models."""
        try:
            resp = requests.get(f"{self._ollama_base}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                if models:
                    if self._ollama_model and self._ollama_model in models:
                        return True
                    self._ollama_model = models[0]
                    return True
        except Exception:
            pass
        return False

    # ── Public properties ──────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        if not self._initialized:
            self.initialize()
        return self._backend != "none"

    @property
    def backend(self) -> str:
        if not self._initialized:
            self.initialize()
        return self._backend

    @property
    def current_model(self) -> str:
        if self._backend == "openrouter" and self._free_models:
            idx = min(self._current_model_idx, len(self._free_models) - 1)
            return self._free_models[idx]
        if self._backend == "ollama":
            return self._ollama_model
        return "none"

    @property
    def status_message(self) -> str:
        if not self._initialized:
            self.initialize()
        return self._status_message

    @property
    def free_models(self) -> List[str]:
        return list(self._free_models)

    # ── Config management ──────────────────────────────────────────

    def set_api_key(self, key: str):
        """Update OpenRouter API key and re-initialize."""
        self._api_key = key.strip()
        self._config["openrouter_api_key"] = self._api_key
        save_config(self._config)
        self._initialized = False
        self._free_models = []
        self._current_model_idx = 0
        self.initialize()

    def set_preferred_model(self, model: str):
        """Set preferred model."""
        self._preferred_model = model
        self._config["preferred_model"] = model
        save_config(self._config)
        # Move to front
        if model in self._free_models:
            self._free_models.remove(model)
            self._free_models.insert(0, model)
            self._current_model_idx = 0

    def get_config(self) -> dict:
        return {
            "api_key_set": bool(self._api_key),
            "api_key_preview": f"{self._api_key[:8]}...{self._api_key[-4:]}" if len(self._api_key) > 12 else ("***" if self._api_key else ""),
            "backend": self._backend,
            "current_model": self.current_model,
            "preferred_model": self._preferred_model,
            "free_models": self._free_models,
            "ollama_model": self._ollama_model,
            "status": self._status_message,
        }

    # ── Streaming chat (primary path) ──────────────────────────────

    def chat_stream(self, user_message: str, context: str = ""):
        """Send a message and yield response tokens. Auto-fallback through free models."""
        if not self._initialized:
            self.initialize()

        # Build messages
        with self._lock:
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            if context:
                messages.append({"role": "system", "content": f"CURRENT CONTEXT:\n{context}"})
            for msg in self.conversation_history[-20:]:
                messages.append(msg)
            messages.append({"role": "user", "content": user_message})
            self.conversation_history.append({"role": "user", "content": user_message})

        full_response = []
        success = False

        if self._backend == "openrouter":
            # Try each free model until one works
            start_idx = self._current_model_idx
            tried = 0
            while tried < len(self._free_models):
                idx = (start_idx + tried) % len(self._free_models)
                model = self._free_models[idx]
                tried += 1

                try:
                    for token in self._openrouter_stream(messages, model):
                        full_response.append(token)
                        yield token

                    # If we get here, it worked
                    self._current_model_idx = idx
                    self._status_message = f"OpenRouter: {model}"
                    success = True
                    break
                except Exception as e:
                    error_msg = str(e)
                    # Model failed — try next one
                    if tried < len(self._free_models):
                        next_model = self._free_models[(start_idx + tried) % len(self._free_models)]
                        yield f"\n\n⚠️ Model `{model}` failed ({error_msg}). Switching to `{next_model}`...\n\n"
                        full_response = []  # Reset for new model
                    continue

        if not success and self._backend == "openrouter":
            # All OpenRouter models failed — try Ollama
            if self._check_ollama():
                yield "\n\n⚠️ All OpenRouter free models failed. Falling back to local Ollama...\n\n"
                self._backend = "ollama"

        if not success and self._backend == "ollama":
            try:
                for token in self._ollama_stream(messages):
                    full_response.append(token)
                    yield token
                self._status_message = f"Ollama: {self._ollama_model}"
                success = True
            except Exception as e:
                yield f"\n\n⚠️ Ollama error: {e}"

        if not success and self._backend == "none":
            yield "⚠️ No AI backend available. Please configure an OpenRouter API key in Settings, or start Ollama locally."

        # Save assistant response
        complete = "".join(full_response)
        if complete:
            with self._lock:
                self.conversation_history.append({"role": "assistant", "content": complete})

    # ── Non-streaming chat ─────────────────────────────────────────

    def chat(self, user_message: str, context: str = "") -> str:
        """Non-streaming chat — collects full response."""
        tokens = []
        for token in self.chat_stream(user_message, context):
            tokens.append(token)
        return "".join(tokens)

    # ── OpenRouter streaming ───────────────────────────────────────

    def _openrouter_stream(self, messages: list, model: str):
        """Stream from OpenRouter API. Raises on failure."""
        resp = requests.post(
            f"{OPENROUTER_BASE}/chat/completions",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/Neelpatel5656/NmapPilot",
                "X-Title": "NmapPilot",
            },
            json={
                "model": model,
                "messages": messages,
                "stream": True,
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            timeout=120,
            stream=True,
        )

        if resp.status_code != 200:
            error_text = ""
            try:
                error_text = resp.json().get("error", {}).get("message", resp.text[:200])
            except Exception:
                error_text = resp.text[:200]
            raise RuntimeError(f"HTTP {resp.status_code}: {error_text}")

        for line in resp.iter_lines():
            if not line:
                continue
            line_str = line.decode("utf-8", errors="replace")
            if not line_str.startswith("data: "):
                continue
            data_str = line_str[6:]
            if data_str.strip() == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
                delta = chunk.get("choices", [{}])[0].get("delta", {})
                token = delta.get("content", "")
                if token:
                    yield token
            except (json.JSONDecodeError, IndexError, KeyError):
                continue

    # ── Ollama streaming ───────────────────────────────────────────

    def _ollama_stream(self, messages: list):
        """Stream from local Ollama. Raises on failure."""
        resp = requests.post(
            f"{self._ollama_base}/api/chat",
            json={
                "model": self._ollama_model,
                "messages": messages,
                "stream": True,
                "options": {"temperature": 0.3, "num_predict": 4096},
            },
            timeout=300,
            stream=True,
        )
        resp.raise_for_status()

        for line in resp.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        yield token
                    if chunk.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue

    # ── Analyze results ────────────────────────────────────────────

    def analyze_results(self, scan_data: dict) -> str:
        context = json.dumps(scan_data, indent=2, default=str)
        return self.chat(
            "Analyze these NmapPilot scan results. Provide executive summary, "
            "critical findings, risk assessment, and recommended next steps.",
            context=f"Scan Results:\n{context}"
        )

    # ── Reset ──────────────────────────────────────────────────────

    def reset(self):
        with self._lock:
            self.conversation_history.clear()

    def refresh_models(self):
        """Re-fetch free models from OpenRouter."""
        self._free_models = []
        self._current_model_idx = 0
        self._initialized = False
        self.initialize()
