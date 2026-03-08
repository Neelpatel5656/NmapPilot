"""NmapPilot — Ollama AI Engine for natural language scan control."""

import json
import re
import threading
import requests
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════

OLLAMA_BASE = "http://localhost:11434"
MODEL_NAME = "wizard-vicuna-uncensored:13b"

SYSTEM_PROMPT = """You are NmapPilot AI — an expert cybersecurity assistant built into an automated Nmap scanning tool running on Kali Linux. Your job is to help users perform network reconnaissance and vulnerability assessments through natural language.

CAPABILITIES:
- Parse natural language requests to extract scan targets and parameters
- Analyze scan results and explain vulnerabilities in plain English
- Provide actionable security recommendations
- Answer cybersecurity and networking questions

WHEN THE USER WANTS TO SCAN A TARGET:
You MUST respond with a JSON block wrapped in ```json ... ``` containing:
{
  "action": "scan",
  "target": "<IP or hostname>",
  "scan_type": "quick|service|aggressive|comprehensive",
  "max_phase": 1-4,
  "no_vuln": false,
  "no_dos": false,
  "ports": null or "80,443,8080" or "1-1000",
  "message": "<brief confirmation message to show the user>"
}

SCAN TYPE MAPPING:
- "quick" / "fast" / "basic" → scan_type: "quick", max_phase: 1
- "service" / "version" / "detect services" → scan_type: "service", max_phase: 2
- "aggressive" / "full" / "deep" / "thorough" → scan_type: "aggressive", max_phase: 3
- "comprehensive" / "everything" / "complete" → scan_type: "comprehensive", max_phase: 4
- Default (just a target with no specifics) → scan_type: "service", max_phase: 2

WHEN THE USER ASKS A QUESTION (not requesting a scan):
Respond normally in markdown format. Be concise, technical, and helpful.

WHEN ANALYZING RESULTS:
Provide a structured analysis with:
1. Executive summary (1-2 sentences)
2. Key findings (critical issues first)
3. Risk assessment
4. Recommended actions

Always be direct and technical. You are running on Kali Linux for authorized penetration testing."""


# ═══════════════════════════════════════════════════════════════════════
#  OllamaAI class
# ═══════════════════════════════════════════════════════════════════════

class OllamaAI:
    """Interface to the local Ollama LLM for NmapPilot."""

    def __init__(self, model: str = MODEL_NAME, base_url: str = OLLAMA_BASE):
        self.model = model
        self.base_url = base_url
        self.conversation_history = []
        self._lock = threading.Lock()
        self._available = None

    # ── Health check ──────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is loaded."""
        if self._available is not None:
            return self._available
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                self._available = self.model in models
            else:
                self._available = False
        except Exception:
            self._available = False
        return self._available

    # ── Core chat ─────────────────────────────────────────────────────

    def chat(self, user_message: str, context: str = "") -> str:
        """Send a message to the LLM and return the full response."""
        with self._lock:
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            if context:
                messages.append({
                    "role": "system",
                    "content": f"CURRENT CONTEXT:\n{context}"
                })

            # Include recent history (last 10 exchanges to stay within context)
            for msg in self.conversation_history[-20:]:
                messages.append(msg)

            messages.append({"role": "user", "content": user_message})

            # Add user message to history BEFORE the API call so concurrent
            # requests see it immediately.
            self.conversation_history.append(
                {"role": "user", "content": user_message}
            )

        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2048,
                    }
                },
                timeout=300,
            )
            resp.raise_for_status()
            data = resp.json()
            reply = data.get("message", {}).get("content", "").strip()

            # Save assistant reply to history
            with self._lock:
                self.conversation_history.append(
                    {"role": "assistant", "content": reply}
                )

            return reply

        except requests.exceptions.Timeout:
            return "⚠️ AI response timed out. The model may be loading — please try again in a moment."
        except requests.exceptions.ConnectionError:
            self._available = False
            return "⚠️ Cannot connect to Ollama. Make sure it's running: `systemctl start ollama` or `ollama serve`"
        except Exception as e:
            return f"⚠️ AI error: {str(e)}"

    # ── Streaming chat ────────────────────────────────────────────────

    def chat_stream(self, user_message: str, context: str = ""):
        """Send a message and yield response tokens as they arrive."""
        # Build message list and commit user message to history BEFORE streaming
        # so that any subsequent request sees this message immediately.
        with self._lock:
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            if context:
                messages.append({
                    "role": "system",
                    "content": f"CURRENT CONTEXT:\n{context}"
                })

            for msg in self.conversation_history[-20:]:
                messages.append(msg)

            messages.append({"role": "user", "content": user_message})

            # Add user message to history NOW (before streaming starts)
            self.conversation_history.append(
                {"role": "user", "content": user_message}
            )

        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": True,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2048,
                    }
                },
                timeout=300,
                stream=True,
            )
            resp.raise_for_status()

            full_response = []
            for line in resp.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            full_response.append(token)
                            yield token
                        if chunk.get("done", False):
                            break
                    except json.JSONDecodeError:
                        continue

            # Save assistant reply to history after streaming completes
            complete = "".join(full_response)
            with self._lock:
                self.conversation_history.append(
                    {"role": "assistant", "content": complete}
                )

        except requests.exceptions.Timeout:
            yield "⚠️ AI response timed out. Please try again."
        except requests.exceptions.ConnectionError:
            self._available = False
            yield "⚠️ Cannot connect to Ollama. Run: `ollama serve`"
        except Exception as e:
            yield f"⚠️ AI error: {str(e)}"

    # ── Parse natural language into scan parameters ───────────────────

    def parse_scan_request(self, user_message: str) -> dict:
        """Parse a natural language request and extract scan parameters.

        Returns
        -------
        dict
            Keys: action, target, scan_type, max_phase, no_vuln, no_dos,
                  ports, message, raw_response
        """
        response = self.chat(user_message)
        result = self._extract_json(response)
        result["raw_response"] = response
        return result

    def _extract_json(self, text: str) -> dict:
        """Extract JSON scan parameters from LLM response."""
        # Try to find ```json ... ``` block
        json_match = re.search(r'```json\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if data.get("action") == "scan" and data.get("target"):
                    return self._normalize_scan_params(data)
            except json.JSONDecodeError:
                pass

        # Try to find raw JSON object
        json_match = re.search(r'\{[^{}]*"action"\s*:\s*"scan"[^{}]*\}', text, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
                if data.get("target"):
                    return self._normalize_scan_params(data)
            except json.JSONDecodeError:
                pass

        # Fallback: try to extract target manually from common patterns
        target = self._extract_target_fallback(text)
        if target:
            return {
                "action": "scan",
                "target": target,
                "scan_type": "service",
                "max_phase": 2,
                "no_vuln": False,
                "no_dos": False,
                "ports": None,
                "message": text,
            }

        # No scan detected — this is a general chat response
        return {
            "action": "chat",
            "message": text,
            "target": None,
        }

    def _normalize_scan_params(self, data: dict) -> dict:
        """Ensure all expected keys exist with valid values."""
        scan_type = str(data.get("scan_type", "service")).lower()
        phase_map = {
            "quick": 1, "fast": 1,
            "service": 2, "version": 2,
            "aggressive": 3, "full": 3, "deep": 3,
            "comprehensive": 4, "complete": 4, "everything": 4,
        }
        max_phase = data.get("max_phase")
        if not isinstance(max_phase, int) or max_phase < 1 or max_phase > 4:
            max_phase = phase_map.get(scan_type, 2)

        return {
            "action": "scan",
            "target": str(data.get("target", "")),
            "scan_type": scan_type,
            "max_phase": max_phase,
            "no_vuln": bool(data.get("no_vuln", False)),
            "no_dos": bool(data.get("no_dos", False)),
            "ports": data.get("ports"),
            "message": str(data.get("message", "Starting scan...")),
        }

    def _extract_target_fallback(self, text: str) -> Optional[str]:
        """Try to find an IP or hostname in the user's message or AI response."""
        # Look in the original user message from history
        if self.conversation_history:
            last_user = ""
            for msg in reversed(self.conversation_history):
                if msg["role"] == "user":
                    last_user = msg["content"]
                    break

            # IP address
            ip_match = re.search(
                r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', last_user
            )
            if ip_match:
                return ip_match.group(1)

            # Domain-like pattern
            domain_match = re.search(
                r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z]{2,})+)\b',
                last_user,
            )
            if domain_match:
                return domain_match.group(1)

        return None

    # ── Analyze scan results ──────────────────────────────────────────

    def analyze_results(self, scan_data: dict) -> str:
        """Feed scan results to the AI for analysis."""
        context = json.dumps(scan_data, indent=2, default=str)
        prompt = (
            "Analyze these NmapPilot scan results. Provide:\n"
            "1. Executive summary\n"
            "2. Critical findings\n"
            "3. Risk level assessment\n"
            "4. Recommended next steps\n\n"
            f"Scan Results:\n```json\n{context}\n```"
        )
        return self.chat(prompt)

    # ── Reset conversation ────────────────────────────────────────────

    def reset(self):
        """Clear conversation history."""
        with self._lock:
            self.conversation_history.clear()
