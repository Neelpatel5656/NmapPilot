"""NmapPilot — Flask web server with WebSocket support for the GUI."""

import os
import json
import threading
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

from nmappilot import __version__
from nmappilot.ai_engine import OllamaAI
from nmappilot.web_scanner import WebScanner


# ═══════════════════════════════════════════════════════════════════════
#  App Factory
# ═══════════════════════════════════════════════════════════════════════

def create_app():
    """Create and configure the Flask application."""
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
    )
    app.config["SECRET_KEY"] = "nmappilot-secret-key"

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                        allow_upgrades=False)

    # ── Shared state ──
    ai = OllamaAI()
    scanner = WebScanner(emit_fn=lambda event, data: socketio.emit(event, data))
    scan_history = []
    _ai_stream_lock = threading.Lock()  # Prevent concurrent AI streams

    # ═══════════════════════════════════════════════════════════════
    #  Routes
    # ═══════════════════════════════════════════════════════════════

    @app.route("/")
    def index():
        return render_template("index.html", version=__version__)

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "version": __version__,
            "ai_available": ai.is_available(),
            "model": ai.model,
            "scan_running": scanner.is_running,
        })

    # ── AI Chat (streaming via SocketIO — primary path) ────────

    import re as _re

    def _quick_scan_detect(msg):
        """Fast regex-based scan intent detection (no AI call needed)."""
        msg_lower = msg.lower()
        scan_words = ['scan', 'nmap', 'enumerate', 'recon', 'audit',
                      'check ports', 'find open', 'probe', 'sweep']
        has_scan_intent = any(w in msg_lower for w in scan_words)
        if not has_scan_intent:
            return None

        # Extract target
        ip_m = _re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b', msg)
        domain_m = _re.search(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b', msg)
        target = (ip_m and ip_m.group(1)) or (domain_m and domain_m.group(1))
        if not target:
            return None

        # Determine scan depth
        max_phase = 2
        scan_type = 'service'
        if any(w in msg_lower for w in ['quick', 'fast', 'basic']):
            max_phase, scan_type = 1, 'quick'
        elif any(w in msg_lower for w in ['aggressive', 'deep', 'full', 'thorough']):
            max_phase, scan_type = 3, 'aggressive'
        elif any(w in msg_lower for w in ['comprehensive', 'everything', 'complete', 'all']):
            max_phase, scan_type = 4, 'comprehensive'

        return {
            'action': 'scan', 'target': target,
            'scan_type': scan_type, 'max_phase': max_phase,
            'no_vuln': False, 'no_dos': False, 'ports': None,
        }

    @socketio.on("chat_message")
    def handle_chat_message(data):
        message = data.get("message", "").strip()
        if not message:
            return

        # Reject if AI is already streaming a response — prevents race conditions
        if not _ai_stream_lock.acquire(blocking=False):
            socketio.emit("ai_response", {
                "token": "⏳ Please wait — I'm still processing the previous message.",
                "done": True,
            })
            return

        try:
            if not ai.is_available():
                socketio.emit("ai_response", {
                    "token": "⚠️ Ollama is not available. Make sure Ollama is running:\n\n"
                             "`sudo systemctl start ollama` or `ollama serve`",
                    "done": True,
                })
                _ai_stream_lock.release()
                return

            # Step 1: Quick scan-intent detection (instant, no AI call)
            scan_params = _quick_scan_detect(message)
            if scan_params and not scanner.is_running:
                target = scan_params['target']
                socketio.emit("scan_detected", scan_params)
                scanner.start_scan(
                    target=target,
                    max_phase=scan_params.get('max_phase', 2),
                    no_vuln=scan_params.get('no_vuln', False),
                    no_dos=scan_params.get('no_dos', False),
                    ports=scan_params.get('ports'),
                )

            # Step 2: Stream AI response
            context = ""
            if scanner.state.scan_result:
                results = scanner.get_results_for_ai()
                context = f"Current scan results:\n{json.dumps(results, indent=2, default=str)}"

            def stream():
                try:
                    for token in ai.chat_stream(message, context):
                        socketio.emit("ai_response", {"token": token, "done": False})
                        socketio.sleep(0)
                    socketio.emit("ai_response", {"token": "", "done": True})
                finally:
                    _ai_stream_lock.release()

            socketio.start_background_task(stream)
        except Exception:
            _ai_stream_lock.release()
            raise

    # ── AI Chat fallback (HTTP — kept for API access) ────────────

    @app.route("/api/chat", methods=["POST"])
    def api_chat():
        """HTTP fallback — not used by the GUI (which uses SocketIO)."""
        data = request.get_json() or {}
        message = data.get("message", "").strip()
        if not message:
            return jsonify({"error": "Empty message"}), 400
        if not ai.is_available():
            return jsonify({"action": "chat", "message": "⚠️ Ollama offline"}), 200
        result = ai.parse_scan_request(message)
        result["raw_response"] = result.get("message", "")
        return jsonify(result)

    # ── Scan Control ─────────────────────────────────────────────

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        data = request.get_json() or {}
        target = data.get("target", "").strip()

        if not target:
            return jsonify({"error": "No target specified"}), 400

        if scanner.is_running:
            return jsonify({"error": "A scan is already running"}), 409

        result = scanner.start_scan(
            target=target,
            max_phase=data.get("max_phase", 2),
            no_vuln=data.get("no_vuln", False),
            no_dos=data.get("no_dos", False),
            ports=data.get("ports"),
        )

        return jsonify(result)

    @app.route("/api/scan/status")
    def api_scan_status():
        return jsonify(scanner.state.to_dict())

    @app.route("/api/scan/results")
    def api_scan_results():
        return jsonify(scanner.state.to_dict())

    # ── AI Analysis ──────────────────────────────────────────────

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        if not scanner.state.scan_result:
            return jsonify({"error": "No scan results to analyze"}), 400

        if not ai.is_available():
            return jsonify({"error": "Ollama is not available"}), 503

        results = scanner.get_results_for_ai()
        analysis = ai.analyze_results(results)

        return jsonify({"analysis": analysis})

    # ── History ──────────────────────────────────────────────────

    @app.route("/api/history")
    def api_history():
        return jsonify({"history": scan_history})

    # ── AI Reset ─────────────────────────────────────────────────

    @app.route("/api/ai/reset", methods=["POST"])
    def api_ai_reset():
        ai.reset()
        return jsonify({"status": "ok", "message": "AI conversation reset"})

    # ═══════════════════════════════════════════════════════════════
    #  WebSocket events
    # ═══════════════════════════════════════════════════════════════

    @socketio.on("connect")
    def handle_connect():
        emit("connected", {
            "version": __version__,
            "ai_available": ai.is_available(),
            "model": ai.model,
        })

    @socketio.on("request_status")
    def handle_request_status():
        emit("scan_progress", scanner.state.to_dict())

    return app, socketio


# ═══════════════════════════════════════════════════════════════════════
#  Run server
# ═══════════════════════════════════════════════════════════════════════

def run_server(host="0.0.0.0", port=1337, debug=False):
    """Start the NmapPilot web server."""
    app, socketio = create_app()

    print(f"""
  ╔═══════════════════════════════════════════════════════════╗
  ║  NmapPilot AI GUI                                        ║
  ║  ───────────────────────────────────────────────────────  ║
  ║  Server:  http://{host}:{port}                          ║
  ║  Local:   http://127.0.0.1:{port}                       ║
  ║  AI:      {'✔ Ollama connected' :42s}║
  ╚═══════════════════════════════════════════════════════════╝
""")

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
