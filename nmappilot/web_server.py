"""NmapPilot — Flask web server with command-based architecture."""

import os
import json
import subprocess
import threading
import re
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

from nmappilot import __version__
from nmappilot.ai_engine import AIEngine


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
    ai = AIEngine()
    _ai_stream_lock = threading.Lock()
    _cmd_process = {"proc": None, "running": False}  # Track running command

    # ═══════════════════════════════════════════════════════════════
    #  Routes
    # ═══════════════════════════════════════════════════════════════

    @app.route("/")
    def index():
        return render_template("index.html", version=__version__)

    @app.route("/api/status")
    def api_status():
        ai.initialize()
        return jsonify({
            "version": __version__,
            "ai_available": ai.is_available,
            "backend": ai.backend,
            "model": ai.current_model,
            "status": ai.status_message,
            "command_running": _cmd_process["running"],
        })

    # ── Config (API key, model selection) ──────────────────────

    @app.route("/api/config", methods=["GET"])
    def api_config_get():
        return jsonify(ai.get_config())

    @app.route("/api/config", methods=["POST"])
    def api_config_set():
        data = request.get_json() or {}
        if "api_key" in data:
            ai.set_api_key(data["api_key"])
        if "preferred_model" in data:
            ai.set_preferred_model(data["preferred_model"])
        return jsonify(ai.get_config())

    @app.route("/api/config/refresh-models", methods=["POST"])
    def api_refresh_models():
        ai.refresh_models()
        return jsonify(ai.get_config())

    # ── AI Chat (streaming via SocketIO) ──────────────────────

    @socketio.on("chat_message")
    def handle_chat_message(data):
        message = data.get("message", "").strip()
        if not message:
            return

        if not _ai_stream_lock.acquire(blocking=False):
            socketio.emit("ai_response", {
                "token": "⏳ Please wait — still processing the previous message.",
                "done": True,
            })
            return

        try:
            if not ai.is_available:
                socketio.emit("ai_response", {
                    "token": "⚠️ No AI backend available. Go to **Settings** to configure your OpenRouter API key, or start Ollama locally.",
                    "done": True,
                })
                _ai_stream_lock.release()
                return

            # Build context from any running/completed command output
            context = ""
            if _cmd_process.get("last_output"):
                context = f"Last command output:\n```\n{_cmd_process['last_output'][-3000:]}\n```"

            def stream():
                try:
                    for token in ai.chat_stream(message, context):
                        socketio.emit("ai_response", {"token": token, "done": False})
                        socketio.sleep(0)
                    socketio.emit("ai_response", {"token": "", "done": True})
                    # Emit model status update (in case model switched due to fallback)
                    socketio.emit("status_update", {
                        "backend": ai.backend,
                        "model": ai.current_model,
                        "status": ai.status_message,
                    })
                finally:
                    _ai_stream_lock.release()

            socketio.start_background_task(stream)
        except Exception:
            _ai_stream_lock.release()
            raise

    # ── Execute nmap command ──────────────────────────────────

    @socketio.on("execute_command")
    def handle_execute_command(data):
        cmd = data.get("cmd", "").strip()
        if not cmd:
            socketio.emit("command_error", {"error": "Empty command"})
            return

        # Security: only allow nmap commands
        if not cmd.startswith("nmap ") and cmd != "nmap":
            socketio.emit("command_error", {"error": "Only nmap commands are allowed"})
            return

        if _cmd_process["running"]:
            socketio.emit("command_error", {"error": "A command is already running"})
            return

        def run_command():
            _cmd_process["running"] = True
            _cmd_process["last_output"] = ""
            output_lines = []

            socketio.emit("command_started", {"cmd": cmd})

            try:
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                _cmd_process["proc"] = proc

                for line in iter(proc.stdout.readline, ''):
                    line = line.rstrip('\n')
                    if line:
                        output_lines.append(line)
                        socketio.emit("command_output", {"line": line})
                        socketio.sleep(0)

                proc.wait()
                exit_code = proc.returncode

                full_output = "\n".join(output_lines)
                _cmd_process["last_output"] = full_output

                socketio.emit("command_complete", {
                    "exit_code": exit_code,
                    "line_count": len(output_lines),
                })

            except Exception as e:
                socketio.emit("command_error", {"error": str(e)})
            finally:
                _cmd_process["running"] = False
                _cmd_process["proc"] = None

        socketio.start_background_task(run_command)

    @socketio.on("stop_command")
    def handle_stop_command():
        proc = _cmd_process.get("proc")
        if proc and _cmd_process["running"]:
            try:
                proc.terminate()
                socketio.emit("command_output", {"line": "⚠️ Command terminated by user"})
            except Exception:
                pass

    # ── AI Analysis ──────────────────────────────────────────────

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        data = request.get_json() or {}
        results = data.get("results", "")
        if not results:
            return jsonify({"error": "No data to analyze"}), 400
        if not ai.is_available:
            return jsonify({"error": "No AI backend available"}), 503
        analysis = ai.analyze_results(results if isinstance(results, dict) else {"raw": results})
        return jsonify({"analysis": analysis})

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
        ai.initialize()
        emit("connected", {
            "version": __version__,
            "ai_available": ai.is_available,
            "backend": ai.backend,
            "model": ai.current_model,
            "status": ai.status_message,
        })

    @socketio.on("request_status")
    def handle_request_status():
        emit("status_update", {
            "backend": ai.backend,
            "model": ai.current_model,
            "status": ai.status_message,
            "command_running": _cmd_process["running"],
        })

    return app, socketio


# ═══════════════════════════════════════════════════════════════════════
#  Run server
# ═══════════════════════════════════════════════════════════════════════

def run_server(host="0.0.0.0", port=1337, debug=False):
    """Start the NmapPilot web server."""
    app, socketio = create_app()

    # Initialize AI to show status at startup
    ai_temp = AIEngine()
    ai_temp.initialize()

    server_str = f"http://{host}:{port}"
    local_str = f"http://127.0.0.1:{port}"

    print(f"""
  ╔═══════════════════════════════════════════════════════════╗
  ║  NmapPilot AI GUI                                        ║
  ║  ───────────────────────────────────────────────────────  ║
  ║  Server:  {server_str:<42s}║
  ║  Local:   {local_str:<42s}║
  ║  AI:      {ai_temp.status_message:<42s}║
  ╚═══════════════════════════════════════════════════════════╝
""")

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
