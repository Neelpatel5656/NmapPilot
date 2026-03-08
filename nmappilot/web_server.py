"""NmapPilot — Flask web server with command-based architecture."""

import os
import json
import socket
import subprocess
import threading
import re
import html as html_lib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
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
    _cmd_process = {"proc": None, "running": False, "last_output": "",
                    "last_cmd": "", "last_exit_code": None, "last_time": None}

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
            _cmd_process["last_cmd"] = cmd
            _cmd_process["last_exit_code"] = None
            _cmd_process["last_time"] = datetime.now().isoformat()
            output_lines = []

            socketio.emit("command_started", {"cmd": cmd})

            try:
                # Run nmap directly — server already runs as root via sudo
                # Use env to avoid any password prompts, DEBIAN_FRONTEND=noninteractive
                env = os.environ.copy()
                env["DEBIAN_FRONTEND"] = "noninteractive"

                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
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
                _cmd_process["last_exit_code"] = exit_code

                socketio.emit("command_complete", {
                    "exit_code": exit_code,
                    "line_count": len(output_lines),
                    "cmd": cmd,
                    "output": full_output,
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

    # ── Report Export ─────────────────────────────────────────

    @app.route("/api/report/html", methods=["POST"])
    def export_html_report():
        """Generate and return an HTML report from command output."""
        data = request.get_json() or {}
        cmd = data.get("cmd", _cmd_process.get("last_cmd", ""))
        output = data.get("output", _cmd_process.get("last_output", ""))
        timestamp = data.get("timestamp", _cmd_process.get("last_time", datetime.now().isoformat()))

        if not output:
            return jsonify({"error": "No output to export"}), 400

        report_html = _generate_html_report(cmd, output, timestamp)
        return Response(report_html, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename=nmappilot_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"})

    @app.route("/api/report/preview", methods=["POST"])
    def preview_report():
        """Return HTML report for inline preview."""
        data = request.get_json() or {}
        cmd = data.get("cmd", _cmd_process.get("last_cmd", ""))
        output = data.get("output", _cmd_process.get("last_output", ""))
        timestamp = data.get("timestamp", _cmd_process.get("last_time", datetime.now().isoformat()))
        return jsonify({"html": _generate_html_report(cmd, output, timestamp)})

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
#  HTML Report Generator
# ═══════════════════════════════════════════════════════════════════════

def _generate_html_report(cmd, output, timestamp):
    """Generate a standalone HTML report from nmap output."""
    escaped_cmd = html_lib.escape(cmd)
    escaped_output = html_lib.escape(output)

    # Parse nmap output for structured data
    open_ports = []
    for line in output.split('\n'):
        port_match = re.match(r'^(\d+/\w+)\s+(open|closed|filtered)\s+(.*)', line)
        if port_match:
            open_ports.append({
                "port": port_match.group(1),
                "state": port_match.group(2),
                "service": port_match.group(3).strip(),
            })

    ports_table = ""
    if open_ports:
        rows = ""
        for p in open_ports:
            state_class = "open" if p["state"] == "open" else "other"
            rows += f'<tr><td class="port">{html_lib.escape(p["port"])}</td><td class="{state_class}">{html_lib.escape(p["state"])}</td><td>{html_lib.escape(p["service"])}</td></tr>\n'
        ports_table = f"""
        <div class="section">
            <h2>📡 Discovered Ports</h2>
            <table>
                <thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NmapPilot Report — {escaped_cmd}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #d0d8e8; line-height: 1.6; padding: 24px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #00f0ff33; padding-bottom: 20px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 24px; background: linear-gradient(135deg, #00f0ff, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header .meta {{ color: #607080; font-size: 13px; margin-top: 6px; font-family: monospace; }}
        .section {{ background: #0d1320; border: 1px solid #00f0ff15; border-radius: 10px; padding: 18px; margin-bottom: 16px; }}
        .section h2 {{ font-size: 16px; color: #00f0ff; margin-bottom: 12px; }}
        .cmd-box {{ background: #000; border: 1px solid #00f0ff20; border-radius: 6px; padding: 12px 16px; font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #00f0ff; margin-bottom: 16px; word-break: break-all; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background: #141c2e; padding: 8px 12px; text-align: left; font-weight: 600; color: #8090a0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #00f0ff15; }}
        td {{ padding: 8px 12px; border-bottom: 1px solid #ffffff08; }}
        .port {{ font-family: monospace; font-weight: 600; color: #00f0ff; }}
        .open {{ color: #4ade80; font-weight: 600; }}
        .other {{ color: #607080; }}
        .raw-output {{ background: #000; border: 1px solid #00f0ff10; border-radius: 6px; padding: 14px; font-family: 'JetBrains Mono', monospace; font-size: 11px; white-space: pre-wrap; word-break: break-word; max-height: 500px; overflow-y: auto; color: #8090a0; line-height: 1.7; }}
        .footer {{ text-align: center; color: #405060; font-size: 11px; margin-top: 24px; padding-top: 16px; border-top: 1px solid #ffffff08; }}
        @media print {{ body {{ background: #fff; color: #222; }} .section {{ border-color: #ddd; background: #f8f8f8; }} .header h1 {{ color: #333; -webkit-text-fill-color: unset; background: none; }} .cmd-box {{ background: #f0f0f0; color: #333; border-color: #ddd; }} .raw-output {{ background: #f5f5f5; color: #333; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ NmapPilot Scan Report</h1>
            <div class="meta">Generated: {timestamp} | NmapPilot v{__version__}</div>
        </div>
        <div class="section">
            <h2>⚡ Command Executed</h2>
            <div class="cmd-box">{escaped_cmd}</div>
        </div>
        {ports_table}
        <div class="section">
            <h2>📋 Raw Output</h2>
            <div class="raw-output">{escaped_output}</div>
        </div>
        <div class="footer">
            Generated by NmapPilot AI — https://github.com/Neelpatel5656/NmapPilot
        </div>
    </div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════
#  Network helpers
# ═══════════════════════════════════════════════════════════════════════

def _get_local_ip():
    """Get the machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _print_qr_code(url):
    """Print a QR code to the terminal."""
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(url)
        qr.make(fit=True)

        # Print using Unicode block characters for terminal
        matrix = qr.get_matrix()
        print()
        for r in range(0, len(matrix) - 1, 2):
            line = "  "
            for c in range(len(matrix[r])):
                top = matrix[r][c]
                bot = matrix[r + 1][c] if r + 1 < len(matrix) else False
                if top and bot:
                    line += "█"
                elif top and not bot:
                    line += "▀"
                elif not top and bot:
                    line += "▄"
                else:
                    line += " "
            print(line)
        if len(matrix) % 2 == 1:
            line = "  "
            for c in range(len(matrix[-1])):
                line += "▀" if matrix[-1][c] else " "
            print(line)
        print()
    except ImportError:
        print("  (Install 'qrcode' package for QR code: pip install qrcode)")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
#  Run server
# ═══════════════════════════════════════════════════════════════════════

def run_server(host="0.0.0.0", port=1337, debug=False):
    """Start the NmapPilot web server."""
    app, socketio = create_app()

    # Initialize AI to show status at startup
    ai_temp = AIEngine()
    ai_temp.initialize()

    local_ip = _get_local_ip()
    server_str = f"http://{host}:{port}"
    local_str = f"http://127.0.0.1:{port}"
    lan_str = f"http://{local_ip}:{port}"

    print(f"""
  ╔═══════════════════════════════════════════════════════════╗
  ║  NmapPilot AI GUI                                        ║
  ║  ───────────────────────────────────────────────────────  ║
  ║  Local:   {local_str:<42s}║
  ║  Network: {lan_str:<42s}║
  ║  AI:      {ai_temp.status_message:<42s}║
  ╚═══════════════════════════════════════════════════════════╝
""")

    # Print QR code for mobile access
    print("  📱 Scan this QR code to open on your phone:")
    _print_qr_code(lan_str)
    print(f"  Or open: {lan_str}")
    print()

    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
