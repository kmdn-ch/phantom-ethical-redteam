"""Phantom Web Dashboard — Flask + SocketIO with structured data."""

import collections
import hmac
import os
import re
import sys
import json
import time
import logging
import threading
import functools
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, jsonify, request, send_file, make_response

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"

# Read VERSION from the VERSION file at the project root
try:
    _VERSION_FILE = PROJECT_ROOT / "VERSION"
    DASHBOARD_VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip()
except Exception:
    DASHBOARD_VERSION = "unknown"

# Fix #2: Move sys.path.insert to module level (out of run_mission thread)
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "PHANTOM_DASHBOARD_SECRET", os.urandom(24).hex()
)

# --- Dashboard authentication via API key ---
# Set PHANTOM_DASHBOARD_KEY env var to enable auth. If unset, dashboard is open.
DASHBOARD_KEY = os.environ.get("PHANTOM_DASHBOARD_KEY", "")


def require_auth(f):
    """Decorator: require ?key= or X-API-Key header if PHANTOM_DASHBOARD_KEY is set."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not DASHBOARD_KEY:
            return f(*args, **kwargs)
        provided = request.args.get("key") or request.headers.get("X-API-Key", "")
        # Fix #6: Timing-safe comparison
        if not hmac.compare_digest(provided, DASHBOARD_KEY):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# Only import CORS/SocketIO after app is created
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Restrict CORS to localhost by default; override with PHANTOM_CORS_ORIGIN
_cors_origin = os.environ.get("PHANTOM_CORS_ORIGIN", "http://localhost:*")
CORS(app, origins=[_cors_origin])
socketio = SocketIO(app, cors_allowed_origins=_cors_origin, async_mode="threading")


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    """Add HTTP security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws://localhost:* wss://localhost:*; "
        "img-src 'self' data:; "
        "font-src 'self';"
    )
    return response


# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory per-IP, no external deps)
# ---------------------------------------------------------------------------

_rate_store: dict = collections.defaultdict(list)
_RATE_WINDOW = 60   # seconds
_RATE_MAX = int(os.environ.get("PHANTOM_RATE_LIMIT", "120"))  # requests per window

# Fix #5: Thread-safe rate limiter with memory leak prevention
_rate_lock = threading.Lock()


def _is_rate_limited(ip: str) -> bool:
    """Return True if the given IP has exceeded the rate limit."""
    with _rate_lock:
        now = time.time()
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
        if not _rate_store[ip]:
            del _rate_store[ip]
            return False
        # Evict oldest IP if store grows too large
        if len(_rate_store) > 10000:
            oldest_ip = min(_rate_store, key=lambda k: _rate_store[k][0] if _rate_store[k] else 0)
            del _rate_store[oldest_ip]
        if len(_rate_store.get(ip, [])) >= _RATE_MAX:
            return True
        _rate_store[ip].append(now)
        return False


@app.before_request
def check_rate_limit():
    """Apply rate limiting to all API endpoints."""
    if request.path.startswith("/api/"):
        ip = request.remote_addr or "unknown"
        if _is_rate_limited(ip):
            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

# Track running mission
_mission_thread = None
_mission_stop = threading.Event()

# Fix #4: Threading lock for mission thread
_mission_lock = threading.Lock()


# ---------------------------------------------------------------------------
# CSRF Origin check helper
# ---------------------------------------------------------------------------

def _check_origin():
    """Fix #7: Validate Origin/Referer header on mutating requests."""
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    host = os.environ.get("PHANTOM_DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("PHANTOM_DASHBOARD_PORT", "5000"))
    allowed = [
        f"http://{host}:{port}",
        f"http://localhost:{port}",
        f"http://127.0.0.1:{port}",
    ]
    if not any(origin.startswith(a) for a in allowed):
        return False
    return True


# ---------------------------------------------------------------------------
# Structured result parsers
# ---------------------------------------------------------------------------

def parse_nuclei_output(raw: str) -> list:
    """Parse nuclei text output into structured findings."""
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Nuclei format: [severity] [template-id] [protocol] url [extra]
        m = re.match(
            r"\[(?P<sev>critical|high|medium|low|info)\]\s+"
            r"\[(?P<tid>[^\]]+)\]\s+"
            r"\[(?P<proto>[^\]]+)\]\s+"
            r"(?P<url>\S+)\s*(?P<extra>.*)",
            line, re.IGNORECASE,
        )
        if m:
            findings.append({
                "severity": m.group("sev").lower(),
                "template": m.group("tid"),
                "protocol": m.group("proto"),
                "url": m.group("url"),
                "extra": m.group("extra").strip(),
            })
        # Also match bracket-only severity mentions
        elif re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.IGNORECASE):
            sev_m = re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.IGNORECASE)
            findings.append({
                "severity": sev_m.group(1).lower(),
                "template": "",
                "protocol": "",
                "url": "",
                "extra": line,
            })
    return findings


def parse_nmap_output(raw: str) -> dict:
    """Parse nmap text output into structured data."""
    ports = []
    host_info = {}
    for line in raw.splitlines():
        # Open port lines: 80/tcp open http Apache httpd 2.4.x
        pm = re.match(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", line)
        if pm:
            ports.append({
                "port": int(pm.group(1)),
                "protocol": pm.group(2),
                "state": pm.group(3),
                "service": pm.group(4),
                "version": pm.group(5).strip(),
            })
        if "Nmap scan report for" in line:
            host_info["target"] = line.split("for")[-1].strip()
        if "Host is up" in line:
            host_info["status"] = "up"
            latency = re.search(r"\(([\d.]+)s latency\)", line)
            if latency:
                host_info["latency"] = latency.group(1)
    return {"host": host_info, "ports": ports}


def parse_ffuf_output(raw: str) -> list:
    """Parse ffuf results."""
    results = []
    for line in raw.splitlines():
        # ffuf output: URL status size words lines
        m = re.match(r".*\[Status:\s*(\d+),\s*Size:\s*(\d+),.*Words:\s*(\d+).*\]\s*(.+)", line)
        if m:
            results.append({
                "status": int(m.group(1)),
                "size": int(m.group(2)),
                "words": int(m.group(3)),
                "url": m.group(4).strip(),
            })
    # Also try JSON format
    if not results:
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "results" in data:
                for r in data["results"]:
                    results.append({
                        "status": r.get("status", 0),
                        "size": r.get("length", 0),
                        "words": r.get("words", 0),
                        "url": r.get("url", r.get("input", {}).get("FUZZ", "")),
                    })
        except (json.JSONDecodeError, TypeError):
            pass
    return results


def parse_recon_output(raw: str) -> dict:
    """Parse recon results."""
    data = {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = {"raw": raw[:2000]}
    return data


def parse_sqlmap_output(raw: str) -> dict:
    """Parse sqlmap output."""
    vulns = []
    for line in raw.splitlines():
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            vulns.append(line.strip())
        if "available databases" in line.lower():
            vulns.append(line.strip())
    return {"vulnerabilities": vulns, "raw_lines": len(raw.splitlines())}


TOOL_PARSERS = {
    "run_nuclei": ("nuclei", parse_nuclei_output),
    "run_nmap": ("nmap", parse_nmap_output),
    "run_ffuf": ("ffuf", parse_ffuf_output),
    "run_recon": ("recon", parse_recon_output),
    "run_sqlmap": ("sqlmap", parse_sqlmap_output),
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    """Health check endpoint for monitoring and load balancers."""
    running = _mission_thread is not None and _mission_thread.is_alive()
    return jsonify({
        "status": "ok",
        "mission_running": running,
        "version": DASHBOARD_VERSION,
    })


@app.route("/api/sessions")
@require_auth
def list_sessions():
    """List available sessions with optional pagination.

    Query params:
        page  (int, default 1): page number (1-based)
        limit (int, default 50): max sessions per page
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except (ValueError, TypeError):
        page, limit = 1, 50

    sessions = []
    if LOGS_DIR.exists():
        for d in sorted(LOGS_DIR.iterdir(), reverse=True):
            if d.is_dir() and d.name != "temp":
                # Skip hidden directories
                if d.name.startswith("."):
                    continue
                files = [f.name for f in d.iterdir() if f.is_file()]
                has_report = any("report" in f for f in files)
                has_state = "state.json" in files
                try:
                    dt = datetime.strptime(d.name[:15], "%Y%m%d_%H%M%S")
                    label = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    label = d.name
                sessions.append({
                    "id": d.name,
                    "label": label,
                    "has_report": has_report,
                    "has_state": has_state,
                    "file_count": len(files),
                })

    total = len(sessions)
    start = (page - 1) * limit
    paged = sessions[start: start + limit]
    return jsonify({
        "sessions": paged,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, (total + limit - 1) // limit),
    })


@app.route("/api/sessions/<session_id>")
@require_auth
def session_detail(session_id):
    safe_session = os.path.basename(session_id)
    if safe_session != session_id or ".." in session_id or session_id.startswith("/"):
        return jsonify({"error": "Invalid session id"}), 400
    session_dir = LOGS_DIR / safe_session
    if not str(session_dir.resolve()).startswith(str(LOGS_DIR.resolve())):
        return jsonify({"error": "Access denied"}), 403
    if not session_dir.is_dir():
        return jsonify({"error": "Session not found"}), 404

    files = []
    for f in sorted(session_dir.iterdir()):
        if f.is_file():
            files.append({"name": f.name, "size": f.stat().st_size, "type": f.suffix})

    state = None
    state_path = session_dir / "state.json"
    if state_path.exists():
        try:
            with open(state_path) as f:
                raw = json.load(f)
            state = {
                "turn": raw.get("turn", 0),
                "message_count": len(raw.get("messages", [])),
            }
        except Exception:
            pass

    return jsonify({"id": session_id, "files": files, "state": state})


@app.route("/api/sessions/<session_id>/logs/<path:filename>")
@require_auth
def read_log(session_id, filename):
    # Strict path traversal protection
    safe_session = os.path.basename(session_id)
    safe_filename = os.path.basename(filename)
    if safe_session != session_id or safe_filename != filename:
        return jsonify({"error": "Invalid path"}), 400
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid path"}), 400

    file_path = (LOGS_DIR / safe_session / safe_filename).resolve()
    logs_resolved = LOGS_DIR.resolve()
    if not str(file_path).startswith(str(logs_resolved)):
        return jsonify({"error": "Access denied"}), 403
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404
    content = file_path.read_text(encoding="utf-8", errors="replace")
    return jsonify({"filename": safe_filename, "content": content[:100000]})


@app.route("/api/sessions/<session_id>/state")
@require_auth
def read_state(session_id):
    """Read and parse state.json for a past session — extract structured data."""
    # Path traversal protection — mirror read_log guard
    safe_session = os.path.basename(session_id)
    if safe_session != session_id or ".." in session_id or session_id.startswith("/"):
        return jsonify({"error": "Invalid session id"}), 400
    state_file = (LOGS_DIR / safe_session / "state.json").resolve()
    if not str(state_file).startswith(str(LOGS_DIR.resolve())):
        return jsonify({"error": "Access denied"}), 403
    state_path = LOGS_DIR / safe_session / "state.json"
    if not state_path.exists():
        return jsonify({"error": "No state.json"}), 404

    try:
        with open(state_path) as f:
            raw = json.load(f)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    messages = raw.get("messages", [])
    turn = raw.get("turn", 0)

    # Extract structured data from all messages
    tools_used = []
    all_findings = []
    nmap_data = []
    ffuf_data = []
    texts = []

    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            if msg.get("role") == "assistant" and isinstance(content, str):
                texts.append(content)
            continue

        for block in content:
            btype = block.get("type")

            if btype == "text" and msg.get("role") == "assistant":
                texts.append(block.get("text", ""))

            elif btype == "tool_use":
                tools_used.append({
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "input": block.get("input", {}),
                })

            elif btype == "tool_result":
                raw_content = str(block.get("content", ""))
                tool_use_id = block.get("tool_use_id", "")
                # Find the matching tool_use
                tool_name = ""
                for t in tools_used:
                    if t["id"] == tool_use_id:
                        tool_name = t["name"]
                        break

                if tool_name in TOOL_PARSERS:
                    label, parser = TOOL_PARSERS[tool_name]
                    parsed = parser(raw_content)
                    if label == "nuclei" and isinstance(parsed, list):
                        all_findings.extend(parsed)
                    elif label == "nmap" and isinstance(parsed, dict):
                        nmap_data.append(parsed)
                    elif label == "ffuf" and isinstance(parsed, list):
                        ffuf_data.extend(parsed)

    # Also parse findings from assistant text
    for text in texts:
        extra = parse_nuclei_output(text)
        all_findings.extend(extra)

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return jsonify({
        "turn": turn,
        "message_count": len(messages),
        "tools_used": tools_used,
        "findings": all_findings,
        "severity_counts": severity_counts,
        "nmap": nmap_data,
        "ffuf": ffuf_data,
        "texts": texts[-5:],  # Last 5 assistant texts
    })


@app.route("/api/sessions/<session_id>/report")
@require_auth
def get_report(session_id):
    """Fix #9: Serve report with Content-Disposition and sandboxed CSP."""
    safe_session = os.path.basename(session_id)
    if safe_session != session_id or ".." in session_id or session_id.startswith("/"):
        return jsonify({"error": "Invalid session id"}), 400
    session_dir = LOGS_DIR / safe_session
    if not str(session_dir.resolve()).startswith(str(LOGS_DIR.resolve())):
        return jsonify({"error": "Access denied"}), 403
    reports = sorted(session_dir.glob("report_*.html"), reverse=True)
    if not reports:
        return jsonify({"error": "No report found"}), 404
    response = make_response(send_file(reports[0], as_attachment=False, mimetype="text/html"))
    response.headers["Content-Security-Policy"] = "sandbox"
    return response


# ---------------------------------------------------------------------------
# Mission control
# ---------------------------------------------------------------------------

@app.route("/api/missions/start", methods=["POST"])
@require_auth
def start_mission():
    global _mission_thread

    # Fix #7: CSRF origin check
    if not _check_origin():
        return jsonify({"error": "Forbidden: invalid origin"}), 403

    data = request.json or {}

    def run_mission():
        socketio.emit("mission_status", {"status": "running"})
        try:
            # Fix #1: No os.chdir — use absolute paths everywhere
            # Fix #2: sys.path.insert moved to module level

            import yaml
            with open(PROJECT_ROOT / "config.yaml") as f:
                config = yaml.safe_load(f)

            # Fix #3: Override provider from request
            if data.get("provider"):
                config["provider"] = data["provider"]

            # Override scope if provided from UI
            scope_text = data.get("scope", "").strip()
            if scope_text:
                scope_file = PROJECT_ROOT / config.get("scope_file", "scopes/current_scope.md")
                scope_file.parent.mkdir(parents=True, exist_ok=True)
                scope_file.write_text(scope_text)

            from tools.logs_helper import init_session
            session_dir = init_session()
            socketio.emit("session_started", {"session": session_dir})

            from agent_client import AgentClient
            client = AgentClient(config=config)

            with open(PROJECT_ROOT / "prompts" / "system_prompt.txt") as f:
                system_prompt = f.read()

            scope_path = PROJECT_ROOT / config.get("scope_file", "scopes/current_scope.md")
            scope = scope_path.read_text() if scope_path.exists() else ""

            messages = [{
                "role": "user",
                "content": f"Authorized scope:\n{scope}\n\nSTART THE MISSION IN AUTONOMOUS MODE.",
            }]

            mission_start = time.time()

            for turn in range(config.get("max_autonomous_turns", 50)):
                if _mission_stop.is_set():
                    socketio.emit("agent_output", {
                        "type": "system", "text": "Mission stopped by user.",
                    })
                    break

                socketio.emit("turn_start", {"turn": turn + 1})
                turn_start = time.time()

                messages = client.think(messages=messages, system_prompt=system_prompt)
                client.save_state(messages, turn, session_dir)

                turn_duration = round(time.time() - turn_start, 1)

                # Parse and emit the last assistant message
                last = next(
                    (m for m in reversed(messages) if m["role"] == "assistant"), None
                )
                if last:
                    content = last["content"]
                    if isinstance(content, list):
                        for block in content:
                            if block.get("type") == "text":
                                text = block["text"]
                                socketio.emit("agent_output", {
                                    "type": "agent",
                                    "text": text,
                                    "turn": turn + 1,
                                })
                                # Parse findings from text
                                found = parse_nuclei_output(text)
                                for f in found:
                                    socketio.emit("finding", f)

                            elif block.get("type") == "tool_use":
                                socketio.emit("tool_start", {
                                    "id": block.get("id", ""),
                                    "name": block["name"],
                                    "input": block["input"],
                                    "turn": turn + 1,
                                })

                # Parse and emit tool results
                tool_msg = next(
                    (m for m in reversed(messages)
                     if m["role"] == "user" and isinstance(m.get("content"), list)),
                    None,
                )
                if tool_msg:
                    for block in tool_msg["content"]:
                        if block.get("type") == "tool_result":
                            raw_result = str(block.get("content", ""))
                            tool_use_id = block["tool_use_id"]

                            # Find matching tool name
                            tool_name = ""
                            if last and isinstance(last["content"], list):
                                for b in last["content"]:
                                    if b.get("type") == "tool_use" and b.get("id") == tool_use_id:
                                        tool_name = b["name"]
                                        break

                            # Emit raw result (truncated)
                            socketio.emit("tool_result", {
                                "id": tool_use_id,
                                "name": tool_name,
                                "content": raw_result[:2000],
                                "turn": turn + 1,
                                "duration": turn_duration,
                            })

                            # Emit structured parsed data
                            if tool_name in TOOL_PARSERS:
                                label, parser = TOOL_PARSERS[tool_name]
                                try:
                                    parsed = parser(raw_result)
                                    socketio.emit("tool_data", {
                                        "tool": tool_name,
                                        "label": label,
                                        "data": parsed,
                                        "turn": turn + 1,
                                    })
                                    # Emit individual findings
                                    if label == "nuclei" and isinstance(parsed, list):
                                        for f in parsed:
                                            socketio.emit("finding", f)
                                except Exception:
                                    pass

                # Check mission complete
                assistant_text = ""
                if last:
                    c = last["content"]
                    if isinstance(c, list):
                        assistant_text = " ".join(
                            b.get("text", "") for b in c if b.get("type") == "text"
                        )
                    else:
                        assistant_text = str(c)

                if "=== MISSION COMPLETE ===" in assistant_text:
                    total_time = round(time.time() - mission_start, 1)
                    socketio.emit("mission_complete", {
                        "session": session_dir,
                        "turns": turn + 1,
                        "duration": total_time,
                        "summary": assistant_text.split("=== MISSION COMPLETE ===")[-1].strip(),
                    })
                    return

            total_time = round(time.time() - mission_start, 1)
            socketio.emit("mission_complete", {
                "session": session_dir,
                "turns": turn + 1,
                "duration": total_time,
                "summary": "Max turns reached.",
            })

        except Exception as e:
            import traceback
            logger.error("Mission failed:\n%s", traceback.format_exc())
            # Fix #8: Don't leak exception type to client
            socketio.emit("mission_error", {
                "error": "Mission failed unexpectedly",
            })

    _mission_stop.clear()

    # Fix #4: Use threading lock to prevent race conditions
    with _mission_lock:
        if _mission_thread and _mission_thread.is_alive():
            return jsonify({"error": "Mission already running"}), 409
        _mission_thread = threading.Thread(target=run_mission, daemon=True)
        _mission_thread.start()

    return jsonify({"status": "started"})


@app.route("/api/missions/stop", methods=["POST"])
@require_auth
def stop_mission():
    # Fix #7: CSRF origin check
    if not _check_origin():
        return jsonify({"error": "Forbidden: invalid origin"}), 403
    _mission_stop.set()
    return jsonify({"status": "stopping"})


@socketio.on("connect")
def on_connect():
    if DASHBOARD_KEY:
        provided = request.args.get("key", "")
        # Fix #6: Timing-safe comparison
        if not hmac.compare_digest(provided, DASHBOARD_KEY):
            return False  # Reject WebSocket connection
    running = _mission_thread is not None and _mission_thread.is_alive()
    # Fix #10: Emit to specific client only, not broadcast
    emit("connected", {"status": "ok", "mission_running": running}, to=request.sid)


if __name__ == "__main__":
    host = os.environ.get("PHANTOM_DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("PHANTOM_DASHBOARD_PORT", "5000"))
    debug = os.environ.get("PHANTOM_DEBUG", "false").lower() == "true"
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
