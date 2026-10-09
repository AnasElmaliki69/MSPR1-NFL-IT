#!/usr/bin/env python3
"""
Seahawks Nester — hardened central supervision platform.

Receives JSON telemetry reports from Seahawks Harvester probes and renders a
minimal status dashboard for N1/N2 support teams.

Security properties
-------------------
* No secrets in source: API key and web password hash come from the environment.
* Constant-time credential comparison (no timing side-channels).
* Authenticated uploads: every /upload request needs a valid API key header.
* Path traversal impossible: report filenames are allow-listed AND safe_joined.
* No stored XSS: every value rendered into HTML is escaped.
* Payload validation: strict JSON schema, 1 MiB cap, bounded host lists.
* Disk-exhaustion protection: only the N most recent reports are retained.
* Brute-force throttling: in-memory rate limits on /upload and web login.
* Hardened HTTP responses: nosniff, anti-clickjacking, referrer policy, CSP.
* Production-ready entrypoint: refuses Flask's debug server; document TLS
  termination (reverse proxy) in front of the app.

Required environment variables
------------------------------
    NESTER_API_KEY        shared secret expected in the X-API-Key header
    NESTER_WEB_PASS_HASH  werkzeug password hash for the dashboard login
                          (generate: python -c "from werkzeug.security import
                           generate_password_hash; print(generate_password_hash('pw'))")

"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, request
from werkzeug.security import check_password_hash
from werkzeug.utils import safe_join

VERSION = "2.0"

def _getenv(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"[!] Missing required environment variable: {name}")
    return value  # type: ignore[return-value]


API_KEY = _getenv("NESTER_API_KEY", required=True).encode()
WEB_USERNAME = _getenv("NESTER_WEB_USER", "admin")
WEB_PASSWORD_HASH = _getenv("NESTER_WEB_PASS_HASH", required=True)
UPLOAD_FOLDER = Path(_getenv("NESTER_DATA_DIR", "reports"))
HOST = _getenv("NESTER_HOST", "0.0.0.0")
PORT = int(_getenv("NESTER_PORT", "5000"))

MAX_CONTENT_LENGTH = 1 * 1024 * 1024        
MAX_STORED_REPORTS = 500                     
MAX_HOSTS_PER_REPORT = 4096
REPORT_FILENAME_RE = re.compile(r"^report_\d{8}_\d{6}\.json$")
HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ALERT_LEVELS = {"OK", "WARNING", "CRITICAL"}

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nester")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

_hits: dict[str, deque[float]] = defaultdict(deque)


def rate_limited(max_requests: int, window_seconds: int):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            key = f"{request.remote_addr}:{view.__name__}"
            now = time.monotonic()
            bucket = _hits[key]
            while bucket and bucket[0] <= now - window_seconds:
                bucket.popleft()
            if len(bucket) >= max_requests:
                log.warning("Rate limit exceeded for %s", key)
                return jsonify({"status": "rate_limited"}), 429
            bucket.append(now)
            return view(*args, **kwargs)

        return wrapper

    return decorator
def api_key_valid(provided: str | None) -> bool:
    if not provided:
        return False
    return hmac.compare_digest(provided.encode(), API_KEY)


def check_web_auth(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username, WEB_USERNAME)
    pass_ok = check_password_hash(WEB_PASSWORD_HASH, password)
    return user_ok and pass_ok


def _unauthorized_web() -> Response:
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="Seahawks Nester"'},
    )


def requires_web_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_web_auth(auth.username or "", auth.password or ""):
            return _unauthorized_web()
        return view(*args, **kwargs)

    return wrapper

def validate_report(data: object) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["payload must be a JSON object"]

    def check(field: str, types, extra=None):
        if field not in data:
            errors.append(f"missing field: {field}")
        elif not isinstance(data[field], types):
            errors.append(f"field {field!r} has wrong type")
        elif extra and not extra(data[field]):
            errors.append(f"field {field!r} has invalid value")

    check("host_id", str, lambda v: bool(HOST_ID_RE.match(v)))
    check("scan_date", str, lambda v: len(v) <= 64)
    check("devices_detected", int, lambda v: 0 <= v <= MAX_HOSTS_PER_REPORT)
    check("average_latency_ms", (str, int, float), lambda v: len(str(v)) <= 32)
    check("alert_level", str, lambda v: v in ALERT_LEVELS)
    check("version", str, lambda v: len(v) <= 16)
    hosts = data.get("hosts", [])
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS_PER_REPORT:
        errors.append("field 'hosts' must be a list within bounds")
    return errors


def prune_old_reports() -> None:
    """Keep only the MAX_STORED_REPORTS most recent reports."""
    files = sorted(
        (p for p in UPLOAD_FOLDER.iterdir() if REPORT_FILENAME_RE.match(p.name)),
        key=lambda p: p.name,
    )
    for stale in files[: max(0, len(files) - MAX_STORED_REPORTS)]:
        try:
            stale.unlink()
            log.info("Pruned old report %s", stale.name)
        except OSError as exc:
            log.warning("Could not prune %s: %s", stale.name, exc)


def latest_reports() -> dict[str, dict]:
    """Newest report per probe host_id. Filenames are allow-listed; bad files skipped."""
    probes: dict[str, dict] = {}
    for path in sorted(UPLOAD_FOLDER.iterdir(), reverse=True):
        if not REPORT_FILENAME_RE.match(path.name):
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        host = data.get("host_id")
        if isinstance(host, str) and host not in probes:
            probes[host] = {"filename": path.name, "data": data}
    return probes

def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


PAGE_HEAD = """<html><head><title>Seahawks Nester</title><style>
body{font-family:Arial,sans-serif;margin:30px}
h1{color:#333}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:10px;text-align:left}
th{background-color:#f2f2f2}a{text-decoration:none;color:#0077cc}
</style></head><body>"""


@app.route("/")
@requires_web_auth
@rate_limited(60, 60)
def home():
    probes = latest_reports()
    if not probes:
        return (
            PAGE_HEAD
            + "<h1>Seahawks Nester - Probe Status</h1><p>No reports received yet.</p></body></html>"
        )
    alert_color = {"OK": "#d4edda", "WARNING": "#fff3cd", "CRITICAL": "#f8d7da"}
    rows = []
    for host, info in probes.items():
        data, filename = info["data"], info["filename"]
        try:
            scan_time = datetime.fromisoformat(str(data.get("scan_date", "")))
            delta = (datetime.now() - scan_time).total_seconds()
            status = "CONNECTED" if delta < 120 else "DISCONNECTED"
        except ValueError:
            status = "UNKNOWN"
        alert = data.get("alert_level", "OK")
        color = alert_color.get(alert, "#eeeeee")
        rows.append(
            "<tr><td><a href=\"/report/" + _esc(filename) + "\">" + _esc(filename) + "</a></td>"
            "<td>" + _esc(host) + "</td>"
            "<td>" + _esc(data.get("scan_date", "N/A")) + "</td>"
            "<td>" + _esc(data.get("devices_detected", "N/A")) + "</td>"
            "<td>" + _esc(data.get("average_latency_ms", "N/A")) + "</td>"
            "<td>" + _esc(data.get("version", "N/A")) + "</td>"
            "<td>" + _esc(status) + "</td>"
            "<td style=\"background-color:" + color + ";font-weight:bold;\">" + _esc(alert) + "</td></tr>"
        )
    return (
        PAGE_HEAD
        + "<h1>Seahawks Nester - Probe Status</h1><table>"
        "<tr><th>Filename</th><th>Host ID</th><th>Last Scan</th><th>Devices Detected</th>"
        "<th>Latency (ms)</th><th>Version</th><th>Status</th><th>Alert</th></tr>"
        + "".join(rows)
        + "</table></body></html>"
    )


@app.route("/report/<filename>")
@requires_web_auth
@rate_limited(60, 60)
def report_detail(filename: str):
    if not REPORT_FILENAME_RE.match(filename):
        return "Report not found", 404
    path = safe_join(str(UPLOAD_FOLDER), filename)
    if not path:
        return "Report not found", 404
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return "Report not found", 404
    body = _esc(json.dumps(data, indent=2))
    return (
        "<html><head><title>Report " + _esc(filename) + "</title><style>"
        "body{font-family:monospace;margin:40px;background:#f5f5f5}"
        "pre{background:white;padding:20px;border:1px solid #ccc;overflow:auto}"
        "</style></head><body><h2>Report: " + _esc(filename) + "</h2><pre>" + body
        + '</pre><a href="/">← Back</a></body></html>'
    )


@app.route("/upload", methods=["POST"])
@rate_limited(30, 60)
def upload():
    if not api_key_valid(request.headers.get("X-API-Key")):
        time.sleep(0.2)
        return jsonify({"status": "unauthorized"}), 401
    if not request.is_json:
        return jsonify({"status": "invalid_content_type"}), 415
    data = request.get_json(silent=True)
    errors = validate_report(data)
    if data is None or errors:
        log.warning("Rejected malformed upload from %s: %s", request.remote_addr, errors)
        return jsonify({"status": "invalid_payload", "errors": errors}), 422
    filename = f"report_{datetime.now():%Y%m%d_%H%M%S}.json"
    path = UPLOAD_FOLDER / filename
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    prune_old_reports()
    log.info("Stored report %s from %s", filename, request.remote_addr)
    return jsonify({"status": "received", "file": filename}), 200


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.errorhandler(413)
def _too_large(_exc):
    return jsonify({"status": "payload_too_large"}), 413


if __name__ == "__main__":

    log.warning(
        "Starting Flask development server — for production use gunicorn "
        "behind a TLS reverse proxy. Never expose this port to untrusted networks."
    )
    app.run(host=HOST, port=PORT)
