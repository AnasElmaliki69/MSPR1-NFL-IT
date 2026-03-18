from flask import Flask, request, jsonify, Response
from functools import wraps
import os
import json
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "reports"
API_KEY = "seahawks-secret-2026"

WEB_USERNAME = "admin"
WEB_PASSWORD = "seahawks2026"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def check_auth(username, password):
    return username == WEB_USERNAME and password == WEB_PASSWORD


def authenticate():
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@requires_auth
def home():
    files = sorted(os.listdir(UPLOAD_FOLDER), reverse=True)

    if not files:
        return """
        <html>
        <head>
            <title>Seahawks Nester</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 30px;
                }
            </style>
        </head>
        <body>
            <h1>Seahawks Nester - Probe Status</h1>
            <p>No reports received yet.</p>
        </body>
        </html>
        """

    probes = {}

    for filename in files:
        path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            with open(path, "r") as f:
                data = json.load(f)

            host = data.get("host_id", "unknown")

            if host not in probes:
                probes[host] = {
                    "filename": filename,
                    "data": data
                }
        except Exception:
            continue

    rows = []

    for host, probe_info in probes.items():
        data = probe_info["data"]
        filename = probe_info["filename"]

        try:
            scan_time = datetime.strptime(
                data["scan_date"].split(".")[0],
                "%Y-%m-%d %H:%M:%S"
            )
            delta = (datetime.now() - scan_time).total_seconds()
            status = "CONNECTED" if delta < 120 else "DISCONNECTED"
        except Exception:
            status = "UNKNOWN"

        alert = data.get("alert_level", "OK")
        alert_color = {
            "OK": "#d4edda",
            "WARNING": "#fff3cd",
            "CRITICAL": "#f8d7da"
        }.get(alert, "#eeeeee")

        rows.append(f"""
        <tr>
            <td><a href="/report/{filename}">{filename}</a></td>
            <td>{host}</td>
            <td>{data.get('scan_date', 'N/A')}</td>
            <td>{data.get('devices_detected', 'N/A')}</td>
            <td>{data.get('average_latency_ms', 'N/A')}</td>
            <td>{data.get('version', 'N/A')}</td>
            <td>{status}</td>
            <td style="background-color:{alert_color}; font-weight:bold;">{alert}</td>
        </tr>
        """)

    return f"""
    <html>
    <head>
        <title>Seahawks Nester</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 30px;
            }}
            h1 {{
                color: #333;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            a {{
                text-decoration: none;
                color: #0077cc;
            }}
        </style>
    </head>
    <body>
        <h1>Seahawks Nester - Probe Status</h1>
        <table>
            <tr>
                <th>Filename</th>
                <th>Host ID</th>
                <th>Last Scan</th>
                <th>Devices Detected</th>
                <th>Latency (ms)</th>
                <th>Version</th>
                <th>Status</th>
                <th>Alert</th>
            </tr>
            {''.join(rows)}
        </table>
    </body>
    </html>
    """


@app.route("/upload", methods=["POST"])
def upload():
    auth_header = request.headers.get("X-API-KEY")

    if auth_header != API_KEY:
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json()

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

    return jsonify({"status": "received", "file": filename}), 200


@app.route("/report/<filename>")
@requires_auth
def report_detail(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(path):
        return "Report not found", 404

    with open(path) as f:
        data = json.load(f)

    return f"""
    <html>
    <head>
        <title>Report {filename}</title>
        <style>
            body {{
                font-family: monospace;
                margin: 40px;
                background: #f5f5f5;
            }}
            pre {{
                background: white;
                padding: 20px;
                border: 1px solid #ccc;
            }}
            a {{
                text-decoration: none;
                color: #0077cc;
            }}
        </style>
    </head>
    <body>
        <h2>Report: {filename}</h2>
        <pre>{json.dumps(data, indent=4)}</pre>
        <a href="/">← Back</a>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)