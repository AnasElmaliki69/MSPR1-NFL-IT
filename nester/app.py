from flask import Flask, request, jsonify
import os
import json
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
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

            # Keep only the newest report for each probe
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

        rows.append(f"""
        <tr>
            <td>{filename}</td>
            <td>{host}</td>
            <td>{data.get('scan_date', 'N/A')}</td>
            <td>{data.get('devices_detected', 'N/A')}</td>
            <td>{data.get('average_latency_ms', 'N/A')}</td>
            <td>{data.get('version', 'N/A')}</td>
            <td>{status}</td>
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
            </tr>
            {''.join(rows)}
        </table>
    </body>
    </html>
    """


@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_json()

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(UPLOAD_FOLDER, filename)

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

    return jsonify({"status": "received", "file": filename}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)