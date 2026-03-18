import nmap
import json
import datetime
import socket
import subprocess
import logging
import requests
import os

BASE_DIR = "/home/harvester-vm/seahawks-harvester"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOGS_DIR, "harvester.log"),
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

network = "192.168.50.0/24"

nm = nmap.PortScanner()
nm.scan(hosts=network, arguments='-sn')

hosts = []

for host in nm.all_hosts():
    hosts.append(host)

latency = "unknown"

try:
    ping = subprocess.check_output(
        ["ping", "-c", "2", "192.168.50.20"],
        stderr=subprocess.DEVNULL
    ).decode()

    for line in ping.split("\n"):
        if "rtt" in line or "avg" in line:
            latency = line.split("/")[4]
except:
    latency = "unreachable"

report = {
    "host_id": socket.gethostname(),
    "scan_date": str(datetime.datetime.now()),
    "devices_detected": len(hosts),
    "hosts": hosts,
    "average_latency_ms": latency,
    "version": "1.1"
}

filename = os.path.join(
    REPORTS_DIR,
    f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
)

with open(filename, "w") as f:
    json.dump(report, f, indent=4)

logging.info(f"Scan completed. Devices: {len(hosts)} Latency: {latency}")

print("Scan finished")
print(report)

try:
    r = requests.post(
        "http://192.168.50.20:5000/upload",
        json=report,
        timeout=5
    )
    print("Upload status:", r.status_code)
except Exception as e:
    print("Upload failed:", e)
    logging.error(f"Upload failed: {e}")