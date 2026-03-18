import nmap
import json
import datetime
import socket
import subprocess
import logging
import requests
import os
import time

BASE_DIR = "/home/harvester-vm/seahawks-harvester"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

NESTER_URL = "http://192.168.50.20:5000/upload"
API_KEY = "seahawks-secret-2026"
SCAN_NETWORK = "192.168.50.0/24"
NESTER_IP = "192.168.50.20"
VERSION = "1.2"

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOGS_DIR, "harvester.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


def measure_latency(target_ip: str) -> str:
    latency = "unknown"
    try:
        ping_output = subprocess.check_output(
            ["ping", "-c", "2", target_ip],
            stderr=subprocess.DEVNULL
        ).decode()

        for line in ping_output.split("\n"):
            if "rtt min/avg/max" in line or "round-trip min/avg/max" in line:
                latency = line.split("/")[4]
                break
    except Exception as e:
        latency = "unreachable"
        logging.error(f"Latency measurement failed: {e}")

    return latency


def discover_hosts(network: str) -> list:
    hosts = []
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments="-sn")
        for host in nm.all_hosts():
            hosts.append(host)
    except Exception as e:
        logging.error(f"Host discovery failed: {e}")
    return hosts


def compute_alert_level(latency: str, hosts: list) -> str:
    alert_level = "OK"

    if latency == "unreachable":
        alert_level = "CRITICAL"
    elif latency != "unknown":
        try:
            if float(latency) > 50:
                alert_level = "WARNING"
        except Exception:
            pass

    if len(hosts) == 0:
        alert_level = "CRITICAL"

    return alert_level


def build_report() -> dict:
    hosts = discover_hosts(SCAN_NETWORK)
    latency = measure_latency(NESTER_IP)
    alert_level = compute_alert_level(latency, hosts)

    report = {
        "host_id": socket.gethostname(),
        "scan_date": str(datetime.datetime.now()),
        "devices_detected": len(hosts),
        "hosts": hosts,
        "average_latency_ms": latency,
        "alert_level": alert_level,
        "version": VERSION
    }

    logging.info(
        f"Scan completed. Devices: {len(hosts)} "
        f"Latency: {latency} Alert: {alert_level}"
    )

    return report


def save_report(report: dict) -> str:
    filename = os.path.join(
        REPORTS_DIR,
        f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    return filename


def upload_report(report: dict) -> None:
    try:
        r = requests.post(
            NESTER_URL,
            json=report,
            headers={"X-API-KEY": API_KEY},
            timeout=5
        )
        print("Upload status:", r.status_code)
        logging.info(f"Upload status: {r.status_code}")
    except Exception as e:
        print("Upload failed:", e)
        logging.error(f"Upload failed: {e}")


def main():
    while True:
        try:
            report = build_report()
            saved_file = save_report(report)

            print("Scan finished")
            print(report)
            print("Saved to:", saved_file)

            upload_report(report)

        except Exception as e:
            logging.error(f"Agent error: {e}")
            print("Agent error:", e)

        time.sleep(60)


if __name__ == "__main__":
    main()