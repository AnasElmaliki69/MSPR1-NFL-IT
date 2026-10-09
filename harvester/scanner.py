#!/usr/bin/env python3
"""
Seahawks Harvester — hardened network-scan agent.

Collects network telemetry (host discovery, WAN latency) on a local Linux VM
and ships JSON reports to the Seahawks Nester central platform.

Security properties
-------------------
* No secrets in source: the API key and all settings come from the environment.
* TLS by default: reports are uploaded over HTTPS with certificate verification.
  Plain HTTP is refused unless explicitly allowed (testing only).
* Least privilege: report files are created with mode 0600.
* Input validation: scan targets are validated as IP networks / addresses.
* No secret leakage: logs and stdout never contain the API key or full payloads.
* Fail-safe defaults: the agent refuses to start without an API key configured.
* Resilient uploads: exponential-backoff retries instead of silent failures.

Required environment variables
------------------------------
    HARVESTER_API_KEY   shared secret with the Nester platform (required)
    NESTER_URL          upload endpoint, e.g. https://nester.lan:5443/upload (required)

"""

from __future__ import annotations

import datetime
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import nmap
import requests

VERSION = "2.0"
UPLOAD_TIMEOUT_SECONDS = 10
MAX_UPLOAD_RETRIES = 4
REPORT_SCHEMA_REQUIRED = {
    "host_id": str,
    "scan_date": str,
    "devices_detected": int,
    "average_latency_ms": (str, int, float),
    "alert_level": str,
    "version": str,
}
ALERT_LEVELS = {"OK", "WARNING", "CRITICAL"}
MAX_HOSTS_PER_REPORT = 4096


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _getenv(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"[!] Missing required environment variable: {name}")
    return value  # type: ignore[return-value]


BASE_DIR = Path(_getenv("HARVESTER_BASE_DIR", "/home/harvester-vm/seahawks-harvester"))
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

NESTER_URL = _getenv("NESTER_URL", required=True)
API_KEY = _getenv("HARVESTER_API_KEY", required=True)
ALLOW_INSECURE_HTTP = _getenv("ALLOW_INSECURE_HTTP", "false").lower() == "true"

try:
    SCAN_NETWORK = ipaddress.ip_network(_getenv("SCAN_NETWORK", "192.168.50.0/24"), strict=False)
except ValueError as exc:
    raise SystemExit(f"[!] Invalid SCAN_NETWORK: {exc}") from exc

try:
    NESTER_IP = ipaddress.ip_address(_getenv("NESTER_IP", "192.168.50.20"))
except ValueError as exc:
    raise SystemExit(f"[!] Invalid NESTER_IP: {exc}") from exc

if NESTER_URL.startswith("http://") and not ALLOW_INSECURE_HTTP:
    raise SystemExit(
        "[!] Refusing to upload over plain HTTP (API key would travel in cleartext). "
        "Use an https:// NESTER_URL or set ALLOW_INSECURE_HTTP=true for isolated lab testing only."
    )

try:
    SCAN_INTERVAL = max(10, int(_getenv("SCAN_INTERVAL", "60")))
except ValueError:
    raise SystemExit("[!] SCAN_INTERVAL must be an integer number of seconds.")

CA_BUNDLE = os.environ.get("NESTER_CA_BUNDLE") or True

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOGS_DIR / "harvester.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("harvester")


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def measure_latency(target: ipaddress._BaseAddress) -> str:
    """ICMP latency to *target* in ms (average), 'unknown' or 'unreachable'.

    The target is an ipaddress object (never raw user input) and ping is
    invoked with an argument list — no shell — plus a hard timeout.
    """
    try:
        out = subprocess.check_output(
            ["ping", "-c", "2", "-W", "2", str(target)],
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).decode(errors="replace")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("Latency probe failed for %s: %s", target, type(exc).__name__)
        return "unreachable"

    for line in out.splitlines():
        if "rtt min/avg/max" in line or "round-trip min/avg/max" in line:
            parts = line.split("/")
            if len(parts) > 5:
                return parts[4]
    return "unknown"


def discover_hosts(network: ipaddress._BaseNetwork) -> list[str]:
    """Ping-scan *network*, returning the list of responding host addresses."""
    hosts: list[str] = []
    try:
        nm = nmap.PortScanner()
        # -sn: host discovery only (no port scan) — least intrusive profile.
        nm.scan(hosts=str(network), arguments="-sn --max-retries 1")
        hosts = sorted(nm.all_hosts(), key=ipaddress.ip_address)
    except Exception as exc:  # nmap may be missing or lack privileges
        log.error("Host discovery failed: %s", type(exc).__name__)
    return hosts


def compute_alert_level(latency: str, hosts: list[str]) -> str:
    if latency == "unreachable" or not hosts:
        return "CRITICAL"
    if latency != "unknown":
        try:
            if float(latency) > 50:
                return "WARNING"
        except (ValueError, TypeError):
            pass
    return "OK"


def build_report() -> dict:
    hosts = discover_hosts(SCAN_NETWORK)
    latency = measure_latency(NESTER_IP)
    report = {
        "host_id": socket.gethostname(),
        "scan_date": datetime.datetime.now().isoformat(timespec="seconds"),
        "devices_detected": len(hosts),
        "hosts": hosts[:MAX_HOSTS_PER_REPORT],
        "average_latency_ms": latency,
        "alert_level": compute_alert_level(latency, hosts),
        "version": VERSION,
    }
    log.info(
        "Scan completed: devices=%d latency=%s alert=%s",
        len(hosts),
        latency,
        report["alert_level"],
    )
    return report


def validate_report(report: dict) -> None:
    """Defense in depth: never persist or upload a malformed report."""
    for field, expected in REPORT_SCHEMA_REQUIRED.items():
        if field not in report:
            raise ValueError(f"report missing required field: {field}")
        if not isinstance(report[field], expected):
            raise ValueError(f"report field {field!r} has wrong type")
    if report["alert_level"] not in ALERT_LEVELS:
        raise ValueError(f"invalid alert_level: {report['alert_level']!r}")
    if not isinstance(report.get("hosts", []), list):
        raise ValueError("report field 'hosts' must be a list")


def save_report(report: dict) -> Path:
    """Persist the report with owner-only permissions (0600)."""
    filename = REPORTS_DIR / f"report_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
    # O_EXCL + 0o600: no symlink races, no world-readable telemetry.
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(report, fh, indent=2)
    except BaseException:
        try:
            os.unlink(filename)
        except OSError:
            pass
        raise
    return filename


def upload_report(report: dict) -> bool:
    """POST the report to Nester over TLS, with exponential-backoff retries."""
    session = requests.Session()
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    for attempt in range(1, MAX_UPLOAD_RETRIES + 1):
        try:
            resp = session.post(
                NESTER_URL, json=report, headers=headers,
                timeout=UPLOAD_TIMEOUT_SECONDS, verify=CA_BUNDLE,
            )
            if 200 <= resp.status_code < 300:
                log.info("Upload succeeded (attempt %d, status %d)", attempt, resp.status_code)
                return True
            log.warning("Upload rejected: HTTP %d (attempt %d)", resp.status_code, attempt)
            if resp.status_code in (401, 403, 422):
                return False  # auth/validation errors won't fix themselves
        except requests.RequestException as exc:
            log.warning("Upload failed (attempt %d): %s", attempt, type(exc).__name__)
        time.sleep(2 ** attempt)
    log.error("Upload failed after %d attempts", MAX_UPLOAD_RETRIES)
    return False


def main() -> None:
    log.info("Harvester v%s starting (scan %s every %ds)", VERSION, SCAN_NETWORK, SCAN_INTERVAL)
    # The report stays available locally even when the uplink is down (offline mode).
    while True:
        try:
            report = build_report()
            validate_report(report)
            saved = save_report(report)
            log.info("Report saved to %s", saved.name)
            upload_report(report)
        except Exception as exc:  # never let one bad cycle kill the agent
            log.error("Agent cycle failed: %s", type(exc).__name__, exc_info=True)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Harvester stopped by operator")
        sys.exit(0)
