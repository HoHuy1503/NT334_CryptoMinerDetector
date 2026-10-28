import json
import os
import socket
import time
from datetime import datetime, timezone

import psutil
from detection.rule_engine import detect, format_alert
from detection.threat_intel import ThreatIntelClient

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "system_events.jsonl")
ALERT_FILE = os.path.join(OUTPUT_DIR, "alerts.jsonl")
INTERVAL = 3
CPU_STREAKS = {}
CONNECTION_STREAKS = {}
THREAT_INTEL = ThreatIntelClient(os.environ.get("MALWAREBAZAAR_AUTH_KEY"))
SESSION = {"snapshots": 0, "alerts": 0, "high": 0, "medium": 0, "low": 0}
CPU_TOTALS = {}


def get_timestamp():
    return datetime.now(timezone.utc).astimezone().isoformat()


def safe_value(func, default=None):
    try:
        return func()
    except (psutil.Error, OSError, PermissionError):
        return default


def collect_processes():
    processes = []
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                processes.append({
                    "timestamp": get_timestamp(), "pid": proc.pid,
                    "ppid": safe_value(proc.ppid), "name": safe_value(proc.name),
                    "exe": safe_value(proc.exe), "username": safe_value(proc.username),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_percent": safe_value(proc.memory_percent),
                    "status": safe_value(proc.status), "create_time": safe_value(proc.create_time),
                })
        except (psutil.Error, OSError, PermissionError):
            continue
    return processes


def collect_connections():
    connections = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            local, remote = conn.laddr, conn.raddr
            connections.append({
                "timestamp": get_timestamp(), "pid": conn.pid,
                "family": str(conn.family), "type": str(conn.type),
                "local_address": f"{local.ip}:{local.port}" if local else None,
                "remote_address": f"{remote.ip}:{remote.port}" if remote else None,
                "status": conn.status,
            })
    except (psutil.Error, OSError, PermissionError) as exc:
        connections.append({"timestamp": get_timestamp(), "error": type(exc).__name__})
    return connections


def write_jsonl(path, event):
    with open(path, "a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")


def print_session_summary():
    print("\n=== Session summary ===")
    print("Snapshots:", SESSION["snapshots"])
    print("Alerts:", SESSION["alerts"],
          f"(high={SESSION['high']}, medium={SESSION['medium']}, low={SESSION['low']})")
    top_cpu = sorted(CPU_TOTALS.values(), key=lambda row: row["average_cpu"], reverse=True)[:5]
    if top_cpu:
        print("Top average CPU (excluding PID 0):")
        for row in top_cpu:
            print(f"  PID={row['pid']:<7} AvgCPU={row['average_cpu']:>6.1f}% Name={row['name']}")
    else:
        print("No process CPU samples available.")
    print("Snapshot log:", OUTPUT_FILE)
    print("Alert log:", ALERT_FILE)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("=== CryptoMiner Detector ===")
    print("OS:", os.name, "| Host:", socket.gethostname())
    print("Snapshot log:", OUTPUT_FILE, "| Alerts:", ALERT_FILE)
    print("Sampling interval:", INTERVAL, "seconds | Stop with Ctrl+C.\n")
    print("Hash reputation lookup:", "enabled (hash only, for flagged processes)" if THREAT_INTEL.enabled else "disabled (set MALWAREBAZAAR_AUTH_KEY to opt in)")

    for proc in psutil.process_iter():
        safe_value(proc.cpu_percent)

    try:
        while True:
            started = time.monotonic()
            processes = collect_processes()
            connections = collect_connections()
            event = {
                "timestamp": get_timestamp(),
                "hostname": socket.gethostname(),  # hostname string, not a PID dict
                "os": os.name, "event_type": "system_snapshot",
                "process_count": len(processes), "processes": processes,
                "connections": connections,
            }
            write_jsonl(OUTPUT_FILE, event)
            SESSION["snapshots"] += 1

            # PID 0 is the idle process; its CPU value is idle capacity, not load.
            for proc in processes:
                pid = proc.get("pid")
                if pid in (None, 0):
                    continue
                try:
                    cpu = float(proc.get("cpu_percent") or 0)
                except (TypeError, ValueError):
                    continue
                row = CPU_TOTALS.setdefault(pid, {"pid": pid, "name": proc.get("name") or "unknown", "total_cpu": 0.0, "samples": 0})
                row["name"] = proc.get("name") or row["name"]
                row["total_cpu"] += cpu
                row["samples"] += 1
                row["average_cpu"] = row["total_cpu"] / row["samples"]

            # Keep CPU streak counters across snapshots during this run only.
            alerts = detect(event, cpu_streaks=CPU_STREAKS,
                            connection_streaks=CONNECTION_STREAKS)
            for alert in alerts:
                # Hash lookup runs in a background worker and never uploads the executable.
                alert = THREAT_INTEL.enrich_alert(alert)
                print("ALERT:", format_alert(alert))
                write_jsonl(ALERT_FILE, {"event_type": "detection_alert", **alert})
                SESSION["alerts"] += 1
                SESSION[alert["severity"]] += 1

            top = sorted((p for p in processes if p.get("pid") != 0),
                         key=lambda p: p["cpu_percent"] or 0, reverse=True)[:5]
            print(f"\nTime: {event['timestamp']} | Host: {event['hostname']} | Processes: {len(processes)} | Connections: {len(connections)} | Alerts: {len(alerts)}")
            print("Top CPU processes:")
            for proc in top:
                print(f"  PID={proc['pid']:<7} CPU={proc['cpu_percent']:>6.1f}% RAM={proc['memory_percent'] or 0:>5.1f}% Name={proc['name']}")
            time.sleep(max(0, INTERVAL - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("\nStopped. Log saved to:", OUTPUT_FILE)
        print_session_summary()


if __name__ == "__main__":
    main()
