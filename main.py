import json
import os
import re
import subprocess
import socket
import time
from datetime import datetime, timezone

from detection.trace import trace_alert
import psutil
from detection.rule_engine import detect, format_alert
from detection.threat_intel import ThreatIntelClient

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "system_events.jsonl")
ALERT_FILE = os.path.join(OUTPUT_DIR, "alerts.jsonl")
INTERVAL = 3
CPU_STREAKS = {}
IDLE_CPU_STREAKS = {}
GPU_STREAKS = {}
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


MINER_COMMAND_LINE_MARKERS = {
    "STRATUM_POOL_URI": ("stratum+tcp://", "stratum+ssl://", "stratum+tls://", "stratum://"),
}


def get_command_line_indicators(proc):
    command_parts = safe_value(proc.cmdline, []) or []
    if not isinstance(command_parts, (list, tuple)):
        return []
    command_text = " ".join(str(part) for part in command_parts).casefold()
    return [
        indicator
        for indicator, markers in MINER_COMMAND_LINE_MARKERS.items()
        if any(marker in command_text for marker in markers)
    ]


def collect_gpu_usage_by_pid():
    """Return the highest Windows GPU-engine utilization grouped by PID."""
    if os.name != "nt":
        return {}
    command = r"$ErrorActionPreference='Stop'; (Get-Counter '\GPU Engine(*)\Utilization Percentage').CounterSamples | Select-Object InstanceName,CookedValue | ConvertTo-Json -Compress"
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        samples = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        return {}

    if isinstance(samples, dict):
        samples = [samples]
    if not isinstance(samples, list):
        return {}
    usage_by_pid_and_engine = {}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        instance = str(sample.get("InstanceName") or "")
        match = re.match(r"pid_(\d+)_.*_engtype_(.*)$", instance, re.IGNORECASE)
        if not match:
            continue
        try:
            pid = int(match.group(1))
            percent = max(0.0, float(sample.get("CookedValue") or 0))
        except (TypeError, ValueError):
            continue
        engine_type = match.group(2).strip().casefold() or "unknown"
        key = (pid, engine_type)
        usage_by_pid_and_engine[key] = usage_by_pid_and_engine.get(key, 0.0) + percent

    best_by_pid = {}
    for (pid, engine_type), percent in usage_by_pid_and_engine.items():
        candidate = {"percent": round(min(percent, 100.0), 1), "engine_type": engine_type}
        if pid not in best_by_pid or candidate["percent"] > best_by_pid[pid]["percent"]:
            best_by_pid[pid] = candidate
    return best_by_pid


def collect_processes():
    processes = []
    psutil.cpu_percent(interval=None)
    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                processes.append({
                    "timestamp": get_timestamp(), "pid": proc.pid,
                    "ppid": safe_value(proc.ppid), "name": safe_value(proc.name),
                    "command_line_indicators": get_command_line_indicators(proc),
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


def main(stop_event=None, event_callback=None):
    def emit(kind, payload):
        if event_callback is not None:
            event_callback(kind, payload)
        elif kind == "alert":
            print(payload["formatted"])
        elif kind in {"info", "stopped", "error"}:
            print(payload)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    emit("info", "=== CryptoMiner Detector ===")
    emit("info", f"OS: {os.name} | Host: {socket.gethostname()}")
    emit("info", f"Snapshot log: {OUTPUT_FILE} | Alerts: {ALERT_FILE}")
    emit("info", f"Sampling interval: {INTERVAL} seconds")
    emit("info", "MalwareBazaar: " + ("enabled" if THREAT_INTEL.enabled else "disabled"))

    psutil.cpu_percent(interval=None)
    for proc in psutil.process_iter():
        safe_value(proc.cpu_percent)

    try:
        while stop_event is None or not stop_event.is_set():
            started = time.monotonic()
            processes = collect_processes()
            connections = collect_connections()
            system_cpu_percent = psutil.cpu_percent(interval=None)
            gpu_usage_by_pid = collect_gpu_usage_by_pid()
            for process in processes:
                gpu_usage = gpu_usage_by_pid.get(process.get("pid"), {})
                process["gpu_engine_percent"] = gpu_usage.get("percent")
                process["gpu_engine_type"] = gpu_usage.get("engine_type")
            event = {
                "timestamp": get_timestamp(), "hostname": socket.gethostname(),
                "os": os.name, "event_type": "system_snapshot",
                "system_cpu_percent": system_cpu_percent,
                "process_count": len(processes), "processes": processes,
                "connections": connections,
            }
            write_jsonl(OUTPUT_FILE, event)
            SESSION["snapshots"] += 1

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

            alerts = detect(event, cpu_streaks=CPU_STREAKS,
                            connection_streaks=CONNECTION_STREAKS,
                            idle_cpu_streaks=IDLE_CPU_STREAKS,
                            gpu_streaks=GPU_STREAKS)
            by_pid = {p["pid"]: p for p in processes} if alerts else {}
            for alert in alerts:
                alert["trace"] = trace_alert(alert, by_pid, connections)
                alert = THREAT_INTEL.enrich_alert(alert)
                formatted = format_alert(alert)
                emit("alert", {"formatted": formatted, "alert": alert})
                write_jsonl(ALERT_FILE, {"event_type": "detection_alert", **alert})
                SESSION["alerts"] += 1
                SESSION[alert["severity"]] += 1

            top = sorted((p for p in processes if p.get("pid") != 0),
                         key=lambda p: p.get("cpu_percent") or 0, reverse=True)[:5]
            status = {
                "timestamp": event["timestamp"], "hostname": event["hostname"],
                "processes": len(processes), "connections": len(connections),
                "alerts": SESSION["alerts"], "system_cpu_percent": system_cpu_percent,
                "top_cpu": [{"pid": p.get("pid"), "name": p.get("name"),
                             "cpu": p.get("cpu_percent") or 0,
                             "gpu": p.get("gpu_engine_percent")} for p in top],
            }
            emit("status", status)
            delay = max(0, INTERVAL - (time.monotonic() - started))
            if stop_event is None:
                time.sleep(delay)
            else:
                stop_event.wait(delay)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        emit("error", f"Monitor error: {type(exc).__name__}: {exc}")
        raise
    finally:
        emit("stopped", f"Stopped. Snapshot log: {OUTPUT_FILE} | Alert log: {ALERT_FILE}")


if __name__ == "__main__":
    main()