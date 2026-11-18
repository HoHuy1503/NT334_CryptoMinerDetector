"""Explainable alert-only rules for CryptoMinerDetector."""
from __future__ import annotations
import ipaddress
import os
from typing import Any

SUSPICIOUS_PROCESS_NAMES = {"xmrig", "minerd", "cpuminer", "phoenixminer", "nbminer", "lolminer", "teamredminer", "gminer", "t-rex", "trex"}
COMMON_POOL_PORTS = {3333, 4444, 5555, 7777, 14444, 14433}
CPU_HIGH_PERCENT = 80.0
CPU_HIGH_STREAK = 5
IDLE_SYSTEM_CPU_MAX = 20.0
PROCESS_CPU_WHILE_IDLE_MIN = 20.0
IDLE_CPU_REQUIRED_SAMPLES = 10
GPU_HIGH_PERCENT = 60.0
GPU_HIGH_REQUIRED_SAMPLES = 10
PUBLIC_CONNECTION_STREAK = 10
INACTIVE_CONNECTION_STATES = {
    "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2",
    "CLOSING", "CLOSED", "LAST_ACK",
}
LOW_REPUTATION_PATHS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
                        "\\windows\\temp\\", "\\users\\public\\")


def _get_port(address: Any) -> int | None:
    if not isinstance(address, str) or not address:
        return None
    try:
        return int(address.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def _get_remote_ip(address: Any) -> str | None:
    if not isinstance(address, str) or not address:
        return None
    host = address.rsplit(":", 1)[0]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _process_identity(proc: dict[str, Any], pid: int) -> tuple[Any, ...]:
    """PID plus creation time and executable/name to avoid PID reuse mixing state."""
    return (pid, proc.get("create_time"),
            str(proc.get("exe") or "").casefold(),
            str(proc.get("name") or "").casefold())


def detect(snapshot: dict[str, Any], cpu_streaks: dict[Any, int] | None = None,
           connection_streaks: dict[Any, dict[str, int]] | None = None,
           idle_cpu_streaks: dict[Any, int] | None = None,
           gpu_streaks: dict[Any, int] | None = None) -> list[dict[str, Any]]:
    """Evaluate a snapshot. Pass a persistent cpu_streaks dict between calls.

    The caller owns this in-memory state; no process is ever changed or stopped.
    """
    hostname = snapshot.get("hostname")
    if not isinstance(hostname, str) or not hostname:
        hostname = os.environ.get("COMPUTERNAME", "unknown")
    processes = snapshot.get("processes", [])
    connections = snapshot.get("connections", [])
    if not isinstance(processes, list):
        return []
    if not isinstance(connections, list):
        connections = []

    by_pid: dict[int, list[dict[str, Any]]] = {}
    for conn in connections:
        if not isinstance(conn, dict) or conn.get("pid") is None:
            continue
        try:
            by_pid.setdefault(int(conn["pid"]), []).append(conn)
        except (TypeError, ValueError):
            continue

    alerts = []
    process_identities: dict[int, tuple[Any, ...]] = {}
    for process in processes:
        if isinstance(process, dict):
            try:
                process_pid = int(process["pid"])
            except (KeyError, TypeError, ValueError):
                continue
            process_identities[process_pid] = _process_identity(process, process_pid)

    current_cpu_identities = set(process_identities.values())
    if gpu_streaks is not None:
        for previous_identity in list(gpu_streaks):
            if previous_identity not in current_cpu_identities:
                gpu_streaks.pop(previous_identity, None)
    if idle_cpu_streaks is not None:
        for previous_identity in list(idle_cpu_streaks):
            if previous_identity not in current_cpu_identities:
                idle_cpu_streaks.pop(previous_identity, None)
    if cpu_streaks is not None:
        for previous_identity in list(cpu_streaks):
            if previous_identity not in current_cpu_identities:
                cpu_streaks.pop(previous_identity, None)

    observed_public: dict[tuple[Any, ...], set[str]] = {}
    if connection_streaks is not None:
        for conn in connections:
            if not isinstance(conn, dict) or str(conn.get("status", "")).upper() != "ESTABLISHED":
                continue
            try:
                connection_pid = int(conn.get("pid"))
            except (TypeError, ValueError):
                continue
            identity = process_identities.get(connection_pid)
            remote_ip = _get_remote_ip(conn.get("remote_address"))
            if identity is None or remote_ip is None:
                continue
            try:
                is_public = ipaddress.ip_address(remote_ip).is_global
            except ValueError:
                is_public = False
            if is_public:
                observed_public.setdefault(identity, set()).add(remote_ip)

        next_connection_streaks = {}
        for identity, endpoints in observed_public.items():
            previous = connection_streaks.get(identity, {})
            next_connection_streaks[identity] = {
                endpoint: previous.get(endpoint, 0) + 1 for endpoint in endpoints
            }
        connection_streaks.clear()
        connection_streaks.update(next_connection_streaks)

    for proc in processes:
        if not isinstance(proc, dict):
            continue
        try:
            pid = int(proc["pid"]) if proc.get("pid") is not None else None
        except (TypeError, ValueError):
            pid = None
        name = str(proc.get("name") or "unknown")
        identity = _process_identity(proc, pid) if pid is not None else None
        exe = str(proc.get("exe") or "")
        try:
            cpu_percent = float(proc.get("cpu_percent") or 0)
        except (TypeError, ValueError):
            cpu_percent = 0.0
        common = {"timestamp": snapshot.get("timestamp"), "hostname": hostname,
                  "pid": pid, "process_name": name,
                  "process_created_at": proc.get("create_time"), "executable_path": exe}

        indicators = []
        score = 0

        if cpu_streaks is not None and identity is not None:
            if cpu_percent >= CPU_HIGH_PERCENT:
                cpu_streaks[identity] = cpu_streaks.get(identity, 0) + 1
            else:
                cpu_streaks.pop(identity, None)
            if cpu_streaks.get(identity, 0) >= CPU_HIGH_STREAK:
                score += 25
                indicators.append({"rule_id": "SUSTAINED_HIGH_CPU", "points": 25,
                    "details": {"cpu_percent": cpu_percent,
                                "consecutive_samples": cpu_streaks[identity],
                                "threshold_percent": CPU_HIGH_PERCENT,
                                "required_samples": CPU_HIGH_STREAK}})

        if idle_cpu_streaks is not None and identity is not None:
            try:
                system_cpu = float(snapshot.get("system_cpu_percent"))
            except (TypeError, ValueError):
                system_cpu = None
            if (system_cpu is not None and system_cpu <= IDLE_SYSTEM_CPU_MAX
                    and cpu_percent >= PROCESS_CPU_WHILE_IDLE_MIN):
                idle_cpu_streaks[identity] = idle_cpu_streaks.get(identity, 0) + 1
            else:
                idle_cpu_streaks.pop(identity, None)
            if idle_cpu_streaks.get(identity, 0) >= IDLE_CPU_REQUIRED_SAMPLES:
                score += 20
                indicators.append({"rule_id": "SUSTAINED_PROCESS_CPU_WHILE_SYSTEM_IDLE", "points": 20,
                    "details": {"process_cpu_percent": cpu_percent, "system_cpu_percent": system_cpu,
                                "consecutive_samples": idle_cpu_streaks[identity],
                                "required_samples": IDLE_CPU_REQUIRED_SAMPLES}})

        if gpu_streaks is not None and identity is not None:
            try:
                gpu_percent = float(proc.get("gpu_engine_percent"))
            except (TypeError, ValueError):
                gpu_percent = 0.0
            if gpu_percent >= GPU_HIGH_PERCENT:
                gpu_streaks[identity] = gpu_streaks.get(identity, 0) + 1
            else:
                gpu_streaks.pop(identity, None)
            if gpu_streaks.get(identity, 0) >= GPU_HIGH_REQUIRED_SAMPLES:
                score += 20
                indicators.append({"rule_id": "SUSTAINED_GPU_ENGINE_ACTIVITY", "points": 20,
                    "details": {"gpu_engine_percent": gpu_percent,
                                "gpu_engine_type": proc.get("gpu_engine_type"),
                                "consecutive_samples": gpu_streaks[identity],
                                "required_samples": GPU_HIGH_REQUIRED_SAMPLES,
                                "note": "Sustained GPU activity can also come from games or compute workloads."}})

        normalized_exe = exe.replace("/", "\\").casefold()
        path_markers = [marker for marker in LOW_REPUTATION_PATHS if marker in normalized_exe]
        if path_markers:
            score += 15
            indicators.append({"rule_id": "EXECUTABLE_IN_USER_TEMP_LOCATION", "points": 15,
                "details": {"executable_path": exe, "matched_location_patterns": path_markers,
                            "note": "Location is an investigation hint, not proof of maliciousness."}})

        normalized_name = name.replace(chr(92), "/").rsplit("/", 1)[-1].casefold()
        if normalized_name.endswith(".exe"):
            normalized_name = normalized_name[:-4]

        if normalized_name in SUSPICIOUS_PROCESS_NAMES:
            score += 60
            indicators.append({"rule_id": "MINER_PROCESS_NAME", "points": 60,
                "details": {
                    "matched_name": name,
                    "normalized_name": normalized_name,
                    "match": "exact, case-insensitive, optional .exe suffix removed",
                }})
        command_line_indicators = proc.get("command_line_indicators", [])
        if isinstance(command_line_indicators, list) and "STRATUM_POOL_URI" in command_line_indicators:
            score += 40
            indicators.append({"rule_id": "MINING_STRATUM_COMMAND_LINE", "points": 40,
                "details": {"matched_pattern": "stratum pool URI", "raw_command_line_logged": False}})

        matches = []
        for conn in by_pid.get(pid, []) if pid is not None else []:
            status = str(conn.get("status") or "").upper()
            if status in INACTIVE_CONNECTION_STATES:
                continue
            port = _get_port(conn.get("remote_address"))
            if port in COMMON_POOL_PORTS:
                matches.append({"remote_address": conn.get("remote_address"),
                                "status": conn.get("status"), "matched_port": port})
        if matches:
            score += 30
            indicators.append({"rule_id": "MINING_POOL_PORT", "points": 30,
                "details": {"connections": matches,
                            "matched_ports": sorted(COMMON_POOL_PORTS)}})

        persistent_endpoints = []
        if connection_streaks is not None and identity is not None:
            persistent_endpoints = [
                {"remote_ip": endpoint, "consecutive_samples": count}
                for endpoint, count in connection_streaks.get(identity, {}).items()
                if count >= PUBLIC_CONNECTION_STREAK
            ]
        if persistent_endpoints:
            score += 15
            indicators.append({"rule_id": "PERSISTENT_EXTERNAL_CONNECTION", "points": 15,
                "details": {"endpoints": persistent_endpoints,
                            "required_samples": PUBLIC_CONNECTION_STREAK,
                            "note": "Persistent public-IP traffic is common in legitimate software too."}})

        if indicators:
            score = min(score, 100)
            if score >= 60:
                severity = "high"
            elif score >= 25:
                severity = "medium"
            else:
                severity = "low"
            alerts.append({**common, "rule_id": "PROCESS_RISK_SUMMARY",
                "severity": severity, "score": score,
                "message": "Điểm ưu tiên kiểm tra dựa trên các dấu hiệu bên dưới; đây không phải kết luận chắc chắn có miner.",
                "indicators": indicators})
    return alerts


def format_alert(alert: dict[str, Any]) -> str:
    rules = ",".join(item["rule_id"] for item in alert.get("indicators", []))
    return (f"[{alert['severity'].upper()}] score={alert.get('score', 0)} "
            f"rules={rules} | "
            f"host={alert['hostname']} pid={alert['pid']} "
            f"process={alert['process_name']} | {alert['message']}")
