"""Read-only integrity and summary report for CryptoMinerDetector JSONL logs."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_SNAPSHOTS = ROOT / "data" / "system_events.jsonl"
DEFAULT_ALERTS = ROOT / "data" / "alerts.jsonl"
DEFAULT_CSV = ROOT / "data" / "session_report.csv"
CPU_REVIEW_CSV = ROOT / "data" / "process_cpu_review.csv"
CPU_REVIEW_THRESHOLD = 80.0


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[int], int]:
    """Return valid object rows, malformed line numbers, and non-object row count."""
    records: list[dict[str, Any]] = []
    malformed: list[int] = []
    non_objects = 0
    if not path.is_file():
        return records, malformed, non_objects
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                malformed.append(line_number)
                continue
            if isinstance(row, dict):
                records.append(row)
            else:
                non_objects += 1
    return records, malformed, non_objects


def summarize(snapshot_path: Path, alert_path: Path) -> dict[str, Any]:
    snapshots, bad_snapshots, non_object_snapshots = read_jsonl(snapshot_path)
    alerts, bad_alerts, non_object_alerts = read_jsonl(alert_path)
    snapshots = [row for row in snapshots if row.get("event_type") == "system_snapshot"]
    alerts = [row for row in alerts if row.get("event_type") == "detection_alert"]
    severity_counts = Counter(str(row.get("severity", "unknown")).lower() for row in alerts)
    latest_by_severity = {}
    for alert in alerts:
        severity = str(alert.get("severity", "unknown")).lower()
        latest_by_severity[severity] = alert
    return {
        "snapshot_path": snapshot_path,
        "alert_path": alert_path,
        "snapshots": snapshots,
        "alerts": alerts,
        "severity_counts": severity_counts,
        "latest_by_severity": latest_by_severity,
        "snapshot_errors": (bad_snapshots, non_object_snapshots),
        "alert_errors": (bad_alerts, non_object_alerts),
    }


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_session_rows(result: dict[str, Any], gap_seconds: int = 60,
                       latest_sessions: int | None = None) -> list[dict[str, Any]]:
    """Group snapshots by timestamp gaps and count alerts per nearest prior sample."""
    snapshots = result["snapshots"]
    groups: list[list[dict[str, Any]]] = []
    previous_time = None
    for snapshot in snapshots:
        current_time = parse_time(snapshot.get("timestamp"))
        if groups and current_time is not None and previous_time is not None:
            try:
                gap = (current_time - previous_time).total_seconds()
            except TypeError:  # timestamps with/without a timezone
                gap = 0
            if gap > gap_seconds:
                groups.append([])
        if not groups:
            groups.append([])
        groups[-1].append(snapshot)
        previous_time = current_time

    if latest_sessions is not None:
        groups = groups[-latest_sessions:]

    rows = []
    for session_number, group in enumerate(groups, 1):
        times = [parse_time(s.get("timestamp")) for s in group]
        times = [t for t in times if t is not None]
        start = min(times).isoformat() if times else ""
        end = max(times).isoformat() if times else ""
        session_alerts = []
        next_session_start = None
        if session_number < len(groups):
            next_group_times = [parse_time(s.get("timestamp")) for s in groups[session_number]]
            next_group_times = [t for t in next_group_times if t is not None]
            next_session_start = min(next_group_times) if next_group_times else None
        if times:
            for alert in result["alerts"]:
                alert_time = parse_time(alert.get("timestamp"))
                if alert_time is None:
                    continue
                for index, snapshot_time in enumerate(times):
                    next_time = times[index + 1] if index + 1 < len(times) else None
                    try:
                        belongs = snapshot_time <= alert_time and (next_time is None or alert_time < next_time)
                        if belongs and next_time is None and next_session_start is not None:
                            belongs = alert_time < next_session_start
                    except TypeError:
                        belongs = False
                    if belongs:
                        session_alerts.append(alert)
                        break
        severity = Counter(str(alert.get("severity", "unknown")).lower() for alert in session_alerts)
        rows.append({
            "session": session_number,
            "hostname": group[-1].get("hostname", "unknown"),
            "start": start,
            "end": end,
            "snapshot_count": len(group),
            "processes_last": group[-1].get("process_count", ""),
            "connections_last": len(group[-1].get("connections", [])) if isinstance(group[-1].get("connections"), list) else "",
            "alerts": len(session_alerts),
            "high": severity.get("high", 0),
            "medium": severity.get("medium", 0),
            "low": severity.get("low", 0),
        })
    return rows


def export_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columns = ["row_type", "session", "hostname", "start", "end", "snapshot_count",
               "processes_last", "connections_last", "alerts", "high", "medium", "low",
               "alert_time", "pid", "process_name", "score", "severity", "indicators", "message"]
    # utf-8-sig helps Excel open Vietnamese text correctly.
    with output_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def build_process_cpu_rows(snapshots: list[dict[str, Any]], threshold: float = CPU_REVIEW_THRESHOLD,
                           latest_sessions: int | None = None,
                           gap_seconds: int = 60) -> list[dict[str, Any]]:
    """Aggregate observed CPU per process identity; excludes Windows PID 0 idle process."""
    # Reuse session splitting to respect the requested recent-session limit.
    groups: list[list[dict[str, Any]]] = []
    previous_time = None
    for snapshot in snapshots:
        current_time = parse_time(snapshot.get("timestamp"))
        if groups and current_time is not None and previous_time is not None:
            try:
                is_new = (current_time - previous_time).total_seconds() > gap_seconds
            except TypeError:
                is_new = False
            if is_new:
                groups.append([])
        if not groups:
            groups.append([])
        groups[-1].append(snapshot)
        previous_time = current_time
    if latest_sessions is not None:
        groups = groups[-latest_sessions:]

    totals: dict[tuple[Any, ...], dict[str, Any]] = {}
    for session_index, group in enumerate(groups, 1):
        for snapshot in group:
            timestamp = snapshot.get("timestamp", "")
            for proc in snapshot.get("processes", []):
                if not isinstance(proc, dict):
                    continue
                try:
                    pid = int(proc.get("pid"))
                    cpu = float(proc.get("cpu_percent") or 0)
                except (TypeError, ValueError):
                    continue
                if pid == 0:
                    continue
                name = str(proc.get("name") or "unknown")
                created = proc.get("create_time")
                identity = (session_index, pid, name.lower(), created)
                row = totals.setdefault(identity, {
                    "session": session_index, "hostname": snapshot.get("hostname", "unknown"),
                    "pid": pid, "process_name": name, "exe": proc.get("exe") or "",
                    "username": proc.get("username") or "", "create_time": created or "",
                    "samples": 0, "cpu_sum": 0.0, "cpu_max": 0.0,
                    "samples_at_or_above_threshold": 0, "first_seen": timestamp,
                    "last_seen": timestamp,
                })
                row["samples"] += 1
                row["cpu_sum"] += cpu
                row["cpu_max"] = max(row["cpu_max"], cpu)
                row["samples_at_or_above_threshold"] += cpu >= threshold
                row["last_seen"] = timestamp
    rows = []
    for row in totals.values():
        row["cpu_average"] = round(row["cpu_sum"] / row["samples"], 2)
        row["cpu_max"] = round(row["cpu_max"], 2)
        row["threshold_percent"] = threshold
        row["high_cpu_share_percent"] = round(100 * row["samples_at_or_above_threshold"] / row["samples"], 1)
        row.pop("cpu_sum")
        rows.append(row)
    return sorted(rows, key=lambda row: (row["samples_at_or_above_threshold"], row["cpu_average"]), reverse=True)


def export_process_cpu_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    columns = ["session", "hostname", "pid", "process_name", "exe", "username", "create_time",
               "samples", "cpu_average", "cpu_max", "threshold_percent",
               "samples_at_or_above_threshold", "high_cpu_share_percent", "first_seen", "last_seen"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def print_report(result: dict[str, Any]) -> None:
    snapshots = result["snapshots"]
    alerts = result["alerts"]
    print("=== CryptoMinerDetector log review (read-only) ===")
    print("Snapshot file:", result["snapshot_path"])
    print("Alert file:", result["alert_path"])
    print("Valid snapshots:", len(snapshots))
    if snapshots:
        print("Snapshot time range:", snapshots[0].get("timestamp"), "to", snapshots[-1].get("timestamp"))
        print("Latest host:", snapshots[-1].get("hostname", "unknown"))
    print("Valid alerts:", len(alerts))
    counts = result["severity_counts"]
    print(f"Severity counts: high={counts.get('high', 0)}, medium={counts.get('medium', 0)}, low={counts.get('low', 0)}")
    if alerts:
        print("Latest alerts by severity:")
        for severity in ("high", "medium", "low"):
            alert = result["latest_by_severity"].get(severity)
            if alert:
                print(f"  {severity.upper()}: time={alert.get('timestamp')} host={alert.get('hostname')} pid={alert.get('pid')} process={alert.get('process_name')} score={alert.get('score')}")
                print("    Indicators:", ", ".join(item.get("rule_id", "unknown") for item in alert.get("indicators", [])))
    for label, (malformed, non_objects) in (("Snapshots", result["snapshot_errors"]), ("Alerts", result["alert_errors"])):
        print(f"{label} parse issues: malformed JSON lines={len(malformed)}, non-object JSON rows={non_objects}")
        if malformed:
            print("  Malformed line numbers:", ", ".join(map(str, malformed[:20])))
    if not snapshots:
        print("No valid system snapshots found. Run main.py to begin collecting.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Kiểm tra log JSONL, chỉ đọc và không sửa file.")
    parser.add_argument("--snapshots", type=Path, default=DEFAULT_SNAPSHOTS)
    parser.add_argument("--alerts", type=Path, default=DEFAULT_ALERTS)
    parser.add_argument("--export-csv", type=Path, help="Xuất báo cáo phiên chạy ra CSV.")
    parser.add_argument("--gap-seconds", type=int, default=60,
                        help="Khoảng nghỉ lớn hơn mức này được coi là phiên mới (mặc định 60).")
    parser.add_argument("--latest-sessions", type=int,
                        help="Chỉ xuất N phiên gần nhất.")
    parser.add_argument("--export-process-cpu", type=Path,
                        help="Xuất CSV tổng hợp CPU theo tiến trình.")
    parser.add_argument("--cpu-threshold", type=float, default=CPU_REVIEW_THRESHOLD,
                        help="Ngưỡng CPU phần trăm để đếm mẫu cao (mặc định 80).")
    args = parser.parse_args()
    result = summarize(args.snapshots, args.alerts)
    print_report(result)
    if args.export_csv:
        rows = build_session_rows(result, max(0, args.gap_seconds), args.latest_sessions)
        # Add per-alert detail rows so the CSV is useful for investigation too.
        detail_rows = []
        for session_row in rows:
            detail_rows.append({"row_type": "session_summary", **session_row})
        for alert in result["alerts"]:
            alert_time = parse_time(alert.get("timestamp"))
            alert_session = None
            for index, session_row in enumerate(rows):
                start_time, end_time = parse_time(session_row.get("start")), parse_time(session_row.get("end"))
                next_start = parse_time(rows[index + 1].get("start")) if index + 1 < len(rows) else None
                if not (alert_time and start_time and end_time):
                    continue
                try:
                    if start_time <= alert_time and (next_start is None or alert_time < next_start):
                        alert_session = session_row["session"]
                        break
                except TypeError:
                    continue
            if alert_session is None:
                continue
            detail_rows.append({
                "row_type": "alert_detail",
                "session": alert_session,
                "hostname": alert.get("hostname", ""),
                "alert_time": alert.get("timestamp", ""),
                "pid": alert.get("pid", ""),
                "process_name": alert.get("process_name", ""),
                "score": alert.get("score", ""),
                "severity": alert.get("severity", ""),
                "indicators": ", ".join(
                    str(item.get("rule_id", "unknown"))
                    for item in alert.get("indicators", [])
                ),
                "message": alert.get("message", ""),
            })
        export_csv(detail_rows, args.export_csv)
        print(f"CSV exported: {args.export_csv} ({len(rows)} sessions, {sum(r.get('row_type') == 'alert_detail' for r in detail_rows)} alert details)")
    if args.export_process_cpu:
        cpu_rows = build_process_cpu_rows(result["snapshots"], args.cpu_threshold,
                                          args.latest_sessions, max(0, args.gap_seconds))
        export_process_cpu_csv(cpu_rows, args.export_process_cpu)
        print(f"Process CPU CSV exported: {args.export_process_cpu} ({len(cpu_rows)} process identities; PID 0 excluded)")
    return 0 if result["snapshots"] or result["alerts"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
