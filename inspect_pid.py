"""Inspect a PID in the most recent CryptoMinerDetector snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_LOG = Path(__file__).resolve().parent / "data" / "system_events.jsonl"


def latest_snapshot(path: Path) -> dict[str, Any] | None:
    """Read the last valid system_snapshot JSON object from a JSONL file."""
    if not path.is_file():
        return None
    latest = None
    with path.open("r", encoding="utf-8-sig") as log_file:
        for line in log_file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("event_type") == "system_snapshot":
                latest = event
    return latest


def find_process(snapshot: dict[str, Any], pid: int) -> dict[str, Any] | None:
    for proc in snapshot.get("processes", []):
        if not isinstance(proc, dict):
            continue
        try:
            if int(proc.get("pid")) == pid:
                return proc
        except (TypeError, ValueError):
            continue
    return None


def connections_for_pid(snapshot: dict[str, Any], pid: int) -> list[dict[str, Any]]:
    found = []
    for conn in snapshot.get("connections", []):
        if not isinstance(conn, dict):
            continue
        try:
            if int(conn.get("pid")) == pid:
                found.append(conn)
        except (TypeError, ValueError):
            continue
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Tra cứu PID trong snapshot gần nhất (chỉ đọc log).")
    parser.add_argument("pid", type=int, help="PID cần tra cứu")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="Đường dẫn system_events.jsonl")
    args = parser.parse_args()

    snapshot = latest_snapshot(args.log)
    if snapshot is None:
        print(f"Không tìm thấy snapshot hợp lệ trong: {args.log}")
        return 2

    proc = find_process(snapshot, args.pid)
    if proc is None:
        print(f"PID {args.pid} không có trong snapshot mới nhất ({snapshot.get('timestamp')}).")
        print("Tiến trình có thể đã kết thúc hoặc PID đã thay đổi; hãy kiểm tra snapshot cũ hơn hoặc chụp mẫu mới.")
        return 1

    print("=== Process from latest snapshot ===")
    print("Timestamp:", snapshot.get("timestamp"))
    print("Hostname:", snapshot.get("hostname"))
    for key in ("pid", "ppid", "name", "exe", "username", "status", "cpu_percent", "memory_percent", "create_time"):
        print(f"{key}:", proc.get(key))

    connections = connections_for_pid(snapshot, args.pid)
    print(f"Connections ({len(connections)}):")
    if not connections:
        print("  (none recorded for this PID in the latest snapshot)")
    for conn in connections:
        if conn.get("error"):
            print("  collection error:", conn["error"])
            continue
        print(f"  {conn.get('status')} {conn.get('local_address')} -> {conn.get('remote_address')}")
    print("Note: this is historical snapshot data; it does not verify the PID's current identity or reputation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
