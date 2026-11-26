"""Local evidence captured when an alert is recorded on Windows."""
import ntpath
import os
from datetime import datetime
from urllib.parse import urlsplit


def local_time(value):
    try:
        return datetime.fromtimestamp(value).astimezone().isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def trace_alert(alert, processes, connections):
    pid = alert.get("pid")
    proc = processes.get(pid, {})
    parent = processes.get(proc.get("ppid"), {})
    if (parent.get("create_time") or 0) > (proc.get("create_time") or 0):
        parent = {}
    trace = {
        "parent_pid": proc.get("ppid"), "parent_name": parent.get("name"),
        "parent_path": parent.get("exe"), "file_created": None, "download_host": None,
        "connections": sorted({str(c["remote_address"]) for c in connections
                               if c.get("pid") == pid and c.get("remote_address")
                               and c.get("status") == "ESTABLISHED"}),
    }
    path = alert.get("executable_path") or ""
    # Read local drive files only. Network paths can trigger authentication.
    if os.name != "nt" or len(ntpath.splitdrive(path)[0]) != 2 or not ntpath.isabs(path):
        return trace
    try:
        stat = os.stat(path)
        trace["file_created"] = local_time(getattr(stat, "st_birthtime", stat.st_ctime))
        with open(path + ":Zone.Identifier", "rb") as stream:
            lines = stream.read(8192).decode("utf-8-sig", errors="replace").splitlines()
        for line in lines:
            key, _, value = line.partition("=")
            if key.strip().lower() == "hosturl":
                trace["download_host"] = urlsplit(value.strip()).hostname
                break
    except (OSError, ValueError):
        pass
    return trace


def trace_text(alert):
    trace = alert.get("trace", {})
    missing = "Chưa có dữ liệu"
    return "\n".join([
        f"Tiến trình: {alert.get('process_name')} (PID {alert.get('pid')})",
        f"Ghi nhận: {alert.get('timestamp')}",
        f"Tệp thực thi: {alert.get('executable_path') or missing}",
        f"Thời điểm tạo tệp trên ổ hiện tại: {trace.get('file_created') or missing}",
        f"Tiến trình bắt đầu: {local_time(alert.get('process_created_at')) or missing}",
        f"Nguồn tải do Windows lưu: {trace.get('download_host') or missing}",
        f"PID cha: {trace.get('parent_pid')} | {trace.get('parent_path') or trace.get('parent_name') or missing}",
        "Đầu mạng kết nối tại lúc cảnh báo: " + (", ".join(trace.get("connections", [])) or missing),
        "",
        "Thời điểm tạo tệp có thể thay đổi khi sao chép. Đầu mạng đang kết nối chưa xác định ai khởi chạy tiến trình.",
        "Để điều tra chạy từ xa, đối chiếu giờ khởi chạy với nhật ký Security 4688 và phiên đăng nhập 4624 qua Logon ID khi có dữ liệu kiểm toán.",
        "Nếu nghi máy đang bị điều khiển, hãy ngắt mạng để cô lập. Nếu đã xác minh tệp, mở Windows Defender Firewall with Advanced Security (wf.msc), tạo Outbound Rule kiểu Program, chọn đúng đường dẫn rồi chọn Block the connection. Quy tắc chặn kết nối đi, tiến trình vẫn có thể chạy.",
    ])