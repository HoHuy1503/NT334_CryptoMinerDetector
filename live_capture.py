"""Record one local interface and store J48 results in PCAPNG section comments."""
import csv
import io
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import threading
from datetime import datetime

from pcap_panel import EVIDENCE, FIELDS, ROOT, analyze

DUMPCAP = shutil.which("dumpcap") or r"C:\Program Files\Wireshark\dumpcap.exe"


def interfaces():
    result = subprocess.run([DUMPCAP, "-D"], capture_output=True, text=True,
                            errors="replace", timeout=10, check=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return [line.split(". ", 1)[1] for line in result.stdout.splitlines() if ". " in line]


def interface_names(entries):
    """Map dumpcap display descriptions to their original capture IDs."""
    names = {}
    for entry in entries:
        device, separator, description = entry.partition(" (")
        label = description.removesuffix(")") if separator else device
        if device.casefold().endswith("npf_loopback"):
            label = "Loopback"
        base = label
        number = 1
        while label in names:
            number += 1
            label = f"{base} ({number})"
        names[label] = device
    return names


def record(interface, path, stop):
    # The helper owns a separate hidden console so Ctrl+Break reaches dumpcap only there.
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    with subprocess.Popen([sys.executable, __file__, interface, str(path)],
                          stdin=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startup,
                          creationflags=subprocess.CREATE_NEW_CONSOLE) as helper:
        while helper.poll() is None and not stop.wait(0.2):
            pass
        _, error = helper.communicate()
        if helper.returncode:
            raise RuntimeError(error.decode(errors="replace")[-900:] or "Không thể ghi PCAPNG")


def helper(interface, path):
    signal.signal(signal.SIGBREAK, lambda *_: None)
    proc = subprocess.Popen([DUMPCAP, "-q", "-p", "-i", interface, "-w", path],
                            stdin=subprocess.DEVNULL)
    def stop_on_eof():
        sys.stdin.buffer.read()
        if proc.poll() is None:
            import ctypes
            ctypes.windll.kernel32.GenerateConsoleCtrlEvent(1, 0)
    threading.Thread(target=stop_on_eof, daemon=True).start()
    return proc.wait()


def annotate(path, rows):
    # dumpcap writes one section. Preserve packets and existing header options.
    temp = path.with_suffix(".annotated.tmp")
    try:
        with path.open("rb") as source, temp.open("wb") as out:
            prefix = source.read(12)
            if prefix[:4] != bytes.fromhex("0a0d0d0a"):
                raise ValueError("Invalid PCAPNG header")
            order = "<" if prefix[8:] == bytes.fromhex("4d3c2b1a") else ">"
            size = struct.unpack(order + "I", prefix[4:8])[0]
            body = prefix[8:] + source.read(size - 16)
            if source.read(4) != prefix[4:8]:
                raise ValueError("Incomplete PCAPNG section header")
            if len(body) > 16 and body.endswith(bytes(4)):
                body = body[:-4]
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=[*FIELDS, "prediction", *EVIDENCE], lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            comments = bytearray()
            chunk = bytearray()
            for line in ("CryptoMinerDetector J48\n" + buf.getvalue()).splitlines(True):
                data = line.encode()
                if len(chunk) + len(data) > 60000:
                    comments.extend(struct.pack(order + "HH", 1, len(chunk)) + chunk + bytes(-len(chunk)%4))
                    chunk.clear()
                chunk.extend(data)
            comments.extend(struct.pack(order + "HH", 1, len(chunk)) + chunk + bytes(-len(chunk)%4))
            length = struct.pack(order + "I", len(body) + len(comments) + 16)
            out.write(prefix[:4] + length + body + comments + bytes(4) + length)
            shutil.copyfileobj(source, out)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def session(interface, stop, emit, monitor_done=None):
    since = datetime.now().astimezone()
    path = ROOT / "data" / "pcaps" / datetime.now().strftime("session_%Y%m%d_%H%M%S_%f.pcapng")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        record(interface, path, stop)
    except Exception as exc:
        stop.set()
        emit("info", f"Không thể ghi lưu lượng tại {path}. Phiên giám sát sẽ dừng: {exc}")
        return
    stop.set()
    if monitor_done is not None:
        monitor_done.wait()
    try:
        emit("info", f"Đã ghi {path}. Đang phân tích J48…")
        rows = analyze(path, ROOT / "data" / "system_events.jsonl", since)
        annotate(path, rows)
        emit("capture_result", (path.name, rows))
    except Exception as exc:
        emit("info", f"Lỗi thu hoặc phân tích tại {path}: {exc}")
    except SystemExit as exc:
        emit("info", f"Lỗi đọc bản ghi {path}: {exc}")


if __name__ == "__main__":
    sys.exit(helper(*sys.argv[1:]))
