"""Offline capture analysis and its Tk results view."""
import csv
import queue
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from tkinter import Text, filedialog, ttk

from extract_features import extract
from mining_model import run
from traffic_forensics import FEATURES

from traffic_evidence import enrich

EVIDENCE = ("domains", "streams", "initiators", "processes", "stratum_streams")

ROOT = Path(__file__).resolve().parent
FIELDS = ("src", "dst", "dport", "flows", "packets", "ip_bytes", *FEATURES)


def analyze(capture, snapshots=None, since=None):
    model = ROOT / "data" / "traffic.model"
    jars = next((p for p in (ROOT / "weka-jars", Path(tempfile.gettempdir()) / "nt334-weka")
                 if list(p.glob("weka*.jar"))), None)
    if not model.is_file() or jars is None:
        raise ValueError("Cần data/traffic.model và thư viện Weka trong weka-jars.")
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        source, output = tmp / "features.csv", tmp / "results.csv"
        with source.open("w", newline="", encoding="ascii") as stream:
            writer = csv.writer(stream)
            writer.writerow(FIELDS)
            writer.writerows(extract(str(capture)))
        with source.open() as stream:
            if next(csv.DictReader(stream), None) is None:
                return []
        run(SimpleNamespace(action="predict", source=source, jars=jars,
                            model=model, output=output), tmp)
        with output.open(newline="", encoding="utf-8") as stream:
            return enrich(capture, list(csv.DictReader(stream)), snapshots, since)


class CapturePanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.messages = queue.Queue()
        self.rows = []
        self.render_version = 0
        self.button = ttk.Button(self, text="Mở PCAP…", command=self.choose)
        self.button.pack(anchor="w", pady=4)
        self.status = ttk.Label(self, text="Chọn bản ghi PCAP hoặc PCAPNG.")
        self.status.pack(anchor="w")
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True)
        columns = ("src", "dst", "dport", "prediction")
        self.table = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for col, title in zip(columns, ("IP nguồn", "IP đích", "Cổng đích", "Dự đoán J48")):
            self.table.heading(col, text=title)
        scroll = ttk.Scrollbar(frame, command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.table.pack(fill="both", expand=True)
        detail_frame = ttk.Frame(self)
        detail_frame.pack(fill="x", pady=8)
        self.detail = Text(detail_frame, height=6, width=1, wrap="none",
                           font="TkTextFont", state="disabled")
        horizontal = ttk.Scrollbar(detail_frame, orient="horizontal", command=self.detail.xview)
        self.detail.configure(xscrollcommand=horizontal.set)
        self.detail.pack(fill="x")
        horizontal.pack(fill="x")
        self.table.bind("<<TreeviewSelect>>", self.show_features)

    def set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.xview_moveto(0)
        self.detail.configure(state="disabled")

    def show_features(self, event):
        selection = self.table.selection()
        if selection:
            row = self.rows[int(selection[0])]
            features = "   |   ".join(f"{key}: {row[key]}" for key in FEATURES)
            details = [
                "Tên miền quan sát: " + (row.get("domains") or "Chưa thấy TLS SNI / HTTP Host"),
                "TCP stream: " + (row.get("streams") or "—"),
                "Bên gửi SYN đầu: " + (row.get("initiators") or "Chưa quan sát"),
                "PID ứng viên cùng phiên: " + (row.get("processes") or "Chưa đối chiếu được"),
                "Stream có mining.notify và mining.submit ngược chiều: " + (row.get("stratum_streams") or "Chưa quan sát"),
            ]
            self.set_detail("\n".join([*details, features]))

    def choose(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[("PCAP / PCAPNG", "*.pcap *.pcapng *.cap")])
        if not path:
            return
        self.render_version += 1
        self.button.state(["disabled"])
        self.table.delete(*self.table.get_children())
        self.rows = []
        self.set_detail("")
        self.status.configure(text=f"Đang phân tích {Path(path).name}…")

        def worker():
            try:
                self.messages.put((analyze(path), None))
            except (Exception, SystemExit) as exc:
                self.messages.put(([], str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(150, self.finish, Path(path).name)

    def finish(self, name):
        try:
            rows, error = self.messages.get_nowait()
        except queue.Empty:
            self.after(150, self.finish, name)
            return
        self.button.state(["!disabled"])
        if error:
            self.status.configure(text=f"Lỗi phân tích: {error}")
            return
        self.display(name, rows)

    def display(self, name, rows):
        self.table.delete(*self.table.get_children())
        self.set_detail("")
        self.rows = sorted(rows, key=lambda row: row["prediction"] != "miner")
        self.render_version += 1
        self.render_batch(self.render_version, 0)
        hits = sum(row["prediction"] == "miner" for row in rows)
        self.status.configure(text=f"{name}   |   {len(rows)} bộ ba IPv4/TCP   |   {hits} dự đoán miner")
        if rows:
            self.table.selection_set("0")

    def render_batch(self, version, start):
        if version != self.render_version:
            return
        end = min(start + 200, len(self.rows))
        for index in range(start, end):
            row = self.rows[index]
            values = tuple(row[key] for key in ("src", "dst", "dport", "prediction"))
            self.table.insert("", "end", iid=str(index), values=values)
        if end < len(self.rows):
            self.after(10, self.render_batch, version, end)
