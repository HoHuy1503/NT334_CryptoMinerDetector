"""Desktop interface for CryptoMinerDetector."""
import os
from pathlib import Path
import queue
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk

from tkinter import messagebox
from detection.trace import trace_text
import main as monitor


class DetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoMinerDetector")
        self.root.geometry("980x680")
        self.root.minsize(760, 520)
        self.events = queue.Queue()
        self.stop_event = None
        self.worker = None
        self.alert_count = 0
        self.alert_stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.process_rows = {}
        self.active_sort = None
        self.sort_state = {}

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        header = ttk.Frame(root, padding=(16, 14))
        header.pack(fill="x")
        ttk.Label(header, text="CryptoMinerDetector", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(header, text="Giám sát hành vi tiến trình, CPU, GPU và kết nối mạng", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.monitor_tab = ttk.Frame(self.tabs, padding=8)
        self.results_tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(self.monitor_tab, text="Giám sát")
        self.tabs.add(self.results_tab, text="Kết quả")

        controls = ttk.Frame(self.monitor_tab, padding=(8, 4))
        controls.pack(fill="x")
        self.start_button = ttk.Button(controls, text="Bắt đầu giám sát", command=self.start_monitor)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(controls, text="Dừng", command=self.stop_monitor, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.status_var = tk.StringVar(value="Đang dừng")
        ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=16)

        summary = ttk.LabelFrame(self.monitor_tab, text="Trạng thái máy", padding=10)
        summary.pack(fill="x", padx=8, pady=(8, 10))
        self.summary_var = tk.StringVar(value="Chưa có dữ liệu giám sát.")
        ttk.Label(summary, textvariable=self.summary_var).pack(anchor="w")

        log_frame = ttk.LabelFrame(self.monitor_tab, text="Nhật ký giám sát trực tiếp", padding=8)
        log_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.log = tk.Text(log_frame, height=12, wrap="word", state="disabled", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)

        stats_frame = ttk.LabelFrame(self.results_tab, text="Thống kê theo tiến trình", padding=8)
        stats_frame.pack(fill="x", pady=(0, 8))
        self.stats_var = tk.StringVar(value="Sự kiện cảnh báo: 0  |  Tiến trình: 0  |  Mức cao: 0  |  Trung bình: 0  |  Thấp: 0")
        ttk.Label(stats_frame, textvariable=self.stats_var).pack(anchor="w")

        alerts_frame = ttk.LabelFrame(self.results_tab, text="Tổng hợp kết quả phát hiện", padding=8)
        alerts_frame.pack(fill="both", expand=True)
        cols = ("process", "pid", "severity", "score", "count", "first_seen", "last_seen", "indicators")
        self.alerts = ttk.Treeview(alerts_frame, columns=cols, show="headings", height=14)
        for col, title, width in [("process", "Tiến trình", 145), ("pid", "PID", 65),
                                  ("severity", "Mức cao nhất", 95), ("score", "Điểm cao nhất", 95),
                                  ("count", "Số lần", 65), ("first_seen", "Phát hiện đầu", 145),
                                  ("last_seen", "Gần nhất", 145), ("indicators", "Dấu hiệu đã gặp", 310)]:
            self.alerts.heading(col, text=title, command=lambda column=col: self.sort_by(column))
            self.alerts.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts.yview)
        self.alerts.configure(yscrollcommand=scroll.set)
        self.alerts.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.alerts.bind("<Double-Button-1>", self.open_process_folder)
        self.alerts.bind("<Button-3>", self.show_alert_context_menu)
        self.alert_context_menu = tk.Menu(root, tearoff=False)
        self.alert_context_menu.add_command(label="Xem truy vết", command=self.show_trace)
        self.alert_context_menu.add_command(label="Copy tên tiến trình", command=self.copy_selected_process_name)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(200, self.process_events)

    def append_log(self, message):
        self.log.configure(state="normal")
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        self.log.insert("end", f"[{timestamp}] {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def copy_selected_process_name(self, event=None):
        selected = self.alerts.selection()
        if not selected:
            self.status_var.set("Chọn một dòng cảnh báo trước khi sao chép.")
            return "break"
        process_name = self.alerts.set(selected[0], "process")
        if not process_name:
            return "break"
        self.root.clipboard_clear()
        self.root.clipboard_append(process_name)
        self.status_var.set(f"Đã sao chép tên tiến trình: {process_name}")
        return "break"

    def alert_for_row(self, row):
        return next((r["latest_alert"] for r in self.process_rows.values()
                     if r.get("row_id") == row), {})

    def open_process_folder(self, event):
        if self.alerts.identify_region(event.x, event.y) != "cell":
            return
        row = self.alerts.identify_row(event.y)
        path = Path(self.alert_for_row(row).get("executable_path") or "")
        try:
            if not path.is_absolute() or len(path.drive) != 2 or not path.parent.is_dir():
                raise FileNotFoundError
            os.startfile(str(path.parent))
        except (OSError, ValueError):
            messagebox.showwarning("Thư mục tiến trình",
                                   "Không thể mở thư mục cục bộ của tệp đã ghi nhận.",
                                   parent=self.root)

    def show_trace(self):
        selected = self.alerts.selection()
        if not selected:
            return
        window = tk.Toplevel(self.root)
        window.title("Truy vết tại lần cảnh báo gần nhất")
        window.transient(self.root)
        window.geometry(f"{min(1100, window.winfo_screenwidth()-60)}x{min(560, window.winfo_screenheight()-100)}")
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        body = tk.Text(window, wrap="none", padx=16, pady=14, font=("Segoe UI", 11))
        body.grid(row=0, column=0, sticky="nsew")
        horizontal = ttk.Scrollbar(window, orient="horizontal", command=body.xview)
        vertical = ttk.Scrollbar(window, orient="vertical", command=body.yview)
        horizontal.grid(row=1, column=0, sticky="ew")
        vertical.grid(row=0, column=1, sticky="ns")
        body.configure(xscrollcommand=horizontal.set, yscrollcommand=vertical.set)
        body.insert("1.0", trace_text(self.alert_for_row(selected[0])))
        body.configure(state="disabled")
        ttk.Button(window, text="Đóng", command=window.destroy).grid(row=2, column=0, sticky="e", padx=10, pady=8)
        window.bind("<Escape>", lambda event: window.destroy())

    def show_alert_context_menu(self, event):
        row = self.alerts.identify_row(event.y)
        if row:
            self.alerts.selection_set(row)
            self.alerts.focus(row)
            self.alert_context_menu.tk_popup(event.x_root, event.y_root)

    def sort_rows(self, column, reverse):
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

        def sort_key(item):
            value = self.alerts.set(item, column)
            if column in {"pid", "score", "count"}:
                try:
                    return (0, float(value))
                except (TypeError, ValueError):
                    return (1, 0)
            if column == "severity":
                return (0, severity_order.get(str(value).upper(), 0))
            return (0, str(value).casefold())

        items = list(self.alerts.get_children(""))
        items.sort(key=sort_key, reverse=reverse)
        for index, item in enumerate(items):
            self.alerts.move(item, "", index)

    def sort_by(self, column):
        reverse = self.sort_state.get(column, False)
        self.sort_rows(column, reverse)
        self.sort_state[column] = not reverse
        self.active_sort = (column, reverse)

    def apply_active_sort(self):
        if self.active_sort is not None:
            self.sort_rows(*self.active_sort)
    def start_monitor(self):
        if self.worker and self.worker.is_alive():
            return
        self.stop_event = threading.Event()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set("Đang khởi động...")
        self.append_log("Bắt đầu giám sát.")

        def run():
            try:
                monitor.main(self.stop_event, lambda kind, payload: self.events.put((kind, payload)))
            except Exception as exc:
                self.events.put(("error", f"Không thể tiếp tục giám sát: {exc}"))

        self.worker = threading.Thread(target=run, name="detector-monitor", daemon=True)
        self.worker.start()

    def stop_monitor(self):
        if self.stop_event:
            self.status_var.set("Đang dừng...")
            self.stop_event.set()
            self.stop_button.configure(state="disabled")

    def process_events(self):
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "info":
                self.append_log(str(payload))
            elif kind == "status":
                self.status_var.set("Đang giám sát")
                self.summary_var.set(
                    f"Máy: {payload['hostname']}  |  Tiến trình: {payload['processes']}  |  "
                    f"Kết nối: {payload['connections']}  |  CPU toàn máy: {payload['system_cpu_percent']:.1f}%  |  "
                    f"Cảnh báo: {payload['alerts']}  |  Cập nhật: {payload['timestamp']}"
                )
            elif kind == "alert":
                alert = payload["alert"]
                severity = alert.get("severity", "low").upper()
                severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
                process_name = alert.get("process_name", "unknown")
                pid = alert.get("pid")
                identity = (alert.get("hostname"), pid,
                            alert.get("process_created_at") or process_name)
                indicators = {item.get("rule_id", "") for item in alert.get("indicators", [])}
                record = self.process_rows.get(identity)
                if record is None:
                    record = {
                        "process": process_name, "pid": pid, "severity": severity,
                        "score": alert.get("score", 0), "count": 0,
                        "first_seen": alert.get("timestamp", ""),
                        "last_seen": alert.get("timestamp", ""), "indicators": set(),
                    }
                    self.process_rows[identity] = record
                record["latest_alert"] = alert
                record["count"] += 1
                record["last_seen"] = alert.get("timestamp", "")
                record["score"] = max(record["score"], alert.get("score", 0))
                record["indicators"].update(indicators)
                if severity_rank.get(severity, 0) > severity_rank.get(record["severity"], 0):
                    record["severity"] = severity
                values = (
                    record["process"], record["pid"], record["severity"],
                    record["score"], record["count"], record["first_seen"],
                    record["last_seen"], ", ".join(sorted(record["indicators"])),
                )
                row_id = record.get("row_id")
                if row_id and self.alerts.exists(row_id):
                    self.alerts.item(row_id, values=values)
                else:
                    row_id = self.alerts.insert("", "end", values=values)
                    record["row_id"] = row_id
                self.alert_count += 1
                levels = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for process_record in self.process_rows.values():
                    levels[process_record["severity"]] += 1
                self.stats_var.set(
                    f"Sự kiện cảnh báo: {self.alert_count}  |  Tiến trình: {len(self.process_rows)}  |  "
                    f"Mức cao: {levels['HIGH']}  |  Trung bình: {levels['MEDIUM']}  |  Thấp: {levels['LOW']}"
                )
                self.apply_active_sort()
                if self.active_sort is None:
                    self.alerts.see(row_id)
                self.append_log(payload["formatted"])
            elif kind in {"stopped", "error"}:
                self.append_log(str(payload))
                self.status_var.set("Đã dừng" if kind == "stopped" else "Có lỗi")
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
        self.root.after(200, self.process_events)

    def close(self):
        if self.worker and self.worker.is_alive():
            self.stop_monitor()
            self.root.after(250, self.close_when_stopped)
        else:
            self.root.destroy()

    def close_when_stopped(self):
        if self.worker and self.worker.is_alive():
            self.root.after(250, self.close_when_stopped)
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    DetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()