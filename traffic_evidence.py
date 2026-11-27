"""Passive evidence from the same TCP streams as the feature extractor."""
import json
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def enrich(capture, rows, snapshots=None, since=None):
    fields = ("tcp.stream", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport",
              "tcp.flags.syn", "tcp.flags.ack", "tls.handshake.extensions_server_name",
              "http.host", "tcp.payload")
    tool = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
    cmd = [tool, "-n", "-r", str(capture), "-Y", "ip && tcp", "-T", "fields",
           "-E", "occurrence=f"]
    for field in fields:
        cmd.extend(("-e", field))
    groups = defaultdict(set)
    hosts, initiators, methods, endpoints = {}, {}, {}, {}
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8",
                          errors="replace") as proc:
        for line in proc.stdout:
            stream, src, sport, dst, dport, syn, ack, sni, host, payload = line.rstrip("\r\n").split("\t")
            if not all((stream, src, sport, dst, dport)):
                continue
            groups[src, dst, dport].add(stream)
            endpoints[stream] = (f"{src}:{sport}", f"{dst}:{dport}")
            if syn == "1" and ack == "0":
                initiators.setdefault(stream, f"{src}:{sport}")
            if sni or host:
                hosts.setdefault(stream, set()).add(sni or host)
            if payload and len(payload) <= 131072:
                try:
                    for message in bytes.fromhex(payload.replace(":", "")).splitlines():
                        if not message.lstrip().startswith(b"{"):
                            continue
                        try:
                            method = json.loads(message).get("method")
                        except (ValueError, AttributeError, RecursionError):
                            continue
                        if method in ("mining.notify", "mining.submit"):
                            methods.setdefault(stream, {}).setdefault(method, set()).add(f"{src}:{sport}")
                except ValueError:
                    pass
        if proc.wait():
            raise RuntimeError("TShark không đọc được bằng chứng TCP.")
    owners = defaultdict(set)
    if snapshots and Path(snapshots).is_file():
        with Path(snapshots).open(encoding="utf-8") as records:
            for line in records:
                try:
                    sample = json.loads(line)
                    if datetime.fromisoformat(sample["timestamp"]) < since:
                        continue
                except (ValueError, KeyError):
                    continue
                names = {p["pid"]: p.get("name") for p in sample.get("processes", [])}
                for conn in sample.get("connections", []):
                    pid = conn.get("pid")
                    if pid is not None:
                        pair = tuple(sorted((conn.get("local_address") or "", conn.get("remote_address") or "")))
                        owners[pair].add(f"{pid} ({names.get(pid) or '?'})")
    for row in rows:
        streams = groups[row["src"], row["dst"], row["dport"]]
        confirmed = [s for s in streams if any(a != b for a in methods.get(s, {}).get("mining.notify", ())
                                              for b in methods.get(s, {}).get("mining.submit", ()))]
        pids = set().union(*(owners.get(tuple(sorted(endpoints[s])), set()) for s in streams))
        row.update(domains=", ".join(sorted({host for s in streams for host in hosts.get(s, ())})),
                   streams=", ".join(sorted(streams, key=int)),
                   initiators=", ".join(sorted({initiators[s] for s in streams if s in initiators})),
                   processes=", ".join(sorted(pids)),
                   stratum_streams=", ".join(sorted(confirmed, key=int)))
    return rows
