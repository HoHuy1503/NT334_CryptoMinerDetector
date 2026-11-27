"""Offline IPv4/TCP features. One directional flow per Wireshark stream.
Use IP total lengths and a capture-wide group window (no exporter timeouts).
"""
import argparse
import csv
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from traffic_forensics import FEATURES


@dataclass
class Flow:
    packets: int = 0
    octets: int = 0
    flags: int = 0
    first: Decimal = Decimal("Infinity")
    last: Decimal = Decimal("-Infinity")


def extract(capture):
    fields = "tcp.stream frame.time_epoch ip.src tcp.srcport ip.dst tcp.dstport ip.len tcp.flags"
    cmd = [shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe",
           "-n", "-r", capture, "-Y", "ip && tcp", "-T", "fields", "-E", "occurrence=f"]
    for field in fields.split():
        cmd.extend(["-e", field])
    flows = defaultdict(Flow)
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as reader:
        for line in reader.stdout:
            stream, ts, src, sport, dst, dport, size, flags = line.rstrip().split("\t")
            flow = flows[stream, src, int(sport), dst, int(dport)]
            time = Decimal(ts)
            flow.first = min(flow.first, time)
            flow.last = max(flow.last, time)
            flow.flags |= int(flags, 16) & 255
            flow.packets += 1
            flow.octets += int(size)
        if reader.wait():
            raise SystemExit("TShark failed")
    groups = defaultdict(list)
    for (_, src, sport, dst, dport), flow in flows.items():
        groups[src, dst, dport].append((sport, flow))
    for key, entries in sorted(groups.items()):
        parts = [flow for _, flow in entries]
        n = len(parts)
        packets = sum(f.packets for f in parts)
        size = sum(f.octets for f in parts)
        seconds = int(max(f.last for f in parts)) - int(min(f.first for f in parts))
        ratios = [100 * sum(bool(f.flags & flag) for f in parts) // n for flag in (2, 4, 1)]
        yield (*key, n, packets, size, 100 * sum(f.flags in (16, 24) for f in parts) // n,
               size // packets, packets // n, -1 if seconds < 5 else packets * 60 // seconds,
               100 * sum(port > key[2] for port, _ in entries) // n, *ratios)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    args = parser.parse_args()
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(("src", "dst", "dport", "flows", "packets", "ip_bytes", *FEATURES))
    writer.writerows(extract(args.capture))
