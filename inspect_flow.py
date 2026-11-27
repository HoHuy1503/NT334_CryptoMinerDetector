"""Inspect directed IPv4/TCP flows in one offline Wireshark stream."""
import argparse
import shutil
import subprocess
from collections import Counter
from decimal import Decimal
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--stream", required=True, type=int)
    args = parser.parse_args()
    tshark = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
    fields = ["frame.time_epoch", "ip.src", "tcp.srcport", "ip.dst",
              "tcp.dstport", "frame.len"]
    command = [tshark, "-n", "-r", str(args.capture), "-Y",
               f"ip && tcp.stream == {args.stream}", "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        command.extend(["-e", field])
    try:
        output = subprocess.check_output(command, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"TShark error: {exc}\n")
    packets, sizes = Counter(), Counter()
    times = []
    for line in output.splitlines():
        timestamp, src, sport, dst, dport, size = line.split("\t")
        direction = (src, sport, dst, dport)
        packets[direction] += 1
        sizes[direction] += int(size)
        times.append(Decimal(timestamp))
    if not times:
        parser.exit(1, "No IPv4/TCP packets for this stream.\n")
    for direction, count in packets.items():
        src, sport, dst, dport = direction
        print(f"{src}:{sport} -> {dst}:{dport}: {count} packets, {sizes[direction]} bytes")
    print(f"Total: {sum(packets.values())} packets, {sum(sizes.values())} bytes, "
          f"duration {max(times) - min(times):.4f} s")


if __name__ == "__main__":
    main()
