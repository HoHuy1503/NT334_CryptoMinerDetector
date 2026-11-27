"""Evaluate mining traffic vectors from nesfit/DI-cryptominingdetection."""
import argparse
import csv
import math
import os
from pathlib import Path
import subprocess
import tempfile


FEATURES = ("ackpush_ratio", "bpp", "ppf", "ppm", "request_ratio",
            "syn_ratio", "rst_ratio", "fin_ratio")


def prepare(folder, output):
    output.write("@relation mining_traffic\n")
    for name in FEATURES:
        output.write(f"@attribute {name} numeric\n")
    output.write("@attribute class {miner,notminer}\n@data\n")
    for label in ("miner", "notminer"):
        path = folder / f"wekaready_{label}s.csv"
        with path.open(encoding="utf-8-sig", newline="") as source:
            count = 0
            for row in csv.reader(source):
                if not row:
                    continue
                if (len(row) != 9 or row[-1].strip() != label or
                        not all(math.isfinite(float(x)) for x in row[:-1])):
                    raise ValueError(f"Invalid record in {path}, row {count + 1}")
                output.write(",".join(row).strip() + "\n")
                count += 1
            if count < 5:
                raise ValueError(f"Too few examples in {path}")
            print(label, count, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_dir", type=Path)
    parser.add_argument("jar_dir", type=Path, help="Directory containing Weka and its dependencies")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "traffic.arff"
        with data.open("w", encoding="ascii") as out:
            prepare(args.csv_dir, out)
        subprocess.run(["java", "-Xmx2g", "-cp", str(args.jar_dir / "*"),
                        "weka.classifiers.meta.FilteredClassifier", "-t", str(data),
                        "-x", "5", "-s", "1", "-v",
                        "-F", "weka.filters.supervised.instance.ClassBalancer",
                        "-W", "weka.classifiers.trees.J48", "--", "-M", "100"], check=True)


if __name__ == "__main__":
    main()
