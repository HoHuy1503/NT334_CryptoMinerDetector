"""Train or apply the mining traffic model. Run with --help for arguments."""
import argparse
import csv
import math
import re
import subprocess
import tempfile
from pathlib import Path

from traffic_forensics import FEATURES, prepare


def run(args, tmp):
    command = ["java", "-Xmx2g", "-cp", str(args.jars / "*"),
               "weka.classifiers.meta.FilteredClassifier"]
    arff = tmp / "traffic.arff"
    if args.action == "train":
        with arff.open("w", encoding="ascii") as out:
            prepare(args.source, out)
        model = tmp / "trained.model"
        subprocess.run(command + ["-t", str(arff), "-no-cv", "-d", str(model),
                       "-F", "weka.filters.supervised.instance.ClassBalancer",
                       "-W", "weka.classifiers.trees.J48", "--", "-M", "100"], check=True)
        model.replace(args.model)
        return
    with args.source.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        fields = reader.fieldnames or []
        if not set((*FEATURES, "src", "dst", "dport")).issubset(fields):
            raise ValueError("Missing feature or triplet columns")
        rows = list(reader)
    with arff.open("w", encoding="ascii") as out:
        out.write("@relation mining_traffic\n")
        for feature in FEATURES:
            out.write(f"@attribute {feature} numeric\n")
        out.write("@attribute class {miner,notminer}\n@data\n")
        for row in rows:
            values = [row[f] for f in FEATURES]
            if not all(math.isfinite(float(v)) for v in values):
                raise ValueError("Invalid numeric feature")
            out.write(",".join(values) + ",?\n")
    result = subprocess.check_output(command + ["-l", str(args.model), "-T", str(arff),
                                     "-p", "0"], text=True)
    labels = re.findall(r"^\s*(\d+)\s+\S+\s+\d+:(miner|notminer)\s", result, re.M)
    if [int(index) for index, _ in labels] != list(range(1, len(rows) + 1)):
        raise ValueError("Weka predictions do not match input rows")
    output = tmp / "predictions.csv"
    with output.open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fields + ["prediction"])
        writer.writeheader()
        for row, (_, label) in zip(rows, labels):
            writer.writerow(dict(row, prediction=label))
    output.replace(args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["train", "predict"])
    parser.add_argument("source", type=Path, help="Training CSV directory or extracted feature file")
    parser.add_argument("jars", type=Path)
    parser.add_argument("model", type=Path)
    parser.add_argument("--output", type=Path, default=Path("data/traffic_predictions.csv"))
    args = parser.parse_args()
    dest = args.model if args.action == "train" else args.output
    if args.action == "predict" and dest.resolve() in (args.source.resolve(), args.model.resolve()):
        parser.error("Choose a separate predictions file")
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        run(args, Path(tmp))
