import argparse
import joblib
import os
import re
import numpy as np
from sklearn.ensemble import IsolationForest

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<date>.*?)\] "(?P<method>\S+) (?P<path>\S+)'
)

def extract_features(line):
    """Extract simple numeric and categorical features from the log."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    
    ip = match.group("ip")
    method = match.group("method")
    path = match.group("path")

    # numeric encoding
    method_num = {"GET":1, "POST":2, "PUT":3, "DELETE":4}.get(method.upper(), 0)

    return np.array([
        len(line),
        method_num,
        len(path),
        path.count("/"),
        ip.count("."),
    ])

def main(args):
    if not os.path.exists(args.model_dir):
        os.makedirs(args.model_dir)

    print("[INFO] Loading logs…")
    with open(args.normal_logs, "r") as f:
        lines = f.readlines()

    print(f"[INFO] Loaded {len(lines)} clean logs")
    print("[INFO] Extracting features…")

    features = []
    for l in lines:
        f = extract_features(l)
        if f is not None:
            features.append(f)

    X = np.array(features)
    print("[INFO] Training Isolation Forest (unsupervised)…")

    model = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=42
    )
    model.fit(X)

    print("[INFO] Saving model…")
    joblib.dump(model, f"{args.model_dir}/isolation_forest.joblib")

    print("[SUCCESS] Training completed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal_logs", required=True)
    parser.add_argument("--model_dir", required=True)
    parser.add_argument("--max_lines", type=int, default=200000)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    main(args)