#!/usr/bin/env python3
import re
import argparse
import joblib
import numpy as np
import logging

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("train_model")

# ---------------------------------------------------------------------
# SAFE UNIVERSAL LOG PARSER (never fails)
# ---------------------------------------------------------------------
LOG_REGEX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?'
    r'\[(?P<time>[^\]]+)\].*?"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?'
    r'\s*(?P<url>[^"]*)"?\s*(?P<code>\d{3})?\s*(?P<size>\d+)?',
    re.IGNORECASE
)

def parse_log(line):
    """Safe parser: returns tokens even when regex fails."""
    m = LOG_REGEX.search(line)
    if m:
        g = m.groupdict()
        return {
            "ip": g.get("ip", ""),
            "method": g.get("method", ""),
            "url": g.get("url", ""),
            "code": g.get("code", "0"),
            "size": g.get("size", "0"),
            "raw": line.strip()
        }
    else:
        # Fallback for zero-day / weird logs
        return {
            "ip": "",
            "method": "",
            "url": "",
            "code": "0",
            "size": "0",
            "raw": line.strip()
        }

# ---------------------------------------------------------------------
# READ LOGS
# ---------------------------------------------------------------------
def read_file(path, max_lines):
    lines = []
    log.info(f"Loading: {path}")
    with open(path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            lines.append(line.strip())
    return lines

# ---------------------------------------------------------------------
# NUMERIC FEATURES (behavior-based)
# ---------------------------------------------------------------------
def numeric_features(parsed):
    return np.array([
        int(parsed["code"]),
        int(parsed["size"]),
        len(parsed["method"]),
        len(parsed["url"]),
        len(parsed["raw"]),
        parsed["raw"].count("/")
    ], dtype=float)

# ---------------------------------------------------------------------
# MAIN TRAINING PIPELINE
# ---------------------------------------------------------------------
def main(args):
    # Load logs
    normal_lines = read_file(args.normal_logs, args.max_lines)
    attack_lines = read_file(args.attack_logs, args.max_lines)

    log.info(f"Loaded {len(normal_lines)} normal logs")
    log.info(f"Loaded {len(attack_lines)} attack logs")

    # Parse logs
    parsed_normal = [parse_log(l) for l in normal_lines]
    parsed_attack = [parse_log(l) for l in attack_lines]

    # Numeric feature matrix
    normal_numeric = np.vstack([numeric_features(p) for p in parsed_normal])
    attack_numeric = np.vstack([numeric_features(p) for p in parsed_attack])

    # Text feature extraction (HashingVectorizer → scalable)
    hv = HashingVectorizer(
        n_features=args.hashing_features,
        alternate_sign=False,
        norm="l2"
    )

    log.info("Vectorizing logs with HashingVectorizer...")
    normal_text = hv.transform([p["raw"] for p in parsed_normal])
    attack_text = hv.transform([p["raw"] for p in parsed_attack])

    # Dimensionality reduction
    log.info(f"Reducing text features via SVD to {args.svd_dim} dims...")
    svd = TruncatedSVD(n_components=args.svd_dim)
    normal_svd = svd.fit_transform(normal_text)
    attack_svd = svd.transform(attack_text)

    # Combine numeric + SVD
    X_normal = np.hstack([normal_numeric, normal_svd])
    X_attack = np.hstack([attack_numeric, attack_svd])

    # Save scaler
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    X_attack_scaled = scaler.transform(X_attack)

    # Save unsupervised anomaly detector (zero-day detection)
    log.info("Training IsolationForest (behavior-based zero-day detector)...")
    iso = IsolationForest(
        n_estimators=300,
        contamination=args.contamination,
        random_state=42
    )
    iso.fit(X_normal_scaled)

    # Save supervised classifier (signature-based)
    log.info("Training RandomForest (signature attack classifier)...")
    y = np.array([0]*len(X_normal_scaled) + [1]*len(X_attack_scaled))
    X_combined = np.vstack([X_normal_scaled, X_attack_scaled])

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        n_jobs=-1
    )
    rf.fit(X_combined, y)

    # Save models
    log.info(f"Saving all models to: {args.model_dir}")
    joblib.dump(hv, f"{args.model_dir}/hashing_vectorizer.joblib")
    joblib.dump(svd, f"{args.model_dir}/svd.joblib")
    joblib.dump(scaler, f"{args.model_dir}/scaler.joblib")
    joblib.dump(iso, f"{args.model_dir}/isolation_forest.joblib")
    joblib.dump(rf, f"{args.model_dir}/rf_classifier.joblib")

    log.info("TRAINING COMPLETE — MODELS READY.")

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--normal_logs", required=True)
    parser.add_argument("--attack_logs", required=True)
    parser.add_argument("--model_dir", required=True)
    parser.add_argument("--max_lines", type=int, default=200000)
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--svd_dim", type=int, default=64)
    parser.add_argument("--hashing_features", type=int, default=65536)

    args = parser.parse_args()
    main(args)