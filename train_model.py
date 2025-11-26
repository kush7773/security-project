# train_model.py
import os
import argparse
import logging
from collections import defaultdict, deque
from datetime import datetime
import time
import re
import math
import random

import joblib
import numpy as np
import scipy.sparse as sp

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("train_model")

# signatures used to create features too (same as main.py)
SIG_REGEXES = {
    "sql_injection": re.compile(r"(?:')|(?:--)|(/\*)|(\bUNION\b)|(\bSELECT\b.*\bFROM\b)|(\bOR\b\s+\d+=\d+)", re.IGNORECASE),
    "xss": re.compile(r"<script\b|<\/script>|javascript:|onerror=|onload=", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./|\.\.\\"),
    "jndi_like": re.compile(r"\$\{.*jndi:.*\}", re.IGNORECASE),
    "shell_meta": re.compile(r"[;|`$&<>\\\(\)\{\}]", re.IGNORECASE),
    "ssrf_ip": re.compile(r"http://169\.254\.169\.254|169\.254\.169\.254"),
    "long_uri": re.compile(r"\/\S{100,}"),
    "sensitive_file": re.compile(r"(etc/passwd|/etc/shadow|wp-config\.php)", re.IGNORECASE),
}

def read_lines(path, max_lines=None):
    out = []
    with open(path, "r", errors="ignore") as f:
        for i, L in enumerate(f):
            out.append(L.strip())
            if max_lines and i+1 >= max_lines:
                break
    return out

def extract_basic_fields(line):
    # same parsing strategy as main.py simplified for training: return ip, ts, path, status, text
    ip = "0.0.0.0"
    ts = time.time()
    path = "/"
    status = 0
    text = line
    # try minimal regex
    m = re.match(r'(?P<ip>\S+).* \[(?P<date>.*?)\] "(?P<method>\S+) (?P<path>\S+).*" (?P<status>\d{3})', line)
    if m:
        ip = m.group("ip")
        path = m.group("path")
        status = int(m.group("status"))
        text = line
        # parse date not strictly necessary
    return ip, ts, path, status, text

def signature_features(text):
    feats = []
    for k, rx in SIG_REGEXES.items():
        feats.append(1 if rx.search(text) else 0)
    return np.array(feats, dtype=int)

def build_behavioral_counts(lines, window_sec=60):
    # For training synthetic features: count requests per ip per last minute at sample time.
    ip_queues = defaultdict(deque)
    samples = []
    for line in lines:
        ip, ts, path, status, text = extract_basic_fields(line)
        now_ts = time.time()
        ipq = ip_queues[ip]
        ipq.append(now_ts)
        # pop older than window
        cutoff = now_ts - window_sec
        while ipq and ipq[0] < cutoff:
            ipq.popleft()
        # build sample feature
        count_1m = len(ipq)
        failed_5m = 0  # we don't have timed history here, could be extended
        uniq_paths = 1  # placeholder
        samples.append({
            "text": text,
            "count_1m": count_1m,
            "failed_5m": failed_5m,
            "unique_paths_1m": uniq_paths,
            "status": status
        })
    return samples

def assemble_feature_matrix(samples, tfidf=None, svd=None):
    texts = [s["text"] for s in samples]
    if tfidf is None:
        tfidf = TfidfVectorizer(ngram_range=(1,3), max_features=20000, analyzer='char_wb', min_df=1)
        X_text = tfidf.fit_transform(texts)
    else:
        X_text = tfidf.transform(texts)
    # reduce sparse with TruncatedSVD
    if svd is None:
        n_comp = min(100, X_text.shape[1]-1) if X_text.shape[1] > 1 else 1
        svd = TruncatedSVD(n_components=n_comp)
        X_red = svd.fit_transform(X_text)
    else:
        X_red = svd.transform(X_text)

    numerics = np.array([[s["count_1m"], s["failed_5m"], s["unique_paths_1m"], s["status"]] for s in samples], dtype=float)
    sigs = np.array([signature_features(s["text"]) for s in samples], dtype=float)
    X = np.hstack([numerics, sigs, X_red])
    return X, tfidf, svd

def main(args):
    logger.info("Loading normal logs...")
    normal_lines = read_lines(args.normal_logs[0], max_lines=args.max_lines)
    logger.info("Loaded %d normal lines", len(normal_lines))

    attack_lines = []
    if args.attack_logs:
        for p in args.attack_logs:
            if os.path.exists(p):
                attack_lines += read_lines(p, max_lines=args.max_lines)
            else:
                logger.warning("Attack log %s not found, skipping", p)
    logger.info("Loaded %d attack lines", len(attack_lines))

    # Build samples
    normal_samples = build_behavioral_counts(normal_lines)
    attack_samples = build_behavioral_counts(attack_lines) if attack_lines else []

    # Assemble feature matrix for normal samples (unsupervised)
    X_normal, tfidf, svd = assemble_feature_matrix(normal_samples)
    logger.info("TF-IDF shaped: %s", X_normal.shape)

    # scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)

    # train IsolationForest
    iso = IsolationForest(n_estimators=200, contamination=args.contamination, random_state=42)
    iso.fit(X_scaled)
    logger.info("IsolationForest trained")

    # optionally train supervised classifier if attack samples exist
    rf = None
    if attack_samples:
        all_samples = normal_samples + attack_samples
        X_all, tfidf2, svd2 = assemble_feature_matrix(all_samples, tfidf=tfidf, svd=svd)
        y = np.array([0]*len(normal_samples) + [1]*len(attack_samples))
        X_train, X_test, y_train, y_test = train_test_split(X_all, y, test_size=0.2, random_state=42, stratify=y)
        rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
        rf.fit(X_train, y_train)
        logger.info("RandomForest trained (supervised)")

    # Save models
    os.makedirs(args.model_dir, exist_ok=True)
    joblib.dump(tfidf, os.path.join(args.model_dir, "tfidf_vectorizer.joblib"))
    joblib.dump(svd, os.path.join(args.model_dir, "pca.joblib"))
    joblib.dump(scaler, os.path.join(args.model_dir, "scaler.joblib"))
    joblib.dump(iso, os.path.join(args.model_dir, "isolation_forest.joblib"))
    if rf:
        joblib.dump(rf, os.path.join(args.model_dir, "rf_classifier.joblib"))
    logger.info("Saved models to %s", args.model_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal_logs", nargs="+", required=True, help="Paths to normal log files")
    parser.add_argument("--attack_logs", nargs="*", help="Paths to known attack log files (optional)")
    parser.add_argument("--model_dir", default="/app/models", help="Where to save models")
    parser.add_argument("--max_lines", type=int, default=200000, help="Max lines per input file")
    parser.add_argument("--contamination", type=float, default=0.01, help="contamination for IsolationForest")
    args = parser.parse_args()
    main(args)
