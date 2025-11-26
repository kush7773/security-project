# train_model.py
import os
import sys
import re
import argparse
import logging
from collections import Counter
import math
import joblib

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("train_model")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def extract_numeric_features(line: str):
    """Return numeric feature vector for a log line."""
    ln = len(line)
    ent = shannon_entropy(line)
    digit_ratio = sum(ch.isdigit() for ch in line) / max(1, ln)
    nonalnum_ratio = sum(not ch.isalnum() for ch in line) / max(1, ln)
    # status/size
    m = re.search(r'"\s*(\d{3})\s+(\d+)', line)
    status = int(m.group(1)) if m else 0
    size = int(m.group(2)) if m else 0
    return [ln, ent, digit_ratio, nonalnum_ratio, status, size]

def load_lines(paths, max_lines=None):
    lines = []
    for p in paths:
        with open(p, "r", errors="ignore") as fh:
            for i, ln in enumerate(fh):
                if max_lines and len(lines) >= max_lines:
                    break
                ln = ln.strip()
                if ln:
                    lines.append(ln)
    return lines

def safe_n_components(requested, n_samples, n_features):
    # At most n_samples - 1 for PCA with full svd (avoid singular error).
    max_comp = max(1, min(n_samples - 1, n_features))
    return min(requested, max_comp)

def main(args):
    logger.info("Loading normal logs...")
    normal_lines = load_lines(args.normal_logs, max_lines=args.max_lines)
    n = len(normal_lines)
    logger.info("Loaded %d normal lines", n)
    if n < 5:
        logger.warning("Very few normal lines (less than 5). Results may be unreliable.")

    # TF-IDF training
    logger.info("Training TF-IDF...")
    tfidf = TfidfVectorizer(ngram_range=(1,2), max_features=2000, analyzer='char_wb')  # char_wb helps for payloads
    tfidf_mat = tfidf.fit_transform(normal_lines)
    logger.info("TF-IDF shaped: %s", tfidf_mat.shape)

    # PCA on TF-IDF (optional)
    # compute safe n_components
    requested_pca = args.pca_dim
    n_features = tfidf_mat.shape[1]
    safe_pc = safe_n_components(requested_pca, n, n_features)
    logger.info("Applying PCA to TF-IDF (safe n_components=%d)...", safe_pc)
    pca = PCA(n_components=safe_pc)
    # convert to array (should be OK within memory for moderate sizes)
    tfidf_array = tfidf_mat.toarray()
    tfidf_reduced = pca.fit_transform(tfidf_array)
    logger.info("PCA applied, reduced shape: %s", tfidf_reduced.shape)

    # Numeric features
    logger.info("Extracting numeric features...")
    numeric_feats = np.vstack([extract_numeric_features(ln) for ln in normal_lines])
    logger.info("Numeric features shape: %s", numeric_feats.shape)

    # Combine features
    X = np.hstack([numeric_feats, tfidf_reduced])
    logger.info("Combined feature matrix shape: %s", X.shape)

    # Scale
    logger.info("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train IsolationForest
    logger.info("Training IsolationForest...")
    if args.if_estimators < 1:
        args.if_estimators = 100
    if_model = IsolationForest(n_estimators=args.if_estimators, contamination=args.contamination, random_state=42, n_jobs=-1)
    if_model.fit(X_scaled)
    logger.info("IsolationForest trained")

    # Save models
    os.makedirs(args.model_dir, exist_ok=True)
    tfidf_path = os.path.join(args.model_dir, "tfidf_vectorizer.joblib")
    pca_path = os.path.join(args.model_dir, "pca.joblib")
    scaler_path = os.path.join(args.model_dir, "scaler.joblib")
    if_path = os.path.join(args.model_dir, "isolation_forest.joblib")

    logger.info("Saving models to %s", args.model_dir)
    joblib.dump(tfidf, tfidf_path)
    joblib.dump(pca, pca_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(if_model, if_path)
    logger.info("Saved tfidf, pca, scaler, isolation forest.")

    print("TRAINING COMPLETE")
    print(f"Models saved at: {args.model_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train anomaly detection models from normal logs (for zero-day detection improvements).")
    parser.add_argument("--normal_logs", nargs="+", required=True, help="Paths to clean/normal log files (space separated)")
    parser.add_argument("--model_dir", default="./models", help="Directory to write models")
    parser.add_argument("--max_lines", type=int, default=50000, help="Max number of lines to load from all logs")
    parser.add_argument("--pca_dim", type=int, default=50, help="Requested PCA dimensions (will auto-adjust if too large)")
    parser.add_argument("--if_estimators", type=int, default=100, help="Number of estimators for IsolationForest")
    parser.add_argument("--contamination", type=float, default=0.01, help="Contamination parameter for IsolationForest")
    args = parser.parse_args()
    main(args)
