# main.py
import os
import re
import time
import json
import math
from collections import deque, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, request, jsonify

import joblib
import numpy as np

# ---- Config ----
MODEL_DIR = os.environ.get("MODEL_DIR", "/app/models")
LOG_OUTPUT = os.environ.get("DETECTION_LOG", "/app/data/detections.log")
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.5"))  # higher = more anomalous
RATE_WINDOW_SECONDS = int(os.environ.get("RATE_WINDOW_SECONDS", "60"))  # sliding window for request counts
RATE_THRESHOLD_PER_MIN = int(os.environ.get("RATE_THRESHOLD_PER_MIN", "100"))  # for API abuse tests
FAILED_LOGIN_WINDOW = 300  # seconds
FAILED_LOGIN_THRESHOLD = 10

# ---- Load models (if present) ----
tfidf = None
pca = None
scaler = None
isof = None

def try_load_models():
    global tfidf, pca, scaler, isof
    try:
        tfidf = joblib.load(os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
    except Exception:
        tfidf = None
    try:
        pca = joblib.load(os.path.join(MODEL_DIR, "pca.joblib"))
    except Exception:
        pca = None
    try:
        scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
    except Exception:
        scaler = None
    try:
        isof = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.joblib"))
    except Exception:
        isof = None

try_load_models()

# ---- Signature rules (regex) ----
SIG_RULES = {
    "sql_injection": re.compile(r"(?:')|(?:--)|(/\*)|(\bUNION\b)|(\bSELECT\b.*\bFROM\b)|(\bOR\b\s+\d+=\d+)", re.IGNORECASE),
    "xss": re.compile(r"<script\b|<\/script>|javascript:|onerror=|onload=", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./|\.\.\\"),
    "jndi_like": re.compile(r"\$\{.*jndi:.*\}", re.IGNORECASE),  # detection only: pattern match
    "shell_meta": re.compile(r"[;|`$&<>\\\(\)\{\}]", re.IGNORECASE),
    "ssrf_ip": re.compile(r"http://169\.254\.169\.254|169\.254\.169\.254"),
    "long_uri": re.compile(r"\/\S{100,}"),  # very long URI
    "sensitive_file": re.compile(r"(etc/passwd|/etc/shadow|wp-config\.php)", re.IGNORECASE),
}

# ---- In-memory state for behavioral features (per-IP queues) ----
ip_windows = defaultdict(lambda: deque())  # deque of timestamps
ip_failed_logins = defaultdict(lambda: deque())  # deque of timestamps for 401/403
ip_unique_paths = defaultdict(lambda: set())  # unique URIs seen recently

# housekeeping TTL
MAX_WINDOW_KEEP = 3600  # keep 1 hour of timestamps at most

app = Flask(__name__)

def now_ts():
    return time.time()

def cleanup_ip(ip):
    # remove old entries to avoid memory growth
    cutoff = now_ts() - MAX_WINDOW_KEEP
    q = ip_windows[ip]
    while q and q[0] < cutoff:
        q.popleft()
    f = ip_failed_logins[ip]
    while f and f[0] < cutoff:
        f.popleft()
    # we keep ip_unique_paths cleared by time occasionally (not implemented for speed)

def add_request(ip, ts, path, status):
    ip_windows[ip].append(ts)
    if status in (401, 403):
        ip_failed_logins[ip].append(ts)
    ip_unique_paths[ip].add((path, int(ts // RATE_WINDOW_SECONDS)))  # coarse bucketing for uniqueness
    cleanup_ip(ip)

def compute_behavioral_features(ip):
    ts = now_ts()
    one_min_cutoff = ts - RATE_WINDOW_SECONDS
    q = ip_windows[ip]
    count_1m = sum(1 for t in q if t >= one_min_cutoff)
    failed = ip_failed_logins[ip]
    failed_5m = sum(1 for t in failed if t >= ts - FAILED_LOGIN_WINDOW)
    # unique URIs seen in last minute
    uniq_paths = len([p for p, bucket in ip_unique_paths[ip] if bucket >= int(one_min_cutoff // RATE_WINDOW_SECONDS)])
    return {
        "count_1m": count_1m,
        "failed_5m": failed_5m,
        "unique_paths_1m": uniq_paths,
    }

def extract_basic_fields(log_line):
    """
    Expect log_line as combined log or JSON. We'll try to parse common formats.
    Fallback: treat whole line as 'text'
    Returns: dict with ip, ts (unix), method, path, status (int), user_agent, text
    """
    ip = None
    ts = now_ts()
    method = None
    path = None
    status = None
    user_agent = None

    # If JSON input
    try:
        parsed = json.loads(log_line)
        # if the input already JSON with keys
        ip = parsed.get("ip") or parsed.get("remote_addr")
        method = parsed.get("method")
        path = parsed.get("path") or parsed.get("uri")
        status = int(parsed.get("status")) if parsed.get("status") else None
        user_agent = parsed.get("user_agent") or parsed.get("ua")
        text = json.dumps(parsed)
        return {"ip": ip or "0.0.0.0", "ts": ts, "method": method, "path": path or "/", "status": status or 0, "user_agent": user_agent or "-", "text": text}
    except Exception:
        pass

    # Try common Apache combined log pattern: IP - - [date] "METHOD PATH HTTP/1.1" STATUS BYTES "Referer" "User-Agent"
    m = re.match(r'(?P<ip>\S+) .* \[(?P<date>.*?)\] "(?P<method>\S+) (?P<path>\S+).*" (?P<status>\d{3}) .* "(?P<ref>.*?)" "(?P<ua>.*?)"', log_line)
    if m:
        ip = m.group("ip")
        method = m.group("method")
        path = m.group("path")
        status = int(m.group("status"))
        user_agent = m.group("ua")
        # parse date to timestamp if possible
        try:
            ts = time.mktime(datetime.strptime(m.group("date"), "%d/%b/%Y:%H:%M:%S %z").timetuple())
        except Exception:
            ts = now_ts()
        return {"ip": ip, "ts": ts, "method": method, "path": path, "status": status, "user_agent": user_agent, "text": log_line}

    # Fallback: minimal parse for lines like: "IP - - [date] "GET /path HTTP/1.1" 200 123"
    m2 = re.match(r'(?P<ip>\S+).*"(?P<method>\S+) (?P<path>\S+).*" (?P<status>\d{3})', log_line)
    if m2:
        ip = m2.group("ip")
        method = m2.group("method")
        path = m2.group("path")
        status = int(m2.group("status"))
        return {"ip": ip, "ts": ts, "method": method, "path": path, "status": status, "user_agent": "-", "text": log_line}

    # final fallback
    return {"ip": "0.0.0.0", "ts": ts, "method": None, "path": "/", "status": 0, "user_agent": "-", "text": log_line}

def signature_scan(text):
    hits = []
    for name, rx in SIG_RULES.items():
        if rx.search(text):
            hits.append(name)
    return hits

def make_text_feature(text):
    # transform with tfidf/pca if available; fall back to basic hashing features
    if tfidf is None:
        # fallback: length + token count + char entropy
        length = len(text)
        token_count = len(text.split())
        # char entropy
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        ent = 0.0
        total = len(text) or 1
        import math
        for v in freq.values():
            p = v / total
            ent -= p * math.log2(p)
        return np.array([length, token_count, ent])
    try:
        vec = tfidf.transform([text])
        if pca is not None:
            # If pca expects dense
            try:
                red = pca.transform(vec.toarray())
            except Exception:
                red = pca.transform(vec)
            return red.flatten()
        else:
            # reduce dimensionality by taking top-n word counts
            arr = vec.toarray().flatten()
            # keep first 50 or pad
            n = min(50, len(arr))
            res = np.zeros(50, dtype=float)
            res[:n] = arr[:n]
            return res
    except Exception:
        return np.array([len(text), len(text.split()), 0.0])

def predict_anomaly(feature_vector):
    if isof is None or scaler is None:
        return {"anomaly_score": 0.0, "anomaly": False}
    try:
        fv = np.array(feature_vector).reshape(1, -1)
        fv_scaled = scaler.transform(fv)
        score = -isof.decision_function(fv_scaled)[0]  # map so higher = more anomalous
        anomaly = (score >= ANOMALY_THRESHOLD)
        return {"anomaly_score": float(score), "anomaly": bool(anomaly)}
    except Exception:
        return {"anomaly_score": 0.0, "anomaly": False}

def severity_from_logic(sig_hits, anomaly_info, behavior):
    # Priority: signature hits > behavioral thresholds > anomaly score
    if sig_hits:
        # map certain signatures to severity
        if "jndi_like" in sig_hits or "ssrf_ip" in sig_hits or "sensitive_file" in sig_hits:
            return "critical"
        if "sql_injection" in sig_hits or "xss" in sig_hits or "path_traversal" in sig_hits:
            return "high"
        return "medium"
    # behavioral
    if behavior["count_1m"] >= RATE_THRESHOLD_PER_MIN:
        return "high"
    if behavior["failed_5m"] >= FAILED_LOGIN_THRESHOLD:
        return "high"
    if anomaly_info["anomaly"]:
        # map anomaly score to severity
        s = anomaly_info["anomaly_score"]
        if s > 2.0:
            return "high"
        if s > 1.0:
            return "medium"
        return "low"
    return "none"

def log_detection(d):
    try:
        Path(LOG_OUTPUT).parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_OUTPUT, "a") as f:
            f.write(json.dumps(d) + "\n")
    except Exception:
        pass

@app.route("/", methods=["POST"])
def ingest():
    payload = request.get_json(force=True, silent=True)
    if payload and isinstance(payload, dict) and "log_line" in payload:
        line = payload["log_line"]
    else:
        # accept raw text body
        line = request.get_data(as_text=True) or ""
    fields = extract_basic_fields(line)
    ip = fields["ip"] or "0.0.0.0"
    ts = fields["ts"]
    path = fields["path"] or "/"
    status = fields.get("status", 0)
    text = fields.get("text", line)

    # update behavior state
    add_request(ip, ts, path, status)
    behavior = compute_behavioral_features(ip)

    # signature scan
    sig_hits = signature_scan(text + " " + (fields.get("user_agent") or ""))

    # text feature
    text_feat = make_text_feature(text + " " + (fields.get("user_agent") or ""))
    # numeric features
    numeric = np.array([behavior["count_1m"], behavior["failed_5m"], behavior["unique_paths_1m"], int(status)])
    # assemble feature vector
    fv = np.hstack([numeric, text_feat]).astype(float)

    anomaly_info = predict_anomaly(fv)
    severity = severity_from_logic(sig_hits, anomaly_info, behavior)

    detection = {
        "ip": ip,
        "timestamp": datetime.utcfromtimestamp(ts).isoformat() + "Z",
        "path": path,
        "status": status,
        "signature_hits": sig_hits,
        "anomaly_score": anomaly_info["anomaly_score"],
        "anomaly_flag": anomaly_info["anomaly"],
        "behavior": behavior,
        "severity": severity,
    }

    # log detection
    log_detection(detection)

    if severity == "none":
        return jsonify({"status": "Log analyzed. Traffic is normal."})
    else:
        # map severity to suggested type
        return jsonify({"status": "Attack Detected", "type": ", ".join(sig_hits) or "Anomalous", "severity": severity, **detection})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), debug=False)
