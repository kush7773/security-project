# main.py
import os
import re
import time
import json
import math
import joblib
import logging
import traceback
from datetime import datetime, timedelta
from collections import defaultdict, deque

from flask import Flask, request, jsonify

import numpy as np

# Optional Redis support (recommended for multi-instance deployments)
try:
    import redis
except Exception:
    redis = None

# --- Configuration ---
PORT = int(os.environ.get("PORT", "8080"))
REDIS_URL = os.environ.get("REDIS_URL")  # e.g. redis://:password@host:6379/0
USE_REDIS = (redis is not None) and (REDIS_URL is not None)

# Thresholds (tune these for your environment)
BRUTE_FORCE_WINDOW_S = 60 * 5         # 5 minutes
BRUTE_FORCE_FAILS_THRESHOLD = 10      # e.g., 10 failed logins in window -> suspicious
API_RATE_WINDOW_S = 60                # per minute
API_RATE_THRESHOLD = 120              # requests per minute -> API abuse
ANOMALY_SCORE_THRESHOLD = 0.5         # lower => more sensitive (IsolationForest gives negative/positive/score)
IP_USERAGENT_VARIETY_THRESHOLD = 10   # too many different UA's from same IP in short time
SUSPICIOUS_PAYLOAD_ENTROPY = 4.0

# Model file locations (pretrained)
TFIDF_PATH = os.environ.get("TFIDF_PATH", "tfidf_vectorizer.joblib")
PCA_PATH = os.environ.get("PCA_PATH", "pca.joblib")  # optional if you used PCA
IF_PATH = os.environ.get("IF_PATH", "isolation_forest.joblib")
SCALER_PATH = os.environ.get("SCALER_PATH", "scaler.joblib")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secapp")

app = Flask(__name__)

# Persistent stores (Redis-backed if configured)
if USE_REDIS:
    r = redis.from_url(REDIS_URL)
else:
    r = None
    # In-memory fallback (not shared across instances)
    ip_failures = defaultdict(deque)      # ip -> deque of fail timestamps
    ip_requests = defaultdict(deque)      # ip -> deque of request timestamps
    ip_useragents = defaultdict(lambda: defaultdict(int))  # ip -> ua -> count
    recent_events = deque(maxlen=10000)

# --- Signature regexes (simplified / extend these) ---
SIG_REGEXES = {
    "sql_injection": re.compile(r"(?i)\b(union(\s+all)?\s+select|or\s+1=1|--\s|#\s|/\*.*\*/|sleep\(|benchmark\()", re.IGNORECASE),
    "xss": re.compile(r"(?i)(<script\b|javascript:|onerror=|onload=|%3Cscript%3E)"),
    "path_traversal": re.compile(r"(\.\./|\.\.\\)"),
    "lfi": re.compile(r"(?i)(etc/passwd|proc/self/environ|/etc/shadow)"),
    "rce_cmd": re.compile(r"(?i)(;|\|\||\&\&|\$(\(|\{)|`.*`)\s*(curl|wget|nc|bash|sh)\b"),
    "log4shell": re.compile(r"(?i)\$\{jndi:(ldap|rmi|dns|iiop|corba):\/\/[^\s\}]+\}"),
    "ssrf": re.compile(r"(?i)http:\/\/127\.0\.0\.1|http:\/\/localhost|http:\/\/169\.254\.169\.254"),
    "file_upload_malicious": re.compile(r"(?i)\.(php|phtml|jsp|asp|aspx|exe|sh)$"),
    # Add more rules as you need...
}

# Helper: compute entropy of a string
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

# --- Model loading (if present) ---
tfidf = None
pca = None
isof = None
scaler = None

def safe_load_models():
    global tfidf, pca, isof, scaler
    try:
        if os.path.exists(TFIDF_PATH):
            tfidf = joblib.load(TFIDF_PATH)
            logger.info("Loaded TF-IDF vectorizer.")
    except Exception:
        logger.exception("Failed to load TF-IDF.")

    try:
        if os.path.exists(PCA_PATH):
            pca = joblib.load(PCA_PATH)
            logger.info("Loaded PCA.")
    except Exception:
        logger.info("No PCA loaded (optional).")

    try:
        if os.path.exists(IF_PATH):
            isof = joblib.load(IF_PATH)
            logger.info("Loaded IsolationForest.")
    except Exception:
        logger.exception("Failed to load IsolationForest.")

    try:
        if os.path.exists(SCALER_PATH):
            scaler = joblib.load(SCALER_PATH)
            logger.info("Loaded scaler.")
    except Exception:
        logger.info("No scaler loaded (optional).")


safe_load_models()

# --- Rate/behavior helpers ---
def now_ts():
    return int(time.time())

def add_ip_failure(ip):
    t = now_ts()
    if r:
        key = f"fail:{ip}"
        r.lpush(key, t)
        r.expire(key, BRUTE_FORCE_WINDOW_S + 10)
    else:
        dq = ip_failures[ip]
        dq.append(t)
        # prune old
        cutoff = t - BRUTE_FORCE_WINDOW_S
        while dq and dq[0] < cutoff:
            dq.popleft()

def count_ip_failures(ip):
    t = now_ts()
    if r:
        key = f"fail:{ip}"
        return r.llen(key)
    else:
        dq = ip_failures[ip]
        cutoff = t - BRUTE_FORCE_WINDOW_S
        return sum(1 for ts in dq if ts >= cutoff)

def add_ip_request(ip):
    t = now_ts()
    if r:
        key = f"req:{ip}"
        r.lpush(key, t)
        r.expire(key, API_RATE_WINDOW_S + 10)
    else:
        dq = ip_requests[ip]
        dq.append(t)
        cutoff = t - API_RATE_WINDOW_S
        while dq and dq[0] < cutoff:
            dq.popleft()

def count_ip_requests(ip):
    t = now_ts()
    if r:
        key = f"req:{ip}"
        return r.llen(key)
    else:
        dq = ip_requests[ip]
        cutoff = t - API_RATE_WINDOW_S
        return sum(1 for ts in dq if ts >= cutoff)

def add_useragent(ip, ua):
    t = now_ts()
    if r:
        key = f"ua:{ip}"
        r.hincrby(key, ua, 1)
        r.expire(key, API_RATE_WINDOW_S * 10)
    else:
        ip_useragents[ip][ua] += 1

def ua_variety(ip):
    if r:
        key = f"ua:{ip}"
        return len(r.hgetall(key))
    else:
        return len(ip_useragents[ip])

# --- Feature extraction for ML ---
def extract_features_from_log(line: str):
    """
    Return a combined numeric feature vector for the log_line.
    """
    # Basic numeric features
    features = {}
    features["len"] = len(line)
    features["entropy"] = shannon_entropy(line)
    features["digit_ratio"] = sum(ch.isdigit() for ch in line) / max(1, len(line))
    features["nonalnum_ratio"] = sum(not ch.isalnum() for ch in line) / max(1, len(line))
    # status code / response size extraction if present in typical log format
    # Try to parse "HTTP status" and "size" patterns
    m = re.search(r'"\s*(\d{3})\s+(\d+)', line)
    if m:
        features["status"] = int(m.group(1))
        features["size"] = int(m.group(2))
    else:
        features["status"] = 0
        features["size"] = 0
    return features

def vectorize_for_model(line: str):
    """
    Returns a 1D numpy array feature vector combining numeric features + TF-IDF reduced.
    """
    numeric = extract_features_from_log(line)
    numeric_arr = np.array([numeric["len"], numeric["entropy"], numeric["digit_ratio"],
                            numeric["nonalnum_ratio"], numeric["status"], numeric["size"]],
                           dtype=float).reshape(1, -1)
    # TF-IDF part
    tfidf_part = None
    if tfidf is not None:
        try:
            tf = tfidf.transform([line])
            if pca is not None:
                tf_reduced = pca.transform(tf.toarray())
            else:
                # if no PCA, reduce by taking top-k features (or average) -> keep small
                tf_reduced = tf.toarray()
            tfidf_part = tf_reduced
        except Exception:
            logger.exception("tfidf transform failed.")
            tfidf_part = None

    if tfidf_part is not None:
        # align shapes (if tf_reduced has many dims, try to reduce to something manageable)
        # If tfidf_part has shape (1, n), we can concatenante
        try:
            combined = np.hstack([numeric_arr, tfidf_part])
        except Exception:
            # fallback: just use numeric
            combined = numeric_arr
    else:
        combined = numeric_arr

    if scaler is not None:
        try:
            combined = scaler.transform(combined)
        except Exception:
            pass

    return combined.ravel()

# --- Detection pipeline ---
def detect_signatures(line: str):
    matches = []
    for name, rx in SIG_REGEXES.items():
        if rx.search(line):
            matches.append(name)
    return matches

def detect_behavior(ip: str, parsed):
    """
    parsed: dict containing parsed fields like path, status, method, user_agent etc.
    returns list of behavioral alerts
    """
    alerts = []
    add_ip_request(ip)
    add_useragent(ip, parsed.get("user_agent", "unknown"))

    # API rate abuse
    cnt = count_ip_requests(ip)
    if cnt > API_RATE_THRESHOLD:
        alerts.append(("api_rate_abuse", f"{cnt} reqs in last {API_RATE_WINDOW_S}s"))

    # brute force: detect repeated failed auths (status 401 or 403)
    if parsed.get("status") in (401, 403):
        add_ip_failure(ip)
        fails = count_ip_failures(ip)
        if fails >= BRUTE_FORCE_FAILS_THRESHOLD:
            alerts.append(("brute_force", f"{fails} failed auths in {BRUTE_FORCE_WINDOW_S}s"))

    # many distinct user agents from same IP in short period -> potential credential stuffing / bot farm
    variety = ua_variety(ip)
    if variety >= IP_USERAGENT_VARIETY_THRESHOLD:
        alerts.append(("ua_variety", f"{variety} distinct user agents in recent window"))

    return alerts

def parse_log_line(line: str):
    """
    Try to parse common fields: ip, datetime, method, path, protocol, status, size, user-agent if present.
    Returns dict with fields (some optional).
    """
    parsed = {}
    # IP
    m_ip = re.match(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+", line)
    if m_ip:
        parsed["ip"] = m_ip.group(1)
    else:
        parsed["ip"] = "0.0.0.0"

    # status and size
    m_status = re.search(r'"\s*(\d{3})\s+(\d+)', line)
    if m_status:
        parsed["status"] = int(m_status.group(1))
        parsed["size"] = int(m_status.group(2))
    else:
        parsed["status"] = None
        parsed["size"] = None

    # method and path inside quotes ("GET /path HTTP/1.1")
    m_req = re.search(r'\"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^"]+?)\s+HTTP/[\d\.]+"', line)
    if m_req:
        parsed["method"] = m_req.group(1)
        parsed["path"] = m_req.group(2)
    else:
        # fallbacks
        parsed["method"] = None
        parsed["path"] = None

    # user-agent (very naive)
    m_ua = re.search(r'\"[^\"]*\"\s*\"([^\"]+)\"$', line)
    if m_ua:
        parsed["user_agent"] = m_ua.group(1)
    else:
        parsed["user_agent"] = None

    return parsed

@app.route("/", methods=["POST"])
def analyze_log():
    try:
        if not request.is_json:
            return jsonify({"status": "Error", "message": "Content-Type must be application/json"}), 400
        payload = request.get_json()
        if not payload or "log_line" not in payload:
            return jsonify({"status": "Error", "message": "JSON must contain 'log_line' field"}), 400

        line = payload["log_line"]
        # detect signaures
        sigs = detect_signatures(line)
        parsed = parse_log_line(line)
        ip = parsed.get("ip", "0.0.0.0")

        behavior_alerts = detect_behavior(ip, parsed)

        # ML anomaly scoring
        anomaly = None
        anomaly_score = None
        try:
            if isof is not None:
                vec = vectorize_for_model(line).reshape(1, -1)
                # IsolationForest: decision_function higher means more normal -> negative means anomaly depending on sklearn version
                # But we'll use scoring: lower => more anomalous
                score = float(isof.decision_function(vec)[0])
                anomaly_score = score
                # Convert to intuitive anomaly flag (custom threshold)
                if score < ANOMALY_SCORE_THRESHOLD:
                    anomaly = True
                else:
                    anomaly = False
        except Exception:
            logger.exception("ML scoring failed")

        alerts = []
        severity = "None"

        # Collect signature alerts (map to severity)
        if sigs:
            alerts.extend([{"type": s, "source": "signature"} for s in sigs]
                          )
            # if we detected critical signatures, raise severity
            if any(s in ("rce_cmd", "log4shell", "lfi") for s in sigs):
                severity = "High"
            else:
                severity = "Medium"

        # behavior alerts
        if behavior_alerts:
            alerts.extend([{"type": a[0], "source": "behavior", "detail": a[1]} for a in behavior_alerts])
            if any(a[0] == "brute_force" for a in behavior_alerts):
                severity = "High"
            else:
                if severity != "High":
                    severity = "Medium"

        # ML anomaly
        if anomaly is True:
            alerts.append({"type": "anomaly_ml", "source": "ml", "score": anomaly_score})
            if severity != "High":
                severity = "Medium"

        # If no alerts: normal
        if not alerts:
            return jsonify({"status": "Log analyzed. Traffic is normal."})

        out = {
            "status": "Attack Detected",
            "severity": severity,
            "alerts": alerts,
            "ip": ip,
            "raw": line
        }
        return jsonify(out)
    except Exception as e:
        logger.exception("Unhandled exception in analyze_log")
        return jsonify({"status": "Error", "message": str(e), "trace": traceback.format_exc()}), 500

if __name__ == "__main__":
    # GCP will set $PORT; for local debug set FLASK_DEBUG=1 and run with python main.py
    app.run(host="0.0.0.0", port=PORT)