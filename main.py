# main.py
import functions_framework
from google.cloud import storage, firestore
import joblib
import os
import re
import urllib.parse
import uuid
import json
import time
from datetime import datetime, timedelta

# ---------- CONFIG ----------
BUCKET_NAME = os.environ.get('BUCKET_NAME', 'siem-logs-kush-unique')  # set via env in Cloud Run
MODEL_PATH = os.environ.get('MODEL_PATH', 'isolation_forest.joblib')
VECTORIZER_PATH = os.environ.get('VECTORIZER_PATH', 'tfidf_vectorizer.joblib')

# thresholds (tweak for your environment)
BRUTE_FORCE_WINDOW_SECONDS = 60       # lookback window for brute force counts
BRUTE_FORCE_THRESHOLD = 10           # number of failed auth-like requests in window -> alert
API_ABUSE_WINDOW_SECONDS = 60        # rate window for quick API abuse detection
API_ABUSE_THRESHOLD = 30             # > threshold requests in window -> alert

# ---------- Initialize Clients ----------
db = firestore.Client()
storage_client = storage.Client()

# ---------- Load ML Models ----------
ML_MODEL = None
VECTORIZER = None
try:
    print("Loading ML models...")
    if os.path.exists(MODEL_PATH):
        ML_MODEL = joblib.load(MODEL_PATH)
    if os.path.exists(VECTORIZER_PATH):
        VECTORIZER = joblib.load(VECTORIZER_PATH)
    print("Model load complete. ML_MODEL=%s VECTORIZER=%s" % (bool(ML_MODEL), bool(VECTORIZER)))
except Exception as e:
    print(f"[WARN] Failed to load ML models: {e}")
    ML_MODEL = None
    VECTORIZER = None

# ---------- Signature rules (improved) ----------
# These are regexes matched against the URL+query string and headers when available.
SIGNATURE_RULES = {
    "SQL_INJECTION": r"(?i)(\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bunion\b.*\bselect\b|(\%27|')\s*(or|and)\s*('|\%27|\d)\s*=|--|\bupdate\b.*\bset\b|\bdrop\b.*\btable\b)",
    "XSS_SCRIPTING": r"(?i)(<script\b|%3Cscript%3E|javascript:|onerror=|onload=|<img\b.*\bon\w+=)",
    "COMMAND_INJECTION": r"(?i)(;|\&\&|\|\||\$\(.*\)|\`.*\`|\b(cat|ls|whoami|nmap|wget|curl|nc)\b)",
    "DIR_TRAVERSAL": r"(\.\./|\.\.\\)",
    "LOCAL_FILE_INCLUSION": r"(?i)(\b(include|require)\b.*\b(http|ftp|file):\/\/|\.\.\/etc\/passwd)",
    "REMOTE_FILE_INCLUSION": r"(?i)(\bhttps?:\/\/|ftp:\/\/).*\.(php|txt|sh|asp)",
    "SSRF": r"(?i)(http:\/\/|https:\/\/|file:\/\/|gopher:\/\/).*(127\.0\.0\.1|169\.254|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    "LOG4SHELL": r"\$\{\s*jndi:(ldap|rmi|dns)://[^\}]+\}",
    "SHELLOSHOCK": r"\(\)\s*\{\s*:\s*;\s*\};",  # shellshock user agent pattern
    "XML_EXTERNAL_ENTITY": r"(?i)<!DOCTYPE\s+[^>]+ENTITY|<!ENTITY\s+%.*SYSTEM",
}

# Helper: parse common Apache/Nginx combined log pattern
LOG_PATTERN = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - .*?"(?P<request>.*?)" (?P<status>\d{3})')

def parse_log_line(log_line):
    """Extract ip, request (method+path+proto) and optionally headers if appended."""
    m = LOG_PATTERN.search(log_line)
    if not m:
        return None
    ip = m.group('ip')
    request = m.group('request')  # e.g. GET /path?x=1 HTTP/1.1
    status = m.group('status')
    return {'ip': ip, 'request': request, 'status': status}

def scan_signatures(text):
    """Returns (attack_name, pattern_matched) or (None,None)."""
    if not text:
        return None, None
    decoded = urllib.parse.unquote_plus(text)
    for name, pattern in SIGNATURE_RULES.items():
        try:
            if re.search(pattern, decoded, re.IGNORECASE):
                return name, pattern
        except re.error:
            continue
    return None, None

def ml_anomaly_check(request_text):
    """Use IsolationForest & TF-IDF vectorizer to flag anomalies (zero-day candidates)."""
    if not ML_MODEL or not VECTORIZER:
        return False, 0.0
    try:
        features = VECTORIZER.transform([request_text])
        pred = ML_MODEL.predict(features)            # -1 anomaly, 1 normal
        score = float(ML_MODEL.decision_function(features))  # anomaly score (higher = more normal)
        is_anomaly = int(pred[0]) == -1
        return is_anomaly, float(score)
    except Exception as e:
        print(f"[ML ERROR] {e}")
        return False, 0.0

def increment_counter_and_check(ip, kind, window_seconds, threshold):
    """
    Keep simple counters in Firestore for short-term detection (brute force / api abuse).
    Firestore doc per IP+kind with a timestamps list (limited).
    """
    now_ts = int(time.time())
    doc_id = f"{kind}#{ip}"
    doc_ref = db.collection("TransientCounters").document(doc_id)
    try:
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            times = data.get("times", [])
        else:
            times = []
        # drop old entries
        cutoff = now_ts - window_seconds
        times = [t for t in times if t >= cutoff]
        times.append(now_ts)
        doc_ref.set({"times": times, "updated": firestore.SERVER_TIMESTAMP})
        if len(times) >= threshold:
            return True, len(times)
        return False, len(times)
    except Exception as e:
        print(f"[COUNTER ERROR] {e}")
        return False, 0

def save_alert_to_firestore(event):
    """Persist structured alert doc to Firestore DetectedAttacks collection."""
    event_id = str(uuid.uuid4())
    try:
        db.collection("DetectedAttacks").document(event_id).set(event)
        return event_id
    except Exception as e:
        print(f"[FIRESTORE SAVE ERROR] {e}")
        return None

def upload_raw_log(event_id, raw_log):
    """Save raw log to a GCS blob for later forensic analysis."""
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"raw-logs/{event_id}.log")
        blob.upload_from_string(raw_log)
        return True
    except Exception as e:
        print(f"[GCS UPLOAD ERROR] {e}")
        return False

@functions_framework.http
def log_ingestion_api(request):
    """
    HTTP POST: { "log_line": "<single access log line>", "headers": {...} (optional) }
    Returns JSON with detection results.
    """
    if request.method != 'POST':
        return ('Method Not Allowed', 405)

    payload = request.get_json(silent=True)
    if not payload or 'log_line' not in payload:
        return ('Missing "log_line" in request body', 400)

    log_line = payload['log_line']
    parsed = parse_log_line(log_line)
    if not parsed:
        # return something parseable back to the caller so curl doesn't get stuck
        return json.dumps({"status": "Not Parseable", "type": "None", "severity": "None", "ip": "0.0.0.0"}), 200, {'Content-Type': 'application/json'}

    ip = parsed['ip']
    request_text = parsed['request']  # use this for textual analysis
    if payload.get('headers'):
        # append headers text to detection string (helps shellshock, user-agent checks)
        headers_text = " ".join([f"{k}:{v}" for k, v in payload.get('headers').items()])
    else:
        headers_text = ""

    full_analysis_text = f"{request_text} {headers_text}"

    detected = []
    severity = "None"

    # 1) Signature scanning
    attack_name, pattern = scan_signatures(full_analysis_text)
    if attack_name:
        severity = "High" if attack_name not in ("SHELLOSHOCK", "LOG4SHELL") else "Critical"
        detected.append({"type": attack_name, "match": pattern})

    # 2) ML anomaly (zero-day candidate)
    if not detected:
        is_anom, score = ml_anomaly_check(request_text)
        if is_anom:
            detected.append({"type": "ML_ANOMALY_ZERO_DAY", "score": score})
            severity = "Critical"

    # 3) Brute-force / API abuse heuristics (stateful)
    # Very simple rules: look for repeated 'login' or '/auth' or status 401-like patterns
    if re.search(r"(?i)(login|auth|signin|password|passwd)", request_text):
        bf_alert, bf_count = increment_counter_and_check(ip, "BRUTE", BRUTE_FORCE_WINDOW_SECONDS, BRUTE_FORCE_THRESHOLD)
        if bf_alert:
            detected.append({"type": "BRUTE_FORCE", "count": bf_count})
            severity = max(severity, "High", key=lambda x: ["None","Low","Medium","High","Critical"].index(x) if x in ["None","Low","Medium","High","Critical"] else 0)

    # API abuse detection: many requests from same IP in short time
    abuse_alert, abuse_count = increment_counter_and_check(ip, "RATE", API_ABUSE_WINDOW_SECONDS, API_ABUSE_THRESHOLD)
    if abuse_alert:
        detected.append({"type": "API_ABUSE_RATE", "count": abuse_count})
        severity = max(severity, "High", key=lambda x: ["None","Low","Medium","High","Critical"].index(x) if x in ["None","Low","Medium","High","Critical"] else 0)

    # If we have any detection, save an event and store raw log
    if detected:
        event = {
            "timestamp": firestore.SERVER_TIMESTAMP,
            "ip": ip,
            "type": detected,
            "severity": severity,
            "raw_log": log_line,
            "received_at": datetime.utcnow().isoformat() + "Z",
            "status": "Logged"
        }
        event_id = save_alert_to_firestore(event)
        if event_id:
            upload_raw_log(event_id, log_line)
        resp = {"status": "Attack Detected", "findings": detected, "severity": severity, "ip": ip}
        return json.dumps(resp), 200, {'Content-Type': 'application/json'}

    # No detection - normal
    return json.dumps({"status": "OK", "type": "Normal", "ip": ip}), 200, {'Content-Type': 'application/json'}
