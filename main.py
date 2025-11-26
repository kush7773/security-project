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

# --- CONFIG ---
BUCKET_NAME = os.environ.get('BUCKET_NAME', 'siem-logs-kush-unique')
MODEL_PATH = os.environ.get('MODEL_PATH', 'isolation_forest.joblib')
VECTORIZER_PATH = os.environ.get('VECTORIZER_PATH', 'tfidf_vectorizer.joblib')

# thresholds (tune these)
BRUTE_FORCE_WINDOW_SECONDS = 60 * 5   # 5 minutes
BRUTE_FORCE_THRESHOLD = 10            # 10 failed logins in window => brute force
API_ABUSE_WINDOW_SECONDS = 60         # 1 minute
API_ABUSE_THRESHOLD = 50              # 50 requests to same endpoint from same IP in window

# initialize google clients
db = firestore.Client()
storage_client = storage.Client()

# load ML models (if present)
ML_MODEL = None
VECTORIZER = None
try:
    print("Loading ML model and vectorizer...")
    if os.path.exists(MODEL_PATH):
        ML_MODEL = joblib.load(MODEL_PATH)
    if os.path.exists(VECTORIZER_PATH):
        VECTORIZER = joblib.load(VECTORIZER_PATH)
    print("Model load attempted. ML_MODEL:", bool(ML_MODEL), "VECTORIZER:", bool(VECTORIZER))
except Exception as e:
    print("Warning: could not load ML model/vectorizer:", e)
    ML_MODEL = None
    VECTORIZER = None

# --- SIGNATURE RULES (expand as needed) ---
SIGNATURE_RULES = {
    # SQLi (basic patterns)
    "SQL_INJECTION": r"(?:(\%27|')\s*(?:or|and)\s*(?:\%27|')?\s*\d+\s*=\s*\d+|union\s+select|--\s|/\*|\*/|drop\s+table)",
    # XSS
    "XSS_SCRIPTING": r"(<\s*script\b|%3Cscript%3E|onerror=|onload=|<img\s+src=)",
    # Command injection
    "COMMAND_INJECTION": r"(\b(cat|ls|whoami|wget|curl|nc|nmap|bash|sh)\b|\;|\$\(|\`|\|)",
    # Local/Remote File Inclusion
    "LFI_RFI": r"(\.\./\.\.|etc/passwd|file=\/|include_path=|php://filter|data:php)",
    # SSRF common patterns (http:// followed by private/external addresses)
    "SSRF": r"(http:\/\/|https:\/\/)(localhost|127\.0\.0\.1|169\.254|0\.0\.0\.0|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    # Log4Shell / JNDI (Log4j exploitation strings)
    "LOG4SHELL": r"\$\{jndi:(?:ldap|rmi|dns|iiop|corba):\/\/[^\}\s]+\}",
    # LDAP/JNDI attempts encoded
    "LOG4SHELL_ENCODED": r"(%24%7Bjndi:|%24%7Bjndi%3A)(ldap|rmi|dns)",
    # Path traversal
    "PATH_TRAVERSAL": r"(\.\./\.\.|%2e%2e%2f|%2e%2e/)",
    # Common webshell probes (php eval etc)
    "WEBSHELL": r"(eval\(|base64_decode\(|system\(|passthru\(|exec\(|assert\()",
}

# regexp to parse common log format: IP - - [time] "REQUEST" status size
LOG_PATTERN = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}) - .*?"(.*?)" (\d{3})')

def _firestore_increment_counter(collection, doc_id, field, increment=1, extra_update=None):
    """Atomic increment with expiry metadata for counters used in detection."""
    doc_ref = db.collection(collection).document(doc_id)
    now = firestore.SERVER_TIMESTAMP
    def txn_func(txn):
        snapshot = doc_ref.get(transaction=txn)
        if snapshot.exists:
            data = snapshot.to_dict()
            # If stored timestamp is older than window, reset counter
            # We'll keep client-side windowing check as well.
            txn.update(doc_ref, {field: firestore.Increment(increment), 'last_seen': now})
        else:
            doc_data = {field: increment, 'first_seen': now, 'last_seen': now}
            if extra_update:
                doc_data.update(extra_update)
            txn.set(doc_ref, doc_data)
    try:
        db.run_transaction(txn_func)
    except Exception as e:
        print("Firestore counter increment error:", e)

def check_brute_force(ip, endpoint, is_failed_login):
    """Track failed logins per IP (and per endpoint optionally) in Firestore."""
    # doc id per IP (you can also use per-ip+endpoint)
    doc_id = f"bf::{ip}"
    if is_failed_login:
        _firestore_increment_counter("BruteForceCounters", doc_id, "failed_count", increment=1,
                                    extra_update={"last_endpoint": endpoint})
    # read recent counters and decide
    doc_ref = db.collection("BruteForceCounters").document(doc_id)
    try:
        doc = doc_ref.get()
        if not doc.exists:
            return False, 0
        data = doc.to_dict()
        failed = data.get("failed_count", 0)
        # Simple approach: if failed_count >= threshold => alert
        if failed >= BRUTE_FORCE_THRESHOLD:
            return True, failed
        return False, failed
    except Exception as e:
        print("Error reading brute force counters:", e)
        return False, 0

def check_api_abuse(ip, endpoint):
    """Track per-ip endpoint requests rate. Store small window counts in Firestore."""
    # doc key per ip+endpoint
    safe_endpoint = re.sub(r'[^0-9A-Za-z_\-]', '_', endpoint)[:200]
    doc_id = f"api::{ip}::{safe_endpoint}"
    _firestore_increment_counter("APIRequestCounters", doc_id, "count", increment=1)
    doc_ref = db.collection("APIRequestCounters").document(doc_id)
    try:
        doc = doc_ref.get()
        if not doc.exists:
            return False, 0
        data = doc.to_dict()
        cnt = data.get("count", 0)
        if cnt >= API_ABUSE_THRESHOLD:
            return True, cnt
        return False, cnt
    except Exception as e:
        print("API abuse counter read error:", e)
        return False, 0

def analyze_log_line(log_line):
    """
    Returns: (detected_type, severity, ip, meta)
    meta is a dict with helpful debugging info.
    """
    meta = {}
    # parse
    match = re.search(LOG_PATTERN, log_line)
    if not match:
        return "NOT_PARSEABLE", "None", "0.0.0.0", {"raw": log_line}

    ip = match.group(1)
    request_details = match.group(2)  # e.g. GET /path?foo=bar HTTP/1.1
    status = match.group(3)
    meta['request_raw'] = request_details
    # decode URL encoded content
    try:
        decoded = urllib.parse.unquote_plus(request_details)
    except Exception:
        decoded = request_details
    meta['request_decoded'] = decoded

    detected = "Normal"
    severity = "None"

    # Split out method and path
    method = None
    path = decoded
    try:
        parts = decoded.split()
        if len(parts) >= 2:
            method = parts[0]
            path = parts[1]
    except Exception:
        pass
    meta['method'] = method
    meta['path'] = path
    # 1) Signature-based detection: check expanded rules
    for name, pattern in SIGNATURE_RULES.items():
        try:
            if re.search(pattern, decoded, re.IGNORECASE):
                detected = name
                severity = "High" if name not in ("LOG4SHELL", "LOG4SHELL_ENCODED") else "Critical"
                meta['signature_pattern'] = pattern
                break
        except re.error:
            continue

    # 2) Behavioral detections
    # Brute-force: consider 401/403 responses or login endpoint patterns
    is_failed_login = False
    st = int(status) if status and status.isdigit() else 0
    if st in (401, 403):
        is_failed_login = True
    # also heuristics for login paths
    if re.search(r"/auth|/login|/signin|/wp-login.php", path, re.IGNORECASE):
        # treat 401/403 as failed login; else count attempts too
        if st in (401, 403):
            is_failed_login = True

    if is_failed_login:
        bf_alert, bf_count = check_brute_force(ip, path, True)
        meta['brute_failed_count'] = bf_count
        if bf_alert:
            detected = "BRUTE_FORCE"
            severity = "High"

    # API abuse: high request rate to same endpoint
    abuse_alert, abuse_count = check_api_abuse(ip, path)
    meta['api_request_count'] = abuse_count
    if abuse_alert:
        detected = "API_ABUSE"
        severity = "High"

    # 3) ML Anomaly detection (zero-day) if still normal
    if detected == "Normal" and ML_MODEL and VECTORIZER:
        try:
            # we use the decoded request string as feature; consider adding UA/headers later
            features = VECTORIZER.transform([decoded])
            pred = ML_MODEL.predict(features)  # IsolationForest -> -1 is anomaly
            if hasattr(pred, "__len__") and pred[0] == -1:
                detected = "ML_ANOMALY_ZERO_DAY"
                severity = "Critical"
                meta['ml_pred'] = int(pred[0])
        except Exception as e:
            meta['ml_error'] = str(e)

    meta['detected_after'] = datetime.utcnow().isoformat() + "Z"
    return detected, severity, ip, meta

def persist_alert(detected_type, severity, ip, log_line, meta):
    """Store raw log + structured alert into Cloud Storage + Firestore"""
    event_id = str(uuid.uuid4())
    # Save raw log to bucket
    try:
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(f"raw-logs/{event_id}.log")
        blob.upload_from_string(log_line)
    except Exception as e:
        print("Storage upload error:", e)
    # Save structured alert to Firestore
    try:
        doc_ref = db.collection("DetectedAttacks").document(event_id)
        doc_ref.set({
            "timestamp": firestore.SERVER_TIMESTAMP,
            "ip": ip,
            "type": detected_type,
            "severity": severity,
            "raw_log": log_line,
            "meta": meta,
            "status": "Logged"
        })
    except Exception as e:
        print("Firestore save alert error:", e)

@functions_framework.http
def log_ingestion_api(request):
    """
    Cloud Function-style HTTP entrypoint used via functions-framework.
    Expects JSON body: {"log_line": "..."}
    """
    if request.method != 'POST':
        return ('Method Not Allowed', 405)

    data = request.get_json(silent=True)
    if not data or 'log_line' not in data:
        return ('Missing "log_line" in request body', 400)

    log_line = data['log_line']
    print("Received log:", log_line)
    detected, severity, ip, meta = analyze_log_line(log_line)

    # If an attack detected, persist alert
    if detected != "Normal" and detected != "NOT_PARSEABLE":
        try:
            persist_alert(detected, severity, ip, log_line, meta)
        except Exception as e:
            print("Error persisting alert:", e)
        resp = {
            "status": "Attack Detected",
            "type": detected,
            "severity": severity,
            "ip": ip,
            "meta": meta
        }
        return (json.dumps(resp), 200, {'Content-Type': 'application/json'})

    # For normal logs, return a simple message
    return (json.dumps({"status": "Log analyzed. Traffic is normal."}), 200, {'Content-Type': 'application/json'})
