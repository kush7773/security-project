# main.py (recommended replacement)
import functions_framework
from google.cloud import storage, firestore
import joblib
import os
import re
import urllib.parse
import uuid
import json
import logging

# --- CONFIG ---
BUCKET_NAME = os.environ.get("BUCKET_NAME", "siem-logs-kush-unique")
MODEL_PATH = os.environ.get("MODEL_PATH", "isolation_forest.joblib")
VECTORIZER_PATH = os.environ.get("VECTORIZER_PATH", "tfidf_vectorizer.joblib")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("siem-detector")

# Initialize Google clients
try:
    db = firestore.Client()
    storage_client = storage.Client()
except Exception as e:
    logger.warning("Google Cloud clients initialization failed - running locally without GCP integration: %s", e)
    db = None
    storage_client = None

# Load ML artifacts (if present)
ML_MODEL = None
VECTORIZER = None
try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        VECTORIZER = joblib.load(VECTORIZER_PATH)
        ML_MODEL = joblib.load(MODEL_PATH)
        logger.info("ML artifacts loaded.")
    else:
        logger.warning("ML artifacts not found at %s and %s. Skipping ML detection.", MODEL_PATH, VECTORIZER_PATH)
except Exception as e:
    logger.exception("Error loading ML artifacts: %s", e)
    ML_MODEL = None
    VECTORIZER = None

# Improved signature rules (expanded)
SIGNATURE_RULES = {
    # Basic SQLi patterns (covers many simple encodings)
    "SQL_INJECTION": re.compile(
        r"(?:(\bUNION\b.*\bSELECT\b)|(\bSELECT\b.*\bFROM\b)|(\bOR\b\s+\d+=\d+)|(\b1=1\b)|(%27)|(' OR '1'='1')|(--\s)|(%2F\*)|(\bDROP\b\s+\bTABLE\b))",
        re.IGNORECASE
    ),
    "XSS_SCRIPTING": re.compile(r"(<\s*script|<\s*img|onerror\s*=|onload\s*=|%3Cscript%3E)", re.IGNORECASE),
    "COMMAND_INJECTION": re.compile(r"(\b(cat|ls|whoami|nc|nmap|wget|curl|bash|sh)\b|;|\|\||\`|\$\(.*\))", re.IGNORECASE),
    "LFI": re.compile(r"(\.\./|\b/etc/passwd\b|\bproc/self/environ\b)", re.IGNORECASE),
    "DIR_TRAVERSAL": re.compile(r"\.\./\.\./|\.\./", re.IGNORECASE),
    "RFI": re.compile(r"(http://|https://).*\.(php|phtml|pl|py)", re.IGNORECASE),
    "SSRF": re.compile(r"(http://127\.0\.0\.1|http://169\.254\.)", re.IGNORECASE),
    "SUSPICIOUS_ENCODING": re.compile(r"(%3C|%3E|%27|%22|%3B|%252F)", re.IGNORECASE),
}

# Flexible nginx/Apache log parser which extracts IP, request line and status if possible
LOG_PATTERN = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"(?P<request>[^"]+)"\s+(?P<status>\d{3})')

def parse_log_line(log_line: str):
    match = LOG_PATTERN.search(log_line)
    if not match:
        # fallback: try to extract IP and everything after
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', log_line)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"
        return ip, log_line, None
    return match.group("ip"), match.group("request"), match.group("status")

def analyze_log_line(log_line: str):
    ip_address, request_details, status = parse_log_line(log_line)
    try:
        decoded_request = urllib.parse.unquote(request_details or "")
    except Exception:
        decoded_request = request_details or ""

    detected_type = "Normal"
    severity = "None"
    evidence = []

    # Signature detection
    for attack_name, pattern in SIGNATURE_RULES.items():
        if pattern.search(decoded_request):
            detected_type = attack_name
            # grade severity
            if attack_name in ("SQL_INJECTION", "COMMAND_INJECTION", "RFI", "LFI"):
                severity = "High"
            elif attack_name in ("SSRF", "DIR_TRAVERSAL"):
                severity = "Medium"
            else:
                severity = "Low"
            evidence.append(pattern.pattern)
            break

    # ML anomaly detection (only if we still think Normal)
    ml_score = None
    if detected_type == "Normal" and ML_MODEL and VECTORIZER:
        try:
            features = VECTORIZER.transform([decoded_request])
            pred = ML_MODEL.predict(features)
            # IsolationForest returns array, -1 indicates anomaly
            is_anomaly = int(pred[0]) == -1
            if is_anomaly:
                detected_type = "ML_ANOMALY_ZERO_DAY"
                severity = "Critical"
            # if available, try to get anomaly score (decision_function)
            try:
                score = ML_MODEL.decision_function(features)[0]
                ml_score = float(score)
            except Exception:
                ml_score = None
        except Exception as e:
            logger.exception("ML prediction error: %s", e)

    return {
        "type": detected_type,
        "severity": severity,
        "ip": ip_address,
        "evidence": evidence,
        "ml_score": ml_score,
        "raw_request": decoded_request,
        "status": status
    }

@functions_framework.http
def log_ingestion_api(request):
    if request.method != "POST":
        return (json.dumps({"error": "Only POST allowed"}), 405, {"Content-Type": "application/json"})

    # Parse JSON safely
    try:
        payload = request.get_json(silent=True)
        if not payload or "log_line" not in payload:
            return (json.dumps({"error": "Missing 'log_line' in JSON body"}), 400, {"Content-Type": "application/json"})
        log_line = payload["log_line"]
    except Exception as e:
        logger.exception("Bad request JSON: %s", e)
        return (json.dumps({"error": "Invalid JSON"}), 400, {"Content-Type": "application/json"})

    logger.info("Analyzing log: %s", (log_line if len(log_line) < 2000 else log_line[:2000] + "..."))

    result = analyze_log_line(log_line)

    # If detected, store evidence and raw log
    if result["type"] != "Normal":
        event_id = str(uuid.uuid4())
        # Save raw to storage (best-effort)
        if storage_client:
            try:
                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(f"raw-logs/{event_id}.log")
                blob.upload_from_string(log_line)
            except Exception:
                logger.exception("Failed to store raw log to GCS")

        # Save structured event to Firestore (best-effort)
        if db:
            try:
                doc_ref = db.collection("DetectedAttacks").document(event_id)
                doc = {
                    "timestamp": firestore.SERVER_TIMESTAMP,
                    "event_id": event_id,
                    "ip": result["ip"],
                    "detected_type": result["type"],
                    "severity": result["severity"],
                    "evidence": result["evidence"],
                    "ml_score": result["ml_score"],
                    "raw_log": log_line,
                    "status": "Logged"
                }
                doc_ref.set(doc)
            except Exception:
                logger.exception("Failed to write to Firestore")

        resp = {
            "status": "Attack Detected",
            "type": result["type"],
            "severity": result["severity"],
            "ip": result["ip"],
            "ml_score": result["ml_score"]
        }
        return (json.dumps(resp), 200, {"Content-Type": "application/json"})

    # Normal
    return (json.dumps({"status": "Log analyzed. Traffic is normal."}), 200, {"Content-Type": "application/json"})