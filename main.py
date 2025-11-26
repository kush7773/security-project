import functions_framework
from google.cloud import storage
from google.cloud import firestore
import joblib
import os
import re
import urllib.parse
import uuid
import json
import time

# --- CONFIGURATION ---
# Update this to your exact Google Cloud Storage bucket name
BUCKET_NAME = 'siem-logs-kush-unique' 

# Model paths (Models are expected to be in the root directory for Cloud Run build)
MODEL_PATH = 'isolation_forest.joblib'
VECTORIZER_PATH = 'tfidf_vectorizer.joblib'

# Initialize Google Cloud Clients
db = firestore.Client()
storage_client = storage.Client()

# --- LOAD MODELS (Runs once when container starts) ---
try:
    print("Loading ML models into memory...")
    ML_MODEL = joblib.load(MODEL_PATH)
    VECTORIZER = joblib.load(VECTORIZER_PATH)
    print("SUCCESS: ML Models loaded.")
except Exception as e:
    print(f"CRITICAL WARNING: Could not load ML models: {e}")
    ML_MODEL = None
    VECTORIZER = None

# Attack Signatures
SIGNATURE_RULES = {
    "SQL_INJECTION": r"(\'|\%27)\s*(OR|UNION)\s*(\'|\%27|1)\s*(=|LIKE)\s*(\'|\%27|1)",
    "XSS_SCRIPTING": r"(<|%3C)\s*(script|img|onload|onerror)\s*(>|%3E|\s)",
    "COMMAND_INJECTION": r"(cat|ls|whoami|nmap|wget|curl|pwd|;|%3B)\s*(\/|%F|\s)"
}

def analyze_log_line(log_line):
    # ... (Detection logic remains the same) ...
    # Omitted for brevity, but this function is in your file.
    
    # 1. Parse the log line (Matches standard Nginx format)
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .*?"(.*?)" (\d{3})')
    match = re.search(log_pattern, log_line)
    
    if not match:
        return "Not Parseable", "None", "0.0.0.0"

    ip_address = match.group(1)
    request_details = match.group(2)
    
    try:
        decoded_request = urllib.parse.unquote(request_details)
    except Exception:
        decoded_request = request_details

    detected_type = "Normal"
    severity = "None"

    # 2. Check Signatures
    for attack, pattern in SIGNATURE_RULES.items():
        if re.search(pattern, decoded_request, re.IGNORECASE):
            detected_type = attack
            severity = "High"
            break
    
    # 3. Check ML Model
    if detected_type == "Normal" and ML_MODEL and VECTORIZER:
        try:
            features = VECTORIZER.transform([request_details])
            prediction = ML_MODEL.predict(features)
            
            if prediction == -1: 
                detected_type = "ML_ANOMALY_ZERO_DAY"
                severity = "Critical"
        except Exception as e:
            print(f"ML Prediction Error: {e}")
            
    return detected_type, severity, ip_address


@functions_framework.http
def log_ingestion_api(request):
    """
    Main API Entry Point. Receives logs via HTTP POST request.
    """
    if request.method != 'POST':
        return ('Method Not Allowed', 405)
        
    try:
        data = request.get_json(silent=True)
        if not data or 'log_line' not in data:
            return ('Missing "log_line" in request body', 400)
        
        log_line = data['log_line']
        print(f"Processing Log: {log_line}")
        
        # 1. Run Analysis
        detected_type, severity, ip_address = analyze_log_line(log_line)
        
        # 2. Save to Database
        if detected_type != "Normal":
            event_id = str(uuid.uuid4())
            
            # Save raw log to Cloud Storage (Data Lake)
            try:
                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(f"raw-logs/{event_id}.txt")
                blob.upload_from_string(log_line)
            except Exception as e:
                print(f"Storage Error (Non-fatal): {e}")

            # Save structured alert to Firestore (Database)
            doc_ref = db.collection("DetectedAttacks").document(event_id)
            attack_data = {
                "timestamp": firestore.SERVER_TIMESTAMP,
                "ip": ip_address, 
                "type": detected_type,
                "severity": severity,
                "raw_log": log_line,
                "status": "Logged"
            }
            doc_ref.set(attack_data)
            
            return json.dumps({
                "status": "Attack Detected",
                "type": detected_type,
                "severity": severity,
                "ip": ip_address
            }), 200, {'Content-Type': 'application/json'}

        return ('Log analyzed. Traffic is normal.', 200)

    except Exception as e:
        print(f"FATAL ERROR: {e}")
        return (f"Internal Server Error: {e}", 500)