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

# Model paths (These files must be in the same folder as this script)
MODEL_PATH = 'isolation_forest.joblib'
VECTORIZER_PATH = 'tfidf_vectorizer.joblib'

# Initialize Google Cloud Clients
# (Firestore automatically finds your database)
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
    # We don't crash here so the container can still start, 
    # but ML detection will be skipped.
    ML_MODEL = None
    VECTORIZER = None

# --- ATTACK SIGNATURES (Regex) ---
SIGNATURE_RULES = {
    "SQL_INJECTION": r"(\'|\%27)\s*(OR|UNION)\s*(\'|\%27|1)\s*(=|LIKE)\s*(\'|\%27|1)",
    "XSS_SCRIPTING": r"(<|%3C)\s*(script|img|onload|onerror)\s*(>|%3E|\s)",
    "COMMAND_INJECTION": r"(cat|ls|whoami|nmap|wget|curl|pwd|;|%3B)\s*(\/|%F|\s)"
}

def analyze_log_line(log_line):
    """
    Analyzes a single log line for threats using Signatures and ML.
    Returns: (Attack_Type, Severity, IP_Address)
    """
    
    # 1. Parse the log line (Matches standard Nginx format)
    # Pattern: IP - - [Date] "REQUEST" Status
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .*?"(.*?)" (\d{3})')
    match = re.search(log_pattern, log_line)
    
    if not match:
        return "Not Parseable", "None", "0.0.0.0"

    ip_address = match.group(1)
    request_details = match.group(2)
    
    # Decode URL (e.g., turn %20 into space)
    try:
        decoded_request = urllib.parse.unquote(request_details)
    except Exception:
        decoded_request = request_details

    detected_type = "Normal"
    severity = "None"

    # 2. Check Signatures (Layer 1 - Fast)
    for attack, pattern in SIGNATURE_RULES.items():
        if re.search(pattern, decoded_request, re.IGNORECASE):
            detected_type = attack
            severity = "High"
            break
    
    # 3. Check ML Model (Layer 2 - Zero Day)
    # Only run if signatures didn't find anything AND models are loaded
    if detected_type == "Normal" and ML_MODEL and VECTORIZER:
        try:
            # Convert text request to numbers
            features = VECTORIZER.transform([request_details])
            # Predict (-1 is anomaly/attack, 1 is normal)
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
    Main API Entry Point.
    Receives a POST request with {"log_line": "..."}
    """
    # 1. Only allow POST requests
    if request.method != 'POST':
        return ('Method Not Allowed', 405)
        
    try:
        # 2. Parse JSON body
        data = request.get_json(silent=True)
        if not data or 'log_line' not in data:
            return ('Missing "log_line" in request body', 400)
        
        log_line = data['log_line']
        print(f"Processing Log: {log_line}")
        
        # 3. Run Analysis
        detected_type, severity, ip_address = analyze_log_line(log_line)
        
        # 4. If Attack Detected, Save to Database
        if detected_type != "Normal":
            print(f"ATTACK FOUND: {detected_type}")
            
            # Create a unique ID for this event
            event_id = str(uuid.uuid4())
            
            # A. Save raw log text to Cloud Storage (Data Lake)
            try:
                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(f"raw-logs/{event_id}.txt")
                blob.upload_from_string(log_line)
            except Exception as e:
                print(f"Storage Error (Non-fatal): {e}")

            # B. Save structured alert to Firestore (Database)
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
            
            # Return JSON response
            return json.dumps({
                "status": "Attack Detected",
                "type": detected_type,
                "severity": severity,
                "ip": ip_address
            }), 200, {'Content-Type': 'application/json'}

        # 5. If Normal
        return ('Log analyzed. Traffic is normal.', 200)

    except Exception as e:
        print(f"FATAL ERROR: {e}")
        return (f"Internal Server Error: {e}", 500)