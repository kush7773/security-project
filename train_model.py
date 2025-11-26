# train_model.py
# This script reads the clean log file, trains the ML model, 
# and saves the models to disk for the API to use.

import re
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import sys
import os

# --- CONFIGURATION ---
CLEAN_LOG_FILE = "clean_access.log"
MODEL_FILE = "isolation_forest.joblib"
VECTORIZER_FILE = "tfidf_vectorizer.joblib"

log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .*?"(.*?)" (\d{3})')

def load_and_parse_logs():
    """Loads the clean log file and extracts the request part."""
    
    # Check if we have the necessary clean log file
    if not os.path.exists(CLEAN_LOG_FILE):
        print(f"[FATAL ERROR] Clean log file not found: {CLEAN_LOG_FILE}")
        print("Please copy your clean log from the victim server first.")
        return None

    print(f"[*] Loading clean log file: {CLEAN_LOG_FILE}...")
    requests = []
    try:
        with open(CLEAN_LOG_FILE, 'r') as f:
            for line in f:
                match = log_pattern.match(line)
                if match:
                    request_details = match.group(2)
                    requests.append(request_details)
        
        if not requests:
            print("[ERROR] No valid log lines found. Aborting.")
            return None

        print(f"[*] Found {len(requests)} normal requests to train on.")
        return requests
        
    except Exception as e:
        print(f"[FATAL ERROR] Could not read log file: {e}")
        return None

def train_and_save_models(requests):
    """Trains the Vectorizer and Isolation Forest model."""
    if not requests:
        print("[ERROR] No requests to train on. Aborting.")
        return

    print("[*] Training TF-IDF vectorizer...")
    # TF-IDF converts text to numerical features
    vectorizer = TfidfVectorizer(max_features=1000)
    features = vectorizer.fit_transform(requests)
    
    print("[*] Training Isolation Forest model...")
    # Isolation Forest is unsupervised; fits model of 'normal' traffic
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(features)
    
    # Save both models locally
    print(f"[*] Saving models to {MODEL_FILE} and {VECTORIZER_FILE}...")
    joblib.dump(vectorizer, VECTORIZER_FILE)
    joblib.dump(model, MODEL_FILE)
    
    print("\n[SUCCESS] Models trained and saved successfully!")

if __name__ == "__main__":
    # Ensure you have a clean_access.log file before running this!
    normal_requests = load_and_parse_logs()
    if normal_requests:
        train_and_save_models(normal_requests)
    else:
        sys.exit(1)