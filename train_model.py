# train_model.py
# This script reads a "clean" log file, trains our ML model,
# and saves the model to disk for our main script to use.

import re
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import sys

# --- CONFIGURATION ---
# These filenames MUST match the ones in security_monitor.py
CLEAN_LOG_FILE = "clean_access.log"
MODEL_FILE = "isolation_forest.joblib"
VECTORIZER_FILE = "tfidf_vectorizer.joblib"

# Use the same log parsing regex as our main script
log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .*?"(.*?)" (\d{3})')

def load_and_parse_logs():
    """
    Loads the clean log file and extracts the "request" part
    (e.g., "GET /index.php") from each line.
    """
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
            print(f"[ERROR] No valid log lines found in {CLEAN_LOG_FILE}.")
            print("Please browse your website on the VM to generate a real log file.")
            return None

        print(f"[*] Found {len(requests)} normal requests to train on.")
        return requests
        
    except FileNotFoundError:
        print(f"[FATAL ERROR] Clean log file not found: {CLEAN_LOG_FILE}")
        print("Please run the 'scp' command to copy the log from your VM first.")
        return None
    except Exception as e:
        print(f"[FATAL ERROR] Could not read log file: {e}")
        return None

def train_and_save_models(requests):
    """
    Takes the list of normal requests, trains the
    Vectorizer and Isolation Forest model, and saves them.
    """
    if not requests:
        print("[ERROR] No requests to train on. Aborting.")
        return

    # 1. Train the Vectorizer
    # This learns to turn text (like "GET /style.css") into numbers
    # based on word frequency (TF-IDF).
    print("[*] Training TF-IDF vectorizer...")
    # We use max_features to keep the model size reasonable
    vectorizer = TfidfVectorizer(max_features=1000, stop_words=None, token_pattern=r"(?u)\b\w\w+\b")
    features = vectorizer.fit_transform(requests)
    
    # 2. Train the Isolation Forest Model
    # This model learns the "shape" of normal traffic.
    # 'contamination' is the percentage of data we *expect*
    # to be an anomaly (even in a "clean" log). We set it low.
    print("[*] Training Isolation Forest model...")
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(features)
    
    # 3. Save both models to disk
    print(f"[*] Saving vectorizer to {VECTORIZER_FILE}...")
    joblib.dump(vectorizer, VECTORIZER_FILE)
    
    print(f"[*] Saving model to {MODEL_FILE}...")
    joblib.dump(model, MODEL_FILE)
    
    print("\n[SUCCESS] Models trained and saved successfully!")
    print(f"Your main script 'security_monitor.py' is now ready to detect zero-day attacks.")

if __name__ == "__main__":
    normal_requests = load_and_parse_logs()
    if normal_requests:
        train_and_save_models(normal_requests)
    else:
        sys.exit(1) # Exit with an error if training failed

