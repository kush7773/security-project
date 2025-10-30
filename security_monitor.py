# security_monitor.py
# This is your main, 24/7 security application.
# It runs on your Ubuntu VM, monitors the live Nginx log,
# and blocks attackers.

import re
import subprocess
import pandas as pd
from datetime import datetime
import time
import os
import joblib  # For loading our trained ML model
import urllib.parse # <-- ADD THIS IMPORT AT THE TOP

# --- 1. CONFIGURATION & RULESET ---

# !!! IMPORTANT !!!
# When you copy this file to your Ubuntu VM, change this path:
LOG_FILE_TO_WATCH = "/var/log/nginx/access.log"
#
# For testing on your Mac, you would use:
# LOG_FILE_TO_WATCH = "fake_access.log"

# The Excel log file that will be created
ATTACK_LOG_FILE = "attack_log.xlsx"

# The ML model files (which must be in the same folder)
MODEL_FILE = "isolation_forest.joblib"
VECTORIZER_FILE = "tfidf_vectorizer.joblib"

# Global variables to hold our loaded models
ML_MODEL = None
VECTORIZER = None

# A. Signature-Based Rules (Regex)
SIGNATURE_RULES = {
    "SQL_INJECTION": r"(\'|\%27)\s*(OR|UNION)\s*(\'|\%27|1)\s*(=|LIKE)\s*(\'|\%27|1)",
    "DIRECTORY_TRAVERSAL": r"(\.\./|%2E%2E%2F|\.\.%5C)",
    "XSS_SCRIPTING": r"(<|%3C)\s*(script|img|onload|onerror)\s*(>|%3E|\s)",
    "COMMAND_INJECTION": r"(cat|ls|whoami|nmap|wget|curl|pwd|;|%3B)\s*(\/|%2F|\s)"
}

# B. Behavioral-Based Rules (Thresholds)
ip_activity_log = {}      # In-memory database of IP activity
REQUEST_TIME_WINDOW = 60  # in seconds
REQUEST_THRESHOLD = 100   # Max requests per IP in the window
ERROR_404_THRESHOLD = 20  # Max 404 errors per IP in the window

# --- 2. RESPONSE & LOGGING MODULES ---

def log_attack(ip, attack_type, log_line):
    """
    Logs the detected attack to an Excel file.
    """
    print(f"[LOGGING] Logging attack: {attack_type} from {ip}")
    new_log_entry = {
        "Timestamp": [datetime.now()],
        "Attacker_IP": [ip],
        "Attack_Type": [attack_type],
        "Full_Log_Line": [log_line]
    }
    df_new = pd.DataFrame(new_log_entry)

    try:
        # If the file exists, append to it
        if os.path.exists(ATTACK_LOG_FILE):
            df_existing = pd.read_excel(ATTACK_LOG_FILE)
            df_combined = pd.concat([df_existing, df_new], ignore_index=True)
        else:
            # If not, this is the first entry
            df_combined = df_new
            
        # Write back to Excel
        df_combined.to_excel(ATTACK_LOG_FILE, index=False)
        
    except Exception as e:
        print(f"[ERROR] Could not write to Excel log: {e}")

def block_ip(ip_address, attack_type):
    """
    Executes a shell command to block the IP using UFW firewall.
    This function is designed for LINUX (Ubuntu) servers.
    """
    print(f"[ACTION] Blocking IP: {ip_address} for {attack_type}")
    try:
        # This is the Linux firewall command
        command = ["sudo", "ufw", "insert", "1", "deny", "from", ip_address]
        
        # We run the command. check=True will raise an error if the command fails.
        subprocess.run(command, check=True)
        print(f"[SUCCESS] Successfully blocked {ip_address}.")
        
    except FileNotFoundError:
        # This error happens when testing on Mac/Windows
        print("[WARNING] 'ufw' not found. This is normal if not on the Linux VM.")
    except subprocess.CalledProcessError as e:
        # This error happens if the user doesn't have 'sudo' permissions
        print(f"[ERROR] Failed to block IP. Do you have sudo permissions? Error: {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while blocking IP: {e}")


# --- 3. DETECTION ENGINE ---

def analyze_log_line(log_line):
    """
    Analyzes a single log line against all our rules in order.
    """
    # Regex to parse a common Nginx log line
    # Example: 1.2.3.4 - - [26/Oct/2025:...] "GET /index.php HTTP/1.1" 200 ...
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - .*?"(.*?)" (\d{3})')
    match = log_pattern.match(log_line)
    
    if not match:
        return  # Not a log line we can parse

    ip_address = match.group(1)
    request_details = match.group(2) # e.g., "GET /index.php?id=1"
    status_code = match.group(3)

    # --- NEW STEP: Decode the request string ---
    # This turns URL-encoded attacks (e.g., "%27%20OR%201%3D1")
    # into plain text (e.g., "' OR 1=1")
    try:
        decoded_request = urllib.parse.unquote(request_details)
    except Exception:
        decoded_request = request_details # Fallback if decoding fails

    # --- A. Check Signature-Based Rules (Fastest) ---
    for attack_type, pattern in SIGNATURE_RULES.items():
        # Check against the DECODED request
        if re.search(pattern, decoded_request, re.IGNORECASE):
            print(f"[DETECTION] Signature match! Type: {attack_type}")
            block_ip(ip_address, attack_type)
            log_attack(ip_address, attack_type, log_line)
            return # Attack found, no need to check other rules

    # --- B. Check Behavioral-Based Rules (Fast) ---
    current_time = time.time()
    
    # Initialize IP if not seen before
    if ip_address not in ip_activity_log:
        ip_activity_log[ip_address] = {'timestamps': [], '404_count': 0}

    # Clean up old timestamps (outside the 60s window)
    ip_activity_log[ip_address]['timestamps'] = [
        t for t in ip_activity_log[ip_address]['timestamps'] 
        if current_time - t < REQUEST_TIME_WINDOW
    ]
    
    # Add current request
    ip_activity_log[ip_address]['timestamps'].append(current_time)
    
    # Check for 404s (Scanners)
    if status_code == "404":
        ip_activity_log[ip_address]['404_count'] += 1

    # Check thresholds
    if len(ip_activity_log[ip_address]['timestamps']) > REQUEST_THRESHOLD:
        print(f"[DETECTION] Behavioral match! Type: RATE_LIMIT (DDoS)")
        block_ip(ip_address, "RATE_LIMIT_DDoS")
        log_attack(ip_address, "RATE_LIMIT_DDoS", log_line)
        return # Attack found
        
    elif ip_activity_log[ip_address]['404_count'] > ERROR_404_THRESHOLD:
        print(f"[DETECTION] Behavioral match! Type: SCANNER (404s)")
        block_ip(ip_address, "SCANNER_404")
        log_attack(ip_address, "SCANNER_404", log_line)
        return # Attack found

    # --- C. Check ML-Based Anomaly Rules (Slower, for Zero-Days) ---
    # This only runs if no other rules were triggered.
    if ML_MODEL and VECTORIZER:
        try:
            # 1. Turn the text request into numbers
            # We use the ORIGINAL request_details here,
            # since our model was trained on the raw, encoded log files.
            features = VECTORIZER.transform([request_details])
            
            # 2. Get a prediction. -1 means anomaly, 1 means normal.
            prediction = ML_MODEL.predict(features)
            
            if prediction == -1:
                # The model flagged this as "weird" or "anomalous"
                print(f"[DETECTION] ML Anomaly match! Type: ZERO_DAY (potential)")
                block_ip(ip_address, "ML_ANOMALY_ZERO_DAY")
                log_attack(ip_address, "ML_ANOMALY_ZERO_DAY", log_line)
                
        except Exception as e:
            print(f"[ERROR] Could not run ML model prediction: {e}")


# --- 4. MAIN EXECUTION & MODEL LOADING ---

def load_models():
    """
    Loads the pre-trained ML model and vectorizer from disk.
    This runs once when the script starts.
    """
    global ML_MODEL, VECTORIZER
    try:
        if os.path.exists(MODEL_FILE) and os.path.exists(VECTORIZER_FILE):
            print(f"[*] Loading ML model from {MODEL_FILE}...")
            ML_MODEL = joblib.load(MODEL_FILE)
            print(f"[*] Loading vectorizer from {VECTORIZER_FILE}...")
            VECTORIZER = joblib.load(VECTORIZER_FILE)
            print("[*] ML models loaded successfully.")
        else:
            print("[WARNING] ML model files not found ({MODEL_FILE} or {VECTORIZER_FILE}).")
            print("[WARNING] Zero-Day (ML) detection will be DISABLED.")
            
    except Exception as e:
        print(f"[FATAL ERROR] Could not load ML models: {e}")


def follow_log_file(filepath):
    """
    "Follows" a log file, like the 'tail -f' command.
    This is a simple version. A more robust version would use 'watchdog'.
    """
    print(f"[*] Starting security monitor. Watching log file: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"[FATAL ERROR] Log file not found: {filepath}")
        print("Please check the LOG_FILE_TO_WATCH path in the script.")
        return

    try:
        with open(filepath, 'r') as file:
            # Go to the end of the file
            file.seek(0, os.SEEK_END)
            
            while True:
                line = file.readline()
                if not line:
                    # No new line, wait a bit
                    time.sleep(0.1)
                    continue
                
                # We have a new line!
                # print(f"[NEW LOG] {line.strip()}") # Uncomment this for debugging
                analyze_log_line(line)
                
    except FileNotFoundError:
        print(f"[FATAL ERROR] Log file not found: {filepath}")
    except KeyboardInterrupt:
        print("\n[*] Stopping security monitor. Goodbye!")
    except Exception as e:
        print(f"[FATAL ERROR] An error occurred: {e}")

# This is the entry point of our script
if __name__ == "__main__":
    load_models()  # Load the ML models first
    follow_log_file(LOG_FILE_TO_WATCH) # Start watching the log file


