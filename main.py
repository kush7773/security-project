# main.py  (Simple Cloud Run Version)

import os
import re
import json
from flask import Flask, request
import joblib

app = Flask(__name__)

MODEL_PATH = "models/isolation_forest.joblib"
model = joblib.load(MODEL_PATH)

# In-memory IP block list
BLOCKED_IPS = set()

# Signature rules
SIGNATURE_RULES = [
    (r"(\.\./|\.\.)", "Path traversal"),
    (r"union\s+select", "SQL Injection"),
    (r"select\s+\*", "SQL Injection"),
    (r"1=1", "SQL Injection"),
    (r"log4j|jndi:ldap", "Log4Shell Attempt"),
    (r"wget|curl\s+http", "Command Injection"),
    (r"etc/passwd", "File Disclosure"),
    (r"\bwp-admin\b", "WordPress attack"),
]

# Behavioral state
failed_login_count = {}

def extract_ip(logline):
    parts = logline.split()
    return parts[0] if parts else "0.0.0.0"

@app.route("/", methods=["POST"])
def analyze():
    data = request.json
    log = data.get("log_line", "")

    ip = extract_ip(log)

    # BLOCK IF IP IS ALREADY BLOCKED
    if ip in BLOCKED_IPS:
        return json.dumps({"status": "Blocked", "ip": ip})

    # 1. SIGNATURE ATTACK DETECTION
    for pattern, attack_name in SIGNATURE_RULES:
        if re.search(pattern, log, re.IGNORECASE):
            BLOCKED_IPS.add(ip)
            return json.dumps({
                "status": "Attack Detected",
                "type": attack_name,
                "severity": "High",
                "ip": ip
            })

    # 2. BEHAVIORAL DETECTION (Bruteforce / API Abuse)
    if "401" in log or "login failed" in log.lower():
        failed_login_count[ip] = failed_login_count.get(ip, 0) + 1

        if failed_login_count[ip] >= 10:
            BLOCKED_IPS.add(ip)
            return json.dumps({
                "status": "Behavior Attack Detected",
                "type": "Bruteforce",
                "severity": "Medium",
                "ip": ip
            })

    # 3. ML MODEL CHECK (very casual)
    X = [[len(log.split()[0])]]
    pred = model.predict(X)[0]

    if pred == -1:  # anomaly
        BLOCKED_IPS.add(ip)
        return json.dumps({
            "status": "ML Anomaly Detected",
            "severity": "Medium",
            "ip": ip
        })

    return json.dumps({"status": "Clean", "ip": ip})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)