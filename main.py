import os
import joblib
import json
import re
from flask import Flask, request, jsonify
from sklearn.feature_extraction.text import HashingVectorizer
import numpy as np

app = Flask(__name__)

# ============
# LOAD MODELS
# ============
MODEL_DIR = "models"

isolation_model = joblib.load(f"{MODEL_DIR}/isolation_forest.joblib")
svd = joblib.load(f"{MODEL_DIR}/svd.joblib")
scaler = joblib.load(f"{MODEL_DIR}/scaler.joblib")

# We use HashingVectorizer ALWAYS → no need to load
hash_vectorizer = HashingVectorizer(
    n_features=65536,
    alternate_sign=False,
    norm='l2'
)

# ==============================
# SIGNATURE-BASED ATTACK PATTERNS
# ==============================
SIGNATURES = {
    "SQL Injection": r"(\'|\%27).*(OR|AND).*(\=|\%3D)|union(\s)+select|sleep\(",
    "XSS": r"(<script>|%3Cscript|javascript:|onerror=|onload=)",
    "Command Injection": r"(;|&&|\|\|).*(cat|ls|wget|curl)",
    "Path Traversal LFI": r"(\.\./|\%2e\%2e\/)",
    "RFI": r"(http:\/\/|https:\/\/).*(\.php|\.txt)",
    "Log4Shell": r"(\$\{jndi:ldap:\/\/)",
    "API Abuse": r"(\/auth\/|\/login|\/token).*(\?)+.*",
    "Brute Force": r"(401|403|invalid password|failed login)"
}

compiled_signatures = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in SIGNATURES.items()}

# ====================
# NUMERIC FEATURE ENGINEERING
# ====================
def extract_numeric_features(log):
    # Basic features for behavioural anomaly detection
    return np.array([
        len(log),                       # text length
        log.count("/"),                 # slashes
        log.count("?"),                 # query complexity
        log.count("="),                 # params count
        int(" 500 " in log),            # server error?
        int(" 404 " in log)             # missing?
    ]).reshape(1, -1)


# =====================
# IP BLOCK LIST
# =====================
BLOCKED_IPS = set()


def block_ip(ip):
    BLOCKED_IPS.add(ip)


# =====================
# SIGNATURE DETECTION
# =====================
def match_signature(log):
    for attack_name, pattern in compiled_signatures.items():
        if pattern.search(log):
            return attack_name
    return None


# =====================
# ZERO-DAY / BEHAVIOURAL DETECTION (ML)
# =====================
def ml_predict(log):
    text_vec = hash_vectorizer.transform([log])
    text_reduced = svd.transform(text_vec)
    numeric = extract_numeric_features(log)
    combined = np.hstack([numeric, text_reduced])

    scaled = scaler.transform(combined)
    pred = isolation_model.predict(scaled)

    return pred[0]  # -1 = anomaly / attack, 1 = normal


# ================
# MAIN API ENDPOINT
# ================
@app.route("/", methods=["POST"])
def analyze():
    try:
        log_line = request.json.get("log_line", "")

        # extract IP
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", log_line)
        ip = ip_match.group(1) if ip_match else "unknown"

        # 1️⃣ Signature-based detection
        signature_attack = match_signature(log_line)

        if signature_attack:
            block_ip(ip)
            return jsonify({
                "status": "Attack Detected",
                "type": signature_attack,
                "method": "signature",
                "severity": "High",
                "action": f"IP {ip} blocked"
            })

        # 2️⃣ ML behavioural detection
        ml_result = ml_predict(log_line)
        if ml_result == -1:
            block_ip(ip)
            return jsonify({
                "status": "Attack Detected",
                "type": "Zero-Day / Behavioural",
                "method": "ML anomaly",
                "severity": "Critical",
                "action": f"IP {ip} blocked"
            })

        # 3️⃣ Normal
        return jsonify({
            "status": "Log analyzed. Traffic normal.",
            "ip_blocked": False
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =====================
# HEALTH CHECK FOR CLOUD RUN
# =====================
@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


# Required for Cloud Run
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)