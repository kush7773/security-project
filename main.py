# main.py
"""
Flask app to receive log lines (JSON {"log_line": "..."}) and detect:
 - signature-based attacks (SQLi, XSS, LFI, RCE, Log4Shell, SSRF, command injection, etc.)
 - brute-force / credential stuffing via rate counters
 - anomaly / zero-day detection using an IsolationForest trained on normal logs + richer features
"""
import os
import re
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

from flask import Flask, request, jsonify

# optional ML dependencies; if missing, signatures still operate
try:
    import joblib
    from sklearn.decomposition import PCA
    from sklearn.preprocessing import StandardScaler
    import numpy as np
except Exception:
    joblib = None
    PCA = None
    StandardScaler = None
    np = None

# lightweight in-memory state for brute-force / rate detection (works across requests in same process)
IP_401_COUNTER = defaultdict(lambda: deque())  # ip -> deque of timestamps of recent 401/429/403
IP_REQUEST_COUNTER = defaultdict(lambda: deque())
IP_USERAGENT_HISTORY = defaultdict(set)

# configuration
BRUTE_FORCE_WINDOW_SECONDS = 300  # 5 minutes
BRUTE_FORCE_THRESHOLD = 10        # >=10 failed auths in window => suspicious
BURST_RATE_WINDOW = 60            # seconds
BURST_RATE_THRESHOLD = 50         # >50 requests in 60s => api abuse
ANOMALY_SCORE_THRESHOLD = 0.6     # IsolationForest anomaly score threshold (0..1); higher => more anomalous

MODEL_DIR = os.environ.get("MODEL_DIR", "/app/models")
TFIDF_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")
IFOREST_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
PCA_PATH = os.path.join(MODEL_DIR, "pca.joblib")

app = Flask(__name__)

# Signature regex patterns (ordered; add more as needed)
SIGNATURES = [
    # SQLi classic patterns
    ("SQLi", re.compile(r"(?i)(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b.*--|--\s|\bOR\s+1=1\b|'\s*or\s*'1'='1'|\";?\s*DROP\s+TABLE\b)")),
    # XSS script tags or onerror/onload injection
    ("XSS", re.compile(r'(?i)(<script\b|<\/script>|javascript:|onerror=|onload=|document\.cookie|\<img[^\>]*src=[^\>]*javascript:)')),
    # Directory traversal
    ("Directory Traversal", re.compile(r"(\.\./\.\.|%2e%2e/%2e%2e|/etc/passwd)")),
    # Local File Inclusion / RFI
    ("LFI/RFI", re.compile(r"(?i)(php://input|data:text\/html|expect:|include_path=.*\.\.|/etc/passwd)")),
    # Command injection (backticks, ;, &&)
    ("Command Injection", re.compile(r"([`|;]\s*ls\b|;.*\b(cat|nc|bash|sh)\b|&&\s*\w)")),
    # Log4Shell-style JNDI
    ("Log4Shell", re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|nis|http)://[^\}]+\}", re.IGNORECASE)),
    # SSRF (requests to internal IPs or "http://127.0.0.1:..." in param)
    ("SSRF", re.compile(r"(?i)(http://127\.0\.0\.1|http://localhost|http://169\.254\.\d+\.\d+|http(s)?://\d{1,3}\.)")),
    # XML external entities (XXE)
    ("XXE", re.compile(r"(?i)<!ENTITY\s+|<!DOCTYPE\s+[^>]*$begin:math:display$\"\)\)\,
    \# File upload malicious filename
    \(\"Malicious Filename\"\, re\.compile\(r\"\(\?i\)\\\.\(php\|phtml\|pl\|exe\|jsp\)\(\\\?\|\$\)\"\)\)\,
    \# Path traversal with null bytes \(old exploitation forms\)
    \(\"Null Byte\/Path\"\, re\.compile\(r\"\%00\"\)\)\,
    \# Generic SQL injection fallback
    \(\"SQLi\-Fallback\"\, re\.compile\(r\"\(\?i\)\(\\bOR\\b\\s\+\\d\+\=\\d\+\|\\bAND\\b\\s\+\\d\+\=\\d\+\|\-\-\|\\bDROP\\b\|\\bINSERT\\b\|\\bUPDATE\\b\)\"\)\)\,
\]

\# severity mapping \(can be tuned\)
SEVERITY\_MAP \= \{
    \"Log4Shell\"\: \"Critical\"\,
    \"Command Injection\"\: \"Critical\"\,
    \"RCE\"\: \"Critical\"\,
    \"SQLi\"\: \"High\"\,
    \"SQLi\-Fallback\"\: \"High\"\,
    \"XSS\"\: \"Medium\"\,
    \"SSRF\"\: \"High\"\,
    \"Directory Traversal\"\: \"High\"\,
    \"XXE\"\: \"High\"\,
    \"Malicious Filename\"\: \"Medium\"\,
    \"Null Byte\/Path\"\: \"Low\"\,
\}

\# load models if available
tfidf \= None
iforest \= None
scaler \= None
pca \= None
models\_loaded \= False

def try\_load\_models\(\)\:
    global tfidf\, iforest\, scaler\, pca\, models\_loaded
    if joblib is None\:
        app\.logger\.warning\(\"joblib\/sklearn not available — ML disabled\.\"\)
        models\_loaded \= False
        return

    try\:
        if os\.path\.exists\(TFIDF\_PATH\)\:
            tfidf \= joblib\.load\(TFIDF\_PATH\)
        if os\.path\.exists\(IFOREST\_PATH\)\:
            iforest \= joblib\.load\(IFOREST\_PATH\)
        if os\.path\.exists\(SCALER\_PATH\)\:
            scaler \= joblib\.load\(SCALER\_PATH\)
        if os\.path\.exists\(PCA\_PATH\)\:
            pca \= joblib\.load\(PCA\_PATH\)
        models\_loaded \= \(tfidf is not None and iforest is not None\)
        app\.logger\.info\(f\"Models loaded\: tfidf\=\{\'yes\' if tfidf else \'no\'\}\, iforest\=\{\'yes\' if iforest else \'no\'\}\"\)
    except Exception as e\:
        app\.logger\.exception\(\"Failed loading models\: \%s\"\, e\)
        models\_loaded \= False

try\_load\_models\(\)

\# Feature extraction used both at runtime and in training
def extract\_features\_from\_logline\(log\_line\)\:
    \"\"\"
    Return feature dict \+ text token for ML vectorization\. Aim to capture\:
      \- raw\_text\: original
      \- length\, token\_count\, unique\_token\_ratio
      \- digit\_ratio\, punct\_ratio
      \- entropy \(char\-level\)
      \- method\, response\_code\, url\_path\_depth\, query\_token\_count
      \- user\-agent \(as token\)
    \"\"\"
    text \= log\_line or \"\"
    \# simple tokenization for counts \(split on whitespace and punctuation\)
    tokens \= re\.split\(r\"\[ \\t\\\"\'\\\[$end:math:display$$begin:math:text$$end:math:text$\{\},;]+", text)
    tokens = [t for t in tokens if t]
    token_count = len(tokens)
    unique_token_ratio = len(set(tokens)) / token_count if token_count else 0.0

    length = len(text)
    digits = sum(ch.isdigit() for ch in text)
    digit_ratio = digits / length if length else 0.0
    punct = sum(not ch.isalnum() and not ch.isspace() for ch in text)
    punct_ratio = punct / length if length else 0.0

    # approximate entropy
    from math import log2
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for v in freq.values():
        p = v / length if length else 0
        if p > 0:
            entropy -= p * log2(p)

    # Extract HTTP method, path, status code if present
    method = None
    status_code = None
    path = ""
    m = re.search(r'\"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^ ]+)\s+HTTP\/', text)
    if m:
        method = m.group(1)
        path = m.group(2)
    sc = re.search(r'\"\s+(\d{3})\s', text)
    if sc:
        status_code = int(sc.group(1))
    # path features
    path_tokens = re.split(r"[\/\?\=&]+", path)
    path_tokens = [t for t in path_tokens if t]
    path_depth = len(path_tokens)
    query_token_count = len(re.findall(r"[?&=]", path))

    # user-agent sniff
    ua_m = re.search(r'\"[^\"]*\"[^\"]*\"([^\"]+)\"$', text)  # fallback attempt
    user_agent = ua_m.group(1) if ua_m else ""

    feature_vector = {
        "raw_text": text,
        "length": length,
        "token_count": token_count,
        "unique_token_ratio": unique_token_ratio,
        "digit_ratio": digit_ratio,
        "punct_ratio": punct_ratio,
        "entropy": entropy,
        "method": method or "",
        "status_code": status_code or 0,
        "path_depth": path_depth,
        "query_token_count": query_token_count,
        "user_agent": user_agent,
    }
    return feature_vector

def vectorize_features(feature_dict):
    """
    Convert extracted features into numeric vector for the IsolationForest.
    We combine TF-IDF of the raw_text (if available) with the scalar features.
    """
    global tfidf, scaler, pca
    scalars = [
        feature_dict["length"],
        feature_dict["token_count"],
        feature_dict["unique_token_ratio"],
        feature_dict["digit_ratio"],
        feature_dict["punct_ratio"],
        feature_dict["entropy"],
        feature_dict["path_depth"],
        feature_dict["query_token_count"],
        feature_dict["status_code"],
    ]
    scalars = np.array(scalars, dtype=float).reshape(1, -1) if np is not None else None

    tfidf_vec = None
    if tfidf is not None:
        try:
            tfidf_vec = tfidf.transform([feature_dict["raw_text"]]).toarray()
        except Exception:
            tfidf_vec = None

    # combine intelligently
    if tfidf_vec is not None and scalars is not None:
        # optional PCA if available
        if pca is not None:
            try:
                tfidf_reduced = pca.transform(tfidf_vec)
            except Exception:
                tfidf_reduced = tfidf_vec
        else:
            tfidf_reduced = tfidf_vec
        combined = np.hstack([scaler.transform(scalars) if scaler is not None else scalars, tfidf_reduced])
    else:
        # fallback to scalars only
        combined = scaler.transform(scalars) if (scaler is not None and scalars is not None) else scalars
    return combined

def signature_check(line):
    """Return list of matched signatures (name, pattern)"""
    matches = []
    for name, pattern in SIGNATURES:
        if pattern.search(line):
            matches.append(name)
    return matches

def assess_severity(matched_names):
    sev = "None"
    if not matched_names:
        return sev
    highest = "Low"
    for name in matched_names:
        s = SEVERITY_MAP.get(name, "Low")
        if s == "Critical":
            return "Critical"
        if s == "High":
            highest = "High"
    return highest if highest != "Low" else "Medium"

@app.route("/", methods=["POST"])
def analyze_log():
    payload = request.get_json(silent=True)
    if not payload or "log_line" not in payload:
        return jsonify({"status":"error","message":"expected JSON with key 'log_line'"}), 400

    log_line = payload["log_line"]
    response = {
        "status": "Log analyzed. Traffic is normal.",
        "matches": [],
        "severity": "None",
        "type": "Normal",
        "ml_anomaly_score": None,
        "details": {},
    }

    # 1) signature-based detection
    matched = signature_check(log_line)
    if matched:
        sev = assess_severity(matched)
        response.update({
            "status": "Attack Detected",
            "matches": matched,
            "severity": sev,
            "type": "Signature",
            "details": {"signatures": matched},
        })
        # return early for clear signature matches
        return jsonify(response), 200

    # 2) brute-force / rate detection heuristics
    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", log_line)
    ip = ip_match.group(1) if ip_match else "unknown"
    now = time.time()

    # detect 401/403/429 entries (failed auth)
    if re.search(r'"\s+401\s|"\s+403\s|"\s+429\s', log_line):
        dq = IP_401_COUNTER[ip]
        dq.append(now)
        # pop older than window
        while dq and dq[0] < now - BRUTE_FORCE_WINDOW_SECONDS:
            dq.popleft()
        if len(dq) >= BRUTE_FORCE_THRESHOLD:
            response.update({
                "status": "Attack Detected",
                "type": "BruteForce",
                "severity": "High",
                "details": {"ip": ip, "failed_auths_window": len(dq), "window_seconds": BRUTE_FORCE_WINDOW_SECONDS}
            })
            return jsonify(response), 200

    # detect request bursts
    dq2 = IP_REQUEST_COUNTER[ip]
    dq2.append(now)
    while dq2 and dq2[0] < now - BURST_RATE_WINDOW:
        dq2.popleft()
    if len(dq2) > BURST_RATE_THRESHOLD:
        response.update({
            "status": "Attack Detected",
            "type": "API Abuse / Rate",
            "severity": "Medium",
            "details": {"ip": ip, "requests_in_window": len(dq2), "window_seconds": BURST_RATE_WINDOW}
        })
        return jsonify(response), 200

    # 3) ML-based anomaly detection (zero-day)
    if models_loaded and iforest is not None and tfidf is not None:
        try:
            feat = extract_features_from_logline(log_line)
            vec = vectorize_features(feat)
            if vec is None:
                raise RuntimeError("vectorization failed")
            # if IsolationForest from sklearn, decision_function gives anomaly score (higher -> less abnormal),
            # but predict/score_samples vary by version. We'll use score_samples and convert to [0,1] anomaly score.
            score = iforest.score_samples(vec)[0]  # higher -> inlier
            # convert to anomaly probability: lower score => more anomalous. Normalize with a rough sigmoid
            # But simpler: compute anomaly_prob = 1 - normalized_score
            # Use min/max from training might be unavailable; we use an ad-hoc mapping:
            anomaly_prob = float(1.0 / (1.0 + np.exp(score))) if np is not None else 0.0
            response["ml_anomaly_score"] = anomaly_prob
            if anomaly_prob >= ANOMALY_SCORE_THRESHOLD:
                response.update({
                    "status": "Attack Detected",
                    "type": "Anomaly/ZeroDay",
                    "severity": "High" if anomaly_prob > 0.85 else "Medium",
                    "details": {"ip": ip, "anomaly_score": anomaly_prob}
                })
                return jsonify(response), 200
        except Exception as e:
            app.logger.exception("ML anomaly detection failed: %s", e)
            # fallback to normal response

    # default normal
    return jsonify(response), 200

if __name__ == "__main__":
    # development: use Flask server; production should use gunicorn with Procfile below.
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)