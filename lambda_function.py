import json
import boto3
import uuid
import time
import re
import urllib.parse
import joblib  # This will import from the container!
import os

# --- 1. Initialize AWS Clients ---
dynamodb = boto3.resource('dynamodb')
db_table = dynamodb.Table('DetectedAttacks') # Our DB Table

# --- 2. Define Model Paths (They are now local!) ---
# These files are in the same folder as our code inside the container.
MODEL_PATH = 'isolation_forest.joblib'
VECTORIZER_PATH = 'tfidf_vectorizer.joblib'

# --- 3. Define S3 Bucket ---
# This is the S3 bucket where your 'LogIngestionFunction' is saving logs
BUCKET_NAME = 'kush-7773' # <-- CRITICAL UPDATE: Changed to your bucket name

# --- 4. Define Attack Signatures ---
SIGNATURE_RULES = {
    "SQL_INJECTION": r"(\'|\%27)\s*(OR|UNION)\s*(\'|\%27|1)\s*(=|LIKE)\s*(\'|\%27|1)",
    "DIRECTORY_TRAVERSAL": r"(\.\./|%2E%2E%2F|\.\.%5C)",
    "XSS_SCRIPTING": r"(<|%3C)\s*(script|img|onload|onerror)\s*(>|%3E|\s)",
    "COMMAND_INJECTION": r"(cat|ls|whoami|nmap|wget|curl|pwd|;|%3B)\s*(\/|%F|\s)"
}

# --- 5. Global Variables for Loaded Models ---
# We load these outside the handler so they stay in memory (Lambda "warm start")
ML_MODEL = joblib.load(MODEL_PATH)
VECTORIZER = joblib.load(VECTORIZER_PATH)
print("ML Models loaded into memory.")

# --- 6. Main Lambda Handler ---
def lambda_handler(event, context):
    """
    This function is triggered by S3. It runs the FULL
    detection pipeline: Signatures, then ML model.
    """
    
    try:
        # --- 1. Get and Read the S3 Log File ---
        s3_record = event['Records'][0]['s3']
        bucket_name = s3_record['bucket']['name']
        file_key = s3_record['object']['key']
        
        # We need an S3 client *inside* the handler for this one part
        s3_client = boto3.client('s3')
        
        # Security Check: Ensure the event is for our bucket
        if bucket_name != BUCKET_NAME:
            print(f"Ignoring event from wrong bucket: {bucket_name}")
            return {'statusCode': 400, 'body': 'Invalid bucket'}
            
        print(f"Reading file {file_key} from bucket {bucket_name}")
        s3_object = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        log_line = s3_object['Body'].read().decode('utf-8').strip()
        
        if not log_line:
            print("Log file is empty. Exiting.")
            return {'statusCode': 200, 'body': 'Empty log file'}

        print(f"Analyzing log: {log_line}")

        # --- 2. Parse the log line ---
        log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1.3}) - .*?"(.*?)" (\d{3})')
        match = log_pattern.match(log_line)
    
        if not match:
            print("Log line does not match pattern. Exiting.")
            return {'statusCode': 200, 'body': 'Log not parseable'}

        ip_address = match.group(1)
        request_details = match.group(2)
        status_code = match.group(3)
        
        try:
            decoded_request = urllib.parse.unquote(request_details)
        except Exception:
            decoded_request = request_details

        # --- 3. Run Signature Analysis (Layer 1) ---
        detected_attack_type = None
        for attack_type, pattern in SIGNATURE_RULES.items():
            if re.search(pattern, decoded_request, re.IGNORECASE):
                print(f"[DETECTION] Signature match! Type: {attack_type}")
                detected_attack_type = attack_type
                break
        
        # --- 4. Run ML Analysis (Layer 2) ---
        if not detected_attack_type:
            try:
                features = VECTORIZER.transform([request_details])
                prediction = ML_MODEL.predict(features)
                
                if prediction == -1: # -1 means ANOMALY
                    print(f"[DETECTION] ML Anomaly match! (Zero-Day)")
                    detected_attack_type = "ML_ANOMALY_ZERO_DAY"
                    
            except Exception as e:
                print(f"ERROR: ML model prediction failed: {e}")

        # --- 5. Write to DynamoDB (if any attack was found) ---
        if detected_attack_type:
            attack_id = str(uuid.uuid4())
            current_timestamp = int(time.time())
            
            severity = "High"
            if detected_attack_type == "ML_ANOMALY_ZERO_DAY":
                severity = "Critical"

            attack_item = {
                'attackID': attack_id,
                'ip': ip_address,
                'type': detected_attack_type,
                'severity': severity,
                'timestamp': current_timestamp,
                'log_line': log_line,
                'status': 'Blocked'
            }
            
            print(f"Writing item to DynamoDB: {attack_item}")
            db_table.put_item(Item=attack_item)
            
            return {
                'statusCode': 200,
                'body': json.dumps(f'Successfully detected {detected_attack_type} and saved to DB')
            }
        
        else:
            print("No attack detected in this log.")
            return {
                'statusCode': 200,
                'body': json.dumps('Log analyzed. No attack found.')
            }

    except Exception as e:
        print(f"FATAL ERROR: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing S3 event: {e}')
        }