# Phase 1: Secret Scanner (Regex + Heuristics)
# Dependencies: None

import re
import os

# -----------------------------
# Configuration
# -----------------------------
REPO_PATH = r"C:\Users\bk826\OneDrive - Comcast\Desktop\WorkSpace\K8ExecutionServiceAPI"  # Replace with your folder path
SECRET_PATTERNS = [
    # Basic credentials
    r'password\s*[:=]\s*["\']?([^\s"\']+)',
    r'secret\s*[:=]\s*["\']?([^\s"\']+)',
    r'api[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'token\s*[:=]\s*["\']?([^\s"\']+)',
    
    # AWS
    r'aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?([A-Z0-9]{16,})',
    r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40,})',
    r'AKIA[0-9A-Z]{16,}',
    
    # GitHub
    r'ghp_[A-Za-z0-9]{36,}',
    r'github[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    r'gh[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    
    # API and service tokens
    r'authorization\s*[:=]\s*[bB]earer\s+([^\s"\']+)',
    r'client[_-]?secret\s*[:=]\s*["\']?([^\s"\']+)',
    r'api[_-]?secret\s*[:=]\s*["\']?([^\s"\']+)',
    r'firebase[_-]?api[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'slack[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    r'slack[_-]?api[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    
    # Database - Relational
    r'mysql[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'db[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'database[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'postgres[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'postgresql[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'oracle[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'mariadb[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'mssql[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'sql[_-]?server[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'sqlite[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'jdbc[:\s]+[a-zA-Z0-9]+:[a-zA-Z0-9]+://[^\s"\']+',
    r'jdbc:mysql://[^\s;]+;user=[^;]+;password=([^;]+)',
    r'Server=[^;]+;Database=[^;]+;User\s?Id=[^;]+;Password=([^;]+)',
    r'Data\s?Source=[^;]+;Initial\s?Catalog=[^;]+;User\s?Id=[^;]+;Password=([^;]+)',
    r'sqlplus\s+[a-zA-Z0-9_]+/([^\s@]+)@',
    
    # Database - NoSQL
    r'mongo[_-]?uri\s*[:=]\s*["\']?(mongodb://[^\s"\']+)',
    r'mongodb[+]?srv://[^:]+:([^@]+)@',
    r'redis[_-]?url\s*[:=]\s*["\']?(redis://[^\s"\']+)',
    r'redis[:\s]+[^:]+:([^@]+)@',
    r'cassandra[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'couchdb[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'dynamodb[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'elasticsearch[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'hbase[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'neo4j[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'riak[_-]?password\s*[:=]\s*["\']?([^\s"\']+)',
    r'cosmosdb[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'firestore[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'couchbase://[^:]+:([^@]+)@',
    
    # Database connection strings
    r'(?:(?:User\s?Id|UID)=)[^;]+(?:;)(?:.*?)(?:(?:Password|PWD)=)([^;]+)',
    r'(?:mongodb(?:\+srv)?|redis|couchbase|postgres|mysql|mariadb)://[a-zA-Z0-9_]+:([^@\s]+)@',
    
    # JWT tokens
    r'jwt\s*[:=]\s*["\']?([^\s"\']+\.[^\s"\']+\.[^\s"\']+)',
    r'["\']?([a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})["\']?',
    
    # Cloud services
    r'azure[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'gcp[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'heroku[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    
    # Other common formats
    r'private[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'connection[_-]?string\s*[:=]\s*["\']?([^\s"\']+)',
    r'access[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    r'refresh[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    r'session[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    r'oauth[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    
    # Environment variables
    r'env["\'][^"\']*password[^"\']*["\']?\s*[:=]\s*["\']?([^\s"\']+)',
    r'env["\'][^"\']*secret[^"\']*["\']?\s*[:=]\s*["\']?([^\s"\']+)',
    r'env["\'][^"\']*token[^"\']*["\']?\s*[:=]\s*["\']?([^\s"\']+)',
    r'env["\'][^"\']*key[^"\']*["\']?\s*[:=]\s*["\']?([^\s"\']+)',
    
    # Certificates and SSL
    r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----([^-]+)-----END\s+(RSA\s+)?PRIVATE\s+KEY-----',
    r'-----BEGIN\s+CERTIFICATE-----([^-]+)-----END\s+CERTIFICATE-----',
    
    # Payment services
    r'sk_live_[A-Za-z0-9]{24,}',  # Stripe secret key
    r'pk_live_[A-Za-z0-9]{24,}',  # Stripe publishable key
    r'AYS[A-Z0-9]{14}',           # PayPal client ID
    r'(visa|mastercard|amex)[:\s]+[0-9]{12,19}[:\s]+[0-9]{3,4}',  # Credit card data
    r'[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}',  # Credit card pattern
    
    # Social media API tokens
    r'twitter[_-]?api[_-]?(key|secret)\s*[:=]\s*["\']?([^\s"\']+)',
    r'facebook[_-]?app[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    r'instagram[_-]?token\s*[:=]\s*["\']?IGQ[A-Za-z0-9_-]{10,}',
    r'linkedin[_-]?secret\s*[:=]\s*["\']?([^\s"\']+)',
    
    # Webhooks
    r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+',
    r'https://discord\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]+',
    
    # Twilio
    r'AC[a-zA-Z0-9]{32}',  # Twilio SID
    r'twilio[_-]?auth[_-]?token\s*[:=]\s*["\']?([^\s"\']+)',
    
    # Mobile services
    r'fcm[_-]?server[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
    r'apns[_-]?key[_-]?id\s*[:=]\s*["\']?([^\s"\']+)',
    r'-----BEGIN\s+ANDROID\s+KEY-----([^-]+)-----END\s+ANDROID\s+KEY-----',
    
    # Cryptocurrency
    r'wallet[_-]?private[_-]?key\s*[:=]\s*["\']?([0-9a-fA-F]{64})',
    r'seed[_-]?phrase\s*[:=]\s*["\']?([a-z\s]{12,})["\']?',
    r'mnemonic\s*[:=]\s*["\']?([a-z\s]{12,})["\']?',
    r'crypto[_-]?api[_-]?key\s*[:=]\s*["\']?([^\s"\']+)',
]

# Scoring thresholds
KEYWORD_SCORE = 2
LENGTH_SCORE = 1
RISK_THRESHOLD = 3

# -----------------------------
# Helper Functions
# -----------------------------
def calculate_risk_score(secret, keyword_matched):
    score = 0
    if keyword_matched:
        score += KEYWORD_SCORE
    if len(secret) >= 0:
        score += LENGTH_SCORE
    return score

def scan_file(content, file_path):
    flagged = []
    for pattern in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            score = calculate_risk_score(match, True)
            if score >= RISK_THRESHOLD:
                flagged.append({
                    "file": file_path,
                    "secret": match,
                    "score": score
                })
    return flagged

# -----------------------------
# Main Folder Scan
# -----------------------------
def scan_folder(folder_path):
    flagged_secrets = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                flagged = scan_file(content, file_path)
                flagged_secrets.extend(flagged)
            except Exception as e:
                # Skip binary or unreadable files
                print(f"Could not read file: {file_path, {e}}")
                continue
    return flagged_secrets

# -----------------------------
# Run Scan
# -----------------------------
if __name__ == "__main__":

    if not os.path.exists(REPO_PATH):
        print("Folder path does not exist!")
        exit(1)

    results = scan_folder(REPO_PATH)
    if results:
        print("=== Potential Secrets Found ===")
        for item in results:
            # print(f"File: {item['file']} | Secret: {item['secret']} | Score: {item['score']}")
            print(f" Secret: {item['secret']} | Score: {item['score']}")

    else:
        print("No secrets detected in this folder.")
