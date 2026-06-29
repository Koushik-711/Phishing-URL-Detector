from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib.parse
import re
import time
import uuid
import torch
import torch.nn as nn
import os
import whois
import dns.resolver
from datetime import datetime

app = FastAPI()

# Enable secure, production-compliant Cross-Origin Resource Sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- GLOBAL IN-MEMORY TASK REGISTRY ---
RESULTS_CACHE = {}

# --- NEURAL NETWORK ARCHITECTURE LINKING ---
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="
char_to_idx = {char: idx + 1 for idx, char in enumerate(CHARS)}
VOCAB_SIZE = len(char_to_idx) + 1
EMBEDDING_DIM = 32
HIDDEN_DIM = 64
MAX_LEN = 100

class URLClassifierLSTM(nn.Module):
    def __init__(self, vocab_size, embedding_dim, hidden_dim):
        super(URLClassifierLSTM, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, (ht, ct) = self.lstm(embedded)
        out = self.fc(ht[-1])
        return self.sigmoid(out)

def url_to_tensor(url: str) -> torch.Tensor:
    url = url.lower()[:MAX_LEN]
    tensor = torch.zeros(MAX_LEN, dtype=torch.long)
    for i, char in enumerate(url):
        if char in char_to_idx:
            tensor[i] = char_to_idx[char]
    return tensor.unsqueeze(0)

model = URLClassifierLSTM(VOCAB_SIZE, EMBEDDING_DIM, HIDDEN_DIM)
if os.path.exists("phishguard_model.pth"):
    model.load_state_dict(torch.load("phishguard_model.pth"))
    model.eval()

class UrlPayload(BaseModel):
    url: str

# --- ENGINE LAYER 1: HEURISTICS EXTRACTION ---
def extract_lexical_features(url_str: str) -> dict:
    url_str = url_str.strip()
    if not url_str.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse('http://' + url_str)
    else:
        parsed = urllib.parse.urlparse(url_str)
    domain = parsed.netloc
    
    features = {
        'url_length': len(url_str),
        'has_http': 1 if parsed.scheme == 'http' else 0,
        'contains_ip': 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0,
        'qty_dots': url_str.count('.'),
        'qty_hyphens': url_str.count('-'),
        'qty_at': url_str.count('@'),
    }
    suspect_keywords = ['login', 'secure', 'verify', 'update', 'banking', 'signin', 'account']
    features['qty_suspect_keywords'] = sum(1 for word in suspect_keywords if word in url_str.lower())
    return features

def calculate_heuristic_risk(features: dict) -> float:
    penalty = 0
    if features['has_http'] == 1: penalty += 20
    if features['contains_ip'] == 1: penalty += 40
    if features['url_length'] > 75: penalty += 15
    if features['qty_dots'] >= 4: penalty += 15
    if features['qty_hyphens'] >= 3: penalty += 10
    if features['qty_at'] > 0: penalty += 30
    if features['qty_suspect_keywords'] > 0: penalty += (features['qty_suspect_keywords'] * 20)
    return float(min(max(penalty, 0.0), 100.0))

# --- ENGINE LAYER 2: LIVE THREAT INTEL OSINT (UPDATED ERROR MATRIX) ---
def extract_domain_intel(url_str: str) -> dict:
    """Performs out-of-band WHOIS and DNS lookups against live internet servers."""
    url_str = url_str.strip()
    if not url_str.startswith(('http://', 'https://')):
        parsed = urllib.parse.urlparse('http://' + url_str)
    else:
        parsed = urllib.parse.urlparse(url_str)
    
    domain = parsed.netloc.split(':')[0]
    
    intel = {
        "domain_age_days": 9999,
        "has_valid_mx": 1,
        "intel_penalty": 0
    }
    
    # 1. Evaluate Live WHOIS Registration Age
    try:
        domain_info = whois.whois(domain)
        
        # If domain doesn't exist on standard registries, trigger exception flow
        if not domain_info or not domain_info.domain_name:
            raise Exception("Non-existent target domain registry record.")
            
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            intel["domain_age_days"] = age_days
            
            if age_days < 30:
                intel["intel_penalty"] += 50  # Maximum zero-day infrastructure penalty
            elif age_days < 180:
                intel["intel_penalty"] += 25
    except Exception:
        # If WHOIS fails to resolve, infrastructure is fake/unregistered. Max risk applied!
        intel["domain_age_days"] = 0
        intel["intel_penalty"] += 60  

    # 2. Evaluate Live DNS Mail Exchanger (MX) Records
    try:
        dns.resolver.resolve(domain, 'MX')
        intel["has_valid_mx"] = 1
    except Exception:
        intel["has_valid_mx"] = 0
        intel["intel_penalty"] += 30  # High risk indicator for missing enterprise mail records
        
    return intel

# --- ASYNC BACKGROUND WORKER PROCESS ---
def async_heavy_analysis_worker(task_id: str, raw_url: str):
    try:
        input_url = raw_url.lower().strip()
        
        # Core Whitelist Layer
        safe_domains = ["google.com", "github.com", "microsoft.com", "linkedin.com", "amazon.com", "apple.com"]
        if any(domain in input_url for domain in safe_domains) and not ("login" in input_url or "verify" in input_url):
            RESULTS_CACHE[task_id] = {
                "status": "COMPLETED",
                "payload": {
                    "url": raw_url,
                    "processed_timestamp": int(time.time()),
                    "verdict": {
                        "risk_index_percentage": 1.2,
                        "is_suspicious": False,
                        "engine_classification": "TRUSTED_WHITELIST"
                    }
                }
            }
            return

        # 1. Process Live Network Intel (DNS / WHOIS OSINT)
        network_intel = extract_domain_intel(raw_url)
        
        # 2. Process Lexical Heuristics
        metrics = extract_lexical_features(raw_url)
        heuristic_score = calculate_heuristic_risk(metrics)
        
        # 3. Process Deep Learning Weights
        dl_score = 0.0
        if os.path.exists("phishguard_model.pth"):
            with torch.no_grad():
                input_tensor = url_to_tensor(raw_url)
                prediction = model(input_tensor)
                dl_score = float(prediction.item() * 100)
                
        # 4. Composite Ensemble Calculation (25% Heuristics, 35% LSTM, 40% Live Network Intel)
        ensemble_risk = (heuristic_score * 0.25) + (dl_score * 0.35) + (network_intel["intel_penalty"] * 0.40)
        ensemble_risk = round(min(max(ensemble_risk, 1.0), 99.0), 1)
        is_suspicious = ensemble_risk >= 45.0
        
        RESULTS_CACHE[task_id] = {
            "status": "COMPLETED",
            "payload": {
                "url": raw_url,
                "processed_timestamp": int(time.time()),
                "verdict": {
                    "risk_index_percentage": ensemble_risk,
                    "is_suspicious": is_suspicious,
                    "engine_classification": "MALICIOUS_INFRASTRUCTURE" if is_suspicious and network_intel["domain_age_days"] == 0 else ("MALICIOUS_VECTOR" if is_suspicious else "STRUCTURALLY_CLEAN")
                }
            }
        }
    except Exception as e:
        RESULTS_CACHE[task_id] = {
            "status": "FAILED",
            "error": str(e)
        }

@app.post("/scan")
async def register_scan_job(payload: UrlPayload, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    RESULTS_CACHE[task_id] = {"status": "PROCESSING", "payload": None}
    background_tasks.add_task(async_heavy_analysis_worker, task_id, payload.url)
    return {"task_id": task_id, "status": "PROCESSING"}

@app.get("/status/{task_id}")
async def fetch_job_status(task_id: str):
    if task_id not in RESULTS_CACHE:
        raise HTTPException(status_code=404, detail="Tracking token not found.")
    return RESULTS_CACHE[task_id]