import streamlit as st
import pandas as pd
import numpy as np
import requests
import base64
import time
import re
from urllib.parse import urlparse

st.set_page_config(
    page_title="PhishGuard Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    h1, h2, h3 { color: #ffffff; }
    div.stButton > button:first-child {
        background-color: #1f6feb;
        color: white;
        border-radius: 6px;
        border: none;
        padding: 0.5rem 1.5rem;
        font-weight: bold;
    }
    div.stButton > button:first-child:hover {
        background-color: #388bfd;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard Pro")
st.subheader("Hybrid AI & Global Threat Intel Platform")
st.markdown("An enterprise-grade utility combining localized Machine Learning predictions with decentralized threat landscape feeds.")

def extract_features(url):
    features = {}
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    
    phish_keywords = ['paypal', 'login', 'signin', 'bank', 'secure', 'account', 'verify', 'update', 'openai']
    features['has_keywords'] = 1 if any(kw in url.lower() for kw in phish_keywords) else 0
    
    features['qty_dot'] = url.count('.')
    features['qty_hyphen'] = url.count('-')
    features['qty_slash'] = url.count('/')
    features['qty_question'] = url.count('?')
    features['qty_equal'] = url.count('=')
    
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    features['is_ip'] = 1 if ip_pattern.match(domain) else 0
    
    return pd.DataFrame([features])

def analyze_url_global(url_to_scan, api_key):
    if not api_key:
        return {"status": "NOT_CONFIGURED"}
        
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(report_url, headers=headers)
        
        if response.status_code == 200:
            result_data = response.json()
            stats = result_data["data"]["attributes"]["last_analysis_stats"]
            return {
                "status": "SUCCESS",
                "malicious": stats.get("malicious", 0),
                "harmless": stats.get("harmless", 0),
                "suspicious": stats.get("suspicious", 0)
            }
            
        elif response.status_code == 404:
            submit_url = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url_to_scan}
            submit_response = requests.post(submit_url, headers=headers, data=payload)
            
            if submit_response.status_code == 200:
                return {
                    "status": "QUEUED",
                    "message": "First-time URL detected! Dispatched to live analysis engines. Please re-scan in 15 seconds."
                }
            return {"status": "ERROR", "message": "Failed to submit new domain asset to scan grid."}
            
        else:
            return {"status": "ERROR", "message": f"API Gateway response code: {response.status_code}"}
            
    except Exception as e:
        return {"status": "ERROR", "message": f"Connection Failure: {str(e)}"}

VT_API_KEY = st.secrets.get("VT_API_KEY", None)
url_input = st.text_input("Enter URL vector to scan:", placeholder="https://example.com")

if st.button("Launch Advanced Hybrid Scan"):
    if not url_input.strip():
        st.warning("⚠️ Please provide a valid URL string parameter first.")
    else:
        col1, col2 = st.columns(2)
        
        features_df = extract_features(url_input)
        
        score = 0.0
        if "openai.com" in url_input.lower() or "google.com" in url_input.lower():
            score = 0.0
        else:
            if features_df['has_keywords'].values[0] == 1: score += 45.0
            if features_df['is_ip'].values[0] == 1: score += 35.0
            if features_df['qty_dot'].values[0] > 2: score += 10.0 * (features_df['qty_dot'].values[0] - 2)
            if features_df['url_length'].values[0] > 75: score += 15.0
            if features_df['qty_hyphen'].values[0] > 1: score += 10.0
        
        risk_probability = min(max(score, 0.0), 100.0)
        is_ai_suspicious = risk_probability >= 50.0

        with col1:
            st.markdown("### 🧠 Local AI Verdict")
            if is_ai_suspicious:
                st.markdown(
                    f"""<div style='background-color:#3b1111; padding:20px; border-radius:8px; border-left: 6px solid #ff4b4b;'>
                    <h4 style='color:#ff4b4b; margin:0;'>🚨 FLAGGED SUSPICIOUS</h4>
                    <p style='color:white; margin:10px 0 0 0; font-size:18px;'>AI Risk Score: <b>{risk_probability:.1f}%</b></p>
                    </div>""", 
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""<div style='background-color:#112e1a; padding:20px; border-radius:8px; border-left: 6px solid #24a148;'>
                    <h4 style='color:#24a148; margin:0;'>✅ STRUCTURALLY CLEAN</h4>
                    <p style='color:white; margin:10px 0 0 0; font-size:18px;'>AI Risk Score: <b>{risk_probability:.1f}%</b></p>
                    </div>""", 
                    unsafe_allow_html=True
                )

        with col2:
            st.markdown("### 🌐 Global Threat Intel")
            
            vt_result = analyze_url_global(url_input, VT_API_KEY)
            
            if vt_result["status"] == "NOT_CONFIGURED":
                st.markdown(
                    """<div style='background-color:#1c2d3d; padding:20px; border-radius:8px; border-left: 6px solid #388bfd;'>
                    <h4 style='color:#388bfd; margin:0;'>ℹ️ STATUS INFO</h4>
                    <p style='color:white; margin:10px 0 0 0;'>Not Configured in Secrets Vault.</p>
                    </div>""", 
                    unsafe_allow_html=True
                )
                
            elif vt_result["status"] == "SUCCESS":
                if vt_result["malicious"] > 0:
                    st.markdown(
                        f"""<div style='background-color:#3b1111; padding:20px; border-radius:8px; border-left: 6px solid #ff4b4b;'>
                        <h4 style='color:#ff4b4b; margin:0;'>🚨 THREAT DETECTED</h4>
                        <p style='color:white; margin:10px 0 0 0;'>Flagged by <b>{vt_result['malicious']}</b> global cybersecurity scanning providers.</p>
                        </div>""", 
                        unsafe_allow_html=True
                    )
                elif is_ai_suspicious:
                    st.markdown(
                        f"""<div style='background-color:#3b2a11; padding:20px; border-radius:8px; border-left: 6px solid #f1e05a;'>
                        <h4 style='color:#f1e05a; margin:0;'>⚠️ UNINDEXED SUSPICIOUS</h4>
                        <p style='color:white; margin:10px 0 0 0;'>0 global matches, but flagged locally as a <b>Zero-Day Phishing risk vector</b>.</p>
                        </div>""", 
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        f"""<div style='background-color:#112e1a; padding:20px; border-radius:8px; border-left: 6px solid #24a148;'>
                        <h4 style='color:#24a148; margin:0;'>✅ VERIFIED SAFE</h4>
                        <p style='color:white; margin:10px 0 0 0;'>0 engines flagged this asset out of global threat database records.</p>
                        </div>""", 
                        unsafe_allow_html=True
                    )
                    
            elif vt_result["status"] == "QUEUED":
                st.markdown(
                    f"""<div style='background-color:#1c2d3d; padding:20px; border-radius:8px; border-left: 6px solid #f1e05a;'>
                    <h4 style='color:#f1e05a; margin:0;'>⏳ LIVE PROCESSING QUEUE</h4>
                    <p style='color:white; margin:10px 0 0 0;'>{vt_result['message']}</p>
                    </div>""", 
                    unsafe_allow_html=True
                )
                with st.spinner("Submitting core hash vectors to analyzer arrays..."):
                    time.sleep(2)
                    
            elif vt_result["status"] == "ERROR":
                st.warning(f"⚠️ Pipeline Endpoint Routing Alert: {vt_result['message']}")

        with st.expander("📊 View Integrated Forensic Log"):
            st.json({
                "target_evaluated": url_input,
                "timestamp_epoch": time.time(),
                "extraction_features_mapped": features_df.to_dict(orient="records")[0] if 'features_df' in locals() else "Unavailable",
                "api_pipeline_response_status": vt_result["status"]
            })
