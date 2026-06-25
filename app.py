import streamlit as st
import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import requests  # New library for internet API calls
import base64    # Needed to format the URL for VirusTotal

# --- VIRUSTOTAL API CONFIGURATION ---
# 🚨 PASTE YOUR VIRUSTOTAL API KEY BETWEEN THE QUOTES BELOW 🚨
VT_API_KEY = "19294f3950f1f751923c37947fc5a7744d3779b37c5bccb272bae02b65a5148d"

# --- 1. THE MACHINE LEARNING ENGINE ---
@st.cache_resource
def train_ai_model():
    data = {
        'has_ip':        [0, 1, 0, 1, 0, 0, 0, 1, 0, 0],
        'long_url':      [0, 1, 1, 1, 0, 0, 1, 0, 0, 1],
        'has_at':        [0, 0, 1, 0, 0, 0, 1, 1, 0, 0],
        'too_many_dots': [0, 1, 0, 1, 0, 1, 1, 0, 0, 1],
        'has_keyword':   [0, 1, 1, 1, 0, 0, 1, 1, 0, 1],
        'label':         [0, 1, 1, 1, 0, 0, 1, 1, 0, 1]
    }
    df = pd.DataFrame(data)
    X = df.drop('label', axis=1)
    y = df['label']
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    return model

ai_classifier = train_ai_model()

# --- 2. THE THREAT INTELLIGENCE ENGINE (VirusTotal API) ---
def check_virustotal(url):
    """ Queries VirusTotal API v3 for global engine detection results """
    if not VT_API_KEY or VT_API_KEY == "YOUR_API_KEY_HERE":
        return "Not Configured"
        
    try:
        # VirusTotal v3 requires URLs to be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {
            "accept": "application/json",
            "x-apikey": VT_API_KEY  
        }
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            # Extract the raw detection statistics
            stats = result['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            return malicious_count
        elif response.status_code == 404:
            return "Unscanned (New URL)"
        else:
            return "API Error"
    except Exception:
        return "Connection Error"

# --- 3. FEATURE EXTRACTION ---
def extract_features(url):
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    features = {
        'has_ip': 1 if re.search(ip_pattern, url) else 0,
        'long_url': 1 if len(url) > 75 else 0,
        'has_at': 1 if "@" in url else 0,
        'too_many_dots': 1 if urlparse(url).netloc.count('.') > 2 else 0
    }
    keywords = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
    features['has_keyword'] = 1 if any(word in url.lower() for word in keywords) else 0
    return features

# --- 4. STREAMLIT FRONTEND INTERFACE ---
st.set_page_config(page_title="PhishGuard AI Pro", page_icon="⚡", layout="centered")

st.title("⚡ PhishGuard Pro")
st.subheader("Hybrid AI & Global Threat Intel Platform")
st.write("This professional dashboard combines local Machine Learning models with live global reputation data via the VirusTotal API network layer.")

# User Input
user_url = st.text_input("Enter URL to scan:", placeholder="https://example.com")

if st.button("Launch Advanced Hybrid Scan"):
    if user_url:
        if not user_url.startswith(("http://", "https://")):
            url_to_analyze = "http://" + user_url
        else:
            url_to_analyze = user_url
            
        # Create UI side-by-side split layout columns
        col1, col2 = st.columns(2)
        
        # COLUMN 1: Run Local Machine Learning Analysis
        with col1:
            st.markdown("### 🤖 Local AI Verdict")
            with st.spinner("Calculating ML tensor matrices..."):
                features_dict = extract_features(url_to_analyze)
                input_data = pd.DataFrame([features_dict])
                probabilities = ai_classifier.predict_proba(input_data)[0]
                phishing_probability = probabilities[1] * 100
                
            if phishing_probability >= 70:
                st.error(f"🚨 CRITICAL RISK\n\nAI Probability: {phishing_probability:.1f}%")
            elif phishing_probability >= 30:
                st.warning(f"⚠️ SUSPICIOUS INDICATORS\n\nAI Probability: {phishing_probability:.1f}%")
            else:
                st.success(f"✅ STRUCTURALLY CLEAN\n\nAI Risk Score: {phishing_probability:.1f}%")
                
        # COLUMN 2: Run Global Threat Intel Check via VirusTotal
        with col2:
            st.markdown("### 🌐 Global Threat Intel")
            with st.spinner("Querying VirusTotal global node..."):
                vt_result = check_virustotal(url_to_analyze)
                
            if isinstance(vt_result, int):
                if vt_result > 0:
                    st.error(f"🚨 POSITIVE DETECTIONS\n\n{vt_result} security engines flagged this link as malicious!")
                else:
                    st.success("✅ GLOBAL CLEARANCE\n\n0/70+ industry engines flagged this URL.")
            else:
                st.info(f"ℹ️ STATUS INFO\n\n{vt_result}\n\n(Verify your API Key script configuration)")
                
        # Lower Expander Report
        with st.expander("View Integrated Forensic Log"):
            st.write("Structural properties analyzed:")
            st.json(features_dict)
    else:
        st.info("Please provide a target URL vector to run the security scanners.")
