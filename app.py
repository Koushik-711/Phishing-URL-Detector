import streamlit as st
import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import requests
import base64

st.markdown(
    """
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
    """,
    unsafe_allow_html=True
)

try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
except Exception:
    VT_API_KEY = None

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

def check_virustotal(url):
    if not VT_API_KEY or VT_API_KEY == "YOUR_API_KEY_HERE":
        return "Not Configured in Secrets"
        
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {
            "accept": "application/json",
            "x-apikey": VT_API_KEY
        }
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            return malicious_count
        elif response.status_code == 404:
            return "Unscanned (New URL Target)"
        else:
            return f"API Error (Status Code: {response.status_code})"
    except Exception:
        return "Network Connection Timeout"

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

st.set_page_config(page_title="PhishGuard Pro", page_icon="🛡️", layout="centered")

st.title("🛡️ PhishGuard Pro")
st.subheader("Hybrid AI & Global Threat Intel Platform")
st.write("An enterprise-grade utility combining localized Machine Learning predictions with decentralized threat landscape feeds.")

user_url = st.text_input("Enter URL vector to scan:", placeholder="https://secure-banking-update.net/login")

if st.button("Launch Advanced Hybrid Scan"):
    if user_url:
        cleaned_url = user_url.replace("—", "-").replace("’", "'").replace("”", '"').strip()
        
        if not cleaned_url.startswith(("http://", "https://")):
            url_to_analyze = "http://" + cleaned_url
        else:
            url_to_analyze = cleaned_url
            
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🤖 Local AI Verdict")
            with st.spinner("Processing ML vectors..."):
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
                
        with col2:
            st.markdown("### 🌐 Global Threat Intel")
            with st.spinner("Pinging VirusTotal server node..."):
                vt_result = check_virustotal(url_to_analyze)
                
            if isinstance(vt_result, int):
                if vt_result > 0:
                    st.error(f"🚨 POSITIVE DETECTIONS\n\n{vt_result} engines flagged this URL as malicious!")
                else:
                    st.success("✅ GLOBAL CLEARANCE\n\n0/70+ security engines flagged this URL.")
            else:
                st.info(f"ℹ️ STATUS INFO\n\n{vt_result}\n\n(Verify your Streamlit Secrets Panel configuration)")
                
        with st.expander("View Integrated Forensic Log"):
            st.write("Extracted mathematical feature mappings passed into Random Forest matrix:")
            st.json(features_dict)
    else:
        st.info("Please provide a target domain path to run the evaluation metrics.")
