import streamlit as st
import re
from urllib.parse import urlparse

# --- SECURITY LOGIC (The Backend) ---
def extract_features(url):
    features = {}
    
    # 1. IP Address check
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    features['Uses IP Address'] = 1 if re.search(ip_pattern, url) else 0

    # 2. URL Length check
    features['Abnormally Long URL'] = 1 if len(url) > 75 else 0

    # 3. "@" Symbol check
    features['Contains "@" Symbol'] = 1 if "@" in url else 0

    # 4. Too many dots check
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    features['Excessive Domain Subdomains'] = 1 if domain.count('.') > 2 else 0

    # 5. Keywords check
    keywords = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
    features['Contains Phishing Keywords'] = 1 if any(word in url.lower() for word in keywords) else 0

    return features

# --- STREAMLIT INTERFACE (The Frontend) ---

# Set webpage browser tab title and icon
st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="centered")

# App Header
st.title("🛡️ PhishGuard Portal")
st.subheader("Enterprise-Grade URL Security Analyzer")
st.write("Paste a suspicious link below to evaluate its risk parameters in real-time.")

# User Input Field
user_url = st.text_input("Enter URL to scan:", placeholder="https://example-phishing-site.com")

# Scan Button Logic
if st.button("Run Security Scan"):
    if user_url:
        # Prepend http if user didn't type it, to allow proper parsing
        if not user_url.startswith(("http://", "https://")):
            url_to_analyze = "http://" + user_url
        else:
            url_to_analyze = user_url
            
        with st.spinner("Analyzing URL structure and signatures..."):
            # Run backend analysis
            flags = extract_features(url_to_analyze)
            total_red_flags = sum(flags.values())
            
        # Display Results Based on Risk
        st.write("---")
        if total_red_flags >= 2:
            st.error(f"🚨 CRITICAL RISK: Phishing Signatures Detected! (Score: {total_red_flags}/5)")
        elif total_red_flags == 1:
            st.warning(f"⚠️ WARNING: Suspicious Indicators Found. (Score: {total_red_flags}/5)")
        else:
            st.success("✅ CLEAN: No known architectural anomalies detected.")
            
        # UI Component: Detailed Risk Metrics Breakdown
        with st.expander("View Detailed Forensic Report"):
            for feature, status in flags.items():
                if status == 1:
                    st.markdown(f"❌ **{feature}**: Red Flag Tripped")
                else:
                    st.markdown(f"✔️ {feature}: Passed")
    else:
        st.info("Please enter a URL first before launching the scanner.")