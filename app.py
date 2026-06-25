import streamlit as st
import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# --- 1. THE MACHINE LEARNING ENGINE ---

@st.cache_resource
def train_ai_model():
    """ Trains the AI on a simulated cybersecurity dataset when the app starts """
    # This represents a spreadsheet of real links parsed into numbers
    # Features: [has_ip, long_url, has_at, too_many_dots, has_keyword]
    # Target: 0 = Clean, 1 = Phishing
    data = {
        'has_ip':        [0, 1, 0, 1, 0, 0, 0, 1, 0, 0],
        'long_url':      [0, 1, 1, 1, 0, 0, 1, 0, 0, 1],
        'has_at':        [0, 0, 1, 0, 0, 0, 1, 1, 0, 0],
        'too_many_dots': [0, 1, 0, 1, 0, 1, 1, 0, 0, 1],
        'has_keyword':   [0, 1, 1, 1, 0, 0, 1, 1, 0, 1],
        'label':         [0, 1, 1, 1, 0, 0, 1, 1, 0, 1]  # 1 = Phishing, 0 = Safe
    }
    
    df = pd.DataFrame(data)
    X = df.drop('label', axis=1) # Features inputs
    y = df['label']              # Answers targets
    
    # Initialize the Random Forest model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    return model

# Load our trained model
ai_classifier = train_ai_model()

# --- 2. FEATURE EXTRACTION ---
def extract_features(url):
    # Extracts the exact same features the AI was trained on
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

# --- 3. STREAMLIT INTERFACE ---
st.set_page_config(page_title="PhishGuard AI v2", page_icon="🤖", layout="centered")

st.title("🤖 PhishGuard AI v2")
st.subheader("Machine Learning Driven URL Analyzer")
st.write("This version uses a Random Forest Machine Learning model to evaluate risk probabilities.")

user_url = st.text_input("Enter URL to scan:", placeholder="https://secure-banking-update.com")

if st.button("Launch AI Analysis"):
    if user_url:
        if not user_url.startswith(("http://", "https://")):
            url_to_analyze = "http://" + user_url
        else:
            url_to_analyze = user_url
            
        with st.spinner("Running statistical AI classification..."):
            # 1. Turn the user's URL into math numbers
            features_dict = extract_features(url_to_analyze)
            
            # Convert dictionary format to a DataFrame row for the AI
            input_data = pd.DataFrame([features_dict])
            
            # 2. Ask the AI to calculate the percentage probability of phishing
            probabilities = ai_classifier.predict_proba(input_data)[0]
            phishing_probability = probabilities[1] * 100 # Percent chance it is bad
            
        st.write("---")
        
        # Display customized metrics based on what the AI mathematically decided
        if phishing_probability >= 70:
            st.error(f"🚨 CRITICAL RISK: AI Classifies this as Phishing! ({phishing_probability:.1f}% Confidence)")
        elif phishing_probability >= 30:
            st.warning(f"⚠️ WARNING: AI Flags this as Suspicious. ({phishing_probability:.1f}% Confidence)")
        else:
            st.success(f"✅ CLEAN: AI detects normal architectural structures. (Malicious Risk: {phishing_probability:.1f}%)")
            
        with st.expander("View AI Inputs Forensic Breakdown"):
            st.write("The numbers below were passed directly into the Random Forest algorithm matrix:")
            st.json(features_dict)
    else:
        st.info("Please input a URL to trigger the classification model.")
