# 🛡️ PhishGuard Pro

## Hybrid AI & Global Threat Intelligence Platform for Phishing URL Detection

PhishGuard Pro is an intelligent phishing URL detection system that combines **Machine Learning** with **real-time global threat intelligence** to identify malicious websites. The application analyzes URL characteristics using a trained **Random Forest Classifier** and verifies URLs against **VirusTotal's** threat intelligence database.

Built with **Python** and **Streamlit**, the project provides an interactive web dashboard capable of performing enterprise-style phishing analysis in real time.

---

# 📌 Project Overview

Traditional phishing detection systems often rely on either machine learning or online reputation services. PhishGuard Pro integrates both approaches to improve detection accuracy.

The system performs:

* Local Machine Learning prediction
* Real-time VirusTotal reputation lookup
* URL feature extraction
* Risk probability estimation
* Interactive forensic reporting

---

# 🚀 Features

## 🤖 Artificial Intelligence

* Random Forest Classifier
* Probability-based phishing prediction
* Cached ML model for faster execution
* Feature vector generation

---

## 🌐 Global Threat Intelligence

* VirusTotal API Integration
* Detects previously reported malicious URLs
* Shows number of antivirus engines that flagged the URL
* Handles unknown or unscanned URLs gracefully

---

## 🔍 URL Feature Analysis

The application extracts multiple security-related URL features.

| Feature              | Description                                 |
| -------------------- | ------------------------------------------- |
| Uses IP Address      | Detects raw IP addresses instead of domains |
| Long URL             | Flags URLs longer than 75 characters        |
| @ Symbol Detection   | Detects hidden redirection attempts         |
| Excessive Subdomains | Detects suspicious domain structures        |
| Phishing Keywords    | Searches for phishing-related words         |

---

## 📊 AI Risk Classification

The trained Random Forest predicts the phishing probability.

| AI Probability | Risk Level               |
| -------------- | ------------------------ |
| 0–29%          | ✅ Structurally Clean     |
| 30–69%         | ⚠️ Suspicious Indicators |
| 70–100%        | 🚨 Critical Risk         |

---

# 🏗️ System Architecture

```
User Input
      │
      ▼
URL Normalization
      │
      ▼
Feature Extraction
      │
      ├──────────────► Random Forest Model
      │                    │
      │                    ▼
      │            AI Risk Prediction
      │
      ▼
VirusTotal API
      │
      ▼
Threat Intelligence
      │
      ▼
Combined Security Report
```

---

# 🧠 Machine Learning Model

Algorithm Used:

* Random Forest Classifier

Training Features:

* IP Address
* URL Length
* @ Symbol
* Number of Subdomains
* Phishing Keywords

Target Classes:

* Legitimate URL
* Phishing URL

The model outputs a phishing probability score using:

```python
predict_proba()
```

---

# 🌐 VirusTotal Integration

The application queries VirusTotal using its REST API.

Information Retrieved:

* Number of malicious detections
* Reputation status
* Previously scanned URLs
* Unknown URL detection

If the URL has never been scanned, the application returns:

```
Unscanned (New URL Target)
```

---

# 🔒 Security Headers

The application includes browser security headers such as:

* X-Content-Type-Options
* X-Frame-Options
* Content-Security-Policy

These headers improve browser-side security.

---

# 📂 Project Structure

```
PhishGuard-Pro/
│
├── app.py
├── requirements.txt
├── README.md
├── .streamlit/
│      └── secrets.toml
│
└── assets/
```

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/PhishGuard-Pro.git

cd PhishGuard-Pro
```

---

## Create Virtual Environment

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 📦 Required Libraries

```
streamlit
pandas
scikit-learn
requests
```

Install manually:

```bash
pip install streamlit pandas scikit-learn requests
```

---

# 🔑 VirusTotal API Setup

Create the following file:

```
.streamlit/secrets.toml
```

Add your VirusTotal API Key:

```toml
VT_API_KEY="YOUR_API_KEY_HERE"
```

You can obtain a free API key by creating an account on the VirusTotal website.

---

# ▶️ Run the Application

```bash
streamlit run app.py
```

The application will start at:

```
http://localhost:8501
```

---

# 📸 Application Workflow

```
Enter URL
      │
      ▼
Normalize URL
      │
      ▼
Extract Features
      │
      ├────────────► AI Prediction
      │
      ├────────────► VirusTotal Lookup
      │
      ▼
Display Results
      │
      ▼
Forensic Report
```

---

# 🧪 Example URLs

## Legitimate URL

```
https://www.google.com
```

Expected:

* AI Risk: Low
* VirusTotal: Clean

---

## Suspicious URL

```
http://192.168.10.20/login/account/confirm
```

Expected:

* High AI Probability
* Multiple Security Flags

---

# 📈 Technologies Used

* Python
* Streamlit
* Pandas
* Scikit-learn
* Random Forest Classifier
* Requests
* Regular Expressions (Regex)
* URL Parsing
* VirusTotal REST API

---

# 🎯 Learning Outcomes

This project demonstrates knowledge of:

* Machine Learning
* Cybersecurity Fundamentals
* Phishing Detection
* Threat Intelligence
* Feature Engineering
* REST API Integration
* Streamlit Application Development
* Random Forest Classification
* Security Header Implementation

---

# 🚀 Future Improvements

* Larger phishing dataset
* XGBoost and LightGBM models
* Deep Learning (LSTM)
* URL entropy analysis
* WHOIS domain age analysis
* SSL certificate validation
* Domain reputation scoring
* URL screenshot analysis
* Email phishing detection
* PDF phishing detection
* QR code phishing detection
* SHAP-based AI explainability
* User authentication
* Scan history database
* Export reports in PDF and CSV formats

---

# ⚠️ Limitations

* Current ML model is trained on a small demonstration dataset.
* Detection primarily relies on structural URL features.
* VirusTotal results depend on prior submissions to its platform.
* Advanced phishing techniques may require additional content and behavioral analysis.

---

# 👨‍💻 Author

**B.V.K. Koushik**

B.Tech – Artificial Intelligence & Data Science

Cybersecurity Enthusiast | SOC Analyst Aspirant | Machine Learning Developer

---

# 📄 License

This project is licensed under the MIT License.

You are free to use, modify, and distribute this project for educational and research purposes.

---

# ⭐ Acknowledgements

Special thanks to:

* Streamlit
* Scikit-learn
* Pandas
* VirusTotal
* Python Community

for providing the open-source tools and APIs that made this project possible.
