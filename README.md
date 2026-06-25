# 🛡️ PhishGuard AI

## Enterprise-Grade URL Security Analyzer

PhishGuard AI is a lightweight phishing URL detection tool built using **Python** and **Streamlit**. It analyzes URLs in real-time and identifies common phishing indicators using rule-based security checks.

The application provides an easy-to-use web interface where users can submit suspicious URLs and receive an instant security assessment along with a detailed forensic report.

---

## 🚀 Features

* Real-time URL security analysis
* Detects URLs using raw IP addresses
* Identifies abnormally long URLs
* Detects usage of "@" symbols commonly found in phishing attacks
* Flags excessive subdomains in domain names
* Detects common phishing-related keywords
* Provides risk scoring system
* Interactive and user-friendly Streamlit dashboard
* Detailed forensic report for every scan

---

## 🏗️ Project Architecture

### Frontend

* Streamlit

### Backend

* Python
* Regular Expressions (Regex)
* URL Parsing (`urllib.parse`)

---

## 📂 Project Structure

```bash
PhishGuard-AI/
│
├── app.py
├── README.md
├── requirements.txt
└── assets/
```

---

## ⚙️ Detection Parameters

The system evaluates URLs using the following security indicators:

| Security Check              | Description                                                  |
| --------------------------- | ------------------------------------------------------------ |
| Uses IP Address             | Detects URLs that use an IP address instead of a domain name |
| Abnormally Long URL         | Flags URLs longer than 75 characters                         |
| Contains @ Symbol           | Detects the use of "@" symbols in URLs                       |
| Excessive Domain Subdomains | Detects domains containing more than two dots                |
| Contains Phishing Keywords  | Searches for common phishing-related keywords                |

### Phishing Keywords Checked

```python
[
    'secure',
    'account',
    'webscr',
    'login',
    'ebayisapi',
    'signin',
    'banking',
    'confirm'
]
```

---

## 🔍 Risk Assessment Logic

| Risk Score | Status           |
| ---------- | ---------------- |
| 0          | ✅ CLEAN          |
| 1          | ⚠️ WARNING       |
| 2 or More  | 🚨 CRITICAL RISK |

---

## 🛠️ Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/your-username/PhishGuard-AI.git
cd PhishGuard-AI
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv
```

### Step 3: Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux/Mac

```bash
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 📦 Requirements

Create a `requirements.txt` file containing:

```text
streamlit
```

---

## ▶️ Running the Application

```bash
streamlit run app.py
```

After launching, Streamlit will provide a local URL similar to:

```text
http://localhost:8501
```

Open the link in your browser.

---

## 🧪 Example Test URLs

### Legitimate URL

```text
https://www.google.com
```

Expected Result:

```text
CLEAN
```

### Suspicious URL

```text
http://192.168.1.1/login/account/confirm
```

Expected Result:

```text
CRITICAL RISK
```

---

## 📸 Application Workflow

1. User enters a URL.
2. System normalizes the URL.
3. Security features are extracted.
4. Risk score is calculated.
5. Risk level is displayed.
6. Detailed forensic report is generated.

---

## 🔒 Limitations

* Uses rule-based detection only.
* Does not perform machine learning classification.
* Does not check website reputation databases.
* Does not analyze webpage content.
* Does not verify SSL certificates.

---

## 🚀 Future Enhancements

* Machine Learning-based phishing detection.
* URL reputation lookup using APIs.
* WHOIS domain age analysis.
* SSL certificate verification.
* VirusTotal integration.
* Domain blacklisting support.
* Threat intelligence feed integration.
* Email phishing detection module.

---

## 🎯 Learning Outcomes

Through this project, users can learn:

* Python programming
* Streamlit web development
* Cybersecurity fundamentals
* Phishing detection techniques
* URL analysis methods
* Regex pattern matching
* Security-focused application development

---

## 👨‍💻 Author

**B.V.K. Koushik**

Cybersecurity Enthusiast | SOC Analyst Aspirant | AI & Data Science Student

---

## 📜 License

This project is licensed under the MIT License.

Feel free to use, modify, and enhance the project for educational and research purposes.
