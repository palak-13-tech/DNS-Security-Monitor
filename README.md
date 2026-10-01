# DNS Security Monitoring & Malicious Domain Detection System
## College Project Demonstration Prototype

A web-based cybersecurity system designed for real-time DNS traffic monitoring, domain feature extraction, and malicious domain detection.

---

## 🚀 Quick Start (Prototype Demonstration)

### 1. Launch the Application
Run the following single command from the project root:
```bash
./.venv/bin/python app.py
```
Then open your browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## ⏱️ 3-Minute College Demonstration Walkthrough

When presenting this prototype to your professor or evaluator:

1. **Overview & Problem Statement (0:00 - 1:00)**:
   * Explain that users generate hundreds of DNS queries daily, and cyber adversaries hide threats (phishing, C2 malware, algorithmic domain generation / DGA) inside these requests.
   * Point out the **SOC Dashboard**: KPI cards (*Total Requests, Safe Domains, Malicious Domains, Security Alerts*), and the **Threat Ratio Chart**.

2. **Demonstrate Real-Time Monitoring (1:00 - 2:00)**:
   * Click **"Start Monitoring"** on the dashboard.
   * Show that simulated DNS queries begin streaming into the **Recent DNS Activity Log** in real-time without reloading the page.
   * Highlight the automatic classification into **SAFE** (green) and **MALICIOUS** (red) tags.
   * Point to the **Recent Security Alerts** panel: when an anomaly is detected, actionable alerts are logged with severity levels (*CRITICAL, HIGH, MEDIUM*) and root-cause details.
   * Click **"Stop Monitoring"** to pause the feed.

3. **Demonstrate the Manual Domain Analyzer (2:00 - 3:00)**:
   * Click **"Domain Analyzer"** in the top navigation bar.
   * Explain that this module analyzes domain lexical and structural characteristics prior to Phase 2 ML model integration.
   * Use the demo quick-buttons to test different threat profiles:
     * **`google.com`**: Demonstrates a clean, benign domain (*Low entropy, 0 suspicious keywords, SAFE verdict*).
     * **`paypal-security-update.xyz`**: Demonstrates a phishing lure (*Phishing keywords detected, high-risk TLD `.xyz`, multiple hyphens, MALICIOUS verdict*).
     * **`k8x92m0qvwz14.info`**: Demonstrates high character entropy (*Shannon entropy > 4.0, unusual digit distribution, MALICIOUS verdict*).
     * **`bcdfghjklmnpqrst.net`**: Demonstrates DGA consonant clustering (*Unusually low vowel ratio, DGA pattern detected*).
   * Show the **Reason for Detection** box which provides human-readable explainability for each flagged domain.

---

## 🧪 Run Automated Tests
```bash
./.venv/bin/python -m unittest discover tests -v
```
*(All 14 unit and integration tests covering database integrity, simulation, analyzer heuristics, and Flask routes pass in < 0.5s).*

---

## 🌐 Cloud Deployment (Render)

This repository is pre-configured for one-click deployment as a Render Web Service:

* **Runtime**: Python 3
* **Build Command**: `pip install -r requirements.txt`
* **Start Command**: `gunicorn app:app`

### Local Production Test (Gunicorn)
To test the production Gunicorn server locally before deploying:
```bash
./.venv/bin/gunicorn app:app
```
Then navigate to: `http://localhost:5000`
