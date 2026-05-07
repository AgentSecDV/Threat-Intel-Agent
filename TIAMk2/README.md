# 🛡️ Threat Intelligence Agent Mk2

A SOC-style threat intelligence platform built in Python that analyzes IPs, domains, and URLs using multi-source enrichment, heuristic scoring, and structured memory.

Designed to simulate real-world Security Operations Center (SOC) workflows used in threat detection and incident triage.

---

## 💡 Why This Project Matters

Modern SOC analysts rely on enrichment, correlation, and context — not just raw indicators.

This project demonstrates how multiple intelligence sources, scoring logic, and historical context can be combined to support real-world security decision-making.

---

## 🔥 Key Features

### 🧾 Supported IOC Types

* IP Addresses
* Domains
* URLs
* Hash detection (planned for future analysis)

---

### 🧠 Multi-Source Enrichment

* AbuseIPDB (abuse scoring)
* VirusTotal (malicious/suspicious detections)
* RDAP (ownership + network context)
* Reverse DNS (hostname resolution)
* Geolocation + ISP context

---

### 🌐 Domain Intelligence (Mk2 Upgrade)

* DNS enrichment (A, MX, NS records)
* RDAP domain analysis (age, expiration, status)
* Domain risk scoring engine
* Suspicious TLD detection
* Infrastructure validation (resolution checks)

---

### 🔗 URL Analysis Engine

* Phishing keyword detection (login, verify, secure, etc.)
* HTTP vs HTTPS detection
* Suspicious domain structure (hyphens, TLDs)
* Raw IP URL detection
* Fallback analysis when domains fail to resolve

---

### 📊 SOC-Style Dashboard (Streamlit)

* Risk, Confidence, and Priority cards
* Report Context (IOC → IP resolution)
* Domain Intelligence Panel
* Expandable DNS/RDAP details
* Key Findings + Analysis sections
* IOC History tracking table

---

### 🧠 Structured Memory System

* Tracks:

  * First seen / last seen
  * Times observed
  * Risk history over time
* Detects:

  * Repeat offenders
  * Risk trends (increasing / decreasing / stable)
* Applies **history-based risk escalation**

---

### ⚖️ Scoring Engine

* Risk scoring:

  * Abuse score
  * VirusTotal detections
  * ASN / AS owner reputation
  * RDAP country influence
  * Domain + URL heuristic signals
* Confidence scoring:

  * Multi-source agreement
  * Data quality
  * Historical consistency
  * Disagreement detection

---

### 🤖 AI Analyst Reports

* Generates SOC-style analyst summaries using OpenAI
* Includes:

  * Disposition
  * Assessment
  * Confidence
  * Priority
  * Key Findings
  * Analyst reasoning
  * Recommended action

---

### 📁 Output & Export

* TXT logging (`Threat_Intel.txt`)
* JSON structured export (`reports.json`)
* Local IOC history database (`ioc_history.json`)

---

## 🛠️ Technologies Used

* Python
* Streamlit
* Requests
* OpenAI API
* AbuseIPDB API
* VirusTotal API
* RDAP
* DNS (dnspython)
* JSON
* python-dotenv

---

## ⚙️ Setup Instructions

### 1. Clone Repository

```bash
git clone https://github.com/AgentSecDV/threat-intel-agent-mk2.git
cd threat-intel-agent-mk2
```

---

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Create `.env` File

```env
ABUSEIPDB_API_KEY=your_key_here
VT_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
```

> ⚠️ **Security Note:**
> Never commit your `.env` file or API keys to GitHub.
> Ensure `.env` is included in your `.gitignore`.

---

### 4. Run the Agent (CLI)

```bash
python threat_intel_agent_mk2.py
```

---

### 5. Run the Dashboard

```bash
streamlit run dashboard.py
```

---

## ⚡ Quick Start

```bash
pip install -r requirements.txt
streamlit run dashboard.py
```

---

## 🧪 Example Use Cases

### Analyze an IP

```
8.8.8.8
```

### Analyze a Domain

```
google.com
```

### Analyze a Suspicious URL

```
http://secure-login-update-example.xyz/account
```

---

## 🎯 Project Purpose

This project was built to simulate real-world **Security Operations Center (SOC)** workflows, including:

* Threat enrichment
* Risk scoring
* Analyst reasoning
* Incident triage
* Memory-based intelligence tracking

---

## 🚀 Future Enhancements (Mk3)

* Threat feed ingestion (OSINT feeds)
* Autonomous agent workflows
* API backend for SaaS deployment
* Multi-IOC batch dashboard view
* GitHub / repository intelligence scanning

---

## 👤 Author

David Coedo
Cybersecurity | Threat Detection | SOC Development

---

