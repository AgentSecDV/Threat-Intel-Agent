# 🛡️ Threat Intelligence Agent

A SOC-style threat intelligence platform built in Python for analyzing IPs, domains, URLs, file hashes, and CVEs using enrichment, scoring, structured memory, and intelligence correlation.

This project simulates real-world Security Operations Center (SOC) workflows used for IOC triage, threat detection, vulnerability intelligence, and analyst reporting.

---

## 🚀 Current Version: Mk3

📁 Located in: `/TIAMk3`

Threat Intelligence Agent Mk3 expands the project into a multi-IOC threat intelligence dashboard with support for IPs, domains, URLs, hashes, CVEs, OSINT enrichment, MITRE ATT&CK context, batch analysis, and exportable results.

---

## 🧬 Project Evolution

### 🔹 Mk1

📁 Earlier version

* IP-based threat intelligence
* AbuseIPDB enrichment
* VirusTotal enrichment
* CLI-based analysis
* Basic risk scoring
* AI-generated analyst summaries

---

### 🔹 Mk2

📁 Located in: `/TIAMk2`

* Streamlit dashboard
* Domain intelligence
* DNS and RDAP enrichment
* URL heuristic analysis
* Structured IOC memory tracking
* Risk, confidence, and priority scoring
* SOC-style report output

---

### 🔹 Mk3 — Current

📁 Located in: `/TIAMk3`

Mk3 adds major SOC-style capabilities, including:

* IP analysis
* Domain analysis
* URL analysis
* File hash analysis
* CVE / CISA KEV analysis
* MalwareBazaar hash intelligence
* URLhaus URL intelligence
* Spamhaus ZEN IP reputation checks
* OSINT correlation scoring
* MITRE ATT&CK context mapping
* Structured IOC history and trend tracking
* Batch IOC analysis
* CSV and JSON batch export
* Streamlit dashboard interface

---

## 🔥 Key Features

* Multi-source IOC enrichment
* SOC-style risk scoring
* Confidence scoring
* Response priority scoring
* Historical IOC memory
* Repeat IOC detection
* Risk trend analysis
* AI-generated analyst summaries
* MITRE ATT&CK context mapping
* Batch analysis dashboard
* Exportable CSV and JSON results

---

## 🧾 Supported IOC Types

Mk3 supports:

* IP addresses
* Domains
* URLs
* File hashes
* CVEs

---

## 🧠 Intelligence Sources

Mk3 uses multiple enrichment and reputation sources:

* AbuseIPDB
* VirusTotal
* MalwareBazaar
* URLhaus
* CISA Known Exploited Vulnerabilities Catalog
* Spamhaus ZEN
* RDAP
* DNS
* Reverse DNS
* OpenAI API for analyst summaries

---

## 📊 Dashboard Capabilities

The Mk3 Streamlit dashboard includes:

* Single IOC analysis
* File upload for hash analysis
* Batch IOC input
* Uploaded IOC list support
* Risk, confidence, and priority cards
* Report context panel
* Hash intelligence panel
* MalwareBazaar panel
* URLhaus panel
* Spamhaus panel
* CISA KEV panel
* MITRE ATT&CK panel
* Domain intelligence panel
* Recent IOC history table
* Batch summary metrics
* CSV and JSON export buttons

---

## ⚙️ How to Run Mk3

Go into the Mk3 folder:

```bash
cd TIAMk3
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the CLI version:

```bash
python threat_intel_agent_mk3.py
```

Run the dashboard:

```bash
streamlit run dashboard.py
```

---

## 🔐 Environment Variables

Create a `.env` file inside the Mk3 folder with the following keys:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VT_API_KEY=your_virustotal_key_here
OPENAI_API_KEY=your_openai_key_here
MALWAREBAZAAR_API_KEY=your_malwarebazaar_key_here
URLHAUS_API_KEY=your_urlhaus_key_here
```

Never upload your real `.env` file or API keys to GitHub.

---

## 🎯 Project Purpose

This project was built as a cybersecurity portfolio project to demonstrate practical skills in:

* Threat intelligence
* SOC triage workflows
* Python automation
* API integration
* Indicator enrichment
* Vulnerability intelligence
* Malware hash investigation
* Risk scoring logic
* Streamlit dashboard development
* MITRE ATT&CK context mapping
* Analyst-style reporting

---

## 🚀 Future Enhancements — Mk4 Roadmap

Planned Mk4 improvements include:

* Cleaner user-friendly labels across all dashboard panels
* Dashboard input redesign
* More polished UI and layout
* Loading indicators for all analysis types
* Optional developer/debug mode
* Raw data cleanup in expandable sections
* MITRE ATT&CK TAXII/STIX enrichment
* Improved report export options
* Possible API backend or SaaS-style architecture

---

## ⚠️ Disclaimer

This tool is intended for educational, portfolio, and defensive security research purposes.

Threat intelligence results should be reviewed by a human analyst before taking action. Do not rely on a single data source or automated score for production security decisions.

---

## 👤 Author

David Coedo
Cybersecurity | Threat Detection | SOC Development
