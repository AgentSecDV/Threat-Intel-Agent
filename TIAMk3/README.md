# 🛡️ Threat Intelligence Agent Mk3

A SOC-style Threat Intelligence Agent built in Python that analyzes IPs, domains, URLs, file hashes, and CVEs using multi-source enrichment, heuristic scoring, structured memory, and intelligence correlation.

Designed to simulate real-world Security Operations Center (SOC) workflows used in threat detection, indicator enrichment, incident triage, and analyst reporting.

---

## 💡 Why This Project Matters

Modern SOC analysts rely on more than raw indicators. They use enrichment, correlation, reputation checks, vulnerability intelligence, historical context, and analyst judgment.

This project demonstrates how multiple intelligence sources can be combined into a structured triage workflow that produces risk, confidence, response priority, key findings, recommended actions, and MITRE ATT&CK context.

---

## 🔥 Key Features

### 🧾 Supported IOC Types

- IP addresses
- Domains
- URLs
- File hashes
- CVEs

---

### 🧠 Multi-Source Threat Intelligence Enrichment

- AbuseIPDB for IP abuse reputation
- VirusTotal for IP and hash reputation
- MalwareBazaar for malware hash intelligence
- URLhaus for malicious URL intelligence
- CISA KEV for known exploited CVE checks
- Spamhaus ZEN for IP reputation and blocklist checks
- RDAP for ownership and network context
- Reverse DNS for hostname resolution
- DNS enrichment for domain infrastructure

---

### 🌐 Domain Intelligence

- DNS enrichment for A, MX, and NS records
- RDAP domain analysis
- Domain age and expiration checks
- Suspicious TLD detection
- Hyphen and long-domain pattern checks
- Infrastructure validation
- Domain risk scoring

---

### 🔗 URL Analysis

- URLhaus enrichment
- Phishing keyword detection
- HTTP vs HTTPS detection
- Suspicious domain structure checks
- Suspicious TLD detection
- Raw IP URL detection
- Fallback URL threat assessment when domains fail to resolve

---

### 🧬 Hash Intelligence

- SHA256, SHA1, and MD5 calculation for uploaded files
- VirusTotal file hash lookup
- MalwareBazaar hash enrichment
- File name, file type, file size, detection counts, and reputation context
- Hash-based risk, confidence, and priority scoring

---

### 🛡️ CVE / Vulnerability Intelligence

- CVE detection
- CISA Known Exploited Vulnerabilities lookup
- KEV status, vendor/project, product, vulnerability name, date added, due date, ransomware campaign use, required action, and notes
- User-friendly CISA KEV dashboard panel
- CVE-based risk, confidence, and response priority scoring

---

### 📬 Spamhaus ZEN Intelligence

- Spamhaus ZEN DNSBL lookup for IP reputation
- SBL, XBL, and PBL return-code mapping
- Spamhaus-based risk influence
- Spamhaus confidence influence
- Dashboard panel for Spamhaus results

---

### 🎯 MITRE ATT&CK Context Mapping

- Maps evidence to possible MITRE ATT&CK context
- Supports mappings such as:
  - T1190 — Exploit Public-Facing Application
  - T1566.002 — Spearphishing Link
  - T1105 — Ingress Tool Transfer
  - T1071 — Application Layer Protocol
  - T1204 — User Execution
- Includes rationale for each mapping
- Avoids overstating certainty by presenting mappings as possible context, not confirmed attacker behavior

---

### 📊 Streamlit Dashboard

- Single IOC analysis
- File upload for hash analysis
- Manual batch IOC input
- Uploaded IOC list support
- Risk, confidence, and priority cards
- Report context panel
- History snapshot
- Recent IOC history table
- Hash intelligence panel
- MalwareBazaar panel
- URLhaus panel
- Spamhaus panel
- CISA KEV panel
- MITRE ATT&CK panel
- Domain intelligence panel
- Key findings, analysis, and recommended action sections
- Batch summary metrics
- Batch results table
- Batch CSV and JSON export

---

### 🧠 Structured IOC Memory

Tracks historical IOC activity using a local structured memory file.

The memory system tracks:

- First seen
- Last seen
- Times observed
- Highest risk ever
- Last risk
- Last confidence
- Last priority
- Last verdict
- Risk history over time

It also supports:

- Repeat IOC detection
- Risk trend analysis
- History-based risk escalation
- Dashboard history snapshots

---

### ⚖️ Risk, Confidence, and Priority Scoring

The agent produces three separate SOC-style outputs:

- Risk Level
- Confidence Level
- Response Priority

Risk scoring considers:

- AbuseIPDB score
- VirusTotal detections
- Spamhaus listings
- CISA KEV presence
- MalwareBazaar matches
- URLhaus matches
- Domain and URL heuristics
- ASN / AS owner context
- RDAP country context
- Historical IOC behavior

Confidence scoring considers:

- Multi-source agreement
- Source disagreement
- Data availability
- Historical consistency
- Enrichment quality

Response priority combines risk and confidence into an analyst-friendly triage result.

---

### 🤖 AI Analyst Reports

The agent generates SOC-style analyst summaries using the OpenAI API.

Reports include:

- Disposition
- Assessment
- Confidence
- Priority
- Key findings
- Analyst reasoning
- Confidence caveat
- Recommended action

---

### 📁 Output & Export

- TXT logging through `Threat_Intel.txt`
- Structured JSON export through `reports.json`
- Local IOC history through `ioc_history.json`
- Batch CSV export
- Batch JSON export

---

## 🛠️ Technologies Used

- Python
- Streamlit
- Requests
- OpenAI API
- AbuseIPDB API
- VirusTotal API
- MalwareBazaar API
- URLhaus API
- CISA KEV catalog
- Spamhaus ZEN DNSBL
- RDAP
- DNS / dnspython
- JSON
- python-dotenv

---

## ⚙️ Setup Instructions

### 1. Clone Repository

```bash
git clone https://github.com/AgentSecDV/Threat-Intel-Agent.git
cd Threat-Intel-Agent