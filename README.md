# 🛡️ Threat Intelligence Agent

A SOC-style threat intelligence platform for analyzing IPs, domains, and URLs using enrichment, scoring, and AI-powered analysis.

---

## 🚀 Project Evolution

### 🔹 Mk1
- IP-based threat intelligence
- AbuseIPDB + VirusTotal enrichment
- CLI-based analysis
- Basic risk scoring

### 🔹 Mk2 (Current)
📁 Located in `/TIAMk2`

- Full SOC-style Streamlit dashboard
- Domain intelligence (DNS + RDAP)
- URL heuristic analysis (phishing detection)
- Structured IOC memory tracking
- Risk + Confidence + Priority scoring
- AI-generated analyst reports

## 📸 Mk2 Dashboard Preview

### 🟢 Low-Risk Domain Analysis
<img src="TIAMk2/assets/domain_low_1.png" width="800"/>
<img src="TIAMk2/assets/domain_low_2.png" width="800"/>
<img src="TIAMk2/assets/domain_low_3.png" width="800"/>
<img src="TIAMk2/assets/domain_low_4.png" width="800"/>

---

### 🟢 Low-Risk IP Analysis
<img src="TIAMk2/assets/ip_low_1.png" width="800"/>
<img src="TIAMk2/assets/ip_low_2.png" width="800"/>
<img src="TIAMk2/assets/ip_low_3.png" width="800"/>

---

### 🔴 High-Risk URL Analysis
<img src="TIAMk2/assets/url_high_1.png" width="800"/>
<img src="TIAMk2/assets/url_high_2.png" width="800"/>

---

## 🎯 Purpose

This project simulates real-world Security Operations Center (SOC) workflows, including:

- Threat enrichment
- Detection logic
- Risk scoring
- Analyst reasoning
- Incident triage

---

## ⚡ How to Run Mk2

```bash
cd TIAMk2
pip install -r requirements.txt
streamlit run dashboard.py
