# Threat Intelligence Agent

🚨 SOC-Style Threat Intelligence Agent with AI-Powered Analysis for IP Risk Assessment

A Python-based threat intelligence tool that analyzes IP addresses using multiple intelligence sources and generates SOC-style analyst reports.

Built to simulate real-world SOC triage workflows and threat intelligence correlation.

## Example Output

Assessment: HIGH  
Confidence: MEDIUM  
Priority: HIGH  

Key Findings:
- High abuse score detected
- Multiple VirusTotal detections
- Tor exit node infrastructure

Analysis:
Likely malicious infrastructure based on strong threat signals.

Recommended Action:
Block and escalate for investigation.

## Features

- IP enrichment using AbuseIPDB, VirusTotal, RDAP, geolocation, and reverse DNS
- Custom risk scoring engine
- Confidence scoring with disagreement detection
- Historical memory and repeat offender tracking
- SOC-style AI-generated analyst summaries
- TXT logging and JSON export
- Batch IP analysis support

## Technologies

- Python
- Requests
- OpenAI API
- AbuseIPDB API
- VirusTotal API
- RDAP
- JSON
- python-dotenv

## Setup

1. Clone the repository
2. Install dependencies:

```bash
pip install -r requirements.txt
