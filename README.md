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

## Demo (Live Output)

### Low Risk Example (Google DNS - 8.8.8.8)
<img width="1000" height="959" alt="Low Risk Example Part 1" src="https://github.com/user-attachments/assets/02108a34-6141-4da1-897a-3c261959c74a" />
<img width="1000" height="664" alt="High Risk Example Part 2" src="https://github.com/user-attachments/assets/600a3e51-cd51-448e-9c97-662d49a4b648" />
Benign Google DNS IP with no malicious detections and high-confidence assessment.

# High Risk Example (Tor Exit Node)
<img width="1000" height="961" alt="High Risk Example Part 1" src="https://github.com/user-attachments/assets/d5bbd27c-4c28-4370-9d08-894c1a539012" />
<img width="1000" height="665" alt="High Risk Example Part 2" src="https://github.com/user-attachments/assets/a2d42908-3ae7-4147-a050-2133e0789e97" />
Tor exit node with high abuse score and multiple malicious detections, supporting a likely malicious infrastructure assessment.

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
