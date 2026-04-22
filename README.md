# Threat Intelligence Agent

A Python-based threat intelligence tool that analyzes IP addresses using multiple intelligence sources and generates SOC-style analyst reports.

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