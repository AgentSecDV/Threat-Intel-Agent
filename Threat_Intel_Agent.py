import requests
import os
from datetime import datetime
import socket
import json
from dotenv import load_dotenv
from openai import OpenAI   

load_dotenv(override=True)

#---------------API KEYS

#ABUSEIPDB API KEY
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not API_KEY:
    raise ValueError("Missing AbuseIPDB API key. Set the ABUSEIPDB_API_KEY environment variable.")

#VIRUSTOTAL API KEY
VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise ValueError("Missing VirusTotal API key. Set the VT_API_KEY environment variable.")

#OPENAI API KEY
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("Missing OpenAI API key. Set the OPENAI_API_KEY environment variable.")

client = OpenAI(api_key = OPENAI_API_KEY)


base_folder = os.path.dirname(__file__)
log_file = os.path.join(base_folder, "Threat_Intel.txt")

def get_ip_info(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url, timeout=5)
    return response.json()


def get_abuse_info(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params, timeout=5)
    return response.json()

#Reverse DNS Lookup
def get_reverse_dns(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "No hostname found."
    

#RDAP Lookup
def get_rdap_info(ip):
    url = f"https://rdap.arin.net/registry/ip/{ip}"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        network_name = data.get("name", "Unknown")
        handle = data.get("handle", "Unknown")
        country = data.get("country", "Unknown")

        return {
            "network_name": network_name,
            "handle": handle,
            "country": country
        }
    except:
        return{
            "network_name": "Unknown",
            "handle": "Unknown",
            "country": "Unknown"
        }
    

#VirusTotal Lookup
def get_virustotal_info(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "asn": attributes.get("asn", "Unknown"),
            "as_owner": attributes.get("as_owner", "Unknown"),
            "network": attributes.get("network", "Unknown"),
            "rir": attributes.get("regional_internet_registry", "Unknown")
        }
    
    except:
        return{
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reputation": 0,
            "asn": "Unknown",
            "as_owner": "Unknown",
            "network": "Unknown",
            "rir": "Unknown"
        }


#AS Owner reputation weighting
def get_as_owner_risk(as_owner):
    high_watchlist_owners = ["M247", "Frantech", "Choopa", "OVH", "DigitalOcean"]
    medium_watchlist_owners = ["Akamai", "Hetzner", "Linode", "Vultr"]

    if not as_owner or as_owner == "Unknown":
        return 0
    
    for owner in high_watchlist_owners:
        if owner.lower() in as_owner.lower():
            return 2
        
    for owner in medium_watchlist_owners:
        if owner.lower() in as_owner.lower():
            return 1
        
    return 0


#RDAP Country Influence
def get_rdap_country_risk(rdap_country):
    if not rdap_country or rdap_country == "Unknown":
        return 0
    
    high_risk_rdap_countries = ["RU", "CN", "KP", "IR"]
    medium_risk_rdap_countries = ["BY", "IN", "PK", "VN"]
    lower_risk_watchlist_country = ["BR", "KH"]

    if rdap_country in high_risk_rdap_countries:
        return 2
    elif rdap_country in medium_risk_rdap_countries:
        return 1
    elif rdap_country in lower_risk_watchlist_country:
        return 1
    
    return 0


#Risk calculator
def calculate_risk(country, abuse_score, vt_info, as_owner, rdap_country):
    risk_points = 0

    if abuse_score >= 80:
        risk_points += 5
    elif abuse_score >= 40:
        risk_points += 3
    elif abuse_score > 0:
        risk_points += 1
    
    #VirusTotal Scoring Influence
    if vt_info["malicious"] > 0:
        risk_points += 3
    elif vt_info["suspicious"] > 0:
        risk_points += 1

    #AS Owner reputation scoring
    as_owner_risk = get_as_owner_risk(as_owner)
    risk_points += as_owner_risk

    #RDAP Country Influence
    rdap_country_risk = get_rdap_country_risk(rdap_country)
    risk_points += rdap_country_risk
    
    #Country placeholder logic
    high_risk_countries = ["China", "Russia", "North Korea", "Iran"]
    active_growing_risk_countries = ["Belarus", "India", "Pakistan", "Vietnam"]
    crime_heavy_countries = ["Brazil", "Cambodia"]
    
    if country in high_risk_countries:
        risk_points += 5
    
    elif country in active_growing_risk_countries:
        risk_points += 4
    
    elif country in crime_heavy_countries:
        risk_points += 3

    if risk_points >= 7:
        risk_level = "HIGH 🚨"
    elif risk_points >= 4:
        risk_level = "MEDIUM ⚠️"
    else:
        risk_level = "LOW ✅"

    return risk_points, risk_level


#Reasoning for risk
def get_reasons(country, abuse_score, vt_info, as_owner, rdap_country):
    reasons = []

    if abuse_score >= 80:
        reasons.append("Very high abuse score detected.")
    elif abuse_score >= 40:
        reasons.append("Moderately high abuse score detected.")
    elif abuse_score > 0:
        reasons.append("Some abuse reports were found.")
    else:
        reasons.append("No abuse reports were found.")
    
    if vt_info["malicious"] > 0:
        reasons.append("VirusTotal shows malicious detections.")
    elif vt_info["suspicious"] > 0:
        reasons.append("VirusTotal shows suspicious detections.")


    high_risk_countries = ["China", "Russia", "North Korea", "Iran"]
    active_growing_risk_countries = ["Belarus", "India", "Pakistan", "Vietnam"]
    crime_heavy_countries = ["Brazil", "Cambodia"]

    if country in high_risk_countries:
        reasons.append("IP originates from a high-risk country.")
    elif country in active_growing_risk_countries:
        reasons.append("IP originates from a growing-risk country.")
    elif country in crime_heavy_countries:
        reasons.append("IP originates from a cyber crime-heavy country.")
    
    as_owner_risk = get_as_owner_risk(as_owner)

    if as_owner_risk == 2:
        reasons.append("AS owner belongs to a higher-watchlist infrastructure provider.")
    elif as_owner_risk == 1:
        reasons.append("AS owner belongs to a medium-watchlist infrastructure provider.")
    
    
    rdap_country_risk = get_rdap_country_risk(rdap_country)

    if rdap_country_risk == 2:
        reasons.append("RDAP country supports a higher-risk ownership context.")
    elif rdap_country_risk == 1:
        reasons.append("RDAP country adds some ownership-risk support.")

    return reasons


#Actions that are recommended
def recommend_action(risk_level,confidence_level, abuse_score):
    if "HIGH" in risk_level:
        if "HIGH" in confidence_level:
            return "Block this IP immediately, review logs, and escalate for investigation."
        elif "MEDIUM" in confidence_level:
            return "Strongly consider blocking this IP, review related logs, and escalate for analyst review."
        else:
            return "Treat this IP as suspicious, investigate immediately, and confirm before taking blocking action."
    
    elif "MEDIUM" in risk_level:
        if "HIGH" in confidence_level:
            return "Investigate this IP promptly and consider temporary containment if related activity is suspicious."
        elif "MEDIUM" in confidence_level:
            return "Monitor this IP closely and review related activity for additional signs of malicious behavior."
        else:
            return "Keep this IP under observation and gather more evidence before taking action."
    
    else:
        if "HIGH" in confidence_level:
            return "No immediate action needed. Continue normal monitoring with high confidence in the benign assessment."
        elif "MEDIUM" in confidence_level:
            return "No immediate action needed. Continue monitoring as a precaution."
        else:
            return "No immediate action needed, but the assessment has limited support. Recheck if new evidence appears."


#Analysis 
def analyst_verdict(risk_level):
    if "HIGH" in risk_level:
        return "Likely malicious infrastructure."
    elif "MEDIUM" in risk_level:
        return "Suspicious activity that deserves analyst review."
    else:
        return "Low concern at this time. No immediate action required."


def get_response_priority(risk_level, confidence_level):
    if "HIGH" in risk_level and "HIGH" in confidence_level:
        return "CRITICAL 🔥"
    elif "HIGH" in risk_level and "MEDIUM" in confidence_level:
        return "HIGH 🚨"
    elif "HIGH" in risk_level and "LOW" in confidence_level:
        return "HIGH ⚠️"

    elif "MEDIUM" in risk_level and "HIGH" in confidence_level:
        return "HIGH 🚨"
    elif "MEDIUM" in risk_level and "MEDIUM" in confidence_level:
        return "MEDIUM ⚠️"
    elif "MEDIUM" in risk_level and "LOW" in confidence_level:
        return "LOW 🔎"
    
    elif "LOW" in risk_level and "HIGH" in confidence_level:
        return "LOW ✅"
    elif "LOW" in risk_level and "MEDIUM" in confidence_level:
        return "LOW ✅"
    else:
        return "INFO ℹ️"
    

#Confidence scoring based on source agreement
def calculate_confidence(abuse_score, vt_info, repeat_count, hostname, risk_level, rdap_country):
    confidence_points = 0
    confidence_reasons = []

    vt_clean = vt_info["malicious"] == 0 and vt_info["suspicious"] == 0
    abuse_clean = abuse_score == 0
    hostname_resolved = hostname != "No hostname found."

    #High confidence for clearly benign results

    if "LOW" in risk_level:
        if abuse_clean:
            confidence_points += 2
            confidence_reasons.append("AbuseIPDB shows no abuse reports.")
        else:
            confidence_reasons.append("AbuseIPDB shows some abuse activity, which weakens a low-risk conclusion.")

        if vt_clean:
            confidence_points += 2
            confidence_reasons.append("VirusTotal shows no malicious or suspicious detections.")
        else:
            confidence_reasons.append("VirusTotal shows detections, which weakens a low-risk conclusion.")
        
        if hostname_resolved:
            confidence_points += 1
            confidence_reasons.append("Reverse DNS resolved successfully, adding context to the assessment.")

        if repeat_count == 0:
            confidence_points += 1
            confidence_reasons.append("This IP has not appeared in the log before.")
        else:
            confidence_reasons.append("This IP has prior history in the log, which weakens a low-risk conclusion.")
        
        if rdap_country == "Unknown":
            confidence_reasons.append("RDAP country information is unavailable, so it does not strengthen the low-risk conclusion.")
        elif rdap_country in ["US", "CA", "GB", "DE", "FR","JP", "AU"]:
            confidence_points += 1
            confidence_reasons.append("RDAP country provides additional support for a benign ownership context.")
        else:
            confidence_reasons.append("RDAP country does not strongly reinforce the low-risk conclusion.")
    
    #High confidence for clearly suspicious / malicious results
    elif "HIGH" in risk_level:
        if abuse_score >= 40:
            confidence_points += 2
            confidence_reasons.append("AbuseIPDB shows elevated abuse confidence.")
        elif abuse_score > 0:
            confidence_points += 1
            confidence_reasons.append("AbuseIPDB shows some abuse activity.")
        else:
            confidence_reasons.append("AbuseIPDB does not strongly support a high-risk conclusion.")

        if vt_info["malicious"] > 0:
            confidence_points += 2
            confidence_reasons.append("VirusTotal has malicious detections.")
        elif vt_info["suspicious"] > 0:
            confidence_points += 1
            confidence_reasons.append("VirusTotal has suspicious detections.")
        else:
            confidence_reasons.append("VirusTotal does not strongly support a high-risk conclusion.")

        if repeat_count >= 2:
            confidence_points += 2
            confidence_reasons.append("This IP has appeared multiple times before.")
        elif repeat_count == 1:
            confidence_points += 1
            confidence_reasons.append("This IP has been seen before.")
        else:
            confidence_reasons.append("There is no repeat history supporting a high-risk conclusion.")
        
        if rdap_country in ["RU", "CN", "KP", "IR", "BY", "PK"]:
            confidence_points += 1
            confidence_reasons.append("RDAP country supports the high-risk conclusion.")
        elif rdap_country == "Unknown":
            confidence_reasons.append("RDAP country information is unavailable and does not strengthen the high-risk conclusion.")
        else:
            confidence_reasons.append("RDAP country does not strongly support the high-risk conclusion.")
    
    #Medium risk usually means mixed or incomplete evidence
    else:
        if abuse_score >= 40:
            confidence_points += 2
            confidence_reasons.append("AbuseIPDB shows elevated abuse confidence.")
        elif abuse_score > 0:
            confidence_points += 1
            confidence_reasons.append("AbuseIPDB shows some abuse activity.")
        else:
            confidence_reasons.append("AbuseIPDB does not add strong support.")

        if vt_info["malicious"] > 0:
            confidence_points += 2
            confidence_reasons.append("VirusTotal has malicious detections.")
        elif vt_info["suspicious"] > 0:
            confidence_points += 1
            confidence_reasons.append("VirusTotal has suspicious detections.")
        else:
            confidence_reasons.append("VirusTotal does not show malicious or suspicious detections.")

        if repeat_count >= 2:
            confidence_points += 2
            confidence_reasons.append("This IP has appeared multiple times before.")
        elif repeat_count == 1:
            confidence_points += 1
            confidence_reasons.append("This IP has been seen before.")

        if hostname_resolved:
            confidence_points += 1
            confidence_reasons.append("Reverse DNS resolved successfully, adding more context.")
        
        if rdap_country == "Unknown":
            confidence_reasons.append("RDAP country information is unavailable, so it does not add support.")
        elif rdap_country in ["RU", "CN", "KP", "IR", "BY", "PK", "IN", "VN", "BR", "KH"]:
            confidence_points += 1
            confidence_reasons.append("RDAP country adds support to the medium-risk conclusion.")
        else:
            confidence_reasons.append("RDAP country does not add strong support to the medium-risk conclusion.")

     #Disagreement Logic
    if vt_info["malicious"] > 0 and abuse_score == 0:
        confidence_points -= 2
        confidence_reasons.append("Data sources disagree: VirusTotal flags malicious activity but AbuseIPDB shows no reports.")
    
    elif vt_info["malicious"] == 0 and abuse_score >= 40:
        confidence_points -= 2
        confidence_reasons.append("Data sources disagree: AbuseIPDB shows elevated abuse confidence but VirusTotal shows no malicious detections.")
    
    #Prevent confidence from going below zero
    confidence_points = max(confidence_points, 0)

    if confidence_points >= 5:
        confidence_level = "HIGH 🟢"
    elif confidence_points >= 3:
        confidence_level = "MEDIUM 🟡"
    else:
        confidence_level = "LOW 🔴"

    return confidence_level, confidence_points, confidence_reasons
    
def generate_ai_summary(ip, country, isp, hostname, rdap_info, vt_info, abuse_score, risk_points, risk_level, confidence_level, confidence_points, response_priority, reasons, confidence_reasons, history_summary, verdict, recommendation):

    clean_risk = risk_level.split()[0]
    clean_confidence = confidence_level.split()[0]
    clean_priority = response_priority.split()[0]

    if "LOW" in risk_level:
        disposition = "benign"
    elif "MEDIUM" in risk_level:
        disposition = "suspicious"
    else:
        disposition = "likely malicious"

    try:
        prompt = f"""You are a cybersecurity threat intelligence analyst.

Write a short SOC-style analyst report for this IP analysis result.
Keep it concise, professional, and easy to understand. Use the tone of a SOC analyst writing an internal triage note for another analyst or incident responder.
Use plain text only. Do not use markdown formatting such as **bold**, bullet markdown, or code formatting.
Use this exact structure:

Disposition: <benign, suspicious, or likely malicious>
Assessment: <final risk>
Confidence: <confidence level>
Priority: <response priority>

Key Findings:
- <finding 1>
- <finding 2>
- <finding 3>

Analysis:
<2-4 sentence analyst explanation>

Confidence Caveat:
<one short sentence explaining what most limits confidence, or write "None." if confidence is strong and well-supported>

Recommended Action:
<final recommendation>

Do not invent facts. Only use the provided data.
Do not overstate certainty. If the indicators are mixed, cloud-hosted, or only partially corroborated, say so plainly.

IP: {ip}
Country: {country}
ISP: {isp}
Hostname: {hostname}
RDAP Network Name: {rdap_info["network_name"]}
RDAP Handle: {rdap_info["handle"]}
RDAP Country: {rdap_info["country"]}
VT Malicious: {vt_info["malicious"]}
VT Suspicious: {vt_info["suspicious"]}
VT Harmless: {vt_info["harmless"]}
VT Undetected: {vt_info["undetected"]}
VT Reputation: {vt_info["reputation"]}
VT ASN: {vt_info["asn"]}
VT AS Owner: {vt_info["as_owner"]}
VT Network: {vt_info["network"]}
VT RIR: {vt_info["rir"]}
Abuse Score: {abuse_score}
Risk Points: {risk_points}
Disposition: {disposition}
Final Risk: {clean_risk}
Confidence Level: {clean_confidence}
Confidence Points: {confidence_points}
Response Priority: {clean_priority}
Reasons: {", ".join(reasons)}
Confidence Reasons: {", ".join(confidence_reasons)}
History Summary: {history_summary}
Verdict: {verdict}
Recommended Action: {recommendation}
"""
            
        response = client.responses.create(model="gpt-5", input=prompt)

        return response.output_text.strip()
    
    except Exception as e:
        return f"AI summary unavailable: {e}"


    

#Creating log file results
def log_result(timestamp, ip, country, isp, hostname, rdap_info, vt_info, abuse_score, risk_points, risk_level, confidence_level, confidence_points, response_priority, reasons, confidence_reasons, history_summary, verdict, recommendation, ai_summary):
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(f"[{risk_level}] {timestamp}\n")
        file.write(f"IP: {ip}\n")
        file.write(f"Country: {country}\n")
        file.write(f"ISP: {isp}\n")
        file.write(f"Hostname: {hostname}\n")
        file.write(f"RDAP Network Name: {rdap_info['network_name']}\n")
        file.write(f"RDAP Handle: {rdap_info['handle']}\n")
        file.write(f"RDAP Country: {rdap_info['country']}\n")
        file.write(f"VT Malicious Detections: {vt_info['malicious']}\n")
        file.write(f"VT Suspicious Detections: {vt_info['suspicious']}\n")
        file.write(f"VT Harmless Detections: {vt_info['harmless']}\n")
        file.write(f"VT Undetected: {vt_info['undetected']}\n")
        file.write(f"VT Reputation: {vt_info['reputation']}\n")
        file.write(f"VT ASN: {vt_info['asn']}\n")
        file.write(f"VT AS Owner: {vt_info['as_owner']}\n")
        file.write(f"VT Network: {vt_info['network']}\n")
        file.write(f"VT RIR: {vt_info['rir']}\n")
        file.write(f"Abuse Score: {abuse_score}\n")
        file.write(f"Risk Points: {risk_points}\n")
        file.write(f"Confidence Level: {confidence_level}\n")
        file.write(f"Confidence Points: {confidence_points}\n")
        file.write(f"Response Priority: {response_priority}\n")

        file.write(f"Reasons:\n")
        for reason in reasons:
            file.write(f"- {reason}\n")
        
        file.write(f"Confidence Reasons:\n")
        for reason in confidence_reasons:
            file.write(f"- {reason}\n")
        
        file.write("Memory Summary:\n")
        file.write(f"{history_summary}\n")

        file.write(f"Verdict: {verdict}\n")
        file.write(f"Recommended Action: {recommendation}\n")
        file.write("AI Analyst Summary:\n")
        file.write(f"{ai_summary}\n")
        file.write(f"-----------------------------------------\n")

def export_to_json(data, filename="reports.json"):
    try:
        file_path = os.path.join(base_folder, filename)

        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                existing_data = json.load(file)
        else:
            existing_data = []

        existing_data.append(data)

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(existing_data, file, indent=4)
        
    except Exception as e:
        print(f"[Agent] Failed to export JSON: {e}")

#Checking if the IP appears multiple times in log file
def check_repeat_offender(ip):
    if not os.path.exists(log_file):
        return 0
        
    count = 0

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip() == f"IP: {ip}":
                count += 1
    
    return count


#Get historical entries for a specific IP from the log
def get_ip_history(ip):
    if not os.path.exists(log_file):
        return []
    
    history = []
    current_entry = []

    with open(log_file, "r", encoding = "utf-8") as file:
        for line in file:
            stripped_line = line.strip()

            if stripped_line.startswith("[") and current_entry:
                entry_text = "\n".join(current_entry)
                if f"IP: {ip}" in entry_text:
                    history.append(entry_text)
                current_entry = []
            
            current_entry.append(stripped_line)

        if current_entry:
            entry_text = "\n".join(current_entry)
            if f"IP: {ip}" in entry_text:
                history.append(entry_text)

    return history

def summarize_ip_history(history):
    if not history:
        return "No prior history found for this IP."
    
    high_count = 0
    medium_count = 0
    low_count = 0

    for entry in history:
        if "[HIGH" in entry:
            high_count += 1
        elif "[MEDIUM" in entry:
            medium_count += 1
        elif "[LOW" in entry:
            low_count += 1

    summary_parts = [f"This IP has {len(history)} prior logged observations."]

    if high_count > 0:
        summary_parts.append(f"{high_count} prior HIGH-risk result(s)")
    if medium_count > 0:
        summary_parts.append(f"{medium_count} prior MEDIUM-risk result(s)")
    if low_count > 0:
        summary_parts.append(f"{low_count} prior LOW-risk result(s)")

    return "History Summary: " + ", ".join(summary_parts)

#Batch Reader
def load_ips_from_file(file_name):
    file_path = os.path.join(base_folder, file_name)

    if not os.path.exists(file_path):
        print("File not found ❌")
        return []
    
    ips = []

    with open(file_path, "r", encoding="utf-8")as file:
        for line in file:
            ip = line.strip()
            if ip:
                ips.append(ip)
    
    return ips


#Analyze IP Batch File
def analyze_ip_batch(file_name):
    ips = load_ips_from_file(file_name)

    if not ips:
        print("No IPs to analyze ❌")
        return
    
    summary_stats = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }
    
    print(f"\nLoaded {len(ips)} IP(s) from {file_name}\n")

    for ip in ips:
        risk_level = analyze_ip(ip)

        if risk_level:
            clean_risk = risk_level.split()[0]

            if clean_risk in summary_stats:
                summary_stats[clean_risk] += 1
    
    print("\n=== BATCH SUMMARY ===")
    print(f"Low Risk: {summary_stats['LOW']}")
    print(f"Medium Risk: {summary_stats['MEDIUM']}")
    print(f"High Risk: {summary_stats['HIGH']}")

#IP Analyzer
def analyze_ip(ip):
    try:
        print("\n[Agent] Gathering geolocation data...")
        geo_data = get_ip_info(ip)

        print("[Agent] Checking AbuseIPDB...")
        abuse_data = get_abuse_info(ip)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if geo_data["status"] == "success" and "data" in abuse_data:
            country = geo_data["country"]
            isp = geo_data["isp"]

            print("[Agent] Resolving reverse DNS...")
            hostname = get_reverse_dns(ip)

            print("[Agent] Querying RDAP ownership data...")
            rdap_info = get_rdap_info(ip)

            print("[Agent] Querying VirusTotal...")
            vt_info = get_virustotal_info(ip)

            abuse_score = abuse_data["data"]["abuseConfidenceScore"]
            print("[Agent] Building final assessment...")

            risk_points, risk_level = calculate_risk(country, abuse_score, vt_info, vt_info["as_owner"], rdap_info["country"])
            reasons = get_reasons(country, abuse_score, vt_info, vt_info["as_owner"], rdap_info["country"])
            repeat_count = check_repeat_offender(ip)

            ip_history = get_ip_history(ip)
            history_summary = summarize_ip_history(ip_history)

            #Escalation based on repeat activity
            if repeat_count >= 2:
                risk_points += 2
            elif repeat_count == 1:
                risk_points += 1

            #Recalculate risk level after escalation
            if risk_points >= 7:
                risk_level = "HIGH 🚨"
            elif risk_points >= 4:
                risk_level = "MEDIUM ⚠️"
            else:
                risk_level = "LOW ✅"

            #Generate confidence first
            confidence_level, confidence_points, confidence_reasons = calculate_confidence(abuse_score, vt_info, repeat_count, hostname, risk_level, rdap_info["country"])

            #Generate verdict and reccomendation after confidence is known
            verdict = analyst_verdict(risk_level)
            recommendation = recommend_action(risk_level,confidence_level, abuse_score)
            response_priority = get_response_priority(risk_level, confidence_level)
            ai_summary = generate_ai_summary(ip, country, isp, hostname, rdap_info, vt_info, abuse_score, risk_points, risk_level, confidence_level, confidence_points, response_priority, reasons, confidence_reasons, history_summary, verdict, recommendation)


            print("\n=== THREAT INTELLIGENCE AGENT REPORT ===")
            print("Time:", timestamp)
            print("IP:", ip)
            print("Country:", country)
            print("ISP:", isp)
            print("Hostname:", hostname)
            print("RDAP Network Name:", rdap_info["network_name"])
            print("RDAP Handle:", rdap_info["handle"])
            print("RDAP Country:", rdap_info["country"])
            print("VT Malicious Detections:", vt_info["malicious"])
            print("VT Suspicious Detections:", vt_info["suspicious"])
            print("VT Harmless Detections:", vt_info["harmless"])
            print("VT Undetected:", vt_info["undetected"])
            print("VT Reputation:", vt_info["reputation"])
            print("VT ASN:", vt_info["asn"])
            print("VT AS Owner:", vt_info["as_owner"])
            print("VT Network:", vt_info["network"])
            print("VT RIR:", vt_info["rir"])
            print("Abuse Score:", abuse_score)
            print("Risk Points:", risk_points)
            print("Final Risk:", risk_level)
            print("Confidence Level:", confidence_level)
            print("Confidence Points:", confidence_points)
            print("Response Priority:", response_priority)

            print("\nReasons:")
            for reason in reasons:
                print("-", reason)
            
            print("\nConfidence Reasons:")
            for reason in confidence_reasons:
                print("-", reason)

            print("\n🧠 Memory Summary:")
            print(history_summary)

            print("\n🧑‍💻 Analyst Verdict:")
            print(verdict)
            
            print("\n📌 Recommended Action:")
            print(recommendation)

            print("\n🤖 AI Analyst Summary:")
            print("-----------------------------------")
            print(ai_summary)
            print("-----------------------------------")

            if repeat_count > 0:
                print(f"\n🔁 REPEAT OFFENDER ALERT: This IP has appeared {repeat_count} time(s) before.")
            else:
                print(f"\n🆕 First time this IP has been seen in the log.")

            if repeat_count >= 2:
                print("⚠️ Escalation Applied: Repeat activity increased risk points.")

            log_result(timestamp, ip, country, isp, hostname, rdap_info, vt_info, abuse_score, risk_points, risk_level, confidence_level, confidence_points, response_priority, reasons, confidence_reasons, history_summary, verdict, recommendation, ai_summary)

            export_to_json({
                "timestamp": timestamp,
                "ip": ip,
                "country": country,
                "isp": isp,
                "hostname": hostname,
                "rdap_network_name": rdap_info["network_name"],
                "rdap_handle": rdap_info["handle"],
                "rdap_country": rdap_info["country"],
                "vt_malicious": vt_info["malicious"],
                "vt_suspicious": vt_info["suspicious"],
                "vt_harmless": vt_info["harmless"],
                "vt_undetected": vt_info["undetected"],
                "vt_reputation": vt_info["reputation"],
                "vt_asn": vt_info["asn"],
                "vt_as_owner": vt_info["as_owner"],
                "vt_network": vt_info["network"],
                "vt_rir": vt_info["rir"],
                "abuse_score": abuse_score,
                "risk_points": risk_points,
                "risk_level": risk_level,
                "confidence_level": confidence_level,
                "confidence_points": confidence_points,
                "response_priority": response_priority,
                "reasons": reasons,
                "confidence_reasons": confidence_reasons,
                "history_summary": history_summary,
                "verdict": verdict,
                "recommendation": recommendation,
                "ai_summary": ai_summary
            })

            return risk_level

        else:
            print(f"\nIP: {ip}")
            print("Invalid data ❌")
            return None

    except requests.exceptions.RequestException:
        print(f"\nIP: {ip}")
        print("Network Error ❌")
        return None


#Command Center
def main():
    while True:
        print("\n--- Threat Intel Agent Menu ---")
        print("1. Analyze a single IP")
        print("2. Analyze IPs from a file")
        print("3. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            ip = input("\nEnter IP: ").strip()

            if ip:
                analyze_ip(ip)
            else:
                print("Invalid input ❌")
            
        elif choice == "2":
            file_name = input("\nEnter file name (example: ips.txt): ").strip()

            if file_name:
                analyze_ip_batch(file_name)
            else:
                print("Invalid file name ❌")
        
        elif choice == "3":
            print("Goodbye! 👋")
            break

        else:
            print("Invalid menu choice ❌")


main()