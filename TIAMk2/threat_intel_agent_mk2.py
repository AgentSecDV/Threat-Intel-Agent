import requests
import os
from datetime import datetime, timezone
import socket
import json
from dotenv import load_dotenv
from openai import OpenAI   
from urllib.parse import urlparse
import dns.resolver

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
history_file = os.path.join(base_folder, "ioc_history.json")


#Detecting what is being analyzed
def detect_ioc_type(ioc):
    ioc = ioc.strip()

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    
    if len(ioc) in [32, 40, 64] and all(char in "0123456789abcdefABCDEF" for char in ioc):
        return "hash"
    
    try:
        socket.inet_aton(ioc)
        return "ip"
    except:
        pass
    
    if "." in ioc and " " not in ioc:
        return "domain"
    
    return "unknown"

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


#Domain to IP resolver
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None
    

#Extract Domain from URL
def extract_domain_from_url(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        #Handle cases like http://example.com:8080
        domain = domain.split(":")[0]

        return domain
    except:
        return None
    

#Normalize Domain
def normalize_domain(domain):
    domain = domain.strip().lower()

    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        domain = parsed.netloc

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]
    
    return domain


#DNS Enrichment for Domains
def get_domain_dns_info(domain):
    dns_info = {
        "a_records": [],
        "mx_records": [],
        "ns_records": []
    }

    try:
        hostname, aliases, addresses = socket.gethostbyname_ex(domain)
        dns_info["a_records"] = addresses
    except:
        pass
    
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        dns_info["mx_records"] = [str(record.exchange).rstrip(".") for record in mx_answers]
    except:
        pass
    
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        dns_info["ns_records"] = [str(record).rstrip(".") for record in ns_answers]
    except:
        pass
    
    return dns_info


#Parse RDAP Date Safely
def parse_rdap_date(date_string):
    if not date_string:
        return None
    
    try:
        clean_date = date_string.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_date)
    except:
        return None
    

#Domain RDAP Lookup
def get_domain_rdap_info(domain):
    url = f"https://rdap.org/domain/{domain}"

    rdap_info = {
        "domain": domain,
        "registration_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "days_until_expiration": None,
        "statuses": [],
        "nameservers": [],
        "rdap_available": False
    }

    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return rdap_info
        
        data = response.json()
        rdap_info["rdap_available"] = True
        rdap_info["statuses"] = data.get("status", [])

        nameservers = data.get("nameservers", [])
        rdap_info["nameservers"] = [ns.get("ldhName", "Unknown") for ns in nameservers]

        events = data.get("events", [])

        for event in events:
            action = event.get("eventAction", "").lower()
            event_date = event.get("eventDate")

            if action in ["registration", "registered"]:
                rdap_info["registration_date"] = event_date
            
            elif action in ["expiration", "expires"]:
                rdap_info["expiration_date"] = event_date
        
        now = datetime.now(timezone.utc)

        registration_datetime = parse_rdap_date(rdap_info["registration_date"])
        expiration_datetime = parse_rdap_date(rdap_info["expiration_date"])

        if registration_datetime:
            rdap_info["domain_age_days"] = (now - registration_datetime).days

        if expiration_datetime:
            rdap_info["days_until_expiration"] = (expiration_datetime - now).days
            
        return rdap_info
        
    except:
        return rdap_info
    

#Advanced Domain Intelligence Scoring
def analyze_domain_intel(domain):
    domain = normalize_domain(domain)

    domain_risk_points = 0
    domain_reasons = []

    dns_info = get_domain_dns_info(domain)
    rdap_info = get_domain_rdap_info(domain)

    suspicious_tlds = [".xyz", ".top", ".club", ".click", ".zip", ".country", ".lol", ".ru", ".cn"]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            domain_risk_points += 2
            domain_reasons.append(f"Domain uses a suspicious or commonly abused TLD: {tld}")

    if "-" in domain:
        domain_risk_points += 1
        domain_reasons.append("Domain contains a hyphen, which can appear in impersonation or phishing domains.")

    if len(domain) > 30:
        domain_risk_points += 1
        domain_reasons.append("Domain name is unusually long.")

    if not dns_info["a_records"]:
        domain_risk_points += 2
        domain_reasons.append("Domain has no A records, meaning it did not resolve to an IPv4 address during DNS enrichment.")
    
    if not dns_info["mx_records"]:
        domain_risk_points += 1
        domain_reasons.append("Domain has no MX records, which may be suspicious depending on the use case.")

    if not dns_info["ns_records"]:
        domain_risk_points += 2
        domain_reasons.append("Domain has no NS records, which weakens trust in the domain infrastructure.")

    if not rdap_info["rdap_available"]:
        domain_risk_points += 1
        domain_reasons.append("Domain RDAP information was unavailable.")

    else:
        domain_age_days = rdap_info["domain_age_days"]
        days_until_expiration = rdap_info["days_until_expiration"]

        if domain_age_days is not None:
            if domain_age_days <= 30:
                domain_risk_points += 4
                domain_reasons.append("Domain is very new, which is a strong phishing and abuse indicator.")
            elif domain_age_days <= 90:
                domain_risk_points += 2
                domain_reasons.append("Domain is relatively new, which adds risk.")
            elif domain_age_days <= 365:
                domain_risk_points += 1
                domain_reasons.append("Domain is less than one year old.")

        if days_until_expiration is not None and days_until_expiration <= 30:
            domain_risk_points += 1
            domain_reasons.append("Domain is close to expiration, which can sometimes appear in disposable infrastructure.")  

        risk_statuses = ["clienthold", "serverhold", "pendingdelete", "redemptionperiod"]

        for status in rdap_info["statuses"]:
            clean_status = status.lower().replace(" ", "")

            if clean_status in risk_statuses:
                domain_risk_points += 2
                domain_reasons.append(f"Domain has risky RDAP status: {status}")

    domain_intel = {
        "domain": domain,
        "dns": dns_info,
        "rdap": rdap_info,
        "domain_risk_points": domain_risk_points,
        "domain_reasons": domain_reasons
    }

    return domain_risk_points, domain_reasons, domain_intel


#Analyze URL
def analyze_url_patterns(url, domain):
    url_risk_points = 0
    url_reasons = []

    lower_url = url.lower()
    lower_domain = domain.lower()

    suspicious_keywords = ["login", "verify", "secure", "account", "password", "update", "banking", "wallet"]

    for keyword in suspicious_keywords:
        if keyword in lower_url:
            url_risk_points += 1
            url_reasons.append(f"URL contains suspicious keyword: {keyword}")
    
    if lower_url.startswith("http://"):
        url_risk_points += 1
        url_reasons.append("URL uses HTTP instead of HTTPS.")
    
    if lower_domain.count("-") >= 2:
        url_risk_points += 1
        url_reasons.append("Domain contains multiple hyphens, which can appear in phishing-style domains.")

    suspicious_tlds = [".xyz", ".top", ".club", ".click", ".zip", ".country"]

    for tld in suspicious_tlds:
        if lower_domain.endswith(tld):
            url_risk_points += 2
            url_reasons.append(f"Domain uses suspicious top-level domain: {tld}")
    
    try:
        socket.inet_aton(lower_domain)
        url_risk_points += 2
        url_reasons.append("URL uses a raw IP address instead of a domain name.")
    except:
        pass
    
    return url_risk_points, url_reasons


#URL Fallback Risk Level
def classify_url_risk(url_risk_points):
    if url_risk_points >= 6:
        return "HIGH 🚨"
    elif url_risk_points >= 3:
        return "MEDIUM ⚠️"
    else:
        return "LOW ✅"


#Url Fallback Recommendation
def recommend_url_action(url_risk_level):
    if "HIGH" in url_risk_level:
        return "Do not visit this URL. Treat as likely phishing or malicious. Block or report if observed in environment."
    elif "MEDIUM" in url_risk_level:
        return "Use caution. Review the URL manually and avoid entering credentials or sensitive information."
    else:
        return "No immediate action required based on URL structure alone, but continue normal caution."
    

def calculate_url_confidence(url_risk_points, url_reasons, domain_resolved):
    confidence_points = 0
    confidence_reasons = []

    if url_risk_points >= 6:
        confidence_points += 3
        confidence_reasons.append("Multiple URL structure indicators strongly support a suspicious assessment.")
    elif url_risk_points >= 3:
        confidence_points += 2
        confidence_reasons.append("Several URL structure indicators support a suspicious assessment.")
    elif url_risk_points > 0:
        confidence_points += 1
        confidence_reasons.append("One or more URL structure indicators were observed.")
    else:
        confidence_reasons.append("No suspicious URL structure indicators were observed.")

    if not domain_resolved:
        confidence_points += 1
        confidence_reasons.append("Domain did not resolve, which can occur with inactive or short-lived phishing infrastructure.")

    if len(url_reasons) >= 4:
        confidence_points += 1
        confidence_reasons.append("Multiple independent URL pattern warnings were detected.")
    
    if confidence_points >= 5:
        confidence_level = "HIGH 🟢"
    elif confidence_points >= 3:
        confidence_level = "MEDIUM 🟡"
    else:
        confidence_level = "LOW 🔴"
    
    return confidence_level, confidence_points, confidence_reasons
    

def print_url_fallback_reports(url, domain, url_risk_points, url_reasons, domain_intel=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    url_risk_level = classify_url_risk(url_risk_points)
    recommendation = recommend_url_action(url_risk_level)

    url_confidence_level, url_confidence_points, url_confidence_reasons = calculate_url_confidence(
    url_risk_points,
    url_reasons,
    domain_resolved=False
    )

    print("\n=== URL THREAT ASSESSMENT ===")
    print("Time:", timestamp)
    print("Original URL:", url)
    print("Extracted Domain:", domain)
    print("Analyzed IP: N/A - domain did not resolve")
    print("URL Risk Points:", url_risk_points)
    print("URL Risk Level:", url_risk_level)
    print("URL Confidence Level:", url_confidence_level)
    print("URL Confidence Points:", url_confidence_points)
    if domain_intel:
        print("\n🌐 Domain Intelligence:")
        print("Domain:", domain_intel["domain"])
        print("Domain Risk Points:", domain_intel["domain_risk_points"])
        print("A Records:", ", ".join(domain_intel["dns"]["a_records"]) or "None")
        print("MX Records:", ", ".join(domain_intel["dns"]["mx_records"]) or "None")
        print("NS Records:", ", ".join(domain_intel["dns"]["ns_records"]) or "None")
        print("Domain Age Days:", domain_intel["rdap"]["domain_age_days"])
        print("Days Until Expiration:", domain_intel["rdap"]["days_until_expiration"])
        print("RDAP Available:", domain_intel["rdap"]["rdap_available"])

    print("\nReasons:")
    if url_reasons:
        for reason in url_reasons:
            print("-", reason)
    else:
        print("- No obvious suspicious URL patterns detected.")

    print("\nConfidence Reasons:")
    for reason in url_confidence_reasons:
        print("-", reason)
    
    print("\nRecommended Action:")
    print(recommendation)
    print("-----------------------------------")

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
    
def generate_ai_summary(ip, country, isp, hostname, rdap_info, vt_info, abuse_score, risk_points, risk_level, confidence_level, confidence_points, response_priority, reasons, confidence_reasons, history_summary, trend_summary, trend_insight, verdict, recommendation):

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
Trend Summary: {trend_summary}
Trend-Based Insight: {trend_insight}
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

#Loading history database
def load_history():
    if not os.path.exists(history_file):
        return {}
    
    try:
        with open(history_file, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return {}
    
#Save history database
def save_history(history_data):
    try:
        with open(history_file, "w", encoding="utf-8") as file:
            json.dump(history_data, file, indent=4)
    except Exception as e:
        print(f"[Agent] Failed to save history database: {e}")

def update_ioc_history(ioc, risk_level, confidence_level, verdict, response_priority):
    history_data = load_history()

    clean_risk = risk_level.split()[0]
    clean_confidence = confidence_level.split()[0]
    clean_priority = response_priority.split()[0]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ioc not in history_data:
        history_data[ioc] = {
            "first_seen": timestamp,
            "last_seen": timestamp,
            "times_seen": 1,
            "highest_risk": clean_risk,
            "last_risk": clean_risk,
            "last_confidence": clean_confidence,
            "last_priority": clean_priority,
            "last_verdict": verdict,
            "risk_history": [clean_risk]
        }
    else:
        entry = history_data[ioc]
        entry["last_seen"] = timestamp
        entry["times_seen"] += 1
        entry["last_risk"] = clean_risk
        entry["last_confidence"] = clean_confidence
        entry["last_priority"] = clean_priority
        entry["last_verdict"] = verdict
        entry["risk_history"].append(clean_risk)

        risk_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        if risk_rank.get(clean_risk, 0) > risk_rank.get(entry["highest_risk"], 0):
            entry["highest_risk"] = clean_risk
    
    save_history(history_data)
    return history_data[ioc]

#Trend Analysis of IOC
def get_trend_direction(risk_history):
    if len(risk_history) < 2:
        return "No clear trend yet."
    
    risk_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    previous = risk_rank.get(risk_history[-2], 0)
    current = risk_rank.get(risk_history[-1], 0)

    if current > previous:
        return "Risk is increasing over time."
    elif current < previous:
        return "Risk is decreasing over time."
    else:
        return "Risk is stable based on recent observations."
    
#Historical risk scoring helper
def get_history_risk_bonus(ioc_record, trend_summary):
    bonus_points = 0
    history_reasons = []

    times_seen = ioc_record.get("times_seen", 0)
    highest_risk = ioc_record.get("highest_risk", "LOW")
    risk_history = ioc_record.get("risk_history", [])

    if times_seen >= 3:
        bonus_points += 2
        history_reasons.append("IOC has been observed repeatedly over time.")
    elif times_seen == 2:
        bonus_points += 1
        history_reasons.append("IOC has been seen more than once.")

    if highest_risk == "HIGH":
        bonus_points += 2
        history_reasons.append("IOC previously reached HIGH risk.")
    elif highest_risk == "MEDIUM":
        bonus_points += 1
        history_reasons.append("IOC has previously reached MEDIUM risk.")
    
    if trend_summary == "Risk is increasing over time.":
        bonus_points += 2
        history_reasons.append("Historical trend shows risk is increasing.")
    elif trend_summary == "Risk is stable based on recent observations." and len(risk_history) >= 2 and risk_history[-1] in ["MEDIUM", "HIGH"]:
        bonus_points += 1
        history_reasons.append("Risk has remained consistently elevated across recent observations.")
    
    return bonus_points, history_reasons

#Trend Insight
def get_trend_insight(ioc_record, trend_summary):
    times_seen = ioc_record.get("times_seen", 0)
    highest_risk = ioc_record.get("highest_risk", "LOW")
    last_risk = ioc_record.get("last_risk", "LOW")

    if times_seen < 2:
        return "No trend-based insight available yet because this IOC has limited history."
    
    if trend_summary == "Risk is increasing over time.":
        return "Risk has increased compared to the previous observation, which may indicate worsening behavior or stronger supporting intelligence."
    
    if trend_summary == "Risk is decreasing over time.":
        return "Risk has decreased compared to the previous observation, suggesting the current evidence is less severe than prior activity."
    
    if trend_summary == "Risk is stable based on recent observations.":
        if last_risk == "HIGH":
            return "Risk has remained consistently HIGH, supporting continued escalation and close investigation."
        elif last_risk == "MEDIUM":
            return "Risk has remained consistently MEDIUM, supporting continued monitoring and analyst review."
        else:
            return "Risk has remained consistently LOW, supporting normal monitoring unless new evidence appears."

    if highest_risk == "HIGH":
        return "This IOC has reached HIGH risk in prior history, so future activity should be reviewed carefully."

    return "Historical context does not currently change the assessment."    

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
def analyze_ip(ip, original_ioc=None, url_risk_points=0, url_reasons=None, domain_risk_points=0, domain_reasons=None, domain_intel=None):
    if url_reasons is None:
        url_reasons = []

    if domain_reasons is None:
        domain_reasons = []

    try:
        print("\n[Agent] Gathering geolocation data...")
        geo_data = get_ip_info(ip)

        print("[Agent] Checking AbuseIPDB...")
        abuse_data = get_abuse_info(ip)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if geo_data["status"] == "success" and "data" in abuse_data:
            country = geo_data["country"]
            isp = geo_data["isp"]

            print("[Agent] Resolving Reverse DNS...")
            hostname = get_reverse_dns(ip)

            print("[Agent] Querying RDAP ownership data...")
            rdap_info = get_rdap_info(ip)

            print("[Agent] Querying VirusTotal...")
            vt_info = get_virustotal_info(ip)

            abuse_score = abuse_data["data"]["abuseConfidenceScore"]
            print("[Agent] Building final assessment...")

            risk_points, risk_level = calculate_risk(country, abuse_score, vt_info, vt_info["as_owner"], rdap_info["country"])
            reasons = get_reasons(country, abuse_score, vt_info, vt_info["as_owner"], rdap_info["country"])

            if url_risk_points > 0:
                risk_points += url_risk_points
                reasons.extend(url_reasons)

            if domain_risk_points > 0:
                risk_points += domain_risk_points
                reasons.extend(domain_reasons)

            existing_history = load_history()
            existing_record = existing_history.get(ip, {
                "times_seen": 0,
                "highest_risk": "LOW",
                "risk_history": []
            })

            repeat_count = existing_record.get("times_seen", 0)

            preview_risk_history = existing_record.get("risk_history", []) + [risk_level.split()[0]]
            preview_trend = get_trend_direction(preview_risk_history)

            preview_record = {
                "times_seen": existing_record.get("times_seen", 0) + 1,
                "highest_risk": existing_record.get("highest_risk", "LOW"),
                "risk_history": preview_risk_history
            }

            risk_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
            if risk_rank.get(risk_level.split()[0], 0) > risk_rank.get(preview_record["highest_risk"], 0):
                preview_record["highest_risk"] = risk_level.split()[0]

            history_bonus, history_reasons = get_history_risk_bonus(preview_record, preview_trend)
            risk_points += history_bonus
            reasons.extend(history_reasons)

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

            ioc_record = update_ioc_history(ip, risk_level, confidence_level, verdict, response_priority)
            trend_summary = get_trend_direction(ioc_record["risk_history"])
            trend_insight = get_trend_insight(ioc_record, trend_summary)

            history_summary = (
                f"First Seen: {ioc_record['first_seen']}\n"
                f"Last Seen: {ioc_record['last_seen']}\n"
                f"Times Seen: {ioc_record['times_seen']}\n"
                f"Highest Risk Ever: {ioc_record['highest_risk']}"
            )

            ai_summary = generate_ai_summary(ip, country, isp, hostname, rdap_info, vt_info, abuse_score, risk_points, risk_level, confidence_level, confidence_points, response_priority, reasons, confidence_reasons, history_summary, trend_summary, trend_insight, verdict, recommendation)


            print("\n=== THREAT INTELLIGENCE AGENT REPORT ===")
            print("Time:", timestamp)
            print("IP:", ip)

            if original_ioc:
                print("Original IOC:", original_ioc)
            
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

            if domain_intel:
                print("\n🌐 Domain Intelligence:")
                print("Domain:", domain_intel["domain"])
                print("Domain Risk Points:", domain_intel["domain_risk_points"])
                print("A Records:", ", ".join(domain_intel["dns"]["a_records"]) or "None")
                print("MX Records:", ", ".join(domain_intel["dns"]["mx_records"]) or "None")
                print("NS Records:", ", ".join(domain_intel["dns"]["ns_records"]) or "None")
                print("Domain Age Days:", domain_intel["rdap"]["domain_age_days"])
                print("Days Until Expiration:", domain_intel["rdap"]["days_until_expiration"])
                print("RDAP Available:", domain_intel["rdap"]["rdap_available"])

            print("\nReasons:")
            for reason in reasons:
                print("-", reason)
            
            print("\nConfidence Reasons:")
            for reason in confidence_reasons:
                print("-", reason)

            print("\n🧠 Memory Summary:")
            print(history_summary)
            print(f"Trend: {trend_summary}")
            print(f"Trend-Based Insight: {trend_insight}")

            print("\n🧑‍💻 Analyst Verdict:")
            print(verdict)
            
            print("\n📌 Recommended Action:")
            print(recommendation)

            print("\n🤖 AI Analyst Summary:")
            print("-----------------------------------")
            print(ai_summary)
            print("-----------------------------------")

            if ioc_record["times_seen"] > 1:
                print(f"\n🔁 REPEAT IOC ALERT: This IOC has appeared {ioc_record['times_seen']} time(s) before in structured memory.")
            else:
                print(f"\n🆕 First time this IOC has been seen in structured memory.")

            if history_bonus > 0:
                print("⚠️ History-Based Escalation Applied: Structured memory increased risk points.")

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
                "ai_summary": ai_summary,
                "domain_intel": domain_intel
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
        print("1. Analyze a single IOC")
        print("2. Analyze IOCs from a file")
        print("3. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            ioc = input("\nEnter IOC (IP, Domain, URL, Hash): ").strip()

            if ioc:
                ioc_type = detect_ioc_type(ioc)
                print(f"[Agent] Detected IOC Type: {ioc_type.upper()}")

                if ioc_type == "ip":
                    analyze_ip(ioc, original_ioc=ioc)
                
                elif ioc_type == "domain":
                    print("[Agent] Running domain intelligence...")
                    domain_risk_points, domain_reasons, domain_intel = analyze_domain_intel(ioc)

                    print("[Agent] Resolving domain...")
                    resolved_ip = resolve_domain(ioc)

                    if resolved_ip:
                        print(f"[Agent] Domain resolved to IP: {resolved_ip}")
                        analyze_ip(resolved_ip, original_ioc=ioc,
                                   domain_risk_points=domain_risk_points,
                                   domain_reasons=domain_reasons,
                                   domain_intel=domain_intel)
                    else:
                        print("Failed to resolve domain ❌")
                        print_url_fallback_reports(ioc,ioc,domain_risk_points, domain_reasons, domain_intel)
                
                elif ioc_type == "url":
                    print("[Agent] Extracting domain from URL...")
                    domain = extract_domain_from_url(ioc)

                    if domain:
                        print(f"[Agent] Extracted domain: {domain}")

                        url_risk_points, url_reasons = analyze_url_patterns(ioc, domain)
                        domain_risk_points, domain_reasons, domain_intel = analyze_domain_intel(domain)

                        if url_reasons:
                            print("[Agent] URL pattern warnings detected:")
                            for reason in url_reasons:
                                print(f"- {reason}")
                        else:
                            print("[Agent] No obvious suspicious URL patterns detected.")

                        print ("[Agent] Resolving domain...")
                        resolved_ip = resolve_domain(domain)

                        if resolved_ip:
                            print(f"[Agent] Domain resolved to IP: {resolved_ip}")
                            analyze_ip(resolved_ip, original_ioc=ioc, url_risk_points=url_risk_points, url_reasons=url_reasons,
                                       domain_risk_points=domain_risk_points, domain_reasons=domain_reasons,
                                       domain_intel=domain_intel)
                        else:
                            print("Failed to resolve domain ❌")
                            print_url_fallback_reports(ioc, domain, url_risk_points, url_reasons, domain_intel)
                    else:
                        print("Failed to extract domain from URL ❌")
                else:
                    print(f"{ioc_type.upper()} analysis is coming in Phase 2. For now, only IP analysis is active.")
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