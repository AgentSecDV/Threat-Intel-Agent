import requests
import os
from datetime import datetime, timezone
import socket
import json
from dotenv import load_dotenv
from openai import OpenAI   
from urllib.parse import urlparse
import dns.resolver
import re

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

#MALWAREBAZAAR API KEY
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")
if not MALWAREBAZAAR_API_KEY:
    raise ValueError("Missing MalwareBazaar API key. Set the MALWAREBAZAAR_API_KEY environment variable.")

#URLHAUS API KEY
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
if not URLHAUS_API_KEY:
    raise ValueError("Missing URLhaus API key. Set the URLHAUS_API_KEY environment variable.")

if not OPENAI_API_KEY:
    raise ValueError("Missing OpenAI API key. Set the OPENAI_API_KEY environment variable.")

client = OpenAI(api_key = OPENAI_API_KEY)


base_folder = os.path.dirname(__file__)
log_file = os.path.join(base_folder, "Threat_Intel.txt")
history_file = os.path.join(base_folder, "ioc_history.json")


#Detecting what is being analyzed
def detect_ioc_type(ioc):
    ioc = ioc.strip()

    if re.fullmatch(r"CVE-\d{4}-\d{4,}", ioc.upper()):
        return "cve"

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


#Apply URLhaus Risk Influence
def apply_urlhaus_risk(url_risk_points, url_reasons, urlhaus_info):
    if urlhaus_info and urlhaus_info.get("found"):
        url_risk_points += 5
        url_reasons.append("URLhaus has a matching malicious URL record for this URL.")

        if urlhaus_info.get("url_status") == "online":
            url_risk_points += 2
            url_reasons.append("URLhaus reports this URL as currently online.")

        if urlhaus_info.get("threat") not in [None, "Unknown"]:
            url_risk_points += 1
            url_reasons.append(f"URLhaus classifies the threat as: {urlhaus_info.get('threat')}.")

    return url_risk_points, url_reasons


#Apply URLhaus Confidence Influence
def apply_urlhaus_confidence(confidence_points, confidence_reasons, urlhaus_info):
    if urlhaus_info and urlhaus_info.get("found"):
        confidence_points += 2
        confidence_reasons.append("URLhaus also has a matching URL record, increasing confidence in the URL assessment.")

    return confidence_points, confidence_reasons

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
    

def calculate_url_confidence(url_risk_points, url_reasons, domain_resolved, urlhaus_info=None):
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
    
    confidence_points, confidence_reasons = apply_urlhaus_confidence(confidence_points, confidence_reasons, urlhaus_info)

    if confidence_points >= 5:
        confidence_level = "HIGH 🟢"
    elif confidence_points >= 3:
        confidence_level = "MEDIUM 🟡"
    else:
        confidence_level = "LOW 🔴"
    
    return confidence_level, confidence_points, confidence_reasons
    

def print_url_fallback_reports(url, domain, url_risk_points, url_reasons, domain_intel=None, urlhaus_info=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if urlhaus_info is None:
        urlhaus_info = get_urlhaus_url_info(url)

        url_risk_points, url_reasons = apply_urlhaus_risk( 
            url_risk_points,
            url_reasons,
            urlhaus_info
        )

    url_risk_level = classify_url_risk(url_risk_points)
    recommendation = recommend_url_action(url_risk_level)

    mitre_mappings = map_mitre_attack_context("url", url_risk_level, url_reasons, urlhaus_info=urlhaus_info)

    url_confidence_level, url_confidence_points, url_confidence_reasons = calculate_url_confidence(
        url_risk_points,
        url_reasons,
        domain_resolved=False,
        urlhaus_info=urlhaus_info
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
    print("URLhaus Found:", urlhaus_info["found"])
    print("URLhaus Status:", urlhaus_info["query_status"])
    print("URLhaus HTTP Status:", urlhaus_info["http_status"])
    print("URLhaus Error:", urlhaus_info["error"])
    print("URLhaus URL Status:", urlhaus_info["url_status"])
    print("URLhaus Threat:", urlhaus_info["threat"])
    print("URLhaus Tags:", ", ".join(urlhaus_info["tags"]) if urlhaus_info["tags"] else "None")
    print("URLhaus Reporter:", urlhaus_info["reporter"])
    print("URLhaus Date Added:", urlhaus_info["date_added"])
    print("URLhaus Reference:", urlhaus_info["urlhaus_reference"])
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

    print_mitre_context(mitre_mappings)
    
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
    

#Spamhaus ZEN Return Code Mapper
def map_spamhaus_return_code(return_code):
    code_map = {
        "127.0.0.2": "SBL - Spamhaus Blocklist listing",
        "127.0.0.3": "SBL - Spamhaus Blocklist listing",
        "127.0.0.4": "XBL - Exploits Blocklist listing",
        "127.0.0.9": "SBL CSS - CSS listing",
        "127.0.0.10": "PBL - Policy Blocklist listing",
        "127.0.0.11": "PBL - Policy Blocklist listing"
    }

    if return_code.startswith("127.255.255."):
        return "Spamhaus DNSBL query error code"

    return code_map.get(return_code, "Unknown Spamhaus return code")


#Spamhaus ZEN IP Lookup
def get_spamhaus_zen_info(ip):
    reversed_ip = ".".join(reversed(ip.split(".")))
    query_domain = f"{reversed_ip}.zen.spamhaus.org"

    default_result = {
        "listed": False,
        "query_status": "unknown",
        "query": query_domain,
        "return_codes": [],
        "listed_lists": [],
        "error": "None"
    }

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        answers = resolver.resolve(query_domain, "A")

        return_codes = [answer.to_text() for answer in answers]
        listed_lists = [map_spamhaus_return_code(code) for code in return_codes]

        error_codes = [
            code for code in return_codes
            if code.startswith("127.255.255.")
        ]

        if error_codes:
            default_result["query_status"] = "query_error"
            default_result["return_codes"] = return_codes
            default_result["listed_lists"] = listed_lists
            default_result["error"] = "Spamhaus returned a DNSBL query error code."
            return default_result

        return {
            "listed": True,
            "query_status": "listed",
            "query": query_domain,
            "return_codes": return_codes,
            "listed_lists": listed_lists,
            "error": "None"
        }

    except dns.resolver.NXDOMAIN:
        default_result["query_status"] = "not_listed"
        return default_result

    except dns.resolver.NoAnswer:
        default_result["query_status"] = "not_listed"
        return default_result

    except dns.resolver.Timeout:
        default_result["query_status"] = "timeout"
        default_result["error"] = "Spamhaus DNS lookup timed out."
        return default_result

    except Exception as e:
        default_result["query_status"] = "lookup_error"
        default_result["error"] = str(e)
        return default_result


#Spamhaus Risk Influence
def calculate_spamhaus_risk(spamhaus_info):
    risk_points = 0
    reasons = []

    if spamhaus_info.get("listed"):
        risk_points += 4
        reasons.append("Spamhaus ZEN lists this IP, indicating poor IP reputation or abuse history.")

        listed_lists = spamhaus_info.get("listed_lists", [])

        for listed_item in listed_lists:
            if "SBL" in listed_item:
                risk_points += 2
                reasons.append("Spamhaus SBL/CSS listing suggests the IP may be tied to spam, malicious hosting, or abusive infrastructure.")
                break

        for listed_item in listed_lists:
            if "XBL" in listed_item:
                risk_points += 2
                reasons.append("Spamhaus XBL listing suggests the IP may be associated with exploited hosts, malware, or botnet activity.")
                break

        for listed_item in listed_lists:
            if "PBL" in listed_item:
                risk_points += 1
                reasons.append("Spamhaus PBL listing indicates the IP may be in a policy-listed range, often unsuitable for direct email sending.")
                break

    elif spamhaus_info.get("query_status") == "not_listed":
        reasons.append("Spamhaus ZEN does not list this IP.")

    elif spamhaus_info.get("query_status") in ["timeout", "lookup_error", "query_error"]:
        reasons.append("Spamhaus ZEN lookup was inconclusive due to a lookup issue.")

    return risk_points, reasons


#Spamhaus Confidence Influence
def apply_spamhaus_confidence(confidence_points, confidence_reasons, spamhaus_info, risk_level):
    if spamhaus_info.get("listed"):
        confidence_points += 2
        confidence_reasons.append("Spamhaus ZEN also lists this IP, increasing confidence in the risk assessment.")

    elif spamhaus_info.get("query_status") == "not_listed":
        if "LOW" in risk_level:
            confidence_points += 1
            confidence_reasons.append("Spamhaus ZEN does not list this IP, adding support to the low-risk assessment.")
        else:
            confidence_reasons.append("Spamhaus ZEN does not list this IP, which slightly limits support for a higher-risk assessment.")

    else:
        confidence_reasons.append("Spamhaus ZEN did not return a usable reputation result.")

    confidence_points = max(confidence_points, 0)

    if confidence_points >= 5:
        confidence_level = "HIGH 🟢"
    elif confidence_points >= 3:
        confidence_level = "MEDIUM 🟡"
    else:
        confidence_level = "LOW 🔴"

    return confidence_level, confidence_points, confidence_reasons


#OSINT Correlation for IP Reputation
def correlate_ip_osint_sources(abuse_score, vt_info, spamhaus_info):
    correlation_points = 0
    correlation_reasons = []
    confidence_bonus = 0
    confidence_reasons = []

    vt_malicious = vt_info.get("malicious", 0)
    vt_suspicious = vt_info.get("suspicious", 0)
    spamhaus_listed = spamhaus_info.get("listed", False)
    spamhaus_status = spamhaus_info.get("query_status", "unknown")

    abuse_high = abuse_score >= 40
    abuse_clean = abuse_score == 0
    vt_bad = vt_malicious > 0 or vt_suspicious > 0
    vt_clean = vt_malicious == 0 and vt_suspicious == 0
    spamhaus_clean = spamhaus_status == "not_listed"

    if abuse_high and vt_bad and spamhaus_listed:
        correlation_points += 4
        confidence_bonus += 3
        correlation_reasons.append("Multiple independent reputation sources agree this IP is suspicious or malicious.")
        confidence_reasons.append("AbuseIPDB, VirusTotal, and Spamhaus all support the elevated-risk assessment.")

    elif abuse_high and vt_bad:
        correlation_points += 2
        confidence_bonus += 2
        correlation_reasons.append("AbuseIPDB and VirusTotal both show concerning activity for this IP.")
        confidence_reasons.append("Two independent sources support the elevated-risk assessment.")

    elif abuse_high and spamhaus_listed:
        correlation_points += 2
        confidence_bonus += 2
        correlation_reasons.append("AbuseIPDB and Spamhaus both show negative reputation signals for this IP.")
        confidence_reasons.append("Two independent sources support the elevated-risk assessment.")

    elif vt_bad and spamhaus_listed:
        correlation_points += 2
        confidence_bonus += 2
        correlation_reasons.append("VirusTotal and Spamhaus both show negative reputation signals for this IP.")
        confidence_reasons.append("Two independent sources support the elevated-risk assessment.")

    elif abuse_clean and vt_clean and spamhaus_clean:
        confidence_bonus += 2
        correlation_reasons.append("AbuseIPDB, VirusTotal, and Spamhaus all show clean or non-listed results for this IP.")
        confidence_reasons.append("Multiple independent reputation sources support the low-risk assessment.")

    elif vt_bad and abuse_clean and spamhaus_clean:
        confidence_bonus -= 1
        correlation_reasons.append("VirusTotal shows concerning activity, but AbuseIPDB and Spamhaus do not corroborate it.")
        confidence_reasons.append("Source disagreement limits confidence in the assessment.")

    elif abuse_high and vt_clean and spamhaus_clean:
        confidence_bonus -= 1
        correlation_reasons.append("AbuseIPDB shows abuse activity, but VirusTotal and Spamhaus do not corroborate it.")
        confidence_reasons.append("Source disagreement limits confidence in the assessment.")

    elif spamhaus_listed and abuse_clean and vt_clean:
        confidence_bonus -= 1
        correlation_reasons.append("Spamhaus lists this IP, but AbuseIPDB and VirusTotal do not corroborate malicious activity.")
        confidence_reasons.append("Source disagreement limits confidence in the assessment.")

    return correlation_points, correlation_reasons, confidence_bonus, confidence_reasons


#MITRE ATT&CK Context Mapper
def map_mitre_attack_context(ioc_type, risk_level, reasons, urlhaus_info=None, malwarebazaar_info=None, kev_info=None, spamhaus_info=None):
    mitre_mappings = []

    clean_reasons = " ".join(reasons).lower()

    def add_mapping(tactic, technique_id, technique_name, rationale):
        mapping = {
            "tactic": tactic,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "rationale": rationale
        }

        if mapping not in mitre_mappings:
            mitre_mappings.append(mapping)

    if ioc_type == "cve" and kev_info and kev_info.get("found"):
        add_mapping(
            "Initial Access",
            "T1190",
            "Exploit Public-Facing Application",
            "CISA KEV lists this CVE as known exploited, which may align with exploitation of vulnerable public-facing applications."
        )

    if urlhaus_info and urlhaus_info.get("found"):
        add_mapping(
            "Initial Access",
            "T1566.002",
            "Spearphishing Link",
            "URLhaus found a matching malicious URL record, which may align with phishing links used for initial access."
        )

        add_mapping(
            "Command and Control",
            "T1105",
            "Ingress Tool Transfer",
            "A malicious URL may be used to retrieve malware, payloads, scripts, or tools into an environment."
        )

    if malwarebazaar_info and malwarebazaar_info.get("found"):
        add_mapping(
            "Execution",
            "T1204",
            "User Execution",
            "A known malware sample may require or follow user execution depending on delivery method and environment."
        )

        add_mapping(
            "Command and Control",
            "T1105",
            "Ingress Tool Transfer",
            "A malware sample may be associated with downloaded payloads, tooling, or staged files."
        )

    if spamhaus_info and spamhaus_info.get("listed"):
        add_mapping(
            "Command and Control",
            "T1071",
            "Application Layer Protocol",
            "Spamhaus listing may indicate abusive network infrastructure that could support command-and-control or spam-related activity."
        )

    if "url contains suspicious keyword" in clean_reasons or "login" in clean_reasons or "verify" in clean_reasons:
        add_mapping(
            "Initial Access",
            "T1566.002",
            "Spearphishing Link",
            "Suspicious URL structure and credential-themed keywords may align with phishing-link activity."
        )

    if "url uses http instead of https" in clean_reasons:
        add_mapping(
            "Command and Control",
            "T1071",
            "Application Layer Protocol",
            "Use of web protocols in suspicious URL activity may align with application-layer communication."
        )

    if "virusTotal shows malicious detections".lower() in clean_reasons or "virustotal shows multiple malicious detections" in clean_reasons:
        add_mapping(
            "Execution",
            "T1204",
            "User Execution",
            "Malicious file or indicator detections may align with execution activity depending on delivery and user interaction."
        )

    if "HIGH" not in risk_level and not mitre_mappings:
        add_mapping(
            "Context",
            "N/A",
            "No strong ATT&CK mapping",
            "Current evidence does not strongly support a specific MITRE ATT&CK technique mapping."
        )

    return mitre_mappings


#Print MITRE ATT&CK Context
def print_mitre_context(mitre_mappings):
    print("\n🎯 MITRE ATT&CK Context:")
    
    if not mitre_mappings:
        print("- No MITRE ATT&CK context generated.")
        return

    for mapping in mitre_mappings:
        print(f"- {mapping['tactic']} | {mapping['technique_id']} | {mapping['technique_name']}")
        print(f"  Rationale: {mapping['rationale']}")


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
    

#VirusTotal Hash/File Lookup
def get_virustotal_hash_info(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

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
            "file_type": attributes.get("type_description", "Unknown"),
            "file_size": attributes.get("size", "Unknown"),
            "meaningful_name": attributes.get("meaningful_name", "Unknown")
        }
    
    except:
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reputation": 0,
            "file_type": "Unknown",
            "file_size": "Unknown",
            "meaningful_name": "Unknown"
        }
    

#MalwareBazaar Hash Lookup
def get_malwarebazaar_hash_info(file_hash):
    url = "https://mb-api.abuse.ch/api/v1/"

    data = {
        "query": "get_info",
        "hash": file_hash
    }

    headers = {
        "Auth-Key": MALWAREBAZAAR_API_KEY
    }

    default_result = {
        "found": False,
        "query_status": "unknown",
        "http_status": "Unknown",
        "error": "None",
        "response_preview": "None",
        "signature": "Unknown",
        "tags": [],
        "file_type": "Unknown",
        "first_seen": "Unknown",
        "last_seen": "Unknown",
        "reporter": "Unknown",
        "delivery_method": "Unknown"
    }

    try:
        response = requests.post(url, data=data, headers=headers, timeout=15)

        default_result["http_status"] = response.status_code
        default_result["response_preview"] = response.text[:300]

        if response.status_code != 200:
            default_result["query_status"] = "http_error"
            default_result["error"] = f"MalwareBazaar returned HTTP status {response.status_code}"
            return default_result

        try:
            result = response.json()
        except Exception as json_error:
            default_result["query_status"] = "json_error"
            default_result["error"] = f"Failed to parse MalwareBazaar JSON response: {json_error}"
            return default_result

        query_status = result.get("query_status")

        if not query_status:
            default_result["query_status"] = "missing_query_status"
            default_result["error"] = "MalwareBazaar response did not include query_status."
            return default_result

        if query_status != "ok":
            default_result["query_status"] = query_status
            return default_result

        sample_data = result.get("data", [])

        if not sample_data:
            default_result["query_status"] = "ok_no_data"
            default_result["error"] = "MalwareBazaar returned ok but no sample data."
            return default_result

        sample = sample_data[0]

        return {
            "found": True,
            "query_status": query_status,
            "http_status": response.status_code,
            "error": "None",
            "response_preview": response.text[:300],
            "signature": sample.get("signature", "Unknown"),
            "tags": sample.get("tags", []),
            "file_type": sample.get("file_type", "Unknown"),
            "first_seen": sample.get("first_seen", "Unknown"),
            "last_seen": sample.get("last_seen", "Unknown"),
            "reporter": sample.get("reporter", "Unknown"),
            "delivery_method": sample.get("delivery_method", "Unknown")
        }

    except requests.exceptions.RequestException as request_error:
        default_result["query_status"] = "request_error"
        default_result["error"] = str(request_error)
        return default_result

    except Exception as unexpected_error:
        default_result["query_status"] = "unexpected_error"
        default_result["error"] = str(unexpected_error)
        return default_result
    

#URLhaus URL Lookup
def get_urlhaus_url_info(url_to_check):
    url = "https://urlhaus-api.abuse.ch/v1/url/"

    data = {
        "url": url_to_check
    }

    headers = {
        "Auth-Key": URLHAUS_API_KEY
    }

    default_result = {
        "found": False,
        "query_status": "unknown",
        "http_status": "Unknown",
        "error": "None",
        "response_preview": "None",
        "url_status": "Unknown",
        "threat": "Unknown",
        "tags": [],
        "reporter": "Unknown",
        "date_added": "Unknown",
        "urlhaus_reference": "Unknown"
    }

    try:
        response = requests.post(url, data=data, headers=headers, timeout=15)

        default_result["http_status"] = response.status_code
        default_result["response_preview"] = response.text[:300]

        if response.status_code != 200:
            default_result["query_status"] = "http_error"
            default_result["error"] = f"URLhaus returned HTTP status {response.status_code}"
            return default_result

        try:
            result = response.json()
        except Exception as json_error:
            default_result["query_status"] = "json_error"
            default_result["error"] = f"Failed to parse URLhaus JSON response: {json_error}"
            return default_result

        query_status = result.get("query_status")

        if not query_status:
            default_result["query_status"] = "missing_query_status"
            default_result["error"] = "URLhaus response did not include query_status."
            return default_result

        if query_status != "ok":
            default_result["query_status"] = query_status
            return default_result

        return {
            "found": True,
            "query_status": query_status,
            "http_status": response.status_code,
            "error": "None",
            "response_preview": response.text[:300],
            "url_status": result.get("url_status", "Unknown"),
            "threat": result.get("threat", "Unknown"),
            "tags": result.get("tags", []),
            "reporter": result.get("reporter", "Unknown"),
            "date_added": result.get("date_added", "Unknown"),
            "urlhaus_reference": result.get("urlhaus_reference", "Unknown")
        }

    except requests.exceptions.RequestException as request_error:
        default_result["query_status"] = "request_error"
        default_result["error"] = str(request_error)
        return default_result

    except Exception as unexpected_error:
        default_result["query_status"] = "unexpected_error"
        default_result["error"] = str(unexpected_error)
        return default_result
    

#CISA KEV CVE Lookup
def get_cisa_kev_info(cve_id):
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    normalized_cve = cve_id.strip().upper()

    default_result = {
        "found": False,
        "query_status": "unknown",
        "http_status": "Unknown",
        "error": "None",
        "response_preview": "None",
        "cve_id": normalized_cve,
        "vendor_project": "Unknown",
        "product": "Unknown",
        "vulnerability_name": "Unknown",
        "date_added": "Unknown",
        "short_description": "Unknown",
        "required_action": "Unknown",
        "due_date": "Unknown",
        "known_ransomware_campaign_use": "Unknown",
        "notes": "Unknown"
    }

    try:
        response = requests.get(kev_url, timeout=20)

        default_result["http_status"] = response.status_code
        default_result["response_preview"] = response.text[:300]

        if response.status_code != 200:
            default_result["query_status"] = "http_error"
            default_result["error"] = f"CISA KEV returned HTTP status {response.status_code}"
            return default_result

        try:
            kev_data = response.json()
        except Exception as json_error:
            default_result["query_status"] = "json_error"
            default_result["error"] = f"Failed to parse CISA KEV JSON response: {json_error}"
            return default_result

        vulnerabilities = kev_data.get("vulnerabilities", [])

        if not vulnerabilities:
            default_result["query_status"] = "empty_catalog"
            default_result["error"] = "CISA KEV catalog returned no vulnerabilities."
            return default_result

        for item in vulnerabilities:
            if item.get("cveID", "").upper() == normalized_cve:
                return {
                    "found": True,
                    "query_status": "ok",
                    "http_status": response.status_code,
                    "error": "None",
                    "response_preview": response.text[:300],
                    "cve_id": normalized_cve,
                    "vendor_project": item.get("vendorProject", "Unknown"),
                    "product": item.get("product", "Unknown"),
                    "vulnerability_name": item.get("vulnerabilityName", "Unknown"),
                    "date_added": item.get("dateAdded", "Unknown"),
                    "short_description": item.get("shortDescription", "Unknown"),
                    "required_action": item.get("requiredAction", "Unknown"),
                    "due_date": item.get("dueDate", "Unknown"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": item.get("notes", "Unknown")
                }

        default_result["query_status"] = "not_found"
        return default_result

    except requests.exceptions.RequestException as request_error:
        default_result["query_status"] = "request_error"
        default_result["error"] = str(request_error)
        return default_result

    except Exception as unexpected_error:
        default_result["query_status"] = "unexpected_error"
        default_result["error"] = str(unexpected_error)
        return default_result
    

#CISA KEV Risk Calculator
def calculate_kev_risk(kev_info):
    risk_points = 0
    reasons = []

    if kev_info.get("found"):
        risk_points += 8
        reasons.append("CISA KEV lists this CVE as known to be exploited in the wild.")

        if kev_info.get("known_ransomware_campaign_use") == "Known":
            risk_points += 2
            reasons.append("CISA KEV notes known ransomware campaign use for this CVE.")

    else:
        reasons.append("CISA KEV does not list this CVE as a known exploited vulnerability.") 

    
    if risk_points >= 8:
        risk_level = "HIGH 🚨"
    elif risk_points >= 4:
        risk_level = "MEDIUM ⚠️"
    else:
        risk_level = "LOW ✅"

    return risk_points, risk_level, reasons


#CISA KEV Confidence Calculator
def calculate_kev_confidence(kev_info, risk_level):
    confidence_points = 0
    confidence_reasons = []

    if kev_info.get("query_status") == "ok":
        confidence_points += 3
        confidence_reasons.append("CISA KEV returned a matching catalog entry for this CVE.")
    elif kev_info.get("query_status") == "not_found":
        confidence_points += 3
        confidence_reasons.append("CISA KEV was checked successfully and did not list this CVE.")
    elif kev_info.get("http_status") == 200:
        confidence_points += 1
        confidence_reasons.append("CISA KEV catalog was reachable, but the result was limited.")
    else:
        confidence_reasons.append("CISA KEV lookup had an error or incomplete response.")

    if "HIGH" in risk_level and kev_info.get("found"):
        confidence_points += 2
        confidence_reasons.append("Known exploitation evidence strongly supports the high-risk assessment.")

    if confidence_points >= 5:
        confidence_level = "HIGH 🟢"
    elif confidence_points >= 3:
        confidence_level = "MEDIUM 🟡"
    else:
        confidence_level = "LOW 🔴"

    return confidence_level, confidence_points, confidence_reasons


#CISA KEV Recommended Action
def recommend_kev_action(kev_info, risk_level):
    if kev_info.get("found"):
        return "Prioritize remediation. Review affected assets, patch or apply vendor guidance, and verify whether this CVE exists in your environment."
    elif "LOW" in risk_level:
        return "CISA KEV does not list this CVE as known exploited. Continue normal vulnerability triage using CVSS, asset exposure, and business impact."
    else:
        return "Review this CVE manually and gather additional vulnerability intelligence."
    

#CVE / CISA KEV Analyzer
def analyze_cve(cve_id):
    try:
        normalized_cve = cve_id.strip().upper()

        print("\n[Agent] Querying CISA KEV catalog...")
        kev_info = get_cisa_kev_info(normalized_cve)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        risk_points, risk_level, reasons = calculate_kev_risk(kev_info)
        confidence_level, confidence_points, confidence_reasons = calculate_kev_confidence(kev_info, risk_level)
        recommendation = recommend_kev_action(kev_info, risk_level)
        response_priority = get_response_priority(risk_level, confidence_level)

        mitre_mappings = map_mitre_attack_context("cve", risk_level, reasons, kev_info=kev_info)

        print("\n=== CISA KEV CVE REPORT ===")
        print("Time:", timestamp)
        print("CVE:", normalized_cve)
        print("CISA KEV Found:", kev_info["found"])
        print("CISA KEV Status:", kev_info["query_status"])
        print("CISA KEV HTTP Status:", kev_info["http_status"])
        print("CISA KEV Error:", kev_info["error"])
        print("Vendor/Project:", kev_info["vendor_project"])
        print("Product:", kev_info["product"])
        print("Vulnerability Name:", kev_info["vulnerability_name"])
        print("Date Added:", kev_info["date_added"])
        print("Due Date:", kev_info["due_date"])
        print("Known Ransomware Campaign Use:", kev_info["known_ransomware_campaign_use"])
        print("Required Action:", kev_info["required_action"])
        print("Short Description:", kev_info["short_description"])
        print("Notes:", kev_info["notes"])
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

        print_mitre_context(mitre_mappings)

        print("\n📌 Recommended Action:")
        print(recommendation)
        print("-----------------------------------")

        export_to_json({
            "timestamp": timestamp,
            "ioc_type": "cve",
            "cve": normalized_cve,
            "cisa_kev_found": kev_info["found"],
            "cisa_kev_status": kev_info["query_status"],
            "cisa_kev_http_status": kev_info["http_status"],
            "cisa_kev_error": kev_info["error"],
            "vendor_project": kev_info["vendor_project"],
            "product": kev_info["product"],
            "vulnerability_name": kev_info["vulnerability_name"],
            "date_added": kev_info["date_added"],
            "due_date": kev_info["due_date"],
            "known_ransomware_campaign_use": kev_info["known_ransomware_campaign_use"],
            "required_action": kev_info["required_action"],
            "short_description": kev_info["short_description"],
            "notes": kev_info["notes"],
            "risk_points": risk_points,
            "risk_level": risk_level,
            "confidence_level": confidence_level,
            "confidence_points": confidence_points,
            "response_priority": response_priority,
            "reasons": reasons,
            "confidence_reasons": confidence_reasons,
            "mitre_mappings": mitre_mappings,
            "recommendation": recommendation
        })

        return risk_level

    except Exception as e:
        print(f"[Agent] CVE analysis failed: {e}")
        return None


#Hash Risk Calculator
def calculate_hash_risk(hash_info, malwarebazaar_info=None):
    risk_points = 0
    reasons = []

    if hash_info["malicious"] >= 5:
        risk_points += 7
        reasons.append("VirusTotal shows multiple malicious detections for this hash.")
    elif hash_info["malicious"] > 0:
        risk_points += 5
        reasons.append("VirusTotal shows malicious detections for this hash.")
    elif hash_info["suspicious"] > 0:
        risk_points += 3
        reasons.append("VirusTotal shows suspicious detections for this hash.")
    else:
        reasons.append("VirusTotal shows no malicious or suspicious detections for this hash.")

    if hash_info["reputation"] < 0:
        risk_points += 1
        reasons.append("VirusTotal reputation score is negative.")

    if malwarebazaar_info and malwarebazaar_info.get("found"):
        risk_points += 4
        reasons.append("MalwareBazaar has a matching malware sample for this hash.")

        if malwarebazaar_info.get("signature") not in [None, "Unknown"]:
            risk_points += 1
            reasons.append(f"MalwareBazaar identifies this sample as: {malwarebazaar_info.get('signature')}.")

    if risk_points >= 7:
        risk_level = "HIGH 🚨"
    elif risk_points >= 3:
        risk_level = "MEDIUM ⚠️"
    else:
        risk_level = "LOW ✅"
    
    return risk_points, risk_level, reasons


#Hash Confidence Calculator
def calculate_hash_confidence(hash_info, risk_level, malwarebazaar_info=None):
    confidence_points = 0
    confidence_reasons = []

    total_detections = (
        hash_info["malicious"]
        + hash_info["suspicious"]
        + hash_info["harmless"]
        + hash_info["undetected"]
    )

    if total_detections == 0:
        confidence_reasons.append("VirusTotal returned no detection stats, which limits confidence.")
    else:
        confidence_points += 1
        confidence_reasons.append("VirusTotal returned detection stats for this hash.")

    if "HIGH" in risk_level:
        if hash_info["malicious"] >= 5:
            confidence_points += 4
            confidence_reasons.append("Multiple malicious detections strongly support the high-risk assessment.")
        elif hash_info["malicious"] > 0:
            confidence_points += 3
            confidence_reasons.append("Malicious detections support the high-risk assessment.")
    
    elif "MEDIUM" in risk_level:
        if hash_info["suspicious"] > 0:
            confidence_points += 2
            confidence_reasons.append("Suspicious detections support the medium-risk assessment.")
        elif hash_info["malicious"] > 0:
            confidence_points += 2
            confidence_reasons.append("Limited malicious detections support further review.")

    else:
        if hash_info["malicious"] == 0 and hash_info["suspicious"] == 0 and total_detections > 0:
            confidence_points += 3
            confidence_reasons.append("No malicious or suspicious detections were found across available results.")

    
    if hash_info["file_type"] != "Unknown":
        confidence_points += 1
        confidence_reasons.append("File type metadata was available, adding context to the assessment.")
    
    if malwarebazaar_info and malwarebazaar_info.get("found"):
        confidence_points += 2
        confidence_reasons.append("MalwareBazaar also has a matching sample, increasing confidence in the assessment.")

    if confidence_points >= 5:
        confidence_level = "HIGH 🟢"
    elif confidence_points >= 3:
        confidence_level = "MEDIUM 🟡"
    else:
        confidence_level = "LOW 🔴"

    return confidence_level, confidence_points, confidence_reasons


#Hash Recommended Action
def recommend_hash_action(risk_level, confidence_level):
    if "HIGH" in risk_level:
        if "HIGH" in confidence_level:
            return "Treat this file hash as malicious. Block or quarantine the related file and investigate affected systems."
        elif "MEDIUM" in confidence_level:
            return "Strongly investigate this file hash and avoid execution until confirmed safe."
        else:
            return "Treat this hash as suspicious and gather more evidence before taking final action."
    
    elif "MEDIUM" in risk_level:
        return "Review this hash manually, check related file behavior, and avoid trusting the file until validated."
    
    else:
        if "HIGH" in confidence_level:
            return "No immediate action needed based on available VirusTotal results."
        else:
            return "No immediate action needed, but confidence is limited. Recheck if more intelligence becomes available."

    
#Hash Analyzer
def analyze_hash(file_hash):
    try:
        print("\n[Agent] Querying VirusTotal for hash...")
        hash_info = get_virustotal_hash_info(file_hash)

        print("[Agent] Querying MalwareBazaar for hash...")
        malwarebazaar_info = get_malwarebazaar_hash_info(file_hash)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        risk_points, risk_level, reasons = calculate_hash_risk(hash_info, malwarebazaar_info)
        confidence_level, confidence_points, confidence_reasons = calculate_hash_confidence(hash_info, risk_level, malwarebazaar_info)
        recommendation = recommend_hash_action(risk_level, confidence_level)
        response_priority = get_response_priority(risk_level, confidence_level)

        mitre_mappings = map_mitre_attack_context("hash", risk_level, reasons, malwarebazaar_info=malwarebazaar_info)

        print("\n=== HASH INTELLIGENCE REPORT ===")
        print("Time:", timestamp)
        print("Hash:", file_hash)
        print("File Name:", hash_info["meaningful_name"])
        print("File Type:", hash_info["file_type"])
        print("File Size:", hash_info["file_size"])
        print("VT Malicious Detections:", hash_info["malicious"])
        print("VT Suspicious Detections:", hash_info["suspicious"])
        print("VT Harmless Detections:", hash_info["harmless"])
        print("VT Undetected:", hash_info["undetected"])
        print("VT Reputation:", hash_info["reputation"])
        print("MalwareBazaar Found:", malwarebazaar_info["found"])
        print("MalwareBazaar Status:", malwarebazaar_info["query_status"])
        print("MalwareBazaar HTTP Status:", malwarebazaar_info["http_status"])
        print("MalwareBazaar Error:", malwarebazaar_info["error"])
        print("MalwareBazaar Signature:", malwarebazaar_info["signature"])
        print("MalwareBazaar Tags:", ", ".join(malwarebazaar_info["tags"]) if malwarebazaar_info["tags"] else "None")
        print("MalwareBazaar File Type:", malwarebazaar_info["file_type"])
        print("MalwareBazaar First Seen:", malwarebazaar_info["first_seen"])
        print("MalwareBazaar Last Seen:", malwarebazaar_info["last_seen"])
        print("MalwareBazaar Reporter:", malwarebazaar_info["reporter"])
        print("MalwareBazaar Delivery Method:", malwarebazaar_info["delivery_method"])
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

        print_mitre_context(mitre_mappings)

        print("\n📌 Recommended Action:")
        print(recommendation)
        print("-----------------------------------")

        export_to_json({
            "timestamp": timestamp,
            "ioc_type": "hash",
            "hash": file_hash,
            "file_name": hash_info["meaningful_name"],
            "file_type": hash_info["file_type"],
            "file_size": hash_info["file_size"],
            "vt_malicious": hash_info["malicious"],
            "vt_suspicious": hash_info["suspicious"],
            "vt_harmless": hash_info["harmless"],
            "vt_undetected": hash_info["undetected"],
            "vt_reputation": hash_info["reputation"],
            "malwarebazaar_found": malwarebazaar_info["found"],
            "malwarebazaar_status": malwarebazaar_info["query_status"],
            "malwarebazaar_http_status": malwarebazaar_info["http_status"],
            "malwarebazaar_error": malwarebazaar_info["error"],
            "malwarebazaar_response_preview": malwarebazaar_info["response_preview"],
            "malwarebazaar_signature": malwarebazaar_info["signature"],
            "malwarebazaar_tags": malwarebazaar_info["tags"],
            "malwarebazaar_file_type": malwarebazaar_info["file_type"],
            "malwarebazaar_first_seen": malwarebazaar_info["first_seen"],
            "malwarebazaar_last_seen": malwarebazaar_info["last_seen"],
            "malwarebazaar_reporter": malwarebazaar_info["reporter"],
            "malwarebazaar_delivery_method": malwarebazaar_info["delivery_method"],
            "risk_points": risk_points,
            "risk_level": risk_level,
            "confidence_level": confidence_level,
            "confidence_points": confidence_points,
            "response_priority": response_priority,
            "reasons": reasons,
            "confidence_reasons": confidence_reasons,
            "mitre_mappings": mitre_mappings,
            "recommendation": recommendation
        })

        return risk_level
    
    except Exception as e:
        print(f"[Agent] Hash analysis failed: {e}")
        return None


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

            print("[Agent] Checking Spamhaus ZEN...")
            spamhaus_info = get_spamhaus_zen_info(ip)

            abuse_score = abuse_data["data"]["abuseConfidenceScore"]
            print("[Agent] Building final assessment...")

            risk_points, risk_level = calculate_risk(country, abuse_score, vt_info, vt_info["as_owner"], rdap_info["country"])
            reasons = get_reasons(country, abuse_score, vt_info, vt_info["as_owner"], rdap_info["country"])

            spamhaus_risk_points, spamhaus_reasons = calculate_spamhaus_risk(spamhaus_info)
            risk_points += spamhaus_risk_points
            reasons.extend(spamhaus_reasons)

            correlation_points, correlation_reasons, correlation_confidence_bonus, correlation_confidence_reasons = correlate_ip_osint_sources(
            abuse_score, vt_info, spamhaus_info)

            risk_points += correlation_points
            reasons.extend(correlation_reasons)

            if url_risk_points > 0:
                risk_points += url_risk_points
                reasons.extend(url_reasons)

            if domain_risk_points > 0:
                risk_points += domain_risk_points
                reasons.extend(domain_reasons)

            if risk_points >= 7:
                risk_level = "HIGH 🚨"
            elif risk_points >= 4:
                risk_level = "MEDIUM ⚠️"
            else:
                risk_level = "LOW ✅"

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

            confidence_level, confidence_points, confidence_reasons = apply_spamhaus_confidence(
            confidence_points, confidence_reasons, spamhaus_info, risk_level)

            confidence_points += correlation_confidence_bonus
            confidence_reasons.extend(correlation_confidence_reasons)

            confidence_points = max(confidence_points, 0)

            if confidence_points >= 5:
                confidence_level = "HIGH 🟢"
            elif confidence_points >= 3:
                confidence_level = "MEDIUM 🟡"
            else:
                confidence_level = "LOW 🔴"

            #Generate verdict and reccomendation after confidence is known
            verdict = analyst_verdict(risk_level)
            recommendation = recommend_action(risk_level,confidence_level, abuse_score)
            response_priority = get_response_priority(risk_level, confidence_level)

            mitre_mappings = map_mitre_attack_context("ip", risk_level, reasons, spamhaus_info=spamhaus_info)

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
            print("Spamhaus Listed:", spamhaus_info["listed"])
            print("Spamhaus Status:", spamhaus_info["query_status"])
            print("Spamhaus Query:", spamhaus_info["query"])
            print("Spamhaus Return Codes:", ", ".join(spamhaus_info["return_codes"]) if spamhaus_info["return_codes"] else "None")
            print("Spamhaus Lists:", ", ".join(spamhaus_info["listed_lists"]) if spamhaus_info["listed_lists"] else "None")
            print("Spamhaus Error:", spamhaus_info["error"])
            print("OSINT Correlation Risk Points:", correlation_points)
            print("OSINT Correlation Confidence Bonus:", correlation_confidence_bonus)
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

            print_mitre_context(mitre_mappings)

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
                "spamhaus_listed": spamhaus_info["listed"],
                "spamhaus_status": spamhaus_info["query_status"],
                "spamhaus_query": spamhaus_info["query"],
                "spamhaus_return_codes": spamhaus_info["return_codes"],
                "spamhaus_lists": spamhaus_info["listed_lists"],
                "spamhaus_error": spamhaus_info["error"],
                "osint_correlation_risk_points": correlation_points,
                "osint_correlation_confidence_bonus": correlation_confidence_bonus,
                "osint_correlation_reasons": correlation_reasons,
                "osint_correlation_confidence_reasons": correlation_confidence_reasons,
                "risk_points": risk_points,
                "risk_level": risk_level,
                "confidence_level": confidence_level,
                "confidence_points": confidence_points,
                "response_priority": response_priority,
                "reasons": reasons,
                "confidence_reasons": confidence_reasons,
                "history_summary": history_summary,
                "mitre_mappings": mitre_mappings,
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
            ioc = input("\nEnter IOC (IP, Domain, URL, Hash, CVE): ").strip()

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

                        print("[Agent] Querying URLhaus for URL...")
                        urlhaus_info = get_urlhaus_url_info(ioc)

                        url_risk_points, url_reasons = apply_urlhaus_risk(url_risk_points, url_reasons, urlhaus_info)

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

                            combined_url_risk_points = url_risk_points + domain_risk_points
                            combined_url_reasons = url_reasons + domain_reasons

                            print_url_fallback_reports(
                                ioc, 
                                domain,
                                combined_url_risk_points,
                                combined_url_reasons, 
                                domain_intel, 
                                urlhaus_info
                                )
                    else:
                        print("Failed to extract domain from URL ❌")

                elif ioc_type == "cve":
                    analyze_cve(ioc)

                elif ioc_type == "hash":
                    analyze_hash(ioc)

                else:
                    print(f"{ioc_type.upper()} analysis is not supported yet.")
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