import streamlit as st
import subprocess
import sys
import json
import os
import hashlib
import csv
import io

base_folder = os.path.dirname(__file__)
history_file = os.path.join(base_folder, "ioc_history.json")


#Calculate File Hashes
def calculate_file_hashes(file_bytes):
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha1_hash = hashlib.sha1(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    return {
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash
    }


#Parse Uploaded IOC List File
def parse_uploaded_ioc_file(uploaded_ioc_file):
    if uploaded_ioc_file is None:
        return []
    
    try:
        file_text = uploaded_ioc_file.getvalue().decode("utf-8", errors = "replace")
    except Exception:
        return []
    
    ioc_list = []

    for line in file_text.splitlines():
        clean_line = line.strip()

        if not clean_line:
            continue
        
        if clean_line.lower() in ["ioc", "indicator", "indicators"]:
            continue
        
        if "," in clean_line:
            parts = clean_line.split(",")

            for part in parts:
                clean_part = part.strip()

                if clean_part and clean_part.lower() not in ["ioc", "indicator", "indicators"]:
                    ioc_list.append(clean_part)

        else:
            ioc_list.append(clean_line)

    return ioc_list 


#Parsing output
def parse_output(output):
    data = {}
    
    for line in output.splitlines():
        if "Final Risk:" in line:
            data["risk"] = line.split("Final Risk:")[-1].strip()
        elif "Confidence Level:" in line:
            data["confidence"] = line.split("Confidence Level:")[-1].strip()
        elif "Response Priority:" in line:
            data["priority"] = line.split("Response Priority:")[-1].strip()
        elif "URL Risk Level" in line:
            data["risk"] = line.split("URL Risk Level:")[-1].strip()
        elif "URL Confidence Level" in line:
            data["confidence"] = line.split("URL Confidence Level:")[-1].strip()
        
    if "priority" not in data and "risk" in data:
        data["priority"] = data["risk"]

    return data


#Clean Severity Labels
def clean_severity(value):
    if not value:
        return "N/A"
    
    value = str(value).upper()

    if "CRITICAL" in value:
        return "CRITICAL"
    elif "HIGH" in value:
        return "HIGH"
    elif "MEDIUM" in value:
        return "MEDIUM"
    elif "LOW" in value:
        return "LOW"
    elif "INFO" in value:
        return "INFO"
    else:
        return "N/A"
    

#Clean Display Value
def clean_display_value(value, fallback="Not Available"):
    if value in [None, "", "Unknown", "N/A", "None"]:
        return fallback
    
    return value


#Build Batch Result Row
def build_batch_result_row(ioc, output):
    parsed = parse_output(output)
    context = parse_report_context(output)

    risk = parsed.get("risk", "N/A")
    confidence = parsed.get("confidence", "N/A")
    priority = parsed.get("priority", "N/A")

    return {
        "IOC": ioc,
        "Report Type": context.get("report_type", "Unknown"),
        "Analyzed IP": context.get("analyzed_ip", "N/A"),
        "Risk": risk,
        "Confidence": confidence,
        "Priority": priority,
        "Risk Clean": clean_severity(risk),
        "Confidence Clean": clean_severity(confidence),
        "Priority Clean": clean_severity(priority)
    }


#Build Batch Summary Metrics
def build_batch_summary(batch_results):
    summary = {
        "total": len(batch_results),
        "high": 0,
        "medium": 0,
        "low": 0,
        "critical": 0
    }

    for row in batch_results:
        risk = row.get("Risk Clean", clean_severity(row.get("Risk", "")))
        priority = row.get("Priority Clean", clean_severity(row.get("Priority", "")))

        if "HIGH" in risk:
            summary["high"] += 1
        elif "MEDIUM" in risk:
            summary["medium"] += 1
        elif "LOW" in risk:
            summary["low"] += 1

        if "CRITICAL" in priority:
            summary["critical"] += 1
        
    return summary 


#Display Batch Summary Metrics
def show_batch_summary(batch_results):
    summary = build_batch_summary(batch_results)

    st.subheader("📌 Batch Summary")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total IOCs", summary["total"])

    with col2:
        st.metric("High Risk", summary["high"])

    with col3:
        st.metric("Medium Risk", summary["medium"])

    with col4:
        st.metric("Low Risk", summary["low"])

    with col5:
        st.metric("Critical Priority", summary["critical"])


#Build Batch Export Rows
def build_batch_export_rows(batch_results):
    export_rows = []

    for row in batch_results:
        export_rows.append({
            "ioc": row.get("IOC", "N/A"),
            "report_type": row.get("Report Type", "N/A"),
            "analyzed_ip": row.get("Analyzed IP", "N/A"),
            "risk": row.get("Risk", "N/A"),
            "confidence": row.get("Confidence", "N/A"),
            "priority": row.get("Priority", "N/A"),
            "risk_clean": row.get("Risk Clean", "N/A"),
            "confidence_clean": row.get("Confidence Clean", "N/A"),
            "priority_clean": row.get("Priority Clean", "N/A")
        })

    return export_rows


#Convert Batch Results To CSV
def convert_batch_results_to_csv(batch_results):
    export_rows = build_batch_export_rows(batch_results)

    if not export_rows:
        return ""
    
    output = io.StringIO()
    output.write("\ufeff")

    fieldnames = [
        "ioc",
        "report_type",
        "analyzed_ip",
        "risk",
        "confidence",
        "priority",
        "risk_clean",
        "confidence_clean",
        "priority_clean"
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(export_rows)

    return output.getvalue()


#Convert Batch Results to JSON
def convert_batch_results_to_json(batch_results):
    export_rows = build_batch_export_rows(batch_results)
    return json.dumps(export_rows, indent=4, ensure_ascii=False)

#Parsing Report Context
def parse_report_context(output):
    context = {
        "report_type": "Unknown",
        "original_ioc": "N/A",
        "analyzed_ip": "N/A"
    }

    for line in output.splitlines():
        clean_line = line.strip()

        if "=== URL THREAT ASSESSMENT ===" in clean_line:
            context["report_type"] = "URL Fallback Analysis"

        elif "=== HASH INTELLIGENCE REPORT ===" in clean_line:
            context["report_type"] = "Hash Analysis"

        elif "=== CISA KEV CVE REPORT ===" in clean_line:
            context["report_type"] = "CISA KEV CVE Report"

        elif "=== THREAT INTELLIGENCE AGENT REPORT ===" in clean_line:
            context["report_type"] = "IOC Enrichment Analysis"

        elif clean_line.startswith("Original IOC:"):
            context["original_ioc"] = clean_line.split("Original IOC:")[-1].strip()
        
        elif clean_line.startswith("Original URL:"):
            context["original_ioc"] = clean_line.split("Original URL:")[-1].strip()
        
        elif clean_line.startswith("IP:"):
            context["analyzed_ip"] = clean_line.split("IP:")[-1].strip()
        
        elif clean_line.startswith("Hash:"):
            hash_value = clean_line.split("Hash:")[-1].strip()
            context["original_ioc"] = hash_value
            context["analyzed_ip"] = "N/A - Hash Analysis"

        elif clean_line.startswith("CVE:"):
            cve_value = clean_line.split("CVE:")[-1].strip()
            context["original_ioc"] = cve_value
            context["analyzed_ip"] = "N/A - CVE Analysis"
        
    if context["report_type"] == "IOC Enrichment Analysis":
        if context["original_ioc"] == context["analyzed_ip"]:
            context["report_type"] = "IP Analysis"
        elif context["original_ioc"] != "N/A" and context["analyzed_ip"] != "N/A":
            context["report_type"] = "Resolved IOC Analysis"

    return context


#Display Report Context
def show_report_context(context):
    st.subheader("🧾 Report Context")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.write("**Report Type**")
        st.write(context.get("report_type", "unknown"))

    with col2:
        st.write("**Original IOC**")
        st.write(context.get("original_ioc", "N/A"))

    with col3:
        st.write("**Analyzed IP**")
        st.write(context.get("analyzed_ip", "N/A"))


#Risk Banners
def show_risk_banner(risk):
    if "HIGH" in risk:
        st.error("🚨 HIGH RISK IOC DETECTED - review immediately.")
    elif "MEDIUM" in risk:
        st.warning("⚠️ MEDIUM RISK IOC - review and monitor closely.")
    elif "LOW" in risk:
        st.success("✅ LOW RISK IOC - no immediate action required.")
    else:
        st.info("ℹ️ Risk level unavailable")


#Color Card Function
def get_card_color(value, card_type = "risk"):
    if card_type == "confidence":
        if "HIGH" in value:
            return "#052e16", "#86efac"
        elif "MEDIUM" in value:
            return "#451a03", "#fdba74"
        elif "LOW" in value:
            return "#450a0a", "#fca5a5"
        else:
            return "#1e293b", "#cbd5e1"

    if "CRITICAL" in value:
        return "#7f1d1d", "#fecaca"
    elif "HIGH" in value:
        return "#450a0a", "#fca5a5"
    elif "MEDIUM" in value:
        return "#451a03", "#fdba74"
    elif "LOW" in value:
        return "#052e16", "#86efac"
    else:
        return "#1e293b", "#cbd5e1"
    

#Metric Cards
def metric_card(title, value, card_type="risk"):
    bg_color, text_color = get_card_color(value, card_type)

    html = f"""
<div style="background-color:{bg_color}; 
    padding:22px; 
    border-radius:16px; 
    border:1px solid {text_color}; 
    box-shadow:0 4px 14px rgba(0,0,0,0.25);">
<p style="margin:0; 
    color:#e5e7eb; 
    font-size:14px; 
    font-weight:600;">{title}</p>
<h2 style="margin:8px 0 0 0; 
    color:{text_color}; 
    font-size:34px; 
    font-weight:800;">{value}</h2>
</div>
"""

    st.markdown(html, unsafe_allow_html=True)


#Extracting Analyzed IPs
def get_history_key(output):
    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("IP:"):
            return clean_line.split("IP:")[-1].strip()
    
    return None


#Loading History
def load_history_record(history_key):
    if not history_key:
        return None
    
    if not os.path.exists(history_file):
        return None
    
    try:
        with open(history_file, "r", encoding = "utf-8") as file:
            history_data = json.load(file)

        return history_data.get(history_key)
    
    except Exception:
        return None


#Loading All IOC History
def load_all_history():
    if not os.path.exists(history_file):
        return {}
    
    try:
        with open(history_file, "r", encoding = "utf-8") as file:
            return json.load(file)
        
    except Exception:
        return {}
    

#History Table
def build_history_table(history_data, limit = 10):
    rows = []

    for ioc, record in history_data.items():
        rows.append({
            "IOC": ioc,
            "Times Seen": record.get("times_seen", "N/A"),
            "Highest Risk": record.get("highest_risk", "N/A"),
            "Last Risk": record.get("last_risk", "N/A"),
            "Last Priority": record.get("last_priority", "N/A"),
            "Last Seen": record.get("last_seen", "N/A")
        })
    
    rows = sorted(
        rows,
        key = lambda row: row.get("Last Seen", ""),
        reverse = True
    )

    return rows[:limit]


#Display History Table
def show_recent_history_table(history_key = None):
    history_data = load_all_history()
    rows = build_history_table(history_data)

    if not rows:
        return
    
    st.subheader("📚 Recent IOC History")
    st.caption("Recent IOC History shows previously analyzed indicators stored in local structured memory.")

    if history_key:
        st.info(f"Current History Key: {history_key}")
    else:
        st.info("Current History Key: Not available for this report type.")

    show_high_risk_only = st.checkbox("Show only high-risk / critical IOCs")

    if show_high_risk_only:
        rows = [
            row for row in rows
            if row.get("Highest Risk") == "HIGH"
            or row.get("Last Risk") == "HIGH"
            or row.get("Last Priority") in ["HIGH", "CRITICAL"]
        ]
    
    if not rows:
        st.warning("No high-risk or critical IOCs found in recent history.")
        return


    st.dataframe(
        rows,
        width = "stretch",
        hide_index = True
    )

#History Trend
def get_dashboard_trend(history_record):
    risk_history = history_record.get("risk_history", [])

    if len(risk_history) < 2:
        return "No clear trend yet."
    
    risk_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3
    }

    previous = risk_rank.get(risk_history[-2], 0)
    current = risk_rank.get(risk_history[-1], 0)

    if current > previous:
        return "Risk is increasing over time."
    elif current < previous:
        return "Risk is decreasing over time."
    else:
        return "Risk is stable based on recent observations."


def get_recent_risk_history(history_record, limit = 5):
    risk_history = history_record.get("risk_history", [])

    if not risk_history:
        return "No risk history available."  
    
    recent_history = risk_history[-limit:]

    return " → ".join(recent_history)

#History Snapshot Display
def show_history_snapshot(history_record):
    if not history_record:
        return
    
    trend = get_dashboard_trend(history_record)
    recent_risk_history = get_recent_risk_history(history_record)

    st.subheader("🧠 History Snapshot")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Times Seen", history_record.get("times_seen", "N/A"))
    
    with col2:
        st.metric("Highest Risk", history_record.get("highest_risk", "N/A"))

    with col3:
        st.metric("Last Risk", history_record.get("last_risk", "N/A"))

    with col4:
        st.metric("Last Priority", history_record.get("last_priority", "N/A"))

    st.write(f"**First Seen:** {history_record.get('first_seen', 'N/A')}")
    st.write(f"**Last Seen:** {history_record.get('last_seen', 'N/A')}")
    st.write(f"**Last Confidence:** {history_record.get('last_confidence', 'N/A')}")
    st.write(f"**Last Verdict:** {history_record.get('last_verdict', 'N/A')}")
    st.write(f"**Trend:** {trend}")
    st.write(f"**Recent Risk History:** {recent_risk_history}")


#Removing CLI Menu Prompt
def clean_output(output):
    lines = output.splitlines()
    cleaned_lines = []

    start = False

    for line in lines:
        if ("=== THREAT INTELLIGENCE AGENT REPORT ===" in line
            or "=== URL THREAT ASSESSMENT ===" in line
            or "=== HASH INTELLIGENCE REPORT ===" in line
            or "=== CISA KEV CVE REPORT ===" in line
        ):
            start = True

        if start and "--- Threat Intel Agent Menu ---" in line:
            break

        if start:
            cleaned_lines.append(line)
    
    return "\n".join(cleaned_lines)


#Parsing Hash Intelligence
def parse_hash_intel(output):
    hash_intel = {}

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("Hash:"):
            hash_intel["hash"] = clean_line.split("Hash:")[-1].strip()

        elif clean_line.startswith("File Name:"):
            hash_intel["file_name"] = clean_line.split("File Name:")[-1].strip()

        elif clean_line.startswith("File Type:"):
            hash_intel["file_type"] = clean_line.split("File Type:")[-1].strip()

        elif clean_line.startswith("File Size:"):
            hash_intel["file_size"] = clean_line.split("File Size:")[-1].strip()

        elif clean_line.startswith("VT Malicious Detections:"):
            hash_intel["vt_malicious"] = clean_line.split("VT Malicious Detections:")[-1].strip()

        elif clean_line.startswith("VT Suspicious Detections:"):
            hash_intel["vt_suspicious"] = clean_line.split("VT Suspicious Detections:")[-1].strip()

        elif clean_line.startswith("VT Harmless Detections:"):
            hash_intel["vt_harmless"] = clean_line.split("VT Harmless Detections:")[-1].strip()

        elif clean_line.startswith("VT Undetected:"):
            hash_intel["vt_undetected"] = clean_line.split("VT Undetected:")[-1].strip()

        elif clean_line.startswith("VT Reputation:"):
            hash_intel["vt_reputation"] = clean_line.split("VT Reputation:")[-1].strip()
        
        elif clean_line.startswith("MalwareBazaar Found:"):
            hash_intel["malwarebazaar_found"] = clean_line.split("MalwareBazaar Found:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Status:"):
            hash_intel["malwarebazaar_status"] = clean_line.split("MalwareBazaar Status:")[-1].strip()
        
        elif clean_line.startswith("MalwareBazaar HTTP Status:"):
            hash_intel["malwarebazaar_http_status"] = clean_line.split("MalwareBazaar HTTP Status:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Error:"):
            hash_intel["malwarebazaar_error"] = clean_line.split("MalwareBazaar Error:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Signature:"):
            hash_intel["malwarebazaar_signature"] = clean_line.split("MalwareBazaar Signature:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Tags:"):
            hash_intel["malwarebazaar_tags"] = clean_line.split("MalwareBazaar Tags:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar File Type:"):
            hash_intel["malwarebazaar_file_type"] = clean_line.split("MalwareBazaar File Type:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar First Seen:"):
            hash_intel["malwarebazaar_first_seen"] = clean_line.split("MalwareBazaar First Seen:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Last Seen:"):
            hash_intel["malwarebazaar_last_seen"] = clean_line.split("MalwareBazaar Last Seen:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Reporter:"):
            hash_intel["malwarebazaar_reporter"] = clean_line.split("MalwareBazaar Reporter:")[-1].strip()

        elif clean_line.startswith("MalwareBazaar Delivery Method:"):
            hash_intel["malwarebazaar_delivery_method"] = clean_line.split("MalwareBazaar Delivery Method:")[-1].strip()

    return hash_intel


#Parsing URLhaus Intelligence
def parse_urlhaus_intel(output):
    urlhaus_intel = {}

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("URLhaus Found:"):
            urlhaus_intel["urlhaus_found"] = clean_line.split("URLhaus Found:")[-1].strip()

        elif clean_line.startswith("URLhaus Status:"):
            urlhaus_intel["urlhaus_status"] = clean_line.split("URLhaus Status:")[-1].strip()

        elif clean_line.startswith("URLhaus HTTP Status:"):
            urlhaus_intel["urlhaus_http_status"] = clean_line.split("URLhaus HTTP Status:")[-1].strip()

        elif clean_line.startswith("URLhaus Error:"):
            urlhaus_intel["urlhaus_error"] = clean_line.split("URLhaus Error:")[-1].strip()

        elif clean_line.startswith("URLhaus URL Status:"):
            urlhaus_intel["urlhaus_url_status"] = clean_line.split("URLhaus URL Status:")[-1].strip()

        elif clean_line.startswith("URLhaus Threat:"):
            urlhaus_intel["urlhaus_threat"] = clean_line.split("URLhaus Threat:")[-1].strip()

        elif clean_line.startswith("URLhaus Tags:"):
            urlhaus_intel["urlhaus_tags"] = clean_line.split("URLhaus Tags:")[-1].strip()

        elif clean_line.startswith("URLhaus Reporter:"):
            urlhaus_intel["urlhaus_reporter"] = clean_line.split("URLhaus Reporter:")[-1].strip()

        elif clean_line.startswith("URLhaus Date Added:"):
            urlhaus_intel["urlhaus_date_added"] = clean_line.split("URLhaus Date Added:")[-1].strip()

        elif clean_line.startswith("URLhaus Reference:"):
            urlhaus_intel["urlhaus_reference"] = clean_line.split("URLhaus Reference:")[-1].strip()

    return urlhaus_intel


#Parsing Spamhaus Intelligence
def parse_spamhaus_intel(output):
    spamhaus_intel = {}

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("Spamhaus Listed:"):
            spamhaus_intel["spamhaus_listed"] = clean_line.split("Spamhaus Listed:")[-1].strip()

        elif clean_line.startswith("Spamhaus Status:"):
            spamhaus_intel["spamhaus_status"] = clean_line.split("Spamhaus Status:")[-1].strip()

        elif clean_line.startswith("Spamhaus Query:"):
            spamhaus_intel["spamhaus_query"] = clean_line.split("Spamhaus Query:")[-1].strip()

        elif clean_line.startswith("Spamhaus Return Codes:"):
            spamhaus_intel["spamhaus_return_codes"] = clean_line.split("Spamhaus Return Codes:")[-1].strip()

        elif clean_line.startswith("Spamhaus Lists:"):
            spamhaus_intel["spamhaus_lists"] = clean_line.split("Spamhaus Lists:")[-1].strip()

        elif clean_line.startswith("Spamhaus Error:"):
            spamhaus_intel["spamhaus_error"] = clean_line.split("Spamhaus Error:")[-1].strip()

    return spamhaus_intel


#Parsing CISA KEV Intelligence
def parse_kev_intel(output):
    kev_intel = {}

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("CVE:"):
            kev_intel["cve"] = clean_line.split("CVE:")[-1].strip()

        elif clean_line.startswith("CISA KEV Found:"):
            kev_intel["cisa_kev_found"] = clean_line.split("CISA KEV Found:")[-1].strip()

        elif clean_line.startswith("CISA KEV Status:"):
            kev_intel["cisa_kev_status"] = clean_line.split("CISA KEV Status:")[-1].strip()

        elif clean_line.startswith("CISA KEV HTTP Status:"):
            kev_intel["cisa_kev_http_status"] = clean_line.split("CISA KEV HTTP Status:")[-1].strip()

        elif clean_line.startswith("CISA KEV Error:"):
            kev_intel["cisa_kev_error"] = clean_line.split("CISA KEV Error:")[-1].strip()

        elif clean_line.startswith("Vendor/Project:"):
            kev_intel["vendor_project"] = clean_line.split("Vendor/Project:")[-1].strip()

        elif clean_line.startswith("Product:"):
            kev_intel["product"] = clean_line.split("Product:")[-1].strip()

        elif clean_line.startswith("Vulnerability Name:"):
            kev_intel["vulnerability_name"] = clean_line.split("Vulnerability Name:")[-1].strip()

        elif clean_line.startswith("Date Added:"):
            kev_intel["date_added"] = clean_line.split("Date Added:")[-1].strip()

        elif clean_line.startswith("Due Date:"):
            kev_intel["due_date"] = clean_line.split("Due Date:")[-1].strip()

        elif clean_line.startswith("Known Ransomware Campaign Use:"):
            kev_intel["known_ransomware_campaign_use"] = clean_line.split("Known Ransomware Campaign Use:")[-1].strip()

        elif clean_line.startswith("Required Action:"):
            kev_intel["required_action"] = clean_line.split("Required Action:")[-1].strip()

        elif clean_line.startswith("Short Description:"):
            kev_intel["short_description"] = clean_line.split("Short Description:")[-1].strip()

        elif clean_line.startswith("Notes:"):
            kev_intel["notes"] = clean_line.split("Notes:")[-1].strip()

    return kev_intel


#Parsing MITRE ATT&CK Context
def parse_mitre_context(output):
    mitre_mappings = []
    current_mapping = None
    inside_mitre_section = False

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("🎯 MITRE ATT&CK Context:"):
            inside_mitre_section = True
            continue

        if inside_mitre_section:
            if clean_line.startswith("🧑‍💻 Analyst Verdict:") or clean_line.startswith("📌 Recommended Action:") or clean_line.startswith("🤖 AI Analyst Summary:"):
                break

            if clean_line.startswith("- "):
                mapping_text = clean_line[2:].strip()
                parts = [part.strip() for part in mapping_text.split("|")]

                if len(parts) == 3:
                    current_mapping = {
                        "tactic": parts[0],
                        "technique_id": parts[1],
                        "technique_name": parts[2],
                        "rationale": "N/A"
                    }

                    mitre_mappings.append(current_mapping)

            elif clean_line.startswith("Rationale:") and current_mapping:
                current_mapping["rationale"] = clean_line.split("Rationale:")[-1].strip()

    return mitre_mappings


#Parsing Domain Intelligence
def parse_domain_intel(output):
    domain_intel = {}

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line.startswith("Domain:"):
            domain_intel["domain"] = clean_line.split("Domain:")[-1].strip()
        
        elif clean_line.startswith("Domain Risk Points:"):
            value = clean_line.split("Domain Risk Points:")[-1].strip()

            try:
                domain_intel["risk_points"] = int(value)
            except:
                domain_intel["risk_points"] = 0

        elif clean_line.startswith("A Records:"):
            domain_intel["a_records"] = clean_line.split("A Records:")[-1].strip()
        
        elif clean_line.startswith("MX Records:"):
            domain_intel["mx_records"] = clean_line.split("MX Records:")[-1].strip()
        
        elif clean_line.startswith("NS Records:"):
            domain_intel["ns_records"] = clean_line.split("NS Records:")[-1].strip()
        
        elif clean_line.startswith("Domain Age Days:"):
            domain_intel["domain_age_days"] = clean_line.split("Domain Age Days:")[-1].strip()

        elif clean_line.startswith("Days Until Expiration:"):
            domain_intel["days_until_expiration"] = clean_line.split("Days Until Expiration:")[-1].strip()

        elif clean_line.startswith("RDAP Available:"):
            domain_intel["rdap_available"] = clean_line.split("RDAP Available:")[-1].strip()
    
    return domain_intel


#Classify Domain Risk For Dashboard
def classify_domain_risk(domain_risk_points):
    if domain_risk_points >= 6:
        return "HIGH 🚨"
    elif domain_risk_points >= 3:
        return "MEDIUM ⚠️"
    else:
        return "LOW ✅"
    


#Panel Visibility Helpers
def has_real_hash_intel(hash_intel):
    return bool(hash_intel.get("hash"))


def has_real_spamhaus_intel(spamhaus_intel):
    return bool(spamhaus_intel.get("spamhaus_status"))


def has_real_urlhaus_intel(urlhaus_intel):
    return bool(urlhaus_intel.get("urlhaus_status"))


def has_real_kev_intel(kev_intel):
    return bool(kev_intel.get("cve"))


def has_real_domain_intel(domain_intel):
    return bool(domain_intel.get("domain"))


def has_real_mitre_mapping(mitre_mappings):
    return bool(mitre_mappings)


#Display Uploaded File Hashes
def show_uploaded_file_hashes(uploaded_hashes):
    if not uploaded_hashes:
        return
    
    st.subheader("📁 Uploaded File Hashes")

    st.write("**File Name:**", uploaded_hashes.get("file_name", "N/A"))
    st.write("**File Size:**", uploaded_hashes.get("file_size", "N/A"), "bytes")

    st.write("**MD5:**")
    st.code(uploaded_hashes.get("md5", "N/A"))

    st.write("**SHA1:**")
    st.code(uploaded_hashes.get("sha1", "N/A"))

    st.write("**SHA256:**")
    st.code(uploaded_hashes.get("sha256", "N/A"))


#Display SOC-Style Hash Panel
def show_hash_panel(hash_intel):
    if not hash_intel:
        return
    
    st.subheader("🧬 Hash Intelligence Summary")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"**Hash:** `{hash_intel.get('hash', 'N/A')}`")
        st.write("**File Name:**", hash_intel.get("file_name", "N/A"))

    with col2:
        st.metric("VT Malicious", hash_intel.get("vt_malicious", "N/A"))
        st.metric("VT Suspicious", hash_intel.get("vt_suspicious", "N/A"))

    with col3:
        st.write("**File Type:**", hash_intel.get("file_type", "N/A"))
        st.write("**File Size:**", hash_intel.get("file_size", "N/A"))
        st.write("**VT Reputation:**", hash_intel.get("vt_reputation", "N/A"))

    st.markdown("### 🧪 MalwareBazaar Intelligence")

    mb_found = hash_intel.get("malwarebazaar_found", "N/A")
    mb_status = hash_intel.get("malwarebazaar_status", "N/A")
    mb_http_status = hash_intel.get("malwarebazaar_http_status", "N/A")
    mb_error = hash_intel.get("malwarebazaar_error", "N/A")
    mb_signature = hash_intel.get("malwarebazaar_signature", "N/A")

    mb_col1, mb_col2, mb_col3, mb_col4 = st.columns(4)

    with mb_col1:
        st.metric("MB Found", mb_found)

    with mb_col2:
        st.write("**Status:**", mb_status)

    with mb_col3:
        st.write("**HTTP:**", mb_http_status)

    with mb_col4:
        st.write("**Signature:**", mb_signature)


    if mb_found == "True":
        st.error("🚨 MalwareBazaar has a matching malware sample for this hash.")
    elif mb_found == "False":
        st.info("ℹ️ MalwareBazaar did not return a matching sample for this hash.")
    else:
        st.info("ℹ️ MalwareBazaar result unavailable.")

    if mb_error not in ["None", "N/A"]:
        st.warning(f"MalwareBazaar lookup note: {mb_error}")

    with st.expander("Show full hash intelligence details"):
        st.write("**Hash:**", hash_intel.get("hash", "N/A"))
        st.write("**File Name:**", hash_intel.get("file_name", "N/A"))
        st.write("**File Type:**", hash_intel.get("file_type", "N/A"))
        st.write("**File Size:**", hash_intel.get("file_size", "N/A"))
        st.write("**VT Malicious Detections:**", hash_intel.get("vt_malicious", "N/A"))
        st.write("**VT Suspicious Detections:**", hash_intel.get("vt_suspicious", "N/A"))
        st.write("**VT Harmless Detections:**", hash_intel.get("vt_harmless", "N/A"))
        st.write("**VT Undetected:**", hash_intel.get("vt_undetected", "N/A"))
        st.write("**VT Reputation:**", hash_intel.get("vt_reputation", "N/A"))
        st.write("---")
        st.write("**MalwareBazaar Found:**", hash_intel.get("malwarebazaar_found", "N/A"))
        st.write("**MalwareBazaar Status:**", hash_intel.get("malwarebazaar_status", "N/A"))
        st.write("**MalwareBazaar HTTP Status:**", hash_intel.get("malwarebazaar_http_status", "N/A"))
        st.write("**MalwareBazaar Error:**", hash_intel.get("malwarebazaar_error", "N/A"))
        st.write("**MalwareBazaar Signature:**", hash_intel.get("malwarebazaar_signature", "N/A"))
        st.write("**MalwareBazaar Tags:**", hash_intel.get("malwarebazaar_tags", "N/A"))
        st.write("**MalwareBazaar File Type:**", hash_intel.get("malwarebazaar_file_type", "N/A"))
        st.write("**MalwareBazaar First Seen:**", hash_intel.get("malwarebazaar_first_seen", "N/A"))
        st.write("**MalwareBazaar Last Seen:**", hash_intel.get("malwarebazaar_last_seen", "N/A"))
        st.write("**MalwareBazaar Reporter:**", hash_intel.get("malwarebazaar_reporter", "N/A"))
        st.write("**MalwareBazaar Delivery Method:**", hash_intel.get("malwarebazaar_delivery_method", "N/A"))


#Display Spamhaus Intelligence Panel
def show_spamhaus_panel(spamhaus_intel):
    if not spamhaus_intel:
        return

    st.markdown("### 📬 Spamhaus ZEN Intelligence")

    sh_listed = spamhaus_intel.get("spamhaus_listed", "N/A")
    sh_status = spamhaus_intel.get("spamhaus_status", "N/A")
    sh_return_codes = spamhaus_intel.get("spamhaus_return_codes", "N/A")
    sh_lists = spamhaus_intel.get("spamhaus_lists", "N/A")
    sh_error = spamhaus_intel.get("spamhaus_error", "N/A")

    sh_col1, sh_col2, sh_col3 = st.columns(3)

    with sh_col1:
        st.metric("Spamhaus Listed", sh_listed)

    with sh_col2:
        st.write("**Status:**", sh_status)

    with sh_col3:
        st.write("**Return Codes:**", sh_return_codes)

    if sh_listed == "True":
        st.error("🚨 Spamhaus ZEN lists this IP. Review for spam, malware, botnet, or policy-listing concerns.")
    elif sh_listed == "False":
        st.success("✅ Spamhaus ZEN does not list this IP.")
    else:
        st.info("ℹ️ Spamhaus ZEN result unavailable.")

    if sh_error not in ["None", "N/A"]:
        st.warning(f"Spamhaus lookup note: {sh_error}")

    if sh_lists not in ["None", "N/A"]:
        st.write("**Spamhaus Lists:**")
        st.write(sh_lists)

    with st.expander("Show full Spamhaus intelligence details"):
        st.write("**Spamhaus Listed:**", spamhaus_intel.get("spamhaus_listed", "N/A"))
        st.write("**Spamhaus Status:**", spamhaus_intel.get("spamhaus_status", "N/A"))
        st.write("**Spamhaus Query:**", spamhaus_intel.get("spamhaus_query", "N/A"))
        st.write("**Spamhaus Return Codes:**", spamhaus_intel.get("spamhaus_return_codes", "N/A"))
        st.write("**Spamhaus Lists:**", spamhaus_intel.get("spamhaus_lists", "N/A"))
        st.write("**Spamhaus Error:**", spamhaus_intel.get("spamhaus_error", "N/A"))


#Display URLhaus Intelligence Panel
def show_urlhaus_panel(urlhaus_intel):
    if not urlhaus_intel:
        return

    st.markdown("### 🧪 URLhaus Intelligence")

    uh_found = urlhaus_intel.get("urlhaus_found", "N/A")
    uh_status = urlhaus_intel.get("urlhaus_status", "N/A")
    uh_http_status = urlhaus_intel.get("urlhaus_http_status", "N/A")
    uh_threat = urlhaus_intel.get("urlhaus_threat", "N/A")
    uh_error = urlhaus_intel.get("urlhaus_error", "N/A")

    uh_col1, uh_col2, uh_col3, uh_col4 = st.columns(4)

    with uh_col1:
        st.metric("URLhaus Found", uh_found)

    with uh_col2:
        st.write("**Status:**", uh_status)

    with uh_col3:
        st.write("**HTTP:**", uh_http_status)

    with uh_col4:
        st.write("**Threat:**", uh_threat)

    if uh_found == "True":
        st.error("🚨 URLhaus has a matching malicious URL record for this URL.")
    elif uh_found == "False":
        st.info("ℹ️ URLhaus did not return a matching URL record.")
    else:
        st.info("ℹ️ URLhaus result unavailable.")

    if uh_error not in ["None", "N/A"]:
        st.warning(f"URLhaus lookup note: {uh_error}")

    with st.expander("Show full URLhaus intelligence details"):
        st.write("**URLhaus Found:**", urlhaus_intel.get("urlhaus_found", "N/A"))
        st.write("**URLhaus Status:**", urlhaus_intel.get("urlhaus_status", "N/A"))
        st.write("**URLhaus HTTP Status:**", urlhaus_intel.get("urlhaus_http_status", "N/A"))
        st.write("**URLhaus Error:**", urlhaus_intel.get("urlhaus_error", "N/A"))
        st.write("**URLhaus URL Status:**", urlhaus_intel.get("urlhaus_url_status", "N/A"))
        st.write("**URLhaus Threat:**", urlhaus_intel.get("urlhaus_threat", "N/A"))
        st.write("**URLhaus Tags:**", urlhaus_intel.get("urlhaus_tags", "N/A"))
        st.write("**URLhaus Reporter:**", urlhaus_intel.get("urlhaus_reporter", "N/A"))
        st.write("**URLhaus Date Added:**", urlhaus_intel.get("urlhaus_date_added", "N/A"))
        st.write("**URLhaus Reference:**", urlhaus_intel.get("urlhaus_reference", "N/A"))


#Display CISA KEV Intelligence Panel
def show_kev_panel(kev_intel):
    if not kev_intel:
        return

    st.markdown("### 🛡️ CISA KEV Intelligence")

    cve = kev_intel.get("cve", "N/A")
    kev_found = kev_intel.get("cisa_kev_found", "N/A")
    kev_status = kev_intel.get("cisa_kev_status", "N/A")
    if kev_found == "True":
        kev_found_display = "Found"
    elif kev_found == "False":
        kev_found_display = "Not Found"
    else:
        kev_found_display = "Unavailable"
    kev_http_status = kev_intel.get("cisa_kev_http_status", "N/A")
    ransomware_use = kev_intel.get("known_ransomware_campaign_use", "N/A")
    kev_error = kev_intel.get("cisa_kev_error", "N/A")

    kev_col1, kev_col2, kev_col3, kev_col4 = st.columns(4)

    with kev_col1:
        st.metric("KEV Result", kev_found_display)

    with kev_col2:
        st.write("**Status:**", kev_status)

    with kev_col3:
        st.write("**HTTP:**", kev_http_status)

    with kev_col4:
        st.write("**Ransomware Use:**", ransomware_use)

    if kev_found == "True":
        st.error("🚨 CISA KEV lists this CVE as known exploited in the wild.")
    elif kev_found == "False":
        st.info("ℹ️ CISA KEV did not list this CVE as known exploited.")
    else:
        st.info("ℹ️ CISA KEV result unavailable.")

    if kev_error not in ["None", "N/A"]:
        st.warning(f"CISA KEV lookup note: {kev_error}")

    st.markdown("#### Vulnerability Context")

    context_col1, context_col2 = st.columns(2)

    with context_col1:
        st.write("**CVE:**", clean_display_value(cve))
        st.write("**Vendor/Project:**", clean_display_value(kev_intel.get("vendor_project")))
        st.write("**Product:**", clean_display_value(kev_intel.get("product")))
        st.write("**Vulnerability Name:**", clean_display_value(kev_intel.get("vulnerability_name")))

    with context_col2:
        st.write("**Date Added:**", clean_display_value(kev_intel.get("date_added")))
        st.write("**Due Date:**", clean_display_value(kev_intel.get("due_date")))
        st.write("**Known Ransomware Campaign Use:**", clean_display_value(ransomware_use))
        st.write("**Notes:**", clean_display_value(kev_intel.get("notes")))

    required_action = kev_intel.get("required_action", "N/A")

    if required_action in ["Unknown", "N/A", "None"]:
        if kev_found == "False":
            required_action = "No KEV remediation guidance is available because this CVE is not listed in CISA KEV."
        else:
            required_action = "No KEV remediation guidance was available from the CISA KEV response."

    st.markdown("#### 🛠️ KEV Remediation Guidance")
    st.info(required_action)

    with st.expander("Show full CISA KEV intelligence details"):
        st.write("**CVE:**", kev_intel.get("cve", "N/A"))
        st.write("**CISA KEV Found:**", kev_intel.get("cisa_kev_found", "N/A"))
        st.write("**CISA KEV Status:**", kev_intel.get("cisa_kev_status", "N/A"))
        st.write("**CISA KEV HTTP Status:**", kev_intel.get("cisa_kev_http_status", "N/A"))
        st.write("**CISA KEV Error:**", kev_intel.get("cisa_kev_error", "N/A"))
        st.write("**Vendor/Project:**", kev_intel.get("vendor_project", "N/A"))
        st.write("**Product:**", kev_intel.get("product", "N/A"))
        st.write("**Vulnerability Name:**", kev_intel.get("vulnerability_name", "N/A"))
        st.write("**Date Added:**", kev_intel.get("date_added", "N/A"))
        st.write("**Due Date:**", kev_intel.get("due_date", "N/A"))
        st.write("**Known Ransomware Campaign Use:**", kev_intel.get("known_ransomware_campaign_use", "N/A"))
        st.write("**Required Action:**", kev_intel.get("required_action", "N/A"))
        st.write("**Short Description:**", kev_intel.get("short_description", "N/A"))
        st.write("**Notes:**", kev_intel.get("notes", "N/A"))

    short_description = kev_intel.get("short_description", "N/A")

    if short_description in ["Unknown", "N/A", "None"]:
        if kev_found == "False":
            short_description = "This CVE was checked against CISA KEV, but no matching known-exploited entry was found."
        else:
            short_description = "No short description was available from the CISA KEV response."

    st.markdown("#### Summary")
    st.write(short_description)


#Display MITRE ATT&CK Context Panel
def show_mitre_panel(mitre_mappings):
    if not mitre_mappings:
        return

    st.markdown("### 🎯 MITRE ATT&CK Context")

    for mapping in mitre_mappings:
        tactic = mapping.get("tactic", "N/A")
        technique_id = mapping.get("technique_id", "N/A")
        technique_name = mapping.get("technique_name", "N/A")
        rationale = mapping.get("rationale", "N/A")

        if technique_id == "N/A":
            st.info("ℹ️ No strong MITRE ATT&CK technique mapping was identified from the current evidence.")
        else:
            st.warning(f"**{tactic} — {technique_id}: {technique_name}**")
            st.write(f"**Rationale:** {rationale}")

    with st.expander("Show full MITRE ATT&CK mapping details"):
        for mapping in mitre_mappings:
            st.write("**Tactic:**", mapping.get("tactic", "N/A"))
            st.write("**Technique ID:**", mapping.get("technique_id", "N/A"))
            st.write("**Technique Name:**", mapping.get("technique_name", "N/A"))
            st.write("**Rationale:**", mapping.get("rationale", "N/A"))
            st.divider()


#Display SOC-Style Domain Panel
def show_domain_panel(domain_intel, sections):
    if not domain_intel:
        return
    
    domain_risk_points = domain_intel.get("risk_points", 0)
    domain_risk_level = classify_domain_risk(domain_risk_points)

    st.subheader("🌐 Domain Intelligence Summary")

    domain_warning_reasons = []

    for item in sections.get("key_findings", []):
        if item.lower().startswith("- domain"):
            domain_warning_reasons.append(item)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(f"**Domain:** `{domain_intel.get('domain', 'N/A')}`")
    
    with col2:
        st.metric("Domain Risk", domain_risk_level)
        st.caption(f"{len(domain_warning_reasons)} warning signals detected")
    
    with col3:
        age = domain_intel.get("domain_age_days")

        if age in [None, "None"]:
            age_display = "Unknown"
        else:
            age_display = f"{age} days"

        st.metric("Domain Age", age_display)

    if domain_risk_points >= 6:
        st.error("🚨 High-risk domain indicators detected. Likely malicious infrastructure.")
    elif domain_risk_points > 0:
        st.warning("⚠️ Domain warning signals were detected. Review the findings below.")
    else:
        st.success("✅ No major domain infrastructure warning signals detected.")
   
    
    if domain_warning_reasons:
        st.write("**Domain Warning Signals:**")
        for reason in domain_warning_reasons:
            st.write(reason)
    
    with st.expander("Show full DNS / RDAP details"):
        st.write("**Internal Domain Risk Score:**", domain_risk_points)
        st.write("**A Records:**", domain_intel.get("a_records", "N/A"))
        st.write("**MX Records:**", domain_intel.get("mx_records", "N/A"))
        st.write("**NS Records:**", domain_intel.get("ns_records", "N/A"))
        st.write("**Days Until Expiration:**", domain_intel.get("days_until_expiration", "N/A"))
        st.write("**RDAP Available:**", domain_intel.get("rdap_available", "N/A"))



#Sectioning 
def parse_sections(output):
    sections = {
        "key_findings": [],
        "analysis": [],
        "memory": [],
        "action": [],
    }

    current_section = None

    stop_markers = [
        "🧑‍💻 Analyst Verdict:",
        "Analyst Verdict:",
        "🤖 AI Analyst Summary:",
        "AI Analyst Summary:",
        "Disposition:",
        "Assessment:",
        "Confidence:",
        "Priority:",
        "File Name:",
        "File Type:",
        "File Size:",
        "VT Malicious Detections:",
        "VT Suspicious Detections:",
        "VT Harmless Detections:",
        "VT Undetected:",
        "VT Reputation:",
        "Spamhaus Listed:",
        "Spamhaus Status:",
        "Spamhaus Query:",
        "Spamhaus Return Codes:",
        "Spamhaus Lists:",
        "Spamhaus Error:",
        "MalwareBazaar Found:",
        "MalwareBazaar Status:",
        "MalwareBazaar HTTP Status:",
        "MalwareBazaar Error:",
        "MalwareBazaar Signature:",
        "MalwareBazaar Tags:",
        "MalwareBazaar File Type:",
        "MalwareBazaar First Seen:",
        "MalwareBazaar Last Seen:",
        "MalwareBazaar Reporter:",
        "MalwareBazaar Delivery Method:",
        "URLhaus Found:",
        "URLhaus Status:",
        "URLhaus HTTP Status:",
        "URLhaus Error:",
        "URLhaus URL Status:",
        "URLhaus Threat:",
        "URLhaus Tags:",
        "URLhaus Reporter:",
        "URLhaus Date Added:",
        "URLhaus Reference:",
        "CISA KEV Found:",
        "CISA KEV Status:",
        "CISA KEV HTTP Status:",
        "CISA KEV Error:",
        "Vendor/Project:",
        "Product:",
        "Vulnerability Name:",
        "Date Added:",
        "Due Date:",
        "Known Ransomware Campaign Use:",
        "Required Action:",
        "Short Description:",
        "Notes:",
        "🎯 MITRE ATT&CK Context:",
        "Rationale:",
        "🔁 REPEAT IOC ALERT:",
        "REPEAT IOC ALERT:",
        "⚠️ History-Based Escalation Applied:",
        "History-Based Escalation Applied:"
    ]

    for line in output.splitlines():
        clean_line = line.strip()

        if clean_line == "Key Findings:" or clean_line == "Reasons:":
            current_section = "key_findings"
            continue

        elif clean_line == "Analysis:" or clean_line == "Confidence Reasons:":
            current_section = "analysis"
            continue

        elif "Memory Summary:" in clean_line:
            current_section = "memory"
            continue

        elif clean_line == "Recommended Action:" or clean_line == "📌 Recommended Action:":
            current_section = "action"
            continue

        elif clean_line.startswith("-----------------------------------"):
            current_section = None
            continue
        
        if any(marker in clean_line for marker in stop_markers):
            current_section = None
            continue

        if current_section and clean_line:
            if current_section == "action" and sections["action"]:
                continue
            
            sections[current_section].append(clean_line)

    return sections


#Main Display Page Setup
st.set_page_config(
    page_title = "Threat Intel Agent Mk3",
    page_icon = "🛡️",
    layout = "wide"
)

st.title("🛡️ Threat Intelligence Agent Mk3")
st.write("Analyze IPs, domains, URLs, and suspicious IOCs using SOC-style enrichment, scoring, and intelligence correlation.")

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "last_ioc" not in st.session_state:
    st.session_state.last_ioc = ""

if "uploaded_file_hashes" not in st.session_state:
    st.session_state.uploaded_file_hashes = None

if "batch_results" not in st.session_state:
    st.session_state.batch_results = []

if "uploaded_ioc_list" not in st.session_state:
    st.session_state.uploaded_ioc_list = []


ioc = st.text_input("Enter IOC", placeholder = "Example: 8.8.8.8 or https://example.com/login")
uploaded_file = st.file_uploader("Upload file for hash analysis")

uploaded_ioc_file = st.file_uploader(
    "Upload IOC list for batch analysis (.txt or .csv)",
    type = ["txt", "csv"] 
)

batch_iocs = st.text_area(
    "Enter multiple IOCs for batch analysis",
    placeholder = "Example:\n8.8.8.8\ngoogle.com\nhttps://example.com/login\n44d88612fea8a8f36de82e1278abb02f",
    height = 160
)

if st.button("Analyze IOC"):
    if not ioc.strip():
        st.error("Please enter an IOC first.")
    else:
        st.info(f"Analyzing: {ioc}")

        result = subprocess.run(
            [sys.executable, "-X", "utf8", "threat_intel_agent_mk3.py"],
            input = f"1\n{ioc}\n3\n",
            text = True,
            capture_output = True,
            encoding = "utf-8",
            errors = "replace"
        )

        st.session_state.last_result = result
        st.session_state.last_ioc = ioc
        st.session_state.uploaded_file_hashes = None
        st.session_state.batch_results = []
        st.session_state.uploaded_ioc_list = []


if st.button("Analyze Uploaded File"):
    if uploaded_file is None:
        st.error("Please upload a file first.")
    
    else:
        file_bytes = uploaded_file.getvalue()
        file_hashes = calculate_file_hashes(file_bytes)

        st.session_state.uploaded_file_hashes = {
            "file_name": uploaded_file.name,
            "file_size": len(file_bytes),
            "md5": file_hashes["md5"],
            "sha1": file_hashes["sha1"],
            "sha256": file_hashes["sha256"]
        }

        sha256_hash = file_hashes["sha256"]

        st.info(f"Analyzing uploaded file SHA256: {sha256_hash}")

        result = subprocess.run(
            [sys.executable, "-X", "utf8", "threat_intel_agent_mk3.py"],
            input = f"1\n{sha256_hash}\n3\n",
            text = True,
            capture_output = True,
            encoding = "utf-8",
            errors = "replace"
        )

        st.session_state.last_result = result
        st.session_state.last_ioc = sha256_hash
        st.session_state.batch_results = []
        st.session_state.uploaded_ioc_list = []


if st.button("Analyze IOC Batch"):
    ioc_list = []

    uploaded_iocs = parse_uploaded_ioc_file(uploaded_ioc_file)

    for uploaded_ioc in uploaded_iocs:
        if uploaded_ioc:
            ioc_list.append(uploaded_ioc)

    for line in batch_iocs.splitlines():
        clean_ioc = line.strip()

        if clean_ioc:
            ioc_list.append(clean_ioc)

    ioc_list = list(dict.fromkeys(ioc_list))

    if not ioc_list:
        st.error("Please enter at least one IOC in the batch box or upload an IOC list file.")
    else:
        st.session_state.uploaded_ioc_list = uploaded_iocs
        batch_results = []

        with st.spinner(f"Analyzing {len(ioc_list)} IOC(s)..."):
            for batch_ioc in ioc_list:
                result = subprocess.run(
                    [sys.executable, "-X", "utf8", "threat_intel_agent_mk3.py"],
                    input = f"1\n{batch_ioc}\n3\n",
                    text = True,
                    capture_output = True,
                    encoding = "utf-8",
                    errors = "replace"
                )

                row = build_batch_result_row(batch_ioc, result.stdout)
                batch_results.append(row)
        
        st.session_state.batch_results = batch_results
        st.session_state.last_result = None
        st.session_state.last_ioc = ""
        st.session_state.uploaded_file_hashes = None
        
result = st.session_state.last_result

if st.session_state.batch_results:
    show_batch_summary(st.session_state.batch_results)

    if st.session_state.uploaded_ioc_list:
        st.info(f"Loaded {len(st.session_state.uploaded_ioc_list)} IOC(s) from uploaded file.")

    st.subheader("📊 Batch IOC Results")

    show_only_high_batch = st.checkbox("Show only high-risk / critical batch results")

    display_rows = st.session_state.batch_results

    if show_only_high_batch:
        display_rows = [
            row for row in st.session_state.batch_results
            if row.get("Risk Clean") == "HIGH"
            or row.get("Priority Clean") in ["HIGH", "CRITICAL"]
        ]
    
    display_rows = [
        {
            "IOC": row.get("IOC", "N/A"),
            "Report Type": row.get("Report Type", "N/A"),
            "Analyzed IP": row.get("Analyzed IP", "N/A"),
            "Risk": row.get("Risk", "N/A"),
            "Confidence": row.get("Confidence", "N/A"),
            "Priority": row.get("Priority", "N/A")
        }
        for row in display_rows
    ]

    if display_rows:
        st.dataframe(
            display_rows,
            width = "stretch",
            hide_index = True
        )
    else:
        st.warning("No high-risk or critical batch results found.")

    
    st.subheader("📤 Export Batch Results")

    csv_data = convert_batch_results_to_csv(st.session_state.batch_results)
    json_data = convert_batch_results_to_json(st.session_state.batch_results)

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label = "Download Batch CSV",
            data = csv_data,
            file_name = "batch_ioc_results.csv",
            mime = "text/csv"
        )

    with col2:
        st.download_button(
            label = "Download Batch JSON",
            data = json_data,
            file_name = "batch_ioc_results.json",
            mime = "application/json"
        ) 

if result:
    if result.stdout:
        parsed = parse_output(result.stdout)
        show_risk_banner(parsed.get("risk", "N/A"))

        context = parse_report_context(result.stdout)
        show_report_context(context)

        col1, col2, col3 = st.columns(3)

        with col1:
            metric_card("Risk Level", parsed.get("risk", "N/A"), card_type="risk")
            
        with col2:
            metric_card("Confidence", parsed.get("confidence", "N/A"), card_type="confidence")
            
        with col3:
            metric_card("Priority", parsed.get("priority", "N/A"), card_type="risk")

        cleaned = clean_output(result.stdout)
        sections = parse_sections(cleaned)
        hash_intel = parse_hash_intel(cleaned)
        spamhaus_intel = parse_spamhaus_intel(cleaned)
        urlhaus_intel = parse_urlhaus_intel(cleaned)
        kev_intel = parse_kev_intel(cleaned)
        mitre_mappings = parse_mitre_context(cleaned)
        domain_intel = parse_domain_intel(cleaned)

        history_key = get_history_key(cleaned)
        history_record = load_history_record(history_key)
        show_history_snapshot(history_record)

        show_recent_history_table(history_key)

        show_uploaded_file_hashes(st.session_state.uploaded_file_hashes)

        if has_real_hash_intel(hash_intel):
            show_hash_panel(hash_intel)

        if has_real_spamhaus_intel(spamhaus_intel):
            show_spamhaus_panel(spamhaus_intel)

        if has_real_urlhaus_intel(urlhaus_intel):
            show_urlhaus_panel(urlhaus_intel)

        if has_real_kev_intel(kev_intel):
            show_kev_panel(kev_intel)

        if has_real_mitre_mapping(mitre_mappings):
            show_mitre_panel(mitre_mappings)

        if has_real_domain_intel(domain_intel):
            show_domain_panel(domain_intel, sections)

        if sections["key_findings"]:
            st.subheader("Key Findings")
            for item in sections["key_findings"]:
                st.write(item)

        if sections["analysis"]:
            st.subheader("Analysis")
            for item in sections["analysis"]:
                st.write(item)

        if sections["action"]:    
            st.subheader("Recommended Action")
            for item in sections["action"]:
                st.write(item)

    if result.stderr:
        st.subheader("Errors")
        st.error(result.stderr)