import streamlit as st
import subprocess
import sys
import json
import os

base_folder = os.path.dirname(__file__)
history_file = os.path.join(base_folder, "ioc_history.json")


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

        elif "=== THREAT INTELLIGENCE AGENT REPORT ===" in clean_line:
            context["report_type"] = "IOC Enrichment Analysis"

        elif clean_line.startswith("Original IOC:"):
            context["original_ioc"] = clean_line.split("Original IOC:")[-1].strip()
        
        elif clean_line.startswith("Original URL:"):
            context["original_ioc"] = clean_line.split("Original URL:")[-1].strip()
        
        elif clean_line.startswith("IP:"):
            context["analyzed_ip"] = clean_line.split("IP:")[-1].strip()
        
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
        st.info("Current History Key: Not available because this IOC did not resolve to a stored IP.")

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
        if "=== THREAT INTELLIGENCE AGENT REPORT ===" in line or "=== URL THREAT ASSESSMENT ===" in line:
            start = True

        if start and "--- Threat Intel Agent Menu ---" in line:
            break

        if start:
            cleaned_lines.append(line)
    
    return "\n".join(cleaned_lines)

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
        "action": []
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
    page_title = "Threat Intel Agent Mk2",
    page_icon = "🛡️",
    layout = "wide"
)

st.title("🛡️ Threat Intelligence Agent Mk2")
st.write("Analyze IPs, domains, URLs, and suspicious IOCs using SOC-style enrichment and scoring.")

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "last_ioc" not in st.session_state:
    st.session_state.last_ioc = ""


ioc = st.text_input("Enter IOC", placeholder = "Example: 8.8.8.8 or https://example.com/login")

if st.button("Analyze IOC"):
    if not ioc.strip():
        st.error("Please enter an IOC first.")
    else:
        st.info(f"Analyzing: {ioc}")

        result = subprocess.run(
            [sys.executable, "-X", "utf8", "threat_intel_agent_mk2.py"],
            input = f"1\n{ioc}\n3\n",
            text = True,
            capture_output = True,
            encoding = "utf-8",
            errors = "replace"
        )

        st.session_state.last_result = result
        st.session_state.last_ioc = ioc

result = st.session_state.last_result

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
        domain_intel = parse_domain_intel(cleaned)

        history_key = get_history_key(cleaned)
        history_record = load_history_record(history_key)
        show_history_snapshot(history_record)

        show_recent_history_table(history_key)

        show_domain_panel(domain_intel, sections)

        if sections["key_findings"]:
            st.subheader("Key Findings")
            for item in sections["key_findings"]:
                st.write(item)

        if sections["analysis"]:
            st.subheader("Analysis")
            for item in sections["analysis"]:
                st.write(item)

        #if sections["memory"]:
        #    st.subheader("Memory Summary")
        #    for item in sections["memory"]:
        #       st.write(item)

        if sections["action"]:    
            st.subheader("Recommended Action")
            for item in sections["action"]:
                st.write(item)
        
    if result.stderr:
        st.subheader("Errors")
        st.error(result.stderr)