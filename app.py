import streamlit as st
import asyncio
import os
import sys
import sqlite3
import json
import pandas as pd
from dotenv import load_dotenv

# Load local environment variables if present
load_dotenv()

# Set page configuration with rich title and icon
st.set_page_config(
    page_title="Secure Citizen-Science Privacy Wrapper",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium styling (Glassmorphism & tailored dark accents)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    .main-title {
        font-weight: 700;
        background: linear-gradient(135deg, #FF4B4B 0%, #FF8F8F 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 5px;
    }
    
    .section-header {
        font-weight: 600;
        color: #31333F;
        border-bottom: 2px solid #F0F2F6;
        padding-bottom: 5px;
        margin-top: 20px;
        margin-bottom: 15px;
    }
    
    .card {
        background-color: #FFFFFF;
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        border: 1px solid #E0E0E0;
        margin-bottom: 15px;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: #6D7280;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .metric-value {
        font-size: 1.2rem;
        font-weight: 700;
        color: #1F2937;
    }
    
    .sanitized-container {
        background-color: #F8FAFC;
        border-left: 4px solid #10B981;
        padding: 15px;
        border-radius: 4px;
        font-family: monospace;
        white-space: pre-wrap;
    }
    
    .raw-container {
        background-color: #FEF2F2;
        border-left: 4px solid #EF4444;
        padding: 15px;
        border-radius: 4px;
        font-family: monospace;
        white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to get SQLite database reports (for viewer)
db_name = os.environ.get("DATABASE_FILE", "reports.db")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_name)

def get_db_records():
    """Retrieve all stored records from database."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT id, user_hash, category, location, summary, severity, timestamp FROM reports ORDER BY id DESC", conn)
        conn.close()
        # Format columns
        df.columns = ["ID", "Anonymous User Hash", "Hazard Category", "General Location", "Incident Summary", "Severity Level", "Timestamp"]
        df["ID"] = df["ID"].apply(lambda x: f"INC-{1000 + x}")
        return df
    except Exception as e:
        st.error(f"Failed to read database: {str(e)}")
        return pd.DataFrame()

def clear_db_records():
    """Delete all records in SQLite reports table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM reports")
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to clear database: {str(e)}")
        return False

def get_admin_passcode():
    """Fetch the custom administrator passcode from the SQLite settings table, or initialize it."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute("SELECT value FROM settings WHERE key = 'admin_passcode'")
        row = cursor.fetchone()
        if row is None:
            cursor.execute("INSERT INTO settings (key, value) VALUES ('admin_passcode', 'admin123')")
            conn.commit()
            passcode = "admin123"
        else:
            passcode = row[0]
        conn.close()
        return passcode
    except Exception as e:
        return "admin123"

def update_admin_passcode(new_passcode):
    """Update the administrator passcode in the SQLite settings table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_passcode', ?)", (new_passcode,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Failed to update passcode in database: {str(e)}")
        return False

# Async helper to run the ADK workflow and stream updates
async def execute_adk_workflow(report_text: str, model_name: str, status_ref):
    from google.adk.sessions import InMemorySessionService
    from google.adk import Runner
    from google.genai import types
    import workflow
    
    # 1. Initialize workflow & sessions
    session_service = InMemorySessionService()
    wf = workflow.create_workflow(model_name)
    runner = Runner(node=wf, session_service=session_service, auto_create_session=True)
    
    content = types.Content(parts=[types.Part(text=report_text)], role="user")
    
    import uuid
    session_id = f"sess_{uuid.uuid4().hex[:8]}"
    user_id = "citizen"
    
    results = {
        "status": "Started",
        "error": None,
        "final_output": None,
        "state": {}
    }
    
    try:
        async for event in runner._run_node_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content
        ):
            # Check which node is running and update status message
            path = event.node_info.path if event.node_info else ""
            if "preprocess_raw_report" in path:
                status_ref.update(label="🔄 Step 1: Preprocessing raw report and preparing state...", state="running")
            elif "PrivacyGuardAgent" in path:
                status_ref.update(label="🕵️ Step 2: Running Privacy Guard Agent (Redacting PII)...", state="running")
            elif "privacy_verification_skill" in path:
                status_ref.update(label="🔒 Step 3: Running Privacy Verification Skill (Regex inspection)...", state="running")
            elif "IncidentAnalysisAgent" in path:
                status_ref.update(label="📊 Step 4: Running Incident Analysis Agent (Extracting hazard details)...", state="running")
            elif "pydantic_validation_layer" in path:
                status_ref.update(label="✨ Step 5: Executing Pydantic Validation Layer...", state="running")
            elif "secure_storage_skill" in path:
                status_ref.update(label="💾 Step 6: Triggering Secure Storage Skill (MCP database write)...", state="running")
                
            if event.output:
                results["final_output"] = event.output
                
        # Fetch final state variables
        session = await session_service.get_session(
            app_name=runner.app_name, 
            user_id=user_id, 
            session_id=session_id
        )
        results["state"] = session.state
        results["status"] = "Success"
        status_ref.update(label="✅ Workflow Execution Completed successfully!", state="complete")
        
    except Exception as e:
        results["status"] = "Failed"
        results["error"] = str(e)
        status_ref.update(label="❌ Workflow interrupted by validation/execution error.", state="error")
        
    return results

# Main Application Layout
st.markdown("<h1 class='main-title'>🛡️ Citizen-Science Privacy Wrapper</h1>", unsafe_allow_html=True)
st.markdown("A secure, multi-agent AI pipeline built using **Google Agent Development Kit (ADK)** and a custom **Model Context Protocol (MCP) Server** to redact Personally Identifiable Information (PII) before storage.", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=90)

# Role Selector in Sidebar
role = st.sidebar.selectbox(
    "User Mode",
    ["Citizen (End User)", "Administrator/Developer"],
    index=0,
    help="Select your role to access different views."
)

admin_authenticated = False
if role == "Administrator/Developer":
    st.sidebar.markdown("### Admin Authentication")
    current_passcode = get_admin_passcode()
    passcode = st.sidebar.text_input(
        "Admin Passcode",
        type="password",
        help="Enter passcode to authenticate."
    )
    if passcode == current_passcode:
        admin_authenticated = True
        st.sidebar.success("Authenticated successfully!")
    elif passcode:
        st.sidebar.error("Incorrect passcode.")

show_admin_configs = (role == "Administrator/Developer" and admin_authenticated)

# Persistent API Key in session state
if "gemini_api_key" not in st.session_state:
    st.session_state["gemini_api_key"] = os.environ.get("GEMINI_API_KEY", "")

if show_admin_configs:
    st.sidebar.markdown("### Configuration")
    api_key = st.sidebar.text_input(
        "Gemini API Key",
        type="password",
        value=st.session_state["gemini_api_key"],
        help="Enter your Gemini API key."
    )
    st.session_state["gemini_api_key"] = api_key
    if api_key:
        os.environ["GEMINI_API_KEY"] = api_key
        st.sidebar.success("API Key successfully set!")
    else:
        st.sidebar.warning("Please provide a Gemini API Key to proceed.")
        
    model_option = st.sidebar.selectbox(
        "Large Language Model",
        ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-3.5-flash"],
        index=0,
        help="Select the Gemini model to power the specialized agents."
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### System Architecture")
    st.sidebar.info("""
    1. **Raw Submission** (Citizen)
    2. **PII Preprocess** (State binding)
    3. **Privacy Guard Agent** (LLM Redaction)
    4. **Privacy Verification Skill** (Regex validation)
    5. **Incident Analysis Agent** (Structured extraction)
    6. **Pydantic Validation** (Strict schema enforce)
    7. **Secure Storage Skill** (MCP Client)
    8. **SQLite Database** (Secure storage)
    """)
else:
    # Citizen view (use persisted key if set, or env key)
    if st.session_state["gemini_api_key"]:
        os.environ["GEMINI_API_KEY"] = st.session_state["gemini_api_key"]
    model_option = "gemini-2.5-flash"

# Create Tabs dynamically based on role
if show_admin_configs:
    tabs = st.tabs(["📤 Submit Incident Report", "🗄️ Secure Database Viewer", "📈 Analytics & Trends", "📐 Architecture & Security"])
    tab_submit = tabs[0]
    tab_database = tabs[1]
    tab_analytics = tabs[2]
    tab_arch = tabs[3]
else:
    tabs = st.tabs(["📤 Submit Incident Report"])
    tab_submit = tabs[0]
    tab_database = None
    tab_analytics = None
    tab_arch = None

# Tab 1: Submit Report
with tab_submit:
    st.markdown("<h3 class='section-header'>Submit a New Incident Report</h3>", unsafe_allow_html=True)
    
    if show_admin_configs:
        default_report = (
            "Hi, my name is Rahul Sharma.\n"
            "I noticed two large blue chemical drums dumped near the river behind Green Park Apartments, 42 Lake View Road, Bangalore.\n"
            "The water smells terrible and several fish appear to be dead.\n"
            "If you need more information, call me at +91 9876543210 or email me at rahul.sharma@gmail.com."
        )
        
        col_input, col_preset = st.columns([3, 1])
        
        with col_preset:
            st.markdown("##### Preset Scenarios")
            preset_selection = st.radio(
                "Select a test scenario:",
                ["Chemical Spill (Valid)", "Trash Burning (Valid)", "Unredacted Phone (Fails verification)", "Unredacted Email (Fails verification)"]
            )
            
            if preset_selection == "Chemical Spill (Valid)":
                report_text = default_report
            elif preset_selection == "Trash Burning (Valid)":
                report_text = (
                    "Hello, I am Priya Nair. Someone is burning plastic wastes in the open fields of Windfield Area, Pune.\n"
                    "The smoke is toxic and thick. Contact me at nair.priya@outlook.com or 09812345678 if needed."
                )
            elif preset_selection == "Unredacted Phone (Fails verification)":
                report_text = (
                    "A sewer line is leaking behind my house in Indiranagar, Bangalore.\n"
                    "Please call me on +91 9876543210 directly to locate it."
                )
            elif preset_selection == "Unredacted Email (Fails verification)":
                report_text = (
                    "Illegal sand mining noticed near Narmada river bank. Email me at report_alert@miningwatch.org for photos."
                )
                
        with col_input:
            user_report_input = st.text_area(
                "Write the environmental incident details below:",
                value=report_text,
                height=180,
                placeholder="Type your report details here..."
            )
            submit_btn = st.button("🚀 Process & Submit Report", use_container_width=True)
    else:
        user_report_input = st.text_area(
            "Write the environmental incident details below:",
            value="",
            height=180,
            placeholder="Describe the environmental incident here (e.g. what you observed, approximate location, severity)..."
        )
        submit_btn = st.button("🚀 Process & Submit Report", use_container_width=True)

    if submit_btn:
        if not os.environ.get("GEMINI_API_KEY"):
            st.error("❌ Gemini API Key is missing. Please provide it in the sidebar.")
        elif not user_report_input.strip():
            st.warning("Please type some report details before submitting.")
        else:
            st.markdown("<h3 class='section-header'>Execution Status</h3>", unsafe_allow_html=True)
            status_container = st.status("Initializing ADK multi-agent workflow runtime...", expanded=True)
            
            # Execute the workflow
            with st.spinner("Executing workflow pipeline..."):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                res = loop.run_until_complete(
                    execute_adk_workflow(user_report_input, model_option, status_container)
                )
                loop.close()
            
            # Display Results
            if res["status"] == "Success":
                st.balloons()
                st.success("🎉 Report Processed and Logged Successfully!")
                
                # Fetch output and state variables
                db_response = res["final_output"] or {}
                state = res["state"]
                sanitized_text = state.get("sanitized_report", "Unavailable")
                incident_report = state.get("incident_report", {})
                
                # Layout results
                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown("#### 🔒 Privacy Scan Comparison")
                    st.markdown("**Raw Report Submitted:**")
                    st.markdown(f"<div class='raw-container'>{user_report_input}</div>", unsafe_allow_html=True)
                    
                    st.markdown("**Sanitized Report (stored in db):**")
                    st.markdown(f"<div class='sanitized-container'>{sanitized_text}</div>", unsafe_allow_html=True)
                    
                with col_right:
                    st.markdown("#### 📝 Structured Environmental Intelligence")
                    
                    # Custom card for details
                    st.markdown(f"""
                    <div class='card'>
                        <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;'>
                            <span style='background-color: #10B981; color: white; padding: 4px 10px; border-radius: 20px; font-size: 0.85rem; font-weight: bold;'>Privacy Scan Passed</span>
                            <span style='font-weight: bold; color: #3b82f6;'>ID: {db_response.get('incident_id', 'N/A')}</span>
                        </div>
                        <div style='margin-bottom: 10px;'>
                            <div class='metric-label'>Anonymous User Hash</div>
                            <div class='metric-value'>{incident_report.get('anonymous_user_hash', 'N/A')}</div>
                        </div>
                        <div style='margin-bottom: 10px;'>
                            <div class='metric-label'>Hazard Category</div>
                            <div class='metric-value'>{incident_report.get('hazard_category', 'N/A')}</div>
                        </div>
                        <div style='margin-bottom: 10px;'>
                            <div class='metric-label'>Generalized Location</div>
                            <div class='metric-value'>{incident_report.get('general_location', 'N/A')}</div>
                        </div>
                        <div style='margin-bottom: 10px;'>
                            <div class='metric-label'>Severity Level</div>
                            <div class='metric-value' style='color: {"#EF4444" if incident_report.get("severity_level") in ("High", "Critical") else "#F59E0B" if incident_report.get("severity_level") == "Medium" else "#10B981"};'>{incident_report.get('severity_level', 'N/A')}</div>
                        </div>
                        <div style='margin-bottom: 10px;'>
                            <div class='metric-label'>Incident Summary</div>
                            <div style='color: #4B5563; font-size: 0.95rem; margin-top: 3px;'>{incident_report.get('incident_summary', 'N/A')}</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.info(f"💾 **MCP Server Response:** {db_response.get('message', '')} {db_response.get('privacy', '')}")
                    
            else:
                st.error("❌ Process Failed: Privacy verification halted execution.")
                st.markdown("#### 🚨 Security Alert: Potential PII Leak Blocked")
                st.warning(f"**Error Details:** {res['error']}")
                st.info("The Privacy Verification Skill detected unredacted PII in the output of the Privacy Guard Agent. Execution was terminated immediately. No database writes or downstream LLM categorization occurred.")

    # Citizen public trends card (outside the submit execution block)
    if not show_admin_configs:
        st.markdown("---")
        st.markdown("<h3 class='section-header'>📊 Public Community Hazard Trends</h3>", unsafe_allow_html=True)
        df_records = get_db_records()
        if df_records.empty:
            st.info("No reports have been submitted yet. Once reports are logged, community hazard trends will be visualised here.")
        else:
            # 1. Render category distribution chart
            category_counts = df_records["Hazard Category"].value_counts().reset_index()
            category_counts.columns = ["Hazard Category", "Report Count"]
            
            st.markdown("##### Reported Hazard Categories")
            st.bar_chart(category_counts.set_index("Hazard Category"), y="Report Count", color="#FF4B4B")
            
            # 2. Display the latest community advisory from cache
            trends_cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "community_trends.json")
            if os.path.exists(trends_cache_path):
                try:
                    import json
                    with open(trends_cache_path, "r") as f:
                        cached_trends = json.load(f)
                    
                    st.info(f"📣 **Community Advisory:** {cached_trends.get('community_advisory', '')}")
                    
                    st.markdown(f"""
                    <div class='card' style='background-color: #F8FAFC; border-left: 4px solid #3B82F6;'>
                        <div class='metric-label'>Most Frequent Hazard Type</div>
                        <div class='metric-value'>{cached_trends.get('most_frequent_hazard', 'N/A')}</div>
                        <div class='metric-label' style='margin-top: 10px;'>Active Geographic Hotspots</div>
                        <div class='metric-value'>{cached_trends.get('active_hotspots', 'N/A')}</div>
                    </div>
                    """, unsafe_allow_html=True)
                except:
                    pass

# Tab 2: Database Viewer
if tab_database is not None:
    with tab_database:
        st.markdown("<h3 class='section-header'>Stored Records in SQLite (reports.db)</h3>", unsafe_allow_html=True)
        st.markdown("Below is the actual SQLite table contents, showing that only sanitized reports and anonymous hashes are saved. **No PII is retained.**")
        
        col_actions, _ = st.columns([1, 4])
        with col_actions:
            if st.button("🔄 Refresh Database", use_container_width=True):
                st.rerun()
                
        df_records = get_db_records()
        if df_records.empty:
            st.info("No records are currently logged in the secure SQLite database.")
        else:
            st.dataframe(df_records, use_container_width=True, hide_index=True)
            
            st.markdown("---")
            st.markdown("##### Administrative Utilities")
            if st.button("🗑️ Clear All Database Records", type="secondary"):
                if clear_db_records():
                    st.success("Database cleared successfully!")
                    st.rerun()

        st.markdown("---")
        st.markdown("##### Change Admin Passcode")
        with st.form("change_passcode_form"):
            new_passcode_input = st.text_input("Enter New Passcode", type="password", placeholder="Type new passcode...")
            confirm_passcode_input = st.text_input("Confirm New Passcode", type="password", placeholder="Retype new passcode...")
            
            submit_passcode = st.form_submit_button("🔑 Update Passcode", use_container_width=True)
            if submit_passcode:
                if not new_passcode_input.strip():
                    st.error("Passcode cannot be empty!")
                elif new_passcode_input != confirm_passcode_input:
                    st.error("Passwords do not match!")
                else:
                    if update_admin_passcode(new_passcode_input):
                        st.success("Passcode updated successfully! Use the new passcode next time you log in.")

# Tab 3: Analytics & Trends
if tab_analytics is not None:
    with tab_analytics:
        st.markdown("<h3 class='section-header'>📈 Environmental Analytics & Agent Trends</h3>", unsafe_allow_html=True)
        df_records = get_db_records()
        if df_records.empty:
            st.info("No records are currently logged to analyze.")
        else:
            # Render two side-by-side charts
            col_chart1, col_chart2 = st.columns(2)
            with col_chart1:
                st.markdown("##### Reports by Hazard Category")
                category_counts = df_records["Hazard Category"].value_counts().reset_index()
                category_counts.columns = ["Hazard Category", "Report Count"]
                st.bar_chart(category_counts.set_index("Hazard Category"), y="Report Count", color="#3B82F6")
            with col_chart2:
                st.markdown("##### Reports by Severity Level")
                severity_counts = df_records["Severity Level"].value_counts().reset_index()
                severity_counts.columns = ["Severity Level", "Report Count"]
                st.bar_chart(severity_counts.set_index("Severity Level"), y="Report Count", color="#F59E0B")
                
            st.markdown("---")
            st.markdown("##### LLM Trend Analysis Agent")
            st.markdown("Invoke the Trend Analysis Agent to analyze all database records, identify geographic hotspots, and generate community advisories.")
            
            # Button to trigger agent analysis
            if st.button("📊 Run AI Trend Analysis", use_container_width=True):
                if not os.environ.get("GEMINI_API_KEY"):
                    st.error("❌ Gemini API Key is missing. Please provide it in the sidebar.")
                else:
                    with st.spinner("Trend Analysis Agent is analyzing SQLite records..."):
                        try:
                            import workflow
                            analysis_results = workflow.analyze_db_trends(model_option)
                            
                            st.balloons()
                            st.success("AI Trend Analysis completed successfully!")
                            
                            # Cache results locally for Citizens
                            trends_cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "community_trends.json")
                            with open(trends_cache_path, "w") as f:
                                json.dump(analysis_results, f)
                                
                            # Render insights
                            st.markdown("#### 📝 Agent Diagnostics & Insights")
                            st.markdown(f"""
                            <div class='card' style='border-top: 4px solid #10B981;'>
                                <div style='margin-bottom: 10px;'>
                                    <div class='metric-label'>Total Reports Evaluated</div>
                                    <div class='metric-value'>{analysis_results.get('total_active_reports', 0)}</div>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <div class='metric-label'>Most Frequent Hazard Category</div>
                                    <div class='metric-value'>{analysis_results.get('most_frequent_hazard', 'N/A')}</div>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <div class='metric-label'>Active Hotspots Detected</div>
                                    <div class='metric-value'>{analysis_results.get('active_hotspots', 'N/A')}</div>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <div class='metric-label'>Public Community Advisory</div>
                                    <div style='color: #1F2937; font-size: 1.05rem; font-weight: 500; margin-top: 3px;'>{analysis_results.get('community_advisory', 'N/A')}</div>
                                </div>
                                <div style='margin-bottom: 10px;'>
                                    <div class='metric-label'>Administrator Diagnostic Notes</div>
                                    <div style='color: #4B5563; font-size: 0.95rem; margin-top: 3px; font-style: italic;'>{analysis_results.get('admin_diagnostic_notes', 'N/A')}</div>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                        except Exception as e:
                            st.error(f"Trend Analysis Agent failed: {str(e)}")

# Tab 3: Architecture & Security
if tab_arch is not None:
    with tab_arch:
        st.markdown("<h3 class='section-header'>Defense-in-Depth Architecture</h3>", unsafe_allow_html=True)
        st.markdown("""
        The Secure Citizen-Science Privacy Wrapper protects user identities using multiple verification and isolation layers:
        
        *   **Layer 1: Privacy Guard Agent (LLM)**: Inspects raw inputs and redacts names, phones, emails, and exact street addresses using soft LLM-based redaction and generalization instructions.
        *   **Layer 2: Privacy Verification Skill (Deterministic)**: Runs strict, non-LLM regex patterns on the sanitized text. If any unredacted contact numbers, emails, PANs, or Aadhaar numbers leak, the workflow is aborted instantly.
        *   **Layer 3: Incident Analysis Agent (Structured LLM)**: Extracts key hazard parameters using structured JSON extraction with strict Pydantic schemas.
        *   **Layer 4: Pydantic Validation Layer**: Enforces fields and type constraints (e.g. validating severity is strictly one of *Low*, *Medium*, *High*, or *Critical*) and generates a short SHA-256 hash prefix (`A18F92C`) of the user's name/contact info to allow anonymous user tracking.
        *   **Layer 5: Model Context Protocol (MCP) Server**: Isolates the SQLite database completely. Agents cannot run SQL commands or access files directly; they can only interact via the exposed `secure_log_incident` tool.
        """)
        
        st.image("https://img.icons8.com/color/144/checked-laptop.png", width=70)
