import os
import sys
import re
import hashlib
import json
import asyncio
from typing import Any, Literal
from pydantic import BaseModel, Field
from google.adk import Agent, Workflow
from google.adk.workflow import node, START
from google.adk.agents.context import Context
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Define the output schema for the Incident Analysis Agent
class IncidentAnalysisOutput(BaseModel):
    hazard_category: str = Field(description="The category of the environmental hazard (e.g. 'Water Pollution', 'Air Pollution', 'Illegal Dumping')")
    general_location: str = Field(description="The generalized location or area where the incident occurred (e.g. 'Lake View Area, Bangalore')")
    incident_summary: str = Field(description="A concise summary of the incident details, excluding any PII.")
    severity_level: Literal['Low', 'Medium', 'High', 'Critical'] = Field(description="The estimated severity level of the incident.")

# Define the final verified report model stored in SQLite
class IncidentReport(BaseModel):
    anonymous_user_hash: str
    hazard_category: str
    general_location: str
    incident_summary: str
    severity_level: Literal['Low', 'Medium', 'High', 'Critical']

# 1. PII Preprocess (Function Node)
@node
async def preprocess_raw_report(ctx: Context, node_input: str) -> str:
    """Preprocess node that saves the raw user report in the workflow state."""
    ctx.state["raw_report"] = node_input
    return node_input

# 3. Privacy Verification Skill (Function Node)
@node
async def privacy_verification_skill(ctx: Context, node_input: str) -> str:
    """
    Deterministic regex-based check running after the Privacy Guard Agent completes.
    Ensures that no sensitive PII (phone, email, PAN, Aadhaar) remains in the sanitized report.
    """
    # Clean the text of existing allowed redaction markers
    text_to_check = node_input
    text_to_check = text_to_check.replace("[REDACTED_CONTACT]", "")
    text_to_check = text_to_check.replace("[REDACTED_NAME]", "")
    
    # 1. Check for email patterns
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    emails = re.findall(email_pattern, text_to_check)
    if emails:
        raise ValueError(f"Privacy Verification Failed: Email address leak detected: '{emails[0]}'")
        
    # 2. Check for phone numbers
    # Exclude dates (YYYY-MM-DD, DD-MM-YYYY) to avoid false positives
    temp_text = re.sub(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b', '', text_to_check)
    temp_text = re.sub(r'\b\d{2}[-/]\d{2}[-/]\d{4}\b', '', temp_text)
    
    phone_pattern = r'(?:\+?91[\s-]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b|\b\d{10}\b'
    phones = re.findall(phone_pattern, temp_text)
    if phones:
        raise ValueError(f"Privacy Verification Failed: Phone number leak detected: '{phones[0]}'")
        
    # 3. Check for PAN card format
    pan_pattern = r'\b[A-Z]{5}\d{4}[A-Z]\b'
    pans = re.findall(pan_pattern, text_to_check)
    if pans:
        raise ValueError(f"Privacy Verification Failed: PAN card leak detected: '{pans[0]}'")
        
    # 4. Check for Aadhaar card format
    aadhaar_pattern = r'\b\d{4}\s\d{4}\s\d{4}\b|\b\d{12}\b'
    aadhaars = re.findall(aadhaar_pattern, text_to_check)
    if aadhaars:
        raise ValueError(f"Privacy Verification Failed: Aadhaar card leak detected: '{aadhaars[0]}'")
        
    # If passed, save the sanitized report in state
    ctx.state["sanitized_report"] = node_input
    return node_input

# 5. Pydantic Validation Layer (Function Node)
@node
async def pydantic_validation_layer(ctx: Context, node_input: Any) -> IncidentReport:
    """
    Validates output from Incident Analysis Agent, computes the anonymous user hash,
    and returns a fully validated IncidentReport.
    """
    # Normalize input (could be IncidentAnalysisOutput object or dict)
    if isinstance(node_input, dict):
        data = node_input
    else:
        data = node_input.model_dump()
        
    # Compute Anonymous User Hash from raw_report
    raw_report = ctx.state.get("raw_report", "")
    
    # Try to extract the user's name or contact details to hash them, otherwise fallback to entire report
    email_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', raw_report)
    phone_match = re.search(r'(?:\+?91[\s-]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b|\b\d{10}\b', raw_report)
    name_match = re.search(r'(?:my name is|I am|name:)\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)', raw_report, re.IGNORECASE)
    
    identity = ""
    if email_match:
        identity = email_match.group(0).strip().lower()
    elif phone_match:
        identity = re.sub(r'[\s-]', '', phone_match.group(0))
    elif name_match:
        identity = name_match.group(1).strip()
    else:
        identity = raw_report.strip()
        
    # Compute SHA-256 hash and take first 7 chars in uppercase
    computed_hash = hashlib.sha256(identity.encode('utf-8')).hexdigest().upper()[:7]
    
    # Build and validate IncidentReport
    incident_report = IncidentReport(
        anonymous_user_hash=computed_hash,
        hazard_category=data.get("hazard_category"),
        general_location=data.get("general_location"),
        incident_summary=data.get("incident_summary"),
        severity_level=data.get("severity_level")
    )
    
    ctx.state["incident_report"] = incident_report.model_dump()
    return incident_report

# 6. Secure Storage Skill (Function Node)
@node
async def secure_storage_skill(ctx: Context, node_input: IncidentReport) -> dict:
    """
    Agent Skill that connects to the custom MCP storage server, sends the validated
    report, and returns the DB insertion results.
    """
    server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_path],
        env=os.environ.copy()
    )
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                # Make tool call on custom MCP server
                arguments = {
                    "user_hash": node_input.anonymous_user_hash,
                    "category": node_input.hazard_category,
                    "location": node_input.general_location,
                    "summary": node_input.incident_summary,
                    "severity": node_input.severity_level
                }
                
                result = await session.call_tool("secure_log_incident", arguments=arguments)
                
                # Parse response
                if result and result.content:
                    response_text = result.content[0].text
                    return json.loads(response_text)
                else:
                    raise RuntimeError("No output received from custom MCP Server.")
    except Exception as e:
        raise RuntimeError(f"Secure Storage Skill failed: {str(e)}")

# Factory to build the full ADK Workflow
def create_workflow(model_name: str = "gemini-2.5-flash") -> Workflow:
    """
    Creates and returns the complete graph-based sequential workflow.
    """
    # 2. Privacy Guard Agent (LLM Agent)
    privacy_guard_agent = Agent(
        model=model_name,
        name="PrivacyGuardAgent",
        description="Redacts PII (names, contact numbers, emails, and exact addresses) from reports.",
        instruction=(
            "You are the Privacy Guard Agent.\n"
            "Your job is to detect and redact all Personally Identifiable Information (PII) from the user's environmental incident report.\n\n"
            "PII includes:\n"
            "- Names (e.g. 'Rahul Sharma') -> replace with '[REDACTED_NAME]'\n"
            "- Phone numbers (e.g. '+91 9876543210') -> replace with '[REDACTED_CONTACT]'\n"
            "- Email addresses (e.g. 'rahul.sharma@gmail.com') -> replace with '[REDACTED_CONTACT]'\n"
            "- Exact street addresses or building names (e.g. '42 Lake View Road, Bangalore', 'Green Park Apartments') -> generalize them (e.g. replace exact street names and numbers with general areas like 'Lake View Area, Bangalore').\n\n"
            "Ensure that details about the environmental hazard (like 'two large blue chemical drums dumped near the river', 'water smells terrible', 'fish appear to be dead') are completely preserved and NOT redacted or altered.\n\n"
            "Return ONLY the sanitized report text. Do not add any conversational preamble or explanations. Do not include original PII anywhere."
        )
    )

    # 4. Incident Analysis Agent (LLM Agent)
    incident_analysis_agent = Agent(
        model=model_name,
        name="IncidentAnalysisAgent",
        description="Analyzes sanitized reports and extracts structured environmental hazard metadata.",
        instruction=(
            "You are the Incident Analysis Agent.\n"
            "Your task is to analyze the sanitized environmental incident report and extract structured details.\n\n"
            "Analyze the input report and extract:\n"
            "- The category of the hazard (e.g. 'Water Pollution', 'Air Pollution', 'Illegal Dumping', 'Infrastructure Hazard').\n"
            "- The generalized location or area where it occurred.\n"
            "- A concise summary of the incident (do not include details about who reported it).\n"
            "- An estimate of the severity level ('Low', 'Medium', 'High', 'Critical').\n\n"
            "You must produce structured output conforming to the required schema."
        ),
        output_schema=IncidentAnalysisOutput
    )

    # Construct the graph with edges specifying sequential execution:
    # START -> preprocess -> PrivacyGuardAgent -> PrivacyVerificationSkill -> IncidentAnalysisAgent -> PydanticValidation -> SecureStorageSkill
    wf = Workflow(
        name="SecureCitizenSciencePrivacyWrapper",
        edges=[
            (
                START, 
                preprocess_raw_report, 
                privacy_guard_agent, 
                privacy_verification_skill, 
                incident_analysis_agent, 
                pydantic_validation_layer, 
                secure_storage_skill
            )
        ]
    )
    
    return wf

class TrendAnalysisOutput(BaseModel):
    most_frequent_hazard: str = Field(description="The hazard category that is reported most frequently.")
    total_active_reports: int = Field(description="The total number of reports evaluated.")
    active_hotspots: str = Field(description="Generalized locations showing high frequency of hazards.")
    community_advisory: str = Field(description="A 2-3 sentence public advisory statement for the community.")
    admin_diagnostic_notes: str = Field(description="Detailed analytical notes for administrators regarding severity and trends.")

async def analyze_db_trends_async(model_name: str) -> dict:
    """
    Fetches anonymized SQLite rows and runs the TrendAnalysisAgent to extract
    structured environmental trends and advisories.
    """
    db_name = os.environ.get("DATABASE_FILE", "reports.db")
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_name)
    if not os.path.exists(db_path):
        return {
            "most_frequent_hazard": "None",
            "total_active_reports": 0,
            "active_hotspots": "None",
            "community_advisory": "No reports have been submitted yet. The community is clean!",
            "admin_diagnostic_notes": "No database file detected."
        }
        
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT category, location, summary, severity, timestamp FROM reports")
        rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        return {
            "most_frequent_hazard": "Error",
            "total_active_reports": 0,
            "active_hotspots": "Error",
            "community_advisory": f"Database read failure: {str(e)}",
            "admin_diagnostic_notes": f"Exception raised: {str(e)}"
        }

    if not rows:
        return {
            "most_frequent_hazard": "None",
            "total_active_reports": 0,
            "active_hotspots": "None",
            "community_advisory": "No reports have been submitted yet. The community is clean!",
            "admin_diagnostic_notes": "Database table is empty."
        }

    # Format the rows as plain text logs for the LLM
    formatted_logs = []
    for idx, r in enumerate(rows):
        formatted_logs.append(
            f"Report #{idx+1}: Timestamp='{r[4]}', Category='{r[0]}', Location='{r[1]}', Severity='{r[3]}', Summary='{r[2]}'"
        )
    logs_input = "\n".join(formatted_logs)

    # Initialize the Trend Analysis LLM Agent
    trend_agent = Agent(
        model=model_name,
        name="TrendAnalysisAgent",
        description="Analyzes anonymized database records and extracts structured environmental hazard trends.",
        instruction=(
            "You are the Trend Analysis Agent.\n"
            "Your task is to analyze the provided list of anonymized environmental incident reports.\n"
            "Identify the most frequent category of hazard, count the total reports, note any active geographic hotspots (generalized locations),\n"
            "generate a friendly 2-3 sentence public advisory statement, and write diagnostic notes for administrators.\n"
            "You must output JSON matching the required schema."
        ),
        output_schema=TrendAnalysisOutput,
        output_key="trend_analysis_output"
    )

    from google.adk.sessions import InMemorySessionService
    from google.adk import Runner
    from google.genai import types

    session_service = InMemorySessionService()
    runner = Runner(node=trend_agent, session_service=session_service, auto_create_session=True)

    content = types.Content(parts=[types.Part(text=f"Analyze these reports:\n\n{logs_input}")], role="user")

    # Run the agent node
    async for _ in runner._run_node_async(
        user_id="analyst",
        session_id="trend_analysis_session",
        new_message=content
    ):
        pass

    # Retrieve output from session state
    session = await session_service.get_session(
        app_name=runner.app_name,
        user_id="analyst",
        session_id="trend_analysis_session"
    )
    final_output = session.state.get("trend_analysis_output")

    if not final_output:
        raise RuntimeError("Trend Analysis Agent returned no output.")
        
    if isinstance(final_output, dict):
        return final_output
    else:
        return final_output.model_dump()

def analyze_db_trends(model_name: str) -> dict:
    """Synchronous wrapper to run trend analysis in an event loop."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(analyze_db_trends_async(model_name))
