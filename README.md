# 🛡️ Secure Citizen-Science Privacy Wrapper

A multi-agent privacy wrapper for citizen-science environmental hazard reporting. The system uses **Google Agent Development Kit (ADK)** and a custom **Model Context Protocol (MCP)** server to automatically sanitize raw reports, extract key structured information, deterministically verify PII removal, and save only anonymized and validated data into a secure SQLite database.

## 🚀 Setup & Execution

### Prerequisites
* Python 3.11+
* `uv` package manager (optional, but recommended)

### 1. Installation
Install the project dependencies in your environment:
```bash
# If using uv
uv pip install -r requirements.txt

# Or if using standard pip
pip install -r requirements.txt
```

### 2. Set Up Environment Variables (Optional)
Create a `.env` file in the root of the project:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(Alternatively, you can type your Gemini API key directly into the sidebar of the Streamlit application at runtime).*

### 3. Run the Streamlit UI
Start the web application:
```bash
streamlit run app.py
```

### 4. Run Automated Logic Verification
To verify the full sequential workflow, MCP connection, and SQLite schema integrity:
```bash
python verify_project.py
```

---

## 📐 System Architecture

1.  **Streamlit Web UI**: Accepts reports, showcases status updates, compares before/after text, and allows direct database exploration.
2.  **ADK Root Agent (Workflow)**: Orchestrates the sequential pipeline.
3.  **PII Preprocessor**: Saves the raw input for anonymous user hash generation.
4.  **Privacy Guard Agent**: Redacts user details and generalizes exact locations using LLM soft-redaction instructions.
5.  **Privacy Verification Skill**: Runs hard-coded regular expressions to detect email patterns, phone formats, PAN card formats, and Aadhaar numbers. Interrupts execution immediately upon detection.
6.  **Incident Analysis Agent**: Categorizes and extracts structured details conforming to a Pydantic schema.
7.  **Pydantic Validation**: Ensures fields conform strictly to constraints.
8.  **Secure Storage Skill**: Starts the custom MCP storage server process.
9.  **Custom MCP Server**: Communicates via stdio transport and writes sanitized reports to the SQLite database, completely isolating direct DB writes.

---

## ☁️ Deployment on Streamlit Community Cloud

To deploy this application to **Streamlit Community Cloud** (share.streamlit.io):

1.  **Push to GitHub**:
    Initialize a Git repository, commit your files, and push them to GitHub. Make sure your `.gitignore` excludes `.venv`, `__pycache__`, and the database files (`*.db`, `test_reports.db`).

2.  **Deploy on share.streamlit.io**:
    *   Sign in to [Streamlit Share](https://share.streamlit.io) using your GitHub account.
    *   Click **New app**.
    *   Select your repository, branch, and set the Main file path to `app.py`.

3.  **Configure Secrets**:
    *   In the App settings page, navigate to **Secrets**.
    *   Add your Gemini API Key so the app can access it automatically without user input:
        ```toml
        GEMINI_API_KEY = "your-gemini-api-key-value-here"
        ```
    *   Click **Save**. The application will redeploy automatically and run with the secure key loaded.

