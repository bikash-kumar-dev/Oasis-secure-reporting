import sqlite3
import os
import sys
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("SecureStorageServer")
DB_NAME = os.environ.get("DATABASE_FILE", "reports.db")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)

def init_db():
    """Ensure database table exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_hash TEXT NOT NULL,
            category TEXT NOT NULL,
            location TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

@mcp.tool()
def secure_log_incident(user_hash: str, category: str, location: str, summary: str, severity: str) -> dict:
    """
    Securely store a sanitized environmental incident report into the SQLite database.
    This tool receives ONLY sanitized and validated data and completely isolates database access.

    Args:
        user_hash: A SHA-256 hashed string representing the anonymous user.
        category: The hazard category (e.g. 'Water Pollution', 'Illegal Dumping').
        location: The generalized location of the incident (e.g. 'Lake View Area, Bangalore').
        summary: A short, concise summary of the incident.
        severity: The severity level of the incident ('Low', 'Medium', 'High', 'Critical').

    Returns:
        A dict containing confirmation of success, the generated incident ID, and privacy statements.
    """
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO reports (user_hash, category, location, summary, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (user_hash, category, location, summary, severity))
        conn.commit()
        row_id = cursor.lastrowid
        conn.close()

        # Generate a unique incident ID format, e.g. INC-1042 where 42 is the database ID
        incident_id = f"INC-{1000 + row_id}"
        
        # Log to stderr since stdout is reserved for JSON-RPC stdio transport
        print(f"Stored incident {incident_id} successfully in DB.", file=sys.stderr)
        
        return {
            "status": "Success",
            "incident_id": incident_id,
            "message": "Your report has been securely processed and stored.",
            "privacy": "No personal information was retained."
        }
    except Exception as e:
        print(f"Error in secure_log_incident: {str(e)}", file=sys.stderr)
        return {
            "status": "Error",
            "message": f"Database insertion failed: {str(e)}"
        }

if __name__ == "__main__":
    # Initialize DB on server start
    init_db()
    # Run the server using stdio transport
    mcp.run(transport="stdio")
