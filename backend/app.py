import os
import uuid
from flask import Flask, render_template, request, jsonify

# Initialize Flask with custom template and static folders pointing to frontend
app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

# In-memory storage for active scan sessions
scan_sessions = {}

@app.route("/")
def index():
    """Renders the main WAVS dashboard interface."""
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Receives target URL and scan options, initializes a scan job,
    and returns a unique scan_id.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request payload"}), 400

    target_url = data.get("target_url") or data.get("target")
    profile = data.get("profile", "full")
    modules = data.get("modules", [])

    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())[:8]

    # Mock findings for testing connection
    mock_findings = [
        {
            "id": 1,
            "severity": "High",
            "type": "SQL Injection",
            "location": f"{target_url}/login.php",
            "parameter": "username",
            "description": "User input is directly concatenated into SQL queries.",
            "remediation": "Use parameterized queries or prepared statements."
        },
        {
            "id": 2,
            "severity": "Medium",
            "type": "Cross-Site Scripting (XSS)",
            "location": f"{target_url}/search",
            "parameter": "q",
            "description": "Unescaped user input reflected directly in response HTML.",
            "remediation": "Sanitize and encode all output variables."
        }
    ]

    # Save session data
    scan_sessions[scan_id] = {
        "status": "completed",
        "endpoints": 12,
        "requests": 45,
        "findings_count": len(mock_findings),
        "findings": mock_findings
    }

    # Also keep a latest global session for simple /results polling
    scan_sessions["latest"] = scan_sessions[scan_id]

    return jsonify({
        "status": "started",
        "scan_id": scan_id,
        "message": f"Scan initialized successfully against {target_url}"
    })

@app.route("/results", methods=["GET"])
@app.route("/api/results", methods=["GET"])
@app.route("/api/results/<scan_id>", methods=["GET"])
def api_results(scan_id=None):
    """
    Fetches scan telemetry, statistics, and findings.
    """
    if scan_id and scan_id in scan_sessions:
        return jsonify(scan_sessions[scan_id])
    
    # Fallback to latest session or default idle state
    latest = scan_sessions.get("latest")
    if latest:
        return jsonify(latest)

    return jsonify({
        "status": "completed",
        "endpoints": 12,
        "requests": 45,
        "findings_count": 2,
        "findings": [
            {
                "id": 1,
                "severity": "High",
                "type": "SQL Injection",
                "location": "http://testphp.vulnweb.com/login.php",
                "parameter": "username",
                "description": "User input is directly concatenated into SQL queries.",
                "remediation": "Use parameterized queries or prepared statements."
            }
        ]
    })

@app.route("/report/pdf", methods=["GET"])
@app.route("/api/report/pdf/<scan_id>", methods=["GET"])
def generate_pdf_report(scan_id=None):
    return jsonify({"message": "PDF report generation endpoint"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)