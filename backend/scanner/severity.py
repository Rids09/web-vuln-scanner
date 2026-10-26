# Maps vulnerability types to a severity rating and a plain-English
# explanation of the risk + a remediation tip. Used to enrich raw
# findings before they're stored/reported.

SEVERITY_MAP = {
    "SQL Injection": {
        "severity": "Critical",
        "explanation": (
            "An attacker can manipulate this input to alter the SQL query "
            "the application runs, potentially reading, modifying, or "
            "deleting data in the database, or bypassing authentication."
        ),
        "remediation": "Use parameterized queries / prepared statements. Never build SQL with string concatenation."
    },
    "SQL Injection (time-based)": {
        "severity": "Critical",
        "explanation": (
            "The response time changed when a delay payload was sent, "
            "suggesting the input reaches the database layer unsanitized "
            "even though no error was directly visible."
        ),
        "remediation": "Use parameterized queries / prepared statements and validate input types."
    },
    "Reflected XSS": {
        "severity": "High",
        "explanation": (
            "User input is echoed back into the page without proper "
            "encoding, allowing an attacker to run arbitrary JavaScript "
            "in a victim's browser (e.g. via a crafted link), enabling "
            "session hijacking or credential theft."
        ),
        "remediation": "Context-aware output encoding (HTML-escape user input) and a Content-Security-Policy header."
    },
    "CSRF - Missing Token": {
        "severity": "Medium",
        "explanation": (
            "This form performs a state-changing action without a CSRF "
            "token, so an attacker could trick a logged-in user's browser "
            "into submitting it unintentionally from another site."
        ),
        "remediation": "Add a per-session anti-CSRF token to every state-changing form and verify it server-side."
    },
    "Insecure Cookie Configuration": {
        "severity": "Low",
        "explanation": (
            "Cookies without the Secure/SameSite flags can be exposed over "
            "unencrypted connections or sent along with cross-site requests."
        ),
        "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict on all session cookies."
    },
    "Open Port": {
        "severity": "Informational",
        "explanation": (
            "An open network port indicates a running service that could "
            "be a larger attack surface if unpatched or misconfigured."
        ),
        "remediation": "Close unused ports; restrict access via firewall to only what's needed."
    },
}

DEFAULT_ENTRY = {
    "severity": "Low",
    "explanation": "No detailed explanation available for this finding type.",
    "remediation": "Review manually."
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def enrich_finding(finding: dict) -> dict:
    info = SEVERITY_MAP.get(finding["type"], DEFAULT_ENTRY)
    finding["severity"] = info["severity"]
    finding["explanation"] = info["explanation"]
    finding["remediation"] = info["remediation"]
    return finding


def enrich_all(findings: list) -> list:
    enriched = [enrich_finding(f) for f in findings]
    enriched.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
    return enriched
