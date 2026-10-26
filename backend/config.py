import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "scan_results.db")

    # Scanner behavior
    REQUEST_TIMEOUT = 8          # seconds per HTTP request
    MAX_CRAWL_PAGES = 40         # cap so a scan can't run forever
    MAX_CRAWL_DEPTH = 2
    THREADS = 10                 # for port scanning
    USER_AGENT = "WebVulnScanner/1.0 (+authorized-security-testing)"

    # Port scan
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                    3306, 3389, 5432, 6379, 8000, 8080, 8443]
    PORT_SCAN_TIMEOUT = 1.0

    # Reports
    REPORTS_DIR = os.path.join(BASE_DIR, "reports", "generated")
