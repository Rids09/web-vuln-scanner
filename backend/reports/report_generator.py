import os
import json
from datetime import datetime
from config import Config

try:
    from weasyprint import HTML
    from jinja2 import Environment, FileSystemLoader
    PDF_AVAILABLE = True
except (ImportError, OSError):
    PDF_AVAILABLE = False


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def generate_json_report(scan_data: dict) -> str:
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    filename = f"scan_{scan_data['id']}.json"
    path = os.path.join(Config.REPORTS_DIR, filename)
    with open(path, "w") as f:
        json.dump(scan_data, f, indent=2)
    return path


def generate_pdf_report(scan_data: dict) -> str:
    if not PDF_AVAILABLE:
        raise RuntimeError(
            "PDF generation requires 'weasyprint' and 'jinja2'. "
            "Install with: pip install weasyprint jinja2"
        )

    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in scan_data.get("findings", []):
        severity_counts[finding.get("severity", "Low")] = \
            severity_counts.get(finding.get("severity", "Low"), 0) + 1

    html_content = template.render(
        scan=scan_data,
        findings=scan_data.get("findings", []),
        severity_counts=severity_counts,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )

    filename = f"scan_{scan_data['id']}.pdf"
    path = os.path.join(Config.REPORTS_DIR, filename)
    HTML(string=html_content).write_pdf(path)
    return path
