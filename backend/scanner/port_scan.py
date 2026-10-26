import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from config import Config
from utils.logger import get_logger

logger = get_logger("port_scan")

COMMON_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}


class PortScanner:
    def __init__(self):
        self.timeout = Config.PORT_SCAN_TIMEOUT

    def _check_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    return port
        except socket.error:
            pass
        return None

    def scan(self, target_url):
        host = urlparse(target_url).netloc.split(":")[0] or target_url
        findings = []

        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            logger.warning(f"Could not resolve host: {host}")
            return findings

        with ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port
                for port in Config.COMMON_PORTS
            }
            for future in as_completed(futures):
                port = future.result()
                if port:
                    service = COMMON_SERVICE_NAMES.get(port, "Unknown")
                    findings.append({
                        "type": "Open Port",
                        "location": host,
                        "parameter": str(port),
                        "payload": "N/A",
                        "evidence": f"Port {port} ({service}) is open",
                        "method": "TCP"
                    })

        logger.info(f"Port scan complete: {len(findings)} open port(s)")
        return sorted(findings, key=lambda f: int(f["parameter"]))
