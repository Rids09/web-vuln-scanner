import time
from urllib.parse import urlparse, parse_qs
from utils.payloads import SQLI_PAYLOADS, SQL_ERROR_SIGNATURES
from utils.logger import get_logger

logger = get_logger("sql_injection")


class SQLInjectionScanner:
    def __init__(self, request_handler):
        self.rh = request_handler

    def _has_sql_error(self, text):
        if not text:
            return False
        lowered = text.lower()
        return any(sig.lower() in lowered for sig in SQL_ERROR_SIGNATURES)

    def _test_params(self, url):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        base = url.split("?")[0]
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload

                start = time.time()
                resp = self.rh.get(base, params=test_params)
                elapsed = time.time() - start
                if resp is None:
                    continue

                if self._has_sql_error(resp.text):
                    findings.append({
                        "type": "SQL Injection",
                        "location": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": "Database error signature returned",
                        "method": "GET"
                    })
                    break  # one confirmed hit per parameter is enough
                elif "SLEEP" in payload.upper() and elapsed > 2.5:
                    findings.append({
                        "type": "SQL Injection (time-based)",
                        "location": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Response delayed {elapsed:.1f}s, suggesting payload executed",
                        "method": "GET"
                    })
                    break
        return findings

    def _test_forms(self, page_url, forms):
        findings = []
        for form in forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]
            if not inputs:
                continue

            for target_input in inputs:
                for payload in SQLI_PAYLOADS:
                    data = {inp["name"]: "test" for inp in inputs}
                    data[target_input["name"]] = payload

                    start = time.time()
                    if method == "post":
                        resp = self.rh.post(action, data=data)
                    else:
                        resp = self.rh.get(action, params=data)
                    elapsed = time.time() - start
                    if resp is None:
                        continue

                    if self._has_sql_error(resp.text):
                        findings.append({
                            "type": "SQL Injection",
                            "location": action,
                            "parameter": target_input["name"],
                            "payload": payload,
                            "evidence": "Database error signature returned",
                            "method": method.upper()
                        })
                        break
                    elif "SLEEP" in payload.upper() and elapsed > 2.5:
                        findings.append({
                            "type": "SQL Injection (time-based)",
                            "location": action,
                            "parameter": target_input["name"],
                            "payload": payload,
                            "evidence": f"Response delayed {elapsed:.1f}s",
                            "method": method.upper()
                        })
                        break
        return findings

    def scan(self, pages):
        """pages: list of {"url": ..., "forms": [...]} from the crawler"""
        results = []
        for page in pages:
            results.extend(self._test_params(page["url"]))
            results.extend(self._test_forms(page["url"], page["forms"]))
        logger.info(f"SQL injection scan complete: {len(results)} finding(s)")
        return results
