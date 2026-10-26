from urllib.parse import urlparse, parse_qs
from utils.payloads import XSS_PAYLOADS
from utils.logger import get_logger

logger = get_logger("xss")


class XSSScanner:
    def __init__(self, request_handler):
        self.rh = request_handler

    def _reflected_unescaped(self, response_text, payload):
        # A real reflected-XSS finding = the payload appears verbatim,
        # not HTML-escaped (&lt;script&gt; would mean it was safely encoded).
        return response_text is not None and payload in response_text

    def _test_params(self, url):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        base = url.split("?")[0]
        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                resp = self.rh.get(base, params=test_params)
                if resp is None:
                    continue

                if self._reflected_unescaped(resp.text, payload):
                    findings.append({
                        "type": "Reflected XSS",
                        "location": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": "Payload reflected unescaped in response HTML",
                        "method": "GET"
                    })
                    break
        return findings

    def _test_forms(self, forms):
        findings = []
        for form in forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]
            if not inputs:
                continue

            for target_input in inputs:
                for payload in XSS_PAYLOADS:
                    data = {inp["name"]: "test" for inp in inputs}
                    data[target_input["name"]] = payload

                    resp = self.rh.post(action, data=data) if method == "post" \
                        else self.rh.get(action, params=data)
                    if resp is None:
                        continue

                    if self._reflected_unescaped(resp.text, payload):
                        findings.append({
                            "type": "Reflected XSS",
                            "location": action,
                            "parameter": target_input["name"],
                            "payload": payload,
                            "evidence": "Payload reflected unescaped in response HTML",
                            "method": method.upper()
                        })
                        break
        return findings

    def scan(self, pages):
        results = []
        for page in pages:
            results.extend(self._test_params(page["url"]))
            results.extend(self._test_forms(page["forms"]))
        logger.info(f"XSS scan complete: {len(results)} finding(s)")
        return results
