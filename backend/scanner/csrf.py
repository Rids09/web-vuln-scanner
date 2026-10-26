from utils.payloads import CSRF_SAFE_TOKEN_NAMES
from utils.logger import get_logger

logger = get_logger("csrf")


class CSRFScanner:
    def __init__(self, request_handler):
        self.rh = request_handler

    def _form_has_csrf_token(self, form):
        input_names = [inp["name"].lower() for inp in form["inputs"]]
        return any(token.lower() in input_names for token in CSRF_SAFE_TOKEN_NAMES)

    def _check_cookie_flags(self, url):
        findings = []
        resp = self.rh.get(url)
        if resp is None:
            return findings

        for cookie in resp.cookies:
            flags_missing = []
            # requests' cookie object exposes 'secure'; samesite is in rest_options
            if not cookie.secure:
                flags_missing.append("Secure")
            samesite = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
            if not samesite:
                flags_missing.append("SameSite")

            if flags_missing:
                findings.append({
                    "type": "Insecure Cookie Configuration",
                    "location": url,
                    "parameter": cookie.name,
                    "payload": "N/A",
                    "evidence": f"Missing flag(s): {', '.join(flags_missing)}",
                    "method": "GET"
                })
        return findings

    def scan(self, pages):
        results = []
        checked_cookie_urls = set()

        for page in pages:
            url = page["url"]

            if url not in checked_cookie_urls:
                results.extend(self._check_cookie_flags(url))
                checked_cookie_urls.add(url)

            for form in page["forms"]:
                if form["method"] == "post" and not self._form_has_csrf_token(form):
                    results.append({
                        "type": "CSRF - Missing Token",
                        "location": form["action"],
                        "parameter": "N/A",
                        "payload": "N/A",
                        "evidence": "State-changing POST form has no CSRF token field",
                        "method": "POST"
                    })

        logger.info(f"CSRF scan complete: {len(results)} finding(s)")
        return results
