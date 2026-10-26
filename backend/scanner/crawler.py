from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import Config
from utils.logger import get_logger

logger = get_logger("crawler")


class Crawler:
    """Breadth-first crawler limited to the target's own domain.
    Collects visited pages and any HTML forms found on them, which
    the vulnerability modules then test."""

    def __init__(self, base_url, request_handler):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(self.base_url).netloc
        self.rh = request_handler
        self.visited = set()
        self.pages = []   # list of {"url": ..., "forms": [...]}

    def _same_domain(self, url):
        return urlparse(url).netloc in ("", self.domain)

    def _extract_links(self, html, current_url):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            full = urljoin(current_url, a["href"])
            full = full.split("#")[0]
            if self._same_domain(full) and full.startswith(("http://", "https://")):
                links.add(full)
        return links

    def _extract_forms(self, html, current_url):
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or current_url
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text")
                    })
            forms.append({
                "action": urljoin(current_url, action),
                "method": method,
                "inputs": inputs
            })
        return forms

    def crawl(self):
        queue = [(self.base_url, 0)]
        self.visited.add(self.base_url)

        while queue:
            url, depth = queue.pop(0)
            resp = self.rh.get(url)
            if resp is None or resp.status_code >= 400:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            forms = self._extract_forms(resp.text, url)
            self.pages.append({"url": url, "forms": forms})
            logger.info(f"Crawled {url} ({len(forms)} form(s) found)")

            if len(self.visited) >= Config.MAX_CRAWL_PAGES or depth >= Config.MAX_CRAWL_DEPTH:
                continue

            for link in self._extract_links(resp.text, url):
                if link not in self.visited and len(self.visited) < Config.MAX_CRAWL_PAGES:
                    self.visited.add(link)
                    queue.append((link, depth + 1))

        return self.pages
