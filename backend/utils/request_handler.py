import requests
from requests.exceptions import RequestException
from config import Config
from utils.logger import get_logger

logger = get_logger("request_handler")


class RequestHandler:
    """Thin wrapper around requests so every scanner module shares
    the same timeout, headers, and error-handling behavior."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.USER_AGENT})

    def get(self, url, params=None, allow_redirects=True):
        try:
            return self.session.get(
                url, params=params, timeout=Config.REQUEST_TIMEOUT,
                allow_redirects=allow_redirects
            )
        except RequestException as e:
            logger.warning(f"GET failed for {url}: {e}")
            return None

    def post(self, url, data=None, allow_redirects=True):
        try:
            return self.session.post(
                url, data=data, timeout=Config.REQUEST_TIMEOUT,
                allow_redirects=allow_redirects
            )
        except RequestException as e:
            logger.warning(f"POST failed for {url}: {e}")
            return None
