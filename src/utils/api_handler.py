"""API handler for external services"""
import requests
from .logger import Logger

class APIHandler:
    """Handle API calls to external services"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
    
    def get(self, url, params=None, headers=None):
        """Make GET request"""
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            Logger.error(f"API GET request failed: {str(e)}")
            raise
    
    def post(self, url, data=None, json=None, headers=None):
        """Make POST request"""
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            Logger.error(f"API POST request failed: {str(e)}")
            raise
    
    def set_proxy(self, proxy_url):
        """Set proxy for requests"""
        proxies = {'http': proxy_url, 'https': proxy_url}
        self.session.proxies.update(proxies)
    
    def set_headers(self, headers):
        """Set default headers"""
        self.session.headers.update(headers)
