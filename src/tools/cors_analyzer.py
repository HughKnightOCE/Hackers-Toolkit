import requests
from typing import Dict, List
from urllib.parse import urlparse
from utils.logger import Logger

logger = Logger.get_logger("CORSAnalyzer")


class CORSAnalyzer:
    """Analyze CORS configuration for security misconfigurations"""

    def __init__(self):
        self.timeout = 10

    def analyze_endpoint(self, url: str, origin: str = "http://attacker.com") -> Dict:
        """Analyze CORS headers on an endpoint"""
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        results = {
            "url": url,
            "vulnerable": False,
            "issues": [],
            "headers": {}
        }

        try:
            headers = {"Origin": origin}
            response = requests.options(url, headers=headers, timeout=self.timeout, allow_redirects=False)
            
            cors_headers = {
                "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
                "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials"),
                "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
                "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
            }
            
            results["headers"] = cors_headers
            self._check_misconfigurations(results, cors_headers, origin)
            
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"CORS analysis failed: {str(e)}")

        return results

    def _check_misconfigurations(self, results: Dict, headers: Dict, origin: str):
        """Check for CORS misconfigurations"""
        allow_origin = headers.get("Access-Control-Allow-Origin", "")
        allow_creds = headers.get("Access-Control-Allow-Credentials", "").lower()
        
        if allow_origin == "*":
            results["vulnerable"] = True
            results["issues"].append("Wildcard '*' allows all origins to access resource")
        
        if allow_origin == origin:
            results["issues"].append(f"Origin {origin} is explicitly allowed (may indicate overly permissive config)")
        
        if allow_origin and allow_creds == "true":
            results["vulnerable"] = True
            results["issues"].append("Allow-Origin combined with Credentials=true allows credential theft")
        
        if not allow_origin:
            results["issues"].append("No CORS headers found - endpoint may block cross-origin requests")

    def test_multiple_origins(self, url: str, origins: List[str] = None) -> List[Dict]:
        """Test multiple origins against the endpoint"""
        if origins is None:
            origins = [
                "http://localhost",
                "http://127.0.0.1",
                "http://attacker.com",
                "http://subdomain.target.com",
                "*"
            ]
        
        results = []
        for origin in origins:
            result = self.analyze_endpoint(url, origin)
            results.append(result)
        
        return results

    def check_preflight_request(self, url: str, method: str = "POST", headers: Dict = None) -> Dict:
        """Check how server handles preflight CORS requests"""
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        results = {"url": url, "preflight_allowed": False, "methods": []}
        
        try:
            preflight_headers = {
                "Origin": "http://attacker.com",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": headers or "Content-Type, Authorization"
            }
            
            response = requests.options(url, headers=preflight_headers, timeout=self.timeout)
            
            if response.status_code in [200, 204]:
                results["preflight_allowed"] = True
                results["methods"] = response.headers.get("Access-Control-Allow-Methods", "").split(",")
            
        except Exception as e:
            logger.error(f"Preflight check failed: {str(e)}")

        return results
