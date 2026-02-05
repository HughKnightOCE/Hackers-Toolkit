"""
XSS Vulnerability Scanner
Identifies cross-site scripting vulnerabilities in web applications
"""

import requests
from datetime import datetime
from src.utils.logger import Logger

logger = Logger.get_logger("XSSScanner")


class XSSScanner:
    """Detects XSS vulnerabilities in web forms"""
    
    def __init__(self):
        self.test_payloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror="alert(\'xss\')">',
            '<svg onload="alert(\'xss\')">',
            '"><script>alert(\'xss\')</script>',
            '<iframe src="javascript:alert(\'xss\')">',
            '<body onload="alert(\'xss\')">',
            '<input onfocus="alert(\'xss\')" autofocus>',
            'javascript:alert("xss")',
            '<marquee onstart="alert(\'xss\')">',
        ]
        
        self.timeout = 5
    
    def scan_endpoint(self, url, param_name, method='GET'):
        """Scan endpoint for XSS vulnerabilities"""
        results = {
            'url': url,
            'parameter': param_name,
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'payloads_tested': 0,
            'found_payloads': []
        }
        
        try:
            for payload in self.test_payloads:
                results['payloads_tested'] += 1
                
                try:
                    if method.upper() == 'GET':
                        params = {param_name: payload}
                        resp = requests.get(url, params=params, timeout=self.timeout, verify=False)
                    else:
                        data = {param_name: payload}
                        resp = requests.post(url, data=data, timeout=self.timeout, verify=False)
                    
                    if self._check_reflection(resp.text, payload):
                        results['vulnerable'] = True
                        results['found_payloads'].append({
                            'payload': payload,
                            'reflected': True
                        })
                except requests.exceptions.RequestException:
                    continue
        
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _check_reflection(self, response_body, payload):
        """Check if payload is reflected in response"""
        if not response_body:
            return False
        
        # Check if the payload appears in response
        if payload in response_body:
            return True
        
        # Check for URL encoded version
        if requests.utils.quote(payload) in response_body:
            return True
        
        return False
    
    def scan_forms(self, url):
        """Scan all forms on a page for XSS"""
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False)
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            results = {
                'url': url,
                'forms_found': len(forms),
                'scan_results': []
            }
            
            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    param_name = input_field.get('name', 'unknown')
                    action = form.get('action', url)
                    method = form.get('method', 'GET').upper()
                    
                    scan_result = self.scan_endpoint(action, param_name, method)
                    results['scan_results'].append(scan_result)
            
            return results
        
        except Exception as e:
            logger.error(f"Form scan error: {str(e)}")
            return {'error': str(e)}
