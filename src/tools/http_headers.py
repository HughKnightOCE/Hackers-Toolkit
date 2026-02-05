"""HTTP Header Security Analyzer"""
import socket
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class HTTPHeaderAnalyzer:
    """Analyze HTTP security headers"""
    
    def __init__(self):
        self.critical_headers = {
            'Strict-Transport-Security': {
                'severity': 'CRITICAL',
                'description': 'Forces HTTPS connection',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000'
            },
            'X-Content-Type-Options': {
                'severity': 'HIGH',
                'description': 'Prevents MIME sniffing attacks',
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            },
            'X-Frame-Options': {
                'severity': 'HIGH',
                'description': 'Prevents clickjacking attacks',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'Content-Security-Policy': {
                'severity': 'HIGH',
                'description': 'Prevents XSS attacks',
                'recommendation': 'Add: Content-Security-Policy: default-src self'
            },
            'X-XSS-Protection': {
                'severity': 'MEDIUM',
                'description': 'Legacy XSS protection',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'severity': 'MEDIUM',
                'description': 'Controls referrer information',
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
            }
        }
    
    def check_headers(self, hostname, port=443):
        """Check HTTP security headers"""
        if not (Validators.is_valid_domain(hostname) or Validators.is_valid_ip(hostname)):
            return {"error": "Invalid hostname or IP"}
        
        if not Validators.is_valid_port(port):
            return {"error": "Invalid port"}
        
        try:
            results = {
                "hostname": hostname,
                "port": port,
                "scan_date": datetime.now().isoformat(),
                "present_headers": {},
                "missing_headers": [],
                "security_score": 0,
                "vulnerabilities": []
            }
            
            # Simulate header retrieval (would use requests in production)
            mock_headers = self._get_mock_headers(hostname)
            
            # Check for critical headers
            for header, details in self.critical_headers.items():
                if header in mock_headers:
                    results["present_headers"][header] = {
                        "value": mock_headers[header],
                        "severity": details['severity']
                    }
                    results["security_score"] += 10
                else:
                    results["missing_headers"].append({
                        "header": header,
                        "severity": details['severity'],
                        "recommendation": details['recommendation']
                    })
            
            # Check for insecure headers
            insecure = self._check_insecure_headers(mock_headers)
            results["vulnerabilities"].extend(insecure)
            
            results["security_score"] = min(100, results["security_score"])
            results["security_grade"] = self._get_grade(results["security_score"])
            
            Logger.info(f"HTTP headers analyzed for {hostname}")
            return results
        except Exception as e:
            Logger.error(f"Header analysis error: {str(e)}")
            return {"error": str(e)}
    
    def _get_mock_headers(self, hostname):
        """Get mock headers for demonstration"""
        # In production, would use requests library
        if 'google' in hostname.lower():
            return {
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': "script-src 'nonce-...' 'unsafe-inline' 'unsafe-eval'",
                'X-Frame-Options': 'SAMEORIGIN',
                'X-Content-Type-Options': 'nosniff'
            }
        elif 'github' in hostname.lower():
            return {
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'deny',
                'X-XSS-Protection': '1; mode=block'
            }
        else:
            # Default minimal headers
            return {
                'Server': 'Apache/2.4.41',
                'Content-Type': 'text/html'
            }
    
    def _check_insecure_headers(self, headers):
        """Check for insecure or revealing headers"""
        insecure = []
        
        # Check for version disclosure
        if 'Server' in headers:
            insecure.append({
                "type": "Information Disclosure",
                "header": "Server",
                "value": headers['Server'],
                "severity": "MEDIUM",
                "recommendation": "Remove or obscure server version information"
            })
        
        # Check for X-Powered-By
        if 'X-Powered-By' in headers:
            insecure.append({
                "type": "Technology Disclosure",
                "header": "X-Powered-By",
                "value": headers['X-Powered-By'],
                "severity": "LOW",
                "recommendation": "Remove X-Powered-By header"
            })
        
        return insecure
    
    def _get_grade(self, score):
        """Get security grade based on score"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def get_header_recommendations(self, grade):
        """Get recommendations based on grade"""
        recommendations = {
            "A": "Excellent security headers configuration",
            "B": "Good configuration, consider adding missing headers",
            "C": "Several important headers missing, implement recommendations",
            "D": "Multiple security headers missing, implement immediately",
            "F": "Critical security headers missing, urgent action required"
        }
        
        return recommendations.get(grade, "Unknown grade")
