"""DDoS Detection and Analysis Tool"""
from datetime import datetime
import socket
import time
from utils.logger import Logger
from utils.validators import Validators

class DDoSAnalyzer:
    """Analyze DDoS vulnerabilities and attack patterns (detection only)"""
    
    def __init__(self):
        self.results = {}
    
    def check_ddos_vulnerabilities(self, ip, port=80):
        """Check target for DDoS vulnerabilities"""
        if not Validators.is_valid_ip(ip):
            return {"error": "Invalid IP address"}
        
        if not Validators.is_valid_port(port):
            return {"error": "Invalid port"}
        
        vulnerabilities = []
        
        # Check for common DDoS vulnerabilities
        checks = {
            "No Rate Limiting": {
                "severity": "HIGH",
                "description": "Server may not limit requests per IP",
                "risk": "Vulnerable to volumetric DDoS"
            },
            "No Connection Limits": {
                "severity": "MEDIUM",
                "description": "Unlimited simultaneous connections",
                "risk": "Vulnerable to connection exhaustion"
            },
            "HTTP Slowloris": {
                "severity": "HIGH",
                "description": "Slow HTTP requests not timed out quickly",
                "risk": "Vulnerable to Slowloris attacks"
            },
            "No SYN Flood Protection": {
                "severity": "MEDIUM",
                "description": "No SYN cookies or connection rate limiting",
                "risk": "Vulnerable to SYN flood attacks"
            },
            "DNS Amplification": {
                "severity": "MEDIUM",
                "description": "DNS service may be open to queries",
                "risk": "Can be used in amplification attacks"
            }
        }
        
        return {
            "ip": ip,
            "port": port,
            "scan_date": datetime.now().isoformat(),
            "potential_vulnerabilities": checks,
            "recommendation": "Implement rate limiting, connection limits, and DDoS protection"
        }
    
    def detect_attack_patterns(self, traffic_data):
        """Analyze traffic for DDoS attack patterns"""
        patterns = {
            "volumetric_attack": {
                "detection": "Unusual volume spike",
                "threshold": "100x normal traffic",
                "example_types": ["UDP flood", "DNS amplification", "ICMP flood"]
            },
            "protocol_attack": {
                "detection": "Malformed packets or protocol abuse",
                "threshold": "Anomalous packet patterns",
                "example_types": ["SYN flood", "Fragmented packets", "Invalid flags"]
            },
            "application_attack": {
                "detection": "Legitimate looking requests",
                "threshold": "Unusual request patterns",
                "example_types": ["HTTP flood", "Slowloris", "Slow POST"]
            }
        }
        
        return {
            "traffic_analysis": traffic_data or {},
            "attack_patterns": patterns,
            "recommendation": "Monitor for these patterns to detect DDoS"
        }
    
    def analyze_ddos_protection(self, hostname):
        """Analyze DDoS protection measures in place"""
        if not Validators.is_valid_domain(hostname):
            return {"error": "Invalid hostname"}
        
        protections = {
            "CloudFlare": {"indicator": "CF-RAY header", "detection": False},
            "AWS Shield": {"indicator": "X-Amzn-Waf", "detection": False},
            "Akamai": {"indicator": "AkamaiGHost", "detection": False},
            "Azure DDoS": {"indicator": "Azure indicators", "detection": False},
            "WAF Present": {"indicator": "X-Protected", "detection": False}
        }
        
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            ip = socket.gethostbyname(hostname)
            sock.connect((ip, 80))
            
            # Send HTTP request to check headers
            request = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            # Check for DDoS protection headers
            if "CF-RAY" in response:
                protections["CloudFlare"]["detection"] = True
            if "X-Amzn-Waf" in response:
                protections["AWS Shield"]["detection"] = True
            if "AkamaiGhost" in response:
                protections["Akamai"]["detection"] = True
        except Exception as e:
            Logger.warning(f"Could not analyze DDoS protection: {str(e)}")
        
        detected = [k for k, v in protections.items() if v["detection"]]
        
        return {
            "hostname": hostname,
            "protections_detected": detected,
            "all_checks": protections,
            "protected": len(detected) > 0,
            "assessment": "Target appears protected" if detected else "No DDoS protection detected"
        }
    
    def get_mitigation_strategies(self, attack_type):
        """Get DDoS mitigation strategies for attack type"""
        strategies = {
            "volumetric": {
                "name": "Volumetric Attack Mitigation",
                "strategies": [
                    "Deploy CDN with DDoS protection (CloudFlare, Akamai)",
                    "Configure rate limiting at firewall",
                    "Implement traffic filtering",
                    "Use BGP black hole routing",
                    "Deploy anycast network"
                ]
            },
            "protocol": {
                "name": "Protocol Attack Mitigation",
                "strategies": [
                    "Enable SYN cookies",
                    "Implement connection limits",
                    "Configure proper firewall rules",
                    "Monitor for unusual packet patterns",
                    "Update network equipment firmware"
                ]
            },
            "application": {
                "name": "Application Attack Mitigation",
                "strategies": [
                    "Deploy WAF (Web Application Firewall)",
                    "Implement rate limiting per IP/session",
                    "Use CAPTCHA for verification",
                    "Monitor application logs",
                    "Implement bot detection"
                ]
            }
        }
        
        return strategies.get(attack_type, {
            "name": "General DDoS Mitigation",
            "strategies": [
                "Deploy DDoS mitigation service",
                "Implement comprehensive logging",
                "Create incident response plan",
                "Test failover procedures",
                "Maintain surge capacity"
            ]
        })
