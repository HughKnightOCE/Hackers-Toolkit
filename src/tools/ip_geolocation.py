"""IP Geolocation tool"""
import json
from utils.logger import Logger
from utils.validators import Validators
from utils.api_handler import APIHandler

class IPGeolocation:
    """IP geolocation and information lookup"""
    
    def __init__(self):
        self.api_handler = APIHandler()
    
    def get_ip_info(self, ip):
        """Get IP information from public APIs"""
        if not Validators.is_valid_ip(ip):
            return {"error": "Invalid IP address"}
        
        try:
            # Using ip-api.com free API
            url = f"http://ip-api.com/json/{ip}"
            response = self.api_handler.get(url)
            data = response.json()
            
            if data.get('status') == 'success':
                result = {
                    "ip": ip,
                    "country": data.get('country'),
                    "region": data.get('regionName'),
                    "city": data.get('city'),
                    "latitude": data.get('lat'),
                    "longitude": data.get('lon'),
                    "timezone": data.get('timezone'),
                    "isp": data.get('isp'),
                    "organization": data.get('org'),
                    "asn": data.get('as')
                }
                Logger.info(f"IP info retrieved for {ip}")
                return result
            else:
                return {"error": "IP lookup failed"}
        except Exception as e:
            Logger.error(f"IP geolocation error: {str(e)}")
            return {"error": str(e)}
    
    def batch_lookup(self, ips):
        """Look up multiple IPs"""
        results = []
        for ip in ips:
            if Validators.is_valid_ip(ip):
                result = self.get_ip_info(ip)
                results.append(result)
        
        return {
            "total": len(results),
            "results": results
        }
    
    def check_ip_reputation(self, ip):
        """Check IP reputation"""
        if not Validators.is_valid_ip(ip):
            return {"error": "Invalid IP address"}
        
        try:
            # Check against AbuseIPDB-like service
            url = f"https://api.abuseipdb.com/api/v2/check"
            # This requires API key - returning placeholder
            result = {
                "ip": ip,
                "reputation": "Unknown",
                "abuse_confidence_score": 0,
                "note": "Full reputation check requires API key configuration"
            }
            Logger.info(f"IP reputation check for {ip}")
            return result
        except Exception as e:
            Logger.error(f"IP reputation check error: {str(e)}")
            return {"error": str(e)}
