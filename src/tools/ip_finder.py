"""IP Finder tool - discover and map IP addresses"""
import socket
import re
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class IPFinder:
    """Find and enumerate IP addresses from various sources"""
    
    def __init__(self):
        self.results = {}
    
    def find_ips_from_domain(self, domain):
        """Find all IPs associated with a domain"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            results = {
                "domain": domain,
                "ips": [],
                "ipv6": [],
                "cname": None,
                "aliases": []
            }
            
            # Get IPv4 addresses
            try:
                info = socket.gethostbyname_ex(domain)
                results["cname"] = info[0]
                results["aliases"] = info[1]
                results["ips"] = info[2]
            except socket.gaierror as e:
                Logger.warning(f"IPv4 lookup failed: {str(e)}")
            
            # Try to get IPv6 addresses
            try:
                ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                ipv6_list = list(set([addr[4][0] for addr in ipv6_info]))
                results["ipv6"] = ipv6_list
            except socket.gaierror:
                pass
            
            Logger.info(f"Found {len(results['ips'])} IPs for {domain}")
            return results
        except Exception as e:
            Logger.error(f"IP finder error: {str(e)}")
            return {"error": str(e)}
    
    def reverse_ip_lookup(self, ip):
        """Reverse IP lookup - find domains pointing to IP"""
        if not Validators.is_valid_ip(ip):
            return {"error": "Invalid IP address"}
        
        try:
            hostname = socket.gethostbyaddr(ip)
            return {
                "ip": ip,
                "hostname": hostname[0],
                "aliases": hostname[1],
                "addresses": hostname[2]
            }
        except socket.herror:
            return {
                "ip": ip,
                "error": "No reverse DNS entry found"
            }
        except Exception as e:
            Logger.error(f"Reverse lookup error: {str(e)}")
            return {"error": str(e)}
    
    def find_ip_range(self, domain):
        """Find IP range for organization"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            # Extract organization name from domain
            org = domain.split('.')[0].upper()
            
            # Get primary IP
            primary_ip = socket.gethostbyname(domain)
            
            # Try to find pattern in IP space (simplified)
            # In production, use real AS/WHOIS data
            ip_parts = primary_ip.split('.')
            base = '.'.join(ip_parts[:3])
            
            return {
                "domain": domain,
                "primary_ip": primary_ip,
                "estimated_range": f"{base}.0/24",
                "note": "Use WHOIS tool for precise IP range"
            }
        except Exception as e:
            Logger.error(f"IP range error: {str(e)}")
            return {"error": str(e)}
    
    def find_subdomains_by_ip(self, ip):
        """Find subdomains hosting on same IP"""
        if not Validators.is_valid_ip(ip):
            return {"error": "Invalid IP address"}
        
        # This would normally query services like SecurityTrails
        # For now, return informational result
        return {
            "ip": ip,
            "note": "Subdomain enumeration via IP requires API keys",
            "recommendation": "Configure SecurityTrails or VirusTotal API in Settings"
        }
    
    def enumerate_ip_space(self, ip, range_size=256):
        """Enumerate active IPs in a range (limited for safety)"""
        if not Validators.is_valid_ip(ip):
            return {"error": "Invalid IP address"}
        
        try:
            # Parse IP
            ip_parts = ip.split('.')
            base = '.'.join(ip_parts[:3])
            
            active_hosts = []
            checked = 0
            
            # Only check first 50 IPs for safety (don't overwhelm network)
            for i in range(1, 51):
                test_ip = f"{base}.{i}"
                try:
                    socket.gethostbyaddr(test_ip)
                    active_hosts.append(test_ip)
                except:
                    pass
                checked += 1
            
            return {
                "base_range": f"{base}.0/24",
                "checked": checked,
                "active_hosts": active_hosts,
                "percentage_active": f"{(len(active_hosts)/checked*100):.1f}%"
            }
        except Exception as e:
            Logger.error(f"Enumeration error: {str(e)}")
            return {"error": str(e)}
