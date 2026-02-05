"""Subdomain Enumerator Tool"""
import socket
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class SubdomainEnumerator:
    """Enumerate subdomains of target domain"""
    
    def __init__(self):
        # Common subdomains wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'ssh', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'admin',
            'test', 'staging', 'dev', 'blog', 'news', 'cms', 'cart', 'shop',
            'cdn', 'mobile', 'app', 'mail2', 'mail3', 'imap', 'server', 'chat',
            'vpn', 'git', 'gitlab', 'github', 'jenkins', 'confluence', 'jira',
            'wiki', 'forum', 'kb', 'support', 'helpdesk', 'monitor', 'backup',
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'oracle'
        ]
    
    def enumerate_subdomains(self, domain):
        """Enumerate subdomains using brute force"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            results = {
                "domain": domain,
                "found_subdomains": [],
                "failed_lookups": 0,
                "scan_date": datetime.now().isoformat(),
                "total_checked": 0
            }
            
            for subdomain in self.common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                results["total_checked"] += 1
                
                try:
                    ip = socket.gethostbyname(full_domain)
                    results["found_subdomains"].append({
                        "subdomain": full_domain,
                        "ip": ip,
                        "type": self._determine_service(subdomain)
                    })
                    Logger.info(f"Found subdomain: {full_domain} -> {ip}")
                except socket.gaierror:
                    results["failed_lookups"] += 1
                except Exception as e:
                    results["failed_lookups"] += 1
            
            results["found_count"] = len(results["found_subdomains"])
            return results
        except Exception as e:
            Logger.error(f"Subdomain enumeration error: {str(e)}")
            return {"error": str(e)}
    
    def check_subdomain_takeover(self, subdomains):
        """Check for subdomain takeover vulnerabilities"""
        results = {
            "vulnerable_subdomains": [],
            "safe_subdomains": [],
            "scan_date": datetime.now().isoformat()
        }
        
        takeover_patterns = {
            'NXDOMAIN': 'Subdomain exists in DNS but points to nothing',
            'CNAME_Unknown': 'CNAME points to unknown service',
            'HTTP_404': 'Subdomain responds with 404'
        }
        
        for subdomain in subdomains:
            try:
                socket.gethostbyname(subdomain)
                results["safe_subdomains"].append(subdomain)
            except socket.gaierror:
                results["vulnerable_subdomains"].append({
                    "subdomain": subdomain,
                    "vulnerability": "Potential takeover",
                    "risk": "Domain points to nothing, can be claimed"
                })
        
        return results
    
    def find_wildcard_subdomain(self, domain):
        """Check if domain uses wildcard DNS"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            # Try to resolve a random subdomain
            test_subdomain = f"xyzrandom{int(__import__('time').time())}.{domain}"
            
            try:
                ip = socket.gethostbyname(test_subdomain)
                return {
                    "domain": domain,
                    "wildcard_enabled": True,
                    "wildcard_ip": ip,
                    "risk": "All subdomains resolve to same IP - wildcard DNS detected",
                    "recommendation": "Check if this is intentional"
                }
            except socket.gaierror:
                return {
                    "domain": domain,
                    "wildcard_enabled": False,
                    "recommendation": "Wildcard DNS not found"
                }
        except Exception as e:
            Logger.error(f"Wildcard check error: {str(e)}")
            return {"error": str(e)}
    
    def check_tld_variants(self, domain):
        """Check common TLD variants of domain"""
        if not '.' in domain:
            return {"error": "Invalid domain"}
        
        try:
            base_name = domain.split('.')[0]
            tlds = [
                '.com', '.net', '.org', '.io', '.co', '.us', '.uk', '.de',
                '.fr', '.au', '.ca', '.jp', '.cn', '.in', '.br', '.ru'
            ]
            
            results = {
                "base_name": base_name,
                "original_domain": domain,
                "variants_found": []
            }
            
            for tld in tlds:
                variant = f"{base_name}{tld}"
                if variant == domain:
                    continue
                
                try:
                    ip = socket.gethostbyname(variant)
                    results["variants_found"].append({
                        "domain": variant,
                        "ip": ip,
                        "registered": True
                    })
                except socket.gaierror:
                    pass
            
            return results
        except Exception as e:
            Logger.error(f"TLD variant check error: {str(e)}")
            return {"error": str(e)}
    
    def _determine_service(self, subdomain):
        """Determine service type from subdomain name"""
        service_mapping = {
            'mail': 'Email',
            'ftp': 'FTP Server',
            'ssh': 'SSH Access',
            'webmail': 'Webmail',
            'smtp': 'SMTP',
            'api': 'API',
            'admin': 'Admin Panel',
            'cdn': 'Content Delivery',
            'git': 'Version Control',
            'vpn': 'VPN',
            'db': 'Database',
            'app': 'Application'
        }
        
        for key, service in service_mapping.items():
            if key in subdomain.lower():
                return service
        
        return "Unknown"
