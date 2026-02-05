"""WHOIS Lookup Tool"""
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

try:
    import whois
except ImportError:
    whois = None

class WHOISLookup:
    """WHOIS domain information lookup"""
    
    def __init__(self):
        if whois is None:
            Logger.warning("whois module not installed. Install with: pip install whois")
    
    def lookup_domain(self, domain):
        """Perform WHOIS lookup on domain"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        if whois is None:
            return {"error": "whois module not installed"}
        
        try:
            domain_whois = whois.whois(domain)
            
            result = {
                "domain": domain,
                "scan_date": datetime.now().isoformat(),
                "registrar": str(domain_whois.registrar) if domain_whois.registrar else "Unknown",
                "registrant": str(domain_whois.registrant) if hasattr(domain_whois, 'registrant') else "Unknown",
                "creation_date": str(domain_whois.creation_date) if domain_whois.creation_date else "Unknown",
                "expiration_date": str(domain_whois.expiration_date) if domain_whois.expiration_date else "Unknown",
                "updated_date": str(domain_whois.updated_date) if domain_whois.updated_date else "Unknown",
                "status": domain_whois.status if domain_whois.status else [],
                "nameservers": domain_whois.nameservers if domain_whois.nameservers else [],
                "emails": domain_whois.emails if domain_whois.emails else []
            }
            
            Logger.info(f"WHOIS lookup successful for {domain}")
            return result
            
        except Exception as e:
            Logger.error(f"WHOIS lookup error for {domain}: {str(e)}")
            return {"error": f"WHOIS lookup failed: {str(e)}"}
    
    def check_domain_expiry(self, domain):
        """Check domain expiration status"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        if whois is None:
            return {"error": "whois module not installed"}
        
        try:
            domain_whois = whois.whois(domain)
            
            if domain_whois.expiration_date:
                from datetime import datetime as dt
                expiration = domain_whois.expiration_date
                if isinstance(expiration, str):
                    expiration = dt.strptime(expiration, "%Y-%m-%d")
                
                days_remaining = (expiration - dt.now()).days
                
                return {
                    "domain": domain,
                    "expiration_date": str(expiration),
                    "days_remaining": days_remaining,
                    "status": "Valid" if days_remaining > 30 else "Warning - Expiring soon" if days_remaining > 0 else "Expired",
                    "renewal_recommended": days_remaining < 30
                }
            else:
                return {"domain": domain, "error": "Expiration date not found"}
        except Exception as e:
            Logger.error(f"Domain expiry check error: {str(e)}")
            return {"error": str(e)}
    
    def analyze_registrant_privacy(self, domain):
        """Analyze registrant privacy protection"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        if whois is None:
            return {"error": "whois module not installed"}
        
        try:
            domain_whois = whois.whois(domain)
            
            privacy_indicators = {
                "privacy_enabled": False,
                "domain": domain,
                "registrant_hidden": False,
                "admin_hidden": False,
                "tech_hidden": False,
                "risk_level": "Unknown"
            }
            
            # Check for privacy protection patterns
            registrant_str = str(domain_whois.registrant) if hasattr(domain_whois, 'registrant') else ""
            
            if "privacy" in registrant_str.lower() or "protected" in registrant_str.lower():
                privacy_indicators["privacy_enabled"] = True
            
            # Check if emails are masked
            emails = domain_whois.emails if domain_whois.emails else []
            masked_count = sum(1 for e in emails if "privacy" in str(e).lower())
            
            if masked_count > 0:
                privacy_indicators["registrant_hidden"] = True
            
            if privacy_indicators["privacy_enabled"] or privacy_indicators["registrant_hidden"]:
                privacy_indicators["risk_level"] = "Low (Privacy Protected)"
            else:
                privacy_indicators["risk_level"] = "High (Registrant Info Public)"
            
            return privacy_indicators
            
        except Exception as e:
            Logger.error(f"Privacy analysis error: {str(e)}")
            return {"error": str(e)}
    
    def check_nameserver_reputation(self, domain):
        """Check reputation of nameservers"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        if whois is None:
            return {"error": "whois module not installed"}
        
        try:
            domain_whois = whois.whois(domain)
            nameservers = domain_whois.nameservers if domain_whois.nameservers else []
            
            result = {
                "domain": domain,
                "nameserver_count": len(nameservers),
                "nameservers": nameservers,
                "reputation": self._analyze_nameserver_reputation(nameservers)
            }
            
            return result
        except Exception as e:
            Logger.error(f"Nameserver check error: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_nameserver_reputation(self, nameservers):
        """Analyze reputation of nameservers"""
        reputable_providers = [
            'godaddy', 'cloudflare', 'aws', 'google', 'akamai',
            'verisign', 'dnsimple', 'route53', 'ns-cloud'
        ]
        
        reputation = {
            "reputable": [],
            "unknown": [],
            "risk_score": 0
        }
        
        for ns in nameservers:
            ns_lower = str(ns).lower()
            is_reputable = any(provider in ns_lower for provider in reputable_providers)
            
            if is_reputable:
                reputation["reputable"].append(ns)
            else:
                reputation["unknown"].append(ns)
                reputation["risk_score"] += 1
        
        return reputation
