"""DNS lookup and analysis tool"""
import socket
import dns.resolver
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class DNSLookup:
    """DNS lookup and analysis"""
    
    def __init__(self):
        self.results = {}
    
    def lookup_a_record(self, domain):
        """Look up A records"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            records = []
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                records.append(str(rdata))
            
            return {
                "domain": domain,
                "record_type": "A",
                "records": records,
                "count": len(records)
            }
        except Exception as e:
            Logger.warning(f"A record lookup failed: {str(e)}")
            return {"error": str(e)}
    
    def lookup_mx_record(self, domain):
        """Look up MX records"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                records.append({
                    "priority": rdata.preference,
                    "exchange": str(rdata.exchange)
                })
            
            return {
                "domain": domain,
                "record_type": "MX",
                "records": sorted(records, key=lambda x: x['priority']),
                "count": len(records)
            }
        except Exception as e:
            Logger.warning(f"MX record lookup failed: {str(e)}")
            return {"error": str(e)}
    
    def lookup_ns_record(self, domain):
        """Look up NS records"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            records = []
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                records.append(str(rdata))
            
            return {
                "domain": domain,
                "record_type": "NS",
                "records": records,
                "count": len(records)
            }
        except Exception as e:
            Logger.warning(f"NS record lookup failed: {str(e)}")
            return {"error": str(e)}
    
    def lookup_txt_record(self, domain):
        """Look up TXT records"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            records = []
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                records.append(str(rdata))
            
            return {
                "domain": domain,
                "record_type": "TXT",
                "records": records,
                "count": len(records)
            }
        except Exception as e:
            Logger.warning(f"TXT record lookup failed: {str(e)}")
            return {"error": str(e)}
    
    def full_dns_lookup(self, domain):
        """Perform full DNS lookup"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        results = {
            "domain": domain,
            "lookup_time": datetime.now().isoformat(),
            "a_records": self.lookup_a_record(domain),
            "mx_records": self.lookup_mx_record(domain),
            "ns_records": self.lookup_ns_record(domain),
            "txt_records": self.lookup_txt_record(domain)
        }
        
        Logger.info(f"Full DNS lookup completed for {domain}")
        return results
