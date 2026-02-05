"""Network reconnaissance tool"""
import socket
import struct
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class NetworkRecon:
    """Network reconnaissance and host discovery"""
    
    def __init__(self):
        self.results = {}
    
    def get_dns_records(self, domain):
        """Get DNS records for domain"""
        if not Validators.is_valid_domain(domain):
            return {"error": "Invalid domain"}
        
        try:
            # Get A records
            results = {
                "domain": domain,
                "a_records": [],
                "mx_records": [],
                "ns_records": [],
                "txt_records": []
            }
            
            try:
                a_records = socket.gethostbyname_ex(domain)
                results["a_records"] = a_records[2]
            except socket.error as e:
                Logger.warning(f"Could not get A records: {str(e)}")
            
            Logger.info(f"DNS records retrieved for {domain}")
            return results
        except Exception as e:
            Logger.error(f"DNS lookup error: {str(e)}")
            return {"error": str(e)}
    
    def reverse_dns_lookup(self, ip):
        """Perform reverse DNS lookup"""
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
                "hostname": None,
                "error": "Hostname not found"
            }
        except Exception as e:
            Logger.error(f"Reverse DNS error: {str(e)}")
            return {"error": str(e)}
    
    def get_host_info(self, hostname):
        """Get detailed host information"""
        try:
            results = {
                "hostname": hostname,
                "ip_addresses": [],
                "fqdn": None,
                "aliases": []
            }
            
            host_info = socket.gethostbyname_ex(hostname)
            results["fqdn"] = host_info[0]
            results["aliases"] = host_info[1]
            results["ip_addresses"] = host_info[2]
            
            Logger.info(f"Host info retrieved for {hostname}")
            return results
        except socket.gaierror as e:
            Logger.warning(f"Host lookup failed: {str(e)}")
            return {"error": f"Could not resolve {hostname}"}
        except Exception as e:
            Logger.error(f"Host info error: {str(e)}")
            return {"error": str(e)}
    
    def subnet_scan(self, network):
        """Scan subnet for active hosts"""
        try:
            import ipaddress
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = []
            
            for ip in list(network_obj.hosts())[:10]:  # Limit to 10 for demo
                ip_str = str(ip)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_str, 80))
                    sock.close()
                    
                    if result == 0:
                        hosts.append(ip_str)
                except:
                    pass
            
            return {
                "network": network,
                "discovered_hosts": hosts,
                "count": len(hosts)
            }
        except Exception as e:
            Logger.error(f"Subnet scan error: {str(e)}")
            return {"error": str(e)}
