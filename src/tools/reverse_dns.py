"""
Reverse DNS Lookup Tool - Reverse IP to Domain Resolution
"""

import socket
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class ReverseDNSLookup:
    """Reverse DNS lookup tool for IP addresses"""
    
    def __init__(self):
        self.logger = Logger()
        self.validators = Validators()
    
    def reverse_lookup(self, ip_address):
        """
        Perform reverse DNS lookup on IP address
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            dict: Hostname and related information
        """
        try:
            if not self.validators.is_valid_ip(ip_address):
                return {"error": "Invalid IP address format"}
            
            try:
                hostname, aliaslist, addresslist = socket.gethostbyaddr(ip_address)
                
                result = {
                    "ip_address": ip_address,
                    "hostname": hostname,
                    "aliases": aliaslist,
                    "address_list": addresslist,
                    "reverse_dns_found": True,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.logger.info(f"Reverse DNS lookup successful for {ip_address}: {hostname}")
                return result
                
            except socket.herror:
                return {
                    "ip_address": ip_address,
                    "reverse_dns_found": False,
                    "message": "No reverse DNS record found",
                    "timestamp": datetime.now().isoformat()
                }
            
        except Exception as e:
            self.logger.error(f"Reverse DNS lookup error: {str(e)}")
            return {"error": str(e)}
    
    def bulk_reverse_lookup(self, ip_list):
        """
        Perform reverse lookup on multiple IPs
        
        Args:
            ip_list: List of IP addresses
            
        Returns:
            dict: Results for all IPs
        """
        results = {}
        for ip in ip_list:
            results[ip] = self.reverse_lookup(ip)
        return results
    
    def reverse_lookup_with_ports(self, ip_address, ports=None):
        """
        Reverse lookup with common port scanning
        
        Args:
            ip_address: Target IP
            ports: List of ports to check (default: common ports)
            
        Returns:
            dict: Hostname and open ports
        """
        if ports is None:
            ports = [21, 22, 25, 53, 80, 443, 445, 3306, 5432, 8080]
        
        dns_result = self.reverse_lookup(ip_address)
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        dns_result["open_ports"] = open_ports
        return dns_result
    
    def get_service_names(self, ports):
        """
        Get service names for ports
        
        Args:
            ports: List of port numbers
            
        Returns:
            dict: Port to service mapping
        """
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            5432: "PostgreSQL",
            5984: "CouchDB",
            6379: "Redis",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt",
            27017: "MongoDB"
        }
        
        return {port: service_map.get(port, "Unknown") for port in ports}
