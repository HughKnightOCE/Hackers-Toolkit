"""Port scanning tool"""
import socket
import threading
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class PortScanner:
    """Scan ports on target host"""
    
    def __init__(self):
        self.results = {}
        self.is_scanning = False
    
    def scan_port(self, host, port, timeout=2):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                return True, service
            return False, None
        except socket.gaierror:
            Logger.error(f"Hostname {host} could not be resolved")
            return False, None
        except socket.error:
            Logger.error(f"Could not connect to {host}")
            return False, None
    
    def scan_range(self, host, port_range="1-1000", timeout=2, callback=None):
        """Scan range of ports"""
        if not Validators.is_valid_ip(host) and not Validators.is_valid_domain(host):
            return {"error": "Invalid host"}
        
        self.is_scanning = True
        self.results = {
            "host": host,
            "start_time": datetime.now().isoformat(),
            "open_ports": [],
            "closed_ports": []
        }
        
        # Parse port range
        if "-" in port_range:
            start, end = port_range.split("-")
            ports = range(int(start), int(end) + 1)
        else:
            ports = [int(port_range)]
        
        for port in ports:
            if not self.is_scanning:
                break
            
            is_open, service = self.scan_port(host, port, timeout)
            
            if is_open:
                self.results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })
            else:
                self.results["closed_ports"].append({
                    "port": port,
                    "state": "closed"
                })
            
            if callback:
                callback(port, is_open)
        
        self.results["end_time"] = datetime.now().isoformat()
        Logger.info(f"Port scan completed for {host}")
        self.is_scanning = False
        return self.results
    
    def stop_scan(self):
        """Stop scanning"""
        self.is_scanning = False
    
    def scan_common_ports(self, host, timeout=2, callback=None):
        """Scan only common ports"""
        common_ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
        self.results = {
            "host": host,
            "scan_type": "common_ports",
            "start_time": datetime.now().isoformat(),
            "open_ports": [],
            "closed_ports": []
        }
        
        for port_str in common_ports.split(","):
            port = int(port_str)
            is_open, service = self.scan_port(host, port, timeout)
            
            if is_open:
                self.results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })
            
            if callback:
                callback(port, is_open)
        
        self.results["end_time"] = datetime.now().isoformat()
        return self.results
