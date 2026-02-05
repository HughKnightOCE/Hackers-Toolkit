"""
Network Stress Simulator - Network Condition Simulation Tool
Simulates various network conditions for testing
"""

import subprocess
import platform
import time
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class NetworkStressSimulator:
    """Simulate network stress conditions for testing"""
    
    def __init__(self):
        self.logger = Logger()
        self.validators = Validators()
        self.is_windows = platform.system() == "Windows"
        self.is_linux = platform.system() == "Linux"
        self.active_rules = []
        
    def simulate_packet_loss(self, interface, loss_percentage=10):
        """
        Simulate packet loss on network interface
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            loss_percentage: Percentage of packets to drop (0-100)
            
        Returns:
            dict: Simulation status
        """
        try:
            if loss_percentage < 0 or loss_percentage > 100:
                return {"error": "Loss percentage must be between 0-100"}
            
            if self.is_linux:
                # Linux: use tc (traffic control)
                cmd = f"sudo tc qdisc add dev {interface} root netem loss {loss_percentage}%"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.active_rules.append({
                        "type": "packet_loss",
                        "interface": interface,
                        "loss": loss_percentage,
                        "timestamp": datetime.now().isoformat()
                    })
                    self.logger.info(f"Packet loss simulated on {interface}: {loss_percentage}%")
                    return {
                        "status": "success",
                        "interface": interface,
                        "loss_percentage": loss_percentage,
                        "method": "tc (Linux)"
                    }
                else:
                    return {"error": result.stderr}
            
            else:
                return {"error": "Packet loss simulation requires Linux (tc command)"}
                
        except Exception as e:
            self.logger.error(f"Packet loss simulation error: {str(e)}")
            return {"error": str(e)}
    
    def simulate_latency(self, interface, latency_ms=100):
        """
        Simulate network latency
        
        Args:
            interface: Network interface name
            latency_ms: Latency in milliseconds
            
        Returns:
            dict: Simulation status
        """
        try:
            if latency_ms < 0:
                return {"error": "Latency must be positive"}
            
            if self.is_linux:
                cmd = f"sudo tc qdisc add dev {interface} root netem delay {latency_ms}ms"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.active_rules.append({
                        "type": "latency",
                        "interface": interface,
                        "latency_ms": latency_ms,
                        "timestamp": datetime.now().isoformat()
                    })
                    self.logger.info(f"Latency simulated on {interface}: {latency_ms}ms")
                    return {
                        "status": "success",
                        "interface": interface,
                        "latency_ms": latency_ms,
                        "method": "tc (Linux)"
                    }
                else:
                    return {"error": result.stderr}
            
            else:
                return {"error": "Latency simulation requires Linux (tc command)"}
                
        except Exception as e:
            self.logger.error(f"Latency simulation error: {str(e)}")
            return {"error": str(e)}
    
    def simulate_bandwidth_limit(self, interface, bandwidth_kbps):
        """
        Simulate bandwidth throttling
        
        Args:
            interface: Network interface name
            bandwidth_kbps: Maximum bandwidth in Kbps
            
        Returns:
            dict: Simulation status
        """
        try:
            if bandwidth_kbps <= 0:
                return {"error": "Bandwidth must be positive"}
            
            if self.is_linux:
                cmd = f"sudo tc qdisc add dev {interface} root tbf rate {bandwidth_kbps}kbit burst 32kbit latency 400ms"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.active_rules.append({
                        "type": "bandwidth_limit",
                        "interface": interface,
                        "bandwidth_kbps": bandwidth_kbps,
                        "timestamp": datetime.now().isoformat()
                    })
                    self.logger.info(f"Bandwidth limited on {interface}: {bandwidth_kbps}kbps")
                    return {
                        "status": "success",
                        "interface": interface,
                        "bandwidth_kbps": bandwidth_kbps,
                        "method": "tc (Linux)"
                    }
                else:
                    return {"error": result.stderr}
            
            else:
                return {"error": "Bandwidth limiting requires Linux (tc command)"}
                
        except Exception as e:
            self.logger.error(f"Bandwidth limit error: {str(e)}")
            return {"error": str(e)}
    
    def combine_conditions(self, interface, latency_ms=0, loss_percentage=0, bandwidth_kbps=0):
        """
        Combine multiple network conditions
        
        Args:
            interface: Network interface
            latency_ms: Latency in milliseconds
            loss_percentage: Packet loss percentage
            bandwidth_kbps: Bandwidth limit in Kbps
            
        Returns:
            dict: Combined simulation status
        """
        try:
            if self.is_linux:
                # Build netem command with multiple parameters
                params = []
                
                if latency_ms > 0:
                    params.append(f"delay {latency_ms}ms")
                
                if loss_percentage > 0:
                    params.append(f"loss {loss_percentage}%")
                
                if params:
                    netem_cmd = " ".join(params)
                    cmd = f"sudo tc qdisc add dev {interface} root netem {netem_cmd}"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode != 0:
                        return {"error": result.stderr}
                
                # Apply bandwidth limit separately if specified
                if bandwidth_kbps > 0:
                    cmd = f"sudo tc class add dev {interface} parent 1: classid 1:1 htb rate {bandwidth_kbps}kbit"
                    subprocess.run(cmd, shell=True, capture_output=True)
                
                self.active_rules.append({
                    "type": "combined",
                    "interface": interface,
                    "latency_ms": latency_ms,
                    "loss_percentage": loss_percentage,
                    "bandwidth_kbps": bandwidth_kbps,
                    "timestamp": datetime.now().isoformat()
                })
                
                self.logger.info(f"Combined conditions applied to {interface}")
                return {
                    "status": "success",
                    "interface": interface,
                    "latency_ms": latency_ms,
                    "loss_percentage": loss_percentage,
                    "bandwidth_kbps": bandwidth_kbps,
                    "method": "tc (Linux)"
                }
            
            else:
                return {"error": "Network condition simulation requires Linux"}
                
        except Exception as e:
            self.logger.error(f"Combined condition error: {str(e)}")
            return {"error": str(e)}
    
    def clear_all_rules(self, interface):
        """
        Clear all network conditions from interface
        
        Args:
            interface: Network interface name
            
        Returns:
            dict: Clear status
        """
        try:
            if self.is_linux:
                cmd = f"sudo tc qdisc del dev {interface} root"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.active_rules = [r for r in self.active_rules if r.get('interface') != interface]
                    self.logger.info(f"All network rules cleared for {interface}")
                    return {
                        "status": "success",
                        "interface": interface,
                        "message": "All rules cleared"
                    }
                else:
                    return {"error": result.stderr}
            
            else:
                return {"error": "Requires Linux"}
                
        except Exception as e:
            self.logger.error(f"Clear rules error: {str(e)}")
            return {"error": str(e)}
    
    def get_active_rules(self):
        """Get list of active simulation rules"""
        return {
            "platform": "Linux" if self.is_linux else platform.system(),
            "active_rules": self.active_rules,
            "note": "Network simulation requires Linux with tc (traffic control) and sudo access"
        }
    
    def get_available_interfaces(self):
        """Get available network interfaces"""
        try:
            if self.is_linux:
                result = subprocess.run("ip link show | grep '^[0-9]'", shell=True, 
                                      capture_output=True, text=True)
                interfaces = [line.split(':')[1].strip() for line in result.stdout.split('\n') if line]
                return {"interfaces": interfaces}
            else:
                return {"error": "Interface listing requires Linux", 
                       "note": "Common interfaces: eth0, wlan0, docker0"}
        except Exception as e:
            return {"error": str(e)}
