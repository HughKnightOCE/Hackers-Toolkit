"""
Packet Sniffer and Analyzer
Captures and analyzes network packets for security analysis
"""

import socket
import struct
import textwrap
from datetime import datetime
from src.utils.logger import Logger

logger = Logger.get_logger("PacketSniffer")


class PacketSniffer:
    """Captures and analyzes network traffic"""
    
    def __init__(self):
        self.packets_captured = 0
        self.packet_data = []
    
    def start_capture(self, interface=None, packet_count=10, timeout=30):
        """Start packet capture session"""
        try:
            result = {
                'interface': interface,
                'packets_requested': packet_count,
                'timestamp_start': datetime.now().isoformat(),
                'packets_captured': 0,
                'packets': [],
                'protocols': {}
            }
            
            # For actual packet capture, we'd use scapy
            try:
                from scapy.all import sniff, IP, TCP, UDP
                
                def packet_callback(pkt):
                    packet_info = self._parse_packet(pkt)
                    result['packets'].append(packet_info)
                    
                    # Track protocol statistics
                    proto = packet_info.get('protocol', 'Other')
                    result['protocols'][proto] = result['protocols'].get(proto, 0) + 1
                
                sniff(prn=packet_callback, count=packet_count, timeout=timeout, store=False)
                result['packets_captured'] = len(result['packets'])
                
            except ImportError:
                logger.warning("Scapy not available, running in demo mode")
                result['mode'] = 'demo'
                result['packets_captured'] = 0
            
            result['timestamp_end'] = datetime.now().isoformat()
            return result
        
        except Exception as e:
            logger.error(f"Capture error: {str(e)}")
            return {'error': str(e)}
    
    def _parse_packet(self, pkt):
        """Parse packet into readable format"""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(pkt),
                'protocol': 'Unknown'
            }
            
            if IP in pkt:
                ip_layer = pkt[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['ttl'] = ip_layer.ttl
                
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    packet_info['flags'] = str(tcp_layer.flags)
                
                elif UDP in pkt:
                    udp_layer = pkt[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                
                elif ICMP in pkt:
                    packet_info['protocol'] = 'ICMP'
                    packet_info['icmp_type'] = pkt[ICMP].type
            
            return packet_info
        
        except Exception as e:
            logger.debug(f"Parse error: {str(e)}")
            return {'error': str(e)}
    
    def analyze_traffic(self, packets):
        """Analyze captured packets"""
        analysis = {
            'total_packets': len(packets),
            'protocols': {},
            'top_ips': {},
            'top_ports': {},
            'suspicious_patterns': []
        }
        
        for pkt in packets:
            # Protocol distribution
            proto = pkt.get('protocol', 'Other')
            analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1
            
            # IP analysis
            if 'src_ip' in pkt:
                src = pkt['src_ip']
                analysis['top_ips'][src] = analysis['top_ips'].get(src, 0) + 1
            
            # Port analysis
            if 'dst_port' in pkt:
                port = pkt['dst_port']
                analysis['top_ports'][port] = analysis['top_ports'].get(port, 0) + 1
        
        return analysis
    
    def detect_patterns(self, packets):
        """Detect suspicious patterns in traffic"""
        patterns = {
            'port_scans': [],
            'unusual_protocols': [],
            'large_packets': []
        }
        
        for pkt in packets:
            # Check for large packets (potential data exfiltration)
            if pkt.get('size', 0) > 5000:
                patterns['large_packets'].append(pkt)
            
            # Check for uncommon ports
            port = pkt.get('dst_port')
            if port and port not in [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080]:
                patterns['unusual_protocols'].append(pkt)
        
        return patterns
