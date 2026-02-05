"""
Reverse DNS Lookup Tab
PyQt5 GUI component for reverse DNS and service identification
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QCheckBox, 
                            QProgressBar, QMessageBox, QSpinBox)
from PyQt5.QtCore import Qt
from src.tools.reverse_dns import ReverseDNSLookup
from src.utils.logger import Logger

logger = Logger.get_logger("ReverseDNSTab")


class ReverseDNSTab(QWidget):
    """GUI Tab for reverse DNS and service identification"""
    
    def __init__(self):
        super().__init__()
        self.reverse_dns = ReverseDNSLookup()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Reverse DNS Lookup & Service Detection")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #00ccff;")
        layout.addWidget(title_label)
        
        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("IP Address:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 8.8.8.8")
        input_layout.addWidget(self.ip_input)
        layout.addLayout(input_layout)
        
        # Advanced options
        options_layout = QHBoxLayout()
        
        self.port_scan_checkbox = QCheckBox("Scan Common Ports")
        self.port_scan_checkbox.setChecked(True)
        options_layout.addWidget(self.port_scan_checkbox)
        
        options_layout.addWidget(QLabel("Port Range Start:"))
        self.port_start = QSpinBox()
        self.port_start.setValue(21)
        self.port_start.setMinimum(1)
        self.port_start.setMaximum(65535)
        options_layout.addWidget(self.port_start)
        
        options_layout.addWidget(QLabel("Port Range End:"))
        self.port_end = QSpinBox()
        self.port_end.setValue(443)
        self.port_end.setMinimum(1)
        self.port_end.setMaximum(65535)
        options_layout.addWidget(self.port_end)
        
        layout.addLayout(options_layout)
        
        # Button section
        button_layout = QHBoxLayout()
        
        lookup_btn = QPushButton("Reverse Lookup")
        lookup_btn.clicked.connect(self.perform_lookup)
        button_layout.addWidget(lookup_btn)
        
        service_btn = QPushButton("Get Service Names")
        service_btn.clicked.connect(self.get_services)
        button_layout.addWidget(service_btn)
        
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_btn)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results area
        results_label = QLabel("Lookup Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(300)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def perform_lookup(self):
        """Perform reverse DNS lookup"""
        ip = self.ip_input.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address")
            return
        
        try:
            self.progress.setVisible(True)
            self.results_text.clear()
            
            # Perform reverse lookup
            hostname = self.reverse_dns.reverse_lookup(ip)
            output = f"=== Reverse DNS Lookup Results ===\n\n"
            output += f"IP Address: {ip}\n"
            output += f"Hostname: {hostname if hostname else 'Not found'}\n\n"
            
            # If port scanning enabled
            if self.port_scan_checkbox.isChecked():
                output += "=== Service Detection ===\n\n"
                port_start = self.port_start.value()
                port_end = self.port_end.value()
                
                ports = list(range(port_start, port_end + 1))
                result = self.reverse_dns.reverse_lookup_with_ports(ip, ports)
                
                if result.get("open_ports"):
                    output += "Open Ports Found:\n"
                    for port_info in result.get("open_ports", []):
                        output += f"  Port {port_info.get('port')}: {port_info.get('service', 'Unknown')}\n"
                else:
                    output += "No open ports detected in specified range.\n"
                
                if result.get("services"):
                    output += f"\nDetected Services: {', '.join(result.get('services', []))}\n"
            
            self.results_text.setText(output)
            
        except Exception as e:
            logger.error(f"Lookup error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Lookup failed: {str(e)}")
        finally:
            self.progress.setVisible(False)
    
    def get_services(self):
        """Display service names for common ports"""
        try:
            self.progress.setVisible(True)
            
            port_start = self.port_start.value()
            port_end = self.port_end.value()
            
            ports = list(range(port_start, port_end + 1))
            services = self.reverse_dns.get_service_names(ports)
            
            output = "=== Common Port Services ===\n\n"
            for port, service in services.items():
                output += f"Port {port}: {service}\n"
            
            self.results_text.setText(output)
            
        except Exception as e:
            logger.error(f"Service retrieval error: {str(e)}")
            self.results_text.setText(f"Error: {str(e)}")
        finally:
            self.progress.setVisible(False)
    
    def clear_results(self):
        """Clear all results and inputs"""
        self.ip_input.clear()
        self.results_text.clear()
        self.port_scan_checkbox.setChecked(True)
        self.port_start.setValue(21)
        self.port_end.setValue(443)
