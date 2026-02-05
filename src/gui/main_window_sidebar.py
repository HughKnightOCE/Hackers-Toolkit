"""
Hackers Toolkit v2.3.0 - Main Window with Sidebar Navigation
Cleaner interface with tool categories instead of flat tab bar
"""

import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QStackedWidget, QLabel, QPushButton, QScrollArea, QFrame, QSplitter, QMessageBox
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont

from tools.port_scanner import PortScanner
from tools.dns_lookup import DNSLookup
from tools.ip_geolocation import IPGeolocation
from tools.ssl_analyzer import SSLAnalyzer
from tools.network_recon import NetworkRecon
from tools.vulnerability_scanner import VulnerabilityScanner
from tools.password_analyzer import PasswordAnalyzer
from tools.hash_analyzer import HashAnalyzer
from tools.ip_finder import IPFinder
from tools.ddos_analyzer import DDoSAnalyzer
from tools.http_headers import HTTPHeaderAnalyzer
from tools.subdomain_enum import SubdomainEnumerator
from tools.whois_lookup import WHOISLookup
from tools.cve_database import CVEDatabase
from tools.load_tester import LoadTester
from tools.network_stress import NetworkStressSimulator
from tools.blockchain_analyzer import BlockchainAnalyzer
from tools.reverse_dns import ReverseDNSLookup
from tools.sql_injection_tester import SQLInjectionTester
from tools.xss_scanner import XSSScanner
from tools.packet_sniffer import PacketSniffer
from tools.firewall_analyzer import FirewallRulesAnalyzer
from tools.audit_log_analyzer import AuditLogAnalyzer
from tools.directory_traversal_scanner import DirectoryTraversalScanner
from tools.command_injection_tester import CommandInjectionTester
from tools.cors_analyzer import CORSAnalyzer
from utils.logger import Logger
from .settings import SettingsDialog
from .stylesheet import get_stylesheet
from .blockchain_analyzer_tab import BlockchainAnalyzerTab
from .reverse_dns_tab import ReverseDNSTab
from .offensive_tools_tabs import SQLInjectionTab, DirectoryTraversalTab, CommandInjectionTab, CORSTab

logger = Logger.get_logger("MainWindow")
APP_VERSION = "2.3.0"
DEVELOPER = "H.Knight"


class DashboardTab(QWidget):
    """Main dashboard with toolkit overview"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        title = QLabel("Hackers Toolkit Dashboard")
        title.setStyleSheet("font-weight: bold; font-size: 16px; color: #00ccff;")
        layout.addWidget(title)
        
        info = QLabel(
            f"Professional Security Analysis Platform v{APP_VERSION}\n\n"
            f"Select a tool from the sidebar to begin analysis.\n\n"
            f"24 Tools Available:\n"
            f"• 6 Network Reconnaissance Tools\n"
            f"• 3 Web Security Tools\n"
            f"• 3 Offensive Security Tools\n"
            f"• 2 Defensive Security Tools\n"
            f"• 5 Data Analysis Tools\n"
            f"• 3 Threat Detection Tools\n"
            f"• 2 Cryptocurrency Tools\n"
            f"• 1 Testing Tool"
        )
        info.setStyleSheet("color: #e0e0e0; padding: 20px;")
        layout.addWidget(info)
        
        layout.addStretch()
        self.setLayout(layout)


class PortScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = PortScanner()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("Port Scanner")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        info = QLabel("Scan for open ports on target hosts")
        layout.addWidget(info)
        
        layout.addStretch()
        self.setLayout(layout)


class SimpleToolTab(QWidget):
    def __init__(self, tool_name, description):
        super().__init__()
        layout = QVBoxLayout()
        
        title = QLabel(tool_name)
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        desc = QLabel(description)
        desc.setStyleSheet("color: #a0a0a0; padding: 10px;")
        layout.addWidget(desc)
        
        layout.addStretch()
        self.setLayout(layout)


class MainWindow(QMainWindow):
    """Main application window with sidebar navigation"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Hackers Toolkit v{APP_VERSION}")
        self.setGeometry(50, 50, 1400, 800)
        self.setStyleSheet(get_stylesheet())
        
        # Create main layout
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        
        # Sidebar
        self.sidebar = self.create_sidebar()
        
        # Content area
        self.content = QStackedWidget()
        self.create_content_pages()
        
        # Add to layout
        main_layout.addWidget(self.sidebar, 1)
        main_layout.addWidget(self.content, 4)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Show dashboard on startup
        self.content.setCurrentIndex(0)
    
    def create_sidebar(self):
        """Create navigation sidebar with categories"""
        sidebar = QFrame()
        sidebar.setStyleSheet("background-color: #2d2d44; border-right: 2px solid #0099ff;")
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Tools")
        header.setStyleSheet("font-weight: bold; font-size: 12px; color: #00ccff; padding: 10px;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Categories
        categories = {
            'Dashboard': ['Dashboard'],
            'Network': [
                'Port Scanner',
                'DNS Lookup',
                'IP Geolocation',
                'WHOIS Lookup',
                'Subdomains',
                'Network Recon',
                'Reverse DNS'
            ],
            'Web Security': [
                'SSL Analyzer',
                'HTTP Headers',
                'Vuln Scanner',
                'SQL Injection',
                'XSS Scanner',
                'Directory Traversal',
                'CORS Analyzer'
            ],
            'Offensive Testing': [
                'Command Injection'
            ],
            'Threat Detection': [
                'DDoS Analyzer',
                'IP Finder',
                'CVE Database'
            ],
            'Defense': [
                'Packet Sniffer',
                'Firewall Rules',
                'Audit Logs'
            ],
            'Analysis': [
                'Password Analyzer',
                'Hash Analyzer',
                'Blockchain'
            ],
            'Testing': [
                'Load Tester',
                'Network Stress'
            ]
        }
        
        self.tool_index = {}
        page_num = 0
        
        for category, tools in categories.items():
            # Category label
            cat_label = QLabel(category)
            cat_label.setStyleSheet("font-weight: bold; color: #0099ff; padding: 8px 0px 5px 10px; font-size: 10px;")
            layout.addWidget(cat_label)
            
            # Tools in category
            for tool in tools:
                btn = QPushButton(tool)
                btn.setMaximumHeight(35)
                btn.setStyleSheet(
                    "QPushButton { text-align: left; padding-left: 15px; font-size: 10px; }"
                    "QPushButton:hover { background-color: #0099ff; }"
                )
                btn.clicked.connect(lambda checked, t=tool: self.select_tool(t))
                layout.addWidget(btn)
                
                self.tool_index[tool] = page_num
                page_num += 1
        
        layout.addStretch()
        
        # Footer
        footer = QLabel(f"v{APP_VERSION}\nBy {DEVELOPER}")
        footer.setStyleSheet("font-size: 8px; color: #666666; text-align: center; padding: 10px;")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer)
        
        sidebar.setLayout(layout)
        sidebar.setMaximumWidth(200)
        
        return sidebar
    
    def create_content_pages(self):
        """Create content pages for each tool"""
        # Dashboard
        self.content.addWidget(DashboardTab())
        
        # Network tools
        self.content.addWidget(SimpleToolTab("Port Scanner", "Scan for open ports on target hosts"))
        self.content.addWidget(SimpleToolTab("DNS Lookup", "Query DNS records (A, MX, NS, TXT)"))
        self.content.addWidget(SimpleToolTab("IP Geolocation", "Locate IP addresses geographically"))
        self.content.addWidget(SimpleToolTab("WHOIS Lookup", "Domain and IP registration info"))
        self.content.addWidget(SimpleToolTab("Subdomain Enumeration", "Find subdomains of target domain"))
        self.content.addWidget(SimpleToolTab("Network Reconnaissance", "Comprehensive network analysis"))
        self.content.addWidget(ReverseDNSTab())
        
        # Web Security tools
        self.content.addWidget(SimpleToolTab("SSL/TLS Analyzer", "Analyze SSL certificates"))
        self.content.addWidget(SimpleToolTab("HTTP Headers Analyzer", "Inspect HTTP response headers"))
        self.content.addWidget(SimpleToolTab("Vulnerability Scanner", "Scan for web vulnerabilities"))
        self.content.addWidget(SQLInjectionTab())
        self.content.addWidget(SimpleToolTab("XSS Scanner", "Detect cross-site scripting vulnerabilities"))
        self.content.addWidget(DirectoryTraversalTab())
        self.content.addWidget(CORSTab())
        
        # Offensive Testing
        self.content.addWidget(CommandInjectionTab())
        
        # Threat Detection
        self.content.addWidget(SimpleToolTab("DDoS Analyzer", "Analyze DDoS attack patterns"))
        self.content.addWidget(SimpleToolTab("IP Finder", "Find your public IP information"))
        self.content.addWidget(SimpleToolTab("CVE Database", "Search vulnerability database"))
        
        # Defense
        self.content.addWidget(SimpleToolTab("Packet Sniffer", "Capture and analyze network traffic"))
        self.content.addWidget(SimpleToolTab("Firewall Rules Analyzer", "Analyze firewall configurations"))
        self.content.addWidget(SimpleToolTab("Audit Log Analyzer", "Parse and analyze security logs"))
        
        # Analysis
        self.content.addWidget(SimpleToolTab("Password Analyzer", "Evaluate password strength"))
        self.content.addWidget(SimpleToolTab("Hash Analyzer", "Identify hash types"))
        self.content.addWidget(BlockchainAnalyzerTab())
        
        # Testing
        self.content.addWidget(SimpleToolTab("Load Tester", "Perform load testing on URLs"))
        self.content.addWidget(SimpleToolTab("Network Stress Simulator", "Simulate network stress"))
    
    def select_tool(self, tool_name):
        """Switch to selected tool"""
        if tool_name in self.tool_index:
            page_num = self.tool_index[tool_name]
            self.content.setCurrentIndex(page_num)
            self.statusBar().showMessage(f"Loaded: {tool_name}")
            logger.info(f"Tool selected: {tool_name}")


def main():
    """Application entry point"""
    app = QMainWindow()
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
