"""
Modern Main GUI Window for Hackers Toolkit
Professional interface with menu system and modern styling
"""
import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QComboBox, QSpinBox, QProgressBar, QStatusBar, QMessageBox, QFileDialog,
    QMenuBar, QMenu, QDialog, QFormLayout, QAction
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QIcon, QFont, QColor

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
from utils.logger import Logger
from .settings import SettingsDialog
from .stylesheet import get_stylesheet
from .blockchain_analyzer_tab import BlockchainAnalyzerTab
from .reverse_dns_tab import ReverseDNSTab

logger = Logger.get_logger("MainWindow")
APP_VERSION = "2.2.0"
DEVELOPER = "H.Knight"
YEAR = "2026"


class WorkerThread(QThread):
    """Worker thread for background operations"""
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, task_func, *args, **kwargs):
        super().__init__()
        self.task_func = task_func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            result = self.task_func(*self.args, **self.kwargs)
            self.result_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))


class PortScannerTab(QWidget):
    """Port Scanner Tab"""
    def __init__(self):
        super().__init__()
        self.scanner = PortScanner()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Port Scanner")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input fields
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g., scanme.nmap.org")
        input_layout.addWidget(self.host_input)
        
        input_layout.addWidget(QLabel("Port Range:"))
        self.port_input = QLineEdit()
        self.port_input.setText("1-1000")
        self.port_input.setMaximumWidth(100)
        input_layout.addWidget(self.port_input)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Ports")
        self.scan_btn.clicked.connect(self.scan_ports)
        btn_layout.addWidget(self.scan_btn)
        
        self.common_btn = QPushButton("Scan Common Ports")
        self.common_btn.clicked.connect(self.scan_common)
        btn_layout.addWidget(self.common_btn)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Scan Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def scan_ports(self):
        host = self.host_input.text().strip()
        ports = self.port_input.text().strip()
        
        if not host or not ports:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields")
            return
        
        self.scan_btn.setEnabled(False)
        self.progress.setVisible(True)
        
        self.worker = WorkerThread(self.scanner.scan_ports, host, ports)
        self.worker.result_signal.connect(self.on_scan_complete)
        self.worker.error_signal.connect(self.on_scan_error)
        self.worker.start()
    
    def scan_common(self):
        host = self.host_input.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter a target host")
            return
        
        self.scan_btn.setEnabled(False)
        self.progress.setVisible(True)
        
        self.worker = WorkerThread(self.scanner.scan_common_ports, host)
        self.worker.result_signal.connect(self.on_scan_complete)
        self.worker.error_signal.connect(self.on_scan_error)
        self.worker.start()
    
    def stop_scan(self):
        if self.worker:
            self.worker.quit()
            self.worker.wait()
        self.scan_btn.setEnabled(True)
        self.progress.setVisible(False)
    
    def on_scan_complete(self, result):
        output = f"=== Port Scan Results ===\n\n"
        output += f"Host: {result.get('host', 'Unknown')}\n"
        output += f"Scan Type: {result.get('scan_type', 'Full')}\n"
        output += f"Time: {result.get('timestamp', 'N/A')}\n\n"
        
        if result.get('open_ports'):
            output += "Open Ports:\n"
            for port in result.get('open_ports', []):
                output += f"  {port}\n"
        else:
            output += "No open ports found\n"
        
        self.results_text.setText(output)
        self.scan_btn.setEnabled(True)
        self.progress.setVisible(False)
    
    def on_scan_error(self, error):
        QMessageBox.critical(self, "Scan Error", f"Error: {error}")
        self.scan_btn.setEnabled(True)
        self.progress.setVisible(False)


class DNSLookupTab(QWidget):
    """DNS Lookup Tab"""
    def __init__(self):
        super().__init__()
        self.dns = DNSLookup()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("DNS Lookup")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input fields
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., google.com")
        input_layout.addWidget(self.domain_input)
        
        input_layout.addWidget(QLabel("Record Type:"))
        self.record_combo = QComboBox()
        self.record_combo.addItems(["A", "MX", "NS", "TXT", "CNAME"])
        input_layout.addWidget(self.record_combo)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        lookup_btn = QPushButton("Lookup DNS")
        lookup_btn.clicked.connect(self.lookup_dns)
        btn_layout.addWidget(lookup_btn)
        
        all_btn = QPushButton("Lookup All")
        all_btn.clicked.connect(self.lookup_all)
        btn_layout.addWidget(all_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("DNS Records:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def lookup_dns(self):
        domain = self.domain_input.text().strip()
        record_type = self.record_combo.currentText()
        
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.dns.lookup, domain, record_type)
        self.worker.result_signal.connect(self.on_lookup_complete)
        self.worker.error_signal.connect(self.on_lookup_error)
        self.worker.start()
    
    def lookup_all(self):
        domain = self.domain_input.text().strip()
        
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.dns.lookup_all, domain)
        self.worker.result_signal.connect(self.on_lookup_complete)
        self.worker.error_signal.connect(self.on_lookup_error)
        self.worker.start()
    
    def on_lookup_complete(self, result):
        output = f"=== DNS Lookup Results ===\n\n"
        output += f"Domain: {result.get('domain', 'Unknown')}\n\n"
        
        for record_type, records in result.items():
            if record_type != 'domain' and records:
                output += f"{record_type.upper()} Records:\n"
                if isinstance(records, list):
                    for record in records:
                        output += f"  {record}\n"
                else:
                    output += f"  {records}\n"
                output += "\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_lookup_error(self, error):
        QMessageBox.critical(self, "Lookup Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear_results(self):
        self.domain_input.clear()
        self.results_text.clear()


class IPGeolocationTab(QWidget):
    """IP Geolocation Tab"""
    def __init__(self):
        super().__init__()
        self.geo = IPGeolocation()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("IP Geolocation")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("IP Address:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 8.8.8.8")
        input_layout.addWidget(self.ip_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        lookup_btn = QPushButton("Lookup Location")
        lookup_btn.clicked.connect(self.lookup_geo)
        btn_layout.addWidget(lookup_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Location Information:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def lookup_geo(self):
        ip = self.ip_input.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.geo.get_location, ip)
        self.worker.result_signal.connect(self.on_lookup_complete)
        self.worker.error_signal.connect(self.on_lookup_error)
        self.worker.start()
    
    def on_lookup_complete(self, result):
        output = f"=== IP Geolocation Results ===\n\n"
        for key, value in result.items():
            formatted_key = key.replace("_", " ").title()
            output += f"{formatted_key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_lookup_error(self, error):
        QMessageBox.critical(self, "Lookup Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear_results(self):
        self.ip_input.clear()
        self.results_text.clear()


class SSLAnalyzerTab(QWidget):
    """SSL Certificate Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.ssl = SSLAnalyzer()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("SSL/TLS Certificate Analyzer")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g., google.com")
        input_layout.addWidget(self.host_input)
        
        input_layout.addWidget(QLabel("Port:"))
        self.port_spin = QSpinBox()
        self.port_spin.setValue(443)
        self.port_spin.setMinimum(1)
        self.port_spin.setMaximum(65535)
        self.port_spin.setMaximumWidth(80)
        input_layout.addWidget(self.port_spin)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        analyze_btn = QPushButton("Analyze Certificate")
        analyze_btn.clicked.connect(self.analyze_ssl)
        btn_layout.addWidget(analyze_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Certificate Details:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def analyze_ssl(self):
        host = self.host_input.text().strip()
        port = self.port_spin.value()
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter a host")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.ssl.analyze, host, port)
        self.worker.result_signal.connect(self.on_analysis_complete)
        self.worker.error_signal.connect(self.on_analysis_error)
        self.worker.start()
    
    def on_analysis_complete(self, result):
        output = f"=== SSL Certificate Analysis ===\n\n"
        for key, value in result.items():
            formatted_key = key.replace("_", " ").title()
            output += f"{formatted_key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_analysis_error(self, error):
        QMessageBox.critical(self, "Analysis Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear_results(self):
        self.host_input.clear()
        self.results_text.clear()


class PasswordAnalyzerTab(QWidget):
    """Password Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = PasswordAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Password Strength Analyzer")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password to analyze")
        input_layout.addWidget(self.password_input)
        
        show_btn = QPushButton("Show")
        show_btn.setMaximumWidth(50)
        show_btn.clicked.connect(self.toggle_password_visibility)
        input_layout.addWidget(show_btn)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        analyze_btn = QPushButton("Analyze Strength")
        analyze_btn.clicked.connect(self.analyze_password)
        btn_layout.addWidget(analyze_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        results_label = QLabel("Strength Analysis:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def analyze_password(self):
        password = self.password_input.text()
        
        if not password:
            QMessageBox.warning(self, "Input Error", "Please enter a password")
            return
        
        result = self.analyzer.analyze_password(password)
        
        output = f"=== Password Strength Analysis ===\n\n"
        output += f"Password Length: {result.get('length', 0)}\n"
        output += f"Strength: {result.get('strength', 'Unknown')}\n"
        output += f"Score: {result.get('score', 0)}/100\n\n"
        
        output += "Criteria:\n"
        for criterion, value in result.items():
            if criterion not in ['length', 'strength', 'score']:
                status = "✓" if value else "✗"
                formatted = criterion.replace("_", " ").title()
                output += f"  {status} {formatted}\n"
        
        self.results_text.setText(output)
    
    def toggle_password_visibility(self):
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
    
    def clear(self):
        self.password_input.clear()
        self.results_text.clear()


class HashAnalyzerTab(QWidget):
    """Hash Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = HashAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Hash Analyzer & Identifier")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Hash:"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Paste hash to identify")
        input_layout.addWidget(self.hash_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        identify_btn = QPushButton("Identify Hash")
        identify_btn.clicked.connect(self.identify_hash)
        btn_layout.addWidget(identify_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        results_label = QLabel("Hash Analysis:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def identify_hash(self):
        hash_value = self.hash_input.text().strip()
        
        if not hash_value:
            QMessageBox.warning(self, "Input Error", "Please enter a hash")
            return
        
        result = self.analyzer.identify_hash(hash_value)
        
        output = f"=== Hash Analysis ===\n\n"
        output += f"Hash: {result.get('hash', 'Unknown')}\n"
        output += f"Type: {result.get('type', 'Unknown')}\n"
        output += f"Length: {result.get('length', 'Unknown')}\n"
        
        self.results_text.setText(output)
    
    def clear(self):
        self.hash_input.clear()
        self.results_text.clear()


class VulnerabilityScannerTab(QWidget):
    """Vulnerability Scanner Tab"""
    def __init__(self):
        super().__init__()
        self.scanner = VulnerabilityScanner()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Vulnerability Scanner")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., https://example.com")
        input_layout.addWidget(self.url_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        scan_btn = QPushButton("Scan Vulnerabilities")
        scan_btn.clicked.connect(self.scan_vulnerabilities)
        btn_layout.addWidget(scan_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Scan Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def scan_vulnerabilities(self):
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.scanner.scan, url)
        self.worker.result_signal.connect(self.on_scan_complete)
        self.worker.error_signal.connect(self.on_scan_error)
        self.worker.start()
    
    def on_scan_complete(self, result):
        output = f"=== Vulnerability Scan Results ===\n\n"
        output += f"URL: {result.get('url', 'Unknown')}\n\n"
        
        if result.get('vulnerabilities'):
            output += "Vulnerabilities Found:\n"
            for vuln in result.get('vulnerabilities', []):
                output += f"  • {vuln}\n"
        else:
            output += "No vulnerabilities detected\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_scan_error(self, error):
        QMessageBox.critical(self, "Scan Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.url_input.clear()
        self.results_text.clear()


class WhoisLookupTab(QWidget):
    """WHOIS Lookup Tab"""
    def __init__(self):
        super().__init__()
        self.whois = WHOISLookup()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("WHOIS Lookup")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain/IP:"))
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("e.g., example.com or 8.8.8.8")
        input_layout.addWidget(self.input_field)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        lookup_btn = QPushButton("Lookup WHOIS")
        lookup_btn.clicked.connect(self.lookup_whois)
        btn_layout.addWidget(lookup_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("WHOIS Information:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def lookup_whois(self):
        query = self.input_field.text().strip()
        
        if not query:
            QMessageBox.warning(self, "Input Error", "Please enter a domain or IP")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.whois.lookup, query)
        self.worker.result_signal.connect(self.on_lookup_complete)
        self.worker.error_signal.connect(self.on_lookup_error)
        self.worker.start()
    
    def on_lookup_complete(self, result):
        output = f"=== WHOIS Lookup Results ===\n\n"
        for key, value in result.items():
            formatted_key = key.replace("_", " ").title()
            output += f"{formatted_key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_lookup_error(self, error):
        QMessageBox.critical(self, "Lookup Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.input_field.clear()
        self.results_text.clear()


class SubdomainEnumTab(QWidget):
    """Subdomain Enumeration Tab"""
    def __init__(self):
        super().__init__()
        self.enumerator = SubdomainEnumerator()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Subdomain Enumeration")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., example.com")
        input_layout.addWidget(self.domain_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        enum_btn = QPushButton("Enumerate Subdomains")
        enum_btn.clicked.connect(self.enumerate)
        btn_layout.addWidget(enum_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Subdomains Found:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def enumerate(self):
        domain = self.domain_input.text().strip()
        
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.enumerator.enumerate, domain)
        self.worker.result_signal.connect(self.on_enum_complete)
        self.worker.error_signal.connect(self.on_enum_error)
        self.worker.start()
    
    def on_enum_complete(self, result):
        output = f"=== Subdomain Enumeration Results ===\n\n"
        output += f"Domain: {result.get('domain', 'Unknown')}\n\n"
        
        if result.get('subdomains'):
            output += f"Subdomains Found ({len(result.get('subdomains', []))}):\n"
            for subdomain in result.get('subdomains', []):
                output += f"  • {subdomain}\n"
        else:
            output += "No subdomains found\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_enum_error(self, error):
        QMessageBox.critical(self, "Enumeration Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.domain_input.clear()
        self.results_text.clear()


class IPFinderTab(QWidget):
    """IP Finder Tab"""
    def __init__(self):
        super().__init__()
        self.finder = IPFinder()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("IP Finder - Find Your Public IP")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Buttons
        btn_layout = QHBoxLayout()
        find_btn = QPushButton("Find My IP")
        find_btn.clicked.connect(self.find_ip)
        btn_layout.addWidget(find_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Your Public IP Information:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def find_ip(self):
        self.progress.setVisible(True)
        
        try:
            result = self.finder.find_ip()
            output = f"=== Your Public IP ===\n\n"
            for key, value in result.items():
                formatted_key = key.replace("_", " ").title()
                output += f"{formatted_key}: {value}\n"
            
            self.results_text.setText(output)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error: {str(e)}")
        finally:
            self.progress.setVisible(False)
    
    def clear(self):
        self.results_text.clear()


class HTTPHeadersTab(QWidget):
    """HTTP Headers Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = HTTPHeaderAnalyzer()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("HTTP Headers Analyzer")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., https://example.com")
        input_layout.addWidget(self.url_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        analyze_btn = QPushButton("Analyze Headers")
        analyze_btn.clicked.connect(self.analyze_headers)
        btn_layout.addWidget(analyze_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("HTTP Headers:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def analyze_headers(self):
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.analyzer.analyze, url)
        self.worker.result_signal.connect(self.on_analysis_complete)
        self.worker.error_signal.connect(self.on_analysis_error)
        self.worker.start()
    
    def on_analysis_complete(self, result):
        output = f"=== HTTP Headers Analysis ===\n\n"
        for key, value in result.items():
            output += f"{key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_analysis_error(self, error):
        QMessageBox.critical(self, "Analysis Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.url_input.clear()
        self.results_text.clear()


class NetworkReconTab(QWidget):
    """Network Reconnaissance Tab"""
    def __init__(self):
        super().__init__()
        self.recon = NetworkRecon()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Network Reconnaissance")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Domain or IP")
        input_layout.addWidget(self.target_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        recon_btn = QPushButton("Run Reconnaissance")
        recon_btn.clicked.connect(self.run_recon)
        btn_layout.addWidget(recon_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Reconnaissance Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def run_recon(self):
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.recon.reconnaissance, target)
        self.worker.result_signal.connect(self.on_recon_complete)
        self.worker.error_signal.connect(self.on_recon_error)
        self.worker.start()
    
    def on_recon_complete(self, result):
        output = f"=== Network Reconnaissance Results ===\n\n"
        for key, value in result.items():
            formatted_key = key.replace("_", " ").title()
            output += f"{formatted_key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_recon_error(self, error):
        QMessageBox.critical(self, "Reconnaissance Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.target_input.clear()
        self.results_text.clear()


class DDoSAnalyzerTab(QWidget):
    """DDoS Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = DDoSAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("DDoS Detection Analyzer")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Log File:"))
        self.log_input = QLineEdit()
        self.log_input.setReadOnly(True)
        input_layout.addWidget(self.log_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_log)
        input_layout.addWidget(browse_btn)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        analyze_btn = QPushButton("Analyze Log")
        analyze_btn.clicked.connect(self.analyze_log)
        btn_layout.addWidget(analyze_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Analysis Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def browse_log(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Log File")
        if file_path:
            self.log_input.setText(file_path)
    
    def analyze_log(self):
        log_file = self.log_input.text().strip()
        
        if not log_file:
            QMessageBox.warning(self, "Input Error", "Please select a log file")
            return
        
        self.progress.setVisible(True)
        
        try:
            result = self.analyzer.analyze_log_file(log_file)
            output = f"=== DDoS Analysis ===\n\n"
            for key, value in result.items():
                formatted_key = key.replace("_", " ").title()
                output += f"{formatted_key}: {value}\n"
            
            self.results_text.setText(output)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error: {str(e)}")
        finally:
            self.progress.setVisible(False)
    
    def clear(self):
        self.log_input.clear()
        self.results_text.clear()


class CVEDatabaseTab(QWidget):
    """CVE Database Tab"""
    def __init__(self):
        super().__init__()
        self.cve_db = CVEDatabase()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("CVE Database Search")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Search Query:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("e.g., WordPress vulnerability")
        input_layout.addWidget(self.search_input)
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        search_btn = QPushButton("Search CVEs")
        search_btn.clicked.connect(self.search_cves)
        btn_layout.addWidget(search_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("CVE Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def search_cves(self):
        query = self.search_input.text().strip()
        
        if not query:
            QMessageBox.warning(self, "Input Error", "Please enter a search query")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.cve_db.search, query)
        self.worker.result_signal.connect(self.on_search_complete)
        self.worker.error_signal.connect(self.on_search_error)
        self.worker.start()
    
    def on_search_complete(self, result):
        output = f"=== CVE Database Results ===\n\n"
        
        if result.get('cves'):
            for cve in result.get('cves', []):
                output += f"CVE ID: {cve.get('id', 'Unknown')}\n"
                output += f"Description: {cve.get('description', 'N/A')}\n"
                output += f"Score: {cve.get('severity_score', 'N/A')}\n\n"
        else:
            output += "No CVEs found\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_search_error(self, error):
        QMessageBox.critical(self, "Search Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.search_input.clear()
        self.results_text.clear()


class LoadTesterTab(QWidget):
    """Load Tester Tab"""
    def __init__(self):
        super().__init__()
        self.load_tester = LoadTester()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Load Testing Tool")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., https://example.com")
        input_layout.addWidget(self.url_input)
        layout.addLayout(input_layout)
        
        # Parameters
        params_layout = QHBoxLayout()
        
        params_layout.addWidget(QLabel("Requests:"))
        self.requests_spin = QSpinBox()
        self.requests_spin.setValue(100)
        self.requests_spin.setMinimum(1)
        self.requests_spin.setMaximum(10000)
        params_layout.addWidget(self.requests_spin)
        
        params_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setValue(10)
        self.threads_spin.setMinimum(1)
        self.threads_spin.setMaximum(100)
        params_layout.addWidget(self.threads_spin)
        
        layout.addLayout(params_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        test_btn = QPushButton("Start Load Test")
        test_btn.clicked.connect(self.start_load_test)
        btn_layout.addWidget(test_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Test Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def start_load_test(self):
        url = self.url_input.text().strip()
        requests = self.requests_spin.value()
        threads = self.threads_spin.value()
        
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.load_tester.run_test, url, requests, threads)
        self.worker.result_signal.connect(self.on_test_complete)
        self.worker.error_signal.connect(self.on_test_error)
        self.worker.start()
    
    def on_test_complete(self, result):
        output = f"=== Load Test Results ===\n\n"
        for key, value in result.items():
            formatted_key = key.replace("_", " ").title()
            output += f"{formatted_key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_test_error(self, error):
        QMessageBox.critical(self, "Test Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.url_input.clear()
        self.results_text.clear()


class NetworkStressTab(QWidget):
    """Network Stress Simulator Tab"""
    def __init__(self):
        super().__init__()
        self.stress = NetworkStressSimulator()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Network Stress Simulator")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #00ccff;")
        layout.addWidget(title)
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g., example.com")
        input_layout.addWidget(self.host_input)
        layout.addLayout(input_layout)
        
        # Parameters
        params_layout = QHBoxLayout()
        
        params_layout.addWidget(QLabel("Packets:"))
        self.packets_spin = QSpinBox()
        self.packets_spin.setValue(100)
        self.packets_spin.setMinimum(1)
        self.packets_spin.setMaximum(10000)
        params_layout.addWidget(self.packets_spin)
        
        params_layout.addWidget(QLabel("Packet Size (bytes):"))
        self.size_spin = QSpinBox()
        self.size_spin.setValue(1024)
        self.size_spin.setMinimum(32)
        self.size_spin.setMaximum(65535)
        params_layout.addWidget(self.size_spin)
        
        layout.addLayout(params_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        simulate_btn = QPushButton("Start Simulation")
        simulate_btn.clicked.connect(self.start_simulation)
        btn_layout.addWidget(simulate_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        results_label = QLabel("Simulation Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def start_simulation(self):
        host = self.host_input.text().strip()
        packets = self.packets_spin.value()
        size = self.size_spin.value()
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter a host")
            return
        
        self.progress.setVisible(True)
        self.worker = WorkerThread(self.stress.simulate, host, packets, size)
        self.worker.result_signal.connect(self.on_simulation_complete)
        self.worker.error_signal.connect(self.on_simulation_error)
        self.worker.start()
    
    def on_simulation_complete(self, result):
        output = f"=== Network Stress Simulation ===\n\n"
        for key, value in result.items():
            formatted_key = key.replace("_", " ").title()
            output += f"{formatted_key}: {value}\n"
        
        self.results_text.setText(output)
        self.progress.setVisible(False)
    
    def on_simulation_error(self, error):
        QMessageBox.critical(self, "Simulation Error", f"Error: {error}")
        self.progress.setVisible(False)
    
    def clear(self):
        self.host_input.clear()
        self.results_text.clear()


class FooterWidget(QWidget):
    """Professional footer widget"""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout()
        
        footer_text = f"Hackers Toolkit v{APP_VERSION} | Developed by {DEVELOPER} - {YEAR} | Professional Security Analysis Platform"
        footer_label = QLabel(footer_text)
        footer_label.setStyleSheet(
            "color: #888888; font-size: 9px; padding: 5px; background-color: #2d2d44; border-top: 1px solid #0099ff;"
        )
        footer_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(footer_label)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        self.setLayout(layout)
        self.setFixedHeight(30)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Hackers Toolkit v{APP_VERSION}")
        self.setGeometry(100, 100, 1200, 700)
        
        # Apply modern stylesheet
        self.setStyleSheet(get_stylesheet())
        
        # Create main widget
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.create_tabs()
        main_layout.addWidget(self.tabs)
        
        # Create footer
        footer = FooterWidget()
        main_layout.addWidget(footer)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        # Create status bar
        self.statusBar().showMessage("Ready")
    
    def create_menu_bar(self):
        """Create menu bar with menus and submenus"""
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New Analysis", self)
        new_action.triggered.connect(self.new_analysis)
        file_menu.addAction(new_action)
        
        open_action = QAction("Open Report", self)
        open_action.triggered.connect(self.open_report)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools Menu
        tools_menu = menubar.addMenu("Tools")
        
        network_submenu = tools_menu.addMenu("Network Reconnaissance")
        network_submenu.addAction("Port Scanner")
        network_submenu.addAction("DNS Lookup")
        network_submenu.addAction("WHOIS Lookup")
        network_submenu.addAction("Subdomain Enumeration")
        network_submenu.addAction("Network Reconnaissance")
        network_submenu.addAction("Reverse DNS Lookup")
        
        web_submenu = tools_menu.addMenu("Web Analysis")
        web_submenu.addAction("SSL Certificate Analyzer")
        web_submenu.addAction("HTTP Headers Analyzer")
        web_submenu.addAction("Vulnerability Scanner")
        
        crypto_submenu = tools_menu.addMenu("Cryptocurrency")
        crypto_submenu.addAction("Blockchain Analyzer")
        
        # Analysis Menu
        analysis_menu = menubar.addMenu("Analysis")
        
        data_submenu = analysis_menu.addMenu("Data Analysis")
        data_submenu.addAction("Hash Analyzer")
        data_submenu.addAction("Password Analyzer")
        data_submenu.addAction("CVE Database")
        
        threat_submenu = analysis_menu.addMenu("Threat Detection")
        threat_submenu.addAction("DDoS Analyzer")
        threat_submenu.addAction("IP Geolocation")
        
        location_submenu = analysis_menu.addMenu("Location & Tracking")
        location_submenu.addAction("IP Finder")
        location_submenu.addAction("IP Geolocation")
        
        # Testing Menu
        testing_menu = menubar.addMenu("Testing")
        
        stress_submenu = testing_menu.addMenu("Load & Stress Testing")
        stress_submenu.addAction("Load Tester")
        stress_submenu.addAction("Network Stress Simulator")
        
        # Settings Menu
        settings_menu = menubar.addMenu("Settings")
        settings_action = QAction("Preferences", self)
        settings_action.triggered.connect(self.open_settings)
        settings_menu.addAction(settings_action)
        
        # Help Menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        help_menu.addSeparator()
        
        documentation_action = QAction("Documentation", self)
        documentation_action.triggered.connect(self.show_documentation)
        help_menu.addAction(documentation_action)
    
    def create_tabs(self):
        """Create all tool tabs"""
        self.tabs.addTab(PortScannerTab(), "Port Scanner")
        self.tabs.addTab(DNSLookupTab(), "DNS Lookup")
        self.tabs.addTab(IPGeolocationTab(), "IP Geolocation")
        self.tabs.addTab(SSLAnalyzerTab(), "SSL Analyzer")
        self.tabs.addTab(NetworkReconTab(), "Network Recon")
        self.tabs.addTab(VulnerabilityScannerTab(), "Vulnerability Scanner")
        self.tabs.addTab(PasswordAnalyzerTab(), "Password Analyzer")
        self.tabs.addTab(HashAnalyzerTab(), "Hash Analyzer")
        self.tabs.addTab(IPFinderTab(), "IP Finder")
        self.tabs.addTab(DDoSAnalyzerTab(), "DDoS Analyzer")
        self.tabs.addTab(HTTPHeadersTab(), "HTTP Headers")
        self.tabs.addTab(SubdomainEnumTab(), "Subdomains")
        self.tabs.addTab(WhoisLookupTab(), "WHOIS Lookup")
        self.tabs.addTab(CVEDatabaseTab(), "CVE Database")
        self.tabs.addTab(LoadTesterTab(), "Load Tester")
        self.tabs.addTab(NetworkStressTab(), "Network Stress")
        self.tabs.addTab(BlockchainAnalyzerTab(), "Blockchain Analyzer")
        self.tabs.addTab(ReverseDNSTab(), "Reverse DNS")
    
    def new_analysis(self):
        """Create new analysis"""
        self.statusBar().showMessage("New analysis created")
        logger.info("New analysis created")
    
    def open_report(self):
        """Open report file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Report", "", "HTML Files (*.html);;PDF Files (*.pdf)"
        )
        if file_path:
            self.statusBar().showMessage(f"Opened: {file_path}")
            logger.info(f"Opened report: {file_path}")
    
    def open_settings(self):
        """Open settings dialog"""
        dialog = SettingsDialog(self)
        dialog.exec_()
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.information(
            self,
            "About Hackers Toolkit",
            f"Hackers Toolkit v{APP_VERSION}\n\n"
            f"Professional Security Analysis Platform\n\n"
            f"Developed by {DEVELOPER} - {YEAR}\n\n"
            f"A comprehensive toolkit for security professionals and penetration testers.\n\n"
            f"Features include network reconnaissance, web analysis, vulnerability scanning, "
            f"and threat detection tools."
        )
    
    def show_documentation(self):
        """Show documentation"""
        QMessageBox.information(
            self,
            "Documentation",
            "Hackers Toolkit Documentation\n\n"
            "For detailed usage instructions and examples,\n"
            "please refer to the README.md file or visit\n"
            "the project documentation online."
        )


def main():
    """Main application entry point"""
    app = QMainWindow()
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
