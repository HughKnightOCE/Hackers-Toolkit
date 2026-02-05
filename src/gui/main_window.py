"""Main GUI window for Hackers Toolkit"""
import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QComboBox, QSpinBox, QProgressBar, QStatusBar, QMessageBox, QFileDialog,
    QMenuBar, QMenu, QDialog, QFormLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
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
from tools.report_generator import ReportGenerator
from tools.subdomain_enum import SubdomainEnumerator
from tools.whois_lookup import WHOISLookup
from tools.cve_database import CVEDatabase
from tools.load_tester import LoadTester
from tools.network_stress import NetworkStressSimulator
from utils.logger import Logger
from .settings import SettingsDialog

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
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input fields
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target Host:"))
        self.host_input = QLineEdit()
        input_layout.addWidget(self.host_input)
        
        input_layout.addWidget(QLabel("Port Range:"))
        self.port_input = QLineEdit()
        self.port_input.setText("1-1000")
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
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def scan_ports(self):
        host = self.host_input.text().strip()
        port_range = self.port_input.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter a target host")
            return
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.results_text.clear()
        
        self.worker = WorkerThread(self.scanner.scan_range, host, port_range)
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def scan_common(self):
        host = self.host_input.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Input Error", "Please enter a target host")
            return
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.results_text.clear()
        
        self.worker = WorkerThread(self.scanner.scan_common_ports, host)
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def stop_scan(self):
        self.scanner.stop_scan()
        self.stop_btn.setEnabled(False)
        self.scan_btn.setEnabled(True)
    
    def display_results(self, results):
        self.stop_btn.setEnabled(False)
        self.scan_btn.setEnabled(True)
        
        text = "=== Port Scan Results ===\n"
        text += f"Host: {results.get('host')}\n"
        text += f"Start Time: {results.get('start_time')}\n"
        text += f"End Time: {results.get('end_time')}\n\n"
        
        text += "OPEN PORTS:\n"
        for port in results.get('open_ports', []):
            text += f"  Port {port['port']}: {port.get('service', 'Unknown')} ({port.get('state')})\n"
        
        text += f"\nCLOSED PORTS: {len(results.get('closed_ports', []))}\n"
        
        self.results_text.setText(text)
        Logger.info("Port scan results displayed")
    
    def handle_error(self, error):
        self.stop_btn.setEnabled(False)
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Scan error: {error}")
        Logger.error(f"Port scan error: {error}")

class DNSLookupTab(QWidget):
    """DNS Lookup Tab"""
    def __init__(self):
        super().__init__()
        self.dns = DNSLookup()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit()
        input_layout.addWidget(self.domain_input)
        
        input_layout.addWidget(QLabel("Record Type:"))
        self.record_combo = QComboBox()
        self.record_combo.addItems(["All", "A", "MX", "NS", "TXT"])
        input_layout.addWidget(self.record_combo)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.lookup_btn = QPushButton("Lookup")
        self.lookup_btn.clicked.connect(self.lookup)
        btn_layout.addWidget(self.lookup_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)
        btn_layout.addWidget(self.clear_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("DNS Records:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def lookup(self):
        domain = self.domain_input.text().strip()
        record_type = self.record_combo.currentText()
        
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain")
            return
        
        self.lookup_btn.setEnabled(False)
        self.results_text.clear()
        
        if record_type == "All":
            self.worker = WorkerThread(self.dns.full_dns_lookup, domain)
        elif record_type == "A":
            self.worker = WorkerThread(self.dns.lookup_a_record, domain)
        elif record_type == "MX":
            self.worker = WorkerThread(self.dns.lookup_mx_record, domain)
        elif record_type == "NS":
            self.worker = WorkerThread(self.dns.lookup_ns_record, domain)
        else:  # TXT
            self.worker = WorkerThread(self.dns.lookup_txt_record, domain)
        
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def display_results(self, results):
        self.lookup_btn.setEnabled(True)
        
        text = "=== DNS Lookup Results ===\n\n"
        
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            for key, value in results.items():
                if isinstance(value, list):
                    text += f"{key}:\n"
                    for item in value:
                        text += f"  {item}\n"
                elif isinstance(value, dict):
                    text += f"{key}:\n"
                    for k, v in value.items():
                        text += f"  {k}: {v}\n"
                else:
                    text += f"{key}: {value}\n"
        
        self.results_text.setText(text)
    
    def handle_error(self, error):
        self.lookup_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Lookup error: {error}")
    
    def clear_results(self):
        self.results_text.clear()
        self.domain_input.clear()

class IPGeolocationTab(QWidget):
    """IP Geolocation Tab"""
    def __init__(self):
        super().__init__()
        self.geo = IPGeolocation()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("IP Address:"))
        self.ip_input = QLineEdit()
        input_layout.addWidget(self.ip_input)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.lookup_btn = QPushButton("Lookup")
        self.lookup_btn.clicked.connect(self.lookup_ip)
        btn_layout.addWidget(self.lookup_btn)
        
        self.reputation_btn = QPushButton("Check Reputation")
        self.reputation_btn.clicked.connect(self.check_reputation)
        btn_layout.addWidget(self.reputation_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Location & Info:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def lookup_ip(self):
        ip = self.ip_input.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address")
            return
        
        self.lookup_btn.setEnabled(False)
        self.results_text.clear()
        
        self.worker = WorkerThread(self.geo.get_ip_info, ip)
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def check_reputation(self):
        ip = self.ip_input.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address")
            return
        
        self.reputation_btn.setEnabled(False)
        
        self.worker = WorkerThread(self.geo.check_ip_reputation, ip)
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def display_results(self, results):
        self.lookup_btn.setEnabled(True)
        self.reputation_btn.setEnabled(True)
        
        text = "=== IP Information ===\n\n"
        
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            for key, value in results.items():
                text += f"{key}: {value}\n"
        
        self.results_text.setText(text)
    
    def handle_error(self, error):
        self.lookup_btn.setEnabled(True)
        self.reputation_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Lookup error: {error}")

class SSLAnalyzerTab(QWidget):
    """SSL Certificate Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.ssl = SSLAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Hostname:"))
        self.hostname_input = QLineEdit()
        input_layout.addWidget(self.hostname_input)
        
        input_layout.addWidget(QLabel("Port:"))
        self.port_spin = QSpinBox()
        self.port_spin.setValue(443)
        self.port_spin.setMinimum(1)
        self.port_spin.setMaximum(65535)
        input_layout.addWidget(self.port_spin)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.cert_btn = QPushButton("Get Certificate")
        self.cert_btn.clicked.connect(self.get_certificate)
        btn_layout.addWidget(self.cert_btn)
        
        self.protocol_btn = QPushButton("Test Protocols")
        self.protocol_btn.clicked.connect(self.test_protocols)
        btn_layout.addWidget(self.protocol_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Certificate Info:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def get_certificate(self):
        hostname = self.hostname_input.text().strip()
        port = self.port_spin.value()
        
        if not hostname:
            QMessageBox.warning(self, "Input Error", "Please enter a hostname")
            return
        
        self.cert_btn.setEnabled(False)
        self.results_text.clear()
        
        self.worker = WorkerThread(self.ssl.get_certificate, hostname, port)
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def test_protocols(self):
        hostname = self.hostname_input.text().strip()
        port = self.port_spin.value()
        
        if not hostname:
            QMessageBox.warning(self, "Input Error", "Please enter a hostname")
            return
        
        self.protocol_btn.setEnabled(False)
        
        self.worker = WorkerThread(self.ssl.test_ssl_protocols, hostname, port)
        self.worker.result_signal.connect(self.display_results)
        self.worker.error_signal.connect(self.handle_error)
        self.worker.start()
    
    def display_results(self, results):
        self.cert_btn.setEnabled(True)
        self.protocol_btn.setEnabled(True)
        
        text = "=== SSL/TLS Certificate Information ===\n\n"
        
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            for key, value in results.items():
                if isinstance(value, list):
                    text += f"{key}:\n"
                    for item in value:
                        text += f"  {item}\n"
                elif isinstance(value, dict):
                    text += f"{key}:\n"
                    for k, v in value.items():
                        text += f"  {k}: {v}\n"
                else:
                    text += f"{key}: {value}\n"
        
        self.results_text.setText(text)
    
    def handle_error(self, error):
        self.cert_btn.setEnabled(True)
        self.protocol_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Analysis error: {error}")

class PasswordAnalyzerTab(QWidget):
    """Password Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = PasswordAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        input_layout.addWidget(self.password_input)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.analyze_password)
        btn_layout.addWidget(self.analyze_btn)
        
        self.generate_btn = QPushButton("Generate Strong Password")
        self.generate_btn.clicked.connect(self.generate_password)
        btn_layout.addWidget(self.generate_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Analysis Results:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def analyze_password(self):
        password = self.password_input.text()
        
        if not password:
            QMessageBox.warning(self, "Input Error", "Please enter a password")
            return
        
        results = self.analyzer.analyze_password(password)
        
        text = "=== Password Analysis ===\n\n"
        text += f"Length: {results.get('password_length')}\n"
        text += f"Strength: {results.get('strength')}\n"
        text += f"Entropy: {results.get('entropy')} bits\n\n"
        text += "Character Types:\n"
        text += f"  Uppercase: {'✓' if results.get('has_uppercase') else '✗'}\n"
        text += f"  Lowercase: {'✓' if results.get('has_lowercase') else '✗'}\n"
        text += f"  Digits: {'✓' if results.get('has_digits') else '✗'}\n"
        text += f"  Special: {'✓' if results.get('has_special') else '✗'}\n"
        text += f"  Common Password: {'✓' if results.get('is_common') else '✗'}\n"
        
        self.results_text.setText(text)
    
    def generate_password(self):
        results = self.analyzer.generate_password(length=16)
        
        text = "=== Generated Password ===\n\n"
        text += f"Password: {results.get('generated_password')}\n"
        text += f"Strength: {results.get('strength')}\n"
        text += f"Entropy: {results.get('entropy')} bits\n"
        
        self.results_text.setText(text)

class HashAnalyzerTab(QWidget):
    """Hash Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = HashAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Hash/Text:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        layout.addLayout(input_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("Analyze Hash")
        self.analyze_btn.clicked.connect(self.analyze_hash)
        btn_layout.addWidget(self.analyze_btn)
        
        btn_layout.addWidget(QLabel("Generate:"))
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["MD5", "SHA1", "SHA256", "SHA512"])
        btn_layout.addWidget(self.hash_type_combo)
        
        self.generate_btn = QPushButton("Generate")
        self.generate_btn.clicked.connect(self.generate_hash)
        btn_layout.addWidget(self.generate_btn)
        
        layout.addLayout(btn_layout)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def analyze_hash(self):
        hash_value = self.input_field.text().strip()
        
        if not hash_value:
            QMessageBox.warning(self, "Input Error", "Please enter a hash or text")
            return
        
        results = self.analyzer.analyze_hash(hash_value)
        
        text = "=== Hash Analysis ===\n\n"
        text += f"Hash: {results.get('hash')}\n"
        text += f"Type: {results.get('hash_type')}\n"
        text += f"Length: {results.get('length')}\n"
        text += f"Valid Format: {'Yes' if results.get('is_valid_format') else 'No'}\n"
        text += f"Cracked: {'Yes' if results.get('cracked') else 'No'}\n"
        
        if results.get('cracked'):
            text += f"Plaintext: {results.get('plaintext')}\n"
        
        self.results_text.setText(text)
    
    def generate_hash(self):
        text = self.input_field.text()
        hash_type = self.hash_type_combo.currentText().lower()
        
        if not text:
            QMessageBox.warning(self, "Input Error", "Please enter text to hash")
            return
        
        results = self.analyzer.generate_hash(text, hash_type)
        
        output_text = "=== Generated Hash ===\n\n"
        output_text += f"Text: {results.get('text')}\n"
        output_text += f"Type: {results.get('hash_type').upper()}\n"
        output_text += f"Hash: {results.get('hash')}\n"
        
        self.results_text.setText(output_text)

class IPFinderTab(QWidget):
    """IP Finder Tab"""
    def __init__(self):
        super().__init__()
        self.finder = IPFinder()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain or IP:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        self.find_ips_btn = QPushButton("Find IPs")
        self.find_ips_btn.clicked.connect(self.find_ips)
        input_layout.addWidget(self.find_ips_btn)
        
        layout.addLayout(input_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def find_ips(self):
        domain = self.input_field.text()
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain or IP")
            return
        
        self.results_text.setText("Finding IPs...")
        results = self.finder.find_ips_from_domain(domain)
        
        text = "=== IP Finder Results ===\n\n"
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            text += f"Domain: {results.get('domain')}\n"
            for ip in results.get('ips', []):
                text += f"IP: {ip}\n"
        
        self.results_text.setText(text)

class DDoSAnalyzerTab(QWidget):
    """DDoS Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = DDoSAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target IP/Domain:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        self.analyze_btn = QPushButton("Analyze DDoS Risk")
        self.analyze_btn.clicked.connect(self.analyze_ddos)
        input_layout.addWidget(self.analyze_btn)
        
        layout.addLayout(input_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def analyze_ddos(self):
        target = self.input_field.text()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target")
            return
        
        self.results_text.setText("Analyzing DDoS vulnerabilities...")
        results = self.analyzer.check_ddos_vulnerabilities(target)
        
        text = "=== DDoS Analysis Results ===\n\n"
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            text += f"Target: {results.get('target')}\n"
            text += f"Risk Level: {results.get('risk_level')}\n"
            text += f"Vulnerabilities Found: {results.get('vulnerability_count')}\n\n"
            text += "Detailed Results:\n"
            for vuln in results.get('vulnerabilities', []):
                text += f"- {vuln}\n"
        
        self.results_text.setText(text)

class HTTPHeaderTab(QWidget):
    """HTTP Header Analyzer Tab"""
    def __init__(self):
        super().__init__()
        self.analyzer = HTTPHeaderAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target URL:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        self.check_btn = QPushButton("Check Headers")
        self.check_btn.clicked.connect(self.check_headers)
        input_layout.addWidget(self.check_btn)
        
        layout.addLayout(input_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def check_headers(self):
        url = self.input_field.text()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL")
            return
        
        self.results_text.setText("Checking headers...")
        results = self.analyzer.check_headers(url)
        
        text = "=== HTTP Header Analysis ===\n\n"
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            text += f"URL: {results.get('url')}\n"
            text += f"Security Grade: {results.get('grade')}\n"
            text += f"Score: {results.get('score')}/100\n\n"
            text += "Missing Headers:\n"
            for header in results.get('missing_headers', []):
                text += f"- {header}\n"
        
        self.results_text.setText(text)

class SubdomainEnumTab(QWidget):
    """Subdomain Enumeration Tab"""
    def __init__(self):
        super().__init__()
        self.enumerator = SubdomainEnumerator()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        self.enum_btn = QPushButton("Enumerate Subdomains")
        self.enum_btn.clicked.connect(self.enumerate)
        input_layout.addWidget(self.enum_btn)
        
        layout.addLayout(input_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def enumerate(self):
        domain = self.input_field.text()
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain")
            return
        
        self.results_text.setText("Enumerating subdomains...")
        results = self.enumerator.enumerate_subdomains(domain)
        
        text = "=== Subdomain Enumeration ===\n\n"
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            text += f"Domain: {results.get('domain')}\n"
            text += f"Found: {results.get('found_count')} subdomains\n\n"
            for subdomain in results.get('found_subdomains', []):
                text += f"- {subdomain.get('subdomain')} ({subdomain.get('ip')})\n"
        
        self.results_text.setText(text)

class WHOISTab(QWidget):
    """WHOIS Lookup Tab"""
    def __init__(self):
        super().__init__()
        self.whois = WHOISLookup()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Domain:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        self.lookup_btn = QPushButton("WHOIS Lookup")
        self.lookup_btn.clicked.connect(self.lookup_whois)
        input_layout.addWidget(self.lookup_btn)
        
        layout.addLayout(input_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def lookup_whois(self):
        domain = self.input_field.text()
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain")
            return
        
        self.results_text.setText("Looking up WHOIS information...")
        results = self.whois.lookup_domain(domain)
        
        text = "=== WHOIS Lookup ===\n\n"
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            text += f"Domain: {results.get('domain')}\n"
            text += f"Registrar: {results.get('registrar')}\n"
            text += f"Created: {results.get('creation_date')}\n"
            text += f"Expires: {results.get('expiration_date')}\n"
            text += f"Updated: {results.get('updated_date')}\n\n"
            text += f"Nameservers:\n"
            for ns in results.get('nameservers', []):
                text += f"- {ns}\n"
        
        self.results_text.setText(text)

class ReportGeneratorTab(QWidget):
    """Report Generator Tab"""
    def __init__(self):
        super().__init__()
        self.generator = ReportGenerator()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        buttons_layout = QHBoxLayout()
        
        self.pdf_btn = QPushButton("Generate PDF Report")
        self.pdf_btn.clicked.connect(self.generate_pdf)
        buttons_layout.addWidget(self.pdf_btn)
        
        self.html_btn = QPushButton("Generate HTML Report")
        self.html_btn.clicked.connect(self.generate_html)
        buttons_layout.addWidget(self.html_btn)
        
        layout.addLayout(buttons_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def generate_pdf(self):
        test_data = {"scan_type": "Port Scan", "target": "localhost", "results": {}}
        result = self.generator.generate_pdf_report(test_data)
        
        text = "=== Report Generation ===\n\n"
        if "error" in result:
            text += f"Error: {result['error']}"
        else:
            text += f"PDF Report Generated:\n"
            text += f"File: {result.get('filename')}\n"
            text += f"Size: {result.get('size')} bytes\n"
        
        self.results_text.setText(text)
    
    def generate_html(self):
        test_data = {"scan_type": "Port Scan", "target": "localhost", "results": {}}
        result = self.generator.generate_html_report(test_data)
        
        text = "=== Report Generation ===\n\n"
        if "error" in result:
            text += f"Error: {result['error']}"
        else:
            text += f"HTML Report Generated:\n"
            text += f"File: {result.get('filename')}\n"
            text += f"Size: {result.get('size')} bytes\n"
        
        self.results_text.setText(text)

class CVEDatabaseTab(QWidget):
    """CVE Database Tab"""
    def __init__(self):
        super().__init__()
        self.cve_db = CVEDatabase()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Search CVE or Software:"))
        self.input_field = QLineEdit()
        input_layout.addWidget(self.input_field)
        
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.search_cve)
        input_layout.addWidget(self.search_btn)
        
        layout.addLayout(input_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def search_cve(self):
        search_term = self.input_field.text()
        if not search_term:
            QMessageBox.warning(self, "Input Error", "Please enter search term")
            return
        
        self.results_text.setText("Searching CVE database...")
        
        # Try CVE ID search first
        if search_term.startswith("CVE-"):
            results = self.cve_db.search_cve(search_term)
        else:
            # Search by software
            results = self.cve_db.search_by_software(search_term)
        
        text = "=== CVE Database Search ===\n\n"
        if "error" in results:
            text += f"Error: {results['error']}"
        else:
            if isinstance(results, dict) and "vulnerabilities" in results:
                text += f"Found {results.get('found_count', 0)} vulnerabilities:\n\n"
                for vuln in results.get('vulnerabilities', []):
                    text += f"CVE: {vuln.get('cve_id')}\n"
                    text += f"Software: {vuln.get('software')}\n"
                    text += f"Severity: {vuln.get('severity')}\n"
                    text += f"CVSS Score: {vuln.get('cvss_score')}\n"
                    text += f"Description: {vuln.get('description')}\n"
                    text += f"Fix: {vuln.get('fix')}\n\n"
            else:
                text += f"CVE: {results.get('cve_id')}\n"
                text += f"Software: {results.get('software')}\n"
                text += f"Severity: {results.get('severity')}\n"
        
        self.results_text.setText(text)

class LoadTesterTab(QWidget):
    """Load Tester Tool Tab"""
    
    def __init__(self):
        super().__init__()
        self.tool = LoadTester()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input fields
        form = QFormLayout()
        self.url_input = QLineEdit()
        self.url_input.setText("http://example.com")
        self.requests_input = QSpinBox()
        self.requests_input.setValue(100)
        self.requests_input.setMaximum(10000)
        self.concurrent_input = QSpinBox()
        self.concurrent_input.setValue(10)
        self.concurrent_input.setMaximum(100)
        
        form.addRow("Target URL:", self.url_input)
        form.addRow("Number of Requests:", self.requests_input)
        form.addRow("Concurrent Requests:", self.concurrent_input)
        
        layout.addLayout(form)
        
        # Buttons
        btn_layout = QHBoxLayout()
        load_btn = QPushButton("Start Load Test")
        load_btn.clicked.connect(self.run_load_test)
        stress_btn = QPushButton("Stress Test (30s)")
        stress_btn.clicked.connect(self.run_stress_test)
        btn_layout.addWidget(load_btn)
        btn_layout.addWidget(stress_btn)
        layout.addLayout(btn_layout)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def run_load_test(self):
        url = self.url_input.text()
        num_requests = self.requests_input.value()
        concurrent = self.concurrent_input.value()
        
        results = self.tool.test_endpoint(url, num_requests, concurrent)
        self.display_results(results)
    
    def run_stress_test(self):
        url = self.url_input.text()
        results = self.tool.stress_test(url, duration_seconds=30)
        self.display_results(results)
    
    def display_results(self, results):
        if "error" in results:
            self.results_text.setText(f"Error: {results['error']}")
            return
        
        text = f"Load Test Results\n{'='*50}\n\n"
        for key, value in results.items():
            text += f"{key}: {value}\n"
        
        self.results_text.setText(text)

class NetworkStressTab(QWidget):
    """Network Stress Simulator Tab"""
    
    def __init__(self):
        super().__init__()
        self.tool = NetworkStressSimulator()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Network Interface:"))
        self.interface_input = QLineEdit()
        self.interface_input.setText("eth0")
        layout.addWidget(self.interface_input)
        
        # Latency
        latency_layout = QHBoxLayout()
        latency_layout.addWidget(QLabel("Latency (ms):"))
        self.latency_input = QSpinBox()
        self.latency_input.setMaximum(10000)
        latency_layout.addWidget(self.latency_input)
        layout.addLayout(latency_layout)
        
        # Packet Loss
        loss_layout = QHBoxLayout()
        loss_layout.addWidget(QLabel("Packet Loss (%):"))
        self.loss_input = QSpinBox()
        self.loss_input.setMaximum(100)
        loss_layout.addWidget(self.loss_input)
        layout.addLayout(loss_layout)
        
        # Bandwidth
        bw_layout = QHBoxLayout()
        bw_layout.addWidget(QLabel("Bandwidth Limit (Kbps):"))
        self.bandwidth_input = QSpinBox()
        self.bandwidth_input.setMaximum(1000000)
        bw_layout.addWidget(self.bandwidth_input)
        layout.addLayout(bw_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        apply_btn = QPushButton("Apply Conditions")
        apply_btn.clicked.connect(self.apply_conditions)
        clear_btn = QPushButton("Clear All Rules")
        clear_btn.clicked.connect(self.clear_rules)
        btn_layout.addWidget(apply_btn)
        btn_layout.addWidget(clear_btn)
        layout.addLayout(btn_layout)
        
        # Info
        layout.addWidget(QLabel("Note: Requires Linux with tc (traffic control) and sudo access"))
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def apply_conditions(self):
        interface = self.interface_input.text()
        latency = self.latency_input.value()
        loss = self.loss_input.value()
        bandwidth = self.bandwidth_input.value()
        
        result = self.tool.combine_conditions(interface, latency, loss, bandwidth)
        self.display_result(result)
    
    def clear_rules(self):
        interface = self.interface_input.text()
        result = self.tool.clear_all_rules(interface)
        self.display_result(result)
    
    def display_result(self, result):
        text = "Status:\n"
        for key, value in result.items():
            text += f"{key}: {value}\n"
        self.results_text.setText(text)

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hackers Toolkit - Professional Security Analysis")
        self.setGeometry(100, 100, 1200, 800)
        
        Logger.info("Hackers Toolkit started")
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create layout
        layout = QVBoxLayout()
        
        # Create tabs
        self.tabs = QTabWidget()
        
        self.tabs.addTab(PortScannerTab(), "Port Scanner")
        self.tabs.addTab(DNSLookupTab(), "DNS Lookup")
        self.tabs.addTab(IPGeolocationTab(), "IP Geolocation")
        self.tabs.addTab(SSLAnalyzerTab(), "SSL Analyzer")
        self.tabs.addTab(PasswordAnalyzerTab(), "Password Analyzer")
        self.tabs.addTab(HashAnalyzerTab(), "Hash Analyzer")
        self.tabs.addTab(IPFinderTab(), "IP Finder")
        self.tabs.addTab(DDoSAnalyzerTab(), "DDoS Analyzer")
        self.tabs.addTab(HTTPHeaderTab(), "HTTP Headers")
        self.tabs.addTab(SubdomainEnumTab(), "Subdomain Enum")
        self.tabs.addTab(WHOISTab(), "WHOIS Lookup")
        self.tabs.addTab(ReportGeneratorTab(), "Report Generator")
        self.tabs.addTab(CVEDatabaseTab(), "CVE Database")
        self.tabs.addTab(LoadTesterTab(), "Load Tester")
        self.tabs.addTab(NetworkStressTab(), "Network Stress")
        self.tabs.addTab(SettingsDialog(), "Settings")
        
        layout.addWidget(self.tabs)
        
        central_widget.setLayout(layout)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
    
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.information(
            self,
            "About Hackers Toolkit",
            "Hackers Toolkit v2.0.0\n\n"
            "Professional Cybersecurity Analysis Platform\n\n"
            "Core Tools (8):\n"
            "• Port Scanning\n"
            "• DNS Lookup\n"
            "• IP Geolocation\n"
            "• SSL/TLS Analysis\n"
            "• Network Reconnaissance\n"
            "• Vulnerability Scanner\n"
            "• Password Analysis\n"
            "• Hash Analysis\n\n"
            "Advanced Tools (7):\n"
            "• IP Finder\n"
            "• DDoS Analyzer\n"
            "• HTTP Header Analysis\n"
            "• Subdomain Enumeration\n"
            "• WHOIS Lookup\n"
            "• Report Generator\n"
            "• CVE Database\n\n"
            "For authorized security testing only"
        )

def main():
    app = application = __import__('PyQt5.QtWidgets', fromlist=['QApplication']).QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
