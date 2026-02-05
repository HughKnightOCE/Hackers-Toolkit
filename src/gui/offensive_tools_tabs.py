from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QHBoxLayout, QSpinBox, QComboBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from gui.help_panel import HelpPanel
from tools.sql_injection_tester import SQLInjectionTester
from tools.xss_scanner import XSSScanner
from tools.packet_sniffer import PacketSniffer
from tools.firewall_analyzer import FirewallRulesAnalyzer
from tools.audit_log_analyzer import AuditLogAnalyzer
from tools.directory_traversal_scanner import DirectoryTraversalScanner
from tools.command_injection_tester import CommandInjectionTester
from tools.cors_analyzer import CORSAnalyzer
from utils.logger import Logger

logger = Logger.get_logger("OffensiveToolsTabs")


class SQLInjectionTab(QWidget):
    """SQL Injection Tester with help guidance"""

    def __init__(self):
        super().__init__()
        self.tester = SQLInjectionTester()
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()
        
        help_panel = HelpPanel(
            "SQL Injection Tester",
            "Test web applications for SQL injection vulnerabilities by submitting crafted payloads.",
            {
                "Target URL": "The web server address (e.g., http://target.com or https://api.example.com)",
                "Parameter Name": "The input field name to test (e.g., 'username', 'id', 'search')",
                "HTTP Method": "GET or POST - check your target form/API documentation",
                "Additional Data (Optional)": "Other form fields if needed (e.g., password=123&token=abc)"
            },
            {
                "URL": "http://vulnerable-app.local/search.php",
                "Parameter": "query",
                "Method": "GET",
                "Looking for": "SQL error messages, unexpected behavior, or data extraction"
            }
        )
        
        help_scroll = self._create_scroll_area(help_panel)
        layout.addWidget(help_scroll, 1)
        
        tool_widget = self._create_tool_widget()
        layout.addWidget(tool_widget, 2)
        
        self.setLayout(layout)

    def _create_tool_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("SQL Injection Tester"))
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://target.com/search.php")
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.url_input)
        
        self.param_input = QLineEdit()
        self.param_input.setPlaceholderText("e.g., query, id, username")
        layout.addWidget(QLabel("Parameter Name:"))
        layout.addWidget(self.param_input)
        
        method_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        method_layout.addWidget(QLabel("Method:"))
        method_layout.addWidget(self.method_combo)
        method_layout.addStretch()
        layout.addLayout(method_layout)
        
        self.data_input = QLineEdit()
        self.data_input.setPlaceholderText("Other params (optional)")
        layout.addWidget(QLabel("Additional Data:"))
        layout.addWidget(self.data_input)
        
        test_btn = QPushButton("Test for SQL Injection")
        test_btn.clicked.connect(self.test_injection)
        layout.addWidget(test_btn)
        
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def test_injection(self):
        url = self.url_input.text().strip()
        param = self.param_input.text().strip()
        method = self.method_combo.currentText()
        
        if not url or not param:
            self.output.setText("Error: URL and Parameter name are required")
            return
        
        self.output.setText("Testing... Please wait")
        try:
            result = self.tester.test_endpoint(url, param, method)
            
            output_text = f"Results for {url}\n"
            output_text += f"Parameter: {param}\n\n"
            
            if result["vulnerable"]:
                output_text += "⚠️  VULNERABLE - SQL Injection found!\n"
                output_text += f"Payloads: {', '.join(result['payloads_found'][:3])}\n"
            else:
                output_text += "✓ No SQL injection detected\n"
            
            self.output.setText(output_text)
        except Exception as e:
            self.output.setText(f"Error: {str(e)}")

    def _create_scroll_area(self, widget):
        from PyQt5.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        scroll.setMaximumWidth(320)
        scroll.setStyleSheet("QScrollArea { background-color: #1a1a1a; border-right: 1px solid #333; }")
        return scroll


class DirectoryTraversalTab(QWidget):
    """Directory Traversal Scanner with guidance"""

    def __init__(self):
        super().__init__()
        self.scanner = DirectoryTraversalScanner()
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()
        
        help_panel = HelpPanel(
            "Directory Traversal Scanner",
            "Test web servers for path traversal vulnerabilities (LFI - Local File Inclusion).",
            {
                "Target URL": "The web server address (e.g., http://target.com)",
                "Endpoint": "The web path to test (e.g., /download, /file, /api/data)",
                "File to Access": "System file to probe for (e.g., /etc/passwd, windows/win.ini, database.db)",
            },
            {
                "URL": "http://fileserver.local",
                "Endpoint": "/download.php",
                "File": "/etc/passwd",
                "Look for": "Actual file contents, configuration data, or error messages revealing paths"
            }
        )
        
        help_scroll = self._create_scroll_area(help_panel)
        layout.addWidget(help_scroll, 1)
        
        tool_widget = self._create_tool_widget()
        layout.addWidget(tool_widget, 2)
        
        self.setLayout(layout)

    def _create_tool_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Directory Traversal Scanner"))
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://target.com")
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.url_input)
        
        self.endpoint_input = QLineEdit()
        self.endpoint_input.setPlaceholderText("/download.php")
        layout.addWidget(QLabel("Endpoint:"))
        layout.addWidget(self.endpoint_input)
        
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("/etc/passwd")
        layout.addWidget(QLabel("File to Access:"))
        layout.addWidget(self.file_input)
        
        scan_btn = QPushButton("Scan for Path Traversal")
        scan_btn.clicked.connect(self.scan_traversal)
        layout.addWidget(scan_btn)
        
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def scan_traversal(self):
        url = self.url_input.text().strip()
        endpoint = self.endpoint_input.text().strip() or "/"
        file_target = self.file_input.text().strip()
        
        if not url:
            self.output.setText("Error: Target URL is required")
            return
        
        self.output.setText("Scanning... Please wait")
        try:
            result = self.scanner.scan_endpoint(url, endpoint, file_target)
            
            output_text = f"Scan Results\n"
            output_text += f"Target: {url}{endpoint}\n\n"
            
            if result["vulnerable"]:
                output_text += "⚠️  VULNERABLE - Directory traversal found!\n"
                output_text += f"Working payloads: {', '.join(result['payloads_found'][:3])}\n"
            else:
                output_text += "✓ No traversal vulnerabilities found\n"
            
            self.output.setText(output_text)
        except Exception as e:
            self.output.setText(f"Error: {str(e)}")

    def _create_scroll_area(self, widget):
        from PyQt5.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        scroll.setMaximumWidth(320)
        scroll.setStyleSheet("QScrollArea { background-color: #1a1a1a; border-right: 1px solid #333; }")
        return scroll


class CommandInjectionTab(QWidget):
    """Command Injection Tester with guidance"""

    def __init__(self):
        super().__init__()
        self.tester = CommandInjectionTester()
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()
        
        help_panel = HelpPanel(
            "Command Injection Tester",
            "Test for OS command injection (shell metacharacters like ; | & $ `).",
            {
                "Target URL": "The vulnerable application (e.g., http://app.local/ping.php)",
                "Parameter Name": "Input field vulnerable to injection (e.g., 'host', 'ip', 'domain')",
                "HTTP Method": "GET or POST - form submission method",
                "Success Indicators": "Successful execution shows username, OS paths, or system info in response"
            },
            {
                "URL": "http://vulnerable-app.local/ping.php",
                "Parameter": "host",
                "Method": "GET",
                "Success": "Response shows 'uid=33' or system commands output"
            }
        )
        
        help_scroll = self._create_scroll_area(help_panel)
        layout.addWidget(help_scroll, 1)
        
        tool_widget = self._create_tool_widget()
        layout.addWidget(tool_widget, 2)
        
        self.setLayout(layout)

    def _create_tool_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Command Injection Tester"))
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://target.com/ping.php")
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.url_input)
        
        self.param_input = QLineEdit()
        self.param_input.setPlaceholderText("host, ip, domain")
        layout.addWidget(QLabel("Parameter Name:"))
        layout.addWidget(self.param_input)
        
        method_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        method_layout.addWidget(QLabel("Method:"))
        method_layout.addWidget(self.method_combo)
        method_layout.addStretch()
        layout.addLayout(method_layout)
        
        test_btn = QPushButton("Test for Command Injection")
        test_btn.clicked.connect(self.test_injection)
        layout.addWidget(test_btn)
        
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def test_injection(self):
        url = self.url_input.text().strip()
        param = self.param_input.text().strip()
        method = self.method_combo.currentText()
        
        if not url or not param:
            self.output.setText("Error: URL and Parameter name are required")
            return
        
        self.output.setText("Testing... Please wait")
        try:
            result = self.tester.test_parameter(url, param, method)
            
            output_text = f"Results\n"
            output_text += f"Target: {url}\n"
            output_text += f"Parameter: {param}\n\n"
            
            if result["vulnerable"]:
                output_text += "⚠️  VULNERABLE - Command injection found!\n"
                output_text += f"Payloads: {', '.join(result['payloads_found'][:3])}\n"
            else:
                output_text += "✓ No command injection detected\n"
            
            self.output.setText(output_text)
        except Exception as e:
            self.output.setText(f"Error: {str(e)}")

    def _create_scroll_area(self, widget):
        from PyQt5.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        scroll.setMaximumWidth(320)
        scroll.setStyleSheet("QScrollArea { background-color: #1a1a1a; border-right: 1px solid #333; }")
        return scroll


class CORSTab(QWidget):
    """CORS Configuration Analyzer with guidance"""

    def __init__(self):
        super().__init__()
        self.analyzer = CORSAnalyzer()
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()
        
        help_panel = HelpPanel(
            "CORS Analyzer",
            "Check for CORS (Cross-Origin Resource Sharing) misconfigurations that allow unauthorized cross-site requests.",
            {
                "Target URL": "The API or resource endpoint (e.g., http://api.example.com/data)",
                "Origin to Test": "Potential attacker origin (e.g., http://attacker.com, http://localhost)",
                "Method": "HTTP method the origin would use (GET, POST, DELETE, etc.)"
            },
            {
                "URL": "http://api.example.com/v1/users",
                "Origin": "http://attacker.com",
                "Vulnerability": "If response has 'Access-Control-Allow-Origin: *' or echoes your origin"
            }
        )
        
        help_scroll = self._create_scroll_area(help_panel)
        layout.addWidget(help_scroll, 1)
        
        tool_widget = self._create_tool_widget()
        layout.addWidget(tool_widget, 2)
        
        self.setLayout(layout)

    def _create_tool_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("CORS Configuration Analyzer"))
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://api.example.com/data")
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.url_input)
        
        self.origin_input = QLineEdit()
        self.origin_input.setPlaceholderText("http://attacker.com")
        layout.addWidget(QLabel("Test Origin:"))
        layout.addWidget(self.origin_input)
        
        analyze_btn = QPushButton("Analyze CORS Configuration")
        analyze_btn.clicked.connect(self.analyze_cors)
        layout.addWidget(analyze_btn)
        
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def analyze_cors(self):
        url = self.url_input.text().strip()
        origin = self.origin_input.text().strip() or "http://attacker.com"
        
        if not url:
            self.output.setText("Error: Target URL is required")
            return
        
        self.output.setText("Analyzing... Please wait")
        try:
            result = self.analyzer.analyze_endpoint(url, origin)
            
            output_text = f"CORS Analysis\n"
            output_text += f"Target: {url}\n"
            output_text += f"Origin: {origin}\n\n"
            
            if result.get("error"):
                output_text += f"Error: {result['error']}\n"
            else:
                if result["vulnerable"]:
                    output_text += "⚠️  VULNERABLE - CORS misconfiguration found!\n"
                else:
                    output_text += "✓ CORS appears properly configured\n"
                
                if result["issues"]:
                    output_text += "\nIssues:\n"
                    for issue in result["issues"]:
                        output_text += f"  • {issue}\n"
            
            self.output.setText(output_text)
        except Exception as e:
            self.output.setText(f"Error: {str(e)}")

    def _create_scroll_area(self, widget):
        from PyQt5.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        scroll.setMaximumWidth(320)
        scroll.setStyleSheet("QScrollArea { background-color: #1a1a1a; border-right: 1px solid #333; }")
        return scroll
