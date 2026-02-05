"""Settings and configuration UI"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QCheckBox, QSpinBox, QFormLayout, QGroupBox, QMessageBox
)
from PyQt5.QtCore import Qt
import json
import os
from utils.logger import Logger

class SettingsDialog(QWidget):
    """Settings and configuration panel"""
    
    def __init__(self):
        super().__init__()
        self.config_file = "config_local.json"
        self.settings = self.load_settings()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # API Settings Group
        api_group = QGroupBox("API Keys")
        api_layout = QFormLayout()
        
        self.abuseipdb_input = QLineEdit()
        self.abuseipdb_input.setText(self.settings.get('abuseipdb', ''))
        self.abuseipdb_input.setEchoMode(QLineEdit.Password)
        api_layout.addRow("AbuseIPDB API Key:", self.abuseipdb_input)
        
        self.shodan_input = QLineEdit()
        self.shodan_input.setText(self.settings.get('shodan', ''))
        self.shodan_input.setEchoMode(QLineEdit.Password)
        api_layout.addRow("Shodan API Key:", self.shodan_input)
        
        self.virustotal_input = QLineEdit()
        self.virustotal_input.setText(self.settings.get('virustotal', ''))
        self.virustotal_input.setEchoMode(QLineEdit.Password)
        api_layout.addRow("VirusTotal API Key:", self.virustotal_input)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)
        
        # Proxy Settings Group
        proxy_group = QGroupBox("Proxy Settings")
        proxy_layout = QFormLayout()
        
        self.proxy_enabled = QCheckBox("Enable Proxy")
        self.proxy_enabled.setChecked(self.settings.get('proxy_enabled', False))
        proxy_layout.addRow("", self.proxy_enabled)
        
        self.proxy_url = QLineEdit()
        self.proxy_url.setText(self.settings.get('proxy_url', 'http://proxy.example.com:8080'))
        proxy_layout.addRow("Proxy URL:", self.proxy_url)
        
        proxy_group.setLayout(proxy_layout)
        layout.addWidget(proxy_group)
        
        # Scanner Settings Group
        scanner_group = QGroupBox("Scanner Settings")
        scanner_layout = QFormLayout()
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setMinimum(1)
        self.timeout_spin.setMaximum(60)
        self.timeout_spin.setValue(self.settings.get('timeout', 5))
        scanner_layout.addRow("Timeout (seconds):", self.timeout_spin)
        
        self.threads_spin = QSpinBox()
        self.threads_spin.setMinimum(1)
        self.threads_spin.setMaximum(100)
        self.threads_spin.setValue(self.settings.get('max_threads', 10))
        scanner_layout.addRow("Max Threads:", self.threads_spin)
        
        self.retries_spin = QSpinBox()
        self.retries_spin.setMinimum(0)
        self.retries_spin.setMaximum(10)
        self.retries_spin.setValue(self.settings.get('retries', 2))
        scanner_layout.addRow("Retries:", self.retries_spin)
        
        scanner_group.setLayout(scanner_layout)
        layout.addWidget(scanner_group)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        btn_layout.addWidget(save_btn)
        
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self.reset_defaults)
        btn_layout.addWidget(reset_btn)
        
        layout.addLayout(btn_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def load_settings(self):
        """Load settings from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.warning(f"Could not load settings: {str(e)}")
        
        return {}
    
    def save_settings(self):
        """Save settings to file"""
        try:
            settings = {
                'abuseipdb': self.abuseipdb_input.text(),
                'shodan': self.shodan_input.text(),
                'virustotal': self.virustotal_input.text(),
                'proxy_enabled': self.proxy_enabled.isChecked(),
                'proxy_url': self.proxy_url.text(),
                'timeout': self.timeout_spin.value(),
                'max_threads': self.threads_spin.value(),
                'retries': self.retries_spin.value()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(settings, f, indent=2)
            
            QMessageBox.information(self, "Success", "Settings saved successfully")
            Logger.info("Settings saved")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")
            Logger.error(f"Settings save error: {str(e)}")
    
    def reset_defaults(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(
            self,
            "Confirm Reset",
            "Reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.abuseipdb_input.clear()
            self.shodan_input.clear()
            self.virustotal_input.clear()
            self.proxy_enabled.setChecked(False)
            self.proxy_url.setText("http://proxy.example.com:8080")
            self.timeout_spin.setValue(5)
            self.threads_spin.setValue(10)
            self.retries_spin.setValue(2)
            Logger.info("Settings reset to defaults")
