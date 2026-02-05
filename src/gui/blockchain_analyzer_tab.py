"""
Blockchain Analyzer Tab
PyQt5 GUI component for cryptocurrency address analysis
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, 
                            QProgressBar, QMessageBox)
from PyQt5.QtCore import Qt
from src.tools.blockchain_analyzer import BlockchainAnalyzer
from src.utils.logger import Logger

logger = Logger.get_logger("BlockchainAnalyzerTab")


class BlockchainAnalyzerTab(QWidget):
    """GUI Tab for Blockchain address analysis"""
    
    def __init__(self):
        super().__init__()
        self.analyzer = BlockchainAnalyzer()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Blockchain Address Analyzer")
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #00ccff;")
        layout.addWidget(title_label)
        
        # Input section
        input_layout = QHBoxLayout()
        
        input_layout.addWidget(QLabel("Cryptocurrency Type:"))
        self.crypto_combo = QComboBox()
        self.crypto_combo.addItems(["Bitcoin", "Ethereum"])
        input_layout.addWidget(self.crypto_combo)
        
        input_layout.addWidget(QLabel("Address:"))
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Enter Bitcoin or Ethereum address...")
        input_layout.addWidget(self.address_input)
        
        layout.addLayout(input_layout)
        
        # Button section
        button_layout = QHBoxLayout()
        
        analyze_btn = QPushButton("Analyze Address")
        analyze_btn.clicked.connect(self.analyze_address)
        button_layout.addWidget(analyze_btn)
        
        detect_btn = QPushButton("Auto-Detect Type")
        detect_btn.clicked.connect(self.detect_type)
        button_layout.addWidget(detect_btn)
        
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(clear_btn)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results area
        results_label = QLabel("Analysis Results:")
        results_label.setStyleSheet("font-weight: bold; color: #00ccff;")
        layout.addWidget(results_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(300)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def analyze_address(self):
        """Analyze the entered cryptocurrency address"""
        address = self.address_input.text().strip()
        
        if not address:
            QMessageBox.warning(self, "Input Error", "Please enter a cryptocurrency address")
            return
        
        crypto_type = self.crypto_combo.currentText()
        
        try:
            self.progress.setVisible(True)
            self.results_text.clear()
            
            if crypto_type == "Bitcoin":
                result = self.analyzer.analyze_bitcoin_address(address)
            else:
                result = self.analyzer.analyze_ethereum_address(address)
            
            if result.get("success"):
                self.display_results(result, crypto_type)
            else:
                self.results_text.setText(f"Error: {result.get('error', 'Unknown error')}")
            
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")
        finally:
            self.progress.setVisible(False)
    
    def detect_type(self):
        """Auto-detect the cryptocurrency type"""
        address = self.address_input.text().strip()
        
        if not address:
            QMessageBox.warning(self, "Input Error", "Please enter a cryptocurrency address")
            return
        
        try:
            detected_type = self.analyzer.detect_address_type(address)
            
            if detected_type == "Bitcoin":
                self.crypto_combo.setCurrentIndex(0)
                msg = "✓ Detected as Bitcoin address"
            elif detected_type == "Ethereum":
                self.crypto_combo.setCurrentIndex(1)
                msg = "✓ Detected as Ethereum address"
            else:
                msg = "✗ Address type not recognized"
            
            self.results_text.setText(msg)
            
        except Exception as e:
            logger.error(f"Detection error: {str(e)}")
            self.results_text.setText(f"Error: {str(e)}")
    
    def display_results(self, result, crypto_type):
        """Display analysis results in formatted text"""
        output = f"=== {crypto_type} Address Analysis ===\n\n"
        
        for key, value in result.items():
            if key != "success":
                formatted_key = key.replace("_", " ").title()
                output += f"{formatted_key}: {value}\n"
        
        # Get risk score
        address = self.address_input.text().strip()
        risk = self.analyzer.get_address_risk_score(address, crypto_type)
        output += f"\nRisk Score: {risk['risk_level']} ({risk['score']}/100)"
        
        self.results_text.setText(output)
    
    def clear_results(self):
        """Clear all results and inputs"""
        self.address_input.clear()
        self.results_text.clear()
        self.crypto_combo.setCurrentIndex(0)
