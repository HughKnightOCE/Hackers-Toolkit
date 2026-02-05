#!/usr/bin/env python3
"""
Hackers Toolkit - Main Application Launcher
Professional Cybersecurity Analysis Platform
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow
from utils.logger import Logger

def main():
    """Main application entry point"""
    Logger.info("Starting Hackers Toolkit")
    
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        Logger.error(f"Application error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
