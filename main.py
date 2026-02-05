#!/usr/bin/env python3
"""
Hackers Toolkit - Application Launcher
v2.3.0 - Cybersecurity analysis platform
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from PyQt5.QtWidgets import QApplication
from gui.main_window_sidebar import MainWindow
from utils.logger import Logger

def main():
    """Start application"""
    Logger.info("Launching Hackers Toolkit v2.3.0")
    
    try:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        Logger.error(f"Error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
