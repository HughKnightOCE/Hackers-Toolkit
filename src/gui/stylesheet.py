"""
Modern Stylesheet for Hackers Toolkit
Professional dark theme with modern aesthetics
"""

MODERN_STYLESHEET = """
QMainWindow {
    background-color: #1e1e2e;
    color: #e0e0e0;
}

QWidget {
    background-color: #1e1e2e;
    color: #e0e0e0;
}

QMenuBar {
    background-color: #2d2d44;
    color: #e0e0e0;
    border-bottom: 2px solid #0099ff;
    padding: 5px;
    font-weight: bold;
}

QMenuBar::item:selected {
    background-color: #0099ff;
    color: #ffffff;
}

QMenu {
    background-color: #2d2d44;
    color: #e0e0e0;
    border: 1px solid #0099ff;
}

QMenu::item:selected {
    background-color: #0099ff;
    color: #ffffff;
    padding-left: 15px;
}

QMenu::separator {
    background-color: #0099ff;
    height: 1px;
    margin: 5px 0px;
}

QTabWidget::pane {
    border: 1px solid #0099ff;
}

QTabBar::tab {
    background-color: #2d2d44;
    color: #a0a0a0;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    border: 1px solid #0099ff;
    border-bottom: none;
}

QTabBar::tab:selected {
    background-color: #0099ff;
    color: #ffffff;
    font-weight: bold;
}

QTabBar::tab:hover {
    background-color: #0066cc;
    color: #ffffff;
}

QLineEdit {
    background-color: #2d2d44;
    color: #e0e0e0;
    border: 2px solid #0099ff;
    border-radius: 5px;
    padding: 5px;
    selection-background-color: #0099ff;
}

QLineEdit:focus {
    border: 2px solid #00ccff;
    background-color: #3a3a52;
}

QPushButton {
    background-color: #0099ff;
    color: #ffffff;
    border: none;
    border-radius: 5px;
    padding: 8px 15px;
    font-weight: bold;
    font-size: 11px;
}

QPushButton:hover {
    background-color: #0066cc;
}

QPushButton:pressed {
    background-color: #004499;
}

QPushButton:disabled {
    background-color: #555555;
    color: #888888;
}

QTextEdit {
    background-color: #2d2d44;
    color: #e0e0e0;
    border: 2px solid #0099ff;
    border-radius: 5px;
    padding: 5px;
    font-family: Consolas, Monaco, monospace;
    font-size: 10px;
}

QComboBox {
    background-color: #2d2d44;
    color: #e0e0e0;
    border: 2px solid #0099ff;
    border-radius: 5px;
    padding: 5px;
}

QComboBox:hover {
    border: 2px solid #00ccff;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
    background-color: #0099ff;
    border-radius: 3px;
}

QSpinBox {
    background-color: #2d2d44;
    color: #e0e0e0;
    border: 2px solid #0099ff;
    border-radius: 5px;
    padding: 5px;
}

QLabel {
    color: #e0e0e0;
    font-size: 11px;
}

QLabel[header="true"] {
    font-weight: bold;
    font-size: 12px;
    color: #00ccff;
}

QStatusBar {
    background-color: #2d2d44;
    color: #e0e0e0;
    border-top: 2px solid #0099ff;
    padding: 5px;
}

QStatusBar::item {
    border: none;
    padding: 0px;
}

QTableWidget {
    background-color: #2d2d44;
    alternate-background-color: #252535;
    color: #e0e0e0;
    border: 1px solid #0099ff;
    border-radius: 5px;
    gridline-color: #0099ff;
}

QTableWidget::item {
    padding: 5px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #0099ff;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #0099ff;
    color: #ffffff;
    padding: 5px;
    border: none;
    font-weight: bold;
}

QScrollBar:vertical {
    background-color: #2d2d44;
    width: 12px;
    border: 1px solid #0099ff;
}

QScrollBar::handle:vertical {
    background-color: #0099ff;
    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {
    background-color: #00ccff;
}

QScrollBar::sub-line:vertical, QScrollBar::add-line:vertical {
    border: none;
    background: none;
}

QScrollBar:horizontal {
    background-color: #2d2d44;
    height: 12px;
    border: 1px solid #0099ff;
}

QScrollBar::handle:horizontal {
    background-color: #0099ff;
    border-radius: 6px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #00ccff;
}

QScrollBar::sub-line:horizontal, QScrollBar::add-line:horizontal {
    border: none;
    background: none;
}

QFormLayout {
    spacing: 10px;
}

QProgressBar {
    background-color: #2d2d44;
    border: 2px solid #0099ff;
    border-radius: 5px;
    text-align: center;
    color: #ffffff;
}

QProgressBar::chunk {
    background-color: #0099ff;
    border-radius: 3px;
}

QMessageBox {
    background-color: #1e1e2e;
}

QMessageBox QLabel {
    color: #e0e0e0;
}

QMessageBox QPushButton {
    min-width: 60px;
}
"""

def get_stylesheet():
    """Return the modern stylesheet"""
    return MODERN_STYLESHEET
