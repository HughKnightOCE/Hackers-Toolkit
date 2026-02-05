from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, 
    QPushButton, QStackedWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor


class HelpPanel(QWidget):
    """Reusable help panel for displaying input requirements and usage info"""

    def __init__(self, title: str, description: str, inputs: dict, examples: dict):
        super().__init__()
        self.title = title
        self.description = description
        self.inputs = inputs
        self.examples = examples
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        title_label = QLabel(self.title)
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)
        
        desc_label = QLabel(self.description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #888; margin: 10px 0;")
        layout.addWidget(desc_label)
        
        layout.addSpacing(10)
        
        inputs_label = QLabel("Required Inputs:")
        inputs_font = QFont()
        inputs_font.setBold(True)
        inputs_label.setFont(inputs_font)
        layout.addWidget(inputs_label)
        
        for input_name, input_help in self.inputs.items():
            input_widget = QWidget()
            input_layout = QVBoxLayout()
            input_layout.setContentsMargins(20, 5, 0, 5)
            
            name_label = QLabel(f"• {input_name}")
            name_label.setStyleSheet("font-weight: bold; color: #0099ff;")
            input_layout.addWidget(name_label)
            
            help_label = QLabel(input_help)
            help_label.setWordWrap(True)
            help_label.setStyleSheet("color: #aaa; margin-left: 15px; font-size: 11px;")
            input_layout.addWidget(help_label)
            
            input_widget.setLayout(input_layout)
            layout.addWidget(input_widget)
        
        layout.addSpacing(10)
        
        examples_label = QLabel("Examples:")
        examples_label.setFont(inputs_font)
        layout.addWidget(examples_label)
        
        for example_name, example_value in self.examples.items():
            example_widget = QWidget()
            example_layout = QVBoxLayout()
            example_layout.setContentsMargins(20, 5, 0, 5)
            
            example_name_label = QLabel(f"• {example_name}")
            example_name_label.setStyleSheet("font-weight: bold; color: #00cc88;")
            example_layout.addWidget(example_name_label)
            
            example_value_label = QLabel(example_value)
            example_value_label.setWordWrap(True)
            example_value_label.setStyleSheet("color: #999; margin-left: 15px; font-family: monospace; font-size: 10px;")
            example_layout.addWidget(example_value_label)
            
            example_widget.setLayout(example_layout)
            layout.addWidget(example_widget)
        
        layout.addStretch()
        
        self.setLayout(layout)


class ToolTab(QWidget):
    """Base widget combining a tool UI with a help panel"""

    def __init__(self, tool_widget: QWidget, help_title: str, help_description: str, 
                 required_inputs: dict, examples: dict):
        super().__init__()
        self.tool_widget = tool_widget
        self.help_title = help_title
        self.help_description = help_description
        self.required_inputs = required_inputs
        self.examples = examples
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()
        
        help_panel = HelpPanel(
            self.help_title,
            self.help_description,
            self.required_inputs,
            self.examples
        )
        
        help_scroll = QScrollArea()
        help_scroll.setWidget(help_panel)
        help_scroll.setWidgetResizable(True)
        help_scroll.setMaximumWidth(350)
        help_scroll.setStyleSheet("""
            QScrollArea {
                background-color: #1a1a1a;
                border-right: 1px solid #333;
            }
        """)
        
        layout.addWidget(help_scroll, 1)
        layout.addWidget(self.tool_widget, 2)
        
        self.setLayout(layout)
