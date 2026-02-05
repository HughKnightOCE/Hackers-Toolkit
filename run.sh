#!/bin/bash
# Hackers Toolkit Launcher
# This script launches the Hackers Toolkit GUI application

echo "Starting Hackers Toolkit..."
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    echo "Please install Python 3.8+ to run this toolkit"
    exit 1
fi

# Check if required packages are installed
python3 -c "import PyQt5" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required packages..."
    pip3 install -r requirements.txt
fi

# Run the application
python3 main.py

if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Application failed to start"
    echo "Check the logs directory for more information"
fi
