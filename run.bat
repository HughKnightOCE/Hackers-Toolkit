@echo off
REM Hackers Toolkit Launcher
REM This script launches the Hackers Toolkit GUI application

echo Starting Hackers Toolkit...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ and add it to your system PATH
    pause
    exit /b 1
)

REM Check if required packages are installed
python -c "import PyQt5" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install -r requirements.txt
)

REM Run the application
python main.py

if errorlevel 1 (
    echo.
    echo Error: Application failed to start
    echo Check the logs directory for more information
    pause
)
