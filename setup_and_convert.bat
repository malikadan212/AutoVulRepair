@echo off
echo ========================================
echo CVE to Pinecone Converter - Setup
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

echo [1/3] Installing required packages...
pip install -r pinecone_requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install packages
    pause
    exit /b 1
)

echo.
echo [2/3] Setup complete!
echo.
echo ========================================
echo Next Steps:
echo ========================================
echo.
echo 1. Create a FREE Pinecone account at: https://www.pinecone.io/
echo 2. Get your API key from the Pinecone console
echo 3. Run the conversion:
echo.
echo    python cve_to_pinecone.py --api-key YOUR_API_KEY --index-name cve-demo --max-records 100
echo.
echo For detailed instructions, see QUICKSTART.md
echo.
pause
