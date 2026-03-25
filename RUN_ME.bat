@echo off
echo ========================================
echo CVE to Pinecone - Quick Setup
echo ========================================
echo.
echo This script will help you convert your CVE database to Pinecone.
echo.
echo Step 1: Installing packages (this may take 5-10 minutes)...
echo.

pip install pinecone-client sentence-transformers tqdm torch --quiet

if errorlevel 1 (
    echo.
    echo ERROR: Package installation failed!
    echo Please run manually: pip install pinecone-client sentence-transformers tqdm torch
    pause
    exit /b 1
)

echo.
echo ========================================
echo Step 2: Ready to convert!
echo ========================================
echo.
echo Please have your Pinecone API key ready.
echo You can find it at: https://app.pinecone.io/ under "API Keys"
echo.
echo Starting interactive setup...
echo.

python interactive_setup.py

pause
