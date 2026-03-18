@echo off
echo ========================================
echo CVE RAG System - Quick Start
echo ========================================
echo.
echo This will start an intelligent CVE Q&A system using:
echo   - FAISS (vector search)
echo   - Google Gemini (AI responses)
echo.
echo ========================================
echo Step 1: Install packages
echo ========================================
echo.

pip install google-generativeai flask flask-cors --quiet

if errorlevel 1 (
    echo ERROR: Package installation failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Step 2: Get Gemini API Key
echo ========================================
echo.
echo You need a FREE Gemini API key.
echo.
echo Get it from: https://makersuite.google.com/app/apikey
echo.
set /p api_key="Enter your Gemini API key: "

if "%api_key%"=="" (
    echo ERROR: API key required!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Step 3: Choose Mode
echo ========================================
echo.
echo 1. Interactive Chat (Ask questions)
echo 2. Web Interface (Browser-based)
echo 3. Single Question
echo.

set /p mode="Enter your choice (1-3): "

if "%mode%"=="1" (
    echo.
    echo Starting interactive chat...
    echo Type your questions and press Enter.
    echo Type 'exit' to quit.
    echo.
    python cve_rag_system.py --api-key %api_key%
) else if "%mode%"=="2" (
    echo.
    echo Starting web interface...
    echo Open your browser to: http://localhost:5001/
    echo Press Ctrl+C to stop the server.
    echo.
    python cve_rag_api.py --gemini-key %api_key% --port 5001
) else if "%mode%"=="3" (
    echo.
    set /p question="Enter your question: "
    echo.
    echo Getting answer...
    echo.
    python cve_rag_system.py --api-key %api_key% --query "%question%"
) else (
    echo Invalid choice!
    pause
    exit /b 1
)

pause
