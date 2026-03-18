@echo off
echo ========================================
echo AutoVulRepair - AI Patching Setup
echo ========================================
echo.
echo This will set up the AI-powered patching system.
echo.
echo Features:
echo   - AI-powered patch generation with Gemini
echo   - CVE database integration
echo   - Intelligent vulnerability analysis
echo   - Secure code fixes with explanations
echo.
pause

echo.
echo ========================================
echo Step 1: Installing Python packages
echo ========================================
echo.

pip install google-generativeai

if errorlevel 1 (
    echo.
    echo ERROR: Package installation failed!
    echo Please run manually: pip install google-generativeai
    pause
    exit /b 1
)

echo.
echo ✓ Packages installed successfully!

echo.
echo ========================================
echo Step 2: API Key Setup
echo ========================================
echo.
echo You need a FREE Gemini API key to use AI patching.
echo.
echo 1. Go to: https://makersuite.google.com/app/apikey
echo 2. Click "Create API Key"
echo 3. Copy your key (starts with AIza...)
echo.
echo Please enter your Gemini API key:
set /p GEMINI_KEY="API Key: "

if "%GEMINI_KEY%"=="" (
    echo.
    echo No API key entered. You can add it later to your .env file:
    echo GEMINI_API_KEY=your_key_here
) else (
    echo.
    echo Adding API key to .env file...
    
    REM Check if .env exists
    if exist .env (
        REM Check if GEMINI_API_KEY already exists
        findstr /C:"GEMINI_API_KEY" .env >nul
        if errorlevel 1 (
            REM Key doesn't exist, add it
            echo GEMINI_API_KEY=%GEMINI_KEY% >> .env
            echo ✓ API key added to .env
        ) else (
            echo.
            echo GEMINI_API_KEY already exists in .env
            echo Please update it manually if needed.
        )
    ) else (
        REM Create new .env file
        echo GEMINI_API_KEY=%GEMINI_KEY% > .env
        echo ✓ Created .env file with API key
    )
)

echo.
echo ========================================
echo Step 3: CVE Database (Optional)
echo ========================================
echo.

REM Check if FAISS index already exists
if exist "faiss_indexes\cve-full\index.faiss" (
    echo ✓ FAISS CVE database already exists!
    echo   Location: faiss_indexes\cve-full\
    echo   Skipping conversion...
    goto skip_cve_setup
)

echo For enhanced patching with CVE context, you can set up the CVE database.
echo This is optional - patching will work without it.
echo.
set /p SETUP_CVE="Set up CVE database? (y/n): "

if /i "%SETUP_CVE%"=="y" (
    if exist "cves.db" (
        echo.
        echo Converting CVE database to FAISS...
        python cve_to_faiss.py --index-name cve-full --max-records 10000
        if errorlevel 1 (
            echo Warning: FAISS conversion failed. Patching will work without CVE context.
        ) else (
            echo ✓ CVE database converted successfully!
        )
    ) else (
        echo.
        echo Warning: cves.db not found. Patching will work without CVE context.
        echo To get full functionality, place cves.db in this directory.
    )
) else (
    echo.
    echo Skipping CVE database setup.
    echo You can set it up later by running: python cve_to_faiss.py
)

:skip_cve_setup

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo ✓ AI Patching system is ready to use!
echo.
echo Next steps:
echo 1. Start the application: python app.py
echo 2. Run a scan to find vulnerabilities
echo 3. Click "AI-Powered Patching" button
echo 4. Generate and review patches
echo.
echo For more information, see PATCHING_SETUP.md
echo.
pause
