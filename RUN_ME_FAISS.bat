@echo off
echo ========================================
echo CVE to FAISS - FREE Local Vector DB
echo ========================================
echo.
echo FAISS Advantages:
echo   - Completely FREE (no limits!)
echo   - All 316,437 CVEs supported
echo   - Runs locally (your data stays private)
echo   - Faster than cloud solutions
echo   - No account or API key needed
echo.
echo ========================================
echo Step 1: Installing packages...
echo ========================================
echo.

pip install faiss-cpu sentence-transformers tqdm torch numpy --quiet

if errorlevel 1 (
    echo.
    echo ERROR: Package installation failed!
    echo Please run manually: pip install -r faiss_requirements.txt
    pause
    exit /b 1
)

echo.
echo ========================================
echo Step 2: Converting CVE Database
echo ========================================
echo.
echo Choose conversion size:
echo   1. Quick Test (100 CVEs) - 1 minute
echo   2. Small (1,000 CVEs) - 5 minutes
echo   3. Medium (10,000 CVEs) - 30 minutes
echo   4. Large (100,000 CVEs) - 2 hours
echo   5. FULL (316,437 CVEs) - 4 hours [FREE!]
echo.

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    set max_records=100
    set index_name=cve-demo
) else if "%choice%"=="2" (
    set max_records=1000
    set index_name=cve-small
) else if "%choice%"=="3" (
    set max_records=10000
    set index_name=cve-medium
) else if "%choice%"=="4" (
    set max_records=100000
    set index_name=cve-large
) else if "%choice%"=="5" (
    set max_records=
    set index_name=cve-full
) else (
    echo Invalid choice!
    pause
    exit /b 1
)

echo.
echo Starting conversion...
echo.

if "%max_records%"=="" (
    python cve_to_faiss.py --index-name %index_name%
) else (
    python cve_to_faiss.py --index-name %index_name% --max-records %max_records%
)

if errorlevel 1 (
    echo.
    echo ERROR: Conversion failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Step 3: Test Search
echo ========================================
echo.

set /p test_query="Enter a search query (or press Enter to skip): "

if not "%test_query%"=="" (
    echo.
    echo Searching for: %test_query%
    echo.
    python search_cve_faiss.py --index-name %index_name% --query "%test_query%" --top-k 5
)

echo.
echo ========================================
echo SUCCESS! Your CVE vector database is ready!
echo ========================================
echo.
echo Index location: faiss_indexes\%index_name%.index
echo.
echo To search:
echo   python search_cve_faiss.py --index-name %index_name% --query "YOUR_QUERY"
echo.
echo Examples:
echo   python search_cve_faiss.py --index-name %index_name% --query "SQL injection"
echo   python search_cve_faiss.py --index-name %index_name% --query "buffer overflow" --severity HIGH
echo.
pause
