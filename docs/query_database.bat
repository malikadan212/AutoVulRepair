@echo off
REM Quick script to query SQLite database

echo ============================================================
echo SQLite Database Query Tool
echo ============================================================
echo.
echo Database: scans.db
echo.
echo Available commands:
echo   .tables          - List all tables
echo   .schema scans    - Show table schema
echo   SELECT * FROM scans;  - View all records
echo   .quit            - Exit
echo.
echo ============================================================
echo.

sqlite3 scans.db
