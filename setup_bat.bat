@echo off
REM SecureChat Setup Script for Windows
REM This script automates the complete setup process

echo ================================================
echo SecureChat - Automated Setup
echo ================================================
echo.

REM Check Python installation
echo [1/8] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)
python --version
echo.

REM Create virtual environment
echo [2/8] Creating virtual environment...
if exist .venv (
    echo Virtual environment already exists, skipping...
) else (
    python -m venv .venv
    echo Virtual environment created
)
echo.

REM Activate virtual environment and install dependencies
echo [3/8] Installing dependencies...
call .venv\Scripts\activate.bat
pip install -r requirements.txt
echo.

REM Create .env file
echo [4/8] Setting up environment configuration...
if exist .env (
    echo .env already exists, skipping...
) else (
    copy .env.example .env
    echo .env file created from template
    echo Please edit .env if you need custom MySQL credentials
)
echo.

REM Create directories
echo [5/8] Creating required directories...
if not exist certs mkdir certs
if not exist transcripts mkdir transcripts
echo Directories created
echo.

REM Check MySQL connection
echo [6/8] Checking MySQL connection...
python -c "import pymysql; pymysql.connect(host='localhost', port=3306, user='scuser', password='scpass', database='securechat')" 2>nul
if errorlevel 1 (
    echo WARNING: Cannot connect to MySQL
    echo Please ensure MySQL is running with the following configuration:
    echo   Host: localhost
    echo   Port: 3306
    echo   User: scuser
    echo   Password: scpass
    echo   Database: securechat
    echo.
    echo To start MySQL with Docker:
    echo   docker run -d --name securechat-db -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_DATABASE=securechat -e MYSQL_USER=scuser -e MYSQL_PASSWORD=scpass -p 3306:3306 mysql:8
    echo.
    pause
) else (
    echo MySQL connection successful
)
echo.

REM Initialize database
echo [7/8] Initializing database schema...
python -m app.storage.db
echo.

REM Generate certificates
echo [8/8] Generating certificates...
if exist certs\ca_cert.pem (
    echo Certificates already exist, skipping...
) else (
    echo Generating Root CA...
    python scripts\gen_ca.py --name "FAST-NU Root CA" --output certs
    echo.
    
    echo Generating Server Certificate...
    python scripts\gen_cert.py --cn server.local --out certs\server --ca-cert certs\ca_cert.pem --ca-key certs\ca_key.pem
    echo.
    
    echo Generating Client Certificate...
    python scripts\gen_cert.py --cn client.local --out certs\client --ca-cert certs\ca_cert.pem --ca-key certs\ca_key.pem
    echo.
)

echo ================================================
echo Setup Complete!
echo ================================================
echo.
echo Next steps:
echo   1. Open TWO command prompts
echo   2. In Terminal 1, run: start_server.bat
echo   3. In Terminal 2, run: start_client.bat
echo.
echo For testing:
echo   - Run attack simulations: python scripts\test_attacks.py
echo   - Verify receipts: python scripts\verify_receipt.py --help
echo   - Export database: python scripts\export_db.py
echo.
pause
