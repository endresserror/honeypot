#!/bin/bash

# Development environment setup script for Vulnerability Scanner System

set -e

echo "Setting up development environment for Vulnerability Scanner System..."

# Check if Python 3.9+ is available
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.9"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.9 or higher is required. Found: $python_version"
    exit 1
fi

echo "Python version check passed: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install Data Server dependencies
echo "Installing Data Server dependencies..."
cd data-server
pip install -r requirements.txt
cd ..

# Install Scanner dependencies
echo "Installing Scanner dependencies..."
cd scanner
pip install -r requirements.txt
cd ..

# Install Honeypot dependencies
echo "Installing Honeypot dependencies..."
cd honeypot
pip install -r requirements.txt
cd ..

# Install Node.js dependencies for dashboard
if command -v npm &> /dev/null; then
    echo "Installing Dashboard dependencies..."
    cd dashboard
    npm install
    cd ..
else
    echo "Warning: npm not found. Please install Node.js to set up the dashboard."
fi

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p logs
mkdir -p data-server/logs
mkdir -p scanner/logs
mkdir -p scanner/results
mkdir -p honeypot/logs

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << EOF
# Database Configuration
DATABASE_URL=postgresql://scanner_user:scanner_password@localhost:5432/vulnerability_scanner

# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=dev-secret-key-change-in-production

# Data Server Configuration
DATA_SERVER_URL=http://localhost:5001

# Scanner Configuration
SCANNER_INSTANCE_ID=dev-scanner-001

# Logging
LOG_LEVEL=INFO

# Development settings
DEBUG=true
EOF
    echo ".env file created with default values. Please review and update as needed."
fi

# Initialize database (if PostgreSQL is available)
if command -v psql &> /dev/null; then
    echo "PostgreSQL found. You can now initialize the database:"
    echo "  1. Create database: createdb vulnerability_scanner"
    echo "  2. Run: python scripts/db_manager.py init"
    echo "  3. Create sample data: python scripts/db_manager.py sample-data"
else
    echo "Warning: PostgreSQL not found. Please install PostgreSQL and create the database manually."
fi

echo ""
echo "Development environment setup completed!"
echo ""
echo "Next steps:"
echo "1. Make sure PostgreSQL is running and create the database:"
echo "   createdb vulnerability_scanner"
echo ""
echo "2. Initialize the database:"
echo "   python scripts/db_manager.py init"
echo ""
echo "3. Create sample data (optional):"
echo "   python scripts/db_manager.py sample-data"
echo ""
echo "4. Start the services:"
echo "   # Terminal 1: Data Server"
echo "   cd data-server && python app.py"
echo ""
echo "   # Terminal 2: Dashboard (if Node.js is available)"
echo "   cd dashboard && npm start"
echo ""
echo "   # Terminal 3: Honeypot"
echo "   cd honeypot && python app.py"
echo ""
echo "5. Run a vulnerability scan:"
echo "   cd scanner && python src/main.py scan --target-url http://localhost:8080/product.php?id=1"
echo ""
echo "Access points:"
echo "- Management Dashboard: http://localhost:3000"
echo "- Data Server API: http://localhost:5001"
echo "- Honeypot Website: http://localhost:8080"