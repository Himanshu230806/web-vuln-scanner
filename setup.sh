#!/bin/bash

# Web Application Vulnerability Scanner Setup Script
# For Kali Linux

set -e

echo "=========================================="
echo "Web Vulnerability Scanner Setup"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] Note: Some operations may require sudo privileges${NC}"
fi

echo "[*] Updating package lists..."
sudo apt-get update

echo "[*] Installing system dependencies..."
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    curl \
    git \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libffi-dev \
    libssl-dev

echo "[*] Installing Chrome/Chromium for Selenium..."
sudo apt-get install -y \
    chromium \
    chromium-driver \
    || sudo apt-get install -y \
    google-chrome-stable \
    || echo -e "${YELLOW}[!] Chrome installation may require manual setup${NC}"

# Install OWASP ZAP
echo "[*] Installing OWASP ZAP..."
if ! command -v zaproxy &> /dev/null; then
    sudo apt-get install -y zaproxy || {
        echo -e "${YELLOW}[!] ZAP not available in repos, downloading...${NC}"
        ZAP_VERSION="2.14.0"
        wget "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -O /tmp/zap.tar.gz
        sudo tar -xzf /tmp/zap.tar.gz -C /opt/
        sudo ln -sf /opt/ZAP_${ZAP_VERSION}/zap.sh /usr/local/bin/zaproxy
    }
else
    echo -e "${GREEN}[+] ZAP already installed${NC}"
fi

# Create virtual environment
echo "[*] Setting up Python virtual environment..."
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "[*] Creating project directories..."
mkdir -p logs
mkdir -p output
mkdir -p logs/zap

# Set permissions
chmod +x run.py
chmod +x setup.sh

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To run the scanner:"
echo "  python run.py -u https://target.com"
echo ""
echo "To run with ZAP integration:"
echo "  1. Start ZAP: zaproxy -daemon -config api.key=your-api-key"
echo "  2. Run: python run.py -u https://target.com --zap"
echo ""
