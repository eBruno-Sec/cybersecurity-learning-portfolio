#!/bin/bash

echo "=========================================="
echo "Dumb Fuzzer Setup Script"
echo "NIST SP 800-115 Compliance Tool"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    echo "Please run: sudo ./setup.sh"
    exit 1
fi

echo "[1/4] Updating package lists..."
apt-get update -qq

echo "[2/4] Installing Python3 and pip..."
apt-get install -y python3 python3-pip python3-dev > /dev/null 2>&1

echo "[3/4] Installing system dependencies for Scapy..."
apt-get install -y tcpdump libpcap-dev > /dev/null 2>&1

echo "[4/4] Installing Python dependencies..."
pip3 install -r requirements.txt --quiet

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Usage:"
echo "  sudo python3 dumb_fuzzer.py --target <IP_ADDRESS>"
echo ""
echo "Example:"
echo "  sudo python3 dumb_fuzzer.py --target 192.168.1.100 --duration 300 --verbose"
echo ""
echo "For help:"
echo "  python3 dumb_fuzzer.py --help"
echo ""
echo "WARNING: Only use on authorized targets with written permission!"
echo "=========================================="
