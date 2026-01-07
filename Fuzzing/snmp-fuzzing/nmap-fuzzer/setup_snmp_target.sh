#!/bin/bash

echo "=== Setting up SNMP Docker Target ==="
echo ""

# Pull the SNMP daemon image
echo "[1/4] Pulling SNMP daemon Docker image..."
docker pull polinux/snmpd

# Run the container
echo ""
echo "[2/4] Starting SNMP daemon container..."
docker run -d \
  --name snmp-target \
  -p 161:161/udp \
  polinux/snmpd

# Wait a moment for container to start
sleep 3

# Check if container is running
echo ""
echo "[3/4] Checking container status..."
docker ps | grep snmp-target

# Test SNMP is responding
echo ""
echo "[4/4] Testing SNMP connectivity..."
nmap -sU -p 161 --script snmp-sysdescr localhost

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "Your SNMP target is running on: localhost:161"
echo "Community string: public (default)"
echo ""
echo "To stop the target:  docker stop snmp-target"
echo "To start it again:   docker start snmp-target"
echo "To remove it:        docker rm -f snmp-target"
echo ""
echo "Now you can run your fuzzing commands against 'localhost' or '127.0.0.1'"
