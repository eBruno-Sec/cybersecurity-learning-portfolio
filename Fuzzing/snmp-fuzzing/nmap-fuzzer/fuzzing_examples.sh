#!/bin/bash

# Complete SNMPv3 Fuzzing Test Examples
# Target: localhost:161 (Docker SNMP container)

echo "=== SNMPv3 Fuzzing Test Suite ==="
echo ""
echo "Target: localhost:161"
echo "Make sure your SNMP Docker container is running first!"
echo ""
read -p "Press Enter to start fuzzing tests..."

# Create output directory
mkdir -p fuzzing_results
cd fuzzing_results

echo ""
echo "========================================="
echo "1. DUMB FUZZING"
echo "========================================="
echo ""

echo "[Dumb Fuzzing 1/2] DNS fuzzing to SNMP port (10 minute duration)..."
nmap -sU -p 161 --script dns-fuzz --script-args dns-fuzz.timelimit=10m localhost -oN dumb_fuzz_dns.txt

echo ""
echo "[Dumb Fuzzing 2/2] HTTP form fuzzing to SNMP port..."
nmap -sT -p 161 --script http-form-fuzzer localhost -oN dumb_fuzz_http.txt

echo ""
echo "========================================="
echo "2. STRUCTURE-AWARE FUZZING"
echo "========================================="
echo ""

echo "[Structure-Aware 1/9] Testing SNMP interfaces..."
nmap -sU -p 161 --script snmp-interfaces localhost -oN structured_fuzz_interfaces.txt

echo ""
echo "[Structure-Aware 2/9] Testing SNMP info..."
nmap -sU -p 161 --script snmp-info localhost -oN structured_fuzz_info.txt

echo ""
echo "[Structure-Aware 3/9] Testing SNMP processes..."
nmap -sU -p 161 --script snmp-processes localhost -oN structured_fuzz_processes.txt

echo ""
echo "[Structure-Aware 4/9] Testing SNMP netstat..."
nmap -sU -p 161 --script snmp-netstat localhost -oN structured_fuzz_netstat.txt

echo ""
echo "[Structure-Aware 5/9] Testing SNMP system description..."
nmap -sU -p 161 --script snmp-sysdescr localhost -oN structured_fuzz_sysdescr.txt

echo ""
echo "[Structure-Aware 6/9] Testing SNMP Win32 services..."
nmap -sU -p 161 --script snmp-win32-services localhost -oN structured_fuzz_services.txt

echo ""
echo "[Structure-Aware 7/9] Testing SNMP Win32 software..."
nmap -sU -p 161 --script snmp-win32-software localhost -oN structured_fuzz_software.txt

echo ""
echo "[Structure-Aware 8/9] Testing SNMP Win32 users..."
nmap -sU -p 161 --script snmp-win32-users localhost -oN structured_fuzz_users.txt

echo ""
echo "[Structure-Aware 9/9] Testing SNMP Win32 shares..."
nmap -sU -p 161 --script snmp-win32-shares localhost -oN structured_fuzz_shares.txt

echo ""
echo "========================================="
echo "3. OPERATIONALLY AWARE FUZZING"
echo "========================================="
echo ""

echo "[Operational 1/4] Testing SNMP brute force..."
nmap -sU -p 161 --script snmp-brute localhost -oN operational_fuzz_brute.txt

echo ""
echo "[Operational 2/4] Testing SNMP IOS config access..."
nmap -sU -p 161 --script snmp-ios-config localhost -oN operational_fuzz_ios.txt

echo ""
echo "[Operational 3/4] Testing SNMP H3C logins..."
nmap -sU -p 161 --script snmp-hh3c-logins localhost -oN operational_fuzz_h3c.txt

echo ""
echo "[Operational 4/4] Testing with invalid community string..."
nmap -sU -p 161 --script snmp-sysdescr --script-args snmpcommunity=INVALID localhost -oN operational_fuzz_invalid.txt

echo ""
echo "========================================="
echo "FUZZING COMPLETE!"
echo "========================================="
echo ""
echo "Results saved in: fuzzing_results/"
echo ""
ls -lh

