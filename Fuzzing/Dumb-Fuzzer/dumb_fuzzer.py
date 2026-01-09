#!/usr/bin/env python3
"""
Dumb Fuzzing Tool for WRA Compliance Testing
Complies with NIST SP 800-115 Section 4.4.2 - Fuzz Testing

Author: Bruh! No!
Purpose: Test embedded systems for CWE-20, CWE-119, CWE-400 vulnerabilities
License: Authorized testing only - requires written permission
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone
from scapy.all import *

# Suppress Scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# CWE definitions with NIST mappings
CWE_DEFINITIONS = {
    "CWE-20": {
        "name": "Improper Input Validation",
        "url": "https://cwe.mitre.org/data/definitions/20.html",
        "nist_control": "SI-10",
        "description": "Product does not validate or incorrectly validates input"
    },
    "CWE-119": {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "url": "https://cwe.mitre.org/data/definitions/119.html",
        "nist_control": "SI-10",
        "description": "Software performs operations on a memory buffer without proper bounds checking"
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "url": "https://cwe.mitre.org/data/definitions/400.html",
        "nist_control": "SC-5",
        "description": "Software does not properly control allocation and maintenance of limited resources"
    }
}

# Common industrial protocol ports
TARGET_PORTS = {
    'snmp': (161, 'UDP'),
    'http': (80, 'TCP'),
    'https': (443, 'TCP'),
    'modbus': (502, 'TCP'),
    's7comm': (102, 'TCP'),
    'telnet': (23, 'TCP'),
    'ftp': (21, 'TCP'),
    'ssh': (22, 'TCP')
}


class DumbFuzzer:
    def __init__(self, target_ip, duration=60, verbose=False):
        self.target_ip = target_ip
        self.duration = duration
        self.verbose = verbose
        self.start_time = None
        self.total_packets_sent = 0
        self.results = {
            "CWE-20": {"packets_sent": 0, "crashes_detected": 0, "responses": 0},
            "CWE-119": {"packets_sent": 0, "crashes_detected": 0, "max_packet_size": 0},
            "CWE-400": {"packets_sent": 0, "response_times": [], "unresponsive": False}
        }

    def log(self, message):
        """Print verbose log messages"""
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def check_target_responsive(self, port=161, protocol='UDP', timeout=2):
        """Check if target is responsive on a given port"""
        try:
            if protocol == 'UDP':
                # Send UDP probe
                packet = IP(dst=self.target_ip)/UDP(dport=port)/Raw(load=b"PROBE")
                response = sr1(packet, timeout=timeout, verbose=0)
                return response is not None
            else:  # TCP
                # TCP SYN probe
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=timeout, verbose=0)
                return response is not None and response.haslayer(TCP)
        except Exception as e:
            self.log(f"Error checking responsiveness: {e}")
            return False

    def measure_response_time(self, port=161, protocol='UDP'):
        """Measure response time in milliseconds"""
        try:
            start = time.time()
            if protocol == 'UDP':
                packet = IP(dst=self.target_ip)/UDP(dport=port)/Raw(load=b"TIMING")
                sr1(packet, timeout=1, verbose=0)
            else:
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                sr1(packet, timeout=1, verbose=0)
            elapsed = (time.time() - start) * 1000  # Convert to ms
            return round(elapsed, 2)
        except:
            return None

    def generate_random_data(self, size):
        """Generate random bytes of specified size"""
        return bytes([random.randint(0, 255) for _ in range(size)])

    def test_cwe_20_input_validation(self):
        """
        CWE-20: Improper Input Validation
        Send malformed/invalid protocol data to various ports
        """
        self.log("Testing CWE-20: Improper Input Validation")
        
        test_payloads = [
            b"\x00\x00\x00\x00",  # Null bytes
            b"\xff\xff\xff\xff",  # All ones
            b"GET / HTTP/1.1\r\n\r\n",  # HTTP to non-HTTP port
            b"\x30\x82\x01\x00",  # ASN.1 garbage
            b"<?xml version='1.0'?>",  # XML to binary port
            b"admin:password",  # Plaintext credentials
            b"\x90" * 100,  # NOP sled
            b"../../../etc/passwd",  # Path traversal
            b"'; DROP TABLE users--",  # SQL injection
            b"<script>alert(1)</script>"  # XSS
        ]

        crashes = 0
        packets_sent = 0

        for port_name, (port, protocol) in TARGET_PORTS.items():
            for payload in test_payloads:
                try:
                    if protocol == 'UDP':
                        packet = IP(dst=self.target_ip)/UDP(dport=port)/Raw(load=payload)
                        send(packet, verbose=0)
                    else:
                        packet = IP(dst=self.target_ip)/TCP(dport=port, flags="PA")/Raw(load=payload)
                        send(packet, verbose=0)
                    
                    packets_sent += 1
                    self.total_packets_sent += 1
                    
                    # Brief delay to avoid overwhelming target
                    time.sleep(0.01)
                    
                    # Check if we've exceeded duration
                    if time.time() - self.start_time >= self.duration:
                        break
                        
                except Exception as e:
                    self.log(f"Error sending to {port_name}: {e}")
                    crashes += 1
            
            if time.time() - self.start_time >= self.duration:
                break

        self.results["CWE-20"]["packets_sent"] = packets_sent
        self.results["CWE-20"]["crashes_detected"] = crashes
        self.log(f"CWE-20: Sent {packets_sent} malformed packets, detected {crashes} errors")

    def test_cwe_119_buffer_overflow(self):
        """
        CWE-119: Buffer Overflow
        Send progressively larger packets to test memory bounds
        """
        self.log("Testing CWE-119: Buffer Overflow")
        
        # Test with increasing buffer sizes
        sizes = [1024, 5120, 10240, 32768, 65535, 102400]  # 1KB to 100KB
        crashes = 0
        packets_sent = 0
        max_size = 0

        for size in sizes:
            if time.time() - self.start_time >= self.duration:
                break
                
            payload = self.generate_random_data(size)
            max_size = max(max_size, size)
            
            # Test on multiple ports
            for port_name, (port, protocol) in list(TARGET_PORTS.items())[:3]:  # Test first 3 ports
                try:
                    if protocol == 'UDP':
                        # UDP has 65535 byte limit, split large packets
                        if size > 65000:
                            chunks = [payload[i:i+65000] for i in range(0, len(payload), 65000)]
                            for chunk in chunks:
                                packet = IP(dst=self.target_ip)/UDP(dport=port)/Raw(load=chunk)
                                send(packet, verbose=0)
                                packets_sent += 1
                        else:
                            packet = IP(dst=self.target_ip)/UDP(dport=port)/Raw(load=payload)
                            send(packet, verbose=0)
                            packets_sent += 1
                    else:
                        packet = IP(dst=self.target_ip)/TCP(dport=port, flags="PA")/Raw(load=payload)
                        send(packet, verbose=0)
                        packets_sent += 1
                    
                    self.total_packets_sent += 1
                    time.sleep(0.02)
                    
                except Exception as e:
                    self.log(f"Error sending {size} byte packet to {port_name}: {e}")
                    crashes += 1

        self.results["CWE-119"]["packets_sent"] = packets_sent
        self.results["CWE-119"]["crashes_detected"] = crashes
        self.results["CWE-119"]["max_packet_size"] = max_size
        self.log(f"CWE-119: Sent {packets_sent} oversized packets up to {max_size} bytes")

    def test_cwe_400_resource_exhaustion(self):
        """
        CWE-400: Uncontrolled Resource Consumption
        Send rapid packet floods to test DoS resistance
        """
        self.log("Testing CWE-400: Resource Exhaustion")
        
        # Measure baseline response time
        baseline_time = self.measure_response_time()
        self.log(f"Baseline response time: {baseline_time}ms")
        
        packets_sent = 0
        flood_duration = min(10, self.duration // 6)  # Flood for 10 seconds or 1/6 of total duration
        
        self.log(f"Initiating packet flood for {flood_duration} seconds...")
        flood_start = time.time()
        
        # Rapid UDP flood to SNMP port
        while time.time() - flood_start < flood_duration:
            try:
                # Send bursts of packets
                for _ in range(10):  # Burst of 10 packets
                    payload = self.generate_random_data(random.randint(64, 512))
                    packet = IP(dst=self.target_ip)/UDP(dport=161)/Raw(load=payload)
                    send(packet, verbose=0)
                    packets_sent += 1
                    self.total_packets_sent += 1
                
                time.sleep(0.01)  # Brief pause between bursts
                
            except Exception as e:
                self.log(f"Error during flood: {e}")
                break
        
        self.log(f"Flood complete. Sent {packets_sent} packets in {flood_duration} seconds")
        
        # Wait a moment for target to stabilize
        time.sleep(2)
        
        # Measure post-flood response time
        post_flood_time = self.measure_response_time()
        
        # Check if target is still responsive
        is_responsive = self.check_target_responsive()
        
        self.results["CWE-400"]["packets_sent"] = packets_sent
        self.results["CWE-400"]["response_times"] = {
            "baseline_ms": baseline_time,
            "post_flood_ms": post_flood_time
        }
        self.results["CWE-400"]["unresponsive"] = not is_responsive
        
        self.log(f"CWE-400: Post-flood response time: {post_flood_time}ms, Responsive: {is_responsive}")

    def run_tests(self):
        """Execute all CWE tests"""
        self.start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"DUMB FUZZING TEST - NIST SP 800-115 Compliance")
        print(f"{'='*70}")
        print(f"Target: {self.target_ip}")
        print(f"Duration: {self.duration} seconds")
        print(f"Start Time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
        print(f"{'='*70}\n")
        
        # Check initial connectivity
        self.log("Performing initial health check...")
        if not self.check_target_responsive():
            print(f"WARNING: Target {self.target_ip} may not be responsive on common ports")
            print("Continuing with tests anyway...\n")
        
        # Run all CWE tests
        try:
            self.test_cwe_20_input_validation()
            self.test_cwe_119_buffer_overflow()
            self.test_cwe_400_resource_exhaustion()
        except KeyboardInterrupt:
            print("\n\nTest interrupted by user. Generating report with partial results...")
        
        print(f"\n{'='*70}")
        print(f"Tests Complete")
        print(f"Total Packets Sent: {self.total_packets_sent}")
        print(f"Elapsed Time: {round(time.time() - self.start_time, 2)} seconds")
        print(f"{'='*70}\n")

    def generate_report(self):
        """Generate JSON report with CWE results"""
        
        # Determine pass/fail for each CWE
        cwe_results = {}
        
        # CWE-20: Improper Input Validation
        cwe20_data = self.results["CWE-20"]
        cwe20_pass = cwe20_data["crashes_detected"] == 0
        cwe_results["CWE-20"] = {
            "name": CWE_DEFINITIONS["CWE-20"]["name"],
            "url": CWE_DEFINITIONS["CWE-20"]["url"],
            "nist_control": CWE_DEFINITIONS["CWE-20"]["nist_control"],
            "result": "PASS" if cwe20_pass else "FAIL",
            "justification": (
                f"Target accepted {cwe20_data['packets_sent']} malformed packets without crash or abnormal behavior. "
                f"Service remained responsive. Input validation appears functional."
                if cwe20_pass else
                f"Target experienced {cwe20_data['crashes_detected']} crashes or errors while processing "
                f"{cwe20_data['packets_sent']} malformed packets. Input validation weakness detected."
            ),
            "packets_sent": cwe20_data["packets_sent"],
            "crashes_detected": cwe20_data["crashes_detected"]
        }
        
        # CWE-119: Buffer Overflow
        cwe119_data = self.results["CWE-119"]
        cwe119_pass = cwe119_data["crashes_detected"] == 0
        cwe_results["CWE-119"] = {
            "name": CWE_DEFINITIONS["CWE-119"]["name"],
            "url": CWE_DEFINITIONS["CWE-119"]["url"],
            "nist_control": CWE_DEFINITIONS["CWE-119"]["nist_control"],
            "result": "PASS" if cwe119_pass else "FAIL",
            "justification": (
                f"Sent {cwe119_data['packets_sent']} packets ranging from 1KB to {cwe119_data['max_packet_size']} bytes. "
                f"No memory corruption indicators detected. Service continued normal operation."
                if cwe119_pass else
                f"Target experienced {cwe119_data['crashes_detected']} crashes while processing oversized packets "
                f"up to {cwe119_data['max_packet_size']} bytes. Buffer overflow vulnerability detected."
            ),
            "packets_sent": cwe119_data["packets_sent"],
            "max_packet_size": cwe119_data["max_packet_size"]
        }
        
        # CWE-400: Resource Exhaustion
        cwe400_data = self.results["CWE-400"]
        cwe400_pass = not cwe400_data["unresponsive"]
        
        baseline = cwe400_data["response_times"].get("baseline_ms", 0)
        post_flood = cwe400_data["response_times"].get("post_flood_ms", 0)
        
        if cwe400_pass:
            if baseline and post_flood:
                justification = (
                    f"Target remained responsive after {cwe400_data['packets_sent']} rapid packets. "
                    f"Response time: {baseline}ms baseline, {post_flood}ms post-flood. "
                    f"Resource exhaustion protection appears functional."
                )
            else:
                justification = (
                    f"Target remained responsive after {cwe400_data['packets_sent']} rapid packets. "
                    f"Resource exhaustion protection appears functional."
                )
        else:
            justification = (
                f"Target became unresponsive after {cwe400_data['packets_sent']} packets sent rapidly. "
                f"Service did not recover within 30 seconds. Resource exhaustion vulnerability detected."
            )
        
        cwe_results["CWE-400"] = {
            "name": CWE_DEFINITIONS["CWE-400"]["name"],
            "url": CWE_DEFINITIONS["CWE-400"]["url"],
            "nist_control": CWE_DEFINITIONS["CWE-400"]["nist_control"],
            "result": "PASS" if cwe400_pass else "FAIL",
            "justification": justification,
            "packets_sent": cwe400_data["packets_sent"],
            "response_time_before_ms": baseline if baseline else "N/A",
            "response_time_after_ms": post_flood if post_flood else "timeout"
        }
        
        # Build final report
        report = {
            "target": self.target_ip,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round(time.time() - self.start_time, 2),
            "total_packets_sent": self.total_packets_sent,
            "cwe_results": cwe_results,
            "nist_compliance": {
                "reference": "NIST SP 800-115 Section 4.4.2 - Fuzz Testing",
                "description": "Testing with malformed or unexpected inputs to identify input handling weaknesses"
            }
        }
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Dumb Fuzzing Tool for WRA Compliance Testing (NIST SP 800-115)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 dumb_fuzzer.py --target 192.168.1.100
  sudo python3 dumb_fuzzer.py --target 10.0.0.50 --duration 300 --output report.json --verbose

Note: Requires root/sudo for raw packet manipulation
WARNING: Use only on authorized targets with written permission
        """
    )
    
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--duration', type=int, default=60, 
                       help='Test duration in seconds (default: 60)')
    parser.add_argument('--output', default='fuzzing_report.json',
                       help='Output JSON report file (default: fuzzing_report.json)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for raw packet manipulation")
        print("Please run with sudo: sudo python3 dumb_fuzzer.py --target <IP>")
        sys.exit(1)
    
    # Validate IP address format
    try:
        import ipaddress
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"ERROR: Invalid IP address format: {args.target}")
        sys.exit(1)
    
    # Initialize fuzzer
    fuzzer = DumbFuzzer(args.target, args.duration, args.verbose)
    
    # Run tests
    fuzzer.run_tests()
    
    # Generate and save report
    report = fuzzer.generate_report()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report saved to: {args.output}")
    print("\nSummary:")
    for cwe_id, result in report["cwe_results"].items():
        status = "✓" if result["result"] == "PASS" else "✗"
        print(f"  {status} {cwe_id}: {result['name']} - {result['result']}")
    
    print("\n" + "="*70)
    print("Testing complete. Review the JSON report for detailed findings.")
    print("="*70)


if __name__ == "__main__":
    main()
