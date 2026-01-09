# Dumb Fuzzing Tool for WRA Compliance Testing

A NIST SP 800-115 compliant network fuzzer designed for testing embedded systems and Weapon Replaceable Assembly (WRA) components against common vulnerability classes.

## Overview

This tool performs **dumb fuzzing** - sending random and malformed data without prior knowledge of application structure - to test systems for three critical Common Weakness Enumerations (CWEs):

- **CWE-20**: Improper Input Validation
- **CWE-119**: Buffer Overflow / Memory Corruption
- **CWE-400**: Uncontrolled Resource Consumption (DoS)

## Features

- ✅ **Zero Protocol Knowledge Required**: Just provide target IP address
- ✅ **Multi-Protocol Coverage**: Tests SNMP, HTTP/HTTPS, Modbus, S7comm, and more
- ✅ **NIST SP 800-115 Compliant**: Documents compliance with Section 4.4.2 (Fuzz Testing)
- ✅ **CWE Mapping**: Automatic mapping to CWE definitions and NIST controls
- ✅ **JSON Reporting**: Generates detailed reports with pass/fail criteria and justifications
- ✅ **Safe for Labs**: Includes health checks and configurable duration/rate limiting

## Requirements

- Linux system (Kali Linux recommended)
- Python 3.x
- Root/sudo access (for raw packet manipulation)
- Direct ethernet connection to target
- **Written authorization** to test target system

## Installation

### Quick Install

```bash
# Clone or download the tool files
cd /path/to/dumb_fuzzer

# Run setup script
sudo ./setup.sh
```

### Manual Install

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip tcpdump libpcap-dev

# Install Python dependencies
sudo pip3 install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Run fuzzer with default settings (60 seconds)
sudo python3 dumb_fuzzer.py --target 192.168.1.100
```

### Advanced Usage

```bash
# Custom duration and output file with verbose logging
sudo python3 dumb_fuzzer.py --target 192.168.1.100 \
    --duration 300 \
    --output my_report.json \
    --verbose
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target IP address (required) | - |
| `--duration` | Test duration in seconds | 60 |
| `--output` | Output JSON report filename | `fuzzing_report.json` |
| `--verbose` | Enable verbose logging | False |

### Help

```bash
python3 dumb_fuzzer.py --help
```

## How It Works

### Test Methodology

The fuzzer performs three distinct test phases:

#### 1. CWE-20: Improper Input Validation
- Sends malformed protocol data to various ports
- Tests with null bytes, invalid encodings, wrong protocols
- Example: Sending HTTP requests to SNMP port, SQL injection strings, XSS payloads

#### 2. CWE-119: Buffer Overflow
- Sends progressively larger packets (1KB → 100KB)
- Tests memory boundary handling
- Monitors for crashes or memory corruption indicators

#### 3. CWE-400: Resource Exhaustion
- Measures baseline response time
- Performs rapid packet flooding (burst testing)
- Measures post-flood response time
- Verifies target remains responsive

### Tested Protocols & Ports

| Protocol | Port | Type | Purpose |
|----------|------|------|---------|
| SNMP | 161 | UDP | Network management |
| HTTP | 80 | TCP | Web services |
| HTTPS | 443 | TCP | Secure web services |
| Modbus | 502 | TCP | Industrial control |
| S7comm | 102 | TCP | Siemens PLCs |
| Telnet | 23 | TCP | Remote access |
| FTP | 21 | TCP | File transfer |
| SSH | 22 | TCP | Secure shell |

## Output Report

The tool generates a JSON report with the following structure:

```json
{
  "target": "192.168.1.100",
  "timestamp": "2026-01-08T10:30:00Z",
  "duration_seconds": 60.5,
  "total_packets_sent": 1523,
  "cwe_results": {
    "CWE-20": {
      "name": "Improper Input Validation",
      "url": "https://cwe.mitre.org/data/definitions/20.html",
      "nist_control": "SI-10",
      "result": "PASS",
      "justification": "Target accepted 500 malformed packets without crash...",
      "packets_sent": 500,
      "crashes_detected": 0
    },
    "CWE-119": { ... },
    "CWE-400": { ... }
  },
  "nist_compliance": {
    "reference": "NIST SP 800-115 Section 4.4.2 - Fuzz Testing",
    "description": "Testing with malformed or unexpected inputs..."
  }
}
```

### Pass/Fail Criteria

| Result | Criteria |
|--------|----------|
| **PASS** | Target continues to respond normally after fuzzing |
| **FAIL** | Target crashes, becomes unresponsive, or exhibits abnormal behavior |

## Example Workflows

### Testing Docker SNMP Target (Lab)

```bash
# Start SNMP container
docker run -d --name snmp-target -p 161:161/udp polinux/snmpd

# Run fuzzer
sudo python3 dumb_fuzzer.py --target 127.0.0.1 --duration 120 --verbose

# View results
cat fuzzing_report.json | python3 -m json.tool
```

### Testing Production System (Requires Authorization!)

```bash
# CRITICAL: Obtain written permission first!

# Test with conservative duration
sudo python3 dumb_fuzzer.py --target 10.50.1.100 --duration 180

# Review report before sharing
less fuzzing_report.json
```

### Testing GreenHills OS Embedded System

```bash
# Direct ethernet connection required
# Verify connectivity first
ping -c 3 192.168.1.50

# Run comprehensive test
sudo python3 dumb_fuzzer.py \
    --target 192.168.1.50 \
    --duration 300 \
    --output greenhills_fuzz_report.json \
    --verbose
```

## NIST SP 800-115 Compliance

This tool implements requirements from **NIST SP 800-115: Technical Guide to Information Security Testing and Assessment**, specifically:

### Section 4.4.2: Fuzz Testing

> "Fuzz testing involves sending malformed or unexpected inputs to an application to identify potential vulnerabilities in input handling and validation mechanisms."

### NIST Control Mappings

| CWE | NIST Control | Control Family |
|-----|--------------|----------------|
| CWE-20 | SI-10 | Information Input Validation |
| CWE-119 | SI-10 | Information Input Validation |
| CWE-400 | SC-5 | Denial of Service Protection |

## Safety Considerations

### ⚠️ Authorization Required

**NEVER** use this tool without explicit written authorization from the system owner. Unauthorized testing may:
- Violate the Computer Fraud and Abuse Act (CFAA)
- Breach contracts and NDAs
- Result in legal prosecution
- Cause unintended system damage

### Lab Safety

When testing in lab environments:
- ✅ Use isolated network segments
- ✅ Ensure systems are in test/development state
- ✅ Have rollback procedures ready
- ✅ Monitor system health during tests
- ✅ Document all test activities

### Production Considerations

If approved to test production systems:
- Schedule tests during maintenance windows
- Start with shorter durations (60-120 seconds)
- Have incident response team on standby
- Implement gradual escalation (start conservative)
- Maintain continuous monitoring
- Have immediate stop procedures

## Troubleshooting

### Permission Denied Error

```bash
# Error: This script requires root privileges
# Solution: Run with sudo
sudo python3 dumb_fuzzer.py --target 192.168.1.100
```

### No Response from Target

```bash
# Check connectivity first
ping 192.168.1.100

# Verify target is running
nmap -p 161 192.168.1.100

# Check firewall rules
sudo iptables -L -n
```

### Scapy Import Error

```bash
# Reinstall Scapy
sudo pip3 install --upgrade scapy

# Install system dependencies
sudo apt-get install tcpdump libpcap-dev
```

### Docker Target Not Responding

```bash
# Check container status
docker ps -a | grep snmp

# View container logs
docker logs snmp-target

# Restart container
docker restart snmp-target
```

## Understanding Results

### Interpreting CWE-20 Results

**PASS Example:**
```
"justification": "Target accepted 500 malformed packets without crash or 
abnormal behavior. Service remained responsive. Input validation appears functional."
```
✅ **Meaning**: System properly validates/rejects bad input without crashing

**FAIL Example:**
```
"justification": "Target experienced 15 crashes while processing 500 malformed 
packets. Input validation weakness detected."
```
❌ **Meaning**: System crashes when receiving malformed input (CWE-20 vulnerability)

### Interpreting CWE-119 Results

**PASS Example:**
```
"justification": "Sent 150 packets ranging from 1KB to 102400 bytes. No memory 
corruption indicators detected. Service continued normal operation."
```
✅ **Meaning**: System handles large inputs safely without buffer overflow

**FAIL Example:**
```
"justification": "Target experienced 3 crashes while processing oversized packets 
up to 102400 bytes. Buffer overflow vulnerability detected."
```
❌ **Meaning**: System has buffer overflow vulnerability with large inputs

### Interpreting CWE-400 Results

**PASS Example:**
```
"justification": "Target remained responsive after 800 rapid packets. Response 
time: 15ms baseline, 18ms post-flood. Resource exhaustion protection functional."
```
✅ **Meaning**: System withstands DoS attacks, implements rate limiting

**FAIL Example:**
```
"justification": "Target became unresponsive after 500 packets sent rapidly. 
Service did not recover within 30 seconds. Resource exhaustion vulnerability detected."
```
❌ **Meaning**: System vulnerable to DoS attacks (CWE-400 vulnerability)

## Portfolio & Resume Usage

This tool demonstrates:
- **Penetration Testing Skills**: Network fuzzing, vulnerability assessment
- **Security Frameworks**: NIST SP 800-115 compliance
- **Tool Development**: Python, Scapy, packet manipulation
- **Compliance Knowledge**: CWE mappings, NIST controls
- **Industrial Security**: SCADA/ICS protocol testing

### Resume Bullet Points

```
• Developed NIST SP 800-115 compliant network fuzzing tool for WRA testing
• Automated CWE-20, CWE-119, and CWE-400 vulnerability assessment
• Tested embedded systems for input validation and DoS vulnerabilities
• Created compliance documentation mapping findings to NIST controls
```

## References

### Standards & Guidelines
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) - Technical Guide to Information Security Testing and Assessment
- [CWE-20](https://cwe.mitre.org/data/definitions/20.html) - Improper Input Validation
- [CWE-119](https://cwe.mitre.org/data/definitions/119.html) - Buffer Overflow
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html) - Resource Exhaustion

### NIST Controls
- **SI-10**: Information Input Validation
- **SC-5**: Denial of Service Protection

### Tools & Libraries
- [Scapy](https://scapy.net/) - Packet manipulation library
- [Python](https://www.python.org/) - Programming language

## License & Disclaimer

**FOR AUTHORIZED TESTING ONLY**

This tool is provided for legitimate security testing and compliance verification. Users are solely responsible for:
- Obtaining proper authorization before testing
- Compliance with applicable laws and regulations
- Any damage or liability resulting from use

The author assumes no liability for misuse or unauthorized use of this tool.

## Support & Feedback

For questions, issues, or improvements:
1. Review this README thoroughly
2. Check troubleshooting section
3. Test in lab environment first
4. Document specific error messages

---

**Version**: 1.0  
**Last Updated**: January 2026  
**Compliance**: NIST SP 800-115 Section 4.4.2  
**Author**: SecretSouce
