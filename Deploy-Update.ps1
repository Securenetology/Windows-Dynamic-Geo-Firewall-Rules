# Windows - Create Dynamic Geo Firewall Rules
# 
# Description
# < 
#Used to deploy and update the Windows host based firewall solution which will block Russia (IPv4/IPv6), China(IPv4/IPv6), North Korea(IPv4), South Korea (IPv4/IPv6)
# and content from exteranl intel sources such as TOR Exit IP Addresses, Bulletproof IP Addresses, High-Risk IP Addresses and Known Malicious IP Addresses.
# >
# Author : Dax
# Created : 04232024

# Begin

# Create Folder if it does not exist

$path = "C:\IP-Security\"
If(!(test-path -PathType container $path))
{
      New-Item -ItemType Directory -Path $path
}

# Set Vairable for working directory

$Working = "C:\IP-Security\"

# Set variable for script location

$script = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/Firewall-Block.ps1"

# Download Script

$filePath = "$path\Firewall-Block.ps1"

# Check if the file exists
if (-not (Test-Path -Path $filePath)) {
    # The file does not exist, download it
    Invoke-WebRequest $script -OutFile $Working\Firewall-Block.ps1
} else {
    Write-Host "The file already exists."
}

# IPv4 Block

# Define China IPv4 list source

$CN4 = "https://www.ipdeny.com/ipblocks/data/countries/cn.zone"

# Define Russia IPv4 list source

$RU4 = "https://www.ipdeny.com/ipblocks/data/countries/ru.zone"

# Define North Korea IPv4 list source

$KP4 = "https://www.ipdeny.com/ipblocks/data/countries/kp.zone"

# Define South Korea IPv4 list source

$KR4 = "https://www.ipdeny.com/ipblocks/data/countries/kr.zone"

# IPv6 Block

# Define China IPv6 list source

$CN6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/cn.zone"

# Define Russia IPv6 list

$RU6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ru.zone"


# Define South Korea IPv6 list source

$KR6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/kr.zone"


# Define External Intelligence list source

$Intel = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/External-Intel-List.txt"

# Download all defined lists

# Download China IPv4 list

Invoke-WebRequest $CN4 -OutFile $Working\CN4.txt

# Download Russia IPv4 list

Invoke-WebRequest $CN4 -OutFile $Working\RU4.txt

# Download North Korea IPv4 list

Invoke-WebRequest $KP4 -OutFile $Working\KP4.txt

# Download South Korea IPv4 list

Invoke-WebRequest $KR4 -OutFile $Working\KR4.txt

# IPv6 Block

# Download China IPv4 list

Invoke-WebRequest $CN6 -OutFile $Working\CN6.txt

# Download Russia IPv4 list

Invoke-WebRequest $CN6 -OutFile $Working\RU6.txt

# Download South Korea IPv4 list

Invoke-WebRequest $KR6 -OutFile $Working\KR6.txt

# Download External Intelligence list

Invoke-WebRequest $Intel -OutFile $Working\Intel.txt

# Combine all lists into one file

# Combine files

Get-Content $Working\*.txt | Set-Content $Working\Blacklist.txt

# Set variable for output

$Blacklist = "$Working\Blacklist.txt"

# Set variable for scripts and arguements

$scriptPath = "$Working\Firewall-Block.ps1"
$argumentList = "-inputfile $Blacklist"

# Call Firewall Block Script for import

Invoke-Expression -Command  "$scriptPath $argumentList"

# Cleanup dynamic Lists for next import

Get-ChildItem -Path $Working *.txt | foreach { Remove-Item -Path $_.FullName }

# Enable Windows Firewall

Set-NetFirewallProfile -Profile Public,Private -Enabled True

# Enable Windows Firewall Logging

# Enable Windows Firewall Logging - Domain

Set-NetFireWallProfile -Profile Domain -LogBlocked True -LogMaxSize 16384 -LogFileName "%systemroot%\system32\LogFiles\Firewall\Domain-Firewall.log"

# Enable Windows Firewall Logging - Private

Set-NetFireWallProfile -Profile Private -LogBlocked True -LogMaxSize 16384 -LogFileName "%systemroot%\system32\LogFiles\Firewall\Private-Firewall.log"

# Enable Windows Firewall Logging - Public

Set-NetFireWallProfile -Profile Public -LogBlocked True -LogMaxSize 16384 -LogFileName "%systemroot%\system32\LogFiles\Firewall\Private-Firewall.log"

# Ensure Deploy-Update Exists for update tasks

# Define script source

$PS = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/Deploy-Update.ps1"

# Download Script

$filePath = "$path\Deploy-Update.ps1"

# Check if the file exists
if (-not (Test-Path -Path $filePath)) {
    # The file does not exist, download it
    Invoke-WebRequest $PS -OutFile $Working\Deploy-Update.ps1
} else {
    Write-Host "The file already exists."
}

# Create Scheduled Task for Daily Updates

$taskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 1am
$taskAction = New-ScheduledTaskAction -Execute "PowerShell" -Argument "-NoProfile -ExecutionPolicy Bypass -File 'C:\IP-Security\Deploy-Update.ps1'" -WorkingDirectory 'C:\IP-Security'
Register-ScheduledTask 'Update-Firewall' -Action $taskAction -Trigger $taskTrigger