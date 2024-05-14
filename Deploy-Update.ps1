# Windows - Create Dynamic Geo Firewall Rules
# 
# Description
# < 
#Used to deploy and update the Windows host based firewall solution which will block various locations based on external IPv4 and IPv6 addresses
# and content from exteranl intel sources such as TOR Exit IP Addresses, Bulletproof IP Addresses, High-Risk IP Addresses and Known Malicious IP Addresses.
# List of Blocked Locations
# Andorra
# United Arab Emirates
# Afghanistan
# Asia/Pacific Region
# Antarctica
# Argentina
# Brazil
# Belarus
# Central African Republic
# China
# Czech Republic
# Dominican Republic
# Estonia
# French Guiana
# Hong Kong
# India
# Iraq
# Iran Islamic Republic Of
# Kyrgyzstan
# Korea Democratic Peoples Republic Of
# Korea Republic Of
# Libyan Arab Jamahiriya
# French Polynesia
# Pakistan
# Qatar
# Russia
# Singapore
# Turkey
# Taiwan ROC
# Ukraine
# Uzbekistan
# Zambia
# >
# Author : Dax
# Created : 04232024
# Modified : 04262024 - Added Thirty Six Countires

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

# Define Andorra IPv4 list source

$AD4 = "https://www.ipdeny.com/ipblocks/data/countries/ad.zone"

# Define United Arab Emirates IPv4 list source

$AE4  = "https://www.ipdeny.com/ipblocks/data/countries/ae.zone"

# Define Afghanistan IPv4 list source

$AF4  = "https://www.ipdeny.com/ipblocks/data/countries/af.zone"

# Define Asia/Pacific Region IPv4 list source

$AP4  = "https://www.ipdeny.com/ipblocks/data/countries/ap.zone"

# Define Antarctica IPv4 list source

$AQ4  = "https://www.ipdeny.com/ipblocks/data/countries/aq.zone"

# Define Argentina IPv4 list source

$AR4  = "https://www.ipdeny.com/ipblocks/data/countries/ar.zone"

# Define Brazil IPv4 list source

$BR4  = "https://www.ipdeny.com/ipblocks/data/countries/br.zone"

# Define Belarus IPv4 list source

$BY4  = "https://www.ipdeny.com/ipblocks/data/countries/by.zone"

# Define Central African Republic IPv4 list source

$CF4  = "https://www.ipdeny.com/ipblocks/data/countries/cf.zone"

# Define China IPv4 list source

$CN4  = "https://www.ipdeny.com/ipblocks/data/countries/cn.zone"

# Define Czech Republic IPv4 list source

$CZ4  = "https://www.ipdeny.com/ipblocks/data/countries/cz.zone"

# Define Dominican Republic IPv4 list source

$DO4  = "https://www.ipdeny.com/ipblocks/data/countries/do.zone"

# Define Estonia IPv4 list source

$EE4  = "https://www.ipdeny.com/ipblocks/data/countries/ee.zone"

# Define French Guiana IPv4 list source

$GF4  = "https://www.ipdeny.com/ipblocks/data/countries/gf.zone"

# Define Hong Kong IPv4 list source

$HK4  = "https://www.ipdeny.com/ipblocks/data/countries/hk.zone"

# Define India IPv4 list source

$IN4  = "https://www.ipdeny.com/ipblocks/data/countries/in.zone"

# Define Iraq IPv4 list source

$IQ4  = "https://www.ipdeny.com/ipblocks/data/countries/iq.zone"

# Define Iran Islamic Republic Of IPv4 list source

$IR4  = "https://www.ipdeny.com/ipblocks/data/countries/ir.zone"

# Define Kyrgyzstan IPv4 list source

$KG4  = "https://www.ipdeny.com/ipblocks/data/countries/kg.zone"

# Define Korea Democratic Peoples Republic Of IPv4 list source

$KP4  = "https://www.ipdeny.com/ipblocks/data/countries/kp.zone"

# Define Korea Republic Of IPv4 list source

$KR4  = "https://www.ipdeny.com/ipblocks/data/countries/kr.zone"

# Define Libyan Arab Jamahiriya IPv4 list source

$LY4  = "https://www.ipdeny.com/ipblocks/data/countries/ly.zone"

# Define French Polynesia IPv4 list source

$PF4  = "https://www.ipdeny.com/ipblocks/data/countries/pf.zone"

# Define Pakistan IPv4 list source

$PK4  = "https://www.ipdeny.com/ipblocks/data/countries/pk.zone"

# Define Qatar IPv4 list source

$QA4  = "https://www.ipdeny.com/ipblocks/data/countries/qa.zone"

# Define Russia IPv4 list source

$RU4  = "https://www.ipdeny.com/ipblocks/data/countries/ru.zone"

# Define Singapore IPv4 list source

$SG4  = "https://www.ipdeny.com/ipblocks/data/countries/sg.zone"

# Define Turkey IPv4 list source

$TR4  = "https://www.ipdeny.com/ipblocks/data/countries/tr.zone"

# Define Taiwan ROC IPv4 list source

$TW4  = "https://www.ipdeny.com/ipblocks/data/countries/tw.zone"

# Define Ukraine IPv4 list source

$UA4  = "https://www.ipdeny.com/ipblocks/data/countries/ua.zone"

# Define Uzbekistan IPv4 list source

$UZ4  = "https://www.ipdeny.com/ipblocks/data/countries/uz.zone"

# Define Zambia IPv4 list source

$ZA4 = "https://www.ipdeny.com/ipblocks/data/countries/za.zone"

# IPv6 Block

# Define Andorra IPv6 list source

$AD6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ad.zone"

# Define United Arab Emirates IPv6 list source

$AE6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ae.zone"

# Define Afghanistan IPv6 list source

$AF6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/af.zone"

# Define Argentina IPv6 list source

$AR6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ar.zone"

# Define Brazil IPv6 list source

$BR6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/br.zone"

# Define Belarus IPv6 list source

$BY6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/by.zone"

# Define China IPv6 list source

$CN6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/cn.zone"

# Define Czech Republic IPv6 list source

$CZ6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/cz.zone"

# Define Dominican Republic IPv6 list source

$DO6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/do.zone"

# Define Estonia IPv6 list source

$EE6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ee.zone"

# Define French Guiana IPv6 list source

$GF6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/gf.zone"

# Define Hong Kong IPv6 list source

$HK6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/hk.zone"

# Define India IPv6 list source

$IN6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/in.zone"

# Define Iraq IPv6 list source

$IQ6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/iq.zone"

# Define Iran Islamic Republic Of IPv6 list source

$IR6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ir.zone"

# Define Kyrgyzstan IPv6 list source

$KG6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/kg.zone"

# Define Korea Republic Of IPv6 list source

$KR6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/kr.zone"

# Define Libyan Arab Jamahiriya IPv6 list source

$LY6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ly.zone"

# Define French Polynesia IPv6 list source

$PF6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/pf.zone"

# Define Pakistan IPv6 list source

$PK6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/pk.zone"

# Define Qatar IPv6 list source

$QA6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/qa.zone"

# Define Russia IPv6 list source

$RU6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ru.zone"

# Define Singapore IPv6 list source

$SG6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/sg.zone"

# Define Turkey IPv6 list source

$TR6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/tr.zone"

# Define Taiwan ROC IPv6 list source

$TW6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/tw.zone"

# Define Ukraine IPv6 list source

$UA6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ua.zone"

# Define Uzbekistan IPv6 list source

$UZ6  = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/uz.zone"

# Define Zambia IPv6 list source

$ZA6 = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/za.zone"

# Define External Intelligence list source

$Intel = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/External-Intel-List.txt"

# Download all defined lists

# IPv4 Block

# Download Andorra IPv4 list

Invoke-WebRequest $AD4 -Outfile $Working\AD4.txt

# Download United Arab Emirates IPv4 list

Invoke-WebRequest $AE4 -Outfile $Working\AE4.txt

# Download Afghanistan IPv4 list

Invoke-WebRequest $AF4 -Outfile $Working\AF4.txt

# Download Asia/Pacific Region IPv4 list

Invoke-WebRequest $AP4 -Outfile $Working\AP4.txt

# Download Antarctica IPv4 list

Invoke-WebRequest $AQ4 -Outfile $Working\AQ4.txt

# Download Argentina IPv4 list

Invoke-WebRequest $AR4 -Outfile $Working\AR4.txt

# Download Brazil IPv4 list

Invoke-WebRequest $BR4 -Outfile $Working\BR4.txt

# Download Belarus IPv4 list

Invoke-WebRequest $BY4 -Outfile $Working\BY4.txt

# Download Central African Republic IPv4 list

Invoke-WebRequest $CF4 -Outfile $Working\CF4.txt

# Download China IPv4 list

Invoke-WebRequest $CN4 -Outfile $Working\CN4.txt

# Download Czech Republic IPv4 list

Invoke-WebRequest $CZ4 -Outfile $Working\CZ4.txt

# Download Dominican Republic IPv4 list

Invoke-WebRequest $DO4 -Outfile $Working\DO4.txt

# Download Estonia IPv4 list

Invoke-WebRequest $EE4 -Outfile $Working\EE4.txt

# Download French Guiana IPv4 list

Invoke-WebRequest $GF4 -Outfile $Working\GF4.txt

# Download Hong Kong IPv4 list

Invoke-WebRequest $HK4 -Outfile $Working\HK4.txt

# Download India IPv4 list

Invoke-WebRequest $IN4 -Outfile $Working\IN4.txt

# Download Iraq IPv4 list

Invoke-WebRequest $IQ4 -Outfile $Working\IQ4.txt

# Download Iran Islamic Republic Of IPv4 list

Invoke-WebRequest $IR4 -Outfile $Working\IR4.txt

# Download Kyrgyzstan IPv4 list

Invoke-WebRequest $KG4 -Outfile $Working\KG4.txt

# Download Korea Democratic Peoples Republic Of IPv4 list

Invoke-WebRequest $KP4 -Outfile $Working\KP4.txt

# Download Korea Republic Of IPv4 list

Invoke-WebRequest $KR4 -Outfile $Working\KR4.txt

# Download Libyan Arab Jamahiriya IPv4 list

Invoke-WebRequest $LY4 -Outfile $Working\LY4.txt

# Download French Polynesia IPv4 list

Invoke-WebRequest $PF4 -Outfile $Working\PF4.txt

# Download Pakistan IPv4 list

Invoke-WebRequest $PK4 -Outfile $Working\PK4.txt

# Download Qatar IPv4 list

Invoke-WebRequest $QA4 -Outfile $Working\QA4.txt

# Download Russia IPv4 list

Invoke-WebRequest $RU4 -Outfile $Working\RU4.txt

# Download Singapore IPv4 list

Invoke-WebRequest $SG4 -Outfile $Working\SG4.txt

# Download Turkey IPv4 list

Invoke-WebRequest $TR4 -Outfile $Working\TR4.txt

# Download Taiwan ROC IPv4 list

Invoke-WebRequest $TW4 -Outfile $Working\TW4.txt

# Download Ukraine IPv4 list

Invoke-WebRequest $UA4 -Outfile $Working\UA4.txt

# Download Uzbekistan IPv4 list

Invoke-WebRequest $UZ4 -Outfile $Working\UZ4.txt

# Download Zambia IPv4 list

Invoke-WebRequest $ZA4 -Outfile $Working\ZA4.txt

# IPv6 Block

# Download Andorra IPv6 list

Invoke-WebRequest $AD6 -Outfile $Working\AD6.txt

# Download United Arab Emirates IPv6 list

Invoke-WebRequest $AE6 -Outfile $Working\AE6.txt

# Download Afghanistan IPv6 list

Invoke-WebRequest $AF6 -Outfile $Working\AF6.txt

# Download Argentina IPv6 list

Invoke-WebRequest $AR6 -Outfile $Working\AR6.txt

# Download Brazil IPv6 list

Invoke-WebRequest $BR6 -Outfile $Working\BR6.txt

# Download Belarus IPv6 list

Invoke-WebRequest $BY6 -Outfile $Working\BY6.txt

# Download China IPv6 list

Invoke-WebRequest $CN6 -Outfile $Working\CN6.txt

# Download Czech Republic IPv6 list

Invoke-WebRequest $CZ6 -Outfile $Working\CZ6.txt

# Download Dominican Republic IPv6 list

Invoke-WebRequest $DO6 -Outfile $Working\DO6.txt

# Download Estonia IPv6 list

Invoke-WebRequest $EE6 -Outfile $Working\EE6.txt

# Download French Guiana IPv6 list

Invoke-WebRequest $GF6 -Outfile $Working\GF6.txt

# Download Hong Kong IPv6 list

Invoke-WebRequest $HK6 -Outfile $Working\HK6.txt

# Download India IPv6 list

Invoke-WebRequest $IN6 -Outfile $Working\IN6.txt

# Download Iraq IPv6 list

Invoke-WebRequest $IQ6 -Outfile $Working\IQ6.txt

# Download Iran Islamic Republic Of IPv6 list

Invoke-WebRequest $IR6 -Outfile $Working\IR6.txt

# Download Kyrgyzstan IPv6 list

Invoke-WebRequest $KG6 -Outfile $Working\KG6.txt

# Download Korea Republic Of IPv6 list

Invoke-WebRequest $KR6 -Outfile $Working\KR6.txt

# Download Libyan Arab Jamahiriya IPv6 list

Invoke-WebRequest $LY6 -Outfile $Working\LY6.txt

# Download French Polynesia IPv6 list

Invoke-WebRequest $PF6 -Outfile $Working\PF6.txt

# Download Pakistan IPv6 list

Invoke-WebRequest $PK6 -Outfile $Working\PK6.txt

# Download Qatar IPv6 list

Invoke-WebRequest $QA6 -Outfile $Working\QA6.txt

# Download Russia IPv6 list

Invoke-WebRequest $RU6 -Outfile $Working\RU6.txt

# Download Singapore IPv6 list

Invoke-WebRequest $SG6 -Outfile $Working\SG6.txt

# Download Turkey IPv6 list

Invoke-WebRequest $TR6 -Outfile $Working\TR6.txt

# Download Taiwan ROC IPv6 list

Invoke-WebRequest $TW6 -Outfile $Working\TW6.txt

# Download Ukraine IPv6 list

Invoke-WebRequest $UA6 -Outfile $Working\UA6.txt

# Download Uzbekistan IPv6 list

Invoke-WebRequest $UZ6 -Outfile $Working\UZ6.txt

# Download Zambia IPv6 list

Invoke-WebRequest $ZA6 -Outfile $Working\ZA6.txt

# Download External Intelligence list

Invoke-WebRequest $Intel -Outfile $Working\Intel.txt

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

Set-NetFireWallProfile -Profile Public -LogBlocked True -LogMaxSize 16384 -LogFileName "%systemroot%\system32\LogFiles\Firewall\Public-Firewall.log"

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
