# Deploy-Solution 
# 
# Description
# < 
# Used to deploy and update the Windows host based firewall solution which will block Russia (IPv4/IPv6), China(IPv4/IPv6), North Korea(IPv4), South Korea (IPv4/IPv6)
# and content from exteranl intel sources such as TOR Exit IP Addresses, Bulletproof IP Addresses, High-Risk IP Addresses and Known Malicious IP Addresses.
# >
# Author : Dax
# Created : 04232024

# Set Execution Policy

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Confirm:$false

# Deploy Script and Install

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

