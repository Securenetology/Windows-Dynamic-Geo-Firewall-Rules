# Windows - Create Dynamic Geo Firewall Rules
# Author: Dax
# Created: 04/23/2024
# Modified: 10/15/2025 - Added Counties, simplified script

# ----------------------------
# Setup Working Directory
# ----------------------------

$Path = "C:\IP-Security\"
if (!(Test-Path -PathType Container $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
}
$Working = $Path

# ----------------------------
# Download Firewall Script
# ----------------------------

$ScriptUrl = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/Firewall-Block.ps1"
$ScriptPath = "$Working\Firewall-Block.ps1"

if (-not (Test-Path -Path $ScriptPath)) {
    Invoke-WebRequest $ScriptUrl -OutFile $ScriptPath
} else {
    Write-Host "Firewall script already exists."
}

# ----------------------------
# Define IP List Sources
# ----------------------------

$Countries = @(
    "ad", "ae", "af", "ap", "aq", "ar", "br", "by", "cf", "cn", "cz", "do", "ee", "gf", "hk",
    "in", "iq", "ir", "kg", "kp", "kr", "ly", "pf", "pk", "qa", "ru", "sg", "tr", "tw", "ua", "uz", "za",
    "ng", "ro", "il", "sa", "vn", "eg", "id", "th", "ph", "bd"
)

$IPv4Urls = $Countries | ForEach-Object { @{ Code = $_; Url = "https://www.ipdeny.com/ipblocks/data/countries/$_.zone" } }
$IPv6Urls = $Countries | ForEach-Object { @{ Code = $_; Url = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/$_.zone" } }

$IntelUrl = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/External-Intel-List.txt"

# ----------------------------
# Download IP Lists Sequentially
# ----------------------------

foreach ($entry in $IPv4Urls + $IPv6Urls) {
    $code = $entry.Code.ToUpper()
    $suffix = if ($entry.Url -like "*ipv6*") { "6" } else { "4" }
    $outFile = "$Working\$code$suffix.txt"

    Write-Host "Downloading $code$suffix list..."
    Invoke-WebRequest $entry.Url -OutFile $outFile
}

Write-Host "Downloading external intel list..."
Invoke-WebRequest $IntelUrl -OutFile "$Working\Intel.txt"

# ----------------------------
# Combine All Lists
# ----------------------------

Get-Content "$Working\*.txt" | Set-Content "$Working\Blacklist.txt"
$Blacklist = "$Working\Blacklist.txt"

# ----------------------------
# Execute Firewall Block Script
# ----------------------------

$ArgumentList = "-inputfile $Blacklist"
Invoke-Expression -Command "$ScriptPath $ArgumentList"

# ----------------------------
# Cleanup Temporary Files
# ----------------------------

Get-ChildItem -Path $Working -Filter *.txt | ForEach-Object { Remove-Item -Path $_.FullName }

# ----------------------------
# Enable Firewall & Logging
# ----------------------------

Set-NetFirewallProfile -Profile Public,Private -Enabled True

Set-NetFirewallProfile -Profile Domain -LogBlocked True -LogMaxSize 16384 `
    -LogFileName "$env:SystemRoot\system32\LogFiles\Firewall\Domain-Firewall.log"

Set-NetFirewallProfile -Profile Private -LogBlocked True -LogMaxSize 16384 `
    -LogFileName "$env:SystemRoot\system32\LogFiles\Firewall\Private-Firewall.log"

Set-NetFirewallProfile -Profile Public -LogBlocked True -LogMaxSize 16384 `
    -LogFileName "$env:SystemRoot\system32\LogFiles\Firewall\Public-Firewall.log"

# ----------------------------
# Ensure Deploy-Update Script Exists
# ----------------------------

$UpdateScriptUrl = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/Deploy-Update.ps1"
$UpdateScriptPath = "$Working\Deploy-Update.ps1"

if (-not (Test-Path -Path $UpdateScriptPath)) {
    Invoke-WebRequest $UpdateScriptUrl -OutFile $UpdateScriptPath
} else {
    Write-Host "Deploy-Update script already exists."
}

# ----------------------------
# Create Scheduled Task for Daily Updates
# ----------------------------

$TaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 1am
$TaskAction = New-ScheduledTaskAction -Execute "PowerShell" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File '$UpdateScriptPath'" `
    -WorkingDirectory $Working

Register-ScheduledTask -TaskName 'Update-Firewall' -Action $TaskAction -Trigger $TaskTrigger
