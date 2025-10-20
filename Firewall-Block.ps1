# Firewall-Block.ps1
# Author: Dax
# Created: 2024-04-23
# Description:
# Builds or deletes Windows Firewall rules based on a blocklist of IP addresses.
# Targets inbound/outbound traffic from high-risk sources.

# --- CONFIGURATION ---
$InputFile     = "BlockList.txt"
$ProfileType   = "any"
$InterfaceType = "any"
$DeleteOnly    = $false
$MaxRangesPerRule = 1000

# --- HELP CHECK ---
if ($InputFile -match '/[?h]') {
    Write-Host "`nRun 'Get-Help .\Firewall-Block.ps1 -Full' or read the script header for usage.`n"
    exit
}

# --- VALIDATE INPUT FILE ---
$file = Get-Item -Path $InputFile -ErrorAction SilentlyContinue
if (-not $file -and -not $DeleteOnly) {
    Write-Error "`nCannot find input file '$InputFile'. Quitting...`n"
    exit 1
}

# --- RULE NAME SETUP ---
$rulename = if ($file) { $file.BaseName } else { "GeoBlock" }
$description = "Rule created on $(Get-Date). Do not edit manually; it will be overwritten."

# --- DELETE EXISTING RULES ---
Write-Host "`nDeleting any firewall rules named like '$rulename-#*'`n"
$currentRules = netsh advfirewall firewall show rule name=all |
    Select-String '^[Rule Name|Regelname]+:\s+(.+)$' |
    ForEach-Object { $_.Matches[0].Groups[1].Value }

if ($currentRules.Count -lt 3) {
    Write-Warning "`nProblem retrieving current firewall rules. Quitting...`n"
    exit 1
}

$currentRules | ForEach-Object {
    if ($_ -like "$rulename-#*") {
        netsh advfirewall firewall delete rule name="$_" | Out-Null
    }
}

if ($DeleteOnly) {
    Write-Host "`nDelete-only mode active. No new rules will be created.`n"
    exit
}

# --- PARSE IP RANGES ---
$ranges = Get-Content $InputFile | Where-Object {
    ($_.Trim().Length -ne 0) -and ($_ -match '^[0-9a-f]{1,4}[\.\:]')
}

if (-not $ranges) {
    Write-Warning "`nNo valid IP addresses found in '$InputFile'. Quitting...`n"
    exit 1
}

$lineCount = $ranges.Count
if ($lineCount -eq 0) {
    Write-Warning "`nZero IP addresses to block. Quitting...`n"
    exit 1
}

# --- CREATE FIREWALL RULES ---
$i = 1
$start = 0

while ($start -lt $lineCount) {
    $end = [Math]::Min($start + $MaxRangesPerRule, $lineCount)
    $chunk = $ranges[$start..($end - 1)]
    $ipBlock = [String]::Join(",", $chunk)
    $suffix = $i.ToString("000")

    Write-Host "`nCreating inbound rule '$rulename-#$suffix' for IPs $start to $end"
    netsh advfirewall firewall add rule name="$rulename-#$suffix" dir=in action=block localip=any remoteip="$ipBlock" description="$description" profile="$ProfileType" interfacetype="$InterfaceType"

    Write-Host "`nCreating outbound rule '$rulename-#$suffix' for IPs $start to $end"
    netsh advfirewall firewall add rule name="$rulename-#$suffix" dir=out action=block localip=any remoteip="$ipBlock" description="$description" profile="$ProfileType" interfacetype="$InterfaceType"

    $i++
    $start += $MaxRangesPerRule
}
