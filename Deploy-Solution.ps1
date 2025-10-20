<#
.SYNOPSIS
Deploys and updates the Windows host-based firewall solution to block traffic from high-risk geolocations and external threat intel sources.

.DESCRIPTION
This script downloads and executes the latest deployment script from the Securenetology GitHub repository. It targets IPv4/IPv6 traffic from Russia, China, North Korea, South Korea, and known malicious sources (TOR, bulletproof hosts, etc.).

.AUTHOR
Dax

.CREATED
2024-04-23
#>

# Set execution policy (non-interactive)
Try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Confirm:$false -ErrorAction Stop
} Catch {
    Write-Warning "Failed to set execution policy: $_"
}

# Define working directory
$WorkingDir = "$env:ProgramData\GeoFirewall"
If (-not (Test-Path $WorkingDir)) {
    New-Item -Path $WorkingDir -ItemType Directory -Force | Out-Null
}

# Define script source and destination
$ScriptUrl = "https://github.com/Securenetology/Windows-Dynamic-Geo-Firewall-Rules/raw/main/Deploy-Update.ps1"
$LocalScriptPath = Join-Path $WorkingDir "Deploy-Update.ps1"

# Download the deployment script if not already present
If (-not (Test-Path $LocalScriptPath)) {
    Try {
        Invoke-WebRequest -Uri $ScriptUrl -OutFile $LocalScriptPath -UseBasicParsing -ErrorAction Stop
        Write-Host "Deployment script downloaded successfully to $LocalScriptPath"
    } Catch {
        Write-Error "Failed to download deployment script: $_"
        Exit 1
    }
} Else {
    Write-Host "Deployment script already exists at $LocalScriptPath"
}

# Execute the deployment script
Try {
    & $LocalScriptPath
    Write-Host "Deployment script executed successfully."
} Catch {
    Write-Error "Failed to execute deployment script: $_"
    Exit 1
}
