#Endpoint Hardening Script

#Windows Security - WPAD Override
Set-ItemProperty -Path 'HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverrride ' -Value '1' -Type DWord

#Set IPv6 source routing to highest protection
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name 'DisableIPSourceRouting' -Value '2' -Type DWord

#Disable IP source routing
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\' -Name 'DisableIPSourceRouting' -Value '2' -Type DWord

#Windows Security - Disable IPv6 configuration requests

Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex $(Get-NetIPInterface -AddressFamily IPv6 | Select-Object -ExpandProperty InterfaceIndex) -RouterDiscovery Disabled -Dhcp Disabled
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name "DisabledComponents" -Value 0x20 -PropertyType "Dword"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name "DisabledComponents" -Value 0x20

#Windows Security - NTLM Hardening


New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -Name 'LMCompatibilityLevel' -Value 5 -PropertyType Dword -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' -Name 'NtlmMinClientSec' -Value 5 -PropertyType Dword -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' -Name 'NtlmMinServerSec' -Value 5 -PropertyType Dword -Force

#Windows - Disable Windows Copilot
#Create needed key
New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\' -Name 'WindowsCopilot'
#Create needed dword
New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Value 1 -PropertyType Dword -Force

#Windows - Disable MS Store Silent Installs

Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Value '0'

#Windows Security - Disable NETBIOS over TCPIP

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

#Windows Security - Disable mDNS

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\" -Name EnableMDNS -Value 0 -Type DWord

#Windows Security - Disable LSASS Injection

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value '0'

#Windows Security - Disable LLMNR

New-Item -Path 'HKLM:\Software\policies\Microsoft\Windows NT\' -Name 'DNSClient'
Set-ItemProperty -Path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value '0'


#Display 'This PC' on desktop

Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0'

#Windows - Enable Application Guard

#Enable Defender Application Guard Featuire
Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard


#Remediate CVE-2013-3900 - Certificate Padding Check
#MS13-098: Vulnerability in Windows Could Allow Remote Code Execution (2893294)

$messageString =  '[' + (Get-Date) +'] :: Starting Container and Key Creation Process'
Write-Information $messageString

#Enable certificate padding check

#Attempt the 32bit container
Try
    {
    $messageString =  '[' + (Get-Date) +'] :: Attempt to create the 32bit Container'
    Write-Information $messageString
    New-Item -Path HKLM:\Software\Microsoft\Cryptography\Wintrust\Config -ItemType Container -Force
    $messageString =  '[' + (Get-Date) +'] :: SUCCESS :: 32bit Container created'
    Write-Information $messageString
    }
Catch
    {
    $messageString =  '[' + (Get-Date) +'] :: ERROR:: Failed to create the 32bit container'
    Write-Information $messageString
    $messageString = $($_.Exception.Message)
    Write-Information $messageString
    }

#Attempt the 32bit key
Try
    {
    $messageString =  '[' + (Get-Date) +'] :: Attempt to create the 32bit Key'
    Write-Information $messageString
    New-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\Wintrust\Config -Name EnableCertPaddingCheck -Value 1 -PropertyType String
    $messageString =  '[' + (Get-Date) +'] :: SUCCESS :: 32bit Container created'
    Write-Information $messageString
    }
Catch
    {
    $messageString =  '[' + (Get-Date) +'] :: ERROR :: Failed to create the 32bit key'
    Write-Information $messageString
    $messageString = $($_.Exception.Message)
    Write-Information $messageString
    }

#Attempt the 64bit container
Try
    {
    $messageString =  '[' + (Get-Date) +'] :: Attempt to create the 64bit Container'
    Write-Information $messageString
    New-Item -Path HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config -ItemType Container -Force
    $messageString =  '[' + (Get-Date) +'] :: SUCCESS :: 32bit Container created'
    Write-Information $messageString
    }
Catch
    {
    $messageString =  '[' + (Get-Date) +'] :: ERROR:: Failed to create the 64bit container'
    Write-Information $messageString
    $messageString = $($_.Exception.Message)
    Write-Information $messageString
    }

#Attempt the 64bit key
Try
    {
    $messageString =  '[' + (Get-Date) +'] :: Attempt to create the 64bit Key'
    Write-Information $messageString
    New-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config -Name EnableCertPaddingCheck -Value 1 -PropertyType String
    $messageString =  '[' + (Get-Date) +'] :: SUCCESS :: 64bit Container created'
    Write-Information $messageString
    }
Catch
    {
    $messageString =  '[' + (Get-Date) +'] :: ERROR :: Failed to create the 64bit key'
    Write-Information $messageString
    $messageString = $($_.Exception.Message)
    Write-Information $messageString
    }

Get-Service -Name CryptSvc -Verbose | Stop-Service -Verbose -Force -PassThru | Start-Service -PassThru -Verbose


# Enable additional verbose logging in the CAPI2 event log
  
# Add a DWORD (32-bit) value DiagLevel with value of 0x00000005
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Crypt32' -Name "DiagLevel" -Type DWORD -Value 5
  
# Add a QWORD (64-bit) value DiagMatchAnyMask with value of 0x00ffffff
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Crypt32' -Name "DiagMatchAnyMask" -Type QWORD -Value 0x00ffffff
  
# Enable CAPI2 operational logging
  
$log = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList "Microsoft-Windows-CAPI2/Operational"
$log.isEnabled = $true
try {
     $log.SaveChanges()
} catch {
    Exit 1
    Write-Warning -Message "Failed to save changes because $($_.Exception.Message)"
} 
 
Get-Service -Name CryptSvc -Verbose | Stop-Service -Verbose -Force -PassThru | Start-Service -PassThru -Verbose

#Report
$HT = @{ ErrorAction = "SilentlyContinue" }
$AMHT = @{ Type = "NoteProperty" ; PassThru = $true ; Force = $true }
$FilterHT = @{ FilterHashTable = @{ LogName = "Microsoft-Windows-CAPI2/Operational" ; Id = 81 }}
Get-WinEvent @FilterHT @HT | ForEach-Object -Process {
    $xml = ([xml]($_.toXML()))
    $_ | Add-Member -Name ProcessName   -Value ($xml.Event.UserData.WinVerifyTrust.EventAuxInfo.ProcessName) @AMHT |
         Add-Member -Name Result        -Value ($xml.Event.UserData.WinVerifyTrust.Result.value) @AMHT |
         Add-Member -Name FilePath      -Value ($xml.Event.UserData.WinVerifyTrust.FileInfo.FilePath) -Force -MemberType NoteProperty
         $msg = 'The WinVerifyTrust check performed by process {0} on file {1} ended with result {2}' -f $_.ProcessName,$_.FilePath,$_.Result
         $_ | Add-Member -Name Message -Value $msg @AMHT
}

#Apply Registry Keys

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI' -Name 'AllowAppHVSI' -Value '0'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI' -Name 'AllowAppHVSI_ProviderSet' -Value '3'

#Enalbe Classic Context Menu in Windows 11

New-Item -Path 'HKCU:\SOFTWARE\CLASSES\CLSID\' -Name '{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
New-Item -Path 'HKCU:\SOFTWARE\CLASSES\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Name 'InprocServer32'
Set-ItemProperty -Path 'HKCU:\SOFTWARE\CLASSES\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(Default)' -Value '1'
Clear-ItemProperty -Path 'HKCU:\SOFTWARE\CLASSES\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(Default)'

#Enable Dark Theme on Windows

Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Value '0'

#### Disable RC4 ####
Write-host "Disabling RC4 Ciphers"
$RC4CipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
# $([char]0x2215) in order to have / in name
$Keyname1 = "RC4 56$([char]0x2215)128"
$Keyname2 = "RC4 40$([char]0x2215)128"
$Keyname3 = "RC4 128$([char]0x2215)128"
$Keyname4 = "RC4 64$([char]0x2215)128"
New-Item $RC4CipherRootKey$Keyname1 -Force
New-Item $RC4CipherRootKey$Keyname2 -Force
New-Item $RC4CipherRootKey$Keyname3 -Force
New-Item $RC4CipherRootKey$Keyname4 -Force
Set-ItemProperty $RC4CipherRootKey$Keyname1 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC4CipherRootKey$Keyname2 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC4CipherRootKey$Keyname3 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC4CipherRootKey$Keyname4 -Name Enabled -Value 0 -Type Dword
#### End Disable RC4 ####

#### Disable RC2 ####
Write-host "Disabling RC2 Ciphers"
$RC2CipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
# $([char]0x2215) in order to have / in name
$Keyname1 = "RC2 56$([char]0x2215)128"
$Keyname2 = "RC2 40$([char]0x2215)128"
$Keyname3 = "RC2 128$([char]0x2215)128"
New-Item $RC2CipherRootKey$Keyname1 -Force
New-Item $RC2CipherRootKey$Keyname2 -Force
New-Item $RC2CipherRootKey$Keyname3 -Force
Set-ItemProperty $RC2CipherRootKey$Keyname1 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC2CipherRootKey$Keyname2 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $RC2CipherRootKey$Keyname3 -Name Enabled -Value 0 -Type Dword
#### End Disable RC2 ####

#### Disable DES and Triple DES ####
Write-host "Disabling Weak DES/3DES Ciphers"
$ESCipherRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\"
$Keyname1 = "DES 56$([char]0x2215)56"
$Keyname2 = "Triple DES 168"
New-Item $ESCipherRootKey$Keyname1 -Force
New-Item $ESCipherRootKey$Keyname2 -Force
Set-ItemProperty $ESCipherRootKey$Keyname1 -Name Enabled -Value 0 -Type Dword
Set-ItemProperty $ESCipherRootKey$Keyname2 -Name Enabled -Value 0 -Type Dword
#### End DES and Triple DES ####

#### Disable SSL3.0 ####
write-host "Disabling SSL3.0 protocol"
$SSL3MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"

New-Item "$SSL3MainKey\Client\" -Force
Set-ItemProperty "$SSL3MainKey\Client\" -Name "DisabledByDefault" -Value 1 -Type Dword

New-Item "$SSL3MainKey\Server\" -Force
Set-ItemProperty "$SSL3MainKey\Server\" -Name "Enabled" -Value 0 -Type Dword
#### End Disable SSL3.0 ####

#### Disable SSL2.0 ####
write-host "Disabling SSL2.0 protocol"
$SSL2MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"

New-Item "$SSL2MainKey\Client\" -Force
Set-ItemProperty "$SSL2MainKey\Client\" -Name "DisabledByDefault" -Value 1 -Type Dword

New-Item "$SSL2MainKey\Server\" -Force
Set-ItemProperty "$SSL2MainKey\Server\" -Name "Enabled" -Value 0 -Type Dword
#### End Disable SSL2.0 ####

#Enable TLS 1.2
$TLS12MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
New-Item "$TLS12MainKey\Server" -Force | Out-Null
New-ItemProperty -path "$TLS12MainKey\Server" -name "Enabled" -value "1" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS12MainKey\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force
New-Item "$TLS12MainKey\Client" -Force | Out-Null
New-ItemProperty -path "$TLS12MainKey\Client" -name "Enabled" -value "1" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS12MainKey\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord" -Force
Write-Host "TLS 1.2 has been enabled."

#Disable TLS 1.0
$TLS10MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
New-Item "$TLS10MainKey\Server" -Force
New-ItemProperty -path "$TLS10MainKey\Server\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS10MainKey\Server\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
New-Item "$TLS10MainKey\Client\" -Force
New-ItemProperty -path "$TLS10MainKey\Client\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS10MainKey\Client\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
Write-Host "TLS 1.0 has been disabled."

#Disable TLS 1.1
$TLS11MainKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
New-Item "$TLS11MainKey\Server" -Force
New-ItemProperty -path "$TLS11MainKey\Server\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS11MainKey\Server\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
New-Item "$TLS11MainKey\Client\" -Force
New-ItemProperty -path "$TLS11MainKey\Client\" -name "Enabled" -value "0" -PropertyType "DWord" -Force
New-ItemProperty -path "$TLS11MainKey\Client\" -name "DisabledByDefault" -value 1 -PropertyType "DWord" -Force
Write-Host "TLS 1.1 has been disabled."


#Enable TLS 1.2

$SChannelRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

New-Item $SChannelRegPath"\TLS 1.2\Server" -Force

New-Item $SChannelRegPath"\TLS 1.2\Client" -Force

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Server" `
-Name Enabled -Value 1 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Server" `
-Name DisabledByDefault -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Client" `
-Name Enabled -Value 1 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Client" `
-Name DisabledByDefault -Value 0 -PropertyType DWORD

#Configure .NET Applicaions to use TLS 1.1 and TLS 1.2

$RegPath1 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"

New-ItemProperty -path $RegPath1 `
-name SystemDefaultTlsVersions -value 1 -PropertyType DWORD

New-ItemProperty -path $RegPath1 `
-name SchUseStrongCrypto -value 1 -PropertyType DWORD

$RegPath2 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"

New-ItemProperty -path $RegPath2 `
-name SystemDefaultTlsVersions -value 1 -PropertyType DWORD

New-ItemProperty -path $RegPath2 `
-name SchUseStrongCrypto -value 1 -PropertyType DWORD

#Disable TLS 1.0 and 1.1

New-Item $SChannelRegPath -Name "TLS 1.0"

New-Item $SChannelRegPath"\TLS 1.0" -Name SERVER

New-ItemProperty -Path $SChannelRegPath"\TLS 1.0\SERVER" `-Name Enabled -Value 0 -PropertyType DWORD

New-Item $SChannelRegPath"\TLS 1.1\Server" –force

New-Item $SChannelRegPath"\TLS 1.1\Client" –force

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Server" ` -Name Enabled -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Server" `-Name DisabledByDefault -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Client" `-Name Enabled -Value 0 -PropertyType DWORD

New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Client" `-Name DisabledByDefault -Value 0 -PropertyType DWORD

#Disable weak ciphers and algorithms

Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_MD5"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA256"

#Permanently enable strong cryptography in the Microsoft .NET Framework version 4.x or later
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Type DWord -Value '1'

Write-Host 'Configuring IIS with SSL/TLS Deployment Best Practices...'
Write-Host '--------------------------------------------------------------------------------'
 
# Disable Multi-Protocol Unified Hello
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'Multi-Protocol Unified Hello has been disabled.'
 
# Disable PCT 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'PCT 1.0 has been disabled.'
 
# Disable SSL 2.0 (PCI Compliance)
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 has been disabled.'
 
# NOTE: If you disable SSL 3.0 the you may lock out some people still using
# Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
# for these people to fall back. Safer shopping certifications may require that
# you disable SSLv3.
#
# Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 has been disabled.'
 
# Disable TLS 1.0 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.0 has been disabled.'
 
# Add and Disable TLS 1.1 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.1 has been disabled.'
 
# Add and Enable TLS 1.2 for client and server SCHANNEL communications
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.'
 
# Re-create the ciphers key.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null
 
# Disable insecure/weak ciphers.
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128',
  'Triple DES 168'
)
Foreach ($insecureCipher in $insecureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host "Weak cipher $insecureCipher has been disabled."
}
 
# Enable new secure ciphers.
# - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
# - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
# - Windows Vista and before 'Triple DES 168' was named 'Triple DES 168/168' per https://support.microsoft.com/en-us/kb/245030
$secureCiphers = @(
  'AES 128/128',
  'AES 256/256'
)
Foreach ($secureCipher in $secureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Strong cipher $secureCipher has been enabled."
}
 
# Set hashes configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
 
$secureHashes = @(
  'SHA',
  'SHA256',
  'SHA384',
  'SHA512'
)
Foreach ($secureHash in $secureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Hash $secureHash has been enabled."
}
 
# Set KeyExchangeAlgorithms configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
$secureKeyExchangeAlgorithms = @(
  'Diffie-Hellman',
  'ECDH',
  'PKCS'
)
Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
}
 
# Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
# https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644
Write-Host 'Configure longer DHE key shares for TLS servers.'
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ServerMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
 
# https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
 
# Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
$os = Get-WmiObject -class Win32_OperatingSystem
if ([System.Version]$os.Version -lt [System.Version]'10.0') {
  Write-Host 'Use cipher suites order for Windows 2008/2008R2/2012/2012R2.'
  $cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
    # Below are the only AEAD ciphers available on Windows 2012R2 and earlier.
    # - RSA certificates need below ciphers, but ECDSA certificates (EV) may not.
    # - We get penalty for not using AEAD suites with RSA certificates.
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_CBC_SHA'
  )
} else {
  Write-Host 'Use cipher suites order for Windows 10/2016 and later.'
  $cipherSuitesOrder = @(
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
  )
}
$cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
# One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null
 
# Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
# https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
# New IIS functionality to help identify weak TLS usage
# https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
Write-Host 'Enable TLS 1.2 for .NET 3.5 and .NET 4.x'
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
}
 
# DefaultSecureProtocols Value	Decimal value  Protocol enabled
# 0x00000008                                8  Enable SSL 2.0 by default
# 0x00000020                               32  Enable SSL 3.0 by default
# 0x00000080                              128  Enable TLS 1.0 by default
# 0x00000200                              512  Enable TLS 1.1 by default
# 0x00000800                             2048  Enable TLS 1.2 by default
$defaultSecureProtocols = @(
  '2048'  # TLS 1.2
)
$defaultSecureProtocolsSum = ($defaultSecureProtocols | Measure-Object -Sum).Sum
 
# Update to enable TLS 1.2 as a default secure protocols in WinHTTP in Windows
# https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in
 
# Verify if hotfix KB3140245 is installed.
$file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | % {("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
$file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | % {("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
  Write-Host 'WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements.'
} else {
  Write-Host 'WinHTTP: Minimum system requirements are met.'
  Write-Host 'WinHTTP: Activate TLS 1.2 only.'
  New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
  if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
    # WinHttp key seems missing in Windows 2019 for unknown reasons.
    New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
  }
}
 
Write-Host 'Windows Internet Explorer: Activate TLS 1.2 only.'
New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null