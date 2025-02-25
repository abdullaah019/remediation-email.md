<#
.SYNOPSIS
    Toggles cryptographic protocols (secure vs insecure) on the system.
    Please test thoroughly in a non-production environment before deploying widely.
    Make sure to run as Administrator or with appropriate privileges.

.NOTES
    Author        : Abdullaah Yaseen
    Date Created  : 2025-02-20
    Last Modified : 2025-02-23
    Version       : 1.0

.TESTED ON
    Date(s) Tested  : 2025-02-22
    Tested By       : Abdullaah Yaseen
    Systems Tested  : Windows Server 2019 Datacenter, Build 1809
    PowerShell Ver. : 5.1.17763.6189

.USAGE
    Set [$makeSecure = $true] to secure the system
    Example syntax:
    PS C:\> .\toggle-protocols.ps1 
#>
 
# Variable to determine if we want to make the computer secure or insecure
$makeSecure = $true

# Check if the script is run as Administrator
function Check-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main script
if (-not (Check-Admin)) {
    Write-Error "Access Denied. Please run with Administrator privileges."
    exit 1
}

# SSL 2.0 settings
$serverPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
$clientPathSSL2 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

if ($makeSecure) {
    New-Item -Path $serverPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 2.0 has been disabled."
} else {
    New-Item -Path $serverPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $serverPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    New-Item -Path $clientPathSSL2 -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path $clientPathSSL2 -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force | Out-Null
    
    Write-Host "SSL 2.0 has been enabled."
}

Write-Host "Please reboot for settings to take effect."
