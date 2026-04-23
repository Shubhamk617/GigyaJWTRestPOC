<#
Import-Certificate-And-GrantAcl.ps1

Interactive PowerShell helper to import a PFX into LocalMachine\My and grant an IIS AppPool (or user) read access to the private key.

Usage (Run as Administrator PowerShell):
  .\Import-Certificate-And-GrantAcl.ps1 -PfxPath C:\tmp\mycert.pfx -PfxPassword 'PfxPwd' -AppPoolName 'MyAppPool'

Parameters:
  -PfxPath      Optional. Full path to a .pfx file to import. If provided, script imports into LocalMachine\My.
  -PfxPassword  Optional. Password for the PFX. If omitted and PfxPath provided, you'll be prompted.
  -Thumbprint   Optional. Thumbprint of an existing cert in the store (no spaces). If omitted and no PfxPath, script lists certs and prompts selection.
  -AppPoolName  Optional. IIS AppPool name or account to grant rights to. Default: 'DefaultAppPool'. If you want to grant to a Windows account, supply e.g. 'DOMAIN\\svc-gigya'.

Note: This script handles classic CAPI (MachineKeys) keys via icacls. For CNG or HSM-backed keys the script will print guidance and you should use the GUI (certlm.msc -> Manage Private Keys...).
#>
param(
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$Thumbprint,
    [string]$AppPoolName = 'DefaultAppPool'
)

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script must be run as Administrator. Open PowerShell as Administrator and re-run."
        exit 1
    }
}

Assert-Admin

if ($PfxPath) {
    if (-not (Test-Path $PfxPath)) {
        Write-Error "PFX file not found: $PfxPath"
        exit 1
    }
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host -AsSecureString "Enter PFX password" | ConvertFrom-SecureString
        # Convert back to plain for Import-PfxCertificate convenience (temporary variable)
        $secure = ConvertTo-SecureString (ConvertTo-SecureString $PfxPassword) -AsPlainText -Force
    }
    else {
        $secure = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
    }

    Write-Host "Importing PFX into LocalMachine\My..."
    try {
        $cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $secure -Exportable
        Write-Host "Imported certificate with subject: $($cert.Subject) thumbprint: $($cert.Thumbprint)"
        $Thumbprint = $cert.Thumbprint
    }
    catch {
        Write-Error "Failed to import PFX: $_"
        exit 1
    }
}

if (-not $Thumbprint) {
    Write-Host "No thumbprint provided. Listing certificates in LocalMachine\My..."
    Get-ChildItem Cert:\LocalMachine\My | Select-Object @{n='Index';e={$_}}, Subject, Thumbprint | Format-Table -AutoSize
    $Thumbprint = Read-Host "Enter the thumbprint of the certificate you want to grant ACL for (no spaces)"
}

$thumbNormalized = ($Thumbprint -replace '\s','').ToUpperInvariant()
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { ($_.Thumbprint -replace '\s','').ToUpperInvariant() -eq $thumbNormalized }
    if (-not $cert) {
        Write-Error "Certificate with thumbprint $Thumbprint not found in LocalMachine\My"
        exit 1
    }
    Write-Host "Found cert: $($cert.Subject) (Thumbprint: $($cert.Thumbprint))"
}
catch {
    Write-Error "Error reading certificate store: $_"
    exit 1
}

# Try to find classic CAPI MachineKeys file
$sp = $null
try {
    $privateKey = $cert.PrivateKey
    if ($privateKey -ne $null) {
        $cspInfo = $privateKey.CspKeyContainerInfo
        if ($cspInfo -ne $null) {
            $keyName = $cspInfo.UniqueKeyContainerName
            $keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName"
            if (Test-Path $keyPath) {
                Write-Host "Detected CAPI key file: $keyPath"
                $sp = 'CAPI'
                Write-Host "Granting Read access to $AppPoolName on the private key file..."
                $acct = "IIS AppPool\$AppPoolName"
                try {
                    & icacls.exe $keyPath /grant "$acct:R" | Write-Host
                    Write-Host "ACL updated successfully.
If your app pool identity is different (custom account) please use that username instead of IIS AppPool\\$AppPoolName."
                }
                catch {
                    Write-Error "Failed to set ACL via icacls: $_"
                    exit 1
                }
            }
        }
    }
}
catch {
    # ignore, will try CNG path
}

if (-not $sp) {
    Write-Host "Could not find a classic CAPI MachineKeys file for this certificate. It may be a CNG or hardware-backed key."
    Write-Host "Please use the Certificate MMC (certlm.msc) -> Personal -> right-click cert -> All Tasks -> Manage Private Keys... to grant access to the app pool identity."
}

Write-Host "\nSuggested Web.config entry (use the thumbprint without spaces):"
Write-Host "<add key=\"GigyaGlobalCertThumbprint\" value=\"$($cert.Thumbprint -replace ' ', '')\" />"
Write-Host "\nYou can test the debug endpoint: GET /api/gigya/cert-status"

Write-Host "Done."