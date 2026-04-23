<#
Convert-PemToPfx-And-Import.ps1

Converts a private-key PEM (and optional certificate PEM) to a PFX using OpenSSL,
imports it into LocalMachine\My, and (optionally) grants ACL to an IIS AppPool.

Intended for interactive use on a Windows server (run as Administrator).

Usage examples:
  # Convert gigya-private.pem + cert.pem -> gigya.pfx, import, grant ACL to 'MyAppPool'
  .\Convert-PemToPfx-And-Import.ps1 -PrivateKeyPem .\gigya-private.pem -CertPem .\gigya-cert.pem -OutPfx .\gigya.pfx -AppPoolName 'MyAppPool'

  # Convert gigya-private.pem by creating a self-signed cert for testing
  .\Convert-PemToPfx-And-Import.ps1 -PrivateKeyPem .\gigya-private.pem -OutPfx .\gigya.pfx -AppPoolName 'MyAppPool'

Notes:
- This script requires OpenSSL installed and available in PATH. If not installed, see https://slproweb.com/products/Win32OpenSSL.html
- Do NOT commit produced PFX or passwords to source control. Keep them secure.
- For production, obtain a proper certificate from your CA instead of using a self-signed cert.
#>
param(
    [string]$PrivateKeyPem = "gigya-private.pem",
    [string]$CertPem = "",
    [string]$OutPfx = "gigya.pfx",
    [string]$AppPoolName = "DefaultAppPool",
    [switch]$GrantAcl = $true,
    [int]$PfxValidityDays = 365
)

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script must be run as Administrator. Open PowerShell as Administrator and re-run."
        exit 1
    }
}

Assert-Admin

# Resolve paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$privateKeyPath = Resolve-Path -LiteralPath $PrivateKeyPem -ErrorAction SilentlyContinue
if (-not $privateKeyPath) {
    Write-Error "Private key PEM not found at path: $PrivateKeyPem"
    exit 1
}
$privateKeyPath = $privateKeyPath.Path

if ($CertPem) {
    $certPemPath = Resolve-Path -LiteralPath $CertPem -ErrorAction SilentlyContinue
    if (-not $certPemPath) {
        Write-Error "Certificate PEM not found at path: $CertPem"
        exit 1
    }
    $certPemPath = $certPemPath.Path
}
else {
    $certPemPath = ""
}

# Find openssl
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Error "OpenSSL not found in PATH. Please install OpenSSL and ensure 'openssl' is available in PATH."
    Write-Host "Suggested: https://slproweb.com/products/Win32OpenSSL.html or use Chocolatey: choco install openssl.light"
    exit 1
}
$opensslPath = $openssl.Source

# Prompt for PFX password
$securePwd = Read-Host -AsSecureString "Enter PFX password (will be used to protect the created PFX)"
$ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
$pfxPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)

# If no cert provided, create a self-signed cert PEM using OpenSSL (for local testing only)
$tempCreatedCert = $false
if (-not $certPemPath) {
    Write-Host "No certificate PEM provided. Creating a temporary self-signed certificate (for testing only)."
    $tempCertPath = Join-Path $scriptDir "temp_cert.pem"
    # Create a self-signed cert using the private key
    $subj = "/CN=GigyaJwtLocalTest"
    $cmd = "req -new -x509 -key `"$privateKeyPath`" -out `"$tempCertPath`" -days $PfxValidityDays -subj `"$subj`""
    Write-Host "Running: openssl $cmd"
    $proc = Start-Process -FilePath $opensslPath -ArgumentList $cmd -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Error "OpenSSL failed to create self-signed certificate (exit $($proc.ExitCode))."
        exit 1
    }
    $certPemPath = $tempCertPath
    $tempCreatedCert = $true
}

# Build openssl pkcs12 export command
$outPfxFull = Resolve-Path -LiteralPath (Join-Path $scriptDir $OutPfx) -ErrorAction SilentlyContinue
if ($outPfxFull) { $outPfxFull = $outPfxFull.Path } else { $outPfxFull = Join-Path $scriptDir $OutPfx }

$exportCmd = "pkcs12 -export -out `"$outPfxFull`" -inkey `"$privateKeyPath`" -in `"$certPemPath`" -passout pass:$pfxPasswordPlain"
Write-Host "Running: openssl $exportCmd"
$proc = Start-Process -FilePath $opensslPath -ArgumentList $exportCmd -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "OpenSSL pkcs12 export failed (exit $($proc.ExitCode))."
    if ($tempCreatedCert -and (Test-Path $certPemPath)) { Remove-Item $certPemPath -ErrorAction SilentlyContinue }
    exit 1
}

Write-Host "PFX created at: $outPfxFull"

# Import the PFX into LocalMachine\My
try {
    $secureForImport = ConvertTo-SecureString $pfxPasswordPlain -AsPlainText -Force
    Write-Host "Importing PFX into LocalMachine\\My..."
    $imported = Import-PfxCertificate -FilePath $outPfxFull -CertStoreLocation Cert:\LocalMachine\My -Password $secureForImport -Exportable
    if (-not $imported) {
        Write-Error "Import-PfxCertificate did not return a certificate object."
        exit 1
    }
    # Import-PfxCertificate may return array; pick first
    if ($imported -is [System.Array]) { $certObj = $imported[0] } else { $certObj = $imported }
    Write-Host "Imported certificate Subject: $($certObj.Subject) Thumbprint: $($certObj.Thumbprint)"
}
catch {
    Write-Error "Failed to import PFX: $_"
    if ($tempCreatedCert -and (Test-Path $certPemPath)) { Remove-Item $certPemPath -ErrorAction SilentlyContinue }
    exit 1
}

# Attempt to set private key ACL (classic CAPI)
$thumbNormalized = ($certObj.Thumbprint -replace '\s','').ToUpperInvariant()
$setAclSuccess = $false
try {
    $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { ($_.Thumbprint -replace '\s','').ToUpperInvariant() -eq $thumbNormalized }
    if ($existingCert -ne $null) {
        $privateKey = $existingCert.PrivateKey
        if ($privateKey -ne $null) {
            $cspInfo = $privateKey.CspKeyContainerInfo
            if ($cspInfo -ne $null) {
                $keyName = $cspInfo.UniqueKeyContainerName
                $keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName"
                if (Test-Path $keyPath) {
                    Write-Host "Found MachineKeys file: $keyPath"
                    $acct = "IIS AppPool\$AppPoolName"
                    Write-Host "Granting Read access to $acct on the private key file using icacls..."
                    & icacls.exe $keyPath /grant "$acct:R" | Write-Host
                    $setAclSuccess = $true
                }
            }
        }
    }
}
catch {
    Write-Warning "Unable to set ACL via icacls: $_"
}

if (-not $setAclSuccess) {
    Write-Host "Could not set ACL automatically. If the key is CNG or hardware-backed, use the MMC to Manage Private Keys:"
    Write-Host "  1. Run certlm.msc (Local Computer -> Personal -> Certificates)."
    Write-Host "  2. Right-click the imported cert -> All Tasks -> Manage Private Keys..."
    Write-Host "  3. Add 'IIS AppPool\$AppPoolName' (or your service account) and grant Read."
}

# Clean up temp cert file if created
if ($tempCreatedCert -and (Test-Path $certPemPath)) { Remove-Item $certPemPath -ErrorAction SilentlyContinue }

Write-Host "\nPFX import complete. Thumbprint (no spaces): $($certObj.Thumbprint -replace ' ','')"
Write-Host "Add to Web.config: <add key=\"GigyaGlobalCertThumbprint\" value=\"$($certObj.Thumbprint -replace ' ','')\" />"
Write-Host "Don't forget to remove any GigyaGlobalPrivateKey entries from Web.config."
Write-Host "Restart your app pool or IIS and test: GET /api/gigya/cert-status"

# Zero sensitive variable
$pfxPasswordPlain = ''

Write-Host "Done."