<#
Detect-CertKeyProvider.ps1

Given a certificate thumbprint (no spaces), this script attempts to detect whether the
certificate private key is managed by legacy CAPI (RSACryptoServiceProvider) or CNG (RSACng),
and prints the underlying key file path that you can use with icacls (for CAPI) or the Keys
folder path (for many CNG keys).

Run as Administrator when inspecting machine keys.

Usage:
  .\Detect-CertKeyProvider.ps1 -Thumbprint FAB7E238E83C2A973FFCCAB9E9BB7D7F028A92C2

Outputs:
  - Provider type: CAPI or CNG or Hardware/HSM
  - If CAPI: the MachineKeys file path
  - If CNG: the likely Keys folder path (C:\ProgramData\Microsoft\Crypto\Keys\<UniqueName>)
  - If unable to resolve, prints guidance to use MMC -> Manage Private Keys
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Thumbprint
)

function Normalize-Thumbprint($t) {
    return ($t -replace '\s','').ToUpperInvariant()
}

$tp = Normalize-Thumbprint $Thumbprint
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { (($_.Thumbprint -replace '\s','').ToUpperInvariant()) -eq $tp }
    if (-not $cert) {
        Write-Error "Certificate with thumbprint $Thumbprint not found in LocalMachine\My"
        exit 1
    }
    Write-Host "Found cert: $($cert.Subject)"

    # Try RSACryptoServiceProvider (CAPI)
    try {
        $privateKey = $cert.PrivateKey
        if ($privateKey -ne $null) {
            $typeName = $privateKey.GetType().FullName
            Write-Host "PrivateKey runtime type: $typeName"
            if ($privateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                $csp = [System.Security.Cryptography.RSACryptoServiceProvider]$privateKey
                $cspInfo = $csp.CspKeyContainerInfo
                $uniqueName = $cspInfo.UniqueKeyContainerName
                $machineKeysPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$uniqueName"
                Write-Host "Detected legacy CAPI (RSACryptoServiceProvider)."
                Write-Host "MachineKeys file path: $machineKeysPath"
                Write-Host "You can run: icacls `"$machineKeysPath`" /grant `"IIS AppPool\YourAppPoolName`:R"
                exit 0
            }
        }
    }
    catch {
        # continue to try CNG
    }

    # Try CNG via RSACng
    try {
        $rsa = $cert.GetRSAPrivateKey()
        if ($rsa -ne $null) {
            $rsaType = $rsa.GetType().FullName
            Write-Host "GetRSAPrivateKey() returned type: $rsaType"
            if ($rsa -is [System.Security.Cryptography.RSACng]) {
                $rsacng = [System.Security.Cryptography.RSACng]$rsa
                $cngKey = $rsacng.Key
                if ($cngKey -ne $null) {
                    $uniqueName = $cngKey.UniqueName
                    if ($uniqueName) {
                        $keysPath = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$uniqueName"
                        Write-Host "Detected CNG (RSACng). Likely key file path: $keysPath"
                        Write-Host "Use the MMC -> Manage Private Keys or icacls on that file to update ACLs if present."
                        exit 0
                    }
                }
            }
            else {
                Write-Host "Private key type is: $rsaType (not RSACng). If it's hardware-backed or a provider without a file, use MMC to manage ACLs."
                exit 0
            }
        }
    }
    catch {
        # ignore
    }

    Write-Host "Unable to automatically determine key file path. The certificate may be hardware-backed (HSM) or require vendor tooling."
    Write-Host "Open certlm.msc -> Personal -> select cert -> All Tasks -> Manage Private Keys... to view and edit ACLs."
    exit 0
}
catch {
    Write-Error "Exception: $_"
    exit 1
}