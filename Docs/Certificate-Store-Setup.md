Purpose

This document describes how to import a PFX certificate into the Windows certificate store, grant the IIS app pool (or other process) access to the private key, and configure `GigyaGlobalCertThumbprint` in `Web.config`. Use these steps for on-prem IIS (highest-security) deployments.

Prerequisites

- Administrative access on the server where you will import the certificate.
- `openssl` available if you must convert PEM -> PFX.
- PowerShell (run as Administrator for import/ACL steps).

1) (Optional) Convert PEM to PFX with OpenSSL

If you have a separate certificate file (`cert.pem`) and private key (`private_key.pem`), convert them to a PFX so you can import on Windows:

```
openssl pkcs12 -export -out mycert.pfx -inkey private_key.pem -in cert.pem -passout pass:YourPfxPassword
```

- Replace `YourPfxPassword` with a strong password.
- Keep `mycert.pfx` and password secure; do not commit to source control.

2) Import the PFX into the LocalMachine\My store

Run PowerShell as Administrator and execute:

```powershell
$pfxPath = 'C:\path\to\mycert.pfx'
$pwd = ConvertTo-SecureString 'YourPfxPassword' -AsPlainText -Force
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $pwd
```

- This imports the certificate into the machine personal store. For dev you can import to `Cert:\CurrentUser\My` instead.

3) Get the certificate thumbprint (value to put in `Web.config`)

```powershell
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Thumbprint
```

- Copy the thumbprint and remove any spaces when adding to config. Example thumbprint (no spaces): `FAB7E238E83C2A973FFCCAB9E9BB7D7F028A92C2`.

4) Grant the app process (IIS App Pool) access to the private key

Option A — GUI (recommended for admins)

- Open `certlm.msc` (Local Computer -> Personal -> Certificates).
- Right-click the certificate -> All Tasks -> Manage Private Keys...
- Add `IIS AppPool\YourAppPoolName` (or the service account), grant Read permission.

Option B — Scripted (works for classic CAPI keys)

Run elevated PowerShell (replace `THUMBPRINT` and `YourAppPoolName`):

```powershell
$thumb = 'THUMBPRINT_WITHOUT_SPACES'
$cert = Get-Item "Cert:\LocalMachine\My\$thumb"
$keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName"
# Grant read access to the app pool identity
icacls $keyPath /grant "IIS AppPool\YourAppPoolName":R
```

- If `$cert.PrivateKey` is null (CNG key) use the GUI "Manage Private Keys" instead.
- If your app runs under a custom Windows account, grant that account instead of `IIS AppPool\...`.

5) Configure `Web.config`

- Open `Web.config` and set the `GigyaGlobalCertThumbprint` appSetting to the cert thumbprint (no spaces):

```xml
<add key="GigyaGlobalCertThumbprint" value="FAB7E238E83C2A973FFCCAB9E9BB7D7F028A92C2" />
```

- Remove any raw private key values from `Web.config` (do not store private keys in config).

6) Restart the application

- Recycle the application pool or restart IIS:

```powershell
# Recycle app pool (requires WebAdministration module)
Import-Module WebAdministration
Restart-WebAppPool -Name 'YourAppPoolName'

# Or restart IIS
iisreset
```

7) Test the debug endpoint

- The project includes an internal debug endpoint to validate cert presence and ACLs:

```
GET https://<your-host>/api/gigya/cert-status
```

- Example using PowerShell (from the server):

```powershell
Invoke-RestMethod -Uri 'https://localhost/api/gigya/cert-status' -UseDefaultCredentials
```

- Expected fields in the JSON response: `Found`, `HasPrivateKey`, `CanSign`, `KeySize`, `Subject`, `Issuer`, `NotBefore`, `NotAfter`, `Message`.

Troubleshooting

- "Certificate not found": verify the cert is in LocalMachine\My and the thumbprint has no spaces and matches exactly.
- "Certificate does not have an RSA private key or the process lacks access to it": confirm the private key was imported and private key ACL grants read to the app identity.
- If `GetRSAPrivateKey()` returns null, the certificate may be using a provider not supported by the .NET API or the key is stored differently (use cert UI to inspect).
- For CNG provider keys use the GUI "Manage Private Keys..." to set ACLs.

Security notes

- Do not store private key material in `Web.config` or source control.
- Keep PFX files and PFX passwords out of the repository; transfer with secure channels.
- Limit private key ACLs to only the required app identity and administrators.
- Consider enterprise secret stores (Key Vault, Vault) for larger deployments.

References

- `Import-PfxCertificate` (PowerShell)
- `certlm.msc` (Certificates snap-in)
- `icacls` (file ACL management)


If you want, I can add this README to the repo and a small PowerShell script that performs the import + ACL steps (interactive, requires admin).