param(
  [string]$SecretDirectory = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Codex\PaldobogLicenseSecrets')
)

$ErrorActionPreference = 'Stop'
$bundlePath = Join-Path $SecretDirectory 'paldobog-license-secrets.dpapi'

if (Test-Path -LiteralPath $bundlePath) {
  throw "A secret bundle already exists at $bundlePath. Keep using that bundle so the deployed app keeps the same signing identity."
}

New-Item -ItemType Directory -Path $SecretDirectory -Force | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $SecretDirectory /inheritance:r /grant:r "$identity`:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the local secrets folder to the current Windows account.' }

$rsa = [System.Security.Cryptography.RSA]::Create(2048)
try {
  $privateDer = $rsa.ExportPkcs8PrivateKey()
  $publicDer = $rsa.ExportSubjectPublicKeyInfo()
  $random = [byte[]]::new(32)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
  $pepper = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
  $adminToken = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')

  $bundle = [ordered]@{
    PALDOBOG_LICENSE_PRIVATE_KEY_B64 = [Convert]::ToBase64String($privateDer)
    PALDOBOG_LICENSE_PEPPER = $pepper
    PALDOBOG_ADMIN_TOKEN = $adminToken
  }
  $plain = [Text.Encoding]::UTF8.GetBytes(($bundle | ConvertTo-Json -Compress))
  $protected = [Security.Cryptography.ProtectedData]::Protect(
    $plain,
    $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser
  )
  [IO.File]::WriteAllBytes($bundlePath, $protected)

  $sha = [Security.Cryptography.SHA256]::HashData($publicDer)
  $fingerprint = [Convert]::ToHexString($sha).ToLowerInvariant()
  Write-Output "Created a Windows-protected host secret bundle: $bundlePath"
  Write-Output "Public signing-key SHA-256 fingerprint: $fingerprint"
  Write-Output 'The private signing key, pepper, and admin token were not printed.'
} finally {
  $rsa.Dispose()
  if ($privateDer) { [Array]::Clear($privateDer, 0, $privateDer.Length) }
  if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
}
