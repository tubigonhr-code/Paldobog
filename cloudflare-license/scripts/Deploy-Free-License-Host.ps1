param(
  [string]$SecretDirectory = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Codex\PaldobogLicenseSecrets')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$bundlePath = Join-Path $SecretDirectory 'paldobog-license-secrets.dpapi'
$wrangler = Join-Path $projectRoot 'node_modules\.bin\wrangler.cmd'

if (-not (Test-Path -LiteralPath $bundlePath)) {
  throw "Secret bundle not found. Run scripts\Generate-Host-Secrets.ps1 first."
}
if (-not (Test-Path -LiteralPath $wrangler)) {
  throw 'Wrangler is not installed. From the license-host folder, run npm install, then rerun this script.'
}

$protected = [IO.File]::ReadAllBytes($bundlePath)
$plain = $null
try {
  $plain = [Security.Cryptography.ProtectedData]::Unprotect(
    $protected,
    $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser
  )
  $secrets = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json

  Push-Location $projectRoot
  try {
    & $wrangler login
    if ($LASTEXITCODE -ne 0) { throw 'Cloudflare sign-in did not finish.' }

    & $wrangler deploy --config wrangler.jsonc
    if ($LASTEXITCODE -ne 0) { throw 'The initial Worker deployment failed.' }

    foreach ($name in @('PALDOBOG_LICENSE_PRIVATE_KEY_B64', 'PALDOBOG_LICENSE_PEPPER', 'PALDOBOG_ADMIN_TOKEN')) {
      $value = [string]$secrets.$name
      if ([string]::IsNullOrWhiteSpace($value)) { throw "Missing secret value: $name" }
      $value | & $wrangler secret put $name --config wrangler.jsonc
      if ($LASTEXITCODE -ne 0) { throw "Cloudflare did not accept secret $name." }
      $value = $null
    }

    Write-Output 'License secrets are set on Cloudflare. Check the Worker URL printed by the deploy, then open /healthz.'
  } finally {
    Pop-Location
  }
} finally {
  if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
  if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
  $secrets = $null
}
