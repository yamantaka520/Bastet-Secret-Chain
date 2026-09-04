# Install a released bsc.exe for the current user and verify its checksum
# against the SHA256SUMS published with the same release.
#
#   .\install.ps1 -Version v0.2.0
#
# This checks integrity: the archive matches the sums published beside it. It
# does not by itself check who built it, because both come from the same
# release page. From v0.2.0 the sums are signed with Sigstore as well —
# SECURITY.md has the `cosign verify-blob` command and says what it proves.
# Read this file before running it.
param([Parameter(Mandatory = $true)][string]$Version, [string]$BinDir = "$env:LOCALAPPDATA\Programs\bsc")
$ErrorActionPreference = "Stop"
$repo = "yamantaka520/Bastet-Secret-Chain"
$target = "x86_64-pc-windows-msvc"
$name = "bsc-$($Version.TrimStart('v'))-$target"
$base = "https://github.com/$repo/releases/download/$Version"
$tmp = Join-Path $env:TEMP ("bsc-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Invoke-WebRequest -Uri "$base/$name.zip" -OutFile "$tmp\$name.zip"
  Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS"
  $expected = (Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match " $name\.zip$" }) -split '\s+' | Select-Object -First 1
  $actual = (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "checksum mismatch - refusing to install" }
  Expand-Archive "$tmp\$name.zip" -DestinationPath $tmp
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  Copy-Item "$tmp\$name\bsc.exe" "$BinDir\bsc.exe" -Force
  Write-Host "installed $BinDir\bsc.exe"
  & "$BinDir\bsc.exe" --version
  Write-Host "`nnext:  bsc init ; bsc service install ; start http://127.0.0.1:8787/"
  Write-Host "add $BinDir to your PATH if it is not already."
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
