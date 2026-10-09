# Publish a new IntelliTest AI desktop release to GitHub Releases (installed apps auto-update from it).
#
#   .\release.ps1                 # bump patch version (1.0.0 -> 1.0.1) and publish
#   .\release.ps1 -Bump minor     # 1.0.1 -> 1.1.0
#   .\release.ps1 -Bump none      # publish the current version (use for the very first release)
#
# Needs: a GitHub repo for the releases and a token with "Contents: read and write" on it.
param(
  [ValidateSet('patch', 'minor', 'major', 'none')] [string]$Bump = 'patch',
  [string]$Owner = $env:GH_OWNER,
  [string]$Repo = $env:GH_REPO
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $Owner) { $Owner = Read-Host 'GitHub username / organisation that owns the releases repo' }
if (-not $Repo)  { $Repo  = Read-Host 'GitHub repository name (e.g. intellitest-ai)' }
if (-not $env:GH_TOKEN) {
  $secure = Read-Host 'GitHub token (input hidden)' -AsSecureString
  $env:GH_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
$env:GH_OWNER = $Owner
$env:GH_REPO = $Repo

if ($Bump -ne 'none') {
  npm version $Bump --no-git-tag-version --workspace desktop | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Version bump failed' }
}
$version = (Get-Content desktop\package.json -Raw | ConvertFrom-Json).version
Write-Host "Testing before release $version ..." -ForegroundColor Cyan
npm test
if ($LASTEXITCODE -ne 0) { throw 'Tests failed - release aborted' }

Write-Host "Building and publishing IntelliTest AI $version to github.com/$Owner/$Repo ..." -ForegroundColor Cyan
npm run release:win
if ($LASTEXITCODE -ne 0) { throw 'Release failed' }

Write-Host ""
Write-Host "Done. Open https://github.com/$Owner/$Repo/releases to review the release notes." -ForegroundColor Green
Write-Host "Installed apps will offer version $version on their next start (or Help > Check for updates)."
