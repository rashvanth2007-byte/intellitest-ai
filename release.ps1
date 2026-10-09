# Publish a new IntelliTest AI desktop release to GitHub Releases (installed apps auto-update from it).
#
#   .\release.ps1                 # bump patch version (1.0.0 -> 1.0.1) and publish
#   .\release.ps1 -Bump minor     # 1.0.1 -> 1.1.0
#   .\release.ps1 -Bump none      # publish the current version (use for the very first release)
#   .\release.ps1 -Manual         # no token: build + latest.yml, then upload the 3 files on github.com yourself
#
# Needs: a GitHub repo for the releases and a token with "Contents: read and write" on it.
param(
  [ValidateSet('patch', 'minor', 'major', 'none')] [string]$Bump = 'patch',
  [string]$Owner = $env:GH_OWNER,
  [string]$Repo = $env:GH_REPO,
  [switch]$Manual
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $Owner) { $Owner = Read-Host 'GitHub username / organisation that owns the releases repo' }
if (-not $Repo)  { $Repo  = Read-Host 'GitHub repository name (e.g. intellitest-ai)' }
if (-not $Manual -and -not $env:GH_TOKEN) {
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

if ($Manual) {
  Write-Host "Building IntelliTest AI $version (update feed: github.com/$Owner/$Repo) ..." -ForegroundColor Cyan
  npm run build:win
  if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
  node desktop\scripts\latest-yml.mjs
  if ($LASTEXITCODE -ne 0) { throw 'Could not write latest.yml' }
  Write-Host ""
  Write-Host "Now upload these 3 files from desktop\dist to a new release tagged v$version :" -ForegroundColor Green
  Write-Host "  IntelliTest-AI-Setup-$version.exe"
  Write-Host "  IntelliTest-AI-Setup-$version.exe.blockmap"
  Write-Host "  latest.yml"
  Start-Process explorer.exe (Resolve-Path desktop\dist)
  Start-Process "https://github.com/$Owner/$Repo/releases/new?tag=v$version&title=IntelliTest%20AI%20$version"
  return
}

Write-Host "Building and publishing IntelliTest AI $version to github.com/$Owner/$Repo ..." -ForegroundColor Cyan
npm run release:win
if ($LASTEXITCODE -ne 0) {
  throw 'Release failed. Scroll up for the first red "HttpError" line. 401 = wrong token; 403 = token lacks "Contents: Read and write" on this repo. Or run: .\release.ps1 -Manual'
}

Write-Host ""
Write-Host "Done. Open https://github.com/$Owner/$Repo/releases to review the release notes." -ForegroundColor Green
Write-Host "Installed apps will offer version $version on their next start (or Help > Check for updates)."
