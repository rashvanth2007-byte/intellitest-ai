# Publish a new IntelliTest AI release. Installed apps auto-update; the download page always shows the newest version.
#
#   .\release.ps1                 # bump 1.0.0 -> 1.0.1, test, commit, tag and push — GitHub Actions builds and publishes it
#   .\release.ps1 -Bump minor     # 1.0.1 -> 1.1.0
#   .\release.ps1 -Bump none      # release the current version as-is (use for the very first release, v1.0.0)
#
# Alternatives (run on this PC instead of GitHub Actions):
#   .\release.ps1 -Local          # build here and upload with a GitHub token (asks for it, input hidden)
#   .\release.ps1 -Manual         # build here, then upload the 3 files on github.com yourself (no token)
param(
  [ValidateSet('patch', 'minor', 'major', 'none')] [string]$Bump = 'patch',
  [string]$Owner = 'rashvanth2007-byte',
  [string]$Repo = 'intellitest-ai',
  [switch]$Local,
  [switch]$Manual
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:GH_OWNER = $Owner
$env:GH_REPO = $Repo

function Run($cmd) { Write-Host "> $cmd" -ForegroundColor DarkGray; Invoke-Expression $cmd; if ($LASTEXITCODE -ne 0) { throw "Failed: $cmd" } }

if (-not $Local -and -not $Manual) {
  $dirty = git status --porcelain
  if ($dirty) { throw "You have uncommitted changes. Commit them first:`n  git add -A`n  git commit -m ""describe your change""" }
}

if ($Bump -ne 'none') { Run "npm version $Bump --no-git-tag-version --workspace desktop" }
$version = (Get-Content desktop\package.json -Raw | ConvertFrom-Json).version
$tag = "v$version"

Write-Host "Testing $version ..." -ForegroundColor Cyan
Run 'npm test'

if ($Manual) {
  Run 'npm run build:win'
  Run 'node desktop\scripts\latest-yml.mjs'
  Write-Host "`nUpload these 3 files from desktop\dist to a new release tagged $tag :" -ForegroundColor Green
  Write-Host "  IntelliTest-AI-Setup-$version.exe`n  IntelliTest-AI-Setup-$version.exe.blockmap`n  latest.yml"
  Start-Process explorer.exe (Resolve-Path desktop\dist)
  Start-Process "https://github.com/$Owner/$Repo/releases/new?tag=$tag&title=IntelliTest%20AI%20$version"
  return
}

if ($Local) {
  if (-not $env:GH_TOKEN) {
    $secure = Read-Host 'GitHub token (input hidden)' -AsSecureString
    $env:GH_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
  }
  npm run release:win
  if ($LASTEXITCODE -ne 0) { throw 'Upload failed. Scroll up for the first red HttpError line: 401 = wrong token, 403 = token lacks Contents: Read and write.' }
  Write-Host "`nPublished $tag : https://github.com/$Owner/$Repo/releases" -ForegroundColor Green
  return
}

# Default: let GitHub Actions build and publish (.github/workflows/release.yml).
if (git tag --list $tag) { throw "Tag $tag already exists. Use a higher version (.\release.ps1 -Bump patch)." }
if ($Bump -ne 'none') {
  Run 'git add desktop/package.json package-lock.json'
  Run "git commit -m ""Release $tag"""
}
Run "git tag -a $tag -m ""IntelliTest AI $version"""
Run 'git push origin main'
Run "git push origin $tag"

Write-Host "`nPushed $tag. GitHub is now building and publishing it (about 5-10 minutes):" -ForegroundColor Green
Write-Host "  Progress:      https://github.com/$Owner/$Repo/actions"
Write-Host "  Release:       https://github.com/$Owner/$Repo/releases/tag/$tag"
Write-Host "  Download page: https://$Owner.github.io/$Repo/"
Start-Process "https://github.com/$Owner/$Repo/actions"
