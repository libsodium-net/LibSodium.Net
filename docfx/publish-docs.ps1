# publish-docs.ps1
# Run from LibSodium.Net/docfx

$ErrorActionPreference = "Stop"

# Go to root of LibSodium.Net
$root = Resolve-Path $PSScriptRoot
Set-Location $root

Write-Host "🧹 Cleaning previous build artifacts..." -ForegroundColor Cyan
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "./_site", "./api"

Write-Host "📄 Generating metadata..." -ForegroundColor Cyan
docfx metadata
if ($LASTEXITCODE -ne 0 -or $metadata -match "Warning") {
    Write-Host "❌ Errors or warnings during metadata generation. Aborting." -ForegroundColor Red
    Write-Output $metadata
    exit 1
}

Write-Host "🏗 Building site..." -ForegroundColor Cyan
docfx build
if ($LASTEXITCODE -ne 0 -or $build -match "Warning") {
    Write-Host "❌ Errors or warnings during site build. Aborting." -ForegroundColor Red
    exit 1
}

# Set path to GitHub Pages repo
$ghPagesPath = Resolve-Path "$root/../../LibSodium-Net.github.io"
$docsPath = Join-Path $ghPagesPath "docs"

if (-Not (Test-Path $ghPagesPath)) {
    Write-Host "❌ GitHub Pages repo not found at $ghPagesPath" -ForegroundColor Red
    exit 1
}

Write-Host "🧹 Cleaning docs directory in GitHub Pages repo..." -ForegroundColor Cyan
Get-ChildItem -Path $docsPath -Exclude "CNAME" | Remove-Item -Recurse -Force

Write-Host "📁 Copying generated site to GitHub Pages repo..." -ForegroundColor Cyan
Copy-Item -Path "./_site/*" -Destination $docsPath -Recurse

# Commit and push
Write-Host "📦 Committing and pushing to GitHub Pages repo..." -ForegroundColor Cyan
Push-Location $ghPagesPath

git add docs
$commitMessage = "Update docs site - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
git commit -m $commitMessage
git push

Pop-Location

Write-Host "✅ Documentation published successfully!" -ForegroundColor Green
