# Build a self-contained Windows installer for Mac2Win Receiver.
#
# Prerequisites (run on Windows):
#   - .NET SDK 10.0.x
#   - Inno Setup 6 (iscc.exe on PATH)  -- not available on this workstation
#   - code-signing cert (optional; unsigned if absent)
#
# Usage:
#   .\win-receiver\installer\publish-windows.ps1
#
# Produces: win-receiver/installer/Output/Mac2WinReceiver-Setup-0.1.0.exe

$ErrorActionPreference = "Stop"
$env:Path = "C:\Program Files\dotnet;$env:Path"
$root = Resolve-Path "."
$publishDir = "$root\win-receiver\App\bin\Release\net10.0-windows\win-x64\publish"
$iss = "$root\win-receiver\installer\Mac2WinReceiver.iss"
$outDir = "$root\win-receiver\installer\Output"

Write-Host "==> Publishing self-contained win-x64 app ..." -ForegroundColor Cyan
dotnet publish "$root\win-receiver\App\Mac2WinReceiver.App.csproj" `
    -c Release -r win-x64 --self-contained `
    /p:PublishSingleFile=false /p:PublishTrimmed=false

if (-not (Test-Path "$publishDir\Mac2WinReceiver.App.exe")) {
    throw "Publish output missing: $publishDir\Mac2WinReceiver.App.exe"
}
Write-Host "==> Publish OK: $(Get-Item "$publishDir\Mac2WinReceiver.App.exe").Length bytes" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

if (Get-Command iscc -ErrorAction SilentlyContinue) {
    Write-Host "==> Building Inno Setup installer ..." -ForegroundColor Cyan
    & iscc "$iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
    Write-Host "==> Installer built in $outDir" -ForegroundColor Green
} else {
    Write-Host "==> iscc not found — skipping installer build." -ForegroundColor Yellow
    Write-Host "    Install Inno Setup 6 and re-run to produce Mac2WinReceiver-Setup-0.1.0.exe" -ForegroundColor Yellow
    Write-Host "    App binaries are ready at: $publishDir" -ForegroundColor Green
}

Write-Host "==> To sign (optional):" -ForegroundColor Cyan
Write-Host "    signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com `"$outDir\Mac2WinReceiver-Setup-0.1.0.exe`"" -ForegroundColor Gray
