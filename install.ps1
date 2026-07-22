# RS-Guard installer for Windows.
# Honest scope: builds the `rs-guard` CLI from source with cargo (no
# code-signed prebuilt binary yet) and installs it to
# $env:LOCALAPPDATA\rs-guard\bin. This tool does not replace your antivirus
# -- it runs alongside it (a repo/dependency pattern scanner, plus an
# optional ClamAV wrapper if ClamAV is separately installed). Requires git
# and a Rust toolchain (installs rustup automatically if missing, via
# winget if available, otherwise prompts the user to install manually).

$ErrorActionPreference = "Stop"

$InstallDir = if ($env:RS_GUARD_HOME) { $env:RS_GUARD_HOME } else { Join-Path $env:LOCALAPPDATA "rs-guard" }
$BinDir = Join-Path $InstallDir "bin"
$RepoUrl = "https://github.com/aon-co-jp/RS-Guard.git"

Write-Host "== RS-Guard installer (Windows) =="

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Rust toolchain not found."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Installing via winget (Rustlang.Rustup)..."
        winget install --id Rustlang.Rustup -e --source winget
    } else {
        Write-Host "Please install Rust manually from https://rustup.rs and re-run this script."
        exit 1
    }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "git is required but was not found on PATH. Install Git for Windows first: https://git-scm.com/download/win"
    exit 1
}

if (-not (Test-Path $InstallDir)) {
    git clone $RepoUrl $InstallDir
} else {
    Write-Host "Existing install found at $InstallDir, pulling latest..."
    git -C $InstallDir pull --ff-only
}

Set-Location $InstallDir
cargo build --release

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Copy-Item (Join-Path $InstallDir "target\release\rs-guard.exe") (Join-Path $BinDir "rs-guard.exe") -Force

Write-Host ""
Write-Host "Installed: $(Join-Path $BinDir 'rs-guard.exe')"
if (($env:Path -split ";") -notcontains $BinDir) {
    Write-Host "Note: $BinDir is not on your PATH. Add it, e.g.:"
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$BinDir', 'User')"
}

Write-Host ""
Write-Host "Checking for ClamAV (optional, used by 'rs-guard scan-file')..."
& (Join-Path $BinDir "rs-guard.exe") doctor

Write-Host ""
Write-Host "Usage:"
Write-Host "  rs-guard scan-repos C:\path\to\your\repos   # dependency-name + suspicious-script scan"
Write-Host "  rs-guard scan-file C:\path\to\file-or-dir   # delegates to ClamAV if installed"
Write-Host "  rs-guard doctor                             # check ClamAV availability"
