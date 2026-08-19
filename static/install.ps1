# Trawl scanner installer for Windows.
#
#   irm https://<your-trawl-site>/install.ps1 | iex
#
# It downloads the prebuilt trawl-scan binary for this machine and starts it.
# No repository, no Rust, no build. The binary listens on http://127.0.0.1:8099,
# which is where the Trawl page looks for it. Leave this window open; the page
# connects on its own.
#
# It installs under your local app data and needs no administrator. The whole
# thing is short on purpose: read it before you run it.
$ErrorActionPreference = 'Stop'

$repo = 'Yuv1s/Trawl'
$port = if ($env:PORT) { $env:PORT } else { '8099' }

if (-not [Environment]::Is64BitOperatingSystem) {
	Write-Error 'trawl-scan: 32-bit Windows is not supported.'
	return
}

$cpu = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
$asset = "trawl-scan-$cpu-windows.exe"
$url = "https://github.com/$repo/releases/latest/download/$asset"

$dir = Join-Path $env:LOCALAPPDATA 'trawl'
$bin = Join-Path $dir 'trawl-scan.exe'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Write-Host "trawl-scan: fetching $asset"
try {
	Invoke-WebRequest -Uri $url -OutFile $bin
}
catch {
	Write-Error "trawl-scan: download failed. There may be no release published yet for this platform."
	return
}

Write-Host "trawl-scan: starting on http://127.0.0.1:$port"
Write-Host "trawl-scan: leave this window open; the Trawl page will connect on its own."
$env:PORT = $port
& $bin
