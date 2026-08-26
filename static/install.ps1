# Trawl scanner installer for Windows.
#
# Run the paired PowerShell install command shown by the Trawl page.
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

if ([string]::IsNullOrWhiteSpace($env:TRAWL_TOKEN) -or [string]::IsNullOrWhiteSpace($env:TRAWL_ORIGIN)) {
	Write-Error 'trawl-scan: pairing details are missing. Run the install command shown by the Trawl page.'
	return
}

if (-not [Environment]::Is64BitOperatingSystem) {
	Write-Error 'trawl-scan: 32-bit Windows is not supported.'
	return
}

$architecture = if ($env:PROCESSOR_ARCHITEW6432) {
	$env:PROCESSOR_ARCHITEW6432
}
else {
	$env:PROCESSOR_ARCHITECTURE
}

if ($architecture -eq 'ARM64') {
	Write-Error 'trawl-scan: Windows ARM64 is not currently supported. No release binary is published for this platform.'
	return
}

if ($architecture -ne 'AMD64') {
	Write-Error "trawl-scan: unsupported Windows processor '$architecture'."
	return
}

$asset = 'trawl-scan-x86_64-windows.exe'
$url = "https://github.com/$repo/releases/latest/download/$asset"
$checksumAsset = "$asset.sha256"
$checksumUrl = "https://github.com/$repo/releases/latest/download/$checksumAsset"

$dir = Join-Path $env:LOCALAPPDATA 'trawl'
$bin = Join-Path $dir 'trawl-scan.exe'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$nonce = [Guid]::NewGuid().ToString('N')
$tempBin = Join-Path $dir ".$asset.$nonce.tmp"
$tempChecksum = Join-Path $dir ".$checksumAsset.$nonce.tmp"

try {
	Write-Host "trawl-scan: fetching $asset"
	try {
		Invoke-WebRequest -Uri $url -OutFile $tempBin
		Invoke-WebRequest -Uri $checksumUrl -OutFile $tempChecksum
	}
	catch {
		throw 'trawl-scan: download failed. The release binary or its checksum may not be published for this platform.'
	}

	$manifest = [IO.File]::ReadAllText($tempChecksum)
	$manifestPattern = '\A(?<hash>[0-9a-f]{64})  ' + [regex]::Escape($asset) + "\r?\n\z"
	$manifestMatch = [regex]::Match($manifest, $manifestPattern)
	if (-not $manifestMatch.Success) {
		throw 'trawl-scan: checksum verification failed because the checksum file is malformed.'
	}

	$expectedHash = $manifestMatch.Groups['hash'].Value
	$actualHash = (Get-FileHash -LiteralPath $tempBin -Algorithm SHA256).Hash.ToLowerInvariant()
	if (-not [string]::Equals($expectedHash, $actualHash, [StringComparison]::Ordinal)) {
		throw 'trawl-scan: checksum verification failed. The downloaded binary was not installed.'
	}

	Move-Item -LiteralPath $tempBin -Destination $bin -Force
	Write-Host 'trawl-scan: checksum verified'
}
finally {
	Remove-Item -LiteralPath $tempBin -Force -ErrorAction SilentlyContinue
	Remove-Item -LiteralPath $tempChecksum -Force -ErrorAction SilentlyContinue
}

Write-Host "trawl-scan: starting on http://127.0.0.1:$port"
Write-Host "trawl-scan: leave this window open; the Trawl page will connect on its own."
$env:PORT = $port
& $bin
