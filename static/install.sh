#!/bin/sh
# Trawl scanner installer for macOS and Linux.
#
#   curl -fsSL https://<your-trawl-site>/install.sh | sh
#
# It downloads the prebuilt trawl-scan binary for this machine and starts it.
# No repository, no Rust, no build. The binary listens on http://127.0.0.1:8099,
# which is where the Trawl page looks for it. Leave the terminal open; the page
# connects on its own.
#
# It installs into your home directory and needs no root. The whole thing is
# short on purpose: read it before you run it.
set -eu

repo="Yuv1s/Trawl"
port="${PORT:-8099}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
	Linux) platform="linux" ;;
	Darwin) platform="macos" ;;
	*)
		echo "trawl-scan: unsupported system '$os'." >&2
		echo "On Windows, use the PowerShell command instead." >&2
		exit 1
		;;
esac

case "$arch" in
	x86_64 | amd64) cpu="x86_64" ;;
	arm64 | aarch64) cpu="aarch64" ;;
	*)
		echo "trawl-scan: unsupported processor '$arch'." >&2
		exit 1
		;;
esac

asset="trawl-scan-${cpu}-${platform}"
url="https://github.com/${repo}/releases/latest/download/${asset}"

dir="${HOME}/.trawl/bin"
bin="${dir}/trawl-scan"
mkdir -p "$dir"

echo "trawl-scan: fetching ${asset}"
if ! curl -fSL "$url" -o "$bin"; then
	echo "trawl-scan: download failed." >&2
	echo "There may be no release published yet for this platform." >&2
	exit 1
fi
chmod +x "$bin"

echo "trawl-scan: starting on http://127.0.0.1:${port}"
echo "trawl-scan: leave this open; the Trawl page will connect on its own."
PORT="$port" exec "$bin"
