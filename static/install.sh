#!/bin/sh
# Trawl scanner installer for macOS and Linux.
#
# Run the paired shell install command shown by the Trawl page.
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

if [ -z "${TRAWL_TOKEN:-}" ] || [ -z "${TRAWL_ORIGIN:-}" ]; then
	echo "trawl-scan: pairing details are missing." >&2
	echo "Run the install command shown by the Trawl page." >&2
	exit 1
fi

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
	arm64 | aarch64)
		if [ "$platform" = "linux" ]; then
			echo "trawl-scan: Linux ARM64 is not currently supported." >&2
			echo "No release binary is published for this platform." >&2
			exit 1
		fi
		cpu="aarch64"
		;;
	*)
		echo "trawl-scan: unsupported processor '$arch'." >&2
		exit 1
		;;
esac

asset="trawl-scan-${cpu}-${platform}"
url="https://github.com/${repo}/releases/latest/download/${asset}"
checksum_asset="${asset}.sha256"
checksum_url="https://github.com/${repo}/releases/latest/download/${checksum_asset}"

dir="${HOME}/.trawl/bin"
bin="${dir}/trawl-scan"
mkdir -p "$dir"

temp_bin=""
temp_checksum=""

cleanup() {
	if [ -n "$temp_bin" ]; then
		rm -f -- "$temp_bin"
	fi
	if [ -n "$temp_checksum" ]; then
		rm -f -- "$temp_checksum"
	fi
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

temp_bin="$(mktemp "${dir}/.trawl-scan.XXXXXX")"
temp_checksum="$(mktemp "${dir}/.trawl-scan-checksum.XXXXXX")"

echo "trawl-scan: fetching ${asset}"
if ! curl -fSL "$url" -o "$temp_bin" || ! curl -fSL "$checksum_url" -o "$temp_checksum"; then
	echo "trawl-scan: download failed." >&2
	echo "The release binary or its checksum may not be published for this platform." >&2
	exit 1
fi

checksum_line="$(sed -n '1p' "$temp_checksum")"
expected_hash="${checksum_line%% *}"

case "$expected_hash" in
	'' | *[!0-9a-f]*)
		echo "trawl-scan: checksum verification failed because the checksum file is malformed." >&2
		exit 1
		;;
esac

if [ "${#expected_hash}" -ne 64 ] || ! printf '%s  %s\n' "$expected_hash" "$asset" | cmp -s - "$temp_checksum"; then
	echo "trawl-scan: checksum verification failed because the checksum file is malformed." >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	digest_output="$(sha256sum "$temp_bin")"
elif command -v shasum >/dev/null 2>&1; then
	digest_output="$(shasum -a 256 "$temp_bin")"
else
	echo "trawl-scan: checksum verification requires sha256sum or shasum." >&2
	exit 1
fi

actual_hash="${digest_output%% *}"
if [ "$actual_hash" != "$expected_hash" ]; then
	echo "trawl-scan: checksum verification failed. The downloaded binary was not installed." >&2
	exit 1
fi

chmod +x "$temp_bin"
mv -f "$temp_bin" "$bin"
temp_bin=""
echo "trawl-scan: checksum verified"

cleanup
trap - 0 HUP INT TERM

echo "trawl-scan: starting on http://127.0.0.1:${port}"
echo "trawl-scan: leave this open; the Trawl page will connect on its own."
PORT="$port" exec "$bin"
