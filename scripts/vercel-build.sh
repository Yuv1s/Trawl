#!/usr/bin/env bash
# Vercel's image ships Node and (usually) rustup, but no wasm-pack, and its
# default Rust may differ from CI. The analysis core is Rust compiled to
# WebAssembly, so pin the toolchain and add wasm-pack here before the documented
# `npm run build`. Versions track .github/workflows/ci.yml so CI and a deploy
# build the same bytes.
set -euo pipefail

RUST_VERSION=1.98.0
WASM_PACK_VERSION=0.15.0
WASM_PACK_SHA256=c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a

# A bin dir we know we can create and that the build's child processes inherit.
# The image's own cargo home may live somewhere read-only, so never assume it.
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
export PATH="$HOME/.cargo/bin:$BIN_DIR:$PATH"
export CARGO_INSTALL_ROOT="$HOME/.local"

# rustup is preinstalled on Vercel; install it only if the image lacks it.
if ! command -v rustup >/dev/null 2>&1; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
		| sh -s -- -y --profile minimal --default-toolchain none
fi

# Pin CI's toolchain with the wasm target, without touching the image's global
# default: RUSTUP_TOOLCHAIN makes every cargo/rustc call in this build use it.
export RUSTUP_TOOLCHAIN="$RUST_VERSION"
rustup toolchain install "$RUST_VERSION" --profile minimal --target wasm32-unknown-unknown

# wasm-pack: prefer the published binary, build from source only if unreachable,
# so a deploy never hangs on one download.
if ! command -v wasm-pack >/dev/null 2>&1; then
	asset="wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl"
	url="https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${asset}.tar.gz"
	tarball="$(mktemp)"
	unpacked="$(mktemp -d)"
	if curl -sSfL "$url" -o "$tarball"; then
		# This builds the site that serves the install scripts, so a tampered tool stops here.
		printf '%s  %s\n' "$WASM_PACK_SHA256" "$tarball" | sha256sum -c -
		tar -xzf "$tarball" -C "$unpacked"
		install -m 0755 "$unpacked/${asset}/wasm-pack" "$BIN_DIR/wasm-pack"
	else
		cargo install wasm-pack --locked --version "$WASM_PACK_VERSION"
	fi
fi

npm run build
