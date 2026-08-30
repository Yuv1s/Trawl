#!/usr/bin/env bash
# Vercel has Node but no Rust; the analysis core is Rust compiled to WebAssembly,
# so install the toolchain here before the documented `npm run build`. Versions
# track .github/workflows/ci.yml so CI and a deploy build the same bytes.
set -euo pipefail

CARGO_BIN="$HOME/.cargo/bin"
export PATH="$CARGO_BIN:$PATH"

RUST_VERSION=1.98.0
WASM_PACK_VERSION=0.15.0

if ! command -v rustup >/dev/null 2>&1; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
		| sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
fi
rustup target add wasm32-unknown-unknown

# Prefer the published binary; fall back to building wasm-pack from source if the
# release asset is ever unreachable, so a deploy never hangs on one download.
if ! command -v wasm-pack >/dev/null 2>&1; then
	asset="wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl"
	url="https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${asset}.tar.gz"
	if curl -sSfL "$url" -o /tmp/wasm-pack.tar.gz; then
		tar -xzf /tmp/wasm-pack.tar.gz -C /tmp
		install -m 0755 "/tmp/${asset}/wasm-pack" "$CARGO_BIN/wasm-pack"
	else
		cargo install wasm-pack --locked --version "$WASM_PACK_VERSION"
	fi
fi

npm run build
