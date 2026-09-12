# Trawl

A browser-based toolkit for finding hidden data in CTF files, text, and websites.

![Trawl](src/lib/assets/TrawlBanner.png)

**Try it:** [trawlctf.vercel.app](https://trawlctf.vercel.app)

Drop in a file or paste a string and Trawl runs the checks you would normally need several separate tools for.

Your files stay on your machine.

## Quick start

Open [trawlctf.vercel.app](https://trawlctf.vercel.app), then:

1. Drop in a file, paste some text, or enter a target URL.
2. Let Trawl run the relevant checks.
3. Review everything it finds in the Cod-end.

No installation or account is required for the hosted version.

## Why Trawl exists

A CTF challenge might give you a normal-looking image with a password hidden inside its pixel values.

Looking at the image will not help. You might need to inspect metadata, extract bit planes, check for appended data, run steganography tools, or try several decoders before finding anything useful.

That usually means jumping between a collection of unrelated tools.

Trawl puts those checks in one interface and shows you which ones produced useful results.

## Features

* Analyze PNG, BMP, GIF, WAV, and JPEG files
* Search for hidden text, metadata, embedded files, and appended data
* Inspect image bit planes, GIF frames, spectrograms, and JPEG data
* Detect and unwrap multiple layers of encoded or encrypted text
* Crawl websites and analyze discovered files
* Check possible flag formats without presenting unverified guesses as flags
* Generate a Markdown writeup from the results

## Cuttlefish

Cuttlefish handles file analysis.

Upload a PNG, BMP, GIF, WAV, or JPEG and it automatically checks the file for hidden text, metadata, embedded files, extra data, and other content that may not be visible normally.

For images and audio, Cuttlefish can inspect:

* Bit planes
* Steganography patterns
* GIF frames
* Spectrograms
* JPEG data

## Mantis

Mantis handles text decoding.

Paste encoded or encrypted text and it attempts to detect and unwrap multiple layers.

Supported techniques include:

* gzip
* zlib
* XOR
* Caesar
* Vigenere
* affine
* rail fence
* transposition
* substitution ciphers

## Remora

Remora handles web analysis.

Paste in a website URL and Remora crawls the target, analyzes discovered files, and sends discovered images through Cuttlefish.

An optional advanced mode can also fuzz requests and test JWT weaknesses.

Because Remora needs to reach the target website, it is the part of Trawl that uses the network.

It only connects to the target you choose.

## Cod-end

Results from the different tools collect in the Cod-end.

It checks possible flag formats, avoids presenting unverified results as confirmed flags, and can generate a Markdown writeup of what was found.

## Local by default

Trawl does not require a server, uploads, accounts, or tracking for file and text analysis.

Once the page has loaded, those parts can work completely offline. Files are opened read-only and are not uploaded for analysis.

Remora is the exception because web analysis requires network access.

## How it works

Trawl's analysis core is written in Rust and compiled to WebAssembly.

Heavy processing runs in a background thread so analysis does not block the interface. The browser handles the application without requiring runtime dependencies for the analysis core.

Trawl also decodes images itself instead of depending entirely on browser image decoding. This helps preserve small pixel-level changes that may contain hidden data.

## Run locally

Requirements:

* Rust
* `wasm32-unknown-unknown` target
* `wasm-pack`
* Node 20+

Clone the repository and start the development server:

```bash
git clone https://github.com/yuv1s/trawl
cd trawl
npm install
npm run build:wasm
npm run dev
```

## Tests

Run the interface tests:

```bash
npm test
```

Run the Rust analysis-core tests:

```bash
cd trawl-core && cargo test
```

Test files are generated from scratch by `fixtures/generate.mjs`, so the planted data used by the tests can be reproduced.

The repository also includes a labelled [sample library](static/samples/README.md) with clean PNG, JPEG, and WAV controls alongside planted examples.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for current progress and planned work.

## License

[MIT](LICENCE.md)
