# Trawl

Browser toolkit for finding hidden data in CTF files, text and web pages.

![Trawl](src/lib/assets/TrawlBanner.png)

**Try it:** [trawlctf.vercel.app](https://trawlctf.vercel.app)

Drop in a file or some text and Trawl performs all the checks which otherwise would have required several separate tools.

Your files are always local.

## Quick start

Open [trawlctf.vercel.app](https://trawlctf.vercel.app) and:

1. Drop in a file, paste some text or provide a target URL.
2. Wait while Trawl performs the appropriate checks.
3. Look at the result in the Cod-end.

No setup or account is required for the hosted version.

## Why Trawl exists

A challenge in a CTF can give you an ordinary looking image, containing a password inside its pixels.

Looking at the image won't help much. You may need to examine metadata, extract bit planes, check for additional data, use various stegano tools or decode something using several decoders.

Which usually involves jumping between various separate tools.

Trawl puts all these checks into a single interface and shows you which of them produce useful results.

## Features

* Analysis of PNG, BMP, GIF, WAV, and JPEG files
* Searching for hidden text, metadata, embedded files and appended data
* Inspection of image bit planes, GIF frames, spectrograms and JPEG data
* Detection and unwrapping of several layers of encoded or encrypted text
* Crawling of websites and analysis of discovered files
* Checking of possible flag formats without guessing unverified results as flags
* Markdown writeup generation based on results

## Cuttlefish

Cuttlefish deals with file analysis.

Drop in a PNG, BMP, GIF, WAV or a JPEG file and Cuttlefish automatically analyses it for hidden text, metadata, embedded files, extra data, and anything else hidden within.

For images and audio it analyses:

* Bit planes
* Steganographic patterns
* GIF frames
* Spectrograms
* JPEG data

## Mantis

Mantis deals with text decoding.

Paste some encoded or encrypted text and Mantis tries to detect and unwrap several layers of encoding/encryption.

Currently supported methods:

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

Remora deals with web analysis.

Paste a website URL and Remora crawls the target site, analyses discovered files and passes images to Cuttlefish.

There is an optional advanced mode with web fuzzing and testing of JWT tokens vulnerabilities.

Because Remora requires web access to analyse the target, this is the part of Trawl that actually uses the network.

It only makes connections to the target you select.

## Cod-end

Analysis results from different tools are collected in the Cod-end.

It analyses possible flag formats, avoids guessing unverified results as flags and allows to generate markdown writeup of the results.

## Local by default

File and text analysis in Trawl does not require server, file uploads, user accounts or any kind of tracking.

Once the app is loaded in the browser, file and text analysis can happen completely offline. Files are opened in a read-only mode and are not uploaded anywhere for analysis.

Remora is an exception because it requires web access for analysis.

## How it works

Trawl's analysis core is implemented in Rust and compiled to WebAssembly.

Processing is done in a background thread to avoid blocking the interface. Browser handles the app without requiring any additional runtimes for the analysis core.

Trawl also decodes images manually, which is useful in preserving small pixel level changes containing hidden data.

## Run locally

Dependencies:

* Rust
* `wasm32-unknown-unknown` target
* `wasm-pack`
* Node 20+

Clone the repo and start the development server:

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

Test files are generated from scratch by `fixtures/generate.mjs`, thus allowing to reproduce planted data used in tests.

The repo also contains a labelled [samples library](static/samples/README.md) with clean PNG, JPEG and WAV controls and planted samples.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for current status and future plans.

## Licence

[MIT](LICENCE.md)
