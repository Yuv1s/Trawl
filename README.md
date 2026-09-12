![Trawl](src/lib/assets/TrawlBanner.png)

Live at [trawlctf.vercel.app](https://trawlctf.vercel.app).

Drop a file in, or paste a string, and Trawl digs out whatever's hidden inside. Your files stay on your machine. It's built for CTF challenges, where the puzzle is usually a normal-looking image, sound clip, or line of text with something buried inside.

See [ROADMAP.md](ROADMAP.md) for where things stand.

## What it's for

Say a challenge hands you a photo with a password hidden inside—not printed on the image, but written into the pixel values themselves, so staring at it gets you nowhere.

Normally you'd reach for four or five separate tools across three languages, one of them a dead Java applet from 2011. That's fifteen minutes of muscle memory if you've done it before, and the reason you skip the category if you haven't.

Trawl runs those checks from one page and tells you which one hit.

## What it does

### Cuttlefish: File analysis

Upload a PNG, BMP, GIF, WAV, or JPEG and Trawl automatically checks for hidden text, metadata, embedded files, extra data, and anything buried inside the file.

Cuttlefish analyzes images and audio using bit planes, steganography checks, GIF frames, spectrograms, and JPEG data.

### Mantis: Text decoding

Paste encoded or encrypted text into Mantis. It detects and unwraps multiple layers including gzip, zlib, XOR, Caesar, Vigenere, affine, rail fence, transposition, and substitution ciphers.

### Remora: Web analysis

Paste a website link into Remora. It crawls the target, analyzes discovered files, and sends images through Cuttlefish.

An optional advanced mode can also fuzz requests and test JWT weaknesses.

### Cod-end: Results

Everything collects in the Cod-end. It checks possible flag formats, avoids claiming unverified flags, and can generate a Markdown writeup.

## It all runs on your machine

### Private by default

No server, uploads, accounts, or tracking. Once the page loads, file and text analysis can work completely offline. Files are opened read-only and never uploaded.

### Local networking only

Remora is the one part that uses the network because reaching a target site is its job. It still runs locally and only connects to the target you choose.

### Built for speed

Trawl is written in Rust and compiled to WebAssembly. Heavy processing runs in a background thread so the page stays responsive, with no runtime dependencies.

### Accurate image decoding

Trawl decodes images itself instead of relying on the browser, helping preserve tiny pixel-level changes that may contain hidden data.

## Run locally

Requires Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, and Node 20+.

```bash
git clone https://github.com/yuv1s/trawl
cd trawl
npm install
npm run build:wasm
npm run dev
```

## Tests

```bash
npm test                              # interface
cd trawl-core && cargo test           # analysis core
```

Test files are built from scratch by `fixtures/generate.mjs`, so anything the tests claim can be reproduced rather than taken on faith.

There's also a labelled [sample library](static/samples/README.md) with clean PNG, JPEG, and WAV controls next to the planted examples.

## License

[MIT](LICENCE.md)
