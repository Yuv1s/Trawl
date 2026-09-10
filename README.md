![Trawl](src/lib/assets/TrawlBanner.png)

Live at [trawlctf.vercel.app](https://trawlctf.vercel.app).

Drop a file in, or paste a string, and Trawl digs out whatever's hidden inside. Nothing leaves your machine. It's built for CTF challenges, where the puzzle is usually a normal-looking image, a sound clip, or a line of text with something buried in it. See [ROADMAP.md](ROADMAP.md) for where things stand.

## What it's for

Say a challenge hands you a photo with a password hidden inside, not printed on the image but written into the pixel values themselves, so staring at it gets you nowhere. Normally you'd reach for four or five separate tools across three languages, one of them a dead Java applet from 2011, which is fifteen minutes of muscle memory if you've done it before and the reason you skip the category if you haven't. Trawl runs those same checks from one page and tells you which one hit.

## What it does

Feed it a PNG, BMP, GIF, WAV or JPEG and it runs everything that fits, reading what the file says about itself (hidden text, metadata, files stuffed inside, anything tacked onto the end where no viewer looks), popping buried files out with one click and running anything inside a ZIP or carved from the middle through the same checks a few layers deep. Cuttlefish takes the pixels apart, laying out every bit plane at once and trying up to 84 ways of reading hidden bits, with a spectrogram for audio, frame-by-frame reading for animated GIFs, and JPEG coefficients read directly where the payloads sit. Paste a string and Mantis works out what's been done to it and peels it back a layer at a time, inflating gzip or zlib and, when the thing is encrypted rather than encoded, attacking XOR, Caesar, Vigenère, affine, rail fence, columnar transposition and substitution with each recovering its own key; when nothing cracks it lays out every rotation with the likely ones up top so you can finish by eye, and it never guesses. Paste a link and Remora, which you start locally from one line the page hands you, crawls the site into the same things Trawl already reads and throws any image at Cuttlefish, with a second mode you have to affirm that fuzzes requests and forges a JWT when the signing key leaks. Everything collects in the Cod-end up top, which matches the flag shapes you give it, never claims a flag it hasn't actually checked, and hands back a Markdown writeup on request.

## It all runs on your machine

No server, no upload, no account, nothing tracked: once the page loads it works with the network unplugged, your file is opened read-only, and since most competitions ban handing challenge files to outside services, Trawl has nowhere to send yours (Remora is the one part that touches the network, because reaching a site is the point, but it still runs locally and talks only to the target you named and your own browser). Under the hood it's Rust compiled to WebAssembly on a background thread so the page stays responsive, with no runtime dependencies in `package.json` or the Rust core and every parser, decoder and attack written from scratch. Worth knowing: you can't trust the browser's own image decoder, which quietly flips the lowest bit on about a fifth of the pixels in any image with transparency, exactly the data you're hunting, so Trawl decodes images itself.

## Running it locally

Needs Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, and Node 20+.

```bash
git clone https://github.com/yuv1s/trawl
cd trawl
npm install
npm run build:wasm
npm run dev
```

Tests:

```bash
npm test                              # the interface
cd trawl-core && cargo test           # the analysis core
```

Test files get built from scratch by `fixtures/generate.mjs`, so anything the tests claim you can reproduce rather than take on faith, and there's a labelled [sample library](static/samples/README.md) with clean PNG, JPEG and WAV controls next to the planted ones.

## Licence

MIT.
