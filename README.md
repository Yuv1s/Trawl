# Trawl

A local toolkit for the file-based CTF categories: steganography, cryptography, and forensics. Drop
a file or paste a string, and every relevant check runs in your browser. Nothing is uploaded.

> **Status: in development.** This document describes what Trawl is being built to do. See the
> [roadmap](#roadmap) for what currently works.

---

## The problem

When a competition hands you a suspicious PNG, the real workflow looks like this:

```
$ exiftool chal.png          # metadata
$ strings chal.png | less    # eyeball for flags
$ binwalk chal.png           # appended files
$ zsteg -a chal.png          # brute-force LSB parameters
$ steghide extract -sf ...   # if it's JPEG and passworded
$ java -jar stegsolve.jar    # bit planes, in a 2011 Java applet
```

Six tools, five interfaces, three languages, and every one has to be installed first. zsteg is Ruby
and only reads PNG and BMP. StegSolve is an unmaintained Java applet. binwalk returns a wall of
false positives. None of them talk to each other, and none of them tell you where to look first.

Crypto is the same story with different names. CyberChef in one tab, a Python REPL with
pycryptodome in another, RsaCtfTool in a third, and whatever substitution solver you bookmarked two
years ago.

For an experienced player that is fifteen minutes of muscle memory. For a beginner it is the reason
they skip forensics and crypto entirely, because they do not know the tools exist, let alone which
one to reach for.

Trawl runs all of it from one page, on files that stay on your machine.

## Why not upload it to an AI

The model never receives your file. It receives a small resampled copy of the picture, and in a
steganography challenge the answer is not in the picture. It is in the bytes.

### What upload does to your image

Every vision model runs the same preprocessing before any part of the network sees anything.

1. **Decode.** Your PNG is inflated and unfiltered into a raster. The container is discarded here,
   along with appended ZIPs, `tEXt` chunks, and anything sitting after `IEND`.
2. **Resample.** The raster is scaled to fit the model's input budget. Each output pixel becomes a
   weighted average of several input pixels. Averaging neighboring values does not preserve the low
   bit of any of them, so an LSB payload does not survive this step.
3. **Normalize.** Values become floats and are rescaled. Bit planes are only meaningful on integers,
   so they stop existing here.
4. **Patch and project.** The result is cut into a grid of patches, and each patch is flattened and
   multiplied into a single embedding vector.

Step 4 holds even if you defeat the first three. Hand the model a native-resolution image with no
resizing, and the patch projection still collapses hundreds of subpixel values into one vector of a
few hundred dimensions. That operation has no inverse. Nothing downstream can ask for bit 0 of the
blue channel at pixel (417, 92), because that number was never encoded.

The model is not refusing to check the bit plane. There is no mechanism by which it could.

### The arithmetic

A 12-megapixel PNG holds 36 million least significant bits, which is roughly 4.5 MB of hiding
capacity. Here is what survives the trip.

| Per analysis                | Trawl                | Upload to a vision model     |
| --------------------------- | -------------------- | ---------------------------- |
| LSBs the analysis can read  | 36,000,000           | 0                            |
| Tokens spent                | 0                    | ~1,500                       |
| Bytes sent over the network | 0                    | the whole file               |
| Original file preserved     | Exact, byte for byte | Resampled before first layer |
| Cost to run it again        | 0                    | Billed again, every time     |

The token figure comes from published tiling formulas. A 12-megapixel image is scaled to about one
megapixel and split into a few thousand patches. Those tokens are not a compressed encoding of the
36 million bits. Step 2 averaged the bits away, and no amount of prompting recovers them from what
is left.

Ask anyway and you get one of two answers. Either an honest "I can't extract that", or a confident,
well-formatted, invented flag. Under a competition clock the second one costs you real time.

### The caveat people will raise

An assistant with code execution can bypass its own vision pipeline, write a script, and read the
bytes directly. That works, and it is worth being straight about it.

What it produces is a fresh implementation on every run, written by a process that cannot check its
own work. A first attempt that sweeps only one bit per channel returns a clean, confident nothing on
a file that does have a payload, and that failure looks identical to a correct negative. Silence
from an untested decoder tells you the script found nothing, which is a much weaker claim than the
file being clean.

Trawl's detectors are fixed, tested against fixtures with known embedding rates, and asserted not to
fire on clean inputs. When it reports 25 percent sequential LSB embedding, that number comes from a
chi-square test whose source you can read and whose fixtures you can regenerate. When it reports
nothing, the negative has been tested too.

### Everything runs on your machine

There is no backend. No upload endpoint, no API key, no account, no telemetry. Analysis runs in a
Web Worker against a Rust core compiled to WebAssembly, so the arithmetic runs at native speed in
your tab with nothing to wait on but your own CPU. After the first load it works with the network
cable pulled.

Files are opened read-only and never modified.

That also settles a rules question. Most competitions restrict redistributing challenge files
outside the event, and uploading one to a third-party API is arguably exactly that. Trawl has
nowhere to send it.

|                                      | Trawl | Chat upload (no code execution) | zsteg / StegSolve / binwalk |
| ------------------------------------ | ----- | ------------------------------- | --------------------------- |
| Reads least significant bits         | Yes   | No, destroyed in preprocessing  | Yes                         |
| Deterministic and reproducible       | Yes   | No                              | Yes                         |
| Tested false-positive rate           | Yes   | No                              | Varies                      |
| File leaves your machine             | Never | Every time                      | Never                       |
| Tokens and cost per run              | None  | Billed on every re-run          | None                        |
| Tools to install                     | None  | None                            | Four, in three languages    |
| Works offline                        | Yes   | No                              | Yes                         |
| Explains what it found and why       | Yes   | Yes                             | Not really                  |
| One interface for the whole workflow | Yes   | Yes                             | No                          |

An assistant _with_ code execution is the different case covered above. It can read the bytes, but
each run is a new untested implementation.

## What Trawl does

### Steganography

The steganography module is called Cuttlefish, and it is the part furthest along.

Container analysis reads raw bytes and does not depend on decoding the image at all. It scans the
entire buffer for file signatures instead of only offset zero, flags data sitting after PNG `IEND`,
JPEG `FFD9`, and the ZIP end-of-central-directory record, walks PNG chunks with `tEXt`, `zTXt` and
`iTXt` decoded, walks JPEG `COM` and `APPn` segments, plots Shannon entropy over a sliding window so
an appended compressed blob shows up as a high-entropy tail, extracts ASCII and UTF-16LE strings,
and parses EXIF through a hand-written IFD walker.

Pixel analysis renders all 8 bit planes across every channel at once, so an anomalous plane stands
out from a field of noise without you having to guess which one to open first. The LSB parameter
sweep covers channel order, bit order, bit plane, and traversal direction, which is `zsteg -a` with
the results laid out visually.

Steganalysis is statistical rather than pattern matching. The chi-square attack (Westfeld and
Pfitzmann, 1999) uses the fact that sequential LSB embedding equalizes the frequencies of pairs of
values. Run over increasing prefixes of the image, the point where embedding stops appears as a
cliff, which also estimates payload length. RS analysis (Fridrich, Goljan and Du, 2001) classifies
pixel groups under flipping masks and estimates the embedding rate instead of answering yes or no.

### Cryptography

Paste a string and Trawl works out what it is before you have to.

Encoding chains are detected and peeled automatically, covering base64, base32, base85, hex, URL,
HTML entities, ROT47, morse, and binary, applied repeatedly until the output stops looking encoded.

Classical ciphers get solved rather than merely applied. Caesar and ROT-N are scored across all
shifts against English quadgram frequencies. Vigenère key length comes from index of coincidence and
Kasiski examination, and then each column is solved independently. Simple substitution is attacked
by hill climbing against the same quadgram model. XOR handles single byte and repeating key, with
key length recovered through normalized Hamming distance.

RSA covers the weaknesses that actually show up in competition: small public exponent with an
integer cube root, shared factors between two moduli found by GCD, Fermat factorization when the
primes sit too close together, and Wiener's attack when d is small. All of it runs on native BigInt.

Hash identification works from length and alphabet. SHA-1 through SHA-512 come from SubtleCrypto.

### Forensics

File carving scans for signatures across the whole buffer and extracts what it finds, instead of
printing an offset and leaving you to `dd` it out.

ZIP archives get a central directory walk that reports encrypted entries, size mismatches, and
comment fields. PDFs get an object and stream walk.

Windows registry hives are parsed by a hand-written reader aimed at USB device artifacts: `USBSTOR`
entries, mounted device GUIDs, and the timestamps that place a specific device on a specific machine
at a specific time.

### How results are presented

One drop runs everything. Detectors fire in parallel and results stream in as they finish.

When an extraction produces something that verifies itself, Trawl puts the answer at the top.
Printable ASCII above a length threshold, a match against common flag formats, or a valid file
signature all count as verification.

When nothing verifies, you get ranked findings instead of a guess. Each finding states what was
measured and what it means, sorted by how suspicious it is, with routine results collapsed.
"Chi-square indicates sequential LSB embedding in the first 34 percent of the image" belongs at the
top. "File has an sRGB chunk" belongs at the bottom, collapsed.

Trawl never asserts a flag it cannot verify. An empty result says what was checked and found clean.

## How it works

The analysis core is Rust compiled to WebAssembly, running in a Web Worker so the interface stays
responsive while a sweep runs. RS analysis over a 12-megapixel image is on the order of 100 million
pixel group evaluations, and the LSB sweep multiplies that across dozens of parameter combinations.
This is genuine compute, not a stylistic choice.

### Zero runtime dependencies

`package.json` lists no runtime dependencies, and neither does the Rust core. Every detector, cipher
attack, and parser in this repository was written for this project.

The browser supplies the plumbing, and platform APIs are not packages:

- `ArrayBuffer` for raw bytes
- `createImageBitmap` with `colorSpaceConversion` and `premultiplyAlpha` both set to `none`, so pixel
  values arrive unmodified
- `DecompressionStream` for inflate
- `SubtleCrypto` for SHA
- `BigInt` for RSA arithmetic

Calling `DecompressionStream` is no more a dependency than calling `Math.sqrt`. There is no
steganography package, no image library, no EXIF library, no crypto library, and no CyberChef.

### Pixel fidelity

Canvas `getImageData` quietly corrupts low bits through color management and alpha premultiplication,
which for this tool destroys exactly the data being looked for. Trawl decodes through
`createImageBitmap` with both conversions disabled, and the test suite round-trips a PNG carrying a
known bit pattern to prove the bits survive the decode path.

## What Trawl will not do

No accounts, no cloud storage, no history, no sharing, no CLI.

No pwn or web categories. Both need a live remote target, and a static page in a browser is the
wrong shape for either one.

No password cracking against steghide or encrypted archives. Wordlist attacks belong on hardware you
control, running something built for it.

Nothing is written back to your file.

## Running locally

Requires Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, and Node 20 or newer.

```bash
git clone https://github.com/yuv1s/trawl
cd trawl
npm install
npm run build:wasm
npm run dev
```

Rust tests, including the steganalysis fixtures:

```bash
cd trawl-core && cargo test --release
```

Fixtures are produced by a generator script in `/fixtures`, so every detection result in the test
suite can be reproduced from scratch.

## Roadmap

Steganography:

- [ ] Container analysis: magic bytes, trailing data, PNG and JPEG walkers, entropy, strings, EXIF
- [ ] Bit-plane wall and LSB parameter sweep
- [ ] Chi-square attack with prefix sweep
- [ ] RS analysis
- [ ] Ranked triage panel
- [ ] WAV support: LSB extraction and FFT spectrogram
- [ ] JPEG DCT analysis for JSteg and F5

Cryptography:

- [ ] Encoding chain detection and automatic peeling
- [ ] Classical cipher solvers with quadgram scoring
- [ ] XOR key recovery
- [ ] RSA attack set
- [ ] Hash identification

Forensics:

- [ ] File carving and extraction
- [ ] ZIP and PDF structure walkers
- [ ] Registry hive parser for USB artifacts

## Naming

Trawling means dragging a net through a volume of water and sorting whatever comes up, which is
close to what this does with a dropped file.

The steganography module is called Cuttlefish because cuttlefish hide by rewriting their own
surface, which is what LSB embedding does to an image. Their ink is also where sepia comes from,
since the pigment is named after _Sepia officinalis_.

## License

MIT.
