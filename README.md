# Cuttlefish

Steganography forensics in the browser. Drop a file, get every hiding place checked at once,
without it ever leaving your machine.

> **Status: in development.** The feature list below describes the target, not what currently
> works. See [Roadmap](#roadmap) for what's actually shipped.

---

## Why not just upload it to an AI?

Because a vision model physically cannot see the data you're looking for.

When you upload an image to Claude, GPT, or Gemini, it doesn't reach the model as your file. It gets
resized and re-encoded into a fixed grid of patches first. That resampling step destroys the least
significant bits of every pixel — which, in an LSB-embedded image, is the entire payload.

The model isn't declining to check bit plane 0 of the blue channel. There is no mechanism by which
it could. It's looking at a lossy thumbnail of the *picture*, while the secret lives in the *file*.

Ask anyway, and you get one of two answers: an honest "I can't extract that," or a confident,
well-formatted, completely invented flag. Under a competition clock, the second one is expensive.

**The fair caveat:** an assistant with code execution can write a script and genuinely analyze the
bytes. But that script is written fresh each time, tested by nobody, and produces a different
implementation on every run. Cuttlefish's detectors are fixed, unit-tested against fixtures with
known embedding rates, and verified not to fire on clean images. When it reports 25% sequential LSB
embedding, that number came from a chi-square test you can read the source of.

|                                      | Cuttlefish | Upload to an LLM | zsteg / StegSolve / binwalk |
| ------------------------------------ | ---------- | ---------------- | --------------------------- |
| Reads least-significant bits         | Yes        | No               | Yes                         |
| Deterministic and reproducible       | Yes        | No               | Yes                         |
| Tested false-positive rate           | Yes        | No               | Varies                      |
| File leaves your machine             | Never      | Every time       | Never                       |
| Tools to install                     | None       | None             | Four, in three languages    |
| Works offline                        | Yes        | No               | Yes                         |
| Explains what it found and why       | Yes        | Yes              | Not really                  |
| One interface for the whole workflow | Yes        | Yes              | No                          |

There's a second reason that has nothing to do with capability. Most competitions restrict
redistributing challenge files outside the event. Uploading one to a third-party API is arguably
exactly that. Cuttlefish has no backend — there is nowhere for your file to go.

## Features

### Container analysis

Operates on the raw bytes, independent of any image decoding.

- **Magic byte scan** across the entire buffer — ZIP, gzip, PDF, PNG, JPEG, RIFF signatures found at
  any offset, not just position zero
- **Trailing data detection** — bytes after PNG `IEND`, after JPEG `FFD9`, after the ZIP end-of-
  central-directory record. The oldest trick in the category, and still the most common.
- **PNG chunk walker** — every chunk typed and sized, ancillary chunks flagged, `tEXt`/`zTXt`/`iTXt`
  decoded, anything appearing after `IEND` surfaced immediately
- **JPEG segment walker** — `COM` comments and `APPn` segments extracted
- **Entropy map** — Shannon entropy over a sliding window, plotted across the file. A high-entropy
  tail means appended compressed or encrypted data.
- **String extraction** — configurable minimum length, ASCII and UTF-16LE
- **EXIF/TIFF walker** — hand-written IFD parser, no library

### Pixel analysis

- **Bit-plane wall** — all 8 planes across every channel rendered simultaneously. An anomalous plane
  visually jumps out of a field of noise; you don't have to know which one to check.
- **LSB parameter sweep** — every combination of channel order, bit order, bit plane, and traversal
  direction, swept in parallel. This is `zsteg -a`, made visual.
- **Palette analysis** for PNG-8 and GIF — duplicate entries and ordering anomalies

### Steganalysis

Statistical detection, not pattern guessing.

- **Chi-square attack** (Westfeld & Pfitzmann, 1999) — sequential LSB embedding equalizes the
  frequencies of pairs-of-values. Run over increasing prefixes of the image, the point where
  embedding stops appears as a visible cliff, which also estimates payload length.
- **RS analysis** (Fridrich, Goljan & Du, 2001) — flipping-mask group classification. Estimates the
  embedding rate rather than just answering yes or no.

### Interface

- **One drop runs everything.** No configure-then-analyze. Every detector fires on file load and
  results stream in as they finish.
- **Ranked triage.** Findings sorted by how suspicious they are, with an explanation of what was
  measured. Noise stays collapsed.
- **Fully client-side.** No upload, no account, no network request. Works offline after first load,
  including on a locked-down competition laptop.
- **Read-only.** Your file is never modified.

## How it works

The analysis core is written in Rust and compiled to WebAssembly, running in a Web Worker so the
interface stays responsive during a sweep. RS analysis over a 12-megapixel image is on the order of
a hundred million pixel-group evaluations, and the LSB sweep multiplies that across dozens of
parameter combinations — this is genuine compute, not a stylistic choice.

The core has zero runtime dependencies. `ArrayBuffer` provides the raw bytes and `createImageBitmap`
provides pixels; everything past that point is arithmetic written for this project. No
steganography package, no image library, no EXIF parser.

## Running locally

Requires Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, and Node 20+.

```bash
git clone https://github.com/yuv1s/cuttlefish
cd cuttlefish
npm install
cd cuttlefish-core && wasm-pack build --target web --out-dir ../src/lib/wasm
cd .. && npm run dev
```

Tests, including the steganalysis fixtures:

```bash
cd cuttlefish-core && cargo test
```

Fixtures are generated by a script in `/fixtures` so the detection results are reproducible.

## Roadmap

- [ ] Container analysis — magic bytes, trailing data, PNG/JPEG walkers, entropy, strings, EXIF
- [ ] Bit-plane wall and LSB parameter sweep
- [ ] Chi-square attack with prefix sweep
- [ ] RS analysis
- [ ] Ranked triage panel
- [ ] WAV support — LSB extraction and FFT spectrogram
- [ ] JPEG DCT analysis — JSteg and F5 detection
- [ ] Sample Pair Analysis as a third cross-check
- [ ] Embedding mode, for generating practice challenges

## Why "Cuttlefish"

They hide by rewriting their own surface, which is what LSB embedding does to an image. Their ink is
also where sepia comes from — the pigment is named after *Sepia officinalis*.

## License

MIT.
