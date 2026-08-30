# Trawl build brief

A browser-based toolkit for file-based CTF categories and guarded web exploration. Drop a file,
paste a string, or connect the local Remora scanner to a target, and every relevant check runs.
File and string analysis stay on the machine.

This document began as the build plan and now records the product constraints and architecture for
an AI coding agent working on this project. Read all of it before writing code. Current feature
status lives in `ROADMAP.md`; this brief explains why the project is built the way it is.

---

## 1. Who I am, and what that means for how you work with me

I'm a high school CS student with a competitive security background:

- **CyberPatriot State Champion**, Windows Lead — I authored 1,800+ line PowerShell/Bash hardening scripts
- **Lockheed Martin CyberQuest** — 2nd place
- **UACTF** — 3rd place Division 2, 2nd place Division 1
- Active CTF player: picoCTF, boroCTF. At boroCTF 2026 I reverse-engineered a challenge written in
  an esoteric language called OmegaCode with no public documentation, and solved it independently.
- Digital forensics is my specific area: steganography, USB registry artifact analysis, reverse
  engineering
- I've shipped a hand-built regex tokenizer and plain-English explanation engine (EzRegex), so
  parsers and byte-level work are familiar territory

**What this means for you:**

- Do not simplify explanations. Use the real terminology. If you're implementing a chi-square
  attack, say "chi-square attack" and cite Westfeld & Pfitzmann.
- Do not reach for a library to avoid explaining something. I want to understand every line in this
  repo well enough to defend it in a code review, because I will have to.
- I have solved the problems this tool addresses, by hand, under time pressure. If a design decision
  doesn't match how these challenges actually work, push back on me — I'd rather argue about it than
  ship something that looks right and isn't.
- I'm learning Rust on this project. Explain Rust idioms as you use them. Don't write clever Rust.

---

## 2. The problem

The real workflow when a competition drops a suspicious PNG on you:

```
$ exiftool chal.png          # check metadata
$ strings chal.png | less    # eyeball for flags
$ binwalk chal.png           # look for appended files
$ zsteg -a chal.png          # brute-force LSB parameters
$ steghide extract -sf ...   # if it's JPEG and passworded
$ java -jar stegsolve.jar    # bit planes, in a 2011 Java applet
```

Six tools, five interfaces, three languages. Every one has to be installed first. `zsteg` is Ruby
and only handles PNG/BMP. StegSolve is an unmaintained Java applet with a UI from another era.
`binwalk` gives you a wall of false positives. None of them talk to each other, and none of them
tell you _where to look first_.

Crypto has the same shape. CyberChef in one tab, a Python REPL with pycryptodome in another,
RsaCtfTool in a third, and a bookmarked substitution solver you half remember how to drive.

For an experienced player that's fifteen minutes of muscle memory. For a beginner it's the reason
they skip these categories entirely. They don't know the tools exist, let alone which one to reach
for.

**Trawl is one interface that runs the applicable checks at once. Dropped files and pasted text never
leave the machine.**

That last part matters more than it sounds. CTF files are often from private or paid competitions,
and the existing web-based tools upload to someone's server. Trawl's file and text analysis runs in
the browser. Remora reaches only the web target the user names, through a local scanner rather than a
hosted backend.

## 3. Who it's for

1. **CTF players mid-competition** — needs to be fast, keyboard-driven, and information-dense. This
   person knows what a bit plane is and wants all 32 of them on screen at once.
2. **People learning forensics and crypto** — needs the tool to explain _why_ something is
   suspicious, not just flag it. Every detector should be able to say what it found in a sentence.
3. **Me, at the next CTF.** If I wouldn't open this instead of my terminal, it isn't done.

## 4. Product principles

**One input, everything runs.** No configure-then-analyze, and no category picker in the common
case. A dropped file routes to the container, pixel, and forensics pipelines. Pasted text routes to
the crypto pipeline. The user should not have to know which analysis to request, or which category
their challenge belongs to.

**Answer when you can prove it, rank when you can't.** If an extraction self-verifies, put the
answer at the top and get out of the way. Verification means printable ASCII above a length
threshold, a match against known flag formats, or a valid file signature. If nothing verifies, fall
back to ranked findings. Never assert a flag the tool cannot check.

**Rank the findings.** A full sweep produces dozens of results, most of them noise. The primary view
is a triage panel sorted by suspicion, with the boring results collapsed. "Chi-square indicates
sequential LSB embedding in the first 34% of the image" goes at the top. "File has an sRGB chunk"
goes at the bottom, collapsed.

**Explain the verdict.** Every finding states what was measured and what it means. A confidence
number with no explanation is worse than nothing, because it can't be argued with.

**No installation for offline analysis, no upload, no account.** The static page works offline after
first load and on a locked-down competition laptop. Remora is the one exception: web challenges need
the small local scanner because reaching the target is the work.

**Never modify the user's file.** Read-only, always.

---

## 5. Hard constraints

This section is not negotiable and is the reason this document exists. This project will be public
on GitHub and judged by other developers. It must not look like it was generated.

### Banned dependencies

**Nothing in the analysis path may come from a package.** The analysis _is_ the project.
Specifically banned:

- Any steganography package (`stegjs`, `steggy`, `stegcloak`)
- Any image manipulation library (`jimp`, `sharp`, `canvas`) — the browser decodes images natively
- Any EXIF library (`exif-js`, `exifreader`, `piexifjs`) — hand-roll the TIFF/IFD walker
- Any crypto or cipher library (`crypto-js`, `node-forge`, `sjcl`) — the attacks are the point
- Any hex viewer, entropy, encoding, or binary-parsing package
- CyberChef, in whole or in part

Zero runtime dependencies is the target, and it is achievable.

### Platform APIs are not dependencies

Browser built-ins are the runtime, not packages. They ship no code, add nothing to `package.json`,
and make no network request. These are allowed and expected:

- `ArrayBuffer` / `DataView` for raw bytes
- `createImageBitmap` for pixels
- `DecompressionStream` for inflate (needed to read PNG pixel data at all)
- `SubtleCrypto` for SHA-1 through SHA-512
- `BigInt` for RSA arithmetic

Calling `DecompressionStream` is no more a dependency than calling `Math.sqrt`. The line is simple:
plumbing may come from the platform, analysis may not. Every detector, cipher attack, estimator, and
parser is hand-written.

If a piece of plumbing has no platform equivalent (MD5, for instance), hand-write it. Do not add a
package for it.

### Banned UI stack

- **No Tailwind.** Hand-written CSS with custom properties, one tokens file.
- No shadcn/ui, Material, Bootstrap, DaisyUI, or any component library
- No CSS-in-JS
- No icon library — draw the handful of icons needed as inline SVG

### Banned visual patterns

These are the tells. Avoid all of them:

- Purple/indigo/violet gradients, anywhere
- Gradient text on a large headline
- A three-across grid of rounded cards with a soft shadow and a hover lift
- `border-radius` above 4px on anything that isn't a button
- Emoji used as interface icons. No sparkle emoji, ever.
- A marketing hero section above the actual tool
- Glassmorphism, blur-behind panels
- Any animation that exists because it looked nice rather than because it communicates state

### Banned copy patterns

- Exclamation marks in interface text
- "Seamlessly", "effortlessly", "unlock", "supercharge", "powered by"
- Feature descriptions that sell rather than describe
- Error messages that apologize. State what happened and what to do.

### Required

- Rust unit tests for every detector, using fixtures with a known payload at a known rate. Assert
  detection, assert rate estimation within tolerance, and assert **no false positive on clean
  inputs**. This is the single most credible artifact in the repo.
- Every detector's math carries a comment citing the paper it comes from
- Small, atomic, well-named commits. Conventional commit format.
- Keyboard accessible, visible focus states, `prefers-reduced-motion` respected

---

## 6. Architecture

```
┌─ SvelteKit (static, adapter-static) ──────────────────────┐
│                                                            │
│  UI layer — Svelte 5 runes, hand-written CSS               │
│      │                                                     │
│      │ postMessage                                         │
│      ▼                                                     │
│  Web Worker ──────────────────────────────────────────┐    │
│      │                                                │    │
│      │ calls                                          │    │
│      ▼                                                │    │
│  trawl-core (Rust → WASM)                             │    │
│    ├── bytes.rs    magic scan, entropy, strings,      │    │
│    │               checksums and carving              │    │
│    ├── cuttlefish/ image and audio steganography      │    │
│    ├── mantis/     encodings, ciphers, XOR, RSA       │    │
│    └── parsers     PNG, GIF, JPEG, WAV, ZIP and EXIF  │    │
└────────────────────────────────────────────────────────────┘

trawl-scan (native Rust process)
    └── Remora: guarded fetch, crawl, decode and active probes
```

The offline Rust crate is `trawl-core`. Cuttlefish and Mantis are modules inside it. Network access
belongs to the separate `trawl-scan` crate, which runs on the user's machine and exposes Remora to
the page through a token-protected loopback service.

**Shared code matters here.** Magic byte scanning, entropy windowing, string extraction, checksums,
and carving live in `bytes.rs` and are written once. Format parsers stay at the crate root or under
their format module rather than being duplicated under category folders.

**Why Rust/WASM and not just JavaScript:** RS analysis over a 12-megapixel image is roughly 100
million pixel-group evaluations, and the LSB parameter sweep multiplies that across ~64 parameter
combinations. Substitution cipher hill climbing runs tens of thousands of scored candidates. This is
real compute, and JS will stutter badly. This is an engineering justification I can defend, not
decoration.

**Why a Web Worker:** the UI stays responsive while a sweep runs. The current worker returns the
completed analysis in one response; if future work streams partial results, keep the same message
boundary rather than moving analysis onto the UI thread.

**Rust scope discipline:** the core is pure functions over `&[u8]` and `&str`. No async, no traits,
no generics unless genuinely needed, no lifetime gymnastics. Slice in, struct out. If a piece of
Rust starts needing lifetime annotations to compile, that's a signal the design is wrong.

**wasm-bindgen** is the one crate dependency. It generates the pointer/length marshalling that lets
a `&[u8]` cross the WASM boundary, which raw WASM signatures cannot express. It contains no analysis
code.

### The pixel-fidelity problem (read this before writing any pixel code)

Canvas `getImageData` will silently corrupt least-significant bits through color management and
alpha premultiplication. For a steganography tool this is fatal, because it destroys exactly the
data we're looking for.

PNG pixel analysis uses the hand-written Rust decoder in `trawl-core/src/png.rs`. The browser's
`DecompressionStream` supplies inflate, then Trawl unfilters and expands every sample itself. The
fidelity tests include bit 0 and translucent input, so canvas premultiplication cannot quietly enter
the PNG path.

Other formats still use `createImageBitmap` with color conversion and alpha premultiplication
disabled. That route is suitable for display and format coverage, but not for any detector that
claims the low bits of translucent pixels are exact.

---

## 7. Scope

Steganography, cryptography, and guarded web exploration are working today. Forensics has ZIP and
metadata coverage but remains the unfinished category. `ROADMAP.md` is the source of truth for what
is done and what remains.

### v1 — steganography (Cuttlefish)

**Container analysis** (operates on raw file bytes)

- Magic byte scan across the whole buffer: PK\x03\x04, \x1f\x8b, %PDF, \x89PNG, RIFF, \xFF\xD8
- Trailing data detection: bytes after PNG `IEND`, after JPEG `FFD9`, after ZIP EOCD
- PNG chunk walker: every chunk typed and sized, ancillary chunks flagged, `tEXt`/`zTXt`/`iTXt`
  decoded, anything after `IEND` flagged loudly
- JPEG segment walker: `COM` comments, `APPn` segments
- Shannon entropy over a sliding window, plotted. A high-entropy tail means appended compressed or
  encrypted data.
- String extraction, configurable minimum length, ASCII and UTF-16LE
- EXIF/TIFF IFD walker, hand-written

**Pixel analysis**

- Bit-plane extraction: 8 planes × up to 4 channels, each renderable as a 1-bit image
- LSB parameter sweep across channel order, bit order, bit plane, and traversal direction
- Palette analysis for PNG-8/GIF: duplicate entries, ordering anomalies
- All-frame GIF analysis: every composited displayed frame and each consecutive difference run through
  the same detectors, budgeted to 128 frames and capped counts

**Steganalysis**

- **Chi-square attack** (Westfeld & Pfitzmann, 1999). Sequential LSB embedding equalizes the
  frequencies of pairs-of-values (2i, 2i+1). Compute observed vs expected frequencies, chi-square
  goodness of fit, derive embedding probability. Run it over increasing prefixes so the point where
  embedding stops becomes visible as a cliff, which also estimates payload length.
- **RS analysis** (Fridrich, Goljan & Du, 2001). Partition into groups, apply flipping masks F₁,
  F₋₁, F₀, classify each group Regular/Singular/Unusable via a discrimination function on
  adjacent-pixel differences. In a clean image R_M ≈ R_₋M and S_M ≈ S_₋M; embedding makes them
  diverge. Solve the quadratic for embedding rate p.

### v2 — cryptography

- Encoding chain detection and automatic peeling: base64, base32, base85, hex, URL, HTML entities,
  ROT47, morse, binary. Detect, decode, repeat until the output stops scoring as encoded.
- Compression-aware peeling: when a layer peels to a gzip or zlib stream, the stream is inflated in
  the browser and peeled after, sharing the same six-layer budget; cycles and bomb bounds stop the walk.
- Caesar/ROT-N solved by scoring all 26 shifts against English quadgram log-probabilities
- Vigenère: key length from index of coincidence and Kasiski examination, then per-column solve
- Simple substitution by hill climbing against the quadgram model
- XOR: single byte by frequency scoring, repeating key with keysize from normalized Hamming distance
- RSA: cube root for small e, GCD across moduli for shared factors, Fermat factorization for close
  primes, Wiener's attack for small d
- Hash identification from length and alphabet

### v3 — forensics

- [x] File carving: locate by signature and extract to a downloadable blob
- [x] ZIP local-header and central-directory comparison, including hidden entries, mismatches,
      comments, recursive scanning, and inflate
- [x] Recursive embedded-file analysis: ZIP entries and carved files scanned with the same checks,
      budgeted to depth 3, 32 children, 1 MiB per child, and 8 MiB expanded in total
- [ ] PDF object and stream walker
- [ ] Windows registry hive parser aimed at USB artifacts: `USBSTOR`, mounted device GUIDs, timestamps

### Later

- Sample Pair Analysis as a third estimator to cross-check chi-square and RS
- Embedding mode, to generate practice challenges

WAV LSB extraction, the FFT spectrogram, JSteg coefficient extraction, and the exact Rust PNG
decoder have shipped. F5 detection remains open because its published comparison needs a
re-compressed copy of the original; see `ROADMAP.md`.

### Explicitly out of scope

No accounts, no cloud storage, no history, and no sharing.

No pwn. It needs a persistent live target. Web challenges are covered only through Remora, a separate
scanner the user starts on their own machine, because a static page cannot reach an arbitrary target
safely on its own.

No password cracking against steghide or encrypted archives. Wordlist attacks belong on hardware the
user controls.

---

## 8. Design direction

**The reference is a signal analyzer, not a SaaS dashboard.** Ghidra, Wireshark, a spectrum
analyzer. Dense, instrument-like, information over whitespace. The audience reads hex for fun.

**Palette** — grounded in the animal that named the steg module. Sepia is literally cuttlefish ink.
Ink and deep water, with chromatophore yellow reserved for one job only.

```css
--ground: #0f1417; /* deep water, page background */
--panel: #182126; /* raised surfaces */
--rule: #26343a; /* dividers, 1px only */
--ink: #7a4a2e; /* sepia — data traces, plot lines */
--signal: #e3b23c; /* chromatophore yellow — ONLY for flagged findings */
--text: #d8dedc; /* pale mantle */
--muted: #6b7b80; /* labels, units, secondary */
```

`--signal` is the discipline test. It marks anomalies and nothing else. If yellow appears on a
button, a border, or a heading, the palette has failed.

**Type** — IBM Plex Sans Condensed for interface chrome and labels, IBM Plex Mono for all data, hex,
and numbers. Institutional, dense, and specifically not Inter. Set a tight type scale; labels go
uppercase at small sizes with wide tracking, like instrument panel legends.

**Layout** — no hero, no landing page, and no category navigation as the primary interface. The
input surface _is_ the page, occupying the full viewport with nothing but the name and a one-line
description. It accepts both a dropped file and pasted text, and routes on what it receives.

On input it transforms in place into a three-region workbench. The center region changes by category;
the left and right rails stay put.

```
┌──────────────┬───────────────────────────┬──────────────┐
│  STRUCTURE   │      ANALYSIS             │   EXTRACT    │
│              │                           │              │
│  chunk tree  │   steg: bit-plane wall    │  hex dump    │
│  ─────────   │   crypto: candidate table │  ────────    │
│  TRIAGE      │   forensics: carve list   │  strings     │
│  ranked      │                           │              │
└──────────────┴───────────────────────────┴──────────────┘
```

Left rail is structure and ranked triage. Center is the analysis view for whatever category the
input routed to. Right is extracted output. This is a disassembler layout, because that's the
vernacular the audience already reads.

Category tabs exist, but as a secondary affordance for forcing a specific tool. They are not the
front door.

**Signature element** — the **bit-plane wall**: all 32 planes rendered simultaneously in a dense
grid, where an anomalous plane visually jumps out of a field of noise. Under it, the **suspicion
trace**: chi-square plotted against byte offset, drawn as an oscilloscope line in `--ink`, where
sequential embedding appears as a visible cliff at the payload boundary. Nothing else on the page
competes with these two things.

**Motion** — use it only for real state changes: loading, moving between tools, opening a dialog, or
drawing a trace whose position carries data. The current analysis arrives as one worker response, so
do not fake staggered detector completion. Everything else stays static.

**Copy** — plain and declarative. "34% of the image shows sequential LSB embedding." Not "Suspicious
activity detected". An empty triage panel says what was checked and found clean, not "No results".

---

## 9. Repo conventions

- Conventional commits, small and atomic. The commit log is part of what this project is judged on.
- `README.md` explains the math, not just the install steps. Diagrams over prose where possible.
- A `/fixtures` directory with the test inputs and a script that generates them, so anyone can
  reproduce the test results. Checked-in binaries with no provenance are not acceptable.
- `README.md` and `ROADMAP.md` carry the public project record. Do not invent a parallel docs tree
  unless a real document needs it.
- MIT license.

## 10. How I want you to work

- **Vertical slices, not scaffolding.** Don't generate the whole file tree and fill it in. Get one
  detector working end to end (Rust → WASM → worker → UI → visible on screen) before starting the
  next.
- **Ask before adding any dependency.** Name it, say what it does, say why hand-writing it is a bad
  trade. I'll usually say no. Platform APIs under §5 don't need asking.
- **Test first for the math.** Every detector gets its fixture and its assertion before it gets its
  implementation.
- **Show me the reasoning on the algorithms.** When you implement RS analysis, walk me through the
  discrimination function and why the quadratic has the form it does. I need to be able to explain
  this to someone else.
- **Push back on me.** If I ask for something that will produce false positives, or that doesn't
  match how these challenges actually work, say so.

## 11. Done means

- Drop a stego PNG with a payload at 25% embedding rate, and the triage panel names it correctly
  within three seconds, without a network request.
- Paste a triple-encoded base64 string and get the plaintext without choosing a decoder.
- The test suite proves detection works and proves it doesn't cry wolf on clean inputs.
- A stranger opens the deployed URL, drops a file, and understands the output without reading docs.
- I'd open it instead of my terminal at the next CTF.
