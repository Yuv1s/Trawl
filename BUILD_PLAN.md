# Cuttlefish — Build Plan

A browser-based steganography forensics lab. Drop in a file, get every hiding place checked at
once, entirely on your own machine.

This document is the brief for an AI coding agent working with me on this project. Read all of it
before writing code.

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
  doesn't match how steg challenges actually work, push back on me — I'd rather argue about it than
  ship something that looks right and isn't.
- I'm learning Rust on this project. Explain Rust idioms as you use them. Don't write clever Rust.

---

## 2. The problem

Here's the real workflow when a CTF drops a suspicious PNG on you:

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
tell you *where to look first*.

For an experienced player that's fifteen minutes of muscle memory. For a beginner it's the reason
they skip the forensics category entirely — they don't know these tools exist, let alone which one
to reach for.

**Cuttlefish is one interface that runs all of it at once, in a browser tab, on a file that never
leaves the machine.**

That last part matters more than it sounds. CTF files are often from private or paid competitions,
and the existing web-based steg tools all upload to someone's server. Cuttlefish does everything
client-side. There is no backend to upload to.

## 3. Who it's for

1. **CTF players mid-competition** — needs to be fast, keyboard-driven, and information-dense. This
   person knows what a bit plane is and wants all 32 of them on screen at once.
2. **People learning forensics** — needs the tool to explain *why* something is suspicious, not just
   flag it. Every detector should be able to say what it found in a sentence.
3. **Me, at the next CTF.** If I wouldn't open this instead of my terminal, it isn't done.

## 4. Product principles

**One drop, everything runs.** No configure-then-analyze. The moment a file lands, every detector
fires in parallel and results stream in as they finish. The user should not have to know which
analysis to request.

**Rank the findings.** The output of a full sweep is dozens of results, most of them noise. The
primary view is a *triage panel*: findings sorted by how suspicious they are, with the boring ones
collapsed. "Chi-square indicates sequential LSB embedding in the first 34% of the image" goes at the
top. "File has an sRGB chunk" goes at the bottom, collapsed.

**Explain the verdict.** Every finding states what was measured and what it means. A confidence
number with no explanation is worse than nothing, because it can't be argued with.

**No installation, no upload, no account.** Static site. Works offline after first load. Works on a
locked-down competition laptop.

**Never modify the user's file.** Read-only, always.

---

## 5. Hard constraints

This section is not negotiable and is the reason this document exists. This project will be public
on GitHub and judged by other developers. It must not look like it was generated.

### Banned dependencies

**Nothing in the analysis path may come from a package.** The analysis *is* the project. Specifically
banned:

- Any steganography package (`stegjs`, `steggy`, `stegcloak`, etc.)
- Any image manipulation library (`jimp`, `sharp`, `canvas`) — the browser decodes images natively
- Any EXIF library (`exif-js`, `exifreader`, `piexifjs`) — hand-roll the TIFF/IFD walker
- Any hex viewer, entropy, or binary-parsing package

Zero runtime dependencies is the target for the core. It's achievable: `ArrayBuffer` gives raw bytes
and `createImageBitmap` gives pixels. Everything else is math I should be writing.

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

- Rust unit tests for every detector, using fixtures where I've embedded a known payload at a known
  rate. Assert detection, assert rate estimation within tolerance, and assert **no false positive on
  clean images**. This is the single most credible artifact in the repo.
- Every detector's math carries a comment citing the paper it comes from
- Small, atomic, well-named commits. Conventional commit format.
- Keyboard accessible, visible focus states, `prefers-reduced-motion` respected

---

## 6. Architecture

```
┌─ SvelteKit (static, adapter-vercel) ──────────────────────┐
│                                                            │
│  UI layer — Svelte 5 runes, hand-written CSS               │
│      │                                                     │
│      │ postMessage                                         │
│      ▼                                                     │
│  Web Worker ──────────────────────────────────────────┐    │
│      │                                                │    │
│      │ calls                                          │    │
│      ▼                                                │    │
│  cuttlefish-core (Rust → WASM)                        │    │
│    · bit plane extraction                             │    │
│    · LSB parameter sweep                              │    │
│    · chi-square attack                                │    │
│    · RS analysis                                      │    │
│    · entropy windowing                                │    │
│    · container/chunk parsers                          │    │
│    · string extraction                                │    │
└────────────────────────────────────────────────────────────┘
```

**Why Rust/WASM and not just JavaScript:** RS analysis over a 12-megapixel image is roughly 100
million pixel-group evaluations, and the LSB parameter sweep multiplies that across ~64 parameter
combinations. This is real compute, and JS will stutter badly. This is an engineering justification
I can defend, not decoration.

**Why a Web Worker:** the UI must stay responsive while a sweep runs, and results must stream in
progressively rather than appearing all at once at the end.

**Rust scope discipline:** the core is pure functions over `&[u8]`. No async, no traits, no generics
unless genuinely needed, no lifetime gymnastics. Slice in, struct out. If a piece of Rust starts
needing lifetime annotations to compile, that's a signal the design is wrong.

### The pixel-fidelity problem (read this before writing any pixel code)

Canvas `getImageData` will silently corrupt least-significant bits through color management and
alpha premultiplication. For a steganography tool this is fatal — it destroys exactly the data we're
looking for.

v1 mitigation, required:

```js
const bitmap = await createImageBitmap(blob, {
  colorSpaceConversion: 'none',
  premultiplyAlpha: 'none'
});
```

Then verify: build a test PNG with a known LSB pattern, round-trip it through the decode path, and
assert the bits survive. **Write this test before writing any analysis.** If the browser path proves
unreliable, escalate to a hand-rolled PNG decoder in Rust (inflate + unfilter) — more work, but
exact, and a strong addition to the project in its own right.

---

## 7. Scope

### v1 — the thing that has to work

**Container analysis** (operates on raw file bytes)

- Magic byte scan across the whole buffer — PK\x03\x04, \x1f\x8b, %PDF, \x89PNG, RIFF, \xFF\xD8
- Trailing data detection: bytes after PNG `IEND`, after JPEG `FFD9`, after ZIP EOCD
- PNG chunk walker: every chunk typed and sized, ancillary chunks flagged, `tEXt`/`zTXt`/`iTXt`
  decoded, anything after `IEND` flagged loudly
- JPEG segment walker: `COM` comments, `APPn` segments
- Shannon entropy over a sliding window, plotted — a high-entropy tail means appended compressed or
  encrypted data
- String extraction, configurable minimum length, ASCII and UTF-16LE
- EXIF/TIFF IFD walker, hand-written

**Pixel analysis**

- Bit-plane extraction: 8 planes × up to 4 channels, each renderable as a 1-bit image
- LSB parameter sweep across channel order, bit order, bit plane, and traversal direction
  (row-major/column-major) — this is `zsteg -a`, made visual
- Palette analysis for PNG-8/GIF: duplicate entries, ordering anomalies

**Steganalysis**

- **Chi-square attack** (Westfeld & Pfitzmann, 1999). Sequential LSB embedding equalizes the
  frequencies of pairs-of-values (2i, 2i+1). Compute observed vs expected frequencies, chi-square
  goodness of fit, derive embedding probability. Run it over increasing prefixes of the image so the
  point where embedding stops becomes visible as a cliff — that also estimates payload length.
- **RS analysis** (Fridrich, Goljan & Du, 2001). Partition into groups, apply flipping masks F₁, F₋₁,
  F₀, classify each group Regular/Singular/Unusable via a discrimination function on adjacent-pixel
  differences. In a clean image R_M ≈ R_₋M and S_M ≈ S_₋M; embedding makes them diverge. Solve the
  quadratic for embedding rate p.

**Triage panel** — everything above, ranked by suspicion, with one-sentence explanations.

### v2 — after v1 ships

- WAV: LSB extraction, and an FFT spectrogram (hidden images in spectrograms are a CTF staple)
- JPEG DCT coefficient analysis — JSteg and F5 detection
- Sample Pair Analysis as a third estimator to cross-check chi-square and RS
- Embedding mode, to generate practice challenges
- Hand-rolled PNG decoder in Rust for guaranteed bit fidelity

### Explicitly out of scope

No accounts, no cloud, no history, no sharing, no CLI. This is a dedicated app with one job.

---

## 8. Design direction

**The reference is a signal analyzer, not a SaaS dashboard.** Ghidra, Wireshark, a spectrum analyzer.
Dense, instrument-like, information over whitespace. The audience reads hex for fun.

**Palette** — grounded in the animal. Sepia is literally cuttlefish ink; the pigment is named after
*Sepia officinalis*. Ink and deep water, with chromatophore yellow reserved for one job only.

```css
--ground:  #0F1417;  /* deep water, page background */
--panel:   #182126;  /* raised surfaces */
--rule:    #26343A;  /* dividers, 1px only */
--ink:     #7A4A2E;  /* sepia — data traces, plot lines */
--signal:  #E3B23C;  /* chromatophore yellow — ONLY for flagged findings */
--text:    #D8DEDC;  /* pale mantle */
--muted:   #6B7B80;  /* labels, units, secondary */
```

`--signal` is the discipline test. It marks anomalies and nothing else. If yellow appears on a
button, a border, or a heading, the palette has failed.

**Type** — IBM Plex Sans Condensed for interface chrome and labels, IBM Plex Mono for all data, hex,
and numbers. Institutional, dense, and specifically not Inter. Set a tight type scale; labels go
uppercase at small sizes with wide tracking, like instrument panel legends.

**Layout** — no hero, no landing page. The dropzone *is* the page, occupying the full viewport with
nothing but the name and a one-line description. On drop it transforms in place into a three-region
workbench:

```
┌──────────────┬───────────────────────────┬──────────────┐
│  STRUCTURE   │      BIT-PLANE WALL       │   EXTRACT    │
│              │                           │              │
│  chunk tree  │   32 planes, live         │  hex dump    │
│  ─────────   │   ───────────────────     │  ────────    │
│  TRIAGE      │   suspicion trace ▁▃▅█▅▁  │  strings     │
│  ranked      │                           │              │
└──────────────┴───────────────────────────┴──────────────┘
```

Left rail is the file's structure and the ranked triage. Center is the visual analysis. Right is
extracted output. This is a disassembler layout, because that's the vernacular the audience already
reads.

**Signature element** — the **bit-plane wall**: all 32 planes rendered simultaneously in a dense
grid, where an anomalous plane visually jumps out of a field of noise. Under it, the **suspicion
trace**: chi-square plotted against byte offset, drawn as an oscilloscope line in `--ink`, where
sequential embedding appears as a visible cliff at the payload boundary. Nothing else on the page
competes with these two things.

**Motion** — one orchestrated moment only. Detectors finish at different speeds, so let results
stream into the triage panel as they land, and let the suspicion trace draw left-to-right as the
chi-square sweep advances. That's motion encoding real progress. Everything else is static.

**Copy** — plain and declarative. "34% of the image shows sequential LSB embedding." Not "Suspicious
activity detected!" An empty triage panel says what was checked and found clean, not "No results."

---

## 9. Repo conventions

- Conventional commits, small and atomic. The commit log is part of what this project is judged on.
- `README.md` explains the steganalysis math, not just the install steps. Diagrams over prose where
  possible.
- A `/fixtures` directory with the test images and a script that generates them, so anyone can
  reproduce the test results.
- `docs/` for devlogs — I'm writing these as I go, and they're part of the deliverable.
- MIT license.

## 10. How I want you to work

- **Vertical slices, not scaffolding.** Don't generate the whole file tree and fill it in. Get one
  detector working end to end — Rust → WASM → worker → UI → visible on screen — before starting the
  next.
- **Ask before adding any dependency.** Name it, say what it does, say why hand-writing it is a bad
  trade. I'll usually say no.
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
- The test suite proves detection works and proves it doesn't cry wolf on clean images.
- A stranger opens the deployed URL, drops a file, and understands the output without reading docs.
- I'd open it instead of my terminal at the next CTF.
