![Trawl](src/lib/assets/TrawlBanner.png)

Live at **[trawlctf.vercel.app](https://trawlctf.vercel.app)**.

Drop a file into the page, or paste a string, and Trawl looks for whatever is
hidden in it. Nothing leaves your computer.

It is built for capture-the-flag competitions, where a puzzle often arrives as
an ordinary-looking image, a sound file, or a line of text with a message buried
inside it. [ROADMAP.md](ROADMAP.md) has the current state.

## What it is for

A competition hands you a photo with a password hidden in it. Not written on the
picture, but written into the numbers the picture is made of, so looking at the
image tells you nothing.

The usual answer is four or five separate programs, in three languages, one of
them an abandoned Java applet from 2011. For someone who has done it before, that
is fifteen minutes of habit. For a beginner it is the reason they skip the
category. Trawl runs the same checks from one page and tells you which one found
something.

## What it can do

Drop in a PNG, BMP, GIF, WAV or JPEG and it runs everything that applies. It
reads what the file says about itself: hidden text, camera metadata, other files
buried inside it, and anything stuck on the end where a viewer would never look.
Buried files save out with one click, and files inside a ZIP or carved from the
middle get the same checks automatically, a few levels deep.

Then Cuttlefish, the steganography half, goes after the data itself. It shows
every bit layer of an image at once so an odd one stands out, and tries up to 84
ways of reading hidden bits rather than making you guess. Sound files get the
same treatment plus a spectrogram, since a picture drawn into audio only shows up
when you look at the sound instead of listening to it. JPEGs get their compressed
numbers read directly, where JPEG payloads live. Animated GIFs are read frame by
frame, so a flag hidden in one frame or in the jump between two does not survive
playback.

Paste a string instead and Mantis, the cryptography half, takes over. It works
out what the string has been through and undoes it layer by layer: base64 around
hex around a rotation, unwound until something readable falls out, inflating gzip
or zlib along the way. If what is underneath is encrypted rather than encoded, it
attacks it: XOR, Caesar, Vigenère, affine, rail fence, columnar transposition and
simple substitution, each recovering its own key rather than asking you for one.
When nothing fires it lays out every rotation it knows with the promising ones
first, so you can finish by eye. It will not guess: a token that reads like
nothing to a scorer is worse than saying so.

A link is the newest input. Remora, the web-exploration half, is for a challenge
that lives on a site rather than in a file you were handed. A browser tab cannot
reach a site it was not served from, so Remora runs as a small program you start
on your own machine with one line the page hands you. From there it pulls the
site apart into the things Trawl already reads: it follows links, scripts, robots
and the sitemap to pages nothing advertises, reads each one for a flag in plain
sight or hidden in a cookie or a variable, and opens any image it finds against
Cuttlefish. A second mode, off until you affirm you are allowed to test the
target, sends what a page did not ask for and forges a JSON web token when the
site leaks its signing key.

Everything found collects in the Cod-end, the panel at the top of the page. It
lists the flag shapes to match (`flag{`, `CTF{`, `key{` and a few more, and you
can add your own) and hands the whole analysis back as a Markdown writeup on
request.

## What it will not tell you

Trawl never claims to have found a flag it has not actually checked. When a
result is uncertain it says what it measured and lets you decide.

Every detector is tested against files with a known answer, and against clean
files too, so it stays quiet when there is nothing there. A tool that reports
something on every file is no better than one that reports nothing.

## Why not just upload it to an AI

Because the model never receives your file. Before the network sees an image it
is decoded, shrunk, and turned into averages, and a blend of two numbers does not
keep the last digit of either. The hidden message is in those last digits. It is
gone before the model starts reading, so the answer you get back is either an
honest "I cannot see that" or a confident invented one. Under a competition clock,
the second one costs you real time.

An assistant that can run code is a different case. It can read the bytes, but
what it writes is a fresh, untested program every time, and a program that finds
nothing because it has a bug looks exactly like a file with nothing in it.

## Everything runs on your machine

No server, no upload, no account, no tracking. After the page loads once it works
with the network unplugged, and your file is opened read-only. That also settles
a rules question: most competitions forbid passing challenge files to outside
services, and Trawl has nowhere to send yours.

Web exploration is the one part that touches the network, because reaching a site
is the whole job. Remora still runs on your own machine and talks only to the
target you named and to your own browser.

## How it works

The analysis is written in Rust and compiled to WebAssembly, running in a
background thread so the page stays responsive. Some of these checks are hundreds
of millions of small calculations, so speed is the point.

Nothing is borrowed. `package.json` lists no runtime dependencies and neither
does the Rust core. Every parser, detector and attack was written for this
project, including the PNG, BMP, GIF, WAV and JPEG decoders and the Fourier
transform behind the spectrogram.

One thing worth knowing: the browser's own image decoder cannot be trusted here.
Ask a canvas for pixel values on an image with any transparency and it quietly
alters the lowest bit of a fifth of them, through the arithmetic it uses to store
transparent colour. That bit is the data being looked for. No setting turns it
off, so Trawl decodes images itself, and the test suite measures both paths.

## Running it locally

Needs Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, and Node 20 or
newer.

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

Test files are built from scratch by `fixtures/generate.mjs`, so every result the
tests claim can be reproduced rather than taken on trust. A labelled
[sample library](static/samples/README.md) covers the common tools, with clean
PNG, JPEG and WAV controls beside the planted samples.

## The names

Trawling is dragging a net through water and sorting whatever comes up, which is
close to what this program does with a dropped file.

**Cuttlefish**, the steganography half. Cuttlefish hide by rewriting their own
surface, which is what hiding a message in an image does to the picture. Their
ink is also where the colour sepia comes from.

**Mantis**, the cryptography half. The mantis shrimp cracks armoured shells with
the fastest strike in the animal kingdom, and sees a range of colour we are blind
to. Force and perception, which is the whole of code breaking.

**Remora**, the web-exploration half. A remora attaches to a larger host and
rides it, going everywhere the host goes. This one attaches to a live site and
brings back every part of it for the other tools to read.

**Cod-end** is the closed end of a trawl net, where the catch collects. In the
app it is the panel holding everything the tools brought up.

## Licence

MIT.
