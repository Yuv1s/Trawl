# Trawl

Drop a file into the page and Trawl looks for whatever is hidden in it. Nothing
leaves your computer.

It is built for capture-the-flag competitions, where a puzzle often arrives as
an ordinary-looking image or sound file with a message buried inside it.

**Status: in development.** [ROADMAP.md](ROADMAP.md) has the current state. The
steganography half works. Cryptography and forensics are not started.

## What it is for

A competition hands you a photo. Somewhere in it, someone has hidden a password.
It is not written in the picture, it is written into the numbers the picture is
made of, so looking at the image tells you nothing.

The usual answer is four or five separate programs, in three languages, each
installed separately, none of which talk to each other. One is an abandoned Java
applet from 2011. For someone who has done it before, that is fifteen minutes of
habit. For a beginner it is the reason they skip the category.

Trawl runs the same checks from one page, and tells you which one found
something.

## What it can do today

Drop in a PNG, BMP, GIF, WAV or JPEG and it runs everything that applies.

It reads what the file says about itself: hidden text, camera metadata, other
files buried inside it, and anything stuck on the end where a viewer would never
look. Buried files can be saved out with one click.

Then Cuttlefish, the steganography half, goes after the data itself. It shows
every layer of an image at once so an odd one stands out. It tries up to 84 different
ways of reading hidden bits rather than making you guess which. Two published
statistical tests estimate how much of a file is carrying a payload. Sound files
get the same bit-level treatment, plus a spectrogram, because drawing a picture
into audio is a common trick and it only shows up when you look at the sound
instead of listening to it. JPEGs get their compressed numbers read directly,
which is where JPEG payloads live, whether the file is an ordinary one or the
progressive kind that loads in passes. Images that paint by numbers get their
palette read too, since two entries holding the same colour let a pixel pick
either one and that choice carries a message no viewer can show you.

Everything found collects in the Cod-end, the panel at the top of the page.

## What it will not tell you

Trawl never claims to have found a flag it has not actually checked. When a
result is uncertain it says what it measured and lets you decide.

Every detector is tested against files with a known answer, and also against
clean files, to make sure it stays quiet when there is nothing there. That
second half matters more than it sounds. A tool that reports something on every
file is no better than one that reports nothing.

## Why not just upload it to an AI

Because the model never receives your file.

Before any part of the network sees an image, it is decoded, shrunk, and turned
into averages. Shrinking replaces each pixel with a blend of its neighbours, and
a blend of two numbers does not preserve the last digit of either. The hidden
message is in those last digits. It is gone before the model starts reading.

So the answer you get back is either an honest "I cannot see that", or a
confident invented one. Under a competition clock, the second costs you real
time.

An assistant that can run code is a different case. It can read the bytes. What
it produces is a fresh, untested program every time, and a program that finds
nothing because it has a bug looks exactly like a file with nothing in it.

## Everything runs on your machine

There is no server, no upload, no account, no tracking. After the page loads
once it works with the network unplugged. Your file is opened read-only and
never changed.

That also settles a rules question. Most competitions forbid passing challenge
files to outside services, and Trawl has nowhere to send yours.

## How it works

The analysis is written in Rust and compiled to WebAssembly, running in a
background thread so the page stays responsive. Some of these checks are
hundreds of millions of small calculations, so the speed is the point rather
than a preference.

Nothing is borrowed. `package.json` lists no runtime dependencies and neither
does the Rust core. Every parser, detector and attack here was written for this
project, including the PNG, BMP, GIF, WAV and JPEG decoders and the Fourier
transform behind the spectrogram.

One thing worth knowing: the browser's own image decoder cannot be trusted with
this. Ask a canvas for pixel values on an image with any transparency and it
quietly alters the lowest bit of a fifth of them, through the arithmetic it uses
to store transparent colour. That bit is the data being looked for. No canvas
setting turns it off, so Trawl decodes images itself, and the test suite
measures both paths: the browser one to record how it fails, ours to prove every
sample comes back untouched.

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
tests claim can be reproduced rather than taken on trust.

## The names

Trawling is dragging a net through water and sorting whatever comes up, which is
close to what this does with a dropped file.

**Cuttlefish** is the steganography half. Cuttlefish hide by rewriting their own
surface, which is what hiding a message in an image does to the picture. Their
ink is also where the colour sepia comes from.

**Cod-end** is the closed end of a trawl net, where the catch collects. In the
app it is the panel holding everything the tools brought up.

## Licence

MIT.
