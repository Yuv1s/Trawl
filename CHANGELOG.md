# Changelog

The scanner's version is what changes here. The site is always the latest code.

## 0.1.4 (2026-11-04)

The tag `v0.1.3` has no release. A settings mistake stopped the workflow before it built anything, so
everything meant for it is here.

### Fixed

- A scan now says when a response ran past the 2 MiB it reads of each, so a flag in the unread part
  no longer looks like a clean result.
- A scan now says when it stops at its limit on pages, scripts and stylesheets, file name finds or
  active requests, and when something it found could not be fetched.
- The page now says when a PDF holds streams Trawl never opened, when a database holds tables it did
  not read, when a JPEG scan ran out of data, and when a capture saved packets short.
- A file inside another file now reports what it stopped short of or failed on, the same as a file
  you drop in yourself. The page counts them and the writeup says which and why.
- Pasted text no longer says "Reading the file" while it loads.
- A release only becomes the latest once every platform's binary is on it, so the install command
  can't end up pointing at a release that is missing one.

### Changed

- The out-of-date warning now says which scanner version the page expects.

## 0.1.2 (2026-11-04)

If you installed the scanner before this release, stop it with Ctrl+C and run the line the page
gives you again. The page warns you when your scanner is out of date.

### Added

- `python serve.py` builds Trawl if it needs to, serves it at `localhost:8000` and opens it.
- Trawl now tells you where it stopped. A file that reaches a limit gets a note on the page and in
  the writeup saying what went unread.
- A compressed stream that is damaged still gives up what came before the damage, the way a browser
  shows an image with a broken end. Trawl uses its own inflate for this.
- PDF streams are read through filter arrays, predictors, `LZW` early change and comments.
- Long SQLite values are searched whole, including ones split across overflow pages.
- A build check in CI fails if the site holds a source map, a secret, a private path or a debug call.

### Fixed

- A very small image could crash the results page. A 101-byte PNG was enough.
- Small hostile files could freeze the tab, exhaust memory or kill the analysis.
- Decoy flags and signatures could use up a scan's limits and hide a real find after them.
- Repairing a PNG's height analysed an empty file.
- "Extract everything" returned the wrong bytes for a hit read column by column.
- RSA attacks ran on the page and could stall it. They now run in the background worker.
- A crafted ZIP could take minutes to read.

### Security

- The scanner only accepts its pairing token in a header, no longer in a URL.
- In local mode, local access now covers only the service you named. A redirect or a DNS change
  after the scan can't send the scanner to your other local services.
- A scan no longer guesses file names on a site it was redirected to, and says when it was
  redirected.
- Google Cloud's IPv6 metadata address is now refused in every mode, alongside the others.
- Text a file controls can't add images or links to the writeup.
- Workflow actions are pinned to commits, the `wasm-pack` download is checked against a hash, and
  checkouts no longer keep a token where a build script could read it.

## 0.1.1 and earlier

See the [commit history](https://github.com/Yuv1s/trawl/commits/main).
