# Roadmap

Where Trawl is. Checked means built, tested, and working in the browser today.

## Done

### Reading things

- [x] PNG, all colour types and bit depths, interlaced or not
- [x] BMP and GIF
- [x] WAV, 8 through 32-bit, mono or multichannel
- [x] JPEG structure, and the compressed numbers underneath it, baseline or
      progressive
- [x] A string you paste, which needs no file at all
- [x] Finding files buried inside other files, and saving them out
- [x] Text, metadata, entropy, and checksums on anything you drop

- [x] ZIP archives, read twice and compared. A zip describes itself in a local
      header before each file and again in a central directory at the end, and
      readers only consult the directory, so the two disagreeing is how an
      archive hides something. Reports entries the directory never lists,
      sizes and checksums the two copies argue about, bytes before the first
      header, bytes appended past the end, and the comments nothing shows
- [x] Reading inside the archive too: each entry inflated and scanned, so a flag
      in a file inside the zip, including one appended to a PNG, shows in place
      without saving it out and unzipping it first

### Cuttlefish, the steganography half

- [x] Bit-plane wall: every layer of an image shown at once
- [x] LSB sweep: up to 84 ways of reading hidden bits, tried in one go
- [x] Chi-square attack (Westfeld and Pfitzmann, 1999)
- [x] RS analysis (Fridrich, Goljan and Du, 2001)
- [x] Palette: reads messages hidden in the choice between identical colours
- [x] Audio LSB sweep
- [x] Spectrogram, for pictures drawn into sound
- [x] JSteg extraction from JPEG coefficients
- [x] Coefficient statistics, with the value counts shown
- [x] AES-CBC run on a file that carries its own key. The hex key and IV out of
      the metadata, the base64 payload from nearby, tried across the key sizes and
      shown only when the result reads as text. A wrong key turns AES into noise,
      so a file with no key in it stays silent, and the cipher is written out here
      the same as every other, nothing pulled in

### Mantis, the cryptography half

- [x] Spot an encoding and peel it, over and over, until plain text falls out
- [x] Sixteen encodings: base64, base58, base32, ascii85, hex, morse, binary,
      uuencode, quoted-printable and the rest
- [x] Caesar, solved rather than applied: every shift tried, the readable one
      kept
- [x] XOR key recovery, single byte and repeating key, with the key length
      worked out rather than asked for
- [x] Hash identification, which names every format a shape allows rather than
      picking one and sounding sure
- [x] A crib attack on flag shapes. No cipher here enciphers punctuation, so the
      braces of `flag{...}` survive being encrypted and the letters in front of
      them are a tag. Assuming a tag anyone would recognise settles those key
      positions by subtraction and leaves a handful to search exhaustively, which
      reaches keys no amount of counting or climbing could: a six letter key out
      of twelve letters, two per position
- [x] Cribs ranked by what they had to get right rather than by how the answer
      reads. A tag longer than the key reaches some position twice and has to
      agree with itself, and a wrong guess almost never does. That check is the
      only part of a crib that could have failed, so it is the only part that is
      evidence, and it decides. Readability cannot: `testCTF{W3lc0me2DaD@sh}` is
      a correct answer that reads like nothing at all
- [x] Layers, one key at a time. Two keys applied in turn are one cipher with a
      longer key, so they can never be recovered separately from the text alone.
      Given the first, the second is an ordinary problem again: applying a key
      that leaves something still enciphered now offers keys for what is under it
- [x] Vigenère keys worked out by climbing rather than counting. A column is
      solved by counting the letters in it, and a short text leaves two or three
      per column, which is nothing. Climbing judges a key letter by every trigram
      its letters touch instead, and on the shortest texts by the words the whole
      thing spells, since the spaces are evidence a letters-only view throws
      away. That took recovery from twelve letters per key position down to five:
      a seven letter key now comes back exactly from thirty-seven letters, and
      within one letter from seventeen
- [x] Vigenère, with the key and its length both worked out from the text,
      including keys stacked one on another: enciphering three times with keys of
      three, five and two letters is one cipher with a thirty letter key, and
      thirty letters is an ordinary key given a page to find it in
- [x] Affine, all 312 keys tried, of which Caesar is twenty-six
- [x] Transposition, rail fence and columnar, where the letters were never
      changed and only moved
- [x] Simple substitution, climbed rather than counted, against a trigram census
      of English measured from a corpus and committed as text
- [x] A letter frequency table, with the index of coincidence and every repeated
      pair and triple, for when no attack fires and the shape is the answer
- [x] A list of keys worked out of the text when you have none. Not common keys
      looked up: each is what falls out of splitting the letters into that many
      columns and counting each one, so a different ciphertext gives entirely
      different keys. Shown with how many letters each column had, since that is
      what decides whether a key is worth anything. Clicking one applies it
- [x] A key box, for the keys no amount of text would give up. Vigenère needs
      about sixty letters before its columns say anything, and a short puzzle has
      neither that nor an answer a scorer could confirm, so a supplied key is
      applied across Vigenère, Beaufort and XOR and every result shown unjudged
- [x] A short wordlist tried automatically, filling the gap between forty letters
      and sixty where a guess can be checked but a key cannot be counted out
- [x] Every rotation laid out when nothing reads, letters, digits and letters
      together, Atbash and reversed, ordered by which of them decode onward.
      Answers that are tokens or keys read like nothing, and against those the
      scorer is blind rather than wrong, so it stops guessing and hands over the
      list
- [x] RSA: small exponent, close primes, a shared prime between two keys, and a
      private exponent chosen too small

### Remora, the web-exploration half

- [x] A guard on where the scanner may reach, refusing loopback, private and
      link-local addresses, the cloud metadata endpoint among them, resolved once
      and connected to the vetted address so a name cannot answer public and turn
      private a moment later
- [x] A guarded fetch that follows redirects by hand, so every hop meets the
      guard again instead of being trusted by the HTTP client
- [x] A scanner started with one line per system, which downloads a prebuilt
      binary, checks it against a published checksum, and runs it on your own
      machine; the page finds it on its own and switches to a box for the target.
      No repository, no toolchain, nothing uploaded
- [x] A token and a single allowed origin, both chosen when the scanner starts,
      required on every request. The scanner is a service on your loopback, and
      this keeps another page on the same machine from turning it into a proxy of
      its own, which matters most once local targets are allowed
- [x] A crawl one level deep: the links, scripts, robots and sitemap followed to
      the pages nothing advertises, and a short list of the places a file gets
      left where it should not be tried by name, the /.git and /.env and a source
      backup among them
- [x] Every page read for a flag in plain sight: in the source, in a comment, in
      a linked filename, and in a response header, the plain `X-Flag` and the
      base64 cookie included
- [x] Encoded flags dug out of the source and headers and kept only when a flag
      falls out of the decoding: base64, hex, ROT13, a reversed-then-base64 ETag,
      a colour written as CSS escapes, and an array of numbers XORed against a
      byte with every byte tried. The same flag-shape filter the offline half uses
      keeps all of it quiet on a page that hid nothing
- [x] Images handed to Cuttlefish. Each is fetched through the scanner and opened
      in a new tab against the same tools a dropped picture gets, so the offline
      half reads a picture off a URL exactly as it reads one off a disk and still
      never touches the network itself
- [x] Active checks, off until you affirm you may test the target, since this is
      the half that sends rather than reads: a quote in a parameter to draw out an
      error, a privilege field into an update, the current time into a window that
      only opens for now, an internal marker into a header. Wordlist-driven, held
      to the target's own host, and bounded by a timeout so a stalling endpoint
      cannot hang the scan
- [x] A box for your own leads, each woven into every position at once, an
      endpoint, a parameter, a field and a header, on top of the built-in list, so
      a name you suspect is tried wherever it might belong without your having to
      say which it is
- [x] Signed tokens forged. A JWT found in a response has its key recovered the
      one way that cannot be fooled, the candidate whose HMAC reproduces the
      token's own signature, whether the site leaked the key in the token's own
      payload or left a weak one a short list guesses. With the key in hand a
      fresh token that names an administrator is signed and replayed against the
      endpoints that answered. SHA-256 and HMAC are written out here too, nothing
      borrowed

### Onboarding and reporting

- [x] A short guided tour on first load, walking through what to drop in and
      what to look for, using example files it builds in your browser
- [x] Three demo files, downloadable anytime from the page: an image with a
      flag in its low bits, an image with a flag in the bytes after it ends,
      and a tone with a flag in its samples
- [x] A list of flag shapes that detectors report against, `flag{`, `CTF{`,
      `key{` and more, edited in the header and saved with the page
- [x] A Markdown writeup of the whole analysis, taken to the clipboard or saved
      as a file, with every candidate and finding listed and generated on your
      machine, nothing uploaded

## Next

### Mantis

- [ ] Playfair and Hill, the two classical ciphers left that are not variations
      on something above
- [ ] Columnar transposition wider than eight columns, which needs the column
      order built up rather than tried exhaustively

### Remora

- [ ] Flows that take more than one request: a value decoded out of one response
      and carried into the next as a header or a host, the multi-step a single
      probe cannot reach on its own
- [ ] A wider wordlist and a deeper crawl, so more of a site's routes and
      parameters are found without a hint to point at them

### Forensics

- [ ] Looking inside PDF files
- [ ] Windows registry, for tracing which USB stick was plugged in when

### Steganography still open

- [ ] F5 detection. The published method needs a re-compressed copy of the
      original to compare against, and Trawl does not have one. Until it does,
      the coefficient counts are shown and you draw the conclusion.
- [ ] Audio hidden by echo or phase rather than by low bits
- [ ] WebP and TIFF, which no CTF has asked for yet

## Not planned

No accounts, no cloud storage, no history, no sharing.

No pwn. It needs a live server to hold onto, which a page in your browser cannot
give it. Web challenges are in reach now, through Remora, but only because Remora
is a separate scanner you run yourself: reaching a site is the one thing the
browser will not do for you.

No password cracking. That belongs on hardware you control, running something
built for it.
