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

## Next

### Mantis

- [ ] Playfair and Hill, the two classical ciphers left that are not variations
      on something above
- [ ] Columnar transposition wider than eight columns, which needs the column
      order built up rather than tried exhaustively

### Forensics

- [ ] Looking inside ZIP and PDF files
- [ ] Windows registry, for tracing which USB stick was plugged in when

### Steganography still open

- [ ] F5 detection. The published method needs a re-compressed copy of the
      original to compare against, and Trawl does not have one. Until it does,
      the coefficient counts are shown and you draw the conclusion.
- [ ] Audio hidden by echo or phase rather than by low bits
- [ ] WebP and TIFF, which no CTF has asked for yet

## Not planned

No accounts, no cloud storage, no history, no sharing.

No pwn or web challenges. Both need a live server to talk to, and Trawl is a
page in your browser.

No password cracking. That belongs on hardware you control, running something
built for it.
