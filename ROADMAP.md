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
- [x] Thirteen encodings: base64, base32, ascii85, hex, morse, binary and the
      rest
- [x] Caesar, solved rather than applied: every shift tried, the readable one
      kept
- [x] XOR key recovery, single byte and repeating key, with the key length
      worked out rather than asked for

## Next

### Mantis

- [ ] Hash identification, from length and alphabet
- [ ] Vigenère and substitution, which need a stronger language model than the
      word list the peeler uses
- [ ] RSA weaknesses that turn up in competitions

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
