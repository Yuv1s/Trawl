# Trawl sample files

These files exercise Trawl's current detectors with known answers. Drop an image, audio file, archive, or `.bin` file onto Trawl. For a file under `crypto/`, follow the instruction in that section.

The controls contain nothing hidden. They matter because a detector should stay quiet on ordinary input, not merely find planted data.

The four files at the top of this directory stay at fixed paths because the in-app demos load them from `/samples/`.

## Built-in practice files

| File | Open with | Expected result |
| --- | --- | --- |
| [`spectrogram-source.png`](spectrogram-source.png) | Drop | Source picture used to make the matching audio sample. Pixel tools run normally. |
| [`spectrogram-and-lsb.wav`](spectrogram-and-lsb.wav) | Drop | Spectrogram recovers the source picture. Audio LSB sweep reads `flag{S@lutations}`. |
| [`palette-clean.png`](palette-clean.png) | Drop | Clean indexed-image control. Palette analysis should find no duplicate-colour capacity. |
| [`palette-duplicate.png`](palette-duplicate.png) | Drop | Palette analysis reports equivalent entries and their hiding capacity. |

## Clean controls

| File | Tools checked | Expected result |
| --- | --- | --- |
| [`controls/clean.png`](controls/clean.png) | Pixel decode, LSB sweep, chi-square, RS analysis, bit-plane wall, entropy | The image decodes, while the steganography detectors stay quiet. |
| [`controls/clean-jpeg.jpg`](controls/clean-jpeg.jpg) | JPEG segments, JSteg, coefficient statistics | The baseline JPEG has readable coefficients and no planted payload. |
| [`controls/clean-wav.wav`](controls/clean-wav.wav) | RIFF chunks, spectrogram, tones, audio LSB | The waveform parses and the payload detectors stay quiet. |

## Survey and file structure

| File | Main tools | Expected result |
| --- | --- | --- |
| [`survey/readable-text.bin`](survey/readable-text.bin) | Flag scan, readable text | Finds `flag{plain_file_scan}` as ASCII and `flag{utf16_readable_text}` as UTF-16LE. |
| [`survey/entropy-contrast.bin`](survey/entropy-contrast.bin) | Entropy window | Shows a low-entropy text region, a high-entropy pseudorandom region, and a flat zero region. |
| [`survey/png-text-chunk.png`](survey/png-text-chunk.png) | PNG text chunks, flag scan, chunk walk | Reads `flag{hidden_in_a_text_chunk}` from a `tEXt` chunk. |
| [`survey/png-zlib-text.png`](survey/png-zlib-text.png) | PNG text chunks, chunk walk | Inflates a `zTXt` chunk and reads `flag{compressed_text_chunk}`. |
| [`survey/png-post-iend.png`](survey/png-post-iend.png) | Post-IEND data, embedded files, flag scan | Reports data after `IEND`, including `flag{parked_after_iend}` and a ZIP signature. |
| [`survey/png-bad-crc.png`](survey/png-bad-crc.png) | PNG chunk CRC, chunk walk | Reports a deliberately corrupted `IHDR` checksum. |
| [`survey/jpeg-exif.jpg`](survey/jpeg-exif.jpg) | Metadata, JPEG segments, flag scan | Reads `flag{read_the_metadata}` from EXIF `ImageDescription`. |
| [`survey/png-exif.png`](survey/png-exif.png) | Metadata, PNG chunk walk | Reads `flag{png_carries_exif_too}` from a PNG `eXIf` chunk. |
| [`survey/gif-comment.gif`](survey/gif-comment.gif) | Readable text, GIF palette, GIF frame analysis | Reads `flag{gif_comment_block}` from a comment and reports a duplicate palette entry. |
| [`survey/wav-riff-comment.wav`](survey/wav-riff-comment.wav) | RIFF chunks, readable text | Reads `flag{riff_comment_chunk}` from a `LIST/INFO` comment. |
| [`survey/wav-trailing.wav`](survey/wav-trailing.wav) | RIFF chunks, flag scan | Reports bytes outside the RIFF length and finds `flag{past_the_declared_end}`. |
| [`survey/carved-zlib-text-png.bin`](survey/carved-zlib-text-png.bin) | Embedded files, recursive analysis | Carves an embedded PNG, walks its chunks, inflates `zTXt`, and reads `flag{compressed_text_chunk}`. |

## ZIP and recursive analysis

| File | Main tools | Expected result |
| --- | --- | --- |
| [`archives/recursive-files.zip`](archives/recursive-files.zip) | Archive entries, recursive analysis | Opens `inner.zip`, then analyses `clue.png` inside it and recovers `flag{compressed_text_chunk}` from compressed PNG text. |
| [`archives/doctored-directory.zip`](archives/doctored-directory.zip) | Archive entries, flag scan | Reports `.hidden.txt` missing from the central directory, a local/directory size disagreement, an encrypted marker, the archive comment `flag{zip_archive_comment}`, and bytes after the end. The hidden entry contains `flag{zip_entry_missing_from_directory}`. |

## Cuttlefish image tools

| File | Main tools | Expected result |
| --- | --- | --- |
| [`cuttlefish/png-lsb-rgb.png`](cuttlefish/png-lsb-rgb.png) | LSB sweep, bit-plane wall | Reads `testCTF{rgb_msb_first}` from RGB bit 0, MSB first. |
| [`cuttlefish/png-lsb-blue.png`](cuttlefish/png-lsb-blue.png) | LSB sweep, bit-plane wall | Reads `flag{blue_channel_lsb_first}` from blue bit 0, LSB first. |
| [`cuttlefish/bmp-lsb.bmp`](cuttlefish/bmp-lsb.bmp) | Pixel decode, LSB sweep, bit-plane wall | Reads `flag{bitmaps_hide_things_too}` from an uncompressed BMP. |
| [`cuttlefish/png-bit-plane-region.png`](cuttlefish/png-bit-plane-region.png) | Bit-plane wall | Makes a rectangular low-bit region visible. The region carries noise rather than text, so LSB text extraction should stay quiet. |
| [`cuttlefish/png-embedded-25.png`](cuttlefish/png-embedded-25.png) | Chi-square, RS analysis | Sequential low-bit embedding over the first 25 percent of RGB samples. |
| [`cuttlefish/png-embedded-50.png`](cuttlefish/png-embedded-50.png) | Chi-square, RS analysis | Sequential low-bit embedding over the first 50 percent of RGB samples. |
| [`cuttlefish/png-embedded-100.png`](cuttlefish/png-embedded-100.png) | Chi-square, RS analysis | Sequential low-bit embedding over all RGB samples. |
| [`cuttlefish/png-palette-message.png`](cuttlefish/png-palette-message.png) | Palette steganography | Reads `flag{the_palette_chose_these_bits}` from choices between identical palette entries. |
| [`cuttlefish/gif-frame-lsb.gif`](cuttlefish/gif-frame-lsb.gif) | GIF frames, LSB sweep | Finds `flag{gif_second_frame_lsb}` in displayed frame 2. |
| [`cuttlefish/gif-difference-lsb.gif`](cuttlefish/gif-difference-lsb.gif) | GIF frames, consecutive differences | Finds `flag{only_the_frame_difference_reads}` in the difference between frames 1 and 2. |

## Cuttlefish JPEG tools

| File | Main tools | Expected result |
| --- | --- | --- |
| [`cuttlefish/jpeg-jsteg.jpg`](cuttlefish/jpeg-jsteg.jpg) | JSteg sweep | Reads `flag{jsteg_lives_in_the_coefficients}` from baseline JPEG coefficients. |
| [`cuttlefish/jpeg-jsteg-full.jpg`](cuttlefish/jpeg-jsteg-full.jpg) | JPEG coefficient statistics | Shows a saturated coefficient payload for the JPEG chi-square detector. The filler is binary and has no flag text. |
| [`cuttlefish/jpeg-jsteg-progressive.jpg`](cuttlefish/jpeg-jsteg-progressive.jpg) | Progressive JPEG parser, JSteg sweep | Reads `flag{progressive_still_reads}` across progressive scans. |

## Cuttlefish audio tools

| File | Main tools | Expected result |
| --- | --- | --- |
| [`cuttlefish/wav-lsb.wav`](cuttlefish/wav-lsb.wav) | Audio LSB sweep | Reads `flag{the_low_bits_of_the_waveform}` from mono sample bit 0. |
| [`cuttlefish/wav-lsb-right.wav`](cuttlefish/wav-lsb-right.wav) | Audio LSB sweep | Reads `flag{right_channel_carries_it}` from the right channel only. |
| [`cuttlefish/wav-spectrogram.wav`](cuttlefish/wav-spectrogram.wav) | Spectrogram | Draws the word `TRAWL` in the frequency display. |
| [`cuttlefish/wav-morse.wav`](cuttlefish/wav-morse.wav) | Spectrogram and tones | Tone analysis decodes `SOS` as Morse. |
| [`cuttlefish/wav-dtmf.wav`](cuttlefish/wav-dtmf.wav) | Spectrogram and tones | Tone analysis decodes the DTMF sequence `2580`. |

## Mantis and AES

Mantis accepts pasted text. Open a `.txt` file below, copy its single encoded line, and paste that line into Trawl. The AES file is different: drop the file onto Trawl so the file analysis can locate its key, IV, and ciphertext together.

| File | How to use it | Expected result |
| --- | --- | --- |
| [`crypto/mantis-base64-gzip.txt`](crypto/mantis-base64-gzip.txt) | Paste | Peels base64, inflates gzip, and reads `flag{mantis_reached_through_gzip}`. |
| [`crypto/mantis-base64-zlib.txt`](crypto/mantis-base64-zlib.txt) | Paste | Peels base64, inflates zlib, and reads `flag{mantis_reached_through_zlib}`. |
| [`crypto/mantis-hex-base64.txt`](crypto/mantis-hex-base64.txt) | Paste | Peels hex, then base64, and reads `flag{mantis_hex_then_base64}`. |
| [`crypto/aes-cbc.txt`](crypto/aes-cbc.txt) | Drop | AES-CBC probe combines the hex key and IV with the base64 ciphertext and decrypts `CTF{aes_key_carried_in_plain_sight}`. |

## Regeneration

Most files in this public corpus are copies of deterministic fixtures produced by [`fixtures/generate.mjs`](../../fixtures/generate.mjs). The focused archive, GIF, tone, AES, compression, carving, and entropy samples were generated with Node built-ins for this corpus. No application source or runtime dependency is required to use them.
