import { encodePng, pngChunk } from '$lib/pixels/png-encode';
import { encodeWavPcm16 } from '$lib/tour/wav-encode';

const WIDTH = 160;
const HEIGHT = 110;
const PIXEL_FLAG = 'flag{welcome_to_trawl}';
const TRAILING_FLAG = 'flag{after_the_end}';
const AUDIO_FLAG = 'flag{can_you_hear_it}';
const NOTE = 'You found the pixels. Chi-square and the bit-plane wall read the same channel.';

function lerp(a: number, b: number, t: number): number {
	return Math.round(a + (b - a) * t);
}

/** A diagonal gradient between the app's own panel and signal hues, so the
 *  cover image reads as designed rather than as noise. */
function buildCover(): Uint8Array {
	const from = [24, 33, 38]; // --panel
	const to = [227, 178, 60]; // --signal
	const pixels = new Uint8Array(WIDTH * HEIGHT * 3);

	for (let y = 0; y < HEIGHT; y++) {
		for (let x = 0; x < WIDTH; x++) {
			const t = (x / (WIDTH - 1) + y / (HEIGHT - 1)) / 2;
			const o = (y * WIDTH + x) * 3;
			pixels[o] = lerp(from[0], to[0], t);
			pixels[o + 1] = lerp(from[1], to[1], t);
			pixels[o + 2] = lerp(from[2], to[2], t);
		}
	}

	return pixels;
}

/** Packs text as bits, MSB first, one bit per call to `write`. */
function bitsOf(text: string, write: (bit: number) => void): void {
	for (const byte of new TextEncoder().encode(text)) {
		for (let i = 7; i >= 0; i--) write((byte >> i) & 1);
	}
}

/** Bit 0 of the red channel, MSB-first, row-major: the plainest LSB scheme
 *  and the first combination the sweep's own brute force lands on. */
function embedInPixels(pixels: Uint8Array, text: string): void {
	let pixel = 0;
	bitsOf(text, (bit) => {
		pixels[pixel * 3] = (pixels[pixel * 3] & 0xfe) | bit;
		pixel++;
	});
}

function withTextChunk(png: Uint8Array, keyword: string, text: string): Uint8Array {
	const data = new Uint8Array(keyword.length + 1 + text.length);
	data.set(new TextEncoder().encode(keyword), 0);
	data[keyword.length] = 0;
	data.set(new TextEncoder().encode(text), keyword.length + 1);

	const tEXt = pngChunk('tEXt', data);
	const iendStart = png.length - 12; // IEND has no payload: 12 bytes, fixed
	const out = new Uint8Array(png.length + tEXt.length);
	out.set(png.subarray(0, iendStart), 0);
	out.set(tEXt, iendStart);
	out.set(png.subarray(iendStart), iendStart + tEXt.length);
	return out;
}

export type SampleFile = { name: string; bytes: Uint8Array; mime: string };

/** How a sample reaches the tools. `drop` runs the file analysis; `paste` reads
 *  the file as text and hands the line to Mantis, the way the crypto samples are
 *  meant to be used. */
export type SampleOpen = 'drop' | 'paste';

export type SampleEntry = {
	name: string;
	mime: string;
	blurb: string;
	open?: SampleOpen;
	build?: () => SampleFile;
	url?: string;
};

export type SampleGroup = {
	title: string;
	note?: string;
	entries: SampleEntry[];
};

/** A cover image with a flag hidden in its low bits, built from source at
 *  tour time instead of shipped as a binary. Nothing here is uploaded, and
 *  nothing here is untraceable either: every byte comes from this file. */
export function buildPixelDemo(): SampleFile {
	const pixels = buildCover();
	embedInPixels(pixels, PIXEL_FLAG);
	const png = encodePng(WIDTH, HEIGHT, 2, pixels);
	return { name: 'trawl-demo.png', bytes: withTextChunk(png, 'Trawl', NOTE), mime: 'image/png' };
}

/** The same cover, clean pixels, with a flag appended after IEND instead.
 *  The LSB sweep finds nothing here on purpose; the byte scan and the
 *  trailing-data tool are the ones built for this. */
export function buildTrailingDemo(): SampleFile {
	const png = encodePng(WIDTH, HEIGHT, 2, buildCover());
	const tail = new TextEncoder().encode(TRAILING_FLAG);
	const out = new Uint8Array(png.length + tail.length);
	out.set(png, 0);
	out.set(tail, png.length);
	return { name: 'trawl-trailing.png', bytes: out, mime: 'image/png' };
}

/** A short tone with a flag written into the low bit of every sample. */
export function buildAudioDemo(): SampleFile {
	const sampleRate = 8000;
	const seconds = 1.5;
	const count = Math.round(sampleRate * seconds);
	const samples = new Int16Array(count);

	for (let i = 0; i < count; i++) {
		samples[i] = Math.round(Math.sin((2 * Math.PI * 440 * i) / sampleRate) * 8000);
	}

	let sample = 0;
	bitsOf(AUDIO_FLAG, (bit) => {
		samples[sample] = (samples[sample] & ~1) | bit;
		sample++;
	});

	return {
		name: 'trawl-audio.wav',
		bytes: encodeWavPcm16(sampleRate, 1, samples),
		mime: 'audio/wav'
	};
}

/** The whole sample corpus, grouped the way static/samples/README.md is, so the
 *  demos panel reads as a labelled library rather than a flat list. `url` paths
 *  mirror the on-disk layout under static/samples/. */
export const SAMPLE_GROUPS: SampleGroup[] = [
	{
		title: 'Starter demos',
		note: 'Built in your browser, each with a flag hidden a different way.',
		entries: [
			{
				name: 'trawl-demo.png',
				mime: 'image/png',
				build: buildPixelDemo,
				blurb: 'A flag in the low bit of the red channel. The one from the tour.'
			},
			{
				name: 'trawl-trailing.png',
				mime: 'image/png',
				build: buildTrailingDemo,
				blurb:
					'A flag stuck on after the image ends. The pixels are clean, so the LSB sweep stays quiet and the byte scan finds it.'
			},
			{
				name: 'trawl-audio.wav',
				mime: 'audio/wav',
				build: buildAudioDemo,
				blurb: 'A short tone with a flag written into the low bit of every sample.'
			}
		]
	},
	{
		title: 'Built-in practice',
		note: 'The four files the tour points at, loaded straight from the app.',
		entries: [
			{
				name: 'spectrogram-source.png',
				mime: 'image/png',
				url: '/samples/spectrogram-source.png',
				blurb: 'The source picture drawn into the matching WAV spectrogram.'
			},
			{
				name: 'spectrogram-and-lsb.wav',
				mime: 'audio/wav',
				url: '/samples/spectrogram-and-lsb.wav',
				blurb: 'The spectrogram recovers the picture; the audio LSB sweep reads flag{S@lutations}.'
			},
			{
				name: 'palette-clean.png',
				mime: 'image/png',
				url: '/samples/palette-clean.png',
				blurb: 'A clean indexed image. Palette analysis should find no duplicate-colour capacity.'
			},
			{
				name: 'palette-duplicate.png',
				mime: 'image/png',
				url: '/samples/palette-duplicate.png',
				blurb: 'The same picture with duplicate palette entries that carry hidden capacity.'
			}
		]
	},
	{
		title: 'Clean controls',
		note: 'Nothing is hidden here. A detector should stay quiet on ordinary input.',
		entries: [
			{
				name: 'clean.png',
				mime: 'image/png',
				url: '/samples/controls/clean.png',
				blurb: 'Decodes cleanly while the steganography detectors stay quiet.'
			},
			{
				name: 'clean-jpeg.jpg',
				mime: 'image/jpeg',
				url: '/samples/controls/clean-jpeg.jpg',
				blurb: 'A baseline JPEG with readable coefficients and no planted payload.'
			},
			{
				name: 'clean-wav.wav',
				mime: 'audio/wav',
				url: '/samples/controls/clean-wav.wav',
				blurb: 'The waveform parses and the payload detectors stay quiet.'
			}
		]
	},
	{
		title: 'Survey and structure',
		entries: [
			{
				name: 'readable-text.bin',
				mime: 'application/octet-stream',
				url: '/samples/survey/readable-text.bin',
				blurb: 'flag{plain_file_scan} as ASCII and flag{utf16_readable_text} as UTF-16LE.'
			},
			{
				name: 'entropy-contrast.bin',
				mime: 'application/octet-stream',
				url: '/samples/survey/entropy-contrast.bin',
				blurb: 'A low-entropy text region, a high-entropy random region, and a flat zero region.'
			},
			{
				name: 'png-text-chunk.png',
				mime: 'image/png',
				url: '/samples/survey/png-text-chunk.png',
				blurb: 'flag{hidden_in_a_text_chunk} read from a tEXt chunk.'
			},
			{
				name: 'png-zlib-text.png',
				mime: 'image/png',
				url: '/samples/survey/png-zlib-text.png',
				blurb: 'Inflates a zTXt chunk to flag{compressed_text_chunk}.'
			},
			{
				name: 'png-post-iend.png',
				mime: 'image/png',
				url: '/samples/survey/png-post-iend.png',
				blurb: 'Data after IEND: flag{parked_after_iend} and a ZIP signature.'
			},
			{
				name: 'png-bad-crc.png',
				mime: 'image/png',
				url: '/samples/survey/png-bad-crc.png',
				blurb: 'Reports a deliberately corrupted IHDR checksum.'
			},
			{
				name: 'jpeg-exif.jpg',
				mime: 'image/jpeg',
				url: '/samples/survey/jpeg-exif.jpg',
				blurb: 'flag{read_the_metadata} from EXIF ImageDescription.'
			},
			{
				name: 'png-exif.png',
				mime: 'image/png',
				url: '/samples/survey/png-exif.png',
				blurb: 'flag{png_carries_exif_too} from a PNG eXIf chunk.'
			},
			{
				name: 'gif-comment.gif',
				mime: 'image/gif',
				url: '/samples/survey/gif-comment.gif',
				blurb: 'flag{gif_comment_block} from a comment, plus a duplicate palette entry.'
			},
			{
				name: 'wav-riff-comment.wav',
				mime: 'audio/wav',
				url: '/samples/survey/wav-riff-comment.wav',
				blurb: 'flag{riff_comment_chunk} from a LIST/INFO comment.'
			},
			{
				name: 'wav-trailing.wav',
				mime: 'audio/wav',
				url: '/samples/survey/wav-trailing.wav',
				blurb: 'Bytes outside the RIFF length: flag{past_the_declared_end}.'
			},
			{
				name: 'carved-zlib-text-png.bin',
				mime: 'application/octet-stream',
				url: '/samples/survey/carved-zlib-text-png.bin',
				blurb: 'Carves an embedded PNG and reads flag{compressed_text_chunk} from it.'
			}
		]
	},
	{
		title: 'Archives and recursion',
		entries: [
			{
				name: 'recursive-files.zip',
				mime: 'application/zip',
				url: '/samples/archives/recursive-files.zip',
				blurb: 'Opens inner.zip, analyses clue.png inside it, recovers flag{compressed_text_chunk}.'
			},
			{
				name: 'doctored-directory.zip',
				mime: 'application/zip',
				url: '/samples/archives/doctored-directory.zip',
				blurb:
					'A hidden entry, a size disagreement, the comment flag{zip_archive_comment}, and flag{zip_entry_missing_from_directory}.'
			}
		]
	},
	{
		title: 'Cuttlefish: images',
		entries: [
			{
				name: 'png-lsb-rgb.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-lsb-rgb.png',
				blurb: 'testCTF{rgb_msb_first} from RGB bit 0, MSB first.'
			},
			{
				name: 'png-lsb-blue.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-lsb-blue.png',
				blurb: 'flag{blue_channel_lsb_first} from blue bit 0, LSB first.'
			},
			{
				name: 'bmp-lsb.bmp',
				mime: 'image/bmp',
				url: '/samples/cuttlefish/bmp-lsb.bmp',
				blurb: 'flag{bitmaps_hide_things_too} from an uncompressed BMP.'
			},
			{
				name: 'png-bit-plane-region.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-bit-plane-region.png',
				blurb:
					'A rectangular low-bit region on the bit-plane wall. Noise, not text, so extraction stays quiet.'
			},
			{
				name: 'png-embedded-25.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-embedded-25.png',
				blurb: 'Sequential low-bit embedding over the first 25 percent of RGB samples.'
			},
			{
				name: 'png-embedded-50.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-embedded-50.png',
				blurb: 'Sequential low-bit embedding over the first 50 percent of RGB samples.'
			},
			{
				name: 'png-embedded-100.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-embedded-100.png',
				blurb: 'Sequential low-bit embedding over all RGB samples.'
			},
			{
				name: 'png-palette-message.png',
				mime: 'image/png',
				url: '/samples/cuttlefish/png-palette-message.png',
				blurb: 'flag{the_palette_chose_these_bits} from choices between identical palette entries.'
			},
			{
				name: 'gif-frame-lsb.gif',
				mime: 'image/gif',
				url: '/samples/cuttlefish/gif-frame-lsb.gif',
				blurb: 'flag{gif_second_frame_lsb} in displayed frame 2.'
			},
			{
				name: 'gif-difference-lsb.gif',
				mime: 'image/gif',
				url: '/samples/cuttlefish/gif-difference-lsb.gif',
				blurb: 'flag{only_the_frame_difference_reads} in the difference between frames 1 and 2.'
			}
		]
	},
	{
		title: 'Cuttlefish: JPEG',
		entries: [
			{
				name: 'jpeg-jsteg.jpg',
				mime: 'image/jpeg',
				url: '/samples/cuttlefish/jpeg-jsteg.jpg',
				blurb: 'flag{jsteg_lives_in_the_coefficients} from baseline JPEG coefficients.'
			},
			{
				name: 'jpeg-jsteg-full.jpg',
				mime: 'image/jpeg',
				url: '/samples/cuttlefish/jpeg-jsteg-full.jpg',
				blurb:
					'A saturated coefficient payload for the JPEG chi-square detector. Binary filler, no flag text.'
			},
			{
				name: 'jpeg-jsteg-progressive.jpg',
				mime: 'image/jpeg',
				url: '/samples/cuttlefish/jpeg-jsteg-progressive.jpg',
				blurb: 'flag{progressive_still_reads} across progressive scans.'
			}
		]
	},
	{
		title: 'Cuttlefish: audio',
		entries: [
			{
				name: 'wav-lsb.wav',
				mime: 'audio/wav',
				url: '/samples/cuttlefish/wav-lsb.wav',
				blurb: 'flag{the_low_bits_of_the_waveform} from mono sample bit 0.'
			},
			{
				name: 'wav-lsb-right.wav',
				mime: 'audio/wav',
				url: '/samples/cuttlefish/wav-lsb-right.wav',
				blurb: 'flag{right_channel_carries_it} from the right channel only.'
			},
			{
				name: 'wav-spectrogram.wav',
				mime: 'audio/wav',
				url: '/samples/cuttlefish/wav-spectrogram.wav',
				blurb: 'Draws the word TRAWL in the frequency display.'
			},
			{
				name: 'wav-morse.wav',
				mime: 'audio/wav',
				url: '/samples/cuttlefish/wav-morse.wav',
				blurb: 'Tone analysis decodes SOS as Morse.'
			},
			{
				name: 'wav-dtmf.wav',
				mime: 'audio/wav',
				url: '/samples/cuttlefish/wav-dtmf.wav',
				blurb: 'Tone analysis decodes the DTMF sequence 2580.'
			}
		]
	},
	{
		title: 'Mantis and AES',
		note: 'Check a paste sample to run it in place, or download it to paste the line yourself. The AES file drops in like any other.',
		entries: [
			{
				name: 'mantis-base64-gzip.txt',
				mime: 'text/plain',
				url: '/samples/crypto/mantis-base64-gzip.txt',
				open: 'paste',
				blurb: 'Peels base64, inflates gzip, reads flag{mantis_reached_through_gzip}.'
			},
			{
				name: 'mantis-base64-zlib.txt',
				mime: 'text/plain',
				url: '/samples/crypto/mantis-base64-zlib.txt',
				open: 'paste',
				blurb: 'Peels base64, inflates zlib, reads flag{mantis_reached_through_zlib}.'
			},
			{
				name: 'mantis-hex-base64.txt',
				mime: 'text/plain',
				url: '/samples/crypto/mantis-hex-base64.txt',
				open: 'paste',
				blurb: 'Peels hex, then base64, reads flag{mantis_hex_then_base64}.'
			},
			{
				name: 'aes-cbc.txt',
				mime: 'text/plain',
				url: '/samples/crypto/aes-cbc.txt',
				blurb:
					'Drop it: the AES-CBC probe joins the hex key and IV with the base64 ciphertext to decrypt CTF{aes_key_carried_in_plain_sight}.'
			}
		]
	}
];

export async function loadSample(entry: SampleEntry): Promise<SampleFile> {
	if (entry.build) return entry.build();
	if (!entry.url) throw new Error(`No source for ${entry.name}`);

	const response = await fetch(entry.url);
	if (!response.ok) throw new Error(`Could not load ${entry.name} (${response.status})`);
	return {
		name: entry.name,
		bytes: new Uint8Array(await response.arrayBuffer()),
		mime: entry.mime
	};
}

export function downloadSample(file: SampleFile): void {
	const url = URL.createObjectURL(
		new Blob([file.bytes as Uint8Array<ArrayBuffer>], { type: file.mime })
	);
	const link = document.createElement('a');
	link.href = url;
	link.download = file.name;
	link.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}
