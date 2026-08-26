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

export const SAMPLE_FILES: { build: () => SampleFile; blurb: string }[] = [
	{
		build: buildPixelDemo,
		blurb: 'The file from the tour. A flag sits in the low bit of the red channel.'
	},
	{
		build: buildTrailingDemo,
		blurb:
			'A flag stuck on after the image ends. The pixels are clean, so the LSB sweep finds nothing, but a byte scan will.'
	},
	{
		build: buildAudioDemo,
		blurb: 'A short tone with a flag written into the low bit of every sample.'
	}
];

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
