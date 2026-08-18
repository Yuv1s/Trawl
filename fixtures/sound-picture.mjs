// Turns a picture into a sound whose spectrogram is that picture, and writes a
// message into the low bits of the same file.
//
//   npm run demo:wav -- path/to/image.png "flag{your_message}"
//
// The result is a real WAV that plays as harsh static. Nothing about listening
// to it reveals anything. Both of Trawl's audio tools should light up on it: the
// spectrogram draws the picture back, and the LSB sweep reads the message.
//
// The PNG is decoded by Trawl's own decoder rather than a second one written
// here, so the demo exercises the same code the app does.

import { readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';
import { inflateSync } from 'node:zlib';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const wasmPath = require.resolve('../src/lib/wasm/trawl_core.js');
const { initSync, png_decode, png_dimensions, png_idat } = await import(
	`file:///${wasmPath.replace(/\\/g, '/')}`
);

initSync({ module: readFileSync(join(dirname(wasmPath), 'trawl_core_bg.wasm')) });

const RATE = 22050;

/** The picture starts here. Below 500 Hz sits under any hum. */
const LOW_HZ = 500;
/** Nothing is drawn above this: the top of the range is where dither lives. */
const CEILING_HZ = 10000;

/**
 * How much audio one column of the picture gets.
 *
 * This is the number that decides whether the result is legible. Trawl analyses
 * the sound in 1024-sample windows stepping 256 at a time, so a column thinner
 * than a window smears into its neighbours and the picture turns to mush. Four
 * steps per column keeps them separate.
 */
const SAMPLES_PER_COLUMN = 1024;

/** Past this the columns get too thin for the transform to resolve. */
const MAX_COLUMNS = 200;
/** Past this the rows land closer together than the transform can separate. */
const MAX_ROWS = 72;

/** Trawl analyses with a 1024-point transform, giving this many frequency bins. */
const BINS = 512;
const HZ_PER_BIN = RATE / 2 / BINS;
/** Spectrogram columns each source column turns into, at the default hop. */
const COLUMNS_PER_CELL = SAMPLES_PER_COLUMN / 256;

const [, , imagePath, message = 'flag{drawn_in_the_sound}'] = process.argv;

if (!imagePath) {
	console.error('usage: npm run demo:wav -- path/to/image.png "your message"');
	process.exit(1);
}

const png = new Uint8Array(readFileSync(imagePath));
const [sourceWidth, sourceHeight] = png_dimensions(png);
const rgba = png_decode(png, new Uint8Array(inflateSync(Buffer.from(png_idat(png)))));

/**
 * Ink at a pixel, 0 to 1.
 *
 * Inverted, because a person draws dark marks on light paper and it is the
 * marks that should make the sound. Transparent pixels count as paper.
 */
function ink(x, y) {
	const at = (y * sourceWidth + x) * 4;
	const alpha = rgba[at + 3] / 255;
	const grey = (rgba[at] * 0.299 + rgba[at + 1] * 0.587 + rgba[at + 2] * 0.114) / 255;
	return (1 - grey) * alpha;
}

// Scale to something the transform can actually resolve, averaging over each
// source block rather than sampling one pixel, so thin strokes survive.
const width = Math.min(MAX_COLUMNS, sourceWidth);

// The frequency band follows the picture's own proportions. Spreading every
// image across the full range instead would stretch a wide one until the letters
// are unreadable bands, which is what a first attempt at this did.
const wanted = Math.round((width * COLUMNS_PER_CELL * sourceHeight) / sourceWidth);
const bandBins = Math.max(48, Math.min(Math.round((CEILING_HZ - LOW_HZ) / HZ_PER_BIN), wanted));
const highHz = LOW_HZ + bandBins * HZ_PER_BIN;

// Four bins per row keeps neighbouring tones from bleeding into each other.
const height = Math.max(4, Math.min(MAX_ROWS, sourceHeight, Math.floor(bandBins / 4)));
const cell = new Float32Array(width * height);

for (let y = 0; y < height; y++) {
	const y0 = Math.floor((y * sourceHeight) / height);
	const y1 = Math.max(y0 + 1, Math.floor(((y + 1) * sourceHeight) / height));

	for (let x = 0; x < width; x++) {
		const x0 = Math.floor((x * sourceWidth) / width);
		const x1 = Math.max(x0 + 1, Math.floor(((x + 1) * sourceWidth) / width));

		let sum = 0;
		let n = 0;
		for (let sy = y0; sy < y1; sy++) {
			for (let sx = x0; sx < x1; sx++) {
				sum += ink(sx, sy);
				n++;
			}
		}
		cell[y * width + x] = sum / n;
	}
}

const total = width * SAMPLES_PER_COLUMN;
const samples = new Float64Array(total);
let voices = 0;

for (let y = 0; y < height; y++) {
	const row = cell.subarray(y * width, (y + 1) * width);
	if (!row.some((v) => v > 0.25)) continue;
	voices++;

	// Rows run top to bottom, so the top of the picture is the highest note.
	const hz = LOW_HZ + ((height - 1 - y) / Math.max(1, height - 1)) * (highHz - LOW_HZ);

	// One continuous oscillator per row, its volume following the row across the
	// picture. Restarting a tone at every column would click, and a click is
	// broadband: it draws a vertical line through everything.
	const phase = (y * 2.399963) % (2 * Math.PI);

	for (let i = 0; i < total; i++) {
		const at = i / SAMPLES_PER_COLUMN - 0.5;
		const left = Math.floor(at);
		const blend = at - left;

		const a = row[Math.max(0, Math.min(width - 1, left))];
		const b = row[Math.max(0, Math.min(width - 1, left + 1))];

		// Sliding between columns rather than stepping keeps the edges soft, and
		// easing the slide rather than ramping it straight keeps them softer
		// still. A straight ramp has a corner at each column boundary, and thirty
		// tones all cornering on the same sample add up to a click, which draws a
		// vertical line through the whole picture.
		const eased = blend * blend * (3 - 2 * blend);
		const level = a + (b - a) * eased;
		if (level <= 0.02) continue;

		samples[i] += Math.sin((2 * Math.PI * hz * i) / RATE + phase) * level;
	}
}

if (voices === 0) {
	console.error('nothing to draw: the image is blank, or its marks are too faint');
	process.exit(1);
}

let peak = 0;
for (const s of samples) peak = Math.max(peak, Math.abs(s));
const pcm = Array.from(samples, (s) => Math.round((s / (peak || 1)) * 12000));

// The second payload, in the low bit of every sample. That sits about ninety
// decibels under the sound, so it changes nothing you can hear and nothing you
// can see in the spectrogram.
const bytes = Buffer.from(`${message}\0`, 'latin1');
for (let i = 0; i < bytes.length * 8 && i < pcm.length; i++) {
	const bit = (bytes[i >> 3] >> (7 - (i % 8))) & 1;
	pcm[i] = (pcm[i] & ~1) | bit;
}

function wav(frames, rate) {
	const data = Buffer.alloc(frames.length * 2);
	frames.forEach((s, i) => data.writeInt16LE(Math.max(-32768, Math.min(32767, s)), i * 2));

	const fmt = Buffer.alloc(16);
	fmt.writeUInt16LE(1, 0);
	fmt.writeUInt16LE(1, 2);
	fmt.writeUInt32LE(rate, 4);
	fmt.writeUInt32LE(rate * 2, 8);
	fmt.writeUInt16LE(2, 12);
	fmt.writeUInt16LE(16, 14);

	const chunk = (id, payload) => {
		const head = Buffer.alloc(8);
		head.write(id, 0, 'latin1');
		head.writeUInt32LE(payload.length, 4);
		return Buffer.concat([head, payload]);
	};

	const body = Buffer.concat([
		Buffer.from('WAVE', 'latin1'),
		chunk('fmt ', fmt),
		chunk('data', data)
	]);

	const head = Buffer.alloc(8);
	head.write('RIFF', 0, 'latin1');
	head.writeUInt32LE(body.length, 4);
	return Buffer.concat([head, body]);
}

const out = join(dirname(imagePath), `${basename(imagePath, extname(imagePath))}.wav`);
writeFileSync(out, wav(pcm, RATE));

console.log(
	`${basename(imagePath)}: ${sourceWidth} x ${sourceHeight}, drawn at ${width} x ${height}`
);
console.log(`${voices} tones between ${LOW_HZ} and ${Math.round(highHz)} Hz`);
if (sourceWidth / sourceHeight > 4) {
	console.log('note: a wide picture lands in a thin band. Squarer images read better.');
}
console.log(`${(total / RATE).toFixed(1)} seconds of audio`);
console.log(`message in the low bits: ${message}`);
console.log(`\nwrote ${out}`);
console.log('drop it into Trawl: the spectrogram draws the picture, the LSB sweep reads the text');
