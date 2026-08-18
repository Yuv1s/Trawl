// Regenerates every test input from scratch. Run `npm run fixtures`.
//
// Nothing binary is committed: the outputs are gitignored and rebuilt from this
// file, so any detection result the README or the test suite claims can be
// reproduced from source rather than taken on trust.
//
// Node's zlib is used for deflate. That is a build-time convenience for making
// fixtures, not a runtime dependency of Trawl, which ships none.

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const OUT = dirname(fileURLToPath(import.meta.url));

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

const crc32 = (bytes) => {
	let c = 0xffffffff;
	for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
};

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function chunk(type, data) {
	const out = Buffer.alloc(12 + data.length);
	out.writeUInt32BE(data.length, 0);
	out.write(type, 4, 'latin1');
	Buffer.from(data).copy(out, 8);
	out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
	return out;
}

/** Deterministic, so a fixture is identical on every machine and every run. */
function rng(seed) {
	let s = seed >>> 0;
	return () => {
		s ^= s << 13;
		s >>>= 0;
		s ^= s >>> 17;
		s ^= s << 5;
		s >>>= 0;
		return s;
	};
}

/**
 * A cover with the properties real photographs have and synthetic gradients do
 * not: a lumpy histogram, and local texture where neighbours differ by small
 * non-zero amounts.
 *
 * This matters more than it sounds. A pure gradient is so smooth that adjacent
 * pixels are identical, which degenerates RS analysis, and its upper bit planes
 * repeat a short cycle, which produced eighteen false positives in an earlier
 * build of the LSB sweep. A fixture that does not behave like real data tests
 * nothing.
 */
function cover(width, height) {
	const px = Buffer.alloc(width * height * 4);

	for (let y = 0; y < height; y++) {
		for (let x = 0; x < width; x++) {
			const o = (y * width + x) * 4;
			const nx = x / width;
			const ny = y / height;
			const r = Math.hypot(nx - 0.5, ny - 0.5);

			const detail = 5 * Math.sin(x * 0.9) + 4 * Math.cos(y * 1.1) + 3 * Math.sin((x + y) * 0.35);

			// A tone curve, which is the other property real photographs have and
			// smooth gradients do not. A gradient spreads values evenly, so the
			// counts of 2i and 2i+1 come out equal by accident, and that is
			// precisely what chi-square reads as a payload. Bunching the values
			// gives the histogram the local slope the test needs to see.
			const level = (base) => {
				const t = Math.min(1, Math.max(0, (base + detail) / 255));
				return Math.max(2, Math.min(253, Math.round(255 * Math.pow(t, 1.9))));
			};

			px[o] = level(180 - 96 * r);
			px[o + 1] = level(138 + 52 * Math.sin(nx * 3));
			px[o + 2] = level(100 + 48 * Math.cos(ny * 2));
			px[o + 3] = 255;
		}
	}

	return px;
}

function encode(width, height, pixels, extraChunks = []) {
	const stride = width * 4;
	const raw = Buffer.alloc((stride + 1) * height);
	for (let y = 0; y < height; y++) {
		raw[y * (stride + 1)] = 0;
		pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
	}

	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8;
	ihdr[9] = 6; // truecolour with alpha

	return Buffer.concat([
		SIGNATURE,
		chunk('IHDR', ihdr),
		...extraChunks,
		chunk('IDAT', deflateSync(raw, { level: 9 })),
		chunk('IEND', Buffer.alloc(0))
	]);
}

const CHANNELS = { r: [0], g: [1], b: [2], rgb: [0, 1, 2], bgr: [2, 1, 0] };

/** Writes bytes into a chosen bit plane, in a chosen channel and bit order. */
function embedMessage(px, text, { channels = 'rgb', bit = 0, order = 'msb' } = {}) {
	const idx = CHANNELS[channels];
	const bits = [];
	for (const byte of Buffer.from(`${text}\0`, 'latin1')) {
		for (let i = 0; i < 8; i++) {
			bits.push(order === 'msb' ? (byte >> (7 - i)) & 1 : (byte >> i) & 1);
		}
	}

	let n = 0;
	outer: for (let p = 0; p < px.length / 4; p++) {
		for (const c of idx) {
			if (n >= bits.length) break outer;
			const at = p * 4 + c;
			px[at] = (px[at] & ~(1 << bit)) | (bits[n++] << bit);
		}
	}
}

/** Randomises the low bit of the leading `rate` of the R,G,B sample stream. */
function embedRate(px, rate, seed) {
	const next = rng(seed);
	const target = Math.round((px.length / 4) * 3 * rate);
	let n = 0;

	outer: for (let p = 0; p < px.length / 4; p++) {
		for (let c = 0; c < 3; c++) {
			if (n >= target) break outer;
			const at = p * 4 + c;
			px[at] = (px[at] & 0xfe) | (next() & 1);
			n++;
		}
	}
}

const made = [];
const emit = (name, buffer, why) => {
	writeFileSync(join(OUT, name), buffer);
	made.push({ name, bytes: buffer.length, why });
};

const W = 600;
const H = 400;

// Controls. Every detector must stay quiet on these.
emit('clean.png', encode(W, H, cover(W, H)), 'untouched cover, nothing hidden');

// Container findings.
{
	const text = Buffer.concat([
		Buffer.from('Comment', 'latin1'),
		Buffer.from([0]),
		Buffer.from('flag{hidden_in_a_text_chunk}', 'latin1')
	]);
	emit('text-chunk.png', encode(W, H, cover(W, H), [chunk('tEXt', text)]), 'flag in a tEXt chunk');
}

emit(
	'appended.png',
	Buffer.concat([
		encode(W, H, cover(W, H)),
		Buffer.from('PK\x03\x04flag{parked_after_iend}', 'latin1')
	]),
	'data after IEND, including a ZIP signature'
);

{
	const file = encode(W, H, cover(W, H));
	file[SIGNATURE.length + 8 + 13] ^= 0xff; // corrupt the IHDR checksum
	emit('bad-crc.png', file, 'IHDR checksum deliberately wrong');
}

// LSB sweep: the payload is only readable at one parameter combination.
{
	const px = cover(W, H);
	embedMessage(px, 'testCTF{rgb_msb_first}', { channels: 'rgb', bit: 0, order: 'msb' });
	emit('lsb-rgb-msb.png', encode(W, H, px), 'message in RGB bit 0, MSB first');
}
{
	const px = cover(W, H);
	embedMessage(px, 'flag{blue_channel_lsb_first}', { channels: 'b', bit: 0, order: 'lsb' });
	emit('lsb-blue-lsb.png', encode(W, H, px), 'message in blue bit 0, LSB first');
}

// Chi-square and RS: known embedding rates to measure the estimators against.
for (const rate of [0.25, 0.5, 1.0]) {
	const px = cover(W, H);
	embedRate(px, rate, 0x2468ace0 + rate * 1000);
	const label = String(Math.round(rate * 100)).padStart(3, '0');
	emit(
		`embed-${label}.png`,
		encode(W, H, px),
		`${label === '100' ? 100 : Number(label)}% sequential LSB embedding`
	);
}

// A payload confined to a rectangle. Invisible to chi-square, obvious on the wall.
{
	const px = cover(W, H);
	const next = rng(0x13572468);
	const box = { x: 150, y: 110, w: 260, h: 180 };
	for (let y = box.y; y < box.y + box.h; y++) {
		for (let x = box.x; x < box.x + box.w; x++) {
			const o = (y * W + x) * 4;
			for (let c = 0; c < 3; c++) px[o + c] = (px[o + c] & 0xfe) | (next() & 1);
		}
	}
	emit('region.png', encode(W, H, px), `payload confined to a ${box.w}x${box.h} rectangle`);
}

// Not a PNG, for the format-routing paths.
emit(
	'not-a-png.jpg',
	Buffer.concat([
		Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]),
		Buffer.from('JFIF\0', 'latin1'),
		Buffer.alloc(64, 0x20),
		Buffer.from('flag{jpeg_container}', 'latin1'),
		Buffer.from([0xff, 0xd9])
	]),
	'JPEG header, for the non-PNG path'
);

// Compressed text, which used to be reported as present but unread.
{
	const body = Buffer.from('flag{compressed_text_chunk}', 'latin1');
	const ztxt = Buffer.concat([
		Buffer.from('Secret', 'latin1'),
		Buffer.from([0, 0]), // null terminator, then compression method 0
		deflateSync(body, { level: 9 })
	]);
	emit(
		'ztxt.png',
		encode(W, H, cover(W, H), [chunk('zTXt', ztxt)]),
		'flag in a deflate-compressed zTXt chunk'
	);
}

// UTF-16LE text, which a single-byte string scan walks straight past.
{
	const wide = Buffer.alloc(0);
	const text = 'flag{wide_characters}';
	const utf16 = Buffer.alloc(text.length * 2);
	for (let i = 0; i < text.length; i++) utf16.writeUInt16LE(text.charCodeAt(i), i * 2);

	emit(
		'utf16.png',
		Buffer.concat([encode(W, H, cover(W, H)), wide, utf16]),
		'flag stored as UTF-16LE after IEND'
	);
}

// An indexed image whose palette holds the same colour twice.
{
	const width = 64;
	const height = 64;
	const palette = Buffer.alloc(256 * 3);
	for (let i = 0; i < 256; i++) {
		palette[i * 3] = i;
		palette[i * 3 + 1] = 255 - i;
		palette[i * 3 + 2] = (i * 7) % 256;
	}
	// Three entries painting an identical colour, which is the hiding place.
	for (const at of [10, 200, 201]) {
		palette[at * 3] = 0x40;
		palette[at * 3 + 1] = 0x80;
		palette[at * 3 + 2] = 0xc0;
	}

	const stride = width;
	const raw = Buffer.alloc((stride + 1) * height);
	const next = rng(0xfeed);
	for (let y = 0; y < height; y++) {
		raw[y * (stride + 1)] = 0;
		for (let x = 0; x < width; x++) {
			raw[y * (stride + 1) + 1 + x] = [10, 200, 201][next() % 3];
		}
	}

	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8;
	ihdr[9] = 3; // indexed

	emit(
		'palette-duplicates.png',
		Buffer.concat([
			SIGNATURE,
			chunk('IHDR', ihdr),
			chunk('PLTE', palette),
			chunk('IDAT', deflateSync(raw, { level: 9 })),
			chunk('IEND', Buffer.alloc(0))
		]),
		'indexed image with one colour repeated three times'
	);
}

// Adam7 interlaced, which the decoder used to refuse.
// Full size, so the statistical tools have enough samples to be meaningful and
// this doubles as a control that interlacing changes nothing they measure.
{
	const width = W;
	const height = H;
	const passes = [
		[0, 0, 8, 8],
		[4, 0, 8, 8],
		[0, 4, 4, 8],
		[2, 0, 4, 4],
		[0, 2, 2, 4],
		[1, 0, 2, 2],
		[0, 1, 1, 2]
	];

	const full = cover(width, height);
	const parts = [];
	for (const [x0, y0, dx, dy] of passes) {
		const pw = Math.ceil(Math.max(0, width - x0) / dx);
		const ph = Math.ceil(Math.max(0, height - y0) / dy);
		if (pw === 0 || ph === 0) continue;

		const stride = pw * 4;
		const raw = Buffer.alloc((stride + 1) * ph);
		for (let row = 0; row < ph; row++) {
			raw[row * (stride + 1)] = 0;
			for (let col = 0; col < pw; col++) {
				const src = ((y0 + row * dy) * width + (x0 + col * dx)) * 4;
				full.copy(raw, row * (stride + 1) + 1 + col * 4, src, src + 4);
			}
		}
		parts.push(raw);
	}

	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8;
	ihdr[9] = 6;
	ihdr[12] = 1; // Adam7

	emit(
		'interlaced.png',
		Buffer.concat([
			SIGNATURE,
			chunk('IHDR', ihdr),
			chunk('IDAT', deflateSync(Buffer.concat(parts), { level: 9 })),
			chunk('IEND', Buffer.alloc(0))
		]),
		'Adam7 interlaced, seven passes'
	);
}

/** An uncompressed 24-bit BMP: bottom-up rows, blue first, padded to four bytes. */
function bmp(width, height, pixels) {
	const stride = Math.ceil((width * 24) / 32) * 4;
	const body = Buffer.alloc(stride * height);

	for (let y = 0; y < height; y++) {
		const row = height - 1 - y; // bottom-up
		for (let x = 0; x < width; x++) {
			const src = (y * width + x) * 4;
			const at = row * stride + x * 3;
			body[at] = pixels[src + 2];
			body[at + 1] = pixels[src + 1];
			body[at + 2] = pixels[src];
		}
	}

	const header = Buffer.alloc(54);
	header.write('BM', 0, 'latin1');
	header.writeUInt32LE(54 + body.length, 2);
	header.writeUInt32LE(54, 10);
	header.writeUInt32LE(40, 14);
	header.writeInt32LE(width, 18);
	header.writeInt32LE(height, 22);
	header.writeUInt16LE(1, 26);
	header.writeUInt16LE(24, 28);
	header.writeInt32LE(2835, 38);
	header.writeInt32LE(2835, 42);

	return Buffer.concat([header, body]);
}

// BMP is uncompressed, so a payload in the low bits survives intact. Same cover
// and the same message as the PNG sweep fixture, so the two are comparable.
// Same dimensions as the PNG fixtures, so the two are directly comparable and
// the statistical tools have the same number of samples to work with.
{
	const px = cover(W, H);
	embedMessage(px, 'flag{bitmaps_hide_things_too}', { channels: 'rgb', bit: 0, order: 'msb' });
	emit('lsb.bmp', bmp(W, H, px), 'message in the low bits of an uncompressed BMP');
}

emit('clean.bmp', bmp(W, H, cover(W, H)), 'untouched bitmap, nothing hidden');

/** A GIF with a global colour table, LZW compressed, optionally commented. */
function gif(width, height, indices, table, comment) {
	const bits = Math.max(1, Math.ceil(Math.log2(table.length)) - 1);
	const entries = 2 << bits;

	const out = [Buffer.from('GIF89a', 'latin1')];
	const screen = Buffer.alloc(7);
	screen.writeUInt16LE(width, 0);
	screen.writeUInt16LE(height, 2);
	screen[4] = 0x80 | bits;
	out.push(screen);

	const palette = Buffer.alloc(entries * 3);
	table.forEach(([r, g, b], i) => {
		palette[i * 3] = r;
		palette[i * 3 + 1] = g;
		palette[i * 3 + 2] = b;
	});
	out.push(palette);

	if (comment) {
		out.push(Buffer.from([0x21, 0xfe]));
		const text = Buffer.from(comment, 'latin1');
		out.push(Buffer.from([text.length]), text, Buffer.from([0]));
	}

	const descriptor = Buffer.alloc(10);
	descriptor[0] = 0x2c;
	descriptor.writeUInt16LE(width, 5);
	descriptor.writeUInt16LE(height, 7);
	out.push(descriptor);

	// LZW with the dictionary cleared before every code, which is valid and keeps
	// this generator short. Codes stay at one bit above the minimum.
	const minCodeSize = Math.max(2, bits + 1);
	const clear = 1 << minCodeSize;
	const end = clear + 1;
	const codeWidth = minCodeSize + 1;

	const bitsOut = [];
	const push = (code) => {
		for (let i = 0; i < codeWidth; i++) bitsOut.push((code >> i) & 1);
	};
	push(clear);
	for (const index of indices) {
		push(index);
		push(clear);
	}
	push(end);

	const packed = Buffer.alloc(Math.ceil(bitsOut.length / 8));
	bitsOut.forEach((bit, i) => {
		if (bit) packed[i >> 3] |= 1 << (i % 8);
	});

	out.push(Buffer.from([minCodeSize]));
	for (let at = 0; at < packed.length; at += 255) {
		const block = packed.subarray(at, at + 255);
		out.push(Buffer.from([block.length]), block);
	}
	out.push(Buffer.from([0, 0x3b]));

	return Buffer.concat(out);
}

{
	const w = 64;
	const h = 48;
	const table = Array.from({ length: 16 }, (_, i) => [i * 16, 255 - i * 16, (i * 37) % 256]);
	// Two entries painting the same colour, the GIF version of the PNG trick.
	table[9] = [...table[3]];
	const indices = Array.from({ length: w * h }, (_, i) => (i * 5) % 16);

	emit(
		'comment.gif',
		gif(w, h, indices, table, 'flag{gif_comment_block}'),
		'flag in a GIF comment block, with a duplicated palette entry'
	);
}

/** A little-endian TIFF block, the same structure JPEG and PNG both carry. */
function tiff(fields) {
	const count = fields.length;
	let heapAt = 8 + 2 + count * 12 + 4;
	const head = [];
	const heap = [];

	for (const [tag, text] of fields) {
		const value = Buffer.concat([Buffer.from(text, 'latin1'), Buffer.from([0])]);
		const entry = Buffer.alloc(12);
		entry.writeUInt16LE(tag, 0);
		entry.writeUInt16LE(2, 2); // ASCII
		entry.writeUInt32LE(value.length, 4);

		if (value.length <= 4) {
			value.copy(entry, 8);
		} else {
			entry.writeUInt32LE(heapAt, 8);
			heap.push(value);
			heapAt += value.length;
		}
		head.push(entry);
	}

	const header = Buffer.alloc(10);
	header.write('II', 0, 'latin1');
	header.writeUInt16LE(42, 2);
	header.writeUInt32LE(8, 4);
	header.writeUInt16LE(count, 8);

	return Buffer.concat([header, ...head, Buffer.alloc(4), ...heap]);
}

// EXIF inside a JPEG, which is where metadata challenges hide a flag.
{
	const block = Buffer.concat([
		Buffer.from('Exif\0\0', 'latin1'),
		tiff([
			[0x010f, 'Nikon'],
			[0x0110, 'D850'],
			[0x0131, 'Trawl fixture generator'],
			[0x010e, 'flag{read_the_metadata}'],
			[0x013b, 'yuv1s']
		])
	]);

	const app1 = Buffer.alloc(4);
	app1[0] = 0xff;
	app1[1] = 0xe1;
	app1.writeUInt16BE(block.length + 2, 2);

	const comment = Buffer.from('nothing to see here, move along', 'latin1');
	const com = Buffer.alloc(4);
	com[0] = 0xff;
	com[1] = 0xfe;
	com.writeUInt16BE(comment.length + 2, 2);

	emit(
		'exif-flag.jpg',
		Buffer.concat([
			Buffer.from([0xff, 0xd8]),
			app1,
			block,
			com,
			comment,
			Buffer.from([0xff, 0xd9])
		]),
		'flag in the EXIF ImageDescription of a JPEG'
	);
}

// The same TIFF block in a PNG eXIf chunk, read by the same walker.
{
	const block = tiff([[0x9286, 'flag{png_carries_exif_too}']]);
	const px = cover(120, 90);
	emit('exif-in-png.png', encode(120, 90, px, [chunk('eXIf', block)]), 'flag in a PNG eXIf chunk');
}

/** A RIFF/WAVE file from 16-bit signed frames, interleaved by channel. */
function wav(frames, channels, rate, extraChunks = []) {
	const data = Buffer.alloc(frames.length * 2);
	frames.forEach((s, i) => data.writeInt16LE(Math.max(-32768, Math.min(32767, s | 0)), i * 2));

	const fmt = Buffer.alloc(16);
	fmt.writeUInt16LE(1, 0); // PCM
	fmt.writeUInt16LE(channels, 2);
	fmt.writeUInt32LE(rate, 4);
	fmt.writeUInt32LE(rate * channels * 2, 8);
	fmt.writeUInt16LE(channels * 2, 12);
	fmt.writeUInt16LE(16, 14);

	const riffChunk = (id, payload) => {
		const head = Buffer.alloc(8);
		head.write(id, 0, 'latin1');
		head.writeUInt32LE(payload.length, 4);
		const pad = payload.length % 2 === 1 ? Buffer.from([0]) : Buffer.alloc(0);
		return Buffer.concat([head, payload, pad]);
	};

	const body = Buffer.concat([
		Buffer.from('WAVE', 'latin1'),
		riffChunk('fmt ', fmt),
		...extraChunks.map(([id, payload]) => riffChunk(id, payload)),
		riffChunk('data', data)
	]);

	const head = Buffer.alloc(8);
	head.write('RIFF', 0, 'latin1');
	head.writeUInt32LE(body.length, 4);
	return Buffer.concat([head, body]);
}

const RATE = 22050;
const SECONDS = 3;

/** A chord plus a little dither, so the low bits move the way a recording's do. */
function music(count, channels, seed) {
	const noise = rng(seed);
	const out = new Array(count * channels);

	for (let i = 0; i < count; i++) {
		const t = i / RATE;
		const envelope = Math.min(1, t * 4) * Math.min(1, (SECONDS - t) * 4);
		for (let c = 0; c < channels; c++) {
			const detune = c === 0 ? 1 : 1.005;
			const value =
				Math.sin(2 * Math.PI * 220 * detune * t) * 0.4 +
				Math.sin(2 * Math.PI * 330 * detune * t) * 0.25 +
				Math.sin(2 * Math.PI * 440 * detune * t) * 0.15;
			out[i * channels + c] = Math.round(value * envelope * 12000 + (noise() % 5) - 2);
		}
	}

	return out;
}

/** Writes a message into one bit plane of the samples, in place. */
function embedSamples(
	samples,
	text,
	{ channels = 1, channel = null, bit = 0, order = 'msb' } = {}
) {
	const bytes = Buffer.from(text, 'latin1');
	const step = channel === null ? 1 : channels;
	const start = channel === null ? 0 : channel;

	for (let i = 0; i < bytes.length * 8; i++) {
		const at = start + i * step;
		if (at >= samples.length) break;
		const shift = order === 'msb' ? 7 - (i % 8) : i % 8;
		const b = (bytes[i >> 3] >> shift) & 1;
		samples[at] = (samples[at] & ~(1 << bit)) | (b << bit);
	}
}

emit('clean.wav', wav(music(RATE * SECONDS, 1, 5), 1, RATE), 'untouched audio, nothing hidden');

{
	const samples = music(RATE * SECONDS, 1, 6);
	embedSamples(samples, 'flag{the_low_bits_of_the_waveform}', { bit: 0, order: 'msb' });
	emit('lsb.wav', wav(samples, 1, RATE), 'message in the low bit of every sample');
}

{
	const samples = music(RATE * SECONDS, 2, 7);
	embedSamples(samples, 'flag{right_channel_carries_it}', { channels: 2, channel: 1, bit: 0 });
	emit('lsb-right.wav', wav(samples, 2, RATE), 'message in the right channel only');
}

// A picture drawn straight into the frequency domain: nothing statistical will
// ever find this, which is exactly why the spectrogram exists.
{
	const glyphs = {
		T: ['#####', '..#..', '..#..', '..#..', '..#..'],
		R: ['####.', '#...#', '####.', '#..#.', '#...#'],
		A: ['.###.', '#...#', '#####', '#...#', '#...#'],
		W: ['#...#', '#...#', '#.#.#', '##.##', '#...#'],
		L: ['#....', '#....', '#....', '#....', '#####']
	};

	const word = 'TRAWL';
	const cellW = 5;
	const cols = word.length * (cellW + 1);
	const rows = 5;

	const count = RATE * SECONDS;
	const samples = new Array(count).fill(0);

	// One tone per lit cell, held for the slice of time that column covers.
	for (let c = 0; c < cols; c++) {
		const letter = glyphs[word[Math.floor(c / (cellW + 1))]];
		const column = c % (cellW + 1);
		if (column === cellW) continue;

		for (let r = 0; r < rows; r++) {
			if (letter[r][column] !== '#') continue;

			// Rows run top to bottom, so the top row is the highest frequency.
			// Spread wide, or five rows land in the bottom tenth of the image.
			const hz = 900 + (rows - 1 - r) * 1900;
			const from = Math.floor((c / cols) * count);
			const to = Math.floor(((c + 1) / cols) * count);

			for (let i = from; i < to; i++) {
				const t = i / RATE;
				// A cell that switches on abruptly is a click, and a click is
				// broadband: it draws a vertical line through every row.
				const envelope = 0.5 - 0.5 * Math.cos((2 * Math.PI * (i - from)) / (to - from));
				samples[i] += Math.sin(2 * Math.PI * hz * t) * 5000 * envelope;
			}
		}
	}

	emit('spectrogram.wav', wav(samples, 1, RATE), 'the word TRAWL drawn in the spectrogram');
}

{
	// A real LIST/INFO: the type, then a tag with its own length, then the text.
	const text = Buffer.from('flag{riff_comment_chunk}\0', 'latin1');
	const size = Buffer.alloc(4);
	size.writeUInt32LE(text.length, 0);
	const list = Buffer.concat([Buffer.from('INFOICMT', 'latin1'), size, text]);

	const samples = music(RATE * SECONDS, 1, 8);
	emit(
		'comment.wav',
		wav(samples, 1, RATE, [['LIST', list]]),
		'flag in a LIST chunk a player skips'
	);
}

{
	const samples = music(RATE * SECONDS, 1, 9);
	const file = wav(samples, 1, RATE);
	emit(
		'appended.wav',
		Buffer.concat([file, Buffer.from('flag{past_the_declared_end}', 'latin1')]),
		'bytes past the length the RIFF header declares'
	);
}

/** Standard JPEG Huffman tables, Annex K. Real variable-length codes, so the
 *  decoder's canonical builder is exercised rather than a flat stand-in. */
const DC_LUMA_COUNTS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const DC_LUMA_VALUES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

const AC_LUMA_COUNTS = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const AC_LUMA_VALUES = [
	0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
	0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
	0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
	0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
	0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
	0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
	0xf9, 0xfa
];

/** Canonical code assignment: the same walk the decoder does, in reverse. */
function codes(counts, values) {
	const table = new Map();
	let code = 0;
	let k = 0;

	for (let length = 1; length <= 16; length++) {
		for (let i = 0; i < counts[length - 1]; i++) {
			table.set(values[k++], { code, length });
			code++;
		}
		code <<= 1;
	}

	return table;
}

const DC_CODES = codes(DC_LUMA_COUNTS, DC_LUMA_VALUES);
const AC_CODES = codes(AC_LUMA_COUNTS, AC_LUMA_VALUES);

class Bits {
	constructor() {
		this.out = [];
		this.byte = 0;
		this.filled = 0;
	}

	push(bit) {
		this.byte = ((this.byte << 1) | (bit & 1)) & 0xff;
		if (++this.filled === 8) {
			this.out.push(this.byte);
			if (this.byte === 0xff) this.out.push(0x00);
			this.byte = 0;
			this.filled = 0;
		}
	}

	write(value, length) {
		for (let i = length - 1; i >= 0; i--) this.push((value >> i) & 1);
	}

	symbol(table, key) {
		const entry = table.get(key);
		if (!entry) throw new Error(`no Huffman code for 0x${key.toString(16)}`);
		this.write(entry.code, entry.length);
	}

	flush() {
		while (this.filled !== 0) this.push(1);
	}
}

function magnitude(value) {
	if (value === 0) return [0, 0];
	const size = 32 - Math.clz32(Math.abs(value));
	return [size, value > 0 ? value : value + (1 << size) - 1];
}

function encodeBlock(bits, block, state) {
	const [size, value] = magnitude(block[0] - state.dc);
	state.dc = block[0];
	bits.symbol(DC_CODES, size);
	bits.write(value, size);

	let last = 0;
	for (let k = 63; k > 0; k--) {
		if (block[k] !== 0) {
			last = k;
			break;
		}
	}

	let run = 0;
	for (let k = 1; k <= last; k++) {
		if (block[k] === 0) {
			run++;
			continue;
		}
		while (run >= 16) {
			bits.symbol(AC_CODES, 0xf0);
			run -= 16;
		}
		const [s, v] = magnitude(block[k]);
		bits.symbol(AC_CODES, (run << 4) | s);
		bits.write(v, s);
		run = 0;
	}

	if (last < 63) bits.symbol(AC_CODES, 0x00);
}

function seg(code, payload) {
	const head = Buffer.alloc(4);
	head[0] = 0xff;
	head[1] = code;
	head.writeUInt16BE(payload.length + 2, 2);
	return Buffer.concat([head, Buffer.from(payload)]);
}

/**
 * A baseline grayscale JPEG carrying exactly these coefficient blocks.
 *
 * No forward DCT: the coefficients are the point, and writing them directly is
 * what makes the fixture's contents knowable rather than a guess about what an
 * encoder produced. The result is a structurally valid JPEG any decoder opens.
 */
function encodeJpeg(blocks, width, height) {
	const dqt = [0x00, ...new Array(64).fill(1)];

	const sof = [8, height >> 8, height & 0xff, width >> 8, width & 0xff, 1, 1, 0x11, 0];

	const dht = [
		0x00,
		...DC_LUMA_COUNTS,
		...DC_LUMA_VALUES,
		0x10,
		...AC_LUMA_COUNTS,
		...AC_LUMA_VALUES
	];

	const sos = [1, 1, 0x00, 0, 63, 0];

	const bits = new Bits();
	const state = { dc: 0 };
	for (const block of blocks) encodeBlock(bits, block, state);
	bits.flush();

	return Buffer.concat([
		Buffer.from([0xff, 0xd8]),
		seg(0xdb, dqt),
		seg(0xc0, sof),
		seg(0xc4, dht),
		seg(0xda, sos),
		Buffer.from(bits.out),
		Buffer.from([0xff, 0xd9])
	]);
}

/** Coefficients that behave like a photograph: a wandering DC and AC magnitudes
 *  that decay geometrically away from zero. A uniform spread would already look
 *  embedded to the chi-square test, which is the trap this generator has fallen
 *  into before on other formats. */
function jpegCover(count, seed) {
	const rand = rng(seed);
	const blocks = [];
	let dc = 0;

	for (let i = 0; i < count; i++) {
		const block = new Int32Array(64);
		dc += (rand() % 21) - 10;
		block[0] = Math.max(-500, Math.min(500, dc));

		for (let k = 1; k < 40; k++) {
			const reach = 40 - k;
			if (rand() % 64 >= reach) continue;

			let magnitude = 1;
			while (magnitude < 30 && rand() % 100 < 60) magnitude++;
			block[k] = rand() % 2 === 0 ? magnitude : -magnitude;
		}

		blocks.push(block);
	}

	return blocks;
}

/** JSteg: the low bit of every coefficient except those equal to 0 or 1. */
function embedJsteg(blocks, text) {
	const bytes = Buffer.from(text, 'latin1');
	let written = 0;

	for (const block of blocks) {
		for (let k = 1; k < 64; k++) {
			if (written === bytes.length * 8) return written;
			const value = block[k];
			if (value === 0 || value === 1) continue;
			const bit = (bytes[written >> 3] >> (7 - (written % 8))) & 1;
			block[k] = (value & ~1) | bit;
			written++;
		}
	}

	return written;
}

{
	const BLOCKS = 1200;
	const W = 8 * 40;
	const H = 8 * 30;

	emit(
		'clean.jpg',
		encodeJpeg(jpegCover(BLOCKS, 11), W, H),
		'untouched coefficients, nothing hidden'
	);

	const carrying = jpegCover(BLOCKS, 12);
	embedJsteg(carrying, 'flag{jsteg_lives_in_the_coefficients}');
	emit('jsteg.jpg', encodeJpeg(carrying, W, H), 'message in the low bits of the DCT coefficients');

	// Every usable coefficient filled, which is what chi-square is built to see.
	// The filler has to be bit-balanced: a structured one skews the pairs and
	// makes the detector look weaker than it is.
	const saturated = jpegCover(BLOCKS, 13);
	const capacity = saturated.reduce(
		(n, b) => n + b.slice(1).filter((v) => v !== 0 && v !== 1).length,
		0
	);
	const noise = rng(14);
	const filler = Array.from({ length: Math.floor(capacity / 8) }, () =>
		String.fromCharCode(noise() & 0xff)
	).join('');
	embedJsteg(saturated, filler);
	emit('jsteg-full.jpg', encodeJpeg(saturated, W, H), 'every usable coefficient carries a bit');
}

// An indexed image carrying a message in the choice between identical entries.
// The picture is unchanged by construction: every choice paints the same colour.
{
	const width = 128;
	const height = 128;

	const palette = Buffer.alloc(256 * 3);
	for (let i = 0; i < 256; i++) {
		palette[i * 3] = (i * 3) % 256;
		palette[i * 3 + 1] = (i * 5) % 256;
		palette[i * 3 + 2] = (i * 11) % 256;
	}

	// Four pairs, each pair painting one colour, so a pixel using any of them
	// carries one bit.
	const pairs = [
		[8, 190],
		[9, 191],
		[10, 192],
		[11, 193]
	];
	for (const [a, b] of pairs) {
		for (const c of [0, 1, 2]) palette[b * 3 + c] = palette[a * 3 + c];
	}

	const message = Buffer.from('flag{the_palette_chose_these_bits}\0', 'latin1');
	const noise = rng(0x9a11);
	const indices = Buffer.alloc(width * height);
	let written = 0;

	for (let i = 0; i < indices.length; i++) {
		// Roughly half the picture uses a duplicated colour, the rest does not,
		// which is what an ordinary image with a redundant palette looks like.
		if (noise() % 2 === 0) {
			indices[i] = 20 + (noise() % 100);
			continue;
		}

		const pair = pairs[written % pairs.length];
		if (written < message.length * 8) {
			const bit = (message[written >> 3] >> (7 - (written % 8))) & 1;
			indices[i] = pair[bit];
			written++;
		} else {
			indices[i] = pair[0];
			written++;
		}
	}

	const stride = width;
	const raw = Buffer.alloc((stride + 1) * height);
	for (let y = 0; y < height; y++) {
		raw[y * (stride + 1)] = 0;
		indices.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
	}

	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8;
	ihdr[9] = 3;

	emit(
		'palette-payload.png',
		Buffer.concat([
			SIGNATURE,
			chunk('IHDR', ihdr),
			chunk('PLTE', palette),
			chunk('IDAT', deflateSync(raw, { level: 9 })),
			chunk('IEND', Buffer.alloc(0))
		]),
		'message hidden in the choice between identical palette entries'
	);
}

/**
 * A progressive JPEG: the DC coefficients in one scan, then the AC coefficients
 * in another. Spectral selection only, which is the simplest shape a real
 * encoder emits and enough to prove the multi-scan path end to end.
 */
function encodeProgressiveJpeg(blocks, width, height) {
	const dqt = [0x00, ...new Array(64).fill(1)];
	const sof = [8, height >> 8, height & 0xff, width >> 8, width & 0xff, 1, 1, 0x11, 0];
	const dht = [
		0x00,
		...DC_LUMA_COUNTS,
		...DC_LUMA_VALUES,
		0x10,
		...AC_LUMA_COUNTS,
		...AC_LUMA_VALUES
	];

	// DC scan: one symbol per block, no AC at all.
	const dcBits = new Bits();
	let predictor = 0;
	for (const block of blocks) {
		const [size, value] = magnitude(block[0] - predictor);
		predictor = block[0];
		dcBits.symbol(DC_CODES, size);
		dcBits.write(value, size);
	}
	dcBits.flush();

	// AC scan: indices 1 to 63, with empty blocks folded into end-of-band runs.
	const acBits = new Bits();
	let eobRun = 0;

	const flushEob = () => {
		if (eobRun === 0) return;
		const r = 31 - Math.clz32(eobRun);
		acBits.symbol(AC_CODES, r << 4);
		if (r > 0) acBits.write(eobRun - (1 << r), r);
		eobRun = 0;
	};

	for (const block of blocks) {
		let last = 0;
		for (let k = 63; k > 0; k--) {
			if (block[k] !== 0) {
				last = k;
				break;
			}
		}

		if (last === 0) {
			eobRun++;
			if (eobRun === (1 << 14) - 1) flushEob();
			continue;
		}

		flushEob();

		let run = 0;
		for (let k = 1; k <= last; k++) {
			if (block[k] === 0) {
				run++;
				continue;
			}
			while (run >= 16) {
				acBits.symbol(AC_CODES, 0xf0);
				run -= 16;
			}
			const [s, v] = magnitude(block[k]);
			acBits.symbol(AC_CODES, (run << 4) | s);
			acBits.write(v, s);
			run = 0;
		}

		if (last < 63) eobRun = 1;
	}

	flushEob();
	acBits.flush();

	return Buffer.concat([
		Buffer.from([0xff, 0xd8]),
		seg(0xdb, dqt),
		seg(0xc2, sof), // SOF2 marks it progressive
		seg(0xc4, dht),
		seg(0xda, [1, 1, 0x00, 0, 0, 0]),
		Buffer.from(dcBits.out),
		seg(0xda, [1, 1, 0x00, 1, 63, 0]),
		Buffer.from(acBits.out),
		Buffer.from([0xff, 0xd9])
	]);
}

{
	const BLOCKS = 1200;
	const W = 8 * 40;
	const H = 8 * 30;

	const carrying = jpegCover(BLOCKS, 21);
	embedJsteg(carrying, 'flag{progressive_still_reads}');
	emit(
		'jsteg-progressive.jpg',
		encodeProgressiveJpeg(carrying, W, H),
		'the same payload, in a progressive JPEG split across two scans'
	);

	emit(
		'clean-progressive.jpg',
		encodeProgressiveJpeg(jpegCover(BLOCKS, 22), W, H),
		'progressive JPEG with nothing hidden'
	);
}

const width = Math.max(...made.map((m) => m.name.length));
for (const m of made) {
	console.log(`${m.name.padEnd(width)}  ${String(m.bytes).padStart(7)} B  ${m.why}`);
}
console.log(`\n${made.length} fixtures written to ${OUT}`);
