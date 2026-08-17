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

const width = Math.max(...made.map((m) => m.name.length));
for (const m of made) {
	console.log(`${m.name.padEnd(width)}  ${String(m.bytes).padStart(7)} B  ${m.why}`);
}
console.log(`\n${made.length} fixtures written to ${OUT}`);
