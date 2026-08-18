// Turns an indexed PNG into one whose palette holds the same colour more than
// once, which is a real steganographic capacity and the thing Trawl's palette
// tool looks for.
//
//   npm run demo -- path/to/image.png
//
// The picture is meant to survive this untouched. Two entries painting the same
// colour render identically, so scattering pixels between them changes the file
// and not the image. Freeing the slots needs a little care, which is where the
// only visible change comes from, and the script reports exactly how much.

import { readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';
import { deflateSync, inflateSync } from 'node:zlib';

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

function readChunks(file) {
	if (!file.subarray(0, 8).equals(SIGNATURE)) throw new Error('not a PNG');

	const out = [];
	let at = 8;
	while (at + 8 <= file.length) {
		const length = file.readUInt32BE(at);
		const kind = file.subarray(at + 4, at + 8).toString('latin1');
		out.push({ kind, data: file.subarray(at + 8, at + 8 + length) });
		if (kind === 'IEND') break;
		at += 12 + length;
	}
	return out;
}

function paeth(a, b, c) {
	const p = a + b - c;
	const pa = Math.abs(p - a);
	const pb = Math.abs(p - b);
	const pc = Math.abs(p - c);
	if (pa <= pb && pa <= pc) return a;
	return pb <= pc ? b : c;
}

/** One byte per pixel, which is what an 8-bit indexed image stores. */
function unfilter(raw, width, height) {
	const out = Buffer.alloc(width * height);

	for (let y = 0; y < height; y++) {
		const type = raw[y * (width + 1)];
		const src = raw.subarray(y * (width + 1) + 1, y * (width + 1) + 1 + width);

		for (let x = 0; x < width; x++) {
			const a = x > 0 ? out[y * width + x - 1] : 0;
			const b = y > 0 ? out[(y - 1) * width + x] : 0;
			const c = x > 0 && y > 0 ? out[(y - 1) * width + x - 1] : 0;

			let predictor = 0;
			if (type === 1) predictor = a;
			else if (type === 2) predictor = b;
			else if (type === 3) predictor = (a + b) >> 1;
			else if (type === 4) predictor = paeth(a, b, c);

			out[y * width + x] = (src[x] + predictor) & 0xff;
		}
	}

	return out;
}

/** Deterministic, so running this twice gives the same file. */
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

const input = process.argv[2];
if (!input) {
	console.error('usage: npm run demo -- path/to/indexed.png');
	process.exit(1);
}

const file = readFileSync(input);
const chunks = readChunks(file);

const ihdr = chunks.find((c) => c.kind === 'IHDR');
const width = ihdr.data.readUInt32BE(0);
const height = ihdr.data.readUInt32BE(4);
const depth = ihdr.data[8];
const colourType = ihdr.data[9];
const interlace = ihdr.data[12];

if (colourType !== 3 || depth !== 8 || interlace !== 0) {
	console.error(
		`This needs an 8-bit indexed PNG with no interlacing. ${basename(input)} is colour type ` +
			`${colourType}, ${depth}-bit, interlace ${interlace}.\n` +
			'Truecolour photos have no palette to duplicate. Convert it to indexed first ' +
			'(GIMP: Image > Mode > Indexed, 256 colours) and run this again.'
	);
	process.exit(1);
}

const plte = chunks.find((c) => c.kind === 'PLTE').data;
const entries = plte.length / 3;
const indices = unfilter(
	inflateSync(Buffer.concat(chunks.filter((c) => c.kind === 'IDAT').map((c) => c.data))),
	width,
	height
);

const counts = new Array(entries).fill(0);
for (const i of indices) counts[i]++;

const colour = (i) => [plte[i * 3], plte[i * 3 + 1], plte[i * 3 + 2]];
const hex = (i) =>
	'#' +
	colour(i)
		.map((v) => v.toString(16).padStart(2, '0'))
		.join('');

// Slots nothing points at are free already. Anything beyond that has to be
// taken from a pair of colours close enough that merging them is invisible.
const WANTED = 12;
const MAX_SHIFT = 2;

const free = [];
for (let i = 0; i < entries; i++) if (counts[i] === 0) free.push(i);

const pairs = [];
for (let i = 0; i < entries; i++) {
	for (let j = i + 1; j < entries; j++) {
		if (counts[i] === 0 || counts[j] === 0) continue;
		const [ar, ag, ab] = colour(i);
		const [br, bg, bb] = colour(j);
		const shift = Math.max(Math.abs(ar - br), Math.abs(ag - bg), Math.abs(ab - bb));
		if (shift <= MAX_SHIFT) pairs.push({ shift, i, j });
	}
}
pairs.sort((a, b) => a.shift - b.shift);

const remap = new Map();
let worstShift = 0;
for (const { shift, i, j } of pairs) {
	if (free.length >= WANTED) break;
	if (remap.has(i) || remap.has(j) || free.includes(i) || free.includes(j)) continue;

	// Keep whichever colour paints more pixels, so fewer of them move at all.
	const [keep, drop] = counts[i] >= counts[j] ? [i, j] : [j, i];
	remap.set(drop, keep);
	free.push(drop);
	worstShift = Math.max(worstShift, shift);
}

if (free.length === 0) {
	console.error('No spare palette slots and no colours close enough to merge safely.');
	process.exit(1);
}

for (let p = 0; p < indices.length; p++) {
	const to = remap.get(indices[p]);
	if (to !== undefined) indices[p] = to;
}

// Recount, then hand the freed slots to the colours that paint the most pixels.
const after = new Array(entries).fill(0);
for (const i of indices) after[i]++;

const busiest = after
	.map((n, i) => ({ n, i }))
	.filter((e) => e.n > 0)
	.sort((a, b) => b.n - a.n)
	.slice(0, free.length);

const palette = Buffer.from(plte);
const groups = new Map();

busiest.forEach((entry, k) => {
	const slot = free[k];
	const [r, g, b] = colour(entry.i);
	palette[slot * 3] = r;
	palette[slot * 3 + 1] = g;
	palette[slot * 3 + 2] = b;
	groups.set(entry.i, [entry.i, slot]);
});

// Scatter pixels across the equivalent entries. Every one of them paints the
// same colour, so this is invisible, and the choice is where the capacity lives.
const next = rng(0x7ea15e);
let carrying = 0;
for (let p = 0; p < indices.length; p++) {
	const group = groups.get(indices[p]);
	if (!group) continue;
	indices[p] = group[next() % group.length];
	carrying++;
}

const stride = width;
const raw = Buffer.alloc((stride + 1) * height);
for (let y = 0; y < height; y++) {
	raw[y * (stride + 1)] = 0;
	indices.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
}

const rebuilt = [SIGNATURE];
for (const c of chunks) {
	if (c.kind === 'IDAT') continue;
	if (c.kind === 'PLTE') {
		rebuilt.push(chunk('PLTE', palette));
		continue;
	}
	if (c.kind === 'IEND') {
		rebuilt.push(chunk('IDAT', deflateSync(raw, { level: 9 })));
		rebuilt.push(chunk('IEND', Buffer.alloc(0)));
		continue;
	}
	rebuilt.push(chunk(c.kind, c.data));
}

const out = join(dirname(input), `${basename(input, extname(input))}.duplicated.png`);
writeFileSync(out, Buffer.concat(rebuilt));

const moved = [...remap.keys()].reduce((n, i) => n + counts[i], 0);
console.log(`${out}`);
console.log(`  ${free.length} palette entries now duplicate a colour already present`);
console.log(`  ${busiest.map((e) => hex(e.i)).join(' ')}`);
console.log(
	`  ${carrying.toLocaleString()} of ${(width * height).toLocaleString()} pixels can choose between two entries`
);
console.log(
	`  roughly ${carrying.toLocaleString()} bits, about ${Math.round(carrying / 8).toLocaleString()} bytes of capacity`
);
console.log(
	`  ${moved.toLocaleString()} pixels shifted colour by at most ${worstShift} of 255, which is ${(
		(moved / (width * height)) *
		100
	).toFixed(1)}% of the image`
);
