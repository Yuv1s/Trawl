import { afterEach, describe, expect, it } from 'vitest';
import { writeupMarkdown } from '$lib/analysis/writeup';
import { encodePng, pngChunk } from '$lib/pixels/png-encode';
import AnalysisWorker from './analysis.worker?worker';
import type { AnalysisRequest, AnalysisResponse, NestedArtifact } from './protocol';

const WIDTH = 8;
const HEIGHT = 16;
const HEIGHT_OFFSET = 20;

function pngWithFalseHeight(): Uint8Array {
	const png = encodePng(WIDTH, HEIGHT, 2, new Uint8Array(WIDTH * HEIGHT * 3).fill(120));
	new DataView(png.buffer, png.byteOffset).setUint32(HEIGHT_OFFSET, HEIGHT / 2);
	return png;
}

describe('the analysis worker', () => {
	let worker: Worker;

	function send(request: AnalysisRequest): Promise<AnalysisResponse> {
		return new Promise((resolve, reject) => {
			worker.onerror = (event) => reject(new Error(event.message));
			worker.onmessage = (event: MessageEvent<AnalysisResponse>) => resolve(event.data);
			worker.postMessage(request);
		});
	}

	afterEach(() => worker.terminate());

	it('repairs a PNG whose header lies about its height, then reads it cleanly', async () => {
		worker = new AnalysisWorker();
		const broken = pngWithFalseHeight();

		const first = await send({
			kind: 'analyse',
			id: 1,
			name: 'cut.png',
			bytes: broken.slice().buffer,
			flagTags: ''
		});
		if (first.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(first)}`);
		const repair = first.structure?.ihdrRepair;
		expect(repair?.recoveredHeight).toBe(HEIGHT);

		const patched = await send({
			kind: 'patchIhdr',
			id: 2,
			name: 'cut.png',
			width: repair!.recoveredWidth,
			height: repair!.recoveredHeight
		});
		if (patched.status !== 'patched') throw new Error(`patch failed: ${JSON.stringify(patched)}`);
		expect(new DataView(patched.bytes.buffer).getUint32(HEIGHT_OFFSET)).toBe(HEIGHT);

		const second = await send({
			kind: 'analyse',
			id: 3,
			name: 'cut.png',
			bytes: patched.bytes.slice().buffer,
			flagTags: ''
		});
		if (second.status !== 'ok') throw new Error(`reanalysis failed: ${JSON.stringify(second)}`);
		expect(second.structure?.chunks.every((chunk) => chunk.crcOk)).toBe(true);
		expect(second.structure?.ihdrRepair).toBeNull();
	});

	it('reads the pixels of a PNG too big for the budget a nested file gets', async () => {
		worker = new AnalysisWorker();
		const side = 1000;
		const png = encodePng(side, side, 2, new Uint8Array(side * side * 3).fill(90));

		const response = await send({
			kind: 'analyse',
			id: 1,
			name: 'big.png',
			bytes: png.slice().buffer,
			flagTags: ''
		});
		if (response.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(response)}`);

		expect(response.pixelError).toBeNull();
		expect(response.sweep).not.toBeNull();
	});

	it('reports a patch with no file loaded instead of analysing nothing', async () => {
		worker = new AnalysisWorker();

		const response = await send({ kind: 'patchIhdr', id: 1, name: 'x', width: 1, height: 1 });

		expect(response.status).toBe('error');
	});

	it('reads a flag out of a deleted database row, cell by cell', async () => {
		worker = new AnalysisWorker();
		const bytes = await (await fetch('/samples/databases/app.sqlite')).arrayBuffer();

		const response = await send({
			kind: 'analyse',
			id: 1,
			name: 'app.sqlite',
			bytes,
			flagTags: 'flag'
		});
		if (response.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(response)}`);

		expect(response.sqlite?.flags).toContainEqual({
			text: 'flag{deleted_rows_never_left}',
			table: 'members',
			deleted: true
		});
	});
});

const REAL = 'flag{the_real_one}';

const ascii = (text: string) => new TextEncoder().encode(text);

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
	let at = 0;
	for (const part of parts) {
		out.set(part, at);
		at += part.length;
	}
	return out;
}

async function deflated(
	bytes: Uint8Array,
	format: 'deflate' | 'deflate-raw' = 'deflate'
): Promise<Uint8Array<ArrayBuffer>> {
	const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new CompressionStream(format));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** The same bytes every run, which a compressor can do nothing with. */
function noise(length: number, seed = 1): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(length);
	let state = seed;
	for (let i = 0; i < length; i += 1) {
		state ^= state << 13;
		state ^= state >>> 17;
		state ^= state << 5;
		out[i] = state & 0xff;
	}
	return out;
}

const hex = (bytes: Uint8Array) =>
	Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const IEND_LENGTH = 12;

function withChunks(png: Uint8Array, ...chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
	const end = png.length - IEND_LENGTH;
	return concat(png.subarray(0, end), ...chunks, png.subarray(end));
}

const plainPng = () => encodePng(1, 1, 2, new Uint8Array(3).fill(0x40));

/** The first IDAT sits straight after the signature and the header. */
const IDAT_AT = 33;

function withIdat(png: Uint8Array, change: (idat: Uint8Array) => Uint8Array): Uint8Array {
	const length = new DataView(png.buffer, png.byteOffset).getUint32(IDAT_AT);
	const idat = png.subarray(IDAT_AT + 8, IDAT_AT + 8 + length);
	return concat(
		png.subarray(0, IDAT_AT),
		pngChunk('IDAT', change(idat)),
		png.subarray(IDAT_AT + 12 + length)
	);
}

/** A PNG whose red, green and blue low bits spell `text`, most significant bit first. */
function lsbPng(text: string, width = 32, height = 32): Uint8Array<ArrayBuffer> {
	const bits = Array.from(ascii(text)).flatMap((byte) =>
		Array.from({ length: 8 }, (_, bit) => (byte >> (7 - bit)) & 1)
	);
	const pixels = new Uint8Array(width * height * 3).map((_, i) => 0x40 | (bits[i] ?? 0));
	return encodePng(width, height, 2, pixels);
}

type Put = {
	name: string;
	data: Uint8Array;
	method?: 0 | 8;
	/** What the entry holds once opened, where that is not `data.length`. */
	size?: number;
	/** What the local header claims, where it differs from the directory. */
	local?: [compressed: number, uncompressed: number];
	/** What both places claim is stored, where that is not `data.length`. */
	stored?: number;
};

function littleEndian(...fields: [width: 2 | 4, value: number][]): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(fields.reduce((total, [width]) => total + width, 0));
	const view = new DataView(out.buffer);
	let at = 0;
	for (const [width, value] of fields) {
		if (width === 2) view.setUint16(at, value, true);
		else view.setUint32(at, value, true);
		at += width;
	}
	return out;
}

/** A ZIP as anything would write it, with room to lie. */
function zipFile(entries: Put[]): Uint8Array<ArrayBuffer> {
	const locals: Uint8Array[] = [];
	const central: Uint8Array[] = [];
	let offset = 0;

	for (const { name, data, method = 0, size = data.length, local, stored } of entries) {
		const nameBytes = ascii(name);
		const claimed = stored ?? data.length;
		const [localStored, localSize] = local ?? [claimed, size];
		const header = concat(
			ascii('PK\x03\x04'),
			littleEndian([2, 20], [2, 0], [2, method], [2, 0], [2, 0], [4, 0]),
			littleEndian([4, localStored], [4, localSize], [2, nameBytes.length], [2, 0]),
			nameBytes,
			data
		);
		central.push(
			concat(
				ascii('PK\x01\x02'),
				littleEndian([2, 20], [2, 20], [2, 0], [2, method], [2, 0], [2, 0], [4, 0]),
				littleEndian(
					[4, claimed],
					[4, size],
					[2, nameBytes.length],
					[2, 0],
					[2, 0],
					[2, 0],
					[2, 0]
				),
				littleEndian([4, 0], [4, offset]),
				nameBytes
			)
		);
		locals.push(header);
		offset += header.length;
	}

	const directory = concat(...central);
	return concat(
		...locals,
		directory,
		ascii('PK\x05\x06'),
		littleEndian(
			[2, 0],
			[2, 0],
			[2, entries.length],
			[2, entries.length],
			[4, directory.length],
			[4, offset],
			[2, 0]
		)
	);
}

/** An entry compressed, so what it holds is read as the entry and not in the archive's bytes. */
async function packed(name: string, inside: Uint8Array): Promise<Put> {
	return {
		name,
		data: await deflated(inside, 'deflate-raw'),
		method: 8,
		size: inside.length
	};
}

function pdfFile(...objects: Uint8Array[]): Uint8Array<ArrayBuffer> {
	return concat(ascii('%PDF-1.7\n'), ...objects, ascii('trailer<</Size 1>>\n%%EOF\n'));
}

function pdfStream(number: number, filter: string, stream: Uint8Array): Uint8Array<ArrayBuffer> {
	return concat(
		ascii(`${number} 0 obj\n<</Length ${stream.length}/Filter${filter}>>\nstream\n`),
		stream,
		ascii('\nendstream\nendobj\n')
	);
}

/** A GIF of this many one-pixel frames. */
function gifFile(frames: number): Uint8Array<ArrayBuffer> {
	const frame = Uint8Array.of(0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 0x01, 0);
	return concat(
		ascii('GIF89a'),
		Uint8Array.of(1, 0, 1, 0, 0x80, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff),
		...Array.from({ length: frames }, () => frame),
		Uint8Array.of(0x3b)
	);
}

/** A WAV of one 32-bit sample, in the format this tag names. */
function wavFile(tag: number): Uint8Array<ArrayBuffer> {
	const format = littleEndian([2, tag], [2, 1], [4, 8000], [4, 32000], [2, 4], [2, 32]);
	const body = concat(
		ascii('WAVEfmt '),
		littleEndian([4, format.length]),
		format,
		ascii('data'),
		littleEndian([4, 4], [4, 0])
	);
	return concat(ascii('RIFF'), littleEndian([4, body.length]), body);
}

const PCAP_HEADER = concat(
	Uint8Array.of(0xd4, 0xc3, 0xb2, 0xa1),
	littleEndian([2, 2], [2, 4], [4, 0], [4, 0], [4, 65535], [4, 1])
);

/** A capture of this many connections, one TCP segment each, every one carrying a flag. */
function captureOfFlags(connections: number): Uint8Array<ArrayBuffer> {
	const records = Array.from({ length: connections }, (_, i) => {
		const payload = ascii(`flag{stream_${i}}`);
		const ip = 40 + payload.length;
		return concat(
			littleEndian([4, i], [4, 0], [4, 14 + ip], [4, 14 + ip]),
			new Uint8Array(12),
			Uint8Array.of(0x08, 0x00, 0x45, 0, ip >> 8, ip & 0xff, 0, 0, 0, 0, 64, 6, 0, 0),
			Uint8Array.of(10, 0, 0, 1, 10, 0, 0, 2),
			Uint8Array.of(i >> 8, i & 0xff, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0, 0, 0, 0, 0, 0),
			payload
		);
	});
	return concat(PCAP_HEADER, ...records);
}

/** A capture of one connection, where this many TCP segments each give the same bytes a new value. */
function captureArguing(segments: number): Uint8Array<ArrayBuffer> {
	const payloadLength = 8;
	const ip = 40 + payloadLength;
	const record = concat(
		littleEndian([4, 0], [4, 0], [4, 14 + ip], [4, 14 + ip]),
		new Uint8Array(12),
		Uint8Array.of(0x08, 0x00, 0x45, 0, ip >> 8, ip & 0xff, 0, 0, 0, 0, 64, 6, 0, 0),
		Uint8Array.of(10, 0, 0, 1, 10, 0, 0, 2),
		Uint8Array.of(0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0, 0, 0, 0, 0, 0),
		new Uint8Array(payloadLength)
	);
	const payload = new DataView(record.buffer, record.length - payloadLength);

	const out = new Uint8Array(PCAP_HEADER.length + record.length * segments);
	out.set(PCAP_HEADER);
	for (let i = 0; i < segments; i++) {
		payload.setUint32(0, i);
		out.set(record, PCAP_HEADER.length + i * record.length);
	}
	return out;
}

/** A database of one table whose only row runs on to an overflow page that is not there. */
function databaseCutShort(): Uint8Array<ArrayBuffer> {
	const size = 512;
	const leaf = (head: number, cell: Uint8Array) => {
		const page = new Uint8Array(size);
		const at = size - cell.length;
		page.set(cell, at);
		page[head] = 0x0d;
		page[head + 4] = 1;
		page.set([at >> 8, at & 0xff], head + 5);
		page.set([at >> 8, at & 0xff], head + 8);
		return page;
	};

	const schema = concat(
		Uint8Array.of(31, 1, 6, 23, 15, 15, 1, 47),
		ascii('tablett\x02CREATE TABLE t(a)')
	);
	// A record of 1000 bytes, 39 of them here, and then no page for the rest to be on.
	const row = concat(Uint8Array.of(0x87, 0x68, 1, 3, 0x8f, 0x57), new Uint8Array(40));

	const first = leaf(100, schema);
	first.set(ascii('SQLite format 3\0'));
	first.set([size >> 8, size & 0xff, 1, 1, 0, 64, 32, 32], 16);
	first.set([0, 0, 0, 2], 28);
	first.set([0, 0, 0, 1], 56);
	return concat(first, leaf(0, row));
}

/** One run of bytes, over and over. */
function repeated(run: Uint8Array, times: number): Uint8Array<ArrayBuffer> {
	return new Uint8Array(run.length * times).map((_, i) => run[i % run.length]);
}

function allFindings(artifacts: NestedArtifact[]): string[] {
	return artifacts.flatMap((artifact) => [
		...artifact.findings.map((finding) => finding.text),
		...allFindings(artifact.children)
	]);
}

const MEBIBYTE = 1 << 20;
const FILLED = new Uint8Array(MEBIBYTE - 1).fill(0xff);

describe('a file built to get in the way', () => {
	let worker: Worker | undefined;

	function send(request: AnalysisRequest): Promise<AnalysisResponse> {
		const running = (worker ??= new AnalysisWorker());
		return new Promise((resolve, reject) => {
			running.onerror = (event) => reject(new Error(event.message));
			running.onmessage = (event: MessageEvent<AnalysisResponse>) => resolve(event.data);
			running.postMessage(request);
		});
	}

	async function analyse(bytes: Uint8Array, flagTags = 'flag') {
		const response = await send({
			kind: 'analyse',
			id: 1,
			name: 'file',
			bytes: bytes.slice().buffer,
			flagTags
		});
		if (response.status !== 'ok') throw new Error(`analysis failed: ${JSON.stringify(response)}`);
		return response;
	}

	afterEach(() => {
		worker?.terminate();
		worker = undefined;
	});

	it(
		'keeps its flags when compressed chunks ask for more than a tab holds, and says what it left',
		{ timeout: 60_000 },
		async () => {
			const bomb = pngChunk('zTXt', concat(ascii('k\0\0'), await deflated(FILLED)));
			const early = await deflated(ascii('flag{inside_a_chunk}'));
			const file = withChunks(
				plainPng(),
				pngChunk('tEXt', ascii(`c\0${REAL}`)),
				pngChunk('zTXt', concat(ascii('k\0\0'), early)),
				...Array.from({ length: 530 }, () => bomb)
			);
			expect(file.length).toBeLessThan(MEBIBYTE);

			const response = await analyse(file);

			const flags = response.structure?.flags.map((flag) => flag.text);
			expect(flags).toContain(REAL);
			expect(flags).toContain('flag{inside_a_chunk}');

			expect(response.notes?.join(' ')).toMatch(/\d+ compressed streams were not opened/);
			expect(response.structure?.text.some((chunk) => chunk.error?.includes('budget'))).toBe(true);

			// What reached the page is the start of each, and no more than the budget.
			const kept = response.structure?.text.reduce((total, chunk) => total + chunk.text.length, 0);
			expect(kept).toBeLessThanOrEqual(17 * MEBIBYTE);
		}
	);

	it(
		'keeps the flags of a PDF whose streams ask for more than a tab holds',
		{ timeout: 60_000 },
		async () => {
			const bomb = await deflated(FILLED);
			const file = pdfFile(
				pdfStream(1, '/FlateDecode', await deflated(ascii(`BT ${REAL} ET`))),
				...Array.from({ length: 900 }, (_, i) => pdfStream(i + 2, '/FlateDecode', bomb))
			);
			expect(file.length).toBeLessThan(MEBIBYTE);

			const response = await analyse(file);

			expect(response.pdf?.objects[0].flags).toContain(REAL);
			expect(response.notes?.join(' ')).toMatch(/\d+ compressed streams were not opened/);
			expect(response.pdf?.objects.at(-1)?.stream?.error).toContain('budget');
		}
	);

	it('says what it left unopened inside a nested file as well', { timeout: 60_000 }, async () => {
		const bomb = pngChunk('zTXt', concat(ascii('k\0\0'), await deflated(FILLED)));
		const nested = withChunks(plainPng(), ...Array.from({ length: 530 }, () => bomb));

		const response = await analyse(zipFile([{ name: 'bombs.png', data: nested }]));

		expect(response.nested?.roots[0].status).toBe('analysed');
		expect(response.notes?.join(' ')).toMatch(/\d+ compressed streams were not opened/);
	});

	describe('with a file behind an entry that claims to cover it', () => {
		const hidden = lsbPng(REAL);

		it.each([
			['a stream that cannot be read', async () => noise(16, 3)],
			['a stream that ends straight away', async () => deflated(ascii('x'), 'deflate-raw')]
		])('still carves it past %s', async (_, stream) => {
			const packed = await stream();
			const response = await analyse(
				zipFile([{ name: 'cover.bin', data: concat(packed, hidden), method: 8, size: 1 }])
			);

			expect(allFindings(response.nested?.roots ?? [])).toContain(REAL);
		});

		it('reads it through the entry when the entry really holds it', async () => {
			const response = await analyse(zipFile([{ name: 'plain.bin', data: hidden }]));

			const entry = response.nested?.roots.find((child) => child.name === 'plain.bin');
			expect(entry?.status).toBe('analysed');
			expect(response.nested?.roots.filter((child) => child.source === 'carved')).toEqual([]);
			expect(allFindings(entry ? [entry] : [])).toContain(REAL);
		});
	});

	it(
		'does not take a real file for a duplicate of a decoy with the same head, tail and length',
		{ timeout: 30_000 },
		async () => {
			const inner = (flag: string) =>
				zipFile([{ name: 'a.txt', data: concat(new Uint8Array(80).fill(0x20), ascii(flag)) }]);
			const decoy = inner('flag{only_the_decoy}');
			const real = inner('flag{the_real__one}!');
			expect(decoy.length).toBe(real.length);
			expect(decoy.subarray(0, 64)).toEqual(real.subarray(0, 64));
			expect(decoy.subarray(-64)).toEqual(real.subarray(-64));

			const response = await analyse(
				zipFile([await packed('one.zip', decoy), await packed('two.zip', real)])
			);

			const two = response.nested?.roots.find((child) => child.name === 'two.zip');
			expect(two?.status).toBe('analysed');
			expect(allFindings(two ? [two] : [])).toContain('flag{the_real__one}');
		}
	);

	describe('with damaged pixel data', () => {
		const good = lsbPng(REAL);

		it.each([
			['a byte after the zlib stream', (idat: Uint8Array) => concat(idat, ascii('x'))],
			[
				'a wrong Adler-32',
				(idat: Uint8Array) => {
					const wrong = idat.slice();
					wrong[wrong.length - 1] ^= 1;
					return wrong;
				}
			],
			['the end cut off', (idat: Uint8Array) => idat.subarray(0, idat.length - 8)]
		])('still reads the pixels with %s, and says so', async (_, damage) => {
			const response = await analyse(withIdat(good, damage));

			expect(response.pixelError).toBeNull();
			expect(response.sweep?.candidates.flatMap((candidate) => candidate.flags)).toContain(REAL);
			expect(response.notes?.join(' ')).toMatch(/image data/);
		});

		it('says nothing about pixel data that is whole', async () => {
			const response = await analyse(good);

			expect(response.sweep?.candidates.flatMap((candidate) => candidate.flags)).toContain(REAL);
			expect(response.notes).toEqual([]);
		});

		it('reports the rows it reached when the stream stops early', async () => {
			const half = withIdat(good, (idat) => idat.subarray(0, Math.floor(idat.length / 2)));

			const response = await analyse(half);

			expect(response.pixelError).toBeNull();
			expect(response.sweep?.candidates.flatMap((candidate) => candidate.flags)).toContain(REAL);
			expect(response.notes?.join(' ')).toMatch(/read \d+ of 32 rows/);
		});
	});

	it('keeps what a damaged compressed chunk gave, with what went wrong', async () => {
		const stream = await deflated(ascii(`the flag is ${REAL} ok`));
		const wrong = stream.slice();
		wrong[wrong.length - 1] ^= 1;

		for (const [damaged, says] of [
			[concat(stream, ascii('x')), '1 byte follows the end of the stream'],
			[wrong, 'Adler-32'],
			[stream.subarray(0, stream.length - 4), 'ends before its Adler-32']
		] as const) {
			const response = await analyse(
				withChunks(plainPng(), pngChunk('zTXt', concat(ascii('a\0\0'), damaged)))
			);

			expect(response.structure?.flags.map((flag) => flag.text)).toContain(REAL);
			expect(response.structure?.text[0].error).toContain(says);
			expect(response.structure?.text[0].text).toContain(REAL);
		}
	});

	describe('with a ZIP that lies', () => {
		const text = ascii(`aaaa ${REAL} bbbb `.repeat(3));

		it.each([
			['zero', 0, 0],
			['0xffffffff', 0xffffffff, 0xffffffff],
			['two mebibytes once opened', null, 2 << 20]
		])('opens an entry whose local header says its sizes are %s', async (_, stored, opened) => {
			const data = await deflated(text, 'deflate-raw');
			const response = await analyse(
				zipFile([
					{
						name: 'x.txt',
						data,
						method: 8,
						size: text.length,
						local: [stored ?? data.length, opened]
					}
				])
			);

			const entry = response.zip?.entries[0];
			expect(entry?.flags).toContain(REAL);
			expect(entry?.compressed).toBe(data.length);
			expect(entry?.uncompressed).toBe(text.length);
		});

		it('opens an entry both descriptions call zero bytes stored', async () => {
			const data = await deflated(text, 'deflate-raw');
			const response = await analyse(
				zipFile([{ name: 'x.txt', data, method: 8, size: text.length, stored: 0 }])
			);

			expect(response.zip?.entries[0].flags).toContain(REAL);
		});

		it(
			'charges entries for what they hold rather than what they declare',
			{ timeout: 30_000 },
			async () => {
				const response = await analyse(
					zipFile([
						...Array.from({ length: 8 }, (_, i) => ({
							name: `tiny${i}`,
							data: ascii(`entry ${i}`),
							size: MEBIBYTE
						})),
						{ name: 'real.txt', data: ascii(`entry ${REAL}`) }
					])
				);

				const real = response.nested?.roots.find((child) => child.name === 'real.txt');
				expect(real?.status).toBe('analysed');
				expect(allFindings(real ? [real] : [])).toContain(REAL);
				expect(response.nested?.expandedBytes).toBeLessThan(1024);
				expect(response.nested?.capped).toBe(false);
			}
		);

		it('does not charge for a file it has already read', { timeout: 60_000 }, async () => {
			const bomb = await deflated(FILLED, 'deflate-raw');
			const response = await analyse(
				zipFile([
					...Array.from({ length: 96 }, (_, i) => ({
						name: `copy${i}`,
						data: bomb,
						method: 8 as const,
						size: FILLED.length
					})),
					{ name: 'real.txt', data: ascii(`entry ${REAL}`) }
				])
			);

			const roots = response.nested?.roots ?? [];
			expect(roots.filter((child) => child.reason?.startsWith('duplicate of')).length).toBe(95);
			expect(response.nested?.expandedBytes).toBeLessThan(2 * MEBIBYTE);

			const real = roots.find((child) => child.name === 'real.txt');
			expect(real?.status).toBe('analysed');
			expect(allFindings(real ? [real] : [])).toContain(REAL);
		});

		it('opens entries well past the fortieth', { timeout: 30_000 }, async () => {
			const response = await analyse(
				zipFile(
					Array.from({ length: 64 }, (_, i) => ({
						name: `f${i}`,
						data: ascii(i === 63 ? REAL : `entry number ${i}`)
					}))
				)
			);

			expect(response.nested?.analysed).toBe(64);
			expect(allFindings(response.nested?.roots ?? [])).toContain(REAL);
		});

		it('says on an entry why it was not opened', { timeout: 60_000 }, async () => {
			const bomb = await deflated(FILLED, 'deflate-raw');
			const response = await analyse(
				zipFile(
					Array.from({ length: 140 }, (_, i) => ({
						name: `b${i}`,
						data: bomb,
						method: 8 as const,
						size: FILLED.length
					}))
				)
			);

			const unopened = response.zip?.entries.filter((entry) => entry.notOpened) ?? [];
			expect(unopened.length).toBeGreaterThan(0);
			expect(unopened[0].notOpened).toContain('budget');
			expect(response.notes?.join(' ')).toMatch(/\d+ compressed streams? (was|were) not opened/);
		});
	});

	describe('with decoys', () => {
		const DECOYS = 'abc{aaaa}\n'.repeat(10_000);

		it('finds a flag behind ten thousand other shapes in a compressed entry', async () => {
			const held = ascii(`${DECOYS}${REAL}`);
			const response = await analyse(
				zipFile([
					{
						name: 'a.txt',
						data: await deflated(held, 'deflate-raw'),
						method: 8,
						size: held.length
					}
				])
			);

			expect(response.zip?.entries[0].flags).toContain(REAL);
		});

		it('finds a flag behind ten thousand other shapes in a compressed chunk', async () => {
			const response = await analyse(
				withChunks(
					plainPng(),
					pngChunk('zTXt', concat(ascii('k\0\0'), await deflated(ascii(`${DECOYS}${REAL}`))))
				)
			);

			expect(response.structure?.flags.map((flag) => flag.text)).toContain(REAL);
		});

		it('finds a flag behind thousands of distinct shapes, and says the list stopped', async () => {
			const distinct = Array.from({ length: 12_000 }, (_, i) => `abc{aaaa${i}}`).join('\n');

			const response = await analyse(ascii(`${distinct}\n${REAL}`));

			expect(response.survey.flags.map((flag) => flag.text)).toContain(REAL);
			expect(response.notes?.join(' ')).toMatch(/more distinct flags than Trawl lists/);
		});

		it('still carves a PNG behind thousands of another signature', async () => {
			const decoys = new Uint8Array(4096 * 6).map(
				(_, i) => [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c][i % 6]
			);
			const response = await analyse(concat(decoys, lsbPng(REAL)));

			expect(response.survey.magic.some((hit) => hit.label === 'PNG image' && hit.embedded)).toBe(
				true
			);
			expect(allFindings(response.nested?.roots ?? [])).toContain(REAL);
		});
	});

	describe('with a tag the person configured', () => {
		const TAGS = 'flag,HV,cyberapocalypse,CSAW';

		it.each(['HV{two_letter_tag}', 'cyberapocalypse{long_tag_here}', 'CSAW{tHiS_iS_MiXeD_cAsE}'])(
			'reports %s in the raw bytes as a flag',
			async (flag) => {
				const response = await analyse(ascii(`xx ${flag} yy`), TAGS);

				const found = response.survey.flags.find((hit) => hit.text === flag);
				expect(found?.credible).toBe(true);
			}
		);

		it('reports one in a PNG text chunk', async () => {
			const response = await analyse(
				withChunks(plainPng(), pngChunk('tEXt', ascii('c\0HV{two_letter_tag}'))),
				TAGS
			);

			expect(response.structure?.flags.map((flag) => flag.text)).toContain('HV{two_letter_tag}');
		});

		it('takes a body a person would call a password', async () => {
			const response = await analyse(ascii('flag{p@$$w0rd_1s_$3cr3t}'));

			expect(response.survey.flags.map((flag) => flag.text)).toContain('flag{p@$$w0rd_1s_$3cr3t}');
		});

		it('keeps a flag credible whatever bytes surround it', async () => {
			const response = await analyse(concat(noise(600), ascii(REAL), noise(600, 7)));

			const found = response.survey.flags.find((flag) => flag.text === REAL);
			expect(found?.credible).toBe(true);
		});
	});

	describe('with a PDF only a thorough reader would read', () => {
		const held = `BT ${REAL} ET`;

		it('says when a PDF inside an archive could not be read in full', async () => {
			const filters = `[${'/ASCIIHexDecode '.repeat(9)}]`;
			let layered = ascii('flag');
			for (let layer = 0; layer < 9; layer += 1) layered = ascii(hex(layered));
			const pdf = pdfFile(pdfStream(1, filters, layered));

			const response = await analyse(zipFile([{ name: 'inner.pdf', data: pdf }]));

			const child = response.nested?.roots.find((root) => root.name === 'inner.pdf');
			expect(child?.status).toBe('analysed');
			expect(child?.damage).toContain('9 filters');
			expect(response.notes?.join(' ')).toContain('could not be read in full');
		});

		it.each([
			['a hex-escaped filter name', '/Fl#61teDecode', async () => deflated(ascii(held))],
			[
				'a hex filter ahead of a Flate one',
				'[/ASCIIHexDecode/FlateDecode]',
				async () => ascii(`${hex(await deflated(ascii(held)))}>`)
			],
			['short filter names', '[/AHx/Fl]', async () => ascii(`${hex(await deflated(ascii(held)))}>`)]
		])('reads a stream behind %s', async (_, filter, stream) => {
			const response = await analyse(pdfFile(pdfStream(1, filter, await stream())));

			expect(response.pdf?.objects[0].flags).toContain(REAL);
		});

		it(
			'says when a PDF holds more streams than it was told about',
			{ timeout: 120_000 },
			async () => {
				const objects = Array.from(
					{ length: (1 << 16) + 2 },
					(_, i) => `${i + 1} 0 obj\n<</Length 1>>\nstream\nx\nendstream\nendobj\n`
				);
				const pdf = pdfFile(ascii(objects.join('')));

				const response = await analyse(pdf);
				expect(response.notes?.join(' ')).toContain('2 PDF streams were never opened');

				const nested = await analyse(zipFile([{ name: 'many.pdf', data: pdf }]));
				const child = nested.nested?.roots.find((root) => root.name === 'many.pdf');
				expect(child?.damage).toContain('2 PDF streams were never opened');
			}
		);

		it('reads a stream whose filter array points at its name', async () => {
			const response = await analyse(
				pdfFile(
					pdfStream(1, '[9 0 R]', await deflated(ascii(held))),
					ascii('9 0 obj\n/FlateDecode\nendobj\n')
				)
			);

			expect(response.pdf?.objects[0].flags).toContain(REAL);
		});

		it('reads a stream behind a PNG predictor', async () => {
			const columns = 8;
			const text = ascii(held);
			const predicted: number[] = [];
			for (let at = 0; at < text.length; at += columns) {
				predicted.push(1);
				let left = 0;
				for (const byte of text.subarray(at, at + columns)) {
					predicted.push((byte - left) & 0xff);
					left = byte;
				}
			}

			const filter = `/FlateDecode/DecodeParms<</Predictor 11/Columns ${columns}>>`;
			const stream = await deflated(Uint8Array.from(predicted));
			const response = await analyse(pdfFile(pdfStream(1, filter, stream)));

			expect(response.pdf?.objects[0].flags).toContain(REAL);
		});

		it.each([
			['a newline', '1 0\nobj'],
			['tabs', '1\t0\tobj']
		])('finds an object whose header is split by %s', async (_, header) => {
			const stream = await deflated(ascii(held));
			const response = await analyse(
				pdfFile(
					concat(
						ascii(`${header}\n<</Filter/FlateDecode>>\nstream\n`),
						stream,
						ascii('\nendstream\nendobj\n')
					)
				)
			);

			expect(response.pdf?.objects[0].flags).toContain(REAL);
		});

		it('is not fooled by a closing mark inside a string', async () => {
			const stream = await deflated(ascii(held));
			const response = await analyse(
				pdfFile(
					concat(
						ascii('1 0 obj\n<</Title(>>)/Filter/FlateDecode>>\nstream\n'),
						stream,
						ascii('\nendstream\nendobj\n')
					)
				)
			);

			expect(response.pdf?.objects[0].stream?.filter).toBe('FlateDecode');
			expect(response.pdf?.objects[0].flags).toContain(REAL);
		});

		it('reads the flags of a PDF inside an archive', async () => {
			const pdf = pdfFile(pdfStream(1, '/FlateDecode', await deflated(ascii(held))));

			const response = await analyse(
				zipFile([
					{ name: 'a.pdf', data: await deflated(pdf, 'deflate-raw'), method: 8, size: pdf.length }
				])
			);

			expect(allFindings(response.nested?.roots ?? [])).toContain(REAL);
		});
	});

	describe('with a nested file it could not read in full', () => {
		const DISTINCT = Array.from({ length: 12_000 }, (_, i) => `abc{aaaa${i}}`).join('\n');
		const SIGNATURES = repeated(Uint8Array.of(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c), 4100);
		const LOCAL_HEADER = concat(
			ascii('PK\x03\x04'),
			littleEndian([2, 20], [2, 0], [2, 0], [2, 0], [2, 0], [4, 0], [4, 0], [4, 0], [2, 1], [2, 0]),
			ascii('x')
		);

		async function nested(inner: Uint8Array) {
			const response = await analyse(zipFile([await packed('inner', inner)]));
			const child = response.nested?.roots.find((root) => root.name === 'inner');
			if (!child) throw new Error('the walk did not reach it');
			return { response, child };
		}

		it.each<[string, () => Uint8Array | Promise<Uint8Array>, string]>([
			['more flags than are listed', () => ascii(DISTINCT), 'the list of flags stops partway'],
			['more signatures than are listed', () => SIGNATURES, 'more file signatures were left out'],
			[
				'more flagged connections than are listed',
				() => captureOfFlags(1025),
				'the list of flags stops partway'
			],
			[
				'more packets than are read',
				() => concat(PCAP_HEADER, new Uint8Array(16 * 500_001)),
				'packets and stopped'
			],
			[
				'more disagreeing segments than are tried',
				() => captureArguing(65_538),
				'not every disagreeing TCP segment was tried'
			],
			[
				'a database cell that stops short',
				databaseCutShort,
				'a long database cell was not read to its end'
			],
			[
				'more local headers than are read',
				() => repeated(LOCAL_HEADER, 65_537),
				'stopped reading local headers at'
			],
			['more GIF frames than are read', () => gifFile(129), 'of 129 GIF frames'],
			['a GIF cut off part way', () => gifFile(2).subarray(0, -4), 'GIF frames stop short'],
			[
				'pixel data cut off part way',
				() => withIdat(lsbPng(REAL), (idat) => idat.subarray(0, idat.length >> 1)),
				'of 32 image rows'
			],
			[
				'pixel data with something after it',
				() => withIdat(lsbPng(REAL), (idat) => concat(idat, ascii('x'))),
				'the image data is damaged (1 byte follows'
			],
			[
				'pixel data that cannot be read',
				() => withIdat(plainPng(), () => noise(16, 3)),
				'the image data could not be read'
			],
			[
				'a row the pixel tools refuse',
				async () => {
					const stream = await deflated(Uint8Array.of(9, 1, 2, 3));
					return withIdat(plainPng(), () => stream);
				},
				'the pixel tools failed'
			],
			['samples the audio sweep refuses', () => wavFile(3), 'the audio sweep failed'],
			['a WAV that does not walk', () => wavFile(2), 'the WAV could not be read'],
			[
				'a JPEG that does not decode',
				() => Uint8Array.of(0xff, 0xd8, 0xff, 0xe0, 0, 2, 0xff, 0xd9),
				'JPEG coefficients could not be read'
			],
			['a GIF with no frames', () => gifFile(0), 'GIF frames could not be read']
		])('says so about %s', { timeout: 60_000 }, async (_, inner, says) => {
			const { response, child } = await nested(await inner());

			expect(child.status).toBe('analysed');
			expect(child.damage).toContain(says);
			expect(response.notes?.join(' ')).toContain('1 nested file could not be read in full');
		});

		it(
			'says how far it read an image too big for what a nested file gets',
			{ timeout: 60_000 },
			async () => {
				const stream = await deflated(new Uint8Array(3001 * 12_000));
				const pixels = new Uint8Array(3000 * 12_000);
				const { child } = await nested(withIdat(encodePng(1000, 12_000, 2, pixels), () => stream));

				expect(child.damage).toContain(`of ${(12_000).toLocaleString()} image rows`);
				expect(child.damage).toContain('only the first');
			}
		);

		it('gives the reason on the page and in the writeup at any depth', async () => {
			const { response, child } = await nested(zipFile([await packed('deep.gif', gifFile(129))]));
			const deep = child.children.find((artifact) => artifact.name === 'deep.gif');

			expect(child.damage).toBeUndefined();
			expect(deep?.damage).toContain('of 129 GIF frames');
			expect(response.notes?.join(' ')).toContain('1 nested file could not be read in full');
			expect(writeupMarkdown(response, [], [])).toContain(deep?.damage);
		});

		it('counts a nested file that could not be opened at all', async () => {
			const reservedBlockType = Uint8Array.of(0x07);
			const response = await analyse(
				zipFile([{ name: 'broken', data: reservedBlockType, method: 8, size: 1 }])
			);

			expect(response.nested?.roots[0].status).toBe('error');
			expect(response.notes?.join(' ')).toContain('1 nested file could not be read in full');
		});

		it.each<[string, () => Uint8Array]>([
			['plain text', () => ascii('nothing to see in here')],
			['text that opens like a bitmap', () => ascii('BMW built this, and it is no picture')],
			['a whole PNG', () => lsbPng(REAL)],
			['a whole GIF', () => gifFile(2)],
			['a whole WAV', () => wavFile(1)]
		])('says nothing about %s', async (_, inner) => {
			const { response, child } = await nested(inner());

			expect(child.status).toBe('analysed');
			expect(child.damage).toBeUndefined();
			expect(response.notes).toEqual([]);
		});

		it('says nothing about a JPEG signature that turned up by chance', async () => {
			const chance = Uint8Array.of(0xff, 0xd8, 0xff, 0xe0, 0, 2, 0xff, 0xd9);

			const response = await analyse(concat(noise(64), chance, noise(64, 5)));

			const carved = response.nested?.roots.find((root) => root.format === 'JPEG image');
			expect(carved?.status).toBe('analysed');
			expect(carved?.damage).toBeUndefined();
			expect(response.notes).toEqual([]);
		});

		it.each([
			'/samples/spectrogram-and-lsb.wav',
			'/samples/archives/recursive-files.zip',
			'/samples/archives/doctored-directory.zip',
			'/samples/survey/carved-zlib-text-png.bin',
			'/samples/survey/png-post-iend.png'
		])('says nothing about the nested files of %s', async (sample) => {
			const bytes = await (await fetch(sample)).arrayBuffer();

			const response = await analyse(new Uint8Array(bytes));

			expect(response.nested?.analysed).toBeGreaterThan(0);
			expect(response.notes).toEqual([]);
		});

		it('keeps a reason that quotes the file to a short line', async () => {
			const { child } = await nested(pdfFile(pdfStream(1, `/${'A'.repeat(100_000)}`, ascii('x'))));

			expect(child.damage).toContain('Trawl does not read AAAA');
			expect(child.damage?.length).toBeLessThan(200);
		});

		it('counts the reasons past the first few rather than listing them', async () => {
			const { child } = await nested(
				withChunks(
					withIdat(plainPng(), () => noise(16, 3)),
					pngChunk('zTXt', concat(ascii('a\0\0'), noise(16, 3))),
					pngChunk('tEXt', ascii(`c\0${DISTINCT}`)),
					pngChunk('tEXt', concat(ascii('d\0'), SIGNATURES))
				)
			);

			expect(child.damage).toContain('the image data could not be read');
			expect(child.damage).toMatch(/; and 1 more$/);
		});
	});

	it('answers plane and extract requests from the latest image it decoded', async () => {
		await analyse(encodePng(2, 1, 2, Uint8Array.of(1, 1, 1, 0, 0, 0)));

		const plane = await send({ kind: 'plane', id: 1, channel: 0, bit: 0 });
		if (plane.status !== 'plane') throw new Error(`plane failed: ${JSON.stringify(plane)}`);
		expect(Array.from(plane.pixels)).toEqual([255, 0]);

		await analyse(lsbPng(REAL));

		const extracted = await send({
			kind: 'extract',
			id: 1,
			columnMajor: false,
			channels: 'rgb',
			bit: 0,
			msbFirst: true
		});
		if (extracted.status !== 'extract') {
			throw new Error(`extract failed: ${JSON.stringify(extracted)}`);
		}
		expect(new TextDecoder().decode(extracted.bytes)).toContain(REAL);

		const next = await send({ kind: 'plane', id: 1, channel: 0, bit: 0 });
		if (next.status !== 'plane') throw new Error(`plane failed: ${JSON.stringify(next)}`);
		expect(next.pixels.length).toBe(32 * 32);
	});

	it('says when a paste has more readings than it follows', { timeout: 120_000 }, async () => {
		const peelOf = async (text: string) => {
			const response = await send({ kind: 'peel', id: 1, text, flagTags: 'flag' });
			if (response.status !== 'peel') throw new Error(`peel failed: ${JSON.stringify(response)}`);
			return response.peel;
		};

		const token = `%${'25'.repeat(6)}41&${'#38;'.repeat(6)}#65;=${'3D'.repeat(6)}41 `;
		expect((await peelOf(token.repeat(Math.floor((256 << 10) / token.length)))).searchCut).toBe(
			true
		);
		expect((await peelOf(btoa('flag{nothing_unseen}'))).searchCut).toBe(false);
	});

	it('breaks RSA off the page, and only for a paste that names a key', async () => {
		const rsaOf = async (text: string) => {
			const response = await send({ kind: 'peel', id: 1, text, flagTags: 'flag' });
			if (response.status !== 'peel') throw new Error(`peel failed: ${JSON.stringify(response)}`);
			return response.rsa;
		};

		expect((await rsaOf('n = 3233, e = 17'))?.recovered.length).toBeGreaterThan(0);
		expect(await rsaOf('the quick brown fox')).toBeNull();
	});

	it('extracts a message written a column at a time the way the sweep found it', async () => {
		const [width, height] = [32, 32];
		const bits = Array.from(ascii(REAL)).flatMap((byte) =>
			Array.from({ length: 8 }, (_, bit) => (byte >> (7 - bit)) & 1)
		);
		const pixels = new Uint8Array(width * height * 3).fill(0x40);
		bits.forEach((bit, i) => {
			const step = Math.floor(i / 3);
			const pixel = (step % height) * width + Math.floor(step / height);
			pixels[pixel * 3 + (i % 3)] |= bit;
		});

		const response = await analyse(encodePng(width, height, 2, pixels));
		const hit = response.sweep?.candidates.find((candidate) => candidate.flags.includes(REAL));
		if (!hit) throw new Error('the sweep did not find it');
		expect(hit.columnMajor).toBe(true);

		const extracted = await send({
			kind: 'extract',
			id: 1,
			channels: hit.channels,
			bit: hit.bit,
			msbFirst: hit.msbFirst,
			columnMajor: true
		});
		if (extracted.status !== 'extract') throw new Error(JSON.stringify(extracted));
		expect(new TextDecoder().decode(extracted.bytes)).toContain(REAL);
		expect(extracted.label).toContain('by column');
	});

	it(
		'says when a capture has more disagreeing segments than it tries',
		{ timeout: 60_000 },
		async () => {
			const { notes } = await analyse(captureArguing(65_538));

			expect(notes?.join(' ')).toContain('more disagreeing TCP segments than Trawl tries');
		}
	);

	it('says when a capture saved fewer bytes of a packet than it carried', async () => {
		worker = new AnalysisWorker();
		const whole = new Uint8Array(
			await (await fetch('/samples/network/http-flag.pcap')).arrayBuffer()
		);
		const snapped = whole.slice();
		// The first record's original length, past what it says it saved.
		const view = new DataView(snapped.buffer);
		const little = view.getUint32(0, true) === 0xa1b2c3d4;
		view.setUint32(24 + 12, view.getUint32(24 + 8, little) + 100, little);

		expect((await analyse(whole)).notes).toEqual([]);
		expect((await analyse(snapped)).notes?.join(' ')).toContain('saved with fewer bytes');
	});

	it('fails a plane request plainly when there are no pixels to read', async () => {
		await analyse(ascii('not an image'));

		const response = await send({ kind: 'plane', id: 1, channel: 0, bit: 0 });

		expect(response.status).toBe('error');
	});

	it(
		'stops the walk when its clock runs out and keeps what the file itself gave',
		{ timeout: 180_000 },
		async () => {
			// AES tries every pairing of these, which is about as long as anything takes on a
			// file this size, and the entries together come to several times what the walk is
			// given. Each starts a byte further on, so none is a duplicate of another.
			const ciphertexts = Array.from({ length: 24 }, (_, i) =>
				btoa(String.fromCharCode(...noise(4096, i + 1)))
			);
			const keys = Array.from({ length: 64 }, (_, i) => hex(noise(32, i + 100)));
			const blob = ascii(`${[...ciphertexts, ...keys].join(' ')} ${REAL}`);

			const response = await analyse(
				zipFile(Array.from({ length: 96 }, (_, i) => ({ name: `c${i}`, data: blob.subarray(i) })))
			);

			expect(response.survey.flags.map((flag) => flag.text)).toContain(REAL);
			expect(response.zip?.entries.length).toBe(96);
			expect(response.nested?.capped).toBe(true);
			expect(
				response.nested?.roots.some(
					(child) =>
						child.status === 'skipped' &&
						child.reason === 'the time budget for nested files ran out'
				)
			).toBe(true);
			expect(response.notes?.join(' ')).toMatch(/time budget for nested files ran out/);
		}
	);
});
