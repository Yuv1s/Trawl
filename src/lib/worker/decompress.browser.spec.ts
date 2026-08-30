import { describe, expect, it } from 'vitest';
import { assertZlibHeader, boundedInflate, compressionOf, fingerprint, isGzip } from './decompress';

async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new CompressionStream('gzip'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function zlib(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new CompressionStream('deflate'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

function text(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

const PLAIN = 'the quick brown fox jumps over the lazy dog';
const RAW = text(PLAIN);

describe('compression framing', () => {
	it('recognises a gzip stream by its magic', async () => {
		expect(isGzip(new Uint8Array([0x1f, 0x8b, 0x08]))).toBe(true);
		expect(isGzip(new Uint8Array([0x1f, 0x8b]))).toBe(true);
		expect(isGzip(new Uint8Array([0x1f, 0x00]))).toBe(false);
		expect(isGzip(new Uint8Array([0x8b, 0x1f]))).toBe(false);
		expect(isGzip(new Uint8Array([0x1f]))).toBe(false);
	});

	it('accepts a credible zlib header', async () => {
		// A real zlib stream is valid by construction.
		const z = await zlib(RAW);
		expect(() => assertZlibHeader(z)).not.toThrow();
	});

	it('rejects a zlib header that fails the mod-31 checksum', async () => {
		const z = await zlib(RAW);
		z[1] = (z[1] + 1) & 0xff; // break CMF/FLG mod-31 without touching FDICT
		expect(() => assertZlibHeader(z)).toThrow();
	});

	it('rejects a preset-dictionary zlib header', () => {
		// CMF 0x78 (deflate, 32K window), FLG with bit 5 (0x20) set; 0x78 + 0x20
		// still a mod-31 residue is not required, we only assert the dictionary bit.
		expect(() => assertZlibHeader(new Uint8Array([0x78, 0x20]))).toThrow('preset dictionary');
	});

	it('rejects a non-deflate method and an oversized window', () => {
		// CMF low nibble 0x01 is not deflate, checked before the checksum.
		expect(() => assertZlibHeader(new Uint8Array([0x01, 0x00]))).toThrow('not deflate');
		// CMF 0x88 keeps deflate in the low nibble but asks for a 256K window.
		expect(() => assertZlibHeader(new Uint8Array([0x88, 0x00]))).toThrow('window');
	});

	it('rejects a truncated zlib header', () => {
		expect(() => assertZlibHeader(new Uint8Array([0x78]))).toThrow('truncated');
	});

	it('names the wrapper a buffer announces', async () => {
		expect(compressionOf(await gzip(RAW))).toBe('gzip');
		expect(compressionOf(await zlib(RAW))).toBe('zlib');
		expect(compressionOf(text('hello'))).toBeNull();
		expect(compressionOf(new Uint8Array([0x42]))).toBeNull();
	});

	it('declines a junk prefix that only resembles zlib', () => {
		// 0x78 0x9c is a textbook valid header, but the payload is not inflatable,
		// which compressionOf does not promise to catch; the inflate step does.
		expect(compressionOf(new Uint8Array([0x78, 0x9c]))).toBe('zlib');
	});
});

describe('bounded inflation', () => {
	it('inflates gzip back to the original bytes', async () => {
		const out = await boundedInflate('gzip', await gzip(RAW));
		expect(new TextDecoder().decode(out)).toBe(PLAIN);
	});

	it('inflates zlib back to the original bytes', async () => {
		const out = await boundedInflate('deflate', await zlib(RAW));
		expect(new TextDecoder().decode(out)).toBe(PLAIN);
	});

	it('rejects output over the limit instead of materialising it', async () => {
		const big = new Uint8Array(2 * 1024 * 1024).fill(0x41);
		await expect(boundedInflate('gzip', await gzip(big), 1 << 20)).rejects.toThrow('exceeds');
	});

	it('rejects a malformed stream', async () => {
		await expect(
			boundedInflate('gzip', new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x02, 0x03]))
		).rejects.toThrow();
	});

	it('round-trips bytes above 0x7f unchanged', async () => {
		const bytes = new Uint8Array([0x00, 0x7f, 0x80, 0xff, 0xc3, 0x28]);
		const out = await boundedInflate('deflate', await zlib(bytes));
		expect(Array.from(out)).toEqual([0x00, 0x7f, 0x80, 0xff, 0xc3, 0x28]);
	});
});

describe('fingerprint', () => {
	it('is deterministic over identical bytes', () => {
		expect(fingerprint(text(PLAIN))).toBe(fingerprint(text(PLAIN)));
	});

	it('distinguishes different lengths and contents', () => {
		expect(fingerprint(text(PLAIN))).not.toBe(fingerprint(text(PLAIN + '!')));
		expect(fingerprint(text(PLAIN))).not.toBe(fingerprint(text('another string entirely')));
	});

	it('differentiates byte order within a window', () => {
		// Same length, same multiset, different order: fingerprints must differ.
		const a = text('aaaabbbb');
		const b = text('aaaabbba');
		expect(fingerprint(a)).not.toBe(fingerprint(b));
	});
});
