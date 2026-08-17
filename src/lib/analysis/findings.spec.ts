import { describe, expect, it } from 'vitest';
import { findings } from './findings';
import type { Chunk, Structure } from '$lib/worker/protocol';

const chunk = (kind: string, offset: number, length = 0, crcOk = true): Chunk => ({
	kind,
	offset,
	length,
	dataOffset: offset + 8,
	crcOk,
	ancillary: kind[0] === kind[0].toLowerCase()
});

const clean: Structure = {
	signature: true,
	size: 1024,
	header: { width: 64, height: 64, bitDepth: 8, colorType: 2, interlace: 0 },
	chunks: [chunk('IHDR', 8, 13), chunk('IDAT', 33, 900), chunk('IEND', 945)],
	text: [],
	flags: [],
	trailing: null
};

const titles = (s: Structure) => findings(s).map((f) => f.title);
const flaggedTitles = (s: Structure) =>
	findings(s)
		.filter((f) => f.flagged)
		.map((f) => f.title);

describe('findings', () => {
	it('flags nothing on a well-formed file', () => {
		expect(flaggedTitles(clean)).toEqual([]);
	});

	it('still reports routine facts when nothing is flagged', () => {
		expect(titles(clean)).toEqual(['64 by 64, 8-bit truecolour', '900 bytes of pixel data']);
	});

	it('flags bytes after IEND', () => {
		const s = { ...clean, trailing: { offset: 957, length: 2048 } };
		expect(flaggedTitles(s)).toEqual(['2,048 bytes after IEND']);
	});

	it('flags a CRC mismatch and names the chunk', () => {
		const s = { ...clean, chunks: [chunk('IHDR', 8, 13), chunk('tEXt', 33, 40, false)] };
		expect(flaggedTitles(s)).toContain('CRC mismatch on tEXt at 0x21');
	});

	it('flags a truncated walk with no IEND', () => {
		const s = { ...clean, chunks: [chunk('IHDR', 8, 13)] };
		expect(flaggedTitles(s)).toContain('No IEND chunk');
	});

	it('reports compressed text as unread rather than empty', () => {
		const s: Structure = {
			...clean,
			text: [
				{
					kind: 'zTXt',
					keyword: 'Secret',
					text: '',
					compressed: true,
					payloadOffset: 60,
					payloadLength: 12
				}
			]
		};
		const finding = findings(s).find((f) => f.id.startsWith('text-'));
		expect(finding?.detail).toMatch(/not yet inflated/);
	});

	it('surfaces a header error instead of dropping it', () => {
		const s: Structure = { ...clean, header: { error: 'bit depth 16 unsupported' } };
		expect(flaggedTitles(s)).toContain('IHDR cannot be decoded');
	});

	it('ranks every flagged finding above every routine one', () => {
		const s: Structure = { ...clean, trailing: { offset: 957, length: 12 } };
		const order = findings(s).map((f) => f.flagged);
		expect(order.indexOf(false)).toBeGreaterThan(order.lastIndexOf(true));
	});
});
