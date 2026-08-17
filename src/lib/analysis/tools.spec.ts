import { describe, expect, it } from 'vitest';
import { PLANNED, tools } from './tools';
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
	header: { width: 64, height: 64, bitDepth: 8, colorType: 6, interlace: 0 },
	chunks: [chunk('IHDR', 8, 13), chunk('IDAT', 33, 900), chunk('IEND', 945)],
	text: [],
	flags: [],
	strings: { total: 42, sample: [] },
	trailing: null
};

const status = (s: Structure, id: string) => tools(s).find((t) => t.id === id)?.status;

describe('tools', () => {
	it('reports every built tool as clear on a clean file', () => {
		expect(tools(clean).some((t) => t.status === 'hit')).toBe(false);
	});

	it('marks the flag scan as a hit when a credible candidate exists', () => {
		const s = {
			...clean,
			flags: [{ offset: 40, text: 'flag{abc}', region: 'inside tEXt', credible: true }]
		};
		expect(status(s, 'flags')).toBe('hit');
	});

	it('stays clear when the only candidate came out of a compressed stream', () => {
		const s = {
			...clean,
			flags: [{ offset: 40, text: 'BM{GEBF}', region: 'inside IDAT', credible: false }]
		};
		expect(status(s, 'flags')).toBe('clear');
	});

	it('reports the sweep as pending when pixels could not be decoded', () => {
		expect(status(clean, 'lsb')).toBe('pending');
	});

	it('reports the sweep as clear when it ran and found nothing', () => {
		const sweep = { pixels: 100, combinations: 30, candidates: [] };
		expect(tools(clean, sweep).find((t) => t.id === 'lsb')?.status).toBe('clear');
	});

	it('reports the sweep as a hit when a combination carried data', () => {
		const sweep = {
			pixels: 100,
			combinations: 30,
			candidates: [
				{
					channels: 'rgb',
					bit: 0,
					msbFirst: true,
					reason: 'text at offset 0',
					preview: 'flag{hello}',
					bytesRead: 4096,
					flags: ['flag{hello}']
				}
			]
		};
		expect(tools(clean, sweep).find((t) => t.id === 'lsb')?.status).toBe('hit');
	});

	it('marks post-IEND data as a hit', () => {
		expect(status({ ...clean, trailing: { offset: 957, length: 8 } }, 'trailing')).toBe('hit');
	});

	it('marks a CRC mismatch as a hit', () => {
		const s = { ...clean, chunks: [chunk('IHDR', 8, 13, false)] };
		expect(status(s, 'crc')).toBe('hit');
	});

	it('blocks pixel decode when the header cannot be read', () => {
		const s: Structure = { ...clean, header: { error: 'bit depth 16 unsupported' } };
		expect(status(s, 'pixels')).toBe('pending');
	});

	it('no longer lists the LSB sweep as unbuilt', () => {
		expect(PLANNED.some((t) => t.id === 'lsb')).toBe(false);
	});

	it('never claims a planned tool has run', () => {
		expect(PLANNED.every((t) => t.status === 'pending')).toBe(true);
		expect(PLANNED.every((t) => t.value === '')).toBe(true);
	});

	it('keeps built and planned ids disjoint', () => {
		const builtIds = new Set(tools(clean).map((t) => t.id));
		expect(PLANNED.some((t) => builtIds.has(t.id))).toBe(false);
	});
});
