import { describe, expect, it } from 'vitest';
import { flagsOf, PLANNED, tools } from './tools';
import type { Chunk, Structure, Survey } from '$lib/worker/protocol';

const chunk = (kind: string, offset: number, length = 0, crcOk = true): Chunk => ({
	kind,
	offset,
	length,
	dataOffset: offset + 8,
	crcOk,
	ancillary: kind[0] === kind[0].toLowerCase()
});

const survey: Survey = {
	size: 1024,
	format: 'PNG image',
	flags: [],
	magic: [{ offset: 0, label: 'PNG image', embedded: false }],
	strings: { total: 42, sample: [] },
	entropy: { window: 256, values: [7.9, 7.8, 7.95] }
};

const structure: Structure = {
	signature: true,
	size: 1024,
	header: { width: 64, height: 64, bitDepth: 8, colorType: 6, interlace: 0 },
	chunks: [chunk('IHDR', 8, 13), chunk('IDAT', 33, 900), chunk('IEND', 945)],
	text: [],
	flags: [],
	strings: { total: 42, sample: [] },
	trailing: null
};

const status = (id: string, s = survey, st: Structure | null = structure) =>
	tools(s, st).find((t) => t.id === id)?.status;

const tool = (id: string, s = survey, st: Structure | null = structure) =>
	tools(s, st).find((t) => t.id === id);

describe('tools', () => {
	it('reports every tool as clear on a clean PNG', () => {
		expect(tools(survey, structure).some((t) => t.status === 'hit')).toBe(false);
	});

	it('marks the flag scan as a hit when a credible candidate exists', () => {
		const s: Structure = {
			...structure,
			flags: [{ offset: 40, text: 'flag{abc}', region: 'inside tEXt', credible: true }]
		};
		expect(status('flags', survey, s)).toBe('hit');
	});

	it('stays clear when the only candidate came out of a compressed stream', () => {
		const s: Structure = {
			...structure,
			flags: [{ offset: 40, text: 'BM{GEBF}', region: 'inside IDAT', credible: false }]
		};
		expect(status('flags', survey, s)).toBe('clear');
	});

	it('flags an embedded file signature past offset zero', () => {
		const s: Survey = {
			...survey,
			magic: [
				{ offset: 0, label: 'PNG image', embedded: false },
				{ offset: 9000, label: 'ZIP archive', embedded: true }
			]
		};
		expect(status('magic', s)).toBe('hit');
		expect(tool('magic', s)?.value).toBe('1 found');
	});

	it('does not treat the file’s own header as an embedded file', () => {
		expect(status('magic')).toBe('clear');
	});

	it('reports the peak entropy it measured', () => {
		expect(tool('entropy')?.value).toBe('peak 7.95 of 8');
	});
});

describe('format scope', () => {
	it('runs the byte-level tools with no PNG structure', () => {
		const byteLevel = tools(survey, null).filter((t) => t.scope === 'bytes');
		expect(byteLevel.length).toBeGreaterThan(0);
		expect(byteLevel.every((t) => t.status !== 'pending')).toBe(true);
	});

	it('stands the PNG tools down rather than hiding them', () => {
		const pngLevel = tools(survey, null).filter((t) => t.scope === 'png');
		expect(pngLevel.length).toBeGreaterThan(0);
		expect(pngLevel.every((t) => t.status === 'pending')).toBe(true);
		expect(pngLevel.every((t) => t.value === 'PNG only, for now')).toBe(true);
	});

	it('keeps strings and flags available on a file it cannot walk', () => {
		expect(status('strings', survey, null)).toBe('ready');
		expect(status('flags', survey, null)).toBe('clear');
		expect(status('entropy', survey, null)).toBe('ready');
	});

	it('prefers the PNG chunk verdict over entropy when both exist', () => {
		const s: Survey = {
			...survey,
			flags: [{ offset: 40, text: 'x{yz}', region: 'readable region', credible: true }]
		};
		const st: Structure = {
			...structure,
			flags: [{ offset: 40, text: 'x{yz}', region: 'inside IDAT', credible: false }]
		};
		expect(flagsOf(s, st)[0].credible).toBe(false);
		expect(flagsOf(s, null)[0].credible).toBe(true);
	});
});

describe('planned tools', () => {
	it('no longer lists anything that has shipped', () => {
		for (const id of ['lsb', 'planes', 'chi', 'rs', 'entropy', 'magic']) {
			expect(PLANNED.some((t) => t.id === id)).toBe(false);
		}
	});

	it('never claims a planned tool has run', () => {
		expect(PLANNED.every((t) => t.status === 'pending')).toBe(true);
		expect(PLANNED.every((t) => t.value === '')).toBe(true);
	});

	it('keeps built and planned ids disjoint', () => {
		const builtIds = new Set(tools(survey, structure).map((t) => t.id));
		expect(PLANNED.some((t) => builtIds.has(t.id))).toBe(false);
	});
});
