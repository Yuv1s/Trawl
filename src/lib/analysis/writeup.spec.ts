import { describe, expect, it } from 'vitest';
import type { AnalysisResponse } from '$lib/worker/protocol';
import { writeupMarkdown } from './writeup';

type Analysis = Extract<AnalysisResponse, { status: 'ok' }>;

const analysis = (extra: Partial<Analysis>): Analysis =>
	({
		id: 1,
		status: 'ok',
		crashed: [],
		name: 'sample.bin',
		size: 10,
		survey: { format: null, magic: [], exif: null, jpegTrailing: null },
		structure: null,
		...extra
	}) as unknown as Analysis;

describe('the writeup', () => {
	it('reports what the structure tools found, not only the flags', () => {
		const markdown = writeupMarkdown(
			analysis({
				pdf: {
					version: '1.7',
					objects: [{ number: 4, generation: 0, orphaned: true }],
					revisions: 2,
					trailing: 0,
					encrypted: false,
					embeddedFiles: []
				} as unknown as Analysis['pdf'],
				binary: {
					format: 'ELF',
					machine: 'x86-64',
					kind: 'executable',
					nx: 'off',
					pie: 'no',
					relro: 'none',
					canary: false,
					needed: ['libc.so.6']
				} as unknown as Analysis['binary'],
				hive: {
					kind: 'SYSTEM',
					devices: [
						{
							vendor: 'Kingston',
							product: 'DataTraveler',
							serial: 'ABC123',
							lastWritten: '2024-01-02',
							source: 'USBSTOR'
						}
					]
				} as unknown as Analysis['hive'],
				sqlite: {
					tables: [
						{
							name: 'members',
							rowCount: 1,
							deleted: [[{ kind: 'text', text: 'flag{deleted}' }]]
						}
					]
				} as unknown as Analysis['sqlite'],
				pcap: {
					format: 'pcap',
					packetCount: 4,
					protocols: [{ name: 'TCP', packets: 4, bytes: 100 }],
					dns: [{ name: 'example.test', type: 'A' }],
					streams: [{ src: 'a', dst: 'b', embeddedFile: 'PNG image', flags: [] }]
				} as unknown as Analysis['pcap']
			}),
			[],
			[]
		);

		expect(markdown).toContain('Object 4 0 is not in the cross-reference table');
		expect(markdown).toContain('NX: off, PIE: no, RELRO: none, Stack canary: none found');
		expect(markdown).toContain('Kingston DataTraveler, serial ABC123');
		expect(markdown).toContain('Deleted row: `flag{deleted}`');
		expect(markdown).toContain('DNS questions: `example.test`');
		expect(markdown).toContain('`a` to `b` carries a PNG image');
	});

	it('keeps anything a file controls inert', () => {
		const image = '![](https://attacker.invalid/flag.png)';
		const html = '<img src="https://attacker.invalid/x.png">';
		const hostile = `text${image}${html}\n\n# injected heading\n\`\`\`\n[click](https://attacker.invalid)`;

		const markdown = writeupMarkdown(
			analysis({
				name: hostile,
				crashed: [hostile],
				notes: [hostile],
				survey: {
					format: null,
					magic: [],
					exif: [{ name: hostile, value: hostile }],
					jpegTrailing: null
				},
				zip: {
					entries: [{ name: hostile, uncompressed: 1, method: 'stored', disagreement: hostile }]
				},
				nested: {
					roots: [{ name: hostile, status: 'error', reason: hostile, findings: [], children: [] }]
				}
			} as unknown as Partial<Analysis>),
			[{ text: hostile, region: hostile, offset: 0, credible: true }],
			[{ text: hostile, origin: hostile }]
		);

		expect(markdown).not.toMatch(/^#+ injected/m);
		expect(markdown).not.toContain('```');

		const outsideCode = markdown.replace(/`[^`\n]*`/g, '');
		for (const live of ['![', '<img', '](http', 'attacker.invalid']) {
			expect(outsideCode).not.toContain(live);
		}
	});

	it('carries the warnings a stream left behind', () => {
		const markdown = writeupMarkdown(
			analysis({
				structure: {
					header: { error: 'none' },
					chunks: [],
					text: [{ kind: 'zTXt', error: 'the text was cut short' }]
				},
				pdf: {
					version: '1.7',
					objects: [{ number: 7, generation: 0, stream: { error: 'the stream has 9 filters' } }],
					revisions: 1,
					trailing: 0,
					encrypted: false,
					embeddedFiles: []
				},
				zip: {
					entries: [
						{ name: 'a', uncompressed: 1, method: 'deflate', readError: 'the stream is damaged' },
						{ name: 'b', uncompressed: 1, method: 'deflate', notOpened: 'encrypted' }
					]
				},
				nested: {
					roots: [
						{
							name: 'inner.pdf',
							status: 'analysed',
							findings: [],
							children: [],
							damage: 'the inner stream was capped'
						}
					]
				}
			} as unknown as Partial<Analysis>),
			[],
			[]
		);

		for (const warning of [
			'the text was cut short',
			'Object 7 0 stream: `the stream has 9 filters`',
			'the stream is damaged',
			'not opened: `encrypted`',
			'the inner stream was capped'
		]) {
			expect(markdown).toContain(warning);
		}
	});

	it('says what the analysis did not cover', () => {
		const markdown = writeupMarkdown(
			analysis({ crashed: ['SQLite'], notes: ['3 compressed streams were not opened.'] }),
			[],
			[]
		);

		expect(markdown).toContain('## What this does not cover');
		expect(markdown).toContain('SQLite reader crashed');
		expect(markdown).toContain('3 compressed streams were not opened.');
		expect(writeupMarkdown(analysis({}), [], [])).not.toContain('What this does not cover');
	});

	it('leaves out sections for formats the file is not', () => {
		const markdown = writeupMarkdown(analysis({}), [], []);

		for (const heading of ['## PDF', '## Binary', '## Registry hive', '## SQLite', '## Network']) {
			expect(markdown).not.toContain(heading);
		}
	});
});
