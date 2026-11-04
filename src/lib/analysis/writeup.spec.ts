import { describe, expect, it } from 'vitest';
import type { AnalysisResponse } from '$lib/worker/protocol';
import { writeupMarkdown } from './writeup';

type Analysis = Extract<AnalysisResponse, { status: 'ok' }>;

const analysis = (extra: Partial<Analysis>): Analysis =>
	({
		id: 1,
		status: 'ok',
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
		expect(markdown).toContain('Deleted row: flag{deleted}');
		expect(markdown).toContain('DNS questions: example.test');
		expect(markdown).toContain('a to b carries a PNG image');
	});

	it('leaves out sections for formats the file is not', () => {
		const markdown = writeupMarkdown(analysis({}), [], []);

		for (const heading of ['## PDF', '## Binary', '## Registry hive', '## SQLite', '## Network']) {
			expect(markdown).not.toContain(heading);
		}
	});
});
