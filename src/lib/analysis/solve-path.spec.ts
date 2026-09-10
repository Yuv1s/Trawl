import { describe, expect, it } from 'vitest';
import { buildSolvePaths, type SolveInput } from './solve-path';
import type { NestedArtifact, PcapCapture, Sweep, ZipArchive } from '$lib/worker/protocol';

const base: SolveInput = { fileName: 'evidence.png' };

describe('buildSolvePaths', () => {
	it('returns nothing when no flag was recovered', () => {
		expect(buildSolvePaths(base)).toEqual([]);
	});

	it('traces a flag through the nested recursion chain', () => {
		const artifact: NestedArtifact = {
			id: 'zip-0-1',
			name: 'inner.zip',
			source: 'zip',
			offset: 0,
			format: 'ZIP',
			size: 100,
			depth: 1,
			status: 'analysed',
			findings: [
				{
					text: 'flag{deep}',
					detector: 'pixel LSB',
					origin: 'evidence.png / inner.zip / clue.png',
					reason: 'red bit 0'
				}
			],
			children: []
		};
		const [path] = buildSolvePaths({ ...base, nested: { roots: [artifact] } });
		expect(path.text).toBe('flag{deep}');
		expect(path.steps).toEqual(['evidence.png', 'inner.zip', 'clue.png', 'pixel LSB']);
	});

	it('traces a flag reassembled from a TCP stream', () => {
		const pcap = {
			streams: [{ src: '10.0.0.1:80', dst: '10.0.0.9:5000', flags: ['flag{split}'] }]
		} as unknown as PcapCapture;
		const [path] = buildSolvePaths({ ...base, fileName: 'capture.pcap', pcap });
		expect(path.steps).toEqual([
			'capture.pcap',
			'TCP 10.0.0.1:80 → 10.0.0.9:5000',
			'reassembled stream'
		]);
	});

	it('traces a flag through an archive entry', () => {
		const zip = {
			entries: [{ name: 'notes.txt', flags: ['flag{in_zip}'] }]
		} as unknown as ZipArchive;
		const [path] = buildSolvePaths({ ...base, zip });
		expect(path.steps).toEqual(['evidence.png', 'notes.txt', 'byte scan']);
	});

	it('traces a pixel sweep find down to the combination', () => {
		const sweep = {
			candidates: [{ channels: 'R', bit: 0, msbFirst: true, flags: ['flag{pixels}'] }]
		} as unknown as Sweep;
		const [path] = buildSolvePaths({ ...base, sweep });
		expect(path.steps).toEqual(['evidence.png', 'pixels', 'LSB R bit 0 msb first']);
	});

	it('keeps the first route when a flag is reachable more than one way', () => {
		const zip = { entries: [{ name: 'a.txt', flags: ['flag{dupe}'] }] } as unknown as ZipArchive;
		const sweep = {
			candidates: [{ channels: 'R', bit: 0, msbFirst: true, flags: ['flag{dupe}'] }]
		} as unknown as Sweep;
		const paths = buildSolvePaths({ ...base, zip, sweep });
		expect(paths).toHaveLength(1);
		expect(paths[0].steps).toContain('a.txt');
	});
});
