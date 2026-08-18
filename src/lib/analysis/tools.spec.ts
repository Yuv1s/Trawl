import { describe, expect, it } from 'vitest';
import { flagsOf, PLANNED, tools } from './tools';
import type { Chunk, Structure, Survey, WavStructure } from '$lib/worker/protocol';

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
	magic: [{ offset: 0, label: 'PNG image', length: 1024, bounded: true, embedded: false }],
	exif: null,
	jpegSegments: [],
	jpegComments: [],
	jpegTrailing: null,
	strings: { total: 42, wide: 0, sample: [] },
	entropy: { window: 256, values: [7.9, 7.8, 7.95] }
};

const structure: Structure = {
	signature: true,
	size: 1024,
	header: { width: 64, height: 64, bitDepth: 8, colorType: 6, interlace: 0 },
	chunks: [chunk('IHDR', 8, 13), chunk('IDAT', 33, 900), chunk('IEND', 945)],
	text: [],
	flags: [],
	trailing: null
};

const status = (id: string, s = survey, st: Structure | null = structure) =>
	tools({ survey: s, structure: st }).find((t) => t.id === id)?.status;

const tool = (id: string, s = survey, st: Structure | null = structure) =>
	tools({ survey: s, structure: st }).find((t) => t.id === id);

describe('tools', () => {
	it('reports every tool as clear on a clean PNG', () => {
		expect(tools({ survey, structure }).some((t) => t.status === 'hit')).toBe(false);
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
				{ offset: 0, label: 'PNG image', length: 1024, bounded: true, embedded: false },
				{ offset: 9000, label: 'ZIP archive', length: 512, bounded: true, embedded: true }
			]
		};
		expect(status('magic', s)).toBe('hit');
		expect(tool('magic', s)?.value).toBe('1 to extract');
	});

	it('does not treat the file own signature as an embedded file', () => {
		expect(status('magic')).toBe('clear');
	});

	it('reports the peak entropy it measured', () => {
		expect(tool('entropy')?.value).toBe('peak 7.95 of 8');
	});
});

describe('metadata', () => {
	const withExif = (exif: Survey['exif']): Survey => ({ ...survey, exif });

	it('reports no metadata block as clear', () => {
		expect(status('exif')).toBe('clear');
		expect(tool('exif')?.value).toBe('none');
	});

	it('flags a field a person typed into', () => {
		const s = withExif([
			{ ifd: 'IFD0', tag: 0x010e, name: 'ImageDescription', value: 'flag{x}', textual: true }
		]);
		expect(status('exif', s)).toBe('hit');
		expect(tool('exif', s)?.value).toBe('1 written field');
	});

	it('does not flag fields a camera fills in by itself', () => {
		const s = withExif([
			{ ifd: 'IFD0', tag: 0x0110, name: 'Model', value: 'EOS 5D', textual: true },
			{ ifd: 'IFD0', tag: 0x0112, name: 'Orientation', value: '6', textual: false }
		]);
		expect(status('exif', s)).toBe('ready');
		expect(tool('exif', s)?.value).toBe('2 fields');
	});

	it('ignores an empty description rather than calling it a find', () => {
		const s = withExif([
			{ ifd: 'IFD0', tag: 0x010e, name: 'ImageDescription', value: '   ', textual: true }
		]);
		expect(status('exif', s)).toBe('ready');
	});
});

describe('jpeg segments', () => {
	it('says so plainly when the file is not a JPEG', () => {
		expect(status('jpeg')).toBe('clear');
		expect(tool('jpeg')?.value).toBe('not a JPEG');
	});

	it('flags a comment segment', () => {
		const s: Survey = {
			...survey,
			jpegSegments: [{ name: 'SOI', marker: 0xd8, offset: 0, length: 0 }],
			jpegComments: [{ offset: 20, text: 'flag{comment}' }]
		};
		expect(status('jpeg', s)).toBe('hit');
		expect(tool('jpeg', s)?.value).toBe('1 comment');
	});

	it('flags bytes past the end-of-image marker', () => {
		const s: Survey = {
			...survey,
			jpegSegments: [{ name: 'EOI', marker: 0xd9, offset: 40, length: 0 }],
			jpegTrailing: { offset: 42, length: 2048 }
		};
		expect(status('jpeg', s)).toBe('hit');
		expect(tool('jpeg', s)?.value).toBe('2,048 bytes past EOI');
	});
});

describe('format scope', () => {
	it('runs the byte-level tools with no PNG structure', () => {
		const byteLevel = tools({ survey }).filter((t) => t.scope === 'bytes');
		expect(byteLevel.length).toBeGreaterThan(0);
		expect(byteLevel.every((t) => t.status !== 'pending')).toBe(true);
	});

	it('stands the PNG tools down rather than hiding them', () => {
		const pngLevel = tools({ survey }).filter((t) => t.scope === 'png');
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

describe('audio', () => {
	const wav: WavStructure = {
		encoding: '16-bit PCM',
		channels: 2,
		sampleRate: 44100,
		bitsPerSample: 16,
		frames: 44100,
		seconds: 1,
		dataOffset: 44,
		dataLength: 176400,
		chunks: [
			{ id: 'fmt ', offset: 12, length: 16, complete: true },
			{ id: 'data', offset: 36, length: 176400, complete: true }
		],
		text: [],
		trailing: null
	};

	const audio = (found: Partial<Parameters<typeof tools>[0]>, id: string) =>
		tools({ survey, structure: null, wav, ...found }).find((t) => t.id === id);

	it('stands the audio tools down on a file with no samples', () => {
		const level = tools({ survey, structure }).filter((t) => t.scope === 'audio');
		expect(level.length).toBeGreaterThan(0);
		expect(level.every((t) => t.status === 'pending')).toBe(true);
		expect(level.every((t) => t.value === 'not an audio file')).toBe(true);
	});

	it('marks the sweep as a hit when a combination carried data', () => {
		const sweep = {
			samples: 88200,
			combinations: 18,
			candidates: [
				{
					channels: 'right',
					channelIndex: 1,
					bit: 0,
					msbFirst: true,
					reason: 'text at offset 0, 12 characters',
					preview: 'flag{sounds}',
					readable: 12,
					bytesRead: 4096,
					flags: ['flag{sounds}']
				}
			]
		};
		expect(audio({ audio: sweep }, 'audio-lsb')?.status).toBe('hit');
		expect(audio({ audio: sweep }, 'audio-lsb')?.value).toBe('1 of 18 combinations');
	});

	it('says how much it swept when nothing came back', () => {
		const sweep = { samples: 88200, combinations: 18, candidates: [] };
		expect(audio({ audio: sweep }, 'audio-lsb')?.status).toBe('clear');
		expect(audio({ audio: sweep }, 'audio-lsb')?.value).toBe('18 swept, none carried data');
	});

	it('flags text in a chunk a player would skip', () => {
		const withText = { ...wav, text: [{ chunk: 'LIST', offset: 40, text: 'flag{riff}' }] };
		const tool = tools({ survey, wav: withText }).find((t) => t.id === 'riff');
		expect(tool?.status).toBe('hit');
		expect(tool?.value).toBe('1 text string');
	});

	it('flags bytes past the length the header declares', () => {
		const appended = { ...wav, trailing: { offset: 176444, length: 27 } };
		const tool = tools({ survey, wav: appended }).find((t) => t.id === 'riff');
		expect(tool?.status).toBe('hit');
		expect(tool?.value).toBe('27 bytes past the end');
	});

	it('reports a plain sound file as ready rather than as a find', () => {
		expect(audio({}, 'riff')?.status).toBe('ready');
		expect(audio({}, 'riff')?.value).toBe('2 chunks');
	});

	it('stands the spectrogram down for a clip too short to draw', () => {
		expect(audio({}, 'spectrogram')?.status).toBe('pending');
		expect(audio({}, 'spectrogram')?.value).toBe('the clip is too short to draw');
	});

	it('reports the range it drew', () => {
		const spectrogram = {
			width: 600,
			height: 512,
			window: 1024,
			hop: 256,
			maxFrequency: 22050,
			seconds: 3.5,
			pixels: new Uint8Array()
		};
		expect(audio({ spectrogram }, 'spectrogram')?.value).toBe('3.5s up to 22.1 kHz');
	});

	it('does not claim a finding on a WAV it could not walk', () => {
		const broken = { error: 'no fmt chunk, so the samples cannot be read', chunks: [] };
		const level = tools({ survey, wav: broken }).filter((t) => t.scope === 'audio');
		expect(level.every((t) => t.status === 'pending')).toBe(true);
	});
});

describe('planned tools', () => {
	it('no longer lists anything that has shipped', () => {
		const shipped = ['lsb', 'planes', 'chi', 'rs', 'entropy', 'magic', 'exif', 'jpeg'];
		for (const id of [...shipped, 'spectrogram', 'audio-lsb', 'riff']) {
			expect(PLANNED.some((t) => t.id === id)).toBe(false);
		}
	});

	it('never claims a planned tool has run', () => {
		expect(PLANNED.every((t) => t.status === 'pending')).toBe(true);
		expect(PLANNED.every((t) => t.value === '')).toBe(true);
	});

	it('keeps built and planned ids disjoint', () => {
		const builtIds = new Set(tools({ survey, structure }).map((t) => t.id));
		expect(PLANNED.some((t) => builtIds.has(t.id))).toBe(false);
	});
});
