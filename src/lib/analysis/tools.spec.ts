import { describe, expect, it } from 'vitest';
import { flagsOf, PLANNED, tools } from './tools';
import type {
	Chunk,
	ElfStructure,
	GifAnalysis,
	NestedAnalysis,
	Structure,
	Survey,
	Sweep,
	SweepCandidate,
	WavStructure,
	ZipArchive,
	ZipEntry
} from '$lib/worker/protocol';

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

describe('gif frames', () => {
	const gif = (over: Partial<GifAnalysis> = {}): GifAnalysis =>
		({
			width: 16,
			height: 16,
			declaredFrames: 1,
			analysedFrames: 1,
			capped: false,
			error: null,
			sources: [],
			...over
		}) as GifAnalysis;

	const lsb = (preview: string, flags: string[]): SweepCandidate => ({
		channels: 'rgb',
		bit: 0,
		msbFirst: false,
		reason: 'text at offset 0',
		preview,
		readable: preview.length,
		bytesRead: 4096,
		flags
	});

	const emptySweep = (): Sweep => ({ pixels: 4096, combinations: 0, candidates: [] });

	const withGif = (g: GifAnalysis | null, nested: NestedAnalysis | null = null) =>
		tools({ survey, gif: g, nested }).find((t) => t.id === 'gif');

	it('stands the GIF tool down on a file with no frame analysis', () => {
		expect(withGif(null)?.status).toBe('pending');
		expect(withGif(null)?.value).toBe('pixels unavailable');
	});

	it('reports an error instead of claiming a finding', () => {
		const broken = gif({ error: 'no image data', sources: [] });
		const g = withGif(broken)!;
		expect(g.status).toBe('clear');
		expect(g.value).toBe('error: no image data');
	});

	it('reports analysed frames and differences but no find on a clean animation', () => {
		const clean = gif({
			declaredFrames: 3,
			analysedFrames: 3,
			sources: [
				{
					kind: 'frame',
					from: 1,
					to: null,
					delay: 5,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				},
				{
					kind: 'frame',
					from: 2,
					to: null,
					delay: 5,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				},
				{
					kind: 'frame',
					from: 3,
					to: null,
					delay: 5,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				},
				{
					kind: 'difference',
					from: 1,
					to: 2,
					delay: null,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				},
				{
					kind: 'difference',
					from: 2,
					to: 3,
					delay: null,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				}
			]
		});
		expect(withGif(clean)?.status).toBe('clear');
		expect(withGif(clean)?.value).toBe('3 frames analysed, 2 differences checked');
	});

	it('calls out the hidden bits as a hit with origin context', () => {
		const stealthy = gif({
			declaredFrames: 2,
			analysedFrames: 2,
			sources: [
				{
					kind: 'difference',
					from: 1,
					to: 2,
					delay: null,
					disposal: null,
					lsb: { pixels: 4096, combinations: 0, candidates: [lsb('flag{blink}', ['flag{blink}'])] },
					chi: null,
					rs: null
				}
			]
		});
		expect(withGif(stealthy)?.status).toBe('hit');
	});

	it('signals a frame budget that stopped the walk', () => {
		const cappedFlow = gif({
			declaredFrames: 200,
			analysedFrames: 128,
			capped: true,
			sources: [
				{
					kind: 'frame',
					from: 1,
					to: null,
					delay: 5,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				}
			]
		});
		expect(withGif(cappedFlow)?.value).toContain('capped');
	});

	it('notes when the nested walk capped alongside the frame analysis', () => {
		const nested = { capped: true } as NestedAnalysis;
		const cappedFlow = gif({
			declaredFrames: 200,
			analysedFrames: 128,
			capped: true,
			sources: [
				{
					kind: 'frame',
					from: 1,
					to: null,
					delay: 5,
					disposal: null,
					lsb: emptySweep(),
					chi: null,
					rs: null
				}
			]
		});
		expect(withGif(cappedFlow, nested)?.value).toContain('walk capped');
	});
});

describe('nested analysis', () => {
	const root = (over: Partial<NestedAnalysis> = {}): NestedAnalysis => ({
		analysed: 0,
		skipped: 0,
		expandedBytes: 0,
		capped: false,
		roots: [],
		...over
	});

	it('reports a hit on the archive tool when a nested child carried a flag', () => {
		// The root survey announces a ZIP; the nested walk found a flag inside an entry.
		const s: Survey = {
			...survey,
			magic: [{ offset: 0, label: 'ZIP archive', length: 1024, bounded: true, embedded: false }]
		};
		const entry: ZipEntry = {
			name: 'readme.txt',
			method: 'stored',
			compressed: 10,
			uncompressed: 40,
			offset: 4,
			dataOffset: 8,
			crc: '00000000',
			encrypted: false,
			undeclared: false,
			comment: '',
			disagreement: null,
			flags: ['flag{inner}']
		};
		const zip: ZipArchive = {
			prefix: 0,
			trailing: 0,
			declared: 1,
			comment: '',
			entries: [entry]
		};
		const nested = root({
			analysed: 1,
			roots: [
				{
					id: 'zip-0',
					name: 'readme.txt',
					source: 'zip',
					offset: 4,
					format: 'text',
					size: 40,
					depth: 1,
					status: 'analysed',
					findings: [
						{ text: 'flag{inner}', detector: 'flag scan', origin: 'archive.zip', reason: '' }
					],
					children: []
				}
			]
		});
		const g = tools({ survey: s, zip, nested }).find((t) => t.id === 'archive')!;
		expect(g.status).toBe('hit');
		expect(g.value).toBe('flag in an entry');
	});

	it('backs the embedded-file tool, staying clear when carved children find nothing', () => {
		// Skipped and empty children surface as an analysed count but carry no finding.
		const nested = root({
			analysed: 2,
			skipped: 1,
			roots: [
				{
					id: 'carved-0',
					name: 'stray.bmp',
					source: 'carved',
					offset: 9000,
					format: 'BMP image',
					size: 512,
					depth: 1,
					status: 'analysed',
					findings: [],
					children: []
				}
			]
		});
		expect(tools({ survey, nested }).some((t) => t.status === 'hit')).toBe(false);
	});

	it('reports a walk that was capped for budget', () => {
		const nested = root({ analysed: 30, skipped: 2, expandedBytes: 8388608, capped: true });
		// A capped walk is still honest clear when it found nothing.
		const tool = tools({ survey, nested }).find((t) => t.id === 'magic')!;
		expect(tool.status).toBe('clear');
	});
});

describe('binary structure', () => {
	const elf = (over: Partial<ElfStructure> = {}): ElfStructure => ({
		class: '64-bit',
		endianness: 'little',
		machine: 'x86-64',
		kind: 'executable',
		entry: '0x401060',
		interpreter: '/lib64/ld-linux-x86-64.so.2',
		runpath: null,
		stripped: false,
		nx: 'on',
		pie: 'yes',
		relro: 'full',
		canary: true,
		fortify: true,
		importCount: 0,
		exportCount: 0,
		needed: [],
		sections: [],
		segments: [],
		imports: [],
		exports: [],
		...over
	});

	it('stands down on a file that is not an ELF', () => {
		const tool = tools({ survey, structure }).find((t) => t.id === 'binary')!;
		expect(tool.status).toBe('pending');
		expect(tool.value).toBe('not an ELF binary');
	});

	it('stays clear on a binary built with every protection on', () => {
		const tool = tools({ survey, elf: elf() }).find((t) => t.id === 'binary')!;
		expect(tool.status).toBe('clear');
		expect(tool.value).toContain('hardened');
	});

	it('reports each protection the file leaves open', () => {
		const tool = tools({
			survey,
			elf: elf({ nx: 'off', pie: 'no', relro: 'none', canary: false })
		}).find((t) => t.id === 'binary')!;

		expect(tool.status).toBe('hit');
		expect(tool.value).toBe('executable stack, no PIE, no RELRO, no canary');
	});

	it('treats a stack header that is missing as unresolved rather than off', () => {
		// The file makes no claim, so the note says so instead of reporting a
		// protection as disabled that the binary never mentions.
		const tool = tools({ survey, elf: elf({ nx: 'not declared' }) }).find(
			(t) => t.id === 'binary'
		)!;
		expect(tool.status).toBe('hit');
		expect(tool.value).toBe('no stack header');
	});

	it('does not hold a shared library to PIE, which does not apply to it', () => {
		const library = elf({ kind: 'shared object', pie: 'shared object', interpreter: null });
		const tool = tools({ survey, elf: library }).find((t) => t.id === 'binary')!;
		expect(tool.status).toBe('clear');
	});

	it('says a hardened binary was stripped when it was', () => {
		const tool = tools({ survey, elf: elf({ stripped: true }) }).find((t) => t.id === 'binary')!;
		expect(tool.value).toContain('stripped');
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
