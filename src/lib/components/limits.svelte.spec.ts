import { page } from 'vitest/browser';
import { afterEach, describe, expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import type {
	AnalysisResponse,
	BinaryStructure,
	Chunk,
	Found,
	GifAnalysis,
	JpegSegment,
	MagicHit,
	NestedAnalysis,
	NestedArtifact,
	PcapCapture,
	PcapStream,
	PdfObject,
	PdfStructure,
	RegistryDevice,
	RegistryHive,
	RiffChunk,
	SqliteDatabase,
	SqliteTable,
	WavStructure,
	ZipArchive,
	ZipEntry
} from '$lib/worker/protocol';
import { encodePng } from '$lib/pixels/png-encode';
import AnalysisWorker from '$lib/worker/analysis.worker?worker';
import Page from '../../routes/+page.svelte';
import BinaryView from './BinaryView.svelte';
import ChunkList from './ChunkList.svelte';
import GifFramesView from './GifFramesView.svelte';
import HiveView from './HiveView.svelte';
import JpegView from './JpegView.svelte';
import MagicList from './MagicList.svelte';
import PcapView from './PcapView.svelte';
import PdfView from './PdfView.svelte';
import PeelPanel from './PeelPanel.svelte';
import RiffView from './RiffView.svelte';
import SqliteView from './SqliteView.svelte';
import StringsView from './StringsView.svelte';
import ZipView from './ZipView.svelte';

const rowsDrawn = () => document.querySelectorAll('tbody tr').length;
const listOf = <T>(length: number, item: (i: number) => T) =>
	Array.from({ length }, (_, i) => item(i));

const zipEntry = (i: number): ZipEntry => ({
	name: `n${i}`,
	method: 'stored',
	compressed: 2,
	uncompressed: 2,
	offset: i * 37,
	dataOffset: i * 37 + 35,
	readLength: 2,
	crc: '00000000',
	encrypted: false,
	undeclared: false,
	comment: '',
	disagreement: null
});

const archive = (entries: ZipEntry[]): ZipArchive => ({
	entries,
	comment: '',
	prefix: 0,
	trailing: 0,
	declared: entries.length
});

const nestedChild = (offset: number, findings: number): NestedArtifact => ({
	id: `zip-${offset}-1`,
	name: `n${offset}`,
	source: 'zip',
	offset,
	format: 'unidentified',
	size: 2,
	depth: 1,
	status: 'analysed',
	findings: listOf(findings, (i) => ({
		text: `flag{${i}}`,
		detector: 'byte scan',
		origin: 'here',
		reason: 'there'
	})),
	children: []
});

const pdfObject = (i: number): PdfObject => ({
	number: i,
	generation: 0,
	offset: i * 8,
	type: null,
	subtype: null,
	orphaned: false,
	stream: null
});

const pdf = (objects: PdfObject[], objectCount: number): PdfStructure => ({
	version: '1.7',
	objectCount,
	trailing: 0,
	encrypted: false,
	usesXrefStream: false,
	revisions: 1,
	info: [],
	embeddedFiles: [],
	objects
});

const binary = (overrides: Partial<BinaryStructure>): BinaryStructure => ({
	format: 'ELF',
	class: '64-bit',
	endianness: 'little',
	machine: 'x86-64',
	kind: 'shared object',
	entry: '0x0',
	interpreter: null,
	runpath: null,
	subsystem: null,
	pdbPath: null,
	stripped: false,
	nx: 'on',
	pie: 'yes',
	relro: 'full',
	canary: true,
	fortify: true,
	cfg: null,
	importCount: 0,
	exportCount: 0,
	needed: [],
	sections: [],
	segments: [],
	imports: [],
	exports: [],
	...overrides
});

const device = (i: number): RegistryDevice => ({
	source: 'USBSTOR',
	vendor: `vendor${i}`,
	product: 'product',
	revision: '1',
	serial: `${i}`,
	friendlyName: '',
	lastWritten: '',
	generatedSerial: false
});

const hive = (devices: RegistryDevice[], keys: number): RegistryHive => ({
	version: '1.5',
	kind: 'SYSTEM',
	fileName: '',
	written: '',
	root: 'ROOT',
	top: listOf(keys, (i) => ({ name: `key${i}`, subkeys: 0, values: 0, written: '' })),
	devices,
	searched: []
});

const sqliteTable = (t: number, columns: number, rows: number): SqliteTable => ({
	name: `t${t}`,
	columns: listOf(columns, (i) => `c${i}`),
	sql: '',
	rows: listOf(rows, () => listOf(columns, () => ({ kind: 'text', text: 'x' }))),
	rowCount: rows,
	deleted: []
});

const stream = (i: number): PcapStream => ({
	src: `10.0.0.1:${i}`,
	dst: '10.0.0.2:80',
	bytes: 8,
	text: 'hello',
	printable: 1,
	embeddedFile: null,
	flags: [`flag{stream_${i}}`]
});

const capture = (streams: PcapStream[], carried: number): PcapCapture => ({
	format: 'pcap',
	linkType: 'Ethernet',
	packetCount: streams.length,
	captureBytes: 0,
	truncated: false,
	duration: '',
	protocols: [],
	conversations: [],
	conversationCount: 0,
	streams,
	streamCount: carried,
	dns: []
});

describe('a view of more than a person reads', () => {
	let unmount: (() => PromiseLike<void>) | undefined;

	afterEach(async () => {
		await unmount?.();
		unmount = undefined;
	});

	it('draws a capped table of a ZIP, with what stands out at the top', async () => {
		const entries = listOf(26_000, zipEntry);
		entries[25_999] = { ...entries[25_999], name: 'last', flags: ['flag{at_the_very_end}'] };
		entries[25_998] = { ...entries[25_998], name: 'argued', disagreement: 'they disagree' };

		const view = await render(ZipView, { archive: archive(entries) });
		unmount = view.unmount;

		await expect.element(page.getByText('flag{at_the_very_end}')).toBeVisible();
		expect(rowsDrawn()).toBe(500);
		await expect.element(page.getByText(/Showing the first 500 of 26,000 entries/)).toBeVisible();

		const names = [...document.querySelectorAll('tbody .name')].map((name) => name.textContent);
		expect(names.slice(0, 2).sort()).toEqual(['argued', 'last']);
	});

	it('matches what the walk found to the right row of a ZIP', async () => {
		const entries = listOf(2000, zipEntry);
		const nested: NestedAnalysis = {
			roots: [nestedChild(entries[3].offset, 1), nestedChild(entries[7].offset, 2)],
			analysed: 2,
			skipped: 0,
			expandedBytes: 4,
			capped: false
		};

		const view = await render(ZipView, { archive: archive(entries), nested });
		unmount = view.unmount;

		const rows = [...document.querySelectorAll('tbody tr')];
		const row = (name: string) =>
			rows.find((tr) => tr.querySelector('.name')?.textContent === name);
		expect(row('n3')?.textContent).toContain('1 finding');
		expect(row('n7')?.textContent).toContain('2 findings');
		expect(row('n5')?.textContent).toContain('not analysed');
	});

	it('says why entries of a ZIP were not opened, once for each reason', async () => {
		const entries = listOf(5, zipEntry);
		entries[1].notOpened = 'the whole-file inflate budget had run out';
		entries[2].notOpened = 'the whole-file inflate budget had run out';
		entries[3].notOpened = 'encrypted';

		const view = await render(ZipView, { archive: archive(entries) });
		unmount = view.unmount;

		await expect
			.element(page.getByText('2 entries not opened: the whole-file inflate budget had run out'))
			.toBeVisible();
		await expect.element(page.getByText('1 entry not opened: encrypted')).toBeVisible();
	});

	it('keeps one kind of signature from burying another', async () => {
		const decoy = (i: number): MagicHit => ({
			offset: i * 6 + 1,
			label: '7-Zip archive',
			length: 6,
			bounded: false,
			embedded: true
		});
		const hits = [
			...listOf(4096, decoy),
			{ offset: 30_000, label: 'PNG image', length: 80, bounded: true, embedded: true }
		];

		const view = await render(MagicList, {
			hits,
			size: 31_000,
			bytes: new Uint8Array(),
			omitted: 12
		});
		unmount = view.unmount;

		expect(document.querySelectorAll('.hits li').length).toBe(51);
		await expect.element(page.getByText('PNG image')).toBeVisible();
		await expect
			.element(page.getByText(/Showing the first 50 of 4,096\s+7-Zip archive signatures/))
			.toBeVisible();
		await expect.element(page.getByText(/Another 12 were left out/)).toBeVisible();
	});

	it('draws a capped table of a PDF, with what stands out at the top', async () => {
		const objects = listOf(4096, pdfObject);
		objects[4095] = { ...objects[4095], number: 9999, flags: ['flag{in_a_stream}'] };

		const view = await render(PdfView, { doc: pdf(objects, 120_000) });
		unmount = view.unmount;

		expect(rowsDrawn()).toBe(500);
		await expect.element(page.getByText('flag{in_a_stream}')).toBeVisible();
		await expect.element(page.getByText(/Showing the first 500 of 120,000 objects/)).toBeVisible();
		expect(document.querySelector('tbody .name')?.textContent).toBe('9999 0 obj');
	});

	it('draws capped tables of a binary and cuts long names', async () => {
		const longName = 'n'.repeat(4096);
		const view = await render(BinaryView, {
			binary: binary({
				sectionCount: 65_535,
				sections: listOf(4096, (i) => ({
					name: `s${i}`,
					kind: 'PROGBITS',
					address: '0x0',
					offset: 0,
					size: 0,
					flags: ''
				})),
				segmentCount: 2000,
				segments: listOf(2000, () => ({
					kind: 'LOAD',
					permissions: 'r--',
					address: '0x0',
					offset: 0,
					fileSize: 0,
					memorySize: 0
				})),
				importCount: 3_570_000,
				symbolsCapped: true,
				imports: listOf(1000, () => ({ name: longName, kind: 'FUNC', address: '0x0', from: null }))
			})
		});
		unmount = view.unmount;

		await expect.element(page.getByText(/Showing the first 500 of 65,535 sections/)).toBeVisible();
		await expect.element(page.getByText(/Showing the first 500 of 2,000 segments/)).toBeVisible();
		await expect.element(page.getByText(/stopped reading the symbol tables/)).toBeVisible();
		const chip = document.querySelector('.chips li');
		expect(chip?.textContent?.trim().length).toBe(200);
		expect(chip?.getAttribute('title')).toBe(longName);
	});

	it('draws capped tables of a hive', async () => {
		const view = await render(HiveView, { hive: hive(listOf(5000, device), 30_000) });
		unmount = view.unmount;

		await expect.element(page.getByText(/Showing the first 500 of 30,000 keys/)).toBeVisible();
		await expect.element(page.getByText(/Showing the first 500 of 5,000 devices/)).toBeVisible();
		expect(rowsDrawn()).toBe(1000);
	});

	it('draws capped tables of a database, in tables, rows and columns', async () => {
		const db: SqliteDatabase = {
			pageSize: 4096,
			pageCount: 10,
			encoding: 'UTF-8',
			freelistPages: 0,
			tables: listOf(40, (t) => sqliteTable(t, t === 0 ? 2000 : 2, t === 0 ? 300 : 1)),
			tableCount: 40
		};

		const view = await render(SqliteView, { db });
		unmount = view.unmount;

		await expect.element(page.getByText(/Showing the first 16 of 40\s+tables/)).toBeVisible();
		await expect.element(page.getByText(/Showing the first 100 of 300 rows/)).toBeVisible();
		await expect.element(page.getByText(/Showing the first 32 of 2,000 columns/)).toBeVisible();
		expect(document.querySelectorAll('table').length).toBe(16);
		expect(document.querySelectorAll('tbody tr:first-child')[0].children.length).toBe(32);
	});

	it('draws a capped list of TCP streams, and says what it left', async () => {
		const streams = listOf(1024, stream);

		const view = await render(PcapView, { cap: capture(streams, 5000) });
		unmount = view.unmount;

		await expect.element(page.getByText('flag{stream_0}', { exact: true })).toBeVisible();
		expect(document.body.textContent).not.toContain('flag{stream_1023}');
		await expect
			.element(page.getByText(/Showing the first 50 of 1,024 streams with a find/))
			.toBeVisible();
	});

	it('tells a person when two copies of a stream disagree', async () => {
		const streams = [{ ...stream(0), conflicting: 2 }];

		const view = await render(PcapView, { cap: capture(streams, 1) });
		unmount = view.unmount;

		await expect.element(page.getByText(/disagree about\s+2 bytes/)).toBeVisible();
	});

	it('draws capped tables of JPEG segments and comments', async () => {
		const segments: JpegSegment[] = listOf(30_000, (i) => ({
			name: 'COM',
			marker: 0xfe,
			offset: i * 4,
			length: 2
		}));
		const comments: Found[] = listOf(1000, (i) => ({ offset: i * 4, text: `comment ${i}` }));

		const view = await render(JpegView, { segments, comments, trailing: null });
		unmount = view.unmount;

		expect(rowsDrawn()).toBe(500);
		await expect.element(page.getByText(/Showing the first 500 of 30,000 segments/)).toBeVisible();
		await expect.element(page.getByText(/Showing the first 50 of 1,000 comments/)).toBeVisible();
	});

	it('draws a capped table of PNG chunks, counted against the whole file', async () => {
		const chunks: Chunk[] = listOf(16_384, (i) => ({
			kind: 'tEXt',
			offset: i * 12,
			length: 0,
			dataOffset: i * 12 + 8,
			crcOk: true,
			ancillary: true
		}));

		const view = await render(ChunkList, {
			chunks,
			total: 100_000,
			selected: -1,
			onselect: () => {}
		});
		unmount = view.unmount;

		expect(rowsDrawn()).toBe(500);
		await expect.element(page.getByText('Showing the first 500 of 100,000 chunks.')).toBeVisible();
	});

	it('draws a capped table of RIFF chunks and strings', async () => {
		const chunk = (i: number): RiffChunk => ({
			id: 'junk',
			offset: i * 8,
			length: 0,
			complete: true
		});
		const wav: WavStructure = {
			encoding: '8-bit PCM',
			channels: 1,
			sampleRate: 8000,
			bitsPerSample: 8,
			frames: 0,
			seconds: 0,
			dataOffset: 0,
			dataLength: 0,
			chunks: listOf(4000, chunk),
			text: listOf(400, (i) => ({ chunk: 'LIST', offset: i, text: `text ${i}` })),
			trailing: null
		};

		const view = await render(RiffView, { wav });
		unmount = view.unmount;

		expect(rowsDrawn()).toBe(500);
		await expect.element(page.getByText(/Showing the first 500 of 4,000 chunks/)).toBeVisible();
		await expect.element(page.getByText(/Showing the first 100 of 400 strings/)).toBeVisible();
	});

	it('says when a paste had more readings than it followed', async () => {
		const worker = new AnalysisWorker();
		const input = btoa('flag{nothing_unseen}');
		const answer = await new Promise<AnalysisResponse>((resolve) => {
			worker.onmessage = (event: MessageEvent<AnalysisResponse>) => resolve(event.data);
			worker.postMessage({ kind: 'peel', id: 1, text: input, flagTags: 'flag' });
		});
		worker.terminate();
		if (answer.status !== 'peel') throw new Error(`peel failed: ${JSON.stringify(answer)}`);

		const props = { input, rsa: null, keyed: null, onkey: () => {}, onreset: () => {} };
		const quiet = await render(PeelPanel, { ...props, peel: answer.peel });
		expect(document.body.textContent).not.toContain('more possible readings');
		await quiet.unmount();

		const view = await render(PeelPanel, { ...props, peel: { ...answer.peel, searchCut: true } });
		unmount = view.unmount;

		await expect.element(page.getByText(/more possible readings than Trawl follows/)).toBeVisible();
	});

	it('counts the strings it did not list', async () => {
		const sample = listOf(5, (i) => ({ offset: i, text: `string ${i}` }));

		const view = await render(StringsView, { total: 100, sample });
		unmount = view.unmount;

		await expect.element(page.getByText(/Showing the first 5 of 100 strings/)).toBeVisible();
	});
});

const ascii = (text: string) => new TextEncoder().encode(text);

function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
	let at = 0;
	for (const part of parts) {
		out.set(part, at);
		at += part.length;
	}
	return out;
}

/** Local headers and nothing else, with a stored body after each. */
function zipOfHeaders(count: number, lastBody: string): Uint8Array<ArrayBuffer> {
	const parts = listOf(count, (i) => {
		const name = ascii(`n${i}`);
		const body = ascii(i === count - 1 ? lastBody : 'ab');
		const header = new DataView(new ArrayBuffer(30));
		header.setUint32(0, 0x04034b50, true);
		header.setUint16(4, 20, true);
		header.setUint32(18, body.length, true);
		header.setUint32(22, body.length, true);
		header.setUint16(26, name.length, true);
		return concat([new Uint8Array(header.buffer), name, body]);
	});
	return concat(parts);
}

/** An ELF header calling for 65,535 sections, each of them the one section after it. */
function elfOfSections(): Uint8Array<ArrayBuffer> {
	const header = new DataView(new ArrayBuffer(128));
	header.setUint32(0, 0x7f454c46);
	header.setUint8(4, 2);
	header.setUint8(5, 1);
	header.setUint8(6, 1);
	header.setUint16(16, 3, true);
	header.setUint16(18, 62, true);
	header.setUint32(20, 1, true);
	header.setBigUint64(40, 64n, true);
	header.setUint16(60, 65_535, true);
	header.setUint32(64 + 4, 1, true);
	header.setBigUint64(64 + 8, 2n, true);
	return new Uint8Array(header.buffer);
}

/** Object headers at eight bytes each, the way a table of them would run. */
const pdfOfHeaders = () =>
	ascii(`%PDF-1.7\n${listOf(120_000, (i) => `${i % 10} 0 obj\n`).join('')}`);

/** The whole page on one file, as far as the person being able to use it. */
async function dropped(bytes: Uint8Array<ArrayBuffer>, name: string): Promise<number> {
	const input = document.querySelector<HTMLInputElement>('input[type=file]');
	if (!input) throw new Error('no file input on the page');

	const files = new DataTransfer();
	files.items.add(new File([bytes], name));
	input.files = files.files;

	const started = performance.now();
	input.dispatchEvent(new Event('change', { bubbles: true }));

	await expect
		.poll(() => document.querySelector('[data-tour="rack"]') !== null, {
			timeout: 90_000,
			interval: 100
		})
		.toBe(true);
	await new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));

	return performance.now() - started;
}

describe('a list with the same thing in it twice', () => {
	it('draws a GIF frame whose two reading orders agree', async () => {
		const candidate = {
			channels: 'r',
			bit: 0,
			msbFirst: true,
			reason: 'a flag',
			preview: 'flag{twice}',
			readable: 11,
			bytesRead: 11,
			flags: ['flag{twice}']
		};
		const gif = {
			capped: false,
			error: null,
			sources: [
				{
					kind: 'frame',
					from: 1,
					to: null,
					delay: null,
					disposal: null,
					lsb: { pixels: 88, combinations: 2, candidates: [candidate, candidate] },
					chi: null,
					rs: null
				}
			]
		} as unknown as GifAnalysis;

		await render(GifFramesView, { gif, nested: null });

		await expect.element(page.getByText('a flag').first()).toBeVisible();
	});

	it('draws a hive that names the same key twice', async () => {
		const twice = { ...hive([], 0), searched: ['ControlSet001', 'ControlSet001'] };

		await render(HiveView, { hive: twice });

		await expect.element(page.getByText('ControlSet001').first()).toBeVisible();
	});
});

describe('the page, given a file built to freeze it', () => {
	const WAIT = { timeout: 120_000 };
	/** Slow runners are slow, and what this guards against took minutes. */
	const INTERACTIVE_WITHIN = 45_000;

	let unmount: (() => PromiseLike<void>) | undefined;

	async function openPage() {
		try {
			localStorage.setItem('trawl.tour.choice', 'skip');
		} catch {
			// Only there to keep the tour prompt out of the way
		}
		const view = await render(Page);
		unmount = view.unmount;
	}

	afterEach(async () => {
		await unmount?.();
		unmount = undefined;
	});

	it(
		'stays usable with a ZIP of 26,000 headers, and reports the flag past them',
		WAIT,
		async () => {
			await openPage();
			const file = zipOfHeaders(26_000, 'flag{past_the_headers}');
			expect(file.length).toBeLessThan(1 << 20);

			expect(await dropped(file, 'headers.zip')).toBeLessThan(INTERACTIVE_WITHIN);

			expect(document.querySelector('.recovered')?.textContent).toContain('flag{past_the_headers}');
			expect(document.getElementsByTagName('*').length).toBeLessThan(20_000);
		}
	);

	it('stays usable with a 128-byte ELF calling for 65,535 sections', WAIT, async () => {
		await openPage();

		expect(await dropped(elfOfSections(), 'sections.elf')).toBeLessThan(INTERACTIVE_WITHIN);

		await expect.element(page.getByText(/Showing the first 500 of 65,535 sections/)).toBeVisible();
		expect(document.getElementsByTagName('*').length).toBeLessThan(20_000);
	});

	it('stays usable with a PDF of 120,000 object headers', WAIT, async () => {
		await openPage();

		expect(await dropped(pdfOfHeaders(), 'objects.pdf')).toBeLessThan(INTERACTIVE_WITHIN);

		await expect.element(page.getByText(/Showing the first 500 of [\d,]+ objects/)).toBeVisible();
		expect(document.getElementsByTagName('*').length).toBeLessThan(20_000);
	});

	it('reads an image one row high, where both reading orders say the same', WAIT, async () => {
		await openPage();
		const bits = [...ascii('flag{one_row_high}')].flatMap((byte) =>
			listOf(8, (bit) => (byte >> (7 - bit)) & 1)
		);
		const pixels = new Uint8Array(bits.length * 3).map(
			(_, i) => 0x40 | (i % 3 === 0 ? bits[i / 3] : 0)
		);

		await dropped(encodePng(bits.length, 1, 2, pixels), 'row.png');

		expect(document.querySelector('.recovered')?.textContent).toContain('flag{one_row_high}');
	});

	it('shows what a file stopped it from doing', WAIT, async () => {
		await openPage();
		const distinct = listOf(12_000, (i) => `abc{aaaa${i}}`).join('\n');

		await dropped(ascii(`${distinct}\nflag{behind_the_shapes}`), 'shapes.txt');

		expect(document.querySelector('.recovered')?.textContent).toContain('flag{behind_the_shapes}');
		expect(document.querySelector('.limits')?.textContent).toMatch(
			/more distinct flags than Trawl lists/
		);
	});
});
