import init, {
	aes_probe,
	DecodedPixels,
	file_survey,
	find_flags_for_tags,
	inflate_stream,
	png_idat,
	png_palette,
	png_patch_ihdr,
	png_structure,
	jpeg_stego,
	jpeg_stego_extract,
	palette_extract,
	palette_stego,
	mantis_with_key_for_tags,
	mantis_packed_pass,
	pdf_stream,
	peel_encodings_for_tags,
	wav_lsb_extract,
	wav_lsb_sweep,
	wav_spectrogram,
	wav_structure,
	zip_structure,
	pdf_structure,
	binary_structure,
	registry_hive,
	sqlite_database,
	pcap_capture,
	gif_frame_analysis
} from '$lib/wasm/trawl_core';
import type {
	AnalysisRequest,
	AnalysisResponse,
	AudioSweep,
	ChiSquare,
	DerivedFinding,
	Found,
	GifAnalysis,
	JpegError,
	JpegStego,
	KeyAttempt,
	NestedArtifact,
	PaletteStego,
	PdfStructure,
	BinaryStructure,
	RegistryHive,
	SqliteDatabase,
	PcapCapture,
	PeelResult,
	PeelStep,
	PlaneWall,
	RsAnalysis,
	Spectrogram,
	Structure,
	Survey,
	Sweep,
	WavError,
	WavStructure,
	ZipArchive,
	ZipEntry,
	AesSolved
} from './protocol';
import { attack, looksLikeRsa } from '$lib/analysis/rsa';
import { isJpegError, isWavError } from './protocol';
import { assertZlibHeader, boundedInflate, compressionOf, isGzip, SeenBytes } from './decompress';

const ready = init();

const SWEEP_BYTES = 4096;
const THUMB_WIDTH = 220;
const CHI_STEPS = 64;

/** 1024 samples is the usual compromise: fine enough in time to read letters,
 *  fine enough in frequency to keep them from smearing together. */
const FFT_WINDOW = 1024;
const SPECTROGRAM_WIDTH = 900;
const CHI_STEPS_JPEG = 64;

/** Kept so a plane or extraction request does not re-send the whole file, and does not
 *  decode the image a sixth time. */
let cached: { bytes: Uint8Array; inflated: Uint8Array; image: DecodedPixels | null } | null = null;

/** Fraction of bytes a person could read, to tell text content from binary. */
function printableRatio(bytes: Uint8Array): number {
	if (bytes.length === 0) return 0;
	let readable = 0;
	for (const b of bytes) {
		if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) readable += 1;
	}
	return readable / bytes.length;
}

/**
 * What one file may spend inflating, across every stream it holds.
 *
 * A deflate stream turns a kilobyte into a megabyte, so a file under a megabyte can ask
 * for more than a tab holds. Bytes read get scanned for flags and go no further; the much
 * smaller share kept is what crosses to the page.
 */
const INFLATE_WORK_LIMIT = 128 << 20;
const INFLATE_KEPT_LIMIT = 16 << 20;
/** The most one stream gives, so one bomb cannot take what the rest of the file gets. */
const STREAM_LIMIT = 16 << 20;
/** Charged for opening a stream however little came out, so thousands of empty ones spend
 *  this budget as well. It leaves room for some thirty thousand of them. */
const STREAM_FLOOR = 4096;
/** Streams can overlap, so bytes alone do not bound the time: one megabyte of input read
 *  by ten thousand entries gives out nothing and takes minutes. */
const INFLATE_TIME_LIMIT = 15_000;
/** Flags kept from inflated streams across one file. */
const STREAM_FLAGS_KEPT = 20_000;

/** How much of an inflated stream the page gets as text. */
const TEXT_PREVIEW = 64 << 10;
const ZIP_TEXT_PREVIEW = 8192;

class InflateBudget {
	private work = INFLATE_WORK_LIMIT;
	private kept = INFLATE_KEPT_LIMIT;
	private flags = STREAM_FLAGS_KEPT;
	private readonly deadline = performance.now() + INFLATE_TIME_LIMIT;
	/** True once a scan had more flags than it or this could keep. */
	flagsTruncated = false;

	get spent(): boolean {
		return this.work <= 0 || performance.now() > this.deadline;
	}

	get streamLimit(): number {
		return Math.min(STREAM_LIMIT, Math.max(this.work, 0));
	}

	charge(bytes: number): void {
		this.work -= Math.max(bytes, STREAM_FLOOR);
	}

	/** Whether this many more bytes may go to the page. */
	keep(bytes: number): boolean {
		if (bytes > this.kept) return false;
		this.kept -= bytes;
		return true;
	}

	/** The flags in a stream, as far as there is room for them. */
	scan(raw: Uint8Array, flagTags: string): Found[] {
		const { flags, truncated } = scanFlags(raw, flagTags);
		const kept = flags.slice(0, Math.max(this.flags, 0));
		this.flags -= kept.length;
		this.flagsTruncated ||= truncated || kept.length < flags.length;
		return kept;
	}
}

const NOT_OPENED = 'the whole-file inflate budget had run out';

/** Recursion limits, one per-root context so nested ZIPs and carved files share a budget. */
const RECURSION_MAX_DEPTH = 8; // below the root file
const RECURSION_MAX_CHILDREN = 256; // total children analysed across the tree
const RECURSION_AGGREGATE_LIMIT = 64 << 20; // bytes across the children analysed
/** What the budgets above count is not what a child costs, since a small file can be built
 *  to take any detector as long as it is allowed. So the walk has a clock as well. */
const RECURSION_TIME_LIMIT = 30_000;
/** Skipped children written out, past which they are counted and no more. */
const RECURSION_SKIPS_LISTED = 512;
/** Findings kept from across the tree. A nested file can hold as many as a root can. */
const RECURSION_FINDINGS_KEPT = 20_000;

const BUDGET_SPENT = 'recursion budget exhausted';
const CLOCK_SPENT = 'the time budget for nested files ran out';

/** The file someone actually dropped gets far more room than a child inside it: a
 *  1000x1000 RGB image is already 3 MB of pixels. Still bounded, since a tiny PNG can
 *  claim to inflate to anything. */
const ROOT_PIXEL_LIMIT = 256 << 20;
const CHILD_PIXEL_LIMIT = 32 << 20;

/** What came out of an inflate, whatever else happened to it. */
type Opened = { output: Uint8Array; error: string | null; capped: boolean; trailing: number };

function unpackOpened(packed: Uint8Array): Opened {
	const headerLength = new DataView(packed.buffer, packed.byteOffset, 4).getUint32(0, true);
	const json = new TextDecoder().decode(packed.subarray(4, 4 + headerLength));
	return { ...JSON.parse(json), output: packed.subarray(4 + headerLength) };
}

function inflate(bytes: Uint8Array, wrapper: 'zlib' | 'raw', limit: number): Opened {
	return unpackOpened(inflate_stream(bytes, wrapper, limit));
}

/** What to say about a stream that did not simply end where it should. */
function damageOf({ output, error, capped, trailing }: Opened): string | null {
	const said: string[] = [];
	if (error) said.push(error);
	if (capped) said.push(`only the first ${output.length.toLocaleString()} bytes were read`);
	if (trailing > 0) {
		said.push(
			`${trailing.toLocaleString()} ${trailing === 1 ? 'byte follows' : 'bytes follow'} the end of the stream`
		);
	}
	return said.length > 0 ? said.join('; ') : null;
}

/** A stream's start as text, marked when there was more. */
function preview(raw: Uint8Array, length: number): string {
	const text = new TextDecoder('utf-8', { fatal: false }).decode(raw.subarray(0, length));
	return raw.length > length ? `${text}\n…` : text;
}

function scanFlags(raw: Uint8Array, flagTags: string): { flags: Found[]; truncated: boolean } {
	return JSON.parse(find_flags_for_tags(raw, flagTags));
}

function readWall(packed: Uint8Array): PlaneWall {
	const headerLength = new DataView(packed.buffer, packed.byteOffset, 4).getUint32(0, true);
	const json = new TextDecoder().decode(packed.subarray(4, 4 + headerLength));
	const meta = JSON.parse(json) as Omit<PlaneWall, 'thumbnails'>;

	return { ...meta, thumbnails: packed.slice(4 + headerLength) };
}

function readSpectrogram(packed: Uint8Array): Spectrogram {
	const headerLength = new DataView(packed.buffer, packed.byteOffset, 4).getUint32(0, true);
	const json = new TextDecoder().decode(packed.subarray(4, 4 + headerLength));
	const meta = JSON.parse(json) as Omit<Spectrogram, 'pixels'>;

	return { ...meta, pixels: packed.slice(4 + headerLength) };
}

function normaliseGifAnalysis(value: unknown): GifAnalysis | null {
	if (value === null || typeof value !== 'object') return null;
	const gif = value as GifAnalysis;
	for (const source of gif.sources ?? []) {
		const legacy = source as typeof source & { lsb: Sweep | Sweep['candidates'] };
		if (Array.isArray(legacy.lsb)) {
			legacy.lsb = {
				pixels: gif.width * gif.height,
				combinations: 0,
				candidates: legacy.lsb
			};
		}
	}
	return gif;
}

/**
 * The inflated pixel data, as much of it as could be read. Only PNG hands its pixel data
 * to an inflate; the rest carry their own.
 *
 * A browser shows the rows it reached when the stream is damaged, so a file can look
 * whole to a person and carry its flag in those rows. Only a stream with nothing in it
 * is an error.
 */
function pixelInput(
	bytes: Uint8Array,
	isPng: boolean,
	limit: number
): { inflated: Uint8Array; damage: string | null; error: string | null } {
	if (!isPng) return { inflated: new Uint8Array(), damage: null, error: null };

	const found = inflate(png_idat(bytes), 'zlib', limit);
	if (found.output.length === 0 && found.error) {
		return { inflated: found.output, damage: null, error: found.error };
	}
	return { inflated: found.output, damage: damageOf(found), error: null };
}

/**
 * Fills in the text of compressed chunks.
 *
 * Rust locates the zlib stream without inflating it, because what comes out has to be
 * budgeted across the whole file. Reporting "content unread" was honest and useless; a
 * flag can sit in a zTXt chunk indefinitely.
 *
 * @return how many chunks were not opened
 */
function inflateTextChunks(
	bytes: Uint8Array,
	structure: Structure,
	flagTags: string,
	budget: InflateBudget
): number {
	let unopened = (structure.textCount ?? structure.text.length) - structure.text.length;

	for (const chunk of structure.text) {
		if (!chunk.compressed || chunk.payloadLength === 0) continue;
		if (budget.spent) {
			chunk.error = NOT_OPENED;
			unopened += 1;
			continue;
		}

		const stream = bytes.subarray(chunk.payloadOffset, chunk.payloadOffset + chunk.payloadLength);
		const found = inflate(stream, 'zlib', budget.streamLimit);
		budget.charge(found.output.length);

		chunk.error = damageOf(found) ?? undefined;
		if (found.output.length === 0) continue;

		chunk.compressed = false;
		if (budget.keep(Math.min(found.output.length, TEXT_PREVIEW))) {
			chunk.text = preview(found.output, TEXT_PREVIEW);
		}

		// The byte-level scan ran before this text existed, so anything hiding
		// in a compressed chunk is only visible now.
		for (const flag of budget.scan(found.output, flagTags)) {
			structure.flags.push({
				offset: chunk.payloadOffset,
				text: flag.text,
				region: `inside ${chunk.kind}, after inflating`,
				credible: true
			});
		}
	}

	return unopened;
}

/** Filters that hold a picture, which a stream is opened for by the magic scan or not at all. */
const IMAGE_FILTERS = new Set(['DCTDecode', 'JPXDecode', 'CCITTFaxDecode', 'JBIG2Decode']);

/**
 * Undoes the filter chain on every stream a PDF's objects carry, and flag-scans the
 * result.
 *
 * A flag or a signature living inside a compressed stream is invisible to the raw
 * byte-level survey, which runs before any of this, so this is the only place it is
 * ever found.
 *
 * @return how many streams were not opened
 */
function inflatePdfStreams(
	bytes: Uint8Array,
	pdf: PdfStructure,
	flagTags: string,
	budget: InflateBudget
): number {
	let unopened = 0;

	for (const object of pdf.objects) {
		const stream = object.stream;
		if (!stream || !stream.filter || stream.length === 0) continue;
		if (IMAGE_FILTERS.has(stream.filter.split(' then ')[0])) continue;
		if (budget.spent) {
			stream.error = NOT_OPENED;
			unopened += 1;
			continue;
		}

		const packed = bytes.subarray(stream.offset, stream.offset + stream.length);
		const found = unpackOpened(pdf_stream(packed, stream.filter, budget.streamLimit));
		budget.charge(found.output.length);

		stream.error = damageOf(found) ?? undefined;
		if (found.output.length === 0) continue;

		stream.decoded = found.output.length;
		if (budget.keep(Math.min(found.output.length, TEXT_PREVIEW))) {
			stream.text = preview(found.output, TEXT_PREVIEW);
		}

		const flags = budget.scan(found.output, flagTags);
		if (flags.length > 0) object.flags = flags.map((f) => f.text);
	}

	return unopened;
}

/**
 * The flags in a database, with where they were.
 *
 * The core searched every live value whole, since what a cell shows stops at 240 bytes.
 * A deleted row is only ever what could be carved out of a page, so that is what gets
 * read here, a cell at a time, since the columns of a row sit side by side in the file and
 * a flag with a word before it stops looking like a flag.
 */
function flagSqliteCells(db: SqliteDatabase, flagTags: string): void {
	const encoder = new TextEncoder();
	const flags: NonNullable<SqliteDatabase['flags']> = [];

	for (const table of db.tables) {
		for (const text of table.flags ?? []) {
			flags.push({ text, table: table.name, deleted: false });
		}
		for (const cell of table.deleted.flat()) {
			if (!cell.text.includes('{')) continue;
			for (const { text } of scanFlags(encoder.encode(cell.text), flagTags).flags) {
				flags.push({ text, table: table.name, deleted: true });
			}
		}
	}

	db.flags = flags;
}

/**
 * The file bytes, with every text chunk's content appended.
 *
 * A compressed chunk holds text the raw bytes do not, and the AES probe pairs
 * hex and base64 it finds lying around. Appending the inflated text puts a key
 * or IV that was compressed back where the probe can see it, next to a payload
 * that was in the clear.
 */
function withInflatedText(bytes: Uint8Array, structure: Structure | null): Uint8Array {
	if (!structure) return bytes;
	const extra = structure.text
		.map((chunk) => chunk.text)
		.filter(Boolean)
		.join('\n');
	if (!extra) return bytes;

	const tail = new TextEncoder().encode(`\n${extra}`);
	const combined = new Uint8Array(bytes.length + tail.length);
	combined.set(bytes, 0);
	combined.set(tail, bytes.length);
	return combined;
}

/** Why an entry cannot be opened whatever the budgets say, if it cannot. */
function whyNotOpened(entry: ZipEntry, fileLength: number): string | null {
	if (entry.dataOffset === null) return 'the directory points here, but there is no header';
	if (entry.encrypted) return 'encrypted';
	if (!readableMethod(entry.method) && !readableMethod(entry.localMethod)) {
		return `${entry.method} compression, which Trawl does not read`;
	}
	if (entry.dataOffset >= fileLength && (entry.readLength ?? 0) > 0) {
		return 'its data would start past the end of the file';
	}
	return null;
}

function readableMethod(method: string | null | undefined): boolean {
	return method === 'stored' || method === 'deflate';
}

/**
 * An entry's content, by whichever method was claimed that can be read.
 *
 * Where the two descriptions disagree, a deflate stream that reads cleanly settles it,
 * since stored bytes almost never pass for one, and a reader taking the other's word
 * would come away with noise.
 */
function readEntry(bytes: Uint8Array, entry: ZipEntry, limit: number): Opened {
	const start = entry.dataOffset ?? bytes.length;
	const data = bytes.subarray(start, start + (entry.readLength ?? entry.compressed));
	const said = [entry.method, entry.localMethod];

	if (said.includes('deflate')) {
		const found = inflate(data, 'raw', limit);
		if (!found.error || !said.includes('stored')) return found;
	}
	return {
		output: data.subarray(0, limit),
		error: null,
		capped: data.length > limit,
		trailing: 0
	};
}

/**
 * Opens what entries it can, keeps what it can of that for the page, and writes on each
 * one that was not opened why not.
 *
 * @return how many entries the budget left unopened
 */
function inflateZipEntries(
	bytes: Uint8Array,
	zip: ZipArchive,
	flagTags: string,
	budget: InflateBudget
): number {
	let unopened = 0;

	for (const entry of zip.entries) {
		const refused = whyNotOpened(entry, bytes.length);
		if (refused) {
			entry.notOpened = refused;
			continue;
		}
		if ((entry.readLength ?? entry.compressed) === 0) continue;
		if (budget.spent) {
			entry.notOpened = NOT_OPENED;
			unopened += 1;
			continue;
		}

		const found = readEntry(bytes, entry, budget.streamLimit);
		const raw = found.output;
		budget.charge(raw.length);

		entry.readError = damageOf(found) ?? undefined;
		if (raw.length !== entry.uncompressed && !found.capped && !found.error) {
			const said = `declares ${entry.uncompressed.toLocaleString()} bytes and holds ${raw.length.toLocaleString()}`;
			entry.disagreement = entry.disagreement ? `${entry.disagreement}; ${said}` : said;
		}
		if (raw.length === 0) continue;

		if (budget.keep(raw.length)) entry.bytes = raw.slice();
		entry.flags = budget.scan(raw, flagTags).map((f) => f.text);
		if (printableRatio(raw) >= 0.85 && budget.keep(Math.min(raw.length, ZIP_TEXT_PREVIEW))) {
			entry.text = preview(raw, ZIP_TEXT_PREVIEW);
		}
	}

	return unopened;
}

/** Context shared by the recursive walk, so budgets are global and dedupe works. */
class RecursionContext {
	readonly inflate = new InflateBudget();
	/** Everything analysed so far, by where it was found. */
	readonly seen = new SeenBytes<string>();
	childrenAnalysed = 0;
	expandedBytes = 0;
	capped = false;
	depthReached = false;
	clockRanOut = false;
	unlisted = 0;
	/** Compressed streams inside nested files that the budget left unopened. */
	unopened = 0;
	findingsDropped = false;
	private skipsListed = 0;
	private findingsLeft = RECURSION_FINDINGS_KEPT;
	private readonly deadline = performance.now() + RECURSION_TIME_LIMIT;

	/** What stops another child from being opened at all, if anything does. */
	refusal(): string | null {
		if (performance.now() > this.deadline) {
			this.capped = true;
			this.clockRanOut = true;
			return CLOCK_SPENT;
		}
		if (this.childrenAnalysed >= RECURSION_MAX_CHILDREN) {
			this.capped = true;
			return BUDGET_SPENT;
		}
		return null;
	}

	/** Charges a child for the bytes it really turned out to hold. */
	tryReserve(childBytes: number): boolean {
		if (this.expandedBytes + childBytes > RECURSION_AGGREGATE_LIMIT) {
			this.capped = true;
			return false;
		}
		this.childrenAnalysed += 1;
		this.expandedBytes += childBytes;
		return true;
	}

	/** Whether another skipped child gets a line of its own. */
	listSkip(): boolean {
		if (this.skipsListed >= RECURSION_SKIPS_LISTED) {
			this.unlisted += 1;
			return false;
		}
		this.skipsListed += 1;
		return true;
	}

	keepFindings(findings: DerivedFinding[]): DerivedFinding[] {
		const kept = findings.slice(0, this.findingsLeft);
		this.findingsLeft -= kept.length;
		this.findingsDropped ||= kept.length < findings.length;
		return kept;
	}
}

type ChildSource = { name: string; source: 'zip' | 'carved'; offset: number; size: number };

function childId({ source, offset }: ChildSource, depth: number): string {
	return `${source}-${offset}-${depth}`;
}

function skippedChild(
	child: ChildSource,
	depth: number,
	status: 'skipped' | 'error',
	reason: string,
	format: string = status
): NestedArtifact {
	return {
		id: childId(child, depth),
		name: child.name,
		source: child.source,
		offset: child.offset,
		format,
		size: child.size,
		depth,
		status,
		reason,
		findings: [],
		children: []
	};
}

function canRecurse(label: string): boolean {
	return [
		'PNG image',
		'BMP image',
		'GIF image',
		'RIFF container',
		'JPEG image',
		'ZIP archive',
		'PDF document'
	].includes(label);
}

/**
 * Opens everything inside a file, within the walk's budgets, and hangs what it finds on
 * `artifact`. A file past any of them gets a line saying which, rather than vanishing.
 */
function descend(
	artifact: NestedArtifact,
	bytes: Uint8Array,
	zip: ZipArchive | null,
	survey: Survey,
	flagTags: string,
	context: RecursionContext,
	depth: number,
	origin: string
): void {
	const next = depth + 1;
	const skip = (
		child: ChildSource,
		status: 'skipped' | 'error',
		reason: string,
		format?: string
	) => {
		if (context.listSkip())
			artifact.children.push(skippedChild(child, next, status, reason, format));
	};

	/** The checks every child goes through once its bytes are in hand. */
	const analyse = (child: ChildSource, raw: Uint8Array, damage: string | null) => {
		const earlier = context.seen.find(raw);
		if (earlier !== undefined) {
			skip({ ...child, size: raw.length }, 'skipped', `duplicate of ${earlier}`, 'duplicate');
			return;
		}
		if (!context.tryReserve(raw.length)) {
			skip({ ...child, size: raw.length }, 'skipped', BUDGET_SPENT);
			return;
		}

		try {
			const found = analyseInternal(child, raw, flagTags, context, next, origin);
			if (damage) found.damage = found.damage ? `${damage}; ${found.damage}` : damage;
			artifact.children.push(found);
		} catch (error: unknown) {
			const reason = error instanceof Error ? error.message : String(error);
			artifact.children.push(skippedChild({ ...child, size: raw.length }, next, 'error', reason));
		}
	};

	const atTheBottom = depth >= RECURSION_MAX_DEPTH;
	const embedded = survey.magic.filter((hit) => hit.embedded && canRecurse(hit.label));
	if (atTheBottom) {
		if (embedded.length > 0 || (zip?.entries.length ?? 0) > 0) {
			context.capped = true;
			context.depthReached = true;
		}
		return;
	}

	/** The stretches of this file that an entry read to its end, with nothing left over. */
	const read: (readonly [number, number])[] = [];

	for (const entry of zip?.entries ?? []) {
		const child: ChildSource = {
			name: entry.name,
			source: 'zip',
			offset: entry.offset,
			size: entry.uncompressed
		};

		const refused = whyNotOpened(entry, bytes.length);
		if (refused) {
			skip(child, 'skipped', refused);
			continue;
		}
		if ((entry.readLength ?? entry.compressed) === 0) continue;

		const stopped = context.refusal();
		if (stopped) {
			skip(child, 'skipped', stopped);
			continue;
		}

		// What the root's own pass already opened and kept need not be opened twice.
		let raw = depth === 0 ? entry.bytes : undefined;
		let damage = depth === 0 ? (entry.readError ?? null) : null;
		if (!raw) {
			if (context.inflate.spent) {
				context.capped = true;
				skip(child, 'skipped', NOT_OPENED);
				continue;
			}
			const found = readEntry(bytes, entry, context.inflate.streamLimit);
			context.inflate.charge(found.output.length);
			raw = found.output;
			damage = damageOf(found);
			if (raw.length === 0) {
				if (found.error) skip(child, 'error', found.error);
				continue;
			}
		}

		analyse(child, raw, damage);
		if (!damage && entry.dataOffset !== null) {
			read.push([entry.dataOffset, entry.dataOffset + (entry.readLength ?? entry.compressed)]);
		}
	}

	// A signature inside something this archive already read was read when that was, and the
	// signature at each of its own headers is only the archive itself again. A span a stream
	// never reached proves nothing: broken or short deflate can claim to cover any bytes.
	const headers = new Set(zip?.entries.map((entry) => entry.offset));
	const inEntry = spansHolding(read);

	for (const hit of embedded) {
		if (hit.offset + hit.length > bytes.length) continue;
		if (headers.has(hit.offset) || inEntry(hit.offset, hit.length)) continue;

		const child: ChildSource = {
			name: hit.label,
			source: 'carved',
			offset: hit.offset,
			size: hit.length
		};

		const stopped = context.refusal();
		if (stopped) {
			skip(child, 'skipped', stopped);
			continue;
		}

		analyse(child, bytes.subarray(hit.offset, hit.offset + hit.length), null);
	}
}

/** The readers of a nested file that can stop short or refuse it, named as a root's are. */
type ChildReaders = Pick<
	Extract<AnalysisResponse, { status: 'ok' }>,
	'survey' | 'structure' | 'wav' | 'jpeg' | 'zip' | 'pdf' | 'sqlite' | 'pcap' | 'gif'
>;

/** What a PDF held past what was read, if anything. */
function pdfShortfall(pdf: PdfStructure | null | undefined): string | null {
	const unlisted = pdf?.streamsUnlisted ?? 0;
	if (unlisted > 0) {
		return `${unlisted.toLocaleString()} PDF ${unlisted === 1 ? 'stream was' : 'streams were'} never opened`;
	}
	return pdf?.objectsCapped ? 'Trawl stopped reading PDF objects at its limit' : null;
}

/** Whether a database held more tables than were read. */
function tablesUnread(sqlite: SqliteDatabase | null | undefined): number {
	return sqlite ? Math.max(sqlite.tableCount - sqlite.tables.length, 0) : 0;
}

/** Reasons one nested file's line gives before it counts the rest. */
const TROUBLE_NAMED = 3;
/** Longest any of them runs, since a stream's error can quote a name out of the file. */
const TROUBLE_LENGTH = 160;

/**
 * What a nested file's readers stopped short of or failed on, in a line, since a tree can
 * hold hundreds of them.
 *
 * @param detectors what only the pass over the file itself could tell, ahead of the rest
 */
function troubleIn(readers: ChildReaders, detectors: string[]): string | undefined {
	const { survey, structure, wav, jpeg, zip, pdf, sqlite, pcap, gif } = readers;
	const errors = [
		...(structure?.text ?? []).map((chunk) => chunk.error),
		...(pdf?.objects ?? []).map((object) => object.stream?.error)
	].filter((error) => error !== undefined);

	const said = [...detectors];
	if (wav && isWavError(wav)) said.push(`the WAV could not be read: ${wav.error}`);
	if (gif?.error) said.push(`GIF frames could not be read: ${gif.error}`);
	if (errors.length > 0) {
		said.push(
			errors.length > 1 ? `${errors[0]}, and ${errors.length - 1} more like it` : errors[0]
		);
	}
	if (gif?.stopped) said.push(`GIF frames stop short: ${gif.stopped}`);
	if (gif?.capped) {
		said.push(
			`Trawl read ${gif.analysedFrames.toLocaleString()} of ${gif.declaredFrames.toLocaleString()} GIF frames`
		);
	}
	if (survey.flagsTruncated || structure?.flagsTruncated || pcap?.flagsTruncated) {
		said.push('the list of flags stops partway');
	}
	if (sqlite?.flagsTruncated) said.push('a long database cell was not read to its end');
	const unreadTables = tablesUnread(sqlite);
	if (unreadTables > 0) {
		said.push(
			`${unreadTables.toLocaleString()} database ${unreadTables === 1 ? 'table was' : 'tables were'} not read`
		);
	}
	const unopened = pdfShortfall(pdf);
	if (unopened) said.push(unopened);
	if (jpeg && !isJpegError(jpeg) && jpeg.truncated) said.push('a JPEG scan ran out of data');

	if (survey.magicOmitted) {
		said.push(`${survey.magicOmitted.toLocaleString()} more file signatures were left out`);
	}
	if (zip?.capped) {
		said.push(`Trawl stopped reading local headers at ${zip.entries.length.toLocaleString()}`);
	}
	if (pcap?.packetsCapped) {
		said.push(`Trawl read the first ${pcap.packetCount.toLocaleString()} packets and stopped`);
	}

	if (said.length === 0) return undefined;

	const named = said
		.slice(0, TROUBLE_NAMED)
		.map((reason) =>
			reason.length > TROUBLE_LENGTH ? `${reason.slice(0, TROUBLE_LENGTH)}…` : reason
		)
		.join('; ');
	return said.length > TROUBLE_NAMED ? `${named}; and ${said.length - TROUBLE_NAMED} more` : named;
}

/** Whether a range sits inside one of these stretches of a file. */
function spansHolding(
	stretches: (readonly [number, number])[]
): (offset: number, length: number) => boolean {
	const spans = [...stretches].sort((a, b) => a[0] - b[0]);

	return (offset, length) => {
		let low = 0;
		let high = spans.length;
		while (low < high) {
			const middle = (low + high) >> 1;
			if (spans[middle][0] <= offset) low = middle + 1;
			else high = middle;
		}
		return low > 0 && offset + length <= spans[low - 1][1];
	};
}

/**
 * Runs the full detector set on a file inside another and returns a compact summary.
 * Summary mode skips plane-wall thumbnails and spectrogram pixels.
 */
function analyseInternal(
	child: ChildSource,
	bytes: Uint8Array,
	flagTags: string,
	context: RecursionContext,
	depth: number,
	parentOrigin: string
): NestedArtifact {
	const { name, source: sourceKind, offset: sourceOffset } = child;
	const origin = parentOrigin ? `${parentOrigin} / ${name}` : name;
	context.seen.add(bytes, origin);

	const survey = JSON.parse(file_survey(bytes, flagTags)) as Survey;
	const walked = JSON.parse(png_structure(bytes, flagTags)) as Structure;
	const structure = walked.signature ? walked : null;

	if (structure) {
		context.unopened += inflateTextChunks(bytes, structure, flagTags, context.inflate);
	}

	const wav = JSON.parse(wav_structure(bytes)) as WavStructure | WavError | null;
	const zip = JSON.parse(zip_structure(bytes)) as ZipArchive | null;

	const aes = JSON.parse(aes_probe(withInflatedText(bytes, structure), flagTags)) as AesSolved[];
	const jpeg = JSON.parse(jpeg_stego(bytes, SWEEP_BYTES, CHI_STEPS_JPEG, flagTags)) as
		JpegStego | JpegError | null;

	let sweep: Sweep | null = null;
	let chi: ChiSquare | null = null;
	let rs: RsAnalysis | null = null;
	let paletteStego: PaletteStego | null = null;
	let audio: AudioSweep | null = null;

	const pixels = pixelInput(bytes, structure !== null, CHILD_PIXEL_LIMIT);

	const detectors: string[] = [];
	const failed = (detector: string, error: unknown) =>
		detectors.push(`${detector} failed: ${error instanceof Error ? error.message : String(error)}`);

	if (pixels.error === null) {
		let image: DecodedPixels | null = null;
		try {
			if (structure) {
				structure.palette = JSON.parse(png_palette(bytes, pixels.inflated)) as Structure['palette'];
			}

			paletteStego = JSON.parse(
				palette_stego(bytes, pixels.inflated, SWEEP_BYTES, flagTags)
			) as PaletteStego | null;

			image = new DecodedPixels(bytes, pixels.inflated);
			sweep = JSON.parse(image.lsb_sweep(SWEEP_BYTES, flagTags)) as Sweep;
			chi = JSON.parse(image.chi_square(CHI_STEPS)) as ChiSquare;
			rs = JSON.parse(image.rs_analysis()) as RsAnalysis;

			const rows = image.rows();
			const declared = image.declared_rows();
			if (rows < declared) {
				detectors.push(
					`Trawl read ${rows.toLocaleString()} of ${declared.toLocaleString()} image rows${pixels.damage ? ` (${pixels.damage})` : ''}`
				);
			} else if (pixels.damage) {
				detectors.push(`the image data is damaged (${pixels.damage})`);
			}
		} catch (error: unknown) {
			// Every file that is not an image comes through here, with no pixels to miss.
			if (['PNG image', 'BMP image', 'GIF image'].includes(survey.format ?? '')) {
				failed('the pixel tools', error);
			}
		} finally {
			image?.free();
		}
	} else {
		detectors.push(`the image data could not be read: ${pixels.error}`);
	}

	if (wav && !isWavError(wav)) {
		try {
			audio = JSON.parse(wav_lsb_sweep(bytes, SWEEP_BYTES, flagTags)) as AudioSweep;
		} catch (error: unknown) {
			failed('the audio sweep', error);
		}
		// Skip spectrogram in recursive analysis to keep summaries compact
	}

	// A JPEG's signature turns up by chance in audio and the like, so one carved out that will
	// not decode may never have been a JPEG. An entry someone put in an archive was a file.
	if (jpeg && isJpegError(jpeg) && sourceKind === 'zip') {
		detectors.push(`JPEG coefficients could not be read: ${jpeg.error}`);
	}

	// Collect direct findings from this level
	const findings: DerivedFinding[] = [];

	// Credible raw flags from survey
	for (const hit of survey.flags) {
		if (hit.credible) {
			findings.push({
				text: hit.text,
				detector: 'byte scan',
				origin,
				reason: `flag at offset 0x${hit.offset.toString(16)}`
			});
		}
	}

	// Credible flags from structure (PNG text chunks, etc.)
	for (const hit of structure?.flags ?? []) {
		if (hit.credible) {
			findings.push({
				text: hit.text,
				detector: 'PNG text chunk',
				origin,
				reason: hit.region
			});
		}
	}

	// AES findings
	for (const solved of aes) {
		for (const flag of solved.flags) {
			findings.push({
				text: flag,
				detector: 'AES-CBC',
				origin,
				reason: `key ${solved.keyHex.slice(0, 8)}… iv ${solved.ivHex.slice(0, 8)}…`
			});
		}
	}

	// JPEG coefficient findings
	if (jpeg && !('error' in jpeg)) {
		for (const candidate of jpeg.candidates) {
			for (const flag of candidate.flags) {
				findings.push({
					text: flag,
					detector: 'JPEG coeffs',
					origin,
					reason: candidate.reason
				});
			}
		}
	}

	// Pixel LSB findings
	if (sweep) {
		for (const candidate of sweep.candidates) {
			for (const flag of candidate.flags) {
				findings.push({
					text: flag,
					detector: 'pixel LSB',
					origin,
					reason: `${candidate.channels} bit ${candidate.bit} ${candidate.msbFirst ? 'msb' : 'lsb'}`
				});
			}
		}
	}

	// Chi-square findings
	if (chi?.detected) {
		findings.push({
			text: `${(chi.embeddedFraction * 100).toFixed(1)}% embedded (chi²)`,
			detector: 'chi-square',
			origin,
			reason: `p=${chi.peakProbability.toFixed(4)}`
		});
	}

	// RS findings
	if (rs?.detected) {
		findings.push({
			text: `${(rs.rate * 100).toFixed(1)}% embedded (RS)`,
			detector: 'RS analysis',
			origin,
			reason: `rate ${rs.rate.toFixed(3)}`
		});
	}

	// Audio LSB findings
	if (audio) {
		for (const candidate of audio.candidates) {
			for (const flag of candidate.flags) {
				findings.push({
					text: flag,
					detector: 'audio LSB',
					origin,
					reason: `${candidate.channels} bit ${candidate.bit}`
				});
			}
		}
		for (const tone of audio.tones ?? []) {
			findings.push({
				text: `${tone.kind}: ${tone.decoded}`,
				detector: 'tone decode',
				origin,
				reason: `${Math.round(tone.confidence * 100)}% fit`
			});
		}
	}

	// Palette stego findings
	if (paletteStego) {
		for (const candidate of paletteStego.candidates) {
			for (const flag of candidate.flags) {
				findings.push({
					text: flag,
					detector: 'palette indices',
					origin,
					reason: candidate.reason
				});
			}
		}
	}

	// The readers that only find a flag once they have read the format. A capture or a
	// database in an archive is as common as one on its own.
	const pdf = JSON.parse(pdf_structure(bytes)) as PdfStructure | null;
	if (pdf) {
		context.unopened += inflatePdfStreams(bytes, pdf, flagTags, context.inflate);
		for (const object of pdf.objects) {
			for (const text of object.flags ?? []) {
				findings.push({ text, detector: 'PDF stream', origin, reason: `object ${object.number}` });
			}
		}
	}

	const sqlite = JSON.parse(sqlite_database(bytes, flagTags)) as SqliteDatabase | null;
	if (sqlite) {
		flagSqliteCells(sqlite, flagTags);
		for (const found of sqlite.flags ?? []) {
			findings.push({
				text: found.text,
				detector: 'SQLite cell',
				origin,
				reason: `${found.deleted ? 'deleted row' : 'row'} in ${found.table}`
			});
		}
	}

	const pcap = JSON.parse(pcap_capture(bytes, flagTags)) as PcapCapture | null;
	for (const stream of pcap?.streams ?? []) {
		for (const text of stream.flags) {
			findings.push({
				text,
				detector: 'TCP stream',
				origin,
				reason: `${stream.src} to ${stream.dst}`
			});
		}
	}

	// Structural anomalies
	if (structure?.trailing) {
		findings.push({
			text: `${structure.trailing.length} bytes after IEND`,
			detector: 'PNG structure',
			origin,
			reason: `at 0x${structure.trailing.offset.toString(16)}`
		});
	}
	for (const chunk of structure?.chunks ?? []) {
		if (!chunk.crcOk) {
			findings.push({
				text: `CRC mismatch on ${chunk.kind}`,
				detector: 'PNG structure',
				origin,
				reason: `at 0x${chunk.offset.toString(16)}`
			});
		}
	}
	if (survey.jpegTrailing) {
		findings.push({
			text: `${survey.jpegTrailing.length} bytes after JPEG EOI`,
			detector: 'JPEG structure',
			origin,
			reason: `at 0x${survey.jpegTrailing.offset.toString(16)}`
		});
	}

	// Determine format string
	let format = survey.format ?? 'unidentified';
	if (structure) format = 'PNG';
	else if (wav && !isWavError(wav)) format = 'WAV';
	else if (jpeg && !('error' in jpeg)) format = 'JPEG';
	else if (zip) format = 'ZIP';

	// GIF frame analysis for nested GIFs (children get frame/difference findings)
	const gifFindings: DerivedFinding[] = [];
	let gif: GifAnalysis | null = null;
	if (survey.format === 'GIF image') {
		try {
			const json = gif_frame_analysis(bytes, flagTags, SWEEP_BYTES, CHI_STEPS);
			gif = normaliseGifAnalysis(JSON.parse(json));
			if (gif && !gif.error && gif.sources.length > 0) {
				for (const source of gif.sources) {
					const label =
						source.kind === 'frame'
							? `frame ${source.from}`
							: `frames ${source.from} to ${source.to} difference`;
					for (const candidate of source.lsb.candidates) {
						for (const flag of candidate.flags) {
							gifFindings.push({
								text: flag,
								detector: `GIF ${label} LSB`,
								origin,
								reason: `${candidate.channels} bit ${candidate.bit} ${candidate.msbFirst ? 'msb' : 'lsb'}`
							});
						}
					}
					if (source.chi?.detected) {
						gifFindings.push({
							text: `${(source.chi.embeddedFraction * 100).toFixed(1)}% embedded (chi²)`,
							detector: `GIF ${label} chi-square`,
							origin,
							reason: `embedded fraction ${source.chi.embeddedFraction.toFixed(3)}`
						});
					}
					if (source.rs?.detected) {
						gifFindings.push({
							text: `${(source.rs.rate * 100).toFixed(1)}% embedded (RS)`,
							detector: `GIF ${label} RS analysis`,
							origin,
							reason: `rate ${source.rs.rate.toFixed(3)}`
						});
					}
				}
			}
		} catch (error: unknown) {
			failed('the GIF frame reader', error);
		}
	}

	const artifact: NestedArtifact = {
		id: childId(child, depth),
		name,
		source: sourceKind,
		offset: sourceOffset,
		format,
		size: bytes.length,
		depth,
		status: 'analysed',
		findings: context.keepFindings([...findings, ...gifFindings]),
		damage: troubleIn({ survey, structure, wav, jpeg, zip, pdf, sqlite, pcap, gif }, detectors),
		children: []
	};

	descend(artifact, bytes, zip, survey, flagTags, context, depth, origin);

	return artifact;
}

function countDamaged(artifact: NestedArtifact): number {
	let count = artifact.damage || artifact.status === 'error' ? 1 : 0;
	for (const child of artifact.children) {
		count += countDamaged(child);
	}
	return count;
}

function countSkipped(artifact: NestedArtifact): number {
	let count = artifact.status === 'skipped' ? 1 : 0;
	for (const child of artifact.children) {
		count += countSkipped(child);
	}
	return count;
}

const NO_SURVEY = (size: number): Survey => ({
	size,
	format: null,
	flags: [],
	magic: [],
	exif: null,
	jpegSegments: [],
	jpegComments: [],
	jpegTrailing: null,
	strings: { total: 0, wide: 0, sample: [] },
	entropy: { window: 0, values: [] }
});

const FLAGS_CUT_SHORT =
	'This file holds more distinct flags than Trawl lists, so the list stops partway. Anything past that point is not shown.';

async function analyseRoot(
	id: number,
	name: string,
	bytes: Uint8Array,
	flagTags: string
): Promise<AnalysisResponse> {
	await ready;

	const crashed: string[] = [];
	const notes: string[] = [];

	/** One reader crashing on a hostile file should not cost the results of the rest. */
	function attempt<T>(reader: string, read: () => T, fallback: T): T {
		try {
			return read();
		} catch {
			crashed.push(reader);
			return fallback;
		}
	}

	// The last file's image is in the way of this one, and nothing can ask for it now.
	cached?.image?.free();
	cached = null;

	const budget = new InflateBudget();
	let unopenedStreams = 0;

	const survey = attempt(
		'byte scan',
		() => JSON.parse(file_survey(bytes, flagTags)) as Survey,
		NO_SURVEY(bytes.length)
	);
	const walked = attempt(
		'PNG',
		() => JSON.parse(png_structure(bytes, flagTags)) as Structure,
		null
	);
	const structure = walked?.signature ? walked : null;

	if (structure) {
		unopenedStreams += attempt(
			'PNG text',
			() => inflateTextChunks(bytes, structure, flagTags, budget),
			0
		);
	}

	const wav = attempt(
		'WAV',
		() => JSON.parse(wav_structure(bytes)) as WavStructure | WavError | null,
		null
	);
	const zip = attempt('ZIP', () => JSON.parse(zip_structure(bytes)) as ZipArchive | null, null);
	if (zip) {
		unopenedStreams += attempt(
			'ZIP entry',
			() => inflateZipEntries(bytes, zip, flagTags, budget),
			0
		);
	}

	const pdf = attempt('PDF', () => JSON.parse(pdf_structure(bytes)) as PdfStructure | null, null);
	if (pdf) {
		unopenedStreams += attempt(
			'PDF stream',
			() => inflatePdfStreams(bytes, pdf, flagTags, budget),
			0
		);
	}

	const binary = attempt(
		'binary',
		() => JSON.parse(binary_structure(bytes)) as BinaryStructure | null,
		null
	);
	const hive = attempt(
		'registry hive',
		() => JSON.parse(registry_hive(bytes)) as RegistryHive | null,
		null
	);
	const sqlite = attempt(
		'SQLite',
		() => JSON.parse(sqlite_database(bytes, flagTags)) as SqliteDatabase | null,
		null
	);
	if (sqlite) attempt('SQLite', () => flagSqliteCells(sqlite, flagTags), undefined);
	const pcap = attempt(
		'packet capture',
		() => JSON.parse(pcap_capture(bytes, flagTags)) as PcapCapture | null,
		null
	);

	const aes = attempt(
		'AES',
		() => JSON.parse(aes_probe(withInflatedText(bytes, structure), flagTags)) as AesSolved[],
		[]
	);
	const jpeg = attempt(
		'JPEG',
		() =>
			JSON.parse(jpeg_stego(bytes, SWEEP_BYTES, CHI_STEPS_JPEG, flagTags)) as
				JpegStego | JpegError | null,
		null
	);

	let sweep: Sweep | null = null;
	let wall: PlaneWall | null = null;
	let chi: ChiSquare | null = null;
	let rs: RsAnalysis | null = null;
	let paletteStego: PaletteStego | null = null;
	let audio: AudioSweep | null = null;
	let spectrogram: Spectrogram | null = null;
	let audioError: string | null = null;

	const pixels = attempt(
		'pixel data',
		() => pixelInput(bytes, structure !== null, ROOT_PIXEL_LIMIT),
		{
			inflated: new Uint8Array(),
			damage: null,
			error: null
		}
	);
	let pixelError = pixels.error;

	// Held whatever happened above
	const held = { bytes, inflated: pixels.inflated, image: null as DecodedPixels | null };
	cached = held;

	if (pixelError === null) {
		try {
			if (structure) {
				structure.palette = JSON.parse(png_palette(bytes, pixels.inflated)) as Structure['palette'];
			}

			paletteStego = JSON.parse(
				palette_stego(bytes, pixels.inflated, SWEEP_BYTES, flagTags)
			) as PaletteStego | null;

			const image = new DecodedPixels(bytes, pixels.inflated);
			held.image = image;

			sweep = JSON.parse(image.lsb_sweep(SWEEP_BYTES, flagTags)) as Sweep;
			wall = readWall(image.plane_wall(THUMB_WIDTH));
			chi = JSON.parse(image.chi_square(CHI_STEPS)) as ChiSquare;
			rs = JSON.parse(image.rs_analysis()) as RsAnalysis;

			const rows = image.rows();
			const declared = image.declared_rows();
			if (rows < declared) {
				notes.push(
					`The image data stops short${pixels.damage ? ` (${pixels.damage})` : ''}. Trawl read ${rows.toLocaleString()} of ${declared.toLocaleString()} rows, as a browser would, and ran the pixel tools on those.`
				);
			} else if (pixels.damage) {
				notes.push(
					`The image data is damaged (${pixels.damage}). Every row could still be read, so the pixel tools ran on all of them.`
				);
			}
		} catch (error: unknown) {
			pixelError = error instanceof Error ? error.message : String(error);
		}
	}

	if (wav && !isWavError(wav)) {
		try {
			audio = JSON.parse(wav_lsb_sweep(bytes, SWEEP_BYTES, flagTags)) as AudioSweep;
		} catch (error: unknown) {
			audioError = error instanceof Error ? error.message : String(error);
		}

		try {
			spectrogram = readSpectrogram(wav_spectrogram(bytes, FFT_WINDOW, SPECTROGRAM_WIDTH));
		} catch (error: unknown) {
			audioError ??= error instanceof Error ? error.message : String(error);
		}
	}

	// GIF frame analysis for root file
	let gif: GifAnalysis | null = null;
	if (survey.format === 'GIF image') {
		try {
			const json = gif_frame_analysis(bytes, flagTags, SWEEP_BYTES, CHI_STEPS);
			gif = normaliseGifAnalysis(JSON.parse(json));
		} catch {
			crashed.push('GIF frame');
		}
	}

	// The walk comes last and is held apart: what it opens can be built to take as long as
	// it is given, and a failure part way through costs what it had not reached yet.
	const context = new RecursionContext();
	context.seen.add(bytes, name);
	const top: NestedArtifact = {
		id: 'root',
		name,
		source: 'zip',
		offset: 0,
		format: survey.format,
		size: bytes.length,
		depth: 0,
		status: 'analysed',
		findings: [],
		children: []
	};
	attempt(
		'nested file',
		() => descend(top, bytes, zip, survey, flagTags, context, 0, ''),
		undefined
	);

	const unopened = unopenedStreams + context.unopened;
	if (unopened > 0) {
		notes.push(
			`This file asks for more decompression than Trawl will do, so ${unopened.toLocaleString()} compressed ${unopened === 1 ? 'stream was' : 'streams were'} not opened. A flag inside one would not show here.`
		);
	}
	const damaged = countDamaged(top);
	if (damaged > 0) {
		notes.push(
			`${damaged.toLocaleString()} nested ${damaged === 1 ? 'file' : 'files'} could not be read in full: a stream was damaged, a limit was reached or a detector failed. A flag in what went unread would not show here. The writeup lists which, and why.`
		);
	}
	if (sqlite?.flagsTruncated) {
		notes.push(
			'Trawl could not read every long database cell to its end, so a flag in what it did not reach would not show here.'
		);
	}
	if (tablesUnread(sqlite) > 0) {
		notes.push(
			`Trawl read the first ${sqlite?.tables.length.toLocaleString()} of ${sqlite?.tableCount.toLocaleString()} database tables. A flag in the others would not show here.`
		);
	}
	const pdfUnread = pdfShortfall(pdf);
	if (pdfUnread) notes.push(`${pdfUnread}. A flag in what went unread would not show here.`);
	if (jpeg && !isJpegError(jpeg) && jpeg.truncated) {
		notes.push(
			'A scan in this JPEG ran out of data, so its last blocks read as zero and the coefficient tools cannot see them.'
		);
	}
	if (pcap?.truncated) {
		notes.push(
			'Some packets in this capture were saved with fewer bytes than they carried, so the rest of them is not in the file.'
		);
	}
	if (zip?.capped) {
		notes.push(
			`Trawl stopped reading local headers at ${zip.entries.length.toLocaleString()}. Entries the directory lists were still opened, and any others past that point were not found.`
		);
	}
	if (context.clockRanOut) {
		notes.push(
			'The time budget for nested files ran out, so the ones marked skipped were not analysed.'
		);
	} else if (context.capped) {
		notes.push(
			context.depthReached
				? `Trawl opens files inside files down to ${RECURSION_MAX_DEPTH} levels, and this goes further. Analyse an entry on its own to carry on from there.`
				: 'This file holds more nested files than Trawl analyses, so the ones marked skipped were not. Analyse an entry on its own to read it in full.'
		);
	}
	if (
		survey.flagsTruncated ||
		structure?.flagsTruncated ||
		pcap?.flagsTruncated ||
		budget.flagsTruncated ||
		context.inflate.flagsTruncated ||
		context.findingsDropped
	) {
		notes.push(FLAGS_CUT_SHORT);
	}
	if (survey.magicOmitted) {
		notes.push(
			`${survey.magicOmitted.toLocaleString()} more file signatures were left out, past the first 4,096 of their kind.`
		);
	}
	if (pcap?.packetsCapped) {
		notes.push(
			`Trawl read the first ${pcap.packetCount.toLocaleString()} packets of this capture and stopped. Anything sent after that was not reassembled.`
		);
	}
	if (binary?.symbolsCapped) {
		notes.push(
			'Trawl stopped reading the symbol tables at its budget, so the counts and the stack guard check cover what it reached.'
		);
	}
	if (gif?.stopped) {
		notes.push(`GIF frames stop short: ${gif.stopped}. The frames before that were analysed.`);
	}

	return {
		id,
		status: 'ok',
		crashed,
		notes,
		name,
		size: bytes.length,
		survey,
		structure,
		wav,
		jpeg,
		paletteStego,
		zip,
		pdf,
		binary,
		hive,
		sqlite,
		pcap,
		aes,
		sweep,
		wall,
		chi,
		rs,
		audio,
		spectrogram,
		pixelError,
		audioError,
		nested: {
			roots: top.children,
			analysed: context.childrenAnalysed,
			skipped: countSkipped(top) + context.unlisted,
			expandedBytes: context.expandedBytes,
			capped: context.capped,
			unlisted: context.unlisted
		},
		gif
	};
}

async function requestPlane(id: number, channel: number, bit: number): Promise<AnalysisResponse> {
	await ready;
	if (!cached?.image) throw new Error('No decoded image is loaded.');

	return {
		id,
		status: 'plane',
		channel,
		bit,
		pixels: cached.image.plane(channel, bit)
	};
}

/** The whole stream for one combination, not the preview the sweep quoted. */
const EXTRACT_LIMIT = 1 << 20;

async function extract(
	id: number,
	channels: string,
	bit: number,
	msbFirst: boolean,
	columnMajor: boolean
): Promise<AnalysisResponse> {
	await ready;
	if (!cached?.image) throw new Error('No decoded image is loaded.');

	return {
		id,
		status: 'extract',
		label: `${channels} · bit ${bit} · ${msbFirst ? 'msb' : 'lsb'} first${columnMajor ? ' · by column' : ''}`,
		bytes: cached.image.lsb_extract(channels, bit, msbFirst, columnMajor, EXTRACT_LIMIT)
	};
}

/** The held file with a repaired IHDR, handed back to be analysed like any other. */
async function patchIhdr(
	id: number,
	name: string,
	width: number,
	height: number
): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No file is loaded.');
	return { id, status: 'patched', name, bytes: png_patch_ihdr(cached.bytes, width, height) };
}

/** Mantis. The only request that carries no file: a string is the whole subject. */
async function peelText(id: number, text: string, flagTags: string): Promise<AnalysisResponse> {
	await ready;

	const bytes = new TextEncoder().encode(text);
	const peel = await peelWithCompression(bytes, flagTags);

	return {
		id,
		status: 'peel',
		input: text,
		peel,
		rsa: looksLikeRsa(text) ? attack(text) : null
	};
}

async function extractPalette(id: number, msbFirst: boolean): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No file is loaded.');

	return {
		id,
		status: 'extract',
		label: `palette indices · ${msbFirst ? 'msb' : 'lsb'} first`,
		bytes: palette_extract(cached.bytes, cached.inflated, msbFirst, EXTRACT_LIMIT)
	};
}

async function extractJpeg(
	id: number,
	includeDc: boolean,
	msbFirst: boolean
): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No file is loaded.');

	return {
		id,
		status: 'extract',
		label: `coefficients${includeDc ? ' with DC' : ''} · ${msbFirst ? 'msb' : 'lsb'} first`,
		bytes: jpeg_stego_extract(cached.bytes, includeDc, msbFirst, EXTRACT_LIMIT)
	};
}

async function extractAudio(
	id: number,
	label: string,
	channelIndex: number | null,
	bit: number,
	msbFirst: boolean
): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No file is loaded.');

	return {
		id,
		status: 'extract',
		label: `${label} · bit ${bit} · ${msbFirst ? 'msb' : 'lsb'} first`,
		// Rust takes a negative index to mean every channel interleaved, since
		// wasm-bindgen has no Option<usize> across the boundary.
		bytes: wav_lsb_extract(cached.bytes, channelIndex ?? -1, bit, msbFirst, EXTRACT_LIMIT)
	};
}

async function applyKey(
	id: number,
	text: string,
	key: string,
	flagTags: string
): Promise<AnalysisResponse> {
	await ready;

	return {
		id,
		status: 'keyed',
		key,
		attempts: JSON.parse(
			mantis_with_key_for_tags(new TextEncoder().encode(text), key, flagTags)
		) as KeyAttempt[]
	};
}

/** Packed Mantis pass: returns u32 LE JSON length + JSON + exact result bytes. */
async function mantisPackedPass(
	bytes: Uint8Array,
	flagTags: string,
	remainingDepth: number
): Promise<{ json: PeelResult; tail: Uint8Array }> {
	await ready;
	const packed = mantis_packed_pass(bytes, flagTags, remainingDepth);
	const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
	const jsonLen = view.getUint32(0, true);
	const jsonBytes = packed.subarray(4, 4 + jsonLen);
	const tail = packed.subarray(4 + jsonLen);
	const json = JSON.parse(new TextDecoder().decode(jsonBytes)) as PeelResult;
	return { json, tail };
}

/** Bounded gzip decompression of a paste, which rejects >1 MiB or an invalid header. */
async function inflateGzip(bytes: Uint8Array): Promise<Uint8Array> {
	if (!isGzip(bytes)) throw new Error('not a gzip stream');
	return boundedInflate('gzip', bytes);
}

/** Bounded zlib decompression of a paste, which validates CMF/FLG (mod-31, no preset dict). */
function inflateZlib(bytes: Uint8Array): Promise<Uint8Array> {
	assertZlibHeader(bytes);
	return boundedInflate('deflate', bytes);
}

/**
 * Alternating loop: Rust text peel -> platform decompress (gzip/zlib) -> repeat.
 * Shares the six-layer budget between text codecs and compression.
 * Returns the final peel with all steps preserved.
 */
function compressionFailure(
	encoding: 'gzip' | 'zlib',
	bytes: Uint8Array,
	error: unknown
): PeelStep {
	return {
		encoding,
		reason: `decompression failed: ${error instanceof Error ? error.message : String(error)}`,
		output: new TextDecoder('latin1').decode(bytes.subarray(0, 256)),
		compressed: true
	};
}

async function peelWithCompression(
	initialBytes: Uint8Array,
	flagTags: string
): Promise<PeelResult> {
	const MAX_LAYERS = 6;
	const seen = new SeenBytes<true>();

	let currentBytes = initialBytes;
	let remainingDepth = MAX_LAYERS;
	const allSteps: PeelStep[] = [];

	while (remainingDepth > 0) {
		// A layer that decodes to itself is a cycle, so stop and return what we have.
		if (seen.find(currentBytes)) break;
		seen.add(currentBytes, true);

		// Run packed Rust text peel with remaining depth
		const { json, tail } = await mantisPackedPass(currentBytes, flagTags, remainingDepth);

		// Each packed pass starts from this layer, so every returned step is new.
		allSteps.push(...json.steps);
		remainingDepth -= json.steps.length;
		currentBytes = tail.slice();

		if (remainingDepth <= 0) break;

		// Check if the exact tail looks like gzip or zlib.
		const encoding = compressionOf(currentBytes);
		let decompressed: Uint8Array | null = null;
		let compressionEncoding = '';

		if (encoding === 'gzip') {
			try {
				decompressed = await inflateGzip(currentBytes);
				compressionEncoding = 'gzip';
			} catch (error: unknown) {
				allSteps.push(compressionFailure('gzip', currentBytes, error));
				break;
			}
		} else if (encoding === 'zlib') {
			try {
				decompressed = await inflateZlib(currentBytes);
				compressionEncoding = 'zlib';
			} catch (error: unknown) {
				allSteps.push(compressionFailure('zlib', currentBytes, error));
				break;
			}
		}

		if (!decompressed) {
			// No compression detected — we're done
			break;
		}

		const { flags } = scanFlags(decompressed, flagTags);
		allSteps.push({
			encoding: compressionEncoding,
			reason:
				flags.length > 0
					? `flag shape, ${flags[0].text}`
					: `platform ${compressionEncoding} decompression`,
			output: new TextDecoder('latin1', { fatal: false }).decode(decompressed.subarray(0, 256)),
			compressed: true
		});

		remainingDepth -= 1;
		currentBytes = decompressed;

		if (remainingDepth <= 0) break;
	}

	const final = JSON.parse(peel_encodings_for_tags(currentBytes, flagTags)) as PeelResult;
	return {
		...final,
		depth: allSteps.length,
		steps: allSteps,
		result: new TextDecoder('utf-8', { fatal: false }).decode(currentBytes)
	};
}

function handle(request: AnalysisRequest): Promise<AnalysisResponse> {
	switch (request.kind) {
		case 'analyse':
			return analyseRoot(request.id, request.name, new Uint8Array(request.bytes), request.flagTags);
		case 'peel':
			return peelText(request.id, request.text, request.flagTags);
		case 'withKey':
			return applyKey(request.id, request.text, request.key, request.flagTags);
		case 'plane':
			return requestPlane(request.id, request.channel, request.bit);
		case 'extract':
			return extract(
				request.id,
				request.channels,
				request.bit,
				request.msbFirst,
				request.columnMajor
			);
		case 'extractPalette':
			return extractPalette(request.id, request.msbFirst);
		case 'extractJpeg':
			return extractJpeg(request.id, request.includeDc, request.msbFirst);
		case 'extractAudio':
			return extractAudio(
				request.id,
				request.label,
				request.channelIndex,
				request.bit,
				request.msbFirst
			);
		case 'patchIhdr':
			return patchIhdr(request.id, request.name, request.width, request.height);
	}
}

self.addEventListener('message', (event: MessageEvent<AnalysisRequest>) => {
	const request = event.data;

	handle(request)
		.then((response) => self.postMessage(response))
		.catch((error: unknown) => {
			const detail =
				error instanceof WebAssembly.RuntimeError
					? `The analysis core crashed on this file (${error.message}). That is a bug in Trawl.`
					: error instanceof Error
						? error.message
						: String(error);
			self.postMessage({
				id: request.id,
				status: 'error',
				name: request.kind === 'analyse' ? request.name : '',
				size: 0,
				detail
			} satisfies AnalysisResponse);
		});
});
