import init, {
	aes_probe,
	chi_square,
	file_survey,
	find_flags_for_tags,
	lsb_extract,
	lsb_sweep,
	plane,
	plane_wall,
	png_idat,
	png_palette,
	png_structure,
	jpeg_stego,
	jpeg_stego_extract,
	palette_extract,
	palette_stego,
	mantis_with_key_for_tags,
	mantis_packed_pass,
	peel_encodings_for_tags,
	rs_analysis,
	wav_lsb_extract,
	wav_lsb_sweep,
	wav_spectrogram,
	wav_structure,
	zip_structure,
	pdf_structure,
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
	NestedAnalysis,
	NestedArtifact,
	PaletteStego,
	PdfStructure,
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
	AesSolved
} from './protocol';
import { isWavError } from './protocol';
import { assertZlibHeader, boundedInflate, compressionOf, fingerprint, isGzip } from './decompress';

const ready = init();

const SWEEP_BYTES = 4096;
const THUMB_WIDTH = 220;
const CHI_STEPS = 64;

/** 1024 samples is the usual compromise: fine enough in time to read letters,
 *  fine enough in frequency to keep them from smearing together. */
const FFT_WINDOW = 1024;
const SPECTROGRAM_WIDTH = 900;
const CHI_STEPS_JPEG = 64;

/** Kept so a plane or extraction request does not re-send the whole file. */
let cached: { bytes: Uint8Array; inflated: Uint8Array } | null = null;

/** Fraction of bytes a person could read, to tell text content from binary. */
function printableRatio(bytes: Uint8Array): number {
	if (bytes.length === 0) return 0;
	let readable = 0;
	for (const b of bytes) {
		if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) readable += 1;
	}
	return readable / bytes.length;
}

/** Recursion limits — one per-root context so nested ZIPs and carved files share a budget. */
const RECURSION_MAX_DEPTH = 3; // below the root file
const RECURSION_MAX_CHILDREN = 32; // total children analysed across the tree
const RECURSION_PER_CHILD_LIMIT = 1 << 20; // 1 MiB per child (decompressed or carved)
const RECURSION_AGGREGATE_LIMIT = 8 << 20; // 8 MiB aggregate bytes expanded
const ZIP_TEXT_PREVIEW = 8192;

/** Deterministic fingerprint for dedup: first 64 bytes + last 64 bytes + length. */
async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
	return boundedInflate('deflate', bytes, RECURSION_PER_CHILD_LIMIT);
}

/** Raw deflate, with no zlib wrapper, which is how a ZIP stores each entry. */
function inflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
	return boundedInflate('deflate-raw', bytes, RECURSION_PER_CHILD_LIMIT);
}

/** Bounded gzip decompression — rejects >1 MiB or invalid header. */
async function inflateGzip(bytes: Uint8Array): Promise<Uint8Array> {
	if (!isGzip(bytes)) throw new Error('not a gzip stream');
	return boundedInflate('gzip', bytes, RECURSION_PER_CHILD_LIMIT);
}

/** Bounded zlib decompression — validates CMF/FLG (mod-31, no preset dict). */
function inflateZlib(bytes: Uint8Array): Promise<Uint8Array> {
	assertZlibHeader(bytes);
	return boundedInflate('deflate', bytes, RECURSION_PER_CHILD_LIMIT);
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

/** Only PNG hands its pixel data to a platform inflate; the rest carry their own. */
async function pixelInput(bytes: Uint8Array, isPng: boolean): Promise<Uint8Array> {
	return isPng ? inflate(png_idat(bytes)) : new Uint8Array();
}

/**
 * Fills in the text of compressed chunks.
 *
 * Rust locates the zlib stream but does not inflate it, because inflate is a
 * platform call. Reporting "content unread" was honest and useless; a flag can
 * sit in a zTXt chunk indefinitely.
 */
async function inflateTextChunks(
	bytes: Uint8Array,
	structure: Structure,
	flagTags: string
): Promise<void> {
	for (const chunk of structure.text) {
		if (!chunk.compressed || chunk.payloadLength === 0) continue;

		try {
			const stream = bytes.subarray(chunk.payloadOffset, chunk.payloadOffset + chunk.payloadLength);
			const raw = await inflate(stream);
			chunk.text = new TextDecoder('utf-8', { fatal: false }).decode(raw);
			chunk.compressed = false;

			// The byte-level scan ran before this text existed, so anything hiding
			// in a compressed chunk is only visible now.
			for (const found of JSON.parse(find_flags_for_tags(raw, flagTags)) as Found[]) {
				structure.flags.push({
					offset: chunk.payloadOffset,
					text: found.text,
					region: `inside ${chunk.kind}, after inflating`,
					credible: true
				});
			}
		} catch (error: unknown) {
			chunk.error = error instanceof Error ? error.message : String(error);
		}
	}
}

/**
 * Inflates every FlateDecode stream a PDF's objects carry, and flag-scans
 * the result.
 *
 * Rust locates the stream but does not decompress it, for the same reason
 * `inflateTextChunks` does not: inflate is a platform call. A flag or a
 * signature living inside a compressed stream is invisible to the raw
 * byte-level survey, which runs before any of this, so this is the only
 * place it is ever found.
 */
async function inflatePdfStreams(
	bytes: Uint8Array,
	pdf: PdfStructure,
	flagTags: string
): Promise<void> {
	for (const object of pdf.objects) {
		const stream = object.stream;
		if (!stream || stream.filter !== 'FlateDecode' || stream.length === 0) continue;

		try {
			const packed = bytes.subarray(stream.offset, stream.offset + stream.length);
			const raw = await inflate(packed);
			stream.text = new TextDecoder('utf-8', { fatal: false }).decode(raw);

			const found = JSON.parse(find_flags_for_tags(raw, flagTags)) as Found[];
			if (found.length > 0) object.flags = found.map((f) => f.text);
		} catch (error: unknown) {
			stream.error = error instanceof Error ? error.message : String(error);
		}
	}
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

/** Context shared by the recursive walk, so budgets are global and dedupe works. */
class RecursionContext {
	seen = new Map<string, string>(); // fingerprint -> stable id
	childrenAnalysed = 0;
	expandedBytes = 0;
	capped = false;

	/** Reserve budget for a child; returns false if any limit is hit. */
	tryReserve(childBytes: number): boolean {
		if (this.capped) return false;
		if (this.childrenAnalysed >= RECURSION_MAX_CHILDREN) {
			this.capped = true;
			return false;
		}
		if (childBytes > RECURSION_PER_CHILD_LIMIT) return false;
		if (this.expandedBytes + childBytes > RECURSION_AGGREGATE_LIMIT) {
			this.capped = true;
			return false;
		}
		this.childrenAnalysed += 1;
		this.expandedBytes += childBytes;
		return true;
	}

	/** Check if already seen; if so return the existing id. Otherwise register and return null. */
	checkDuplicate(bytes: Uint8Array): string | null {
		const fp = fingerprint(bytes);
		const existing = this.seen.get(fp);
		if (existing) return existing;
		return null;
	}

	register(bytes: Uint8Array, id: string): void {
		this.seen.set(fingerprint(bytes), id);
	}
}

/**
 * Runs the full detector set on a file and returns a compact summary.
 * Summary mode skips plane-wall thumbnails and spectrogram pixels.
 */
async function analyseInternal(
	id: number,
	name: string,
	bytes: Uint8Array,
	flagTags: string,
	context: RecursionContext,
	depth: number,
	sourceKind: 'zip' | 'carved',
	sourceOffset: number,
	parentOrigin: string
): Promise<NestedArtifact> {
	const stableId = `${sourceKind}-${sourceOffset}-${depth}`;
	const origin = parentOrigin ? `${parentOrigin} / ${name}` : name;

	// Check duplicate first
	const existing = context.checkDuplicate(bytes);
	if (existing) {
		return {
			id: stableId,
			name,
			source: sourceKind,
			offset: sourceOffset,
			format: 'duplicate',
			size: bytes.length,
			depth,
			status: 'skipped',
			reason: `duplicate of ${existing}`,
			findings: [],
			children: []
		};
	}

	const survey = JSON.parse(file_survey(bytes)) as Survey;
	const walked = JSON.parse(png_structure(bytes)) as Structure;
	const structure = walked.signature ? walked : null;

	if (structure) await inflateTextChunks(bytes, structure, flagTags);

	const wav = JSON.parse(wav_structure(bytes)) as WavStructure | WavError | null;
	const zip = JSON.parse(zip_structure(bytes)) as ZipArchive | null;

	const aes = JSON.parse(aes_probe(withInflatedText(bytes, structure))) as AesSolved[];
	const jpeg = JSON.parse(jpeg_stego(bytes, SWEEP_BYTES, CHI_STEPS_JPEG)) as
		JpegStego | JpegError | null;

	let sweep: Sweep | null = null;
	let chi: ChiSquare | null = null;
	let rs: RsAnalysis | null = null;
	let paletteStego: PaletteStego | null = null;
	let audio: AudioSweep | null = null;

	let inflated: Uint8Array = new Uint8Array();
	let hasPixels = false;

	try {
		inflated = await pixelInput(bytes, structure !== null);
		hasPixels = true;
	} catch {
		// pixelInput errors are not propagated in recursive analysis
	}

	if (hasPixels) {
		try {
			if (structure) {
				structure.palette = JSON.parse(png_palette(bytes, inflated)) as Structure['palette'];
			}

			paletteStego = JSON.parse(palette_stego(bytes, inflated, SWEEP_BYTES)) as PaletteStego | null;

			sweep = JSON.parse(lsb_sweep(bytes, inflated, SWEEP_BYTES)) as Sweep;
			chi = JSON.parse(chi_square(bytes, inflated, CHI_STEPS)) as ChiSquare;
			rs = JSON.parse(rs_analysis(bytes, inflated)) as RsAnalysis;
		} catch {
			// Pixel detectors failed; leave them null
		}
	}

	if (wav && !isWavError(wav)) {
		try {
			audio = JSON.parse(wav_lsb_sweep(bytes, SWEEP_BYTES)) as AudioSweep;
		} catch {
			// Audio LSB failed; leave null
		}
		// Skip spectrogram in recursive analysis to keep summaries compact
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
	if (survey.format === 'GIF image') {
		try {
			const json = gif_frame_analysis(bytes, flagTags, SWEEP_BYTES, CHI_STEPS);
			const gif = normaliseGifAnalysis(JSON.parse(json)) as GifAnalysis;
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
		} catch {
			// If the export fails, leave gifFindings empty
		}
	}

	const artifact: NestedArtifact = {
		id: stableId,
		name,
		source: sourceKind,
		offset: sourceOffset,
		format,
		size: bytes.length,
		depth,
		status: 'analysed',
		findings: [...findings, ...gifFindings],
		children: []
	};

	context.register(bytes, stableId);

	// Recurse into ZIP entries
	if (zip && depth < RECURSION_MAX_DEPTH) {
		for (const entry of zip.entries) {
			if (entry.dataOffset === null || entry.encrypted || entry.compressed === 0) continue;
			if (entry.method !== 'stored' && entry.method !== 'deflate') continue;
			if (entry.uncompressed > RECURSION_PER_CHILD_LIMIT) continue;

			const end = entry.dataOffset + entry.compressed;
			if (end > bytes.length) continue;

			if (!context.tryReserve(entry.uncompressed)) {
				artifact.children.push({
					id: `${sourceKind}-${entry.offset}-${depth + 1}`,
					name: entry.name,
					source: 'zip',
					offset: entry.offset,
					format: 'skipped',
					size: entry.uncompressed,
					depth: depth + 1,
					status: 'skipped',
					reason: 'recursion budget exhausted',
					findings: [],
					children: []
				});
				continue;
			}

			try {
				const packed = bytes.subarray(entry.dataOffset, end);
				const raw = entry.method === 'deflate' ? await inflateRaw(packed) : packed;

				// Validate inflated size
				if (raw.length > entry.uncompressed) {
					artifact.children.push({
						id: `${sourceKind}-${entry.offset}-${depth + 1}`,
						name: entry.name,
						source: 'zip',
						offset: entry.offset,
						format: 'error',
						size: raw.length,
						depth: depth + 1,
						status: 'error',
						reason: 'decompressed size exceeds declared',
						findings: [],
						children: []
					});
					continue;
				}

				const child = await analyseInternal(
					id,
					entry.name,
					raw,
					flagTags,
					context,
					depth + 1,
					'zip',
					entry.offset,
					origin
				);
				artifact.children.push(child);
			} catch (error: unknown) {
				artifact.children.push({
					id: `${sourceKind}-${entry.offset}-${depth + 1}`,
					name: entry.name,
					source: 'zip',
					offset: entry.offset,
					format: 'error',
					size: entry.uncompressed,
					depth: depth + 1,
					status: 'error',
					reason: error instanceof Error ? error.message : String(error),
					findings: [],
					children: []
				});
			}
		}
	}

	// Recurse into magic-carved embedded files
	if (depth < RECURSION_MAX_DEPTH) {
		for (const hit of survey.magic) {
			if (!hit.embedded) continue;
			if (hit.offset + hit.length > bytes.length) continue;

			// Only recurse into formats we can actually decode
			const slice = bytes.subarray(hit.offset, hit.offset + hit.length);
			if (!canRecurse(hit.label)) continue;

			if (!context.tryReserve(hit.length)) {
				artifact.children.push({
					id: `carved-${hit.offset}-${depth + 1}`,
					name: hit.label,
					source: 'carved',
					offset: hit.offset,
					format: 'skipped',
					size: hit.length,
					depth: depth + 1,
					status: 'skipped',
					reason: 'recursion budget exhausted',
					findings: [],
					children: []
				});
				continue;
			}

			try {
				const child = await analyseInternal(
					id,
					hit.label,
					slice,
					flagTags,
					context,
					depth + 1,
					'carved',
					hit.offset,
					origin
				);
				artifact.children.push(child);
			} catch (error: unknown) {
				artifact.children.push({
					id: `carved-${hit.offset}-${depth + 1}`,
					name: hit.label,
					source: 'carved',
					offset: hit.offset,
					format: 'error',
					size: hit.length,
					depth: depth + 1,
					status: 'error',
					reason: error instanceof Error ? error.message : String(error),
					findings: [],
					children: []
				});
			}
		}
	}

	// Suppress root ZIP magic hit when the same range is already covered by archive parsing
	if (depth === 0 && zip) {
		// The magic scan will find the ZIP entries again; suppress them if they're the same ranges
		artifact.children = artifact.children.filter((child) => {
			if (child.source !== 'carved') return true;
			// Check if this carved file overlaps a ZIP entry we already have
			const zipEntry = zip.entries.find(
				(e) =>
					e.dataOffset !== null &&
					child.offset >= e.dataOffset &&
					child.offset + child.size <= e.dataOffset + e.compressed
			);
			return !zipEntry;
		});
	}

	return artifact;
}

function canRecurse(label: string): boolean {
	// Only recurse into formats our decoder handles
	const supported = [
		'PNG image',
		'BMP image',
		'GIF image',
		'WAV audio',
		'JPEG image',
		'ZIP archive'
	];
	return supported.some((s) => label.includes(s));
}

async function analyseRoot(
	id: number,
	name: string,
	bytes: Uint8Array,
	flagTags: string
): Promise<{ response: AnalysisResponse; nested: NestedAnalysis; gif: GifAnalysis | null }> {
	await ready;

	const context = new RecursionContext();

	// Run the internal analyzer on the root file
	const rootArtifact = await analyseInternal(id, name, bytes, flagTags, context, 0, 'zip', 0, '');

	// Now run the FULL analysis for the root (with plane wall, spectrogram, etc.)
	// This is the original analyse logic but we need to merge findings
	const survey = JSON.parse(file_survey(bytes)) as Survey;
	const walked = JSON.parse(png_structure(bytes)) as Structure;
	const structure = walked.signature ? walked : null;

	if (structure) await inflateTextChunks(bytes, structure, flagTags);

	const wav = JSON.parse(wav_structure(bytes)) as WavStructure | WavError | null;
	const zip = JSON.parse(zip_structure(bytes)) as ZipArchive | null;
	if (zip) await inflateZipEntries(bytes, zip, flagTags);

	const pdf = JSON.parse(pdf_structure(bytes)) as PdfStructure | null;
	if (pdf) await inflatePdfStreams(bytes, pdf, flagTags);

	const aes = JSON.parse(aes_probe(withInflatedText(bytes, structure))) as AesSolved[];
	const jpeg = JSON.parse(jpeg_stego(bytes, SWEEP_BYTES, CHI_STEPS_JPEG)) as
		JpegStego | JpegError | null;

	let sweep: Sweep | null = null;
	let wall: PlaneWall | null = null;
	let chi: ChiSquare | null = null;
	let rs: RsAnalysis | null = null;
	let paletteStego: PaletteStego | null = null;
	let audio: AudioSweep | null = null;
	let spectrogram: Spectrogram | null = null;
	let pixelError: string | null = null;
	let audioError: string | null = null;

	let inflated: Uint8Array = new Uint8Array();
	try {
		inflated = await pixelInput(bytes, structure !== null);
	} catch (error: unknown) {
		pixelError = error instanceof Error ? error.message : String(error);
	}

	// Held whatever happened above
	cached = { bytes, inflated };

	if (pixelError === null) {
		try {
			if (structure) {
				structure.palette = JSON.parse(png_palette(bytes, inflated)) as Structure['palette'];
			}

			paletteStego = JSON.parse(palette_stego(bytes, inflated, SWEEP_BYTES)) as PaletteStego | null;

			sweep = JSON.parse(lsb_sweep(bytes, inflated, SWEEP_BYTES)) as Sweep;
			wall = readWall(plane_wall(bytes, inflated, THUMB_WIDTH));
			chi = JSON.parse(chi_square(bytes, inflated, CHI_STEPS)) as ChiSquare;
			rs = JSON.parse(rs_analysis(bytes, inflated)) as RsAnalysis;
		} catch (error: unknown) {
			pixelError = error instanceof Error ? error.message : String(error);
		}
	}

	if (wav && !isWavError(wav)) {
		try {
			audio = JSON.parse(wav_lsb_sweep(bytes, SWEEP_BYTES)) as AudioSweep;
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
			// If the export fails, leave gif as null
		}
	}

	// Build nested analysis envelope from the root artifact
	const nested: NestedAnalysis = {
		roots: rootArtifact.children,
		analysed: context.childrenAnalysed,
		skipped: countSkipped(rootArtifact),
		expandedBytes: context.expandedBytes,
		capped: context.capped
	};

	const response: AnalysisResponse = {
		id,
		status: 'ok',
		name,
		size: bytes.length,
		survey,
		structure,
		wav,
		jpeg,
		paletteStego,
		zip,
		pdf,
		aes,
		sweep,
		wall,
		chi,
		rs,
		audio,
		spectrogram,
		pixelError,
		audioError,
		nested,
		gif
	};

	return { response, nested, gif };
}

function countSkipped(artifact: NestedArtifact): number {
	let count = artifact.status === 'skipped' ? 1 : 0;
	for (const child of artifact.children) {
		count += countSkipped(child);
	}
	return count;
}

/** ZIP entry loop (non-recursive, keeps the old behavior for root-level display) */
async function inflateZipEntries(
	bytes: Uint8Array,
	zip: ZipArchive,
	flagTags: string
): Promise<void> {
	let opened = 0;
	for (const entry of zip.entries) {
		if (opened >= 40) break;
		if (entry.dataOffset === null || entry.encrypted || entry.compressed === 0) continue;
		if (entry.method !== 'stored' && entry.method !== 'deflate') continue;
		if (entry.uncompressed > 1 << 20) continue;

		const end = entry.dataOffset + entry.compressed;
		if (end > bytes.length) continue;
		opened += 1;

		try {
			const packed = bytes.subarray(entry.dataOffset, end);
			const raw = entry.method === 'deflate' ? await inflateRaw(packed) : packed;

			entry.bytes = raw.slice();
			entry.flags = (JSON.parse(find_flags_for_tags(raw, flagTags)) as Found[]).map((f) => f.text);
			if (printableRatio(raw) >= 0.85) {
				const text = new TextDecoder('utf-8', { fatal: false }).decode(
					raw.subarray(0, ZIP_TEXT_PREVIEW)
				);
				entry.text = raw.length > ZIP_TEXT_PREVIEW ? `${text}\n…` : text;
			}
		} catch (error: unknown) {
			entry.readError = error instanceof Error ? error.message : String(error);
		}
	}
}

async function requestPlane(id: number, channel: number, bit: number): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No decoded image is loaded.');

	return {
		id,
		status: 'plane',
		channel,
		bit,
		pixels: plane(cached.bytes, cached.inflated, channel, bit)
	};
}

/** The whole stream for one combination, not the preview the sweep quoted. */
const EXTRACT_LIMIT = 1 << 20;

async function extract(
	id: number,
	channels: string,
	bit: number,
	msbFirst: boolean
): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No decoded image is loaded.');

	return {
		id,
		status: 'extract',
		label: `${channels} · bit ${bit} · ${msbFirst ? 'msb' : 'lsb'} first`,
		bytes: lsb_extract(cached.bytes, cached.inflated, channels, bit, msbFirst, EXTRACT_LIMIT)
	};
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
		peel
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
	const seen = new Set<string>();

	let currentBytes = initialBytes;
	let remainingDepth = MAX_LAYERS;
	const allSteps: PeelStep[] = [];

	while (remainingDepth > 0) {
		// Fingerprint to detect cycles
		const fp = fingerprint(currentBytes);
		if (seen.has(fp)) {
			// Cycle detected — stop and return what we have
			break;
		}
		seen.add(fp);

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

		const flags = JSON.parse(find_flags_for_tags(decompressed, flagTags)) as Found[];
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

self.addEventListener('message', (event: MessageEvent<AnalysisRequest>) => {
	const request = event.data;

	const work =
		request.kind === 'peel'
			? peelText(request.id, request.text, request.flagTags)
			: request.kind === 'withKey'
				? applyKey(request.id, request.text, request.key, request.flagTags)
				: request.kind === 'plane'
					? requestPlane(request.id, request.channel, request.bit)
					: request.kind === 'extract'
						? extract(request.id, request.channels, request.bit, request.msbFirst)
						: request.kind === 'extractPalette'
							? extractPalette(request.id, request.msbFirst)
							: request.kind === 'extractJpeg'
								? extractJpeg(request.id, request.includeDc, request.msbFirst)
								: request.kind === 'extractAudio'
									? extractAudio(
											request.id,
											request.label,
											request.channelIndex,
											request.bit,
											request.msbFirst
										)
									: analyseRoot(
											request.id,
											request.name,
											new Uint8Array(request.bytes),
											request.flagTags
										).then((r) => r.response);

	work
		.then((response) => self.postMessage(response))
		.catch((error: unknown) => {
			const detail = error instanceof Error ? error.message : String(error);
			self.postMessage({
				id: request.id,
				status: 'error',
				name: request.kind === 'analyse' ? request.name : '',
				size: 0,
				detail
			} satisfies AnalysisResponse);
		});
});
