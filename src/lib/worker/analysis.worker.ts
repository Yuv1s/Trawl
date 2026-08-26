import init, {
	aes_probe,
	chi_square,
	file_survey,
	find_flags,
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
	mantis_with_key,
	peel_encodings,
	rs_analysis,
	wav_lsb_extract,
	wav_lsb_sweep,
	wav_spectrogram,
	wav_structure,
	zip_structure
} from '$lib/wasm/trawl_core';
import type {
	AnalysisRequest,
	AnalysisResponse,
	AudioSweep,
	ChiSquare,
	Found,
	JpegError,
	JpegStego,
	PaletteStego,
	KeyAttempt,
	PeelResult,
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

async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new DecompressionStream('deflate'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Raw deflate, with no zlib wrapper, which is how a ZIP stores each entry. */
async function inflateRaw(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new DecompressionStream('deflate-raw'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Fraction of bytes a person could read, to tell text content from binary. */
function printableRatio(bytes: Uint8Array): number {
	if (bytes.length === 0) return 0;
	let readable = 0;
	for (const b of bytes) {
		if ((b >= 0x20 && b <= 0x7e) || b === 9 || b === 10 || b === 13) readable += 1;
	}
	return readable / bytes.length;
}

/** Most entries to open, and the most of one to read, so an archive bomb cannot
 *  turn one dropped file into gigabytes of work. */
const ZIP_ENTRY_LIMIT = 40;
const ZIP_BYTE_LIMIT = 1 << 20;
const ZIP_TEXT_PREVIEW = 8192;

/**
 * Reads what each archive entry actually holds.
 *
 * The structure walk names the entries and where their data sits, but stops at
 * the compression. A flag inside `manifest.txt` is only visible once the entry
 * is inflated, so this does that and scans the result, the same move the text
 * chunks get. Stored entries are already plain; deflated ones go through the
 * platform's raw inflate.
 */
async function inflateZipEntries(bytes: Uint8Array, zip: ZipArchive): Promise<void> {
	let opened = 0;
	for (const entry of zip.entries) {
		if (opened >= ZIP_ENTRY_LIMIT) break;
		if (entry.dataOffset === null || entry.encrypted || entry.compressed === 0) continue;
		if (entry.method !== 'stored' && entry.method !== 'deflate') continue;
		if (entry.uncompressed > ZIP_BYTE_LIMIT) continue;

		const end = entry.dataOffset + entry.compressed;
		if (end > bytes.length) continue;
		opened += 1;

		try {
			const packed = bytes.subarray(entry.dataOffset, end);
			const raw = entry.method === 'deflate' ? await inflateRaw(packed) : packed;

			entry.flags = (JSON.parse(find_flags(raw)) as Found[]).map((f) => f.text);
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

function readWall(packed: Uint8Array): PlaneWall {
	const headerLength = new DataView(packed.buffer, packed.byteOffset, 4).getUint32(0, true);
	const json = new TextDecoder().decode(packed.subarray(4, 4 + headerLength));
	const meta = JSON.parse(json) as Omit<PlaneWall, 'thumbnails'>;

	return { ...meta, thumbnails: packed.slice(4 + headerLength) };
}

/**
 * Fills in the text of compressed chunks.
 *
 * Rust locates the zlib stream but does not inflate it, because inflate is a
 * platform call. Reporting "content unread" was honest and useless; a flag can
 * sit in a zTXt chunk indefinitely.
 */
async function inflateTextChunks(bytes: Uint8Array, structure: Structure): Promise<void> {
	for (const chunk of structure.text) {
		if (!chunk.compressed || chunk.payloadLength === 0) continue;

		try {
			const stream = bytes.subarray(chunk.payloadOffset, chunk.payloadOffset + chunk.payloadLength);
			const raw = await inflate(stream);
			chunk.text = new TextDecoder('utf-8', { fatal: false }).decode(raw);
			chunk.compressed = false;

			// The byte-level scan ran before this text existed, so anything hiding
			// in a compressed chunk is only visible now.
			for (const found of JSON.parse(find_flags(raw)) as Found[]) {
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

function readSpectrogram(packed: Uint8Array): Spectrogram {
	const headerLength = new DataView(packed.buffer, packed.byteOffset, 4).getUint32(0, true);
	const json = new TextDecoder().decode(packed.subarray(4, 4 + headerLength));
	const meta = JSON.parse(json) as Omit<Spectrogram, 'pixels'>;

	return { ...meta, pixels: packed.slice(4 + headerLength) };
}

/** Only PNG hands its pixel data to a platform inflate; the rest carry their own. */
async function pixelInput(bytes: Uint8Array, isPng: boolean): Promise<Uint8Array> {
	return isPng ? inflate(png_idat(bytes)) : new Uint8Array();
}

async function analyse(id: number, name: string, bytes: Uint8Array): Promise<AnalysisResponse> {
	await ready;

	// Byte-level analysis needs no format, so it runs on everything.
	const survey = JSON.parse(file_survey(bytes)) as Survey;
	const walked = JSON.parse(png_structure(bytes)) as Structure;
	const structure = walked.signature ? walked : null;

	if (structure) await inflateTextChunks(bytes, structure);

	const wav = JSON.parse(wav_structure(bytes)) as WavStructure | WavError | null;
	const zip = JSON.parse(zip_structure(bytes)) as ZipArchive | null;
	if (zip) await inflateZipEntries(bytes, zip);
	// The key and IV for a decryption can sit in a compressed text chunk, which
	// the raw bytes do not carry. Text chunks are inflated by now, so the probe
	// runs over the bytes plus that recovered text and can pair the two.
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

	// Compressed and float WAVs parse but have no low bit worth reading, so the
	// audio tools report why they stood down instead of vanishing.
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

	// The container walk is worth returning even when pixels cannot be decoded,
	// and the pixel tools run on any format with a decoder behind it.
	let inflated: Uint8Array = new Uint8Array();
	try {
		inflated = await pixelInput(bytes, structure !== null);
	} catch (error: unknown) {
		pixelError = error instanceof Error ? error.message : String(error);
	}

	// Held whatever happened above: an audio extraction needs the bytes, not the
	// pixels, and a WAV never gets past the decoder.
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

	return {
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
		aes,
		sweep,
		wall,
		chi,
		rs,
		audio,
		spectrogram,
		pixelError,
		audioError
	};
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
async function peelText(id: number, text: string): Promise<AnalysisResponse> {
	await ready;

	return {
		id,
		status: 'peel',
		input: text,
		peel: JSON.parse(peel_encodings(new TextEncoder().encode(text))) as PeelResult
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

async function applyKey(id: number, text: string, key: string): Promise<AnalysisResponse> {
	await ready;

	return {
		id,
		status: 'keyed',
		key,
		attempts: JSON.parse(mantis_with_key(new TextEncoder().encode(text), key)) as KeyAttempt[]
	};
}

self.addEventListener('message', (event: MessageEvent<AnalysisRequest>) => {
	const request = event.data;

	const work =
		request.kind === 'peel'
			? peelText(request.id, request.text)
			: request.kind === 'withKey'
				? applyKey(request.id, request.text, request.key)
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
									: analyse(request.id, request.name, new Uint8Array(request.bytes));

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
