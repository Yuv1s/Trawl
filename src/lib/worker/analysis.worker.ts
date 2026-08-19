import init, {
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
	wav_structure
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
	WavStructure
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
