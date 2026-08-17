import init, {
	file_survey,
	find_flags,
	png_chi_square,
	png_idat,
	png_lsb_extract,
	png_lsb_sweep,
	png_palette,
	png_plane,
	png_plane_wall,
	png_rs_analysis,
	png_structure
} from '$lib/wasm/trawl_core';
import type {
	AnalysisRequest,
	AnalysisResponse,
	ChiSquare,
	Found,
	PlaneWall,
	RsAnalysis,
	Structure,
	Survey,
	Sweep
} from './protocol';

const ready = init();

const SWEEP_BYTES = 4096;
const THUMB_WIDTH = 220;
const CHI_STEPS = 64;

/** Kept so a full-resolution plane request does not re-send the whole file. */
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

async function analyse(id: number, name: string, bytes: Uint8Array): Promise<AnalysisResponse> {
	await ready;

	// Byte-level analysis needs no format, so it runs on everything.
	const survey = JSON.parse(file_survey(bytes)) as Survey;
	const walked = JSON.parse(png_structure(bytes)) as Structure;
	const structure = walked.signature ? walked : null;

	if (!structure) {
		cached = null;
		return {
			id,
			status: 'ok',
			name,
			size: bytes.length,
			survey,
			structure: null,
			sweep: null,
			wall: null,
			chi: null,
			rs: null,
			pixelError: null
		};
	}

	let sweep: Sweep | null = null;
	let wall: PlaneWall | null = null;
	let chi: ChiSquare | null = null;
	let rs: RsAnalysis | null = null;
	let pixelError: string | null = null;

	// The container walk is worth returning even when pixels cannot be decoded,
	// so a broken IHDR or an interlaced image degrades rather than fails.
	await inflateTextChunks(bytes, structure);

	try {
		const inflated = await inflate(png_idat(bytes));
		cached = { bytes, inflated };

		const palette = JSON.parse(png_palette(bytes, inflated)) as Structure['palette'];
		structure.palette = palette ?? null;

		sweep = JSON.parse(png_lsb_sweep(bytes, inflated, SWEEP_BYTES)) as Sweep;
		wall = readWall(png_plane_wall(bytes, inflated, THUMB_WIDTH));
		chi = JSON.parse(png_chi_square(bytes, inflated, CHI_STEPS)) as ChiSquare;
		rs = JSON.parse(png_rs_analysis(bytes, inflated)) as RsAnalysis;
	} catch (error: unknown) {
		cached = null;
		pixelError = error instanceof Error ? error.message : String(error);
	}

	return {
		id,
		status: 'ok',
		name,
		size: bytes.length,
		survey,
		structure,
		sweep,
		wall,
		chi,
		rs,
		pixelError
	};
}

async function plane(id: number, channel: number, bit: number): Promise<AnalysisResponse> {
	await ready;
	if (!cached) throw new Error('No decoded image is loaded.');

	return {
		id,
		status: 'plane',
		channel,
		bit,
		pixels: png_plane(cached.bytes, cached.inflated, channel, bit)
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
		bytes: png_lsb_extract(cached.bytes, cached.inflated, channels, bit, msbFirst, EXTRACT_LIMIT)
	};
}

self.addEventListener('message', (event: MessageEvent<AnalysisRequest>) => {
	const request = event.data;

	const work =
		request.kind === 'plane'
			? plane(request.id, request.channel, request.bit)
			: request.kind === 'extract'
				? extract(request.id, request.channels, request.bit, request.msbFirst)
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
			return;
		});
});
