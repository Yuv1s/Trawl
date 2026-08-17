import init, { png_idat, png_lsb_sweep, png_structure } from '$lib/wasm/trawl_core';
import type { AnalysisRequest, AnalysisResponse, Structure, Sweep } from './protocol';

const ready = init();

const SWEEP_BYTES = 4096;

async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new DecompressionStream('deflate'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function analyse(id: number, name: string, bytes: Uint8Array): Promise<AnalysisResponse> {
	await ready;

	const structure = JSON.parse(png_structure(bytes)) as Structure;
	if (!structure.signature) {
		return {
			id,
			status: 'unsupported',
			name,
			size: bytes.length,
			detail: 'No PNG signature. Only PNG is supported so far.'
		};
	}

	let sweep: Sweep | null = null;
	let sweepError: string | null = null;

	// The container walk is worth returning even when pixels cannot be decoded,
	// so a broken IHDR or an interlaced image degrades rather than fails.
	try {
		const inflated = await inflate(png_idat(bytes));
		sweep = JSON.parse(png_lsb_sweep(bytes, inflated, SWEEP_BYTES)) as Sweep;
	} catch (error: unknown) {
		sweepError = error instanceof Error ? error.message : String(error);
	}

	return { id, status: 'ok', name, size: bytes.length, structure, sweep, sweepError };
}

self.addEventListener('message', (event: MessageEvent<AnalysisRequest>) => {
	const { id, name, bytes } = event.data;

	analyse(id, name, new Uint8Array(bytes))
		.then((response) => self.postMessage(response))
		.catch((error: unknown) => {
			const detail = error instanceof Error ? error.message : String(error);
			self.postMessage({
				id,
				status: 'error',
				name,
				size: bytes.byteLength,
				detail
			} satisfies AnalysisResponse);
		});
});
