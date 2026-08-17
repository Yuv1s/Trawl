import init, { png_decode, png_dimensions, png_idat } from '$lib/wasm/trawl_core';

export type Raster = {
	width: number;
	height: number;
	data: Uint8ClampedArray;
};

const PNG_SIGNATURE = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

let wasm: Promise<unknown> | null = null;

function ready(): Promise<unknown> {
	wasm ??= init();
	return wasm;
}

export function isPng(file: Uint8Array): boolean {
	return PNG_SIGNATURE.every((byte, i) => file[i] === byte);
}

/** wasm-bindgen types its returns over ArrayBufferLike; this build has no shared memory. */
function fromWasm(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
	return bytes as Uint8Array<ArrayBuffer>;
}

async function inflate(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
	const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Exact decode. Inflate comes from the platform, everything that touches sample
 * values is ours, so no sample is rounded, premultiplied or colour-managed.
 */
export async function decodePng(file: Uint8Array<ArrayBuffer>): Promise<Raster> {
	await ready();

	const inflated = await inflate(fromWasm(png_idat(file)));
	const [width, height] = png_dimensions(file);

	return { width, height, data: new Uint8ClampedArray(png_decode(file, inflated)) };
}

/**
 * Browser decode. Fast and format-agnostic, but the canvas readback premultiplies
 * alpha, which destroys bit 0 on anything below alpha 255. Use it for formats the
 * Rust decoder does not handle yet, never for pixel analysis of translucent input.
 */
export async function decodeViaBrowser(blob: Blob): Promise<Raster> {
	const bitmap = await createImageBitmap(blob, {
		colorSpaceConversion: 'none',
		premultiplyAlpha: 'none'
	});

	try {
		const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
		const ctx = canvas.getContext('2d', { colorSpace: 'srgb', willReadFrequently: true });
		if (!ctx) throw new Error('2D canvas context unavailable');

		ctx.drawImage(bitmap, 0, 0);
		const image = ctx.getImageData(0, 0, bitmap.width, bitmap.height, { colorSpace: 'srgb' });
		return { width: image.width, height: image.height, data: image.data };
	} finally {
		bitmap.close();
	}
}

/** Routes to the exact decoder when the format allows it. */
export async function decode(file: Uint8Array<ArrayBuffer>, type = ''): Promise<Raster> {
	if (isPng(file)) return decodePng(file);
	return decodeViaBrowser(new Blob([file], { type }));
}
