export type ColorType = 2 | 6;

const SIGNATURE = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

const CRC_TABLE = /* @__PURE__ */ (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

function crc32(bytes: Uint8Array): number {
	let c = 0xffffffff;
	for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}

function adler32(bytes: Uint8Array): number {
	let a = 1;
	let b = 0;
	for (let i = 0; i < bytes.length; i++) {
		a = (a + bytes[i]) % 65521;
		b = (b + a) % 65521;
	}
	return ((b << 16) | a) >>> 0;
}

function chunk(type: string, data: Uint8Array): Uint8Array {
	const out = new Uint8Array(12 + data.length);
	const view = new DataView(out.buffer);
	view.setUint32(0, data.length);
	for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
	out.set(data, 8);
	view.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)));
	return out;
}

/** zlib stream using deflate stored blocks, so no compressor is involved. */
function deflateStored(raw: Uint8Array): Uint8Array {
	const MAX_BLOCK = 0xffff;
	const blocks = Math.max(1, Math.ceil(raw.length / MAX_BLOCK));
	const out = new Uint8Array(2 + blocks * 5 + raw.length + 4);
	let p = 0;

	out[p++] = 0x78; // CM=8, CINFO=7
	out[p++] = 0x01; // FCHECK making the 2-byte header divisible by 31

	for (let i = 0; i < blocks; i++) {
		const start = i * MAX_BLOCK;
		const len = Math.min(MAX_BLOCK, raw.length - start);
		out[p++] = i === blocks - 1 ? 1 : 0;
		out[p++] = len & 0xff;
		out[p++] = (len >>> 8) & 0xff;
		out[p++] = ~len & 0xff;
		out[p++] = (~len >>> 8) & 0xff;
		out.set(raw.subarray(start, start + len), p);
		p += len;
	}

	const sum = adler32(raw);
	out[p++] = (sum >>> 24) & 0xff;
	out[p++] = (sum >>> 16) & 0xff;
	out[p++] = (sum >>> 8) & 0xff;
	out[p++] = sum & 0xff;

	return out.subarray(0, p);
}

function paeth(a: number, b: number, c: number): number {
	const p = a + b - c;
	const pa = Math.abs(p - a);
	const pb = Math.abs(p - b);
	const pc = Math.abs(p - c);
	if (pa <= pb && pa <= pc) return a;
	return pb <= pc ? b : c;
}

/** Applies one filter type to every row, producing the stream PNG stores. */
function filterRows(
	pixels: Uint8Array,
	stride: number,
	bpp: number,
	height: number,
	filterType: number
): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array((stride + 1) * height);

	for (let y = 0; y < height; y++) {
		out[y * (stride + 1)] = filterType;
		for (let i = 0; i < stride; i++) {
			const cur = pixels[y * stride + i];
			const a = i >= bpp ? pixels[y * stride + i - bpp] : 0;
			const b = y > 0 ? pixels[(y - 1) * stride + i] : 0;
			const c = y > 0 && i >= bpp ? pixels[(y - 1) * stride + i - bpp] : 0;

			const predictor =
				filterType === 0
					? 0
					: filterType === 1
						? a
						: filterType === 2
							? b
							: filterType === 3
								? (a + b) >> 1
								: paeth(a, b, c);

			out[y * (stride + 1) + 1 + i] = (cur - predictor) & 0xff;
		}
	}

	return out;
}

async function deflate(raw: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
	const stream = new Blob([raw]).stream().pipeThrough(new CompressionStream('deflate'));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Real deflate and a real row filter, so a decoder is exercised the way an actual
 * encoder would exercise it.
 */
export async function encodePngDeflate(
	width: number,
	height: number,
	colorType: ColorType,
	pixels: Uint8Array,
	filterType = 4
): Promise<Uint8Array<ArrayBuffer>> {
	const channels = colorType === 6 ? 4 : 3;
	const stride = width * channels;
	const filtered = filterRows(pixels, stride, channels, height, filterType);
	return assemble(width, height, colorType, await deflate(filtered));
}

/** @param pixels packed samples, no per-row filter byte */
export function encodePng(
	width: number,
	height: number,
	colorType: ColorType,
	pixels: Uint8Array
): Uint8Array<ArrayBuffer> {
	const channels = colorType === 6 ? 4 : 3;
	const stride = width * channels;
	if (pixels.length !== stride * height) {
		throw new Error(`expected ${stride * height} samples, received ${pixels.length}`);
	}

	const raw = new Uint8Array((stride + 1) * height);
	for (let y = 0; y < height; y++) {
		raw[y * (stride + 1)] = 0; // filter type None
		raw.set(pixels.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1);
	}

	return assemble(width, height, colorType, deflateStored(raw));
}

function assemble(
	width: number,
	height: number,
	colorType: ColorType,
	idat: Uint8Array
): Uint8Array<ArrayBuffer> {
	const ihdr = new Uint8Array(13);
	const view = new DataView(ihdr.buffer);
	view.setUint32(0, width);
	view.setUint32(4, height);
	ihdr[8] = 8;
	ihdr[9] = colorType;

	const parts = [
		SIGNATURE,
		chunk('IHDR', ihdr),
		chunk('IDAT', idat),
		chunk('IEND', new Uint8Array(0))
	];

	const file = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
	let offset = 0;
	for (const part of parts) {
		file.set(part, offset);
		offset += part.length;
	}
	return file;
}
