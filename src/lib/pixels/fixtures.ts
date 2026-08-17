import { encodePng, encodePngDeflate, type ColorType } from './png-encode';

export type Fixture = {
	name: string;
	width: number;
	height: number;
	colorType: ColorType;
	channels: number;
	pixels: Uint8Array;
	bytes: Uint8Array<ArrayBuffer>;
};

/** Base value per channel, distinct so a channel reordering bug cannot hide. */
const BASE = [0x80, 0x60, 0xa0];

function xorshift32(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s ^= s << 13;
		s >>>= 0;
		s ^= s >>> 17;
		s ^= s << 5;
		s >>>= 0;
		return s;
	};
}

/**
 * Flat cover carrying a payload in bit 0 only. A payload spread across several
 * bits survives corruption that destroys bit 0 alone, which would pass a test
 * that should fail.
 *
 * @param alpha ignored for colorType 2
 */
export function buildFixture(
	name: string,
	colorType: ColorType,
	alpha = 255,
	width = 64,
	height = 64
): Fixture {
	const channels = colorType === 6 ? 4 : 3;
	const pixels = new Uint8Array(width * height * channels);
	const next = xorshift32(0x5eed);

	for (let i = 0; i < width * height; i++) {
		const o = i * channels;
		for (let c = 0; c < 3; c++) pixels[o + c] = (BASE[c] & 0xfe) | (next() & 1);
		if (channels === 4) pixels[o + 3] = alpha;
	}

	return {
		name,
		width,
		height,
		colorType,
		channels,
		pixels,
		bytes: encodePng(width, height, colorType, pixels)
	};
}

/** Same pixels, but Paeth-filtered and deflate-compressed the way a real encoder emits them. */
export async function compress(fixture: Fixture): Promise<Fixture> {
	return {
		...fixture,
		bytes: await encodePngDeflate(
			fixture.width,
			fixture.height,
			fixture.colorType,
			fixture.pixels,
			4
		)
	};
}

export const FIXTURES = {
	rgb: () => buildFixture('RGB, no alpha channel', 2),
	rgbaOpaque: () => buildFixture('RGBA, alpha 255', 6, 255),
	rgbaTranslucent: () => buildFixture('RGBA, alpha 128', 6, 128)
};
