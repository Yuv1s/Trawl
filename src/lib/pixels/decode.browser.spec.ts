import { describe, expect, it } from 'vitest';
import { decode, decodePng, decodeViaBrowser, type Raster } from './decode';
import { compress, FIXTURES, type Fixture } from './fixtures';

type Comparison = {
	samples: number;
	bitZeroMismatches: number;
	maxSampleDelta: number;
};

function compare(fixture: Fixture, raster: Raster): Comparison {
	const result: Comparison = {
		samples: fixture.width * fixture.height * 3,
		bitZeroMismatches: 0,
		maxSampleDelta: 0
	};

	for (let i = 0; i < fixture.width * fixture.height; i++) {
		for (let channel = 0; channel < 3; channel++) {
			const expected = fixture.pixels[i * fixture.channels + channel];
			const actual = raster.data[i * 4 + channel];
			if ((expected & 1) !== (actual & 1)) result.bitZeroMismatches++;
			result.maxSampleDelta = Math.max(result.maxSampleDelta, Math.abs(expected - actual));
		}
	}

	return result;
}

async function viaBrowser(fixture: Fixture): Promise<Comparison> {
	const blob = new Blob([fixture.bytes], { type: 'image/png' });
	const raster = await decodeViaBrowser(blob);

	expect(raster.width).toBe(fixture.width);
	expect(raster.height).toBe(fixture.height);

	return compare(fixture, raster);
}

describe('browser decode path', () => {
	it('preserves bit 0 for RGB with no alpha channel', async () => {
		const { bitZeroMismatches } = await viaBrowser(FIXTURES.rgb());
		expect(bitZeroMismatches).toBe(0);
	});

	it('preserves bit 0 for RGBA at alpha 255', async () => {
		const { bitZeroMismatches } = await viaBrowser(FIXTURES.rgbaOpaque());
		expect(bitZeroMismatches).toBe(0);
	});

	// Canvas backing stores are premultiplied. getImageData divides the alpha back
	// out, and the two roundings do not cancel. premultiplyAlpha: 'none' governs the
	// decode, not this readback, and no canvas flag disables it. Characterised, not
	// accepted: this is the measurement the Rust decoder exists to answer.
	it('destroys bit 0 for RGBA below alpha 255', async () => {
		const { samples, bitZeroMismatches, maxSampleDelta } = await viaBrowser(
			FIXTURES.rgbaTranslucent()
		);

		expect(bitZeroMismatches).toBeGreaterThan(samples * 0.2);
		expect(maxSampleDelta).toBeLessThanOrEqual(2);
	});
});

describe('exact decode path', () => {
	for (const build of Object.values(FIXTURES)) {
		it(`reproduces every sample of ${build().name}`, async () => {
			const fixture = await compress(build());
			const raster = await decodePng(fixture.bytes);

			expect(raster.width).toBe(fixture.width);
			expect(raster.height).toBe(fixture.height);
			expect(compare(fixture, raster)).toMatchObject({
				bitZeroMismatches: 0,
				maxSampleDelta: 0
			});

			if (fixture.channels === 4) {
				expect(Array.from(raster.data)).toEqual(Array.from(fixture.pixels));
			}
		});
	}

	it('reports what is wrong instead of returning corrupt pixels', async () => {
		const fixture = await compress(FIXTURES.rgb());
		const truncated = fixture.bytes.slice(0, 30);
		await expect(decodePng(truncated)).rejects.toThrow();
	});
});

describe('format routing', () => {
	it('sends PNG to the exact decoder', async () => {
		const fixture = await compress(FIXTURES.rgbaTranslucent());
		const raster = await decode(fixture.bytes, 'image/png');
		expect(compare(fixture, raster)).toMatchObject({ maxSampleDelta: 0 });
	});
});
