import { describe, expect, it } from 'vitest';
import {
	attack,
	cubeRoot,
	fermat,
	gcd,
	invert,
	iroot,
	isqrt,
	known,
	looksLikeRsa,
	modpow,
	parse,
	sharedFactor,
	toBytes,
	wiener
} from './rsa';

/** Turns a message into the integer RSA actually encrypts. */
const toNumber = (text: string) =>
	BigInt(`0x${[...text].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')}`);

describe('arithmetic', () => {
	it('takes an integer square root', () => {
		expect(isqrt(0n)).toBe(0n);
		expect(isqrt(1n)).toBe(1n);
		expect(isqrt(144n)).toBe(12n);
		// Rounds down rather than to the nearest.
		expect(isqrt(145n)).toBe(12n);
		expect(isqrt(10n ** 40n)).toBe(10n ** 20n);
	});

	it('takes an integer nth root and says whether it was exact', () => {
		expect(iroot(27n, 3n)).toEqual({ root: 3n, exact: true });
		expect(iroot(28n, 3n)).toEqual({ root: 3n, exact: false });
		expect(iroot(1n << 100n, 2n).exact).toBe(true);
	});

	it('inverts a number against a modulus', () => {
		expect(invert(3n, 11n)).toBe(4n);
		expect((3n * 4n) % 11n).toBe(1n);
		// No inverse exists when they share a factor.
		expect(invert(4n, 8n)).toBeNull();
	});

	it('raises to a power under a modulus', () => {
		expect(modpow(2n, 10n, 1000n)).toBe(24n);
		expect(modpow(4n, 13n, 497n)).toBe(445n);
	});

	it('finds a common divisor', () => {
		expect(gcd(12n, 18n)).toBe(6n);
		expect(gcd(17n, 31n)).toBe(1n);
	});

	it('reads a message out of the number that carries it', () => {
		expect(toBytes(toNumber('hello'))).toBe('hello');
		// Padding sits in front and is stepped over.
		expect(toBytes(BigInt('0x0002ffff0068690000') >> 16n)).toContain('hi');
	});
});

describe('reading what was pasted', () => {
	it('takes the numbers however they were written', () => {
		const found = parse('n = 3233\ne = 17\nc = 2790');
		expect(found).toMatchObject({ n: 3233n, e: 17n, c: 2790n });
	});

	it('reads hex as readily as decimal', () => {
		expect(parse('n: 0xca1\ne: 0x11').n).toBe(3233n);
	});

	it('reads a second modulus for the shared factor check', () => {
		const found = parse('n = 100\nn = 200');
		expect(found.n).toBe(100n);
		expect(found.n2).toBe(200n);
	});

	it('knows when a string is not an RSA challenge', () => {
		expect(looksLikeRsa('the quick brown fox jumps over the lazy dog')).toBe(false);
		expect(looksLikeRsa('e = 3')).toBe(false);
		expect(looksLikeRsa('n = 3233')).toBe(false);
		expect(looksLikeRsa('n = 3233, e = 17')).toBe(true);
	});
});

describe('attacks', () => {
	it('decrypts when the factors were handed over', () => {
		// The textbook example: p = 61, q = 53, e = 17. Its usual d of 413 comes
		// from the Carmichael function; the inverse against (p-1)(q-1) is 2753,
		// and both decrypt correctly because they agree modulo 780.
		const found = known(parse('p = 61\nq = 53\ne = 17\nc = 2790'));

		expect(found?.attack).toBe('Factors were given');
		expect(found?.d).toBe(2753n);
		expect(modpow(2790n, found!.d!, 3233n)).toBe(65n);
	});

	it('factors a modulus small enough to divide out', () => {
		const found = known(parse('n = 3233\ne = 17\nc = 2790'));

		// Trial division reaches the smaller factor first, so which one is called
		// p is an accident of the search rather than a fact about the key.
		expect([found?.p, found?.q].sort()).toEqual([53n, 61n]);
		expect(found?.d).toBe(2753n);
	});

	it('undoes a small exponent with no padding', () => {
		// Cubed without ever reaching the modulus, so the modulus is irrelevant.
		const message = toNumber('attack at dawn');
		const found = cubeRoot({ c: message ** 3n, e: 3n });

		expect(found?.attack).toBe('Small exponent, no padding');
		expect(found?.message).toBe('attack at dawn');
	});

	it('leaves a properly wrapped small exponent alone', () => {
		// Cubed and reduced, so no exact cube root exists and this must decline.
		const n = 3233n;
		const c = modpow(65n, 3n, n);
		expect(cubeRoot({ c, e: 3n })).toBeNull();
	});

	it('splits primes chosen too close together', () => {
		// Two primes a few apart, which Fermat finds almost immediately.
		const p = 1000003n;
		const q = 1000033n;
		const found = fermat({ n: p * q, e: 65537n });

		expect(found?.attack).toBe('Fermat factorisation');
		expect([found?.p, found?.q].sort()).toEqual([q, p].sort());
	});

	it('recovers a message through Fermat', () => {
		const p = 1000003n;
		const q = 1000033n;
		const n = p * q;
		const e = 65537n;
		const d = invert(e, (p - 1n) * (q - 1n))!;
		const c = modpow(toNumber('hi'), e, n);

		const found = fermat({ n, e, c });
		expect(found?.message).toBe('hi');
		expect(found?.d).toBe(d);
	});

	it('breaks two keys that share a prime', () => {
		const shared = 1000003n;
		const first = shared * 1000033n;
		const second = shared * 1000037n;

		const found = sharedFactor({ n: first, n2: second, e: 65537n });
		expect(found?.attack).toBe('Shared prime between two keys');
		expect(found?.p).toBe(shared);
	});

	it('leaves two unrelated keys alone', () => {
		// Genuinely coprime. 3233 is 61 x 53 and 3599 is 59 x 61, which share a
		// prime, so they were the wrong pair to call unrelated.
		expect(sharedFactor({ n: 3233n, n2: 2021n, e: 17n })).toBeNull();
	});

	it('reconstructs a private exponent that was chosen too small', () => {
		// Wiener's condition: d below the fourth root of n over three.
		const p = 1000003n;
		const q = 1000033n;
		const n = p * q;
		const phi = (p - 1n) * (q - 1n);

		let d = 17n;
		while (gcd(d, phi) !== 1n) d += 2n;
		const e = invert(d, phi)!;

		const found = wiener({ n, e });
		expect(found?.attack).toBe("Wiener's attack");
		expect(found?.d).toBe(d);
	});

	it('gives up on a key with nothing wrong with it', () => {
		// Primes far apart, ordinary exponent, no small d. Nothing here works,
		// and inventing an answer would be worse than saying so.
		const p = 1000003n;
		const q = 15485863n;
		const n = p * q;

		expect(fermat({ n, e: 65537n })).toBeNull();
		expect(wiener({ n, e: 65537n })).toBeNull();
		expect(sharedFactor({ n, e: 65537n })).toBeNull();
		expect(cubeRoot({ n, e: 65537n })).toBeNull();
	});
});

describe('the whole run', () => {
	it('reports every attack that worked', () => {
		const report = attack('n = 3233\ne = 17\nc = 2790');

		expect(report.found.n).toBe(3233n);
		expect(report.recovered.length).toBeGreaterThan(0);
		expect(report.recovered[0].message).toBeDefined();
	});

	it('reports nothing on a string that is not a key', () => {
		const report = attack('the quick brown fox jumps over the lazy dog');
		expect(report.recovered).toEqual([]);
	});

	it('survives nonsense without throwing', () => {
		expect(() => attack('n = 0\ne = 0\nc = 0')).not.toThrow();
		expect(() => attack('n = 1\ne = 1')).not.toThrow();
		expect(() => attack('')).not.toThrow();
	});
});
