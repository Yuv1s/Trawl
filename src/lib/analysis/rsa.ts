/**
 * RSA weaknesses that turn up in competitions.
 *
 * The only part of Trawl written in TypeScript rather than Rust, because it
 * needs arbitrary-precision integers and the platform already has them. `BigInt`
 * is no more a dependency than `Math.sqrt` is.
 *
 * None of these attacks break RSA. Each one breaks a key that was built wrong,
 * which is what a competition hands you: primes chosen too close together, an
 * exponent too small for the message, a private exponent small enough to be
 * reconstructed from the public one. A correctly generated key defeats every
 * attack here and Trawl says so rather than grinding.
 */

/** What was pulled out of the pasted text. */
export type Parameters = {
	n?: bigint;
	e?: bigint;
	c?: bigint;
	d?: bigint;
	p?: bigint;
	q?: bigint;
	/** A second modulus, which makes a shared-factor check possible. */
	n2?: bigint;
};

export type Recovery = {
	/** Which weakness this was, in words. */
	attack: string;
	/** What made it work, so the reader can judge the claim. */
	because: string;
	p?: bigint;
	q?: bigint;
	d?: bigint;
	/** The decrypted message, when there was a ciphertext to decrypt. */
	message?: string;
};

const ZERO = 0n;
const ONE = 1n;
const TWO = 2n;

/** Integer square root, by Newton's method. */
export function isqrt(value: bigint): bigint {
	if (value < ZERO) throw new RangeError('no square root of a negative');
	if (value < TWO) return value;

	let guess = value;
	let next = (guess + ONE) / TWO;
	while (next < guess) {
		guess = next;
		next = (guess + value / guess) / TWO;
	}
	return guess;
}

/** Integer nth root, and whether it was exact. */
export function iroot(value: bigint, n: bigint): { root: bigint; exact: boolean } {
	if (value < ZERO) throw new RangeError('no root of a negative');
	if (value < TWO) return { root: value, exact: true };

	// Bisect rather than iterate Newton, which is fiddly to get right for
	// arbitrary n and only needs to run a few hundred times here.
	let low = ONE;
	let high = ONE << BigInt(Math.ceil((value.toString(2).length + 1) / Number(n)) + 1);

	while (low < high) {
		const middle = (low + high + ONE) / TWO;
		if (middle ** n <= value) low = middle;
		else high = middle - ONE;
	}

	return { root: low, exact: low ** n === value };
}

export function gcd(a: bigint, b: bigint): bigint {
	let x = a < ZERO ? -a : a;
	let y = b < ZERO ? -b : b;
	while (y) [x, y] = [y, x % y];
	return x;
}

/** Modular inverse by the extended Euclidean algorithm. */
export function invert(value: bigint, modulus: bigint): bigint | null {
	let [old_r, r] = [value % modulus, modulus];
	let [old_s, s] = [ONE, ZERO];

	while (r !== ZERO) {
		const quotient = old_r / r;
		[old_r, r] = [r, old_r - quotient * r];
		[old_s, s] = [s, old_s - quotient * s];
	}

	if (old_r !== ONE) return null;
	return ((old_s % modulus) + modulus) % modulus;
}

export function modpow(base: bigint, exponent: bigint, modulus: bigint): bigint {
	let result = ONE;
	let b = base % modulus;
	let e = exponent;

	while (e > ZERO) {
		if (e & ONE) result = (result * b) % modulus;
		b = (b * b) % modulus;
		e >>= ONE;
	}

	return result;
}

/** A big integer as the bytes it encodes, which is how RSA carries a message. */
export function toBytes(value: bigint): string {
	let hex = value.toString(16);
	if (hex.length % 2) hex = `0${hex}`;

	const bytes: number[] = [];
	for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));

	// Leading zeros and PKCS padding both sit in front of the message.
	const start = bytes.findIndex((b) => b >= 0x20 && b < 0x7f);
	const printable = start < 0 ? bytes : bytes.slice(start);

	return printable.map((b) => String.fromCharCode(b)).join('');
}

/**
 * Reads whatever the challenge handed you.
 *
 * People paste these in every shape there is: `n = 1234`, `n: 0x4d2`, one per
 * line, or as a Python dict. Rather than demand a format, this looks for each
 * name and takes the number after it.
 */
export function parse(text: string): Parameters {
	const found: Parameters = {};

	const read = (name: string, skip = 0): bigint | undefined => {
		const pattern = new RegExp(`\\b${name}\\s*[=:]\\s*(0x[0-9a-fA-F]+|\\d+)`, 'g');
		const matches = [...text.matchAll(pattern)];
		const match = matches[skip];
		if (!match) return undefined;

		const raw = match[1];
		return raw.startsWith('0x') ? BigInt(raw) : BigInt(raw);
	};

	found.n = read('n');
	found.n2 = read('n', 1);
	found.e = read('e');
	found.c = read('c') ?? read('ct') ?? read('ciphertext');
	found.d = read('d');
	found.p = read('p');
	found.q = read('q');

	return found;
}

/** Decrypts once the factors are known. */
function finish(
	attack: string,
	because: string,
	p: bigint,
	q: bigint,
	e: bigint,
	c?: bigint
): Recovery {
	const phi = (p - ONE) * (q - ONE);
	const d = invert(e, phi);

	return {
		attack,
		because,
		p,
		q,
		d: d ?? undefined,
		message: d && c !== undefined ? toBytes(modpow(c, d, p * q)) : undefined
	};
}

/**
 * A message small enough that raising it to e never wrapped the modulus.
 *
 * With e of 3 and no padding, the ciphertext is just the message cubed. Taking
 * the cube root undoes it, and the modulus never enters into it.
 */
export function cubeRoot(found: Parameters): Recovery | null {
	const { c, e } = found;
	if (c === undefined || e === undefined || e > 64n) return null;

	const { root, exact } = iroot(c, e);
	if (!exact) return null;

	return {
		attack: 'Small exponent, no padding',
		because: `The ciphertext is an exact ${e}th power, so the message never wrapped the modulus`,
		message: toBytes(root)
	};
}

/** Longest Fermat runs before giving up. Close primes fall in a handful. */
const FERMAT_ROUNDS = 100_000;

/**
 * Primes picked too close together.
 *
 * If p and q are near each other they sit either side of the square root of n,
 * so counting up from there finds them fast. Properly generated primes are
 * nowhere near, and this gives up.
 */
export function fermat(found: Parameters): Recovery | null {
	const { n, e } = found;
	if (n === undefined || n <= ONE || !(n & ONE)) return null;

	let a = isqrt(n);
	if (a * a < n) a += ONE;

	for (let round = 0; round < FERMAT_ROUNDS; round++) {
		const b2 = a * a - n;
		const b = isqrt(b2);

		if (b * b === b2) {
			const p = a + b;
			const q = a - b;
			if (q > ONE && p * q === n) {
				return finish(
					'Fermat factorisation',
					`p and q differ by only ${(p - q).toString()}, so they sit either side of the square root of n`,
					p,
					q,
					e ?? 65537n,
					found.c
				);
			}
		}

		a += ONE;
	}

	return null;
}

/**
 * Two keys that share a prime.
 *
 * Nothing about either modulus looks wrong on its own. Take the greatest common
 * divisor of the two and the shared prime falls straight out, which breaks both
 * keys at once.
 */
export function sharedFactor(found: Parameters): Recovery | null {
	const { n, n2, e } = found;
	if (n === undefined || n2 === undefined || n === n2) return null;

	const shared = gcd(n, n2);
	if (shared === ONE || shared === n) return null;

	const other = n / shared;
	return finish(
		'Shared prime between two keys',
		'Two moduli have a factor in common, which a common divisor finds without factoring either',
		shared,
		other,
		e ?? 65537n,
		found.c
	);
}

/**
 * A private exponent small enough to reconstruct from the public one.
 *
 * Wiener's attack. Choosing a small d makes decryption fast and makes d/n a very
 * good rational approximation of e/n, so walking the continued fraction of e/n
 * runs into d within a few steps.
 */
export function wiener(found: Parameters): Recovery | null {
	const { n, e } = found;
	if (n === undefined || e === undefined || e <= ONE) return null;

	// Continued fraction expansion of e/n.
	let [a, b] = [e, n];
	const quotients: bigint[] = [];

	for (let depth = 0; depth < 256 && b !== ZERO; depth++) {
		quotients.push(a / b);
		[a, b] = [b, a % b];
	}

	for (let i = 0; i < quotients.length; i++) {
		// The convergent, built from the quotients so far.
		let numerator = ONE;
		let denominator = ZERO;
		for (let j = i; j >= 0; j--) {
			[numerator, denominator] = [quotients[j] * numerator + denominator, numerator];
		}

		// e/n approximates k/d, so the numerator is k and the denominator is d.
		const k = numerator;
		const d = denominator;
		if (k === ZERO || d === ZERO) continue;

		// If this d is right, phi comes out whole.
		const phiTimesK = e * d - ONE;
		if (phiTimesK % k !== ZERO) continue;
		const phi = phiTimesK / k;

		// p and q are the roots of x^2 - (n - phi + 1)x + n.
		const sum: bigint = n - phi + ONE;
		const discriminant: bigint = sum * sum - 4n * n;
		if (discriminant < ZERO) continue;

		const root: bigint = isqrt(discriminant);
		if (root * root !== discriminant) continue;

		const p: bigint = (sum + root) / TWO;
		const q: bigint = (sum - root) / TWO;
		if (p * q !== n) continue;

		return {
			attack: "Wiener's attack",
			because: `The private exponent is small enough to fall out of the continued fraction of e over n`,
			p,
			q,
			d,
			message: found.c !== undefined ? toBytes(modpow(found.c, d, n)) : undefined
		};
	}

	return null;
}

/** Factors already given, or a modulus small enough to divide out. */
export function known(found: Parameters): Recovery | null {
	const { n, e, p, q } = found;

	if (p !== undefined && q !== undefined) {
		return finish(
			'Factors were given',
			'p and q were in the input, so nothing had to be broken',
			p,
			q,
			e ?? 65537n,
			found.c
		);
	}

	// A modulus small enough that trial division reaches its factors.
	if (n !== undefined && n > ONE && n < 10n ** 14n) {
		for (let factor = TWO; factor * factor <= n; factor += ONE) {
			if (n % factor === ZERO) {
				return finish(
					'Modulus small enough to factor outright',
					`n is only ${n.toString().length} digits, so its factors can simply be found`,
					factor,
					n / factor,
					e ?? 65537n,
					found.c
				);
			}
		}
	}

	return null;
}

/** Everything worth trying, in the order it is worth trying. */
export const ATTACKS = [known, sharedFactor, cubeRoot, fermat, wiener] as const;

export type Report = {
	found: Parameters;
	recovered: Recovery[];
};

export function attack(text: string): Report {
	const found = parse(text);
	const recovered: Recovery[] = [];

	for (const run of ATTACKS) {
		try {
			const result = run(found);
			if (result) recovered.push(result);
		} catch {
			// One attack failing on odd input should not stop the others.
		}
	}

	return { found, recovered };
}

/** True when the text names enough of an RSA key to be worth attacking. */
export function looksLikeRsa(text: string): boolean {
	const found = parse(text);
	const named = [found.n, found.e, found.c, found.d, found.p, found.q].filter(
		(v) => v !== undefined
	).length;

	// A modulus alone is not an RSA challenge, and neither is a stray "e = 3".
	return named >= 2 && (found.n !== undefined || (found.p !== undefined && found.q !== undefined));
}
