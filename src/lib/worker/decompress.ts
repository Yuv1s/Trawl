/**
 * Compression framing and bounded decompression shared by the analysis worker
 * and its tests. The platform's DecompressionStream does the inflate; this
 * module decides which wrapper a buffer carries, validates its header, and
 * stops a stream once its output crosses a budget instead of materializing a
 * decompression bomb in memory.
 */

export const DECOMPRESS_LIMIT = 1 << 20; // 1 MiB per stream by default

export type CompressionKind = 'gzip' | 'zlib' | null;

/** A gzip stream announces itself with the 0x1f 0x8b magic. */
export function isGzip(bytes: Uint8Array): boolean {
	return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

/**
 * Throws if `bytes` is not a well-formed zlib header the browser can inflate.
 *
 * CMF: compression method must be deflate (low nibble 0x08) and the window
 * must fit the platform's 32 KiB limit (high nibble <= 0x07). FLG bit 5 means
 * a preset dictionary, which the platform cannot supply. CMF and FLG together
 * must satisfy the mod-31 check.
 */
export function assertZlibHeader(bytes: Uint8Array): void {
	if (bytes.length < 2) throw new Error('zlib header truncated');
	const cmf = bytes[0];
	const flg = bytes[1];
	if ((cmf & 0x0f) !== 0x08) throw new Error('zlib: not deflate');
	if ((cmf & 0xf0) > 0x70) throw new Error('zlib: window too large');
	if ((flg & 0x20) !== 0) throw new Error('zlib: preset dictionary not supported');
	if ((cmf * 256 + flg) % 31 !== 0) throw new Error('zlib: CMF/FLG checksum failed');
}

/** Which wrapper the head of `bytes` credibly announces, if any. */
export function compressionOf(bytes: Uint8Array): CompressionKind {
	if (isGzip(bytes)) return 'gzip';
	if (bytes.length >= 2) {
		try {
			assertZlibHeader(bytes);
			return 'zlib';
		} catch {
			return null;
		}
	}
	return null;
}

/**
 * Bounded inflate. Rejects output larger than `limit`. The 'deflate' format
 * expects the zlib wrapper, matching what `compressionOf` reports as zlib.
 */
export async function boundedInflate(
	format: 'gzip' | 'deflate' | 'deflate-raw',
	bytes: Uint8Array,
	limit = DECOMPRESS_LIMIT
): Promise<Uint8Array> {
	const reader = new Blob([bytes as Uint8Array<ArrayBuffer>])
		.stream()
		.pipeThrough(new DecompressionStream(format))
		.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;

	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.length;
			if (length > limit) {
				await reader.cancel(`${format} output exceeds limit`);
				throw new Error(`${format} output exceeds limit`);
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	const out = new Uint8Array(length);
	let at = 0;
	for (const chunk of chunks) {
		out.set(chunk, at);
		at += chunk.length;
	}
	return out;
}

/**
 * Deterministic fingerprint for dedup: first 64 bytes, last 64 bytes, and the
 * length. No hashing dependency is needed for a dedup set that also confirms
 * equality on collision.
 */
export function fingerprint(bytes: Uint8Array): string {
	const len = bytes.length;
	const head = bytes.slice(0, 64);
	const tail = bytes.slice(Math.max(0, len - 64));
	let h = 0;
	for (const b of head) h = (h * 1315423911) ^ b;
	for (const b of tail) h = (h * 1315423911) ^ b;
	h = (h * 1315423911) ^ len;
	return `${len}:${h >>> 0}`;
}
