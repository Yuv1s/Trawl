import { COLOR_TYPES, isHeaderError, type Structure } from '$lib/worker/protocol';

export type Finding = {
	id: string;
	flagged: boolean;
	title: string;
	detail: string;
};

const hex = (n: number) => `0x${n.toString(16)}`;

/**
 * Turns the container walk into ranked findings. Flagged means something was
 * measured that a clean file would not show, never a guess.
 */
export function findings(structure: Structure): Finding[] {
	const flagged: Finding[] = [];
	const routine: Finding[] = [];

	if (structure.trailing) {
		flagged.push({
			id: 'trailing',
			flagged: true,
			title: `${structure.trailing.length.toLocaleString()} bytes after IEND`,
			detail: `A PNG ends at IEND. These bytes start at ${hex(structure.trailing.offset)} and no decoder reads them, which is where appended archives are usually parked.`
		});
	}

	for (const chunk of structure.chunks) {
		if (chunk.crcOk) continue;
		flagged.push({
			id: `crc-${chunk.offset}`,
			flagged: true,
			title: `CRC mismatch on ${chunk.kind} at ${hex(chunk.offset)}`,
			detail:
				'The stored checksum disagrees with the chunk contents, so the file was edited after it was written, or the checksum field itself is carrying data.'
		});
	}

	for (const text of structure.text) {
		flagged.push({
			id: `text-${text.kind}-${text.keyword}`,
			flagged: true,
			title: `${text.kind} chunk: ${text.keyword || 'no keyword'}`,
			detail: text.compressed
				? 'Compressed text, not yet inflated. The content is unread rather than empty.'
				: text.text || 'Present but carries no text.'
		});
	}

	if (isHeaderError(structure.header)) {
		flagged.push({
			id: 'header',
			flagged: true,
			title: 'IHDR cannot be decoded',
			detail: structure.header.error
		});
	}

	if (!structure.chunks.some((c) => c.kind === 'IEND')) {
		flagged.push({
			id: 'no-iend',
			flagged: true,
			title: 'No IEND chunk',
			detail:
				'The chunk walk ran out of file before reaching the terminator, so the image is truncated or a length field is lying.'
		});
	}

	if (!isHeaderError(structure.header)) {
		const { width, height, bitDepth, colorType, interlace } = structure.header;
		routine.push({
			id: 'image',
			flagged: false,
			title: `${width} by ${height}, ${bitDepth}-bit ${COLOR_TYPES[colorType] ?? `type ${colorType}`}`,
			detail: interlace ? 'Adam7 interlaced.' : 'Not interlaced.'
		});
	}

	const ancillary = structure.chunks.filter((c) => c.ancillary && !c.kind.endsWith('TXt'));
	if (ancillary.length > 0) {
		routine.push({
			id: 'ancillary',
			flagged: false,
			title: `${ancillary.length} ancillary ${ancillary.length === 1 ? 'chunk' : 'chunks'}`,
			detail: `${ancillary.map((c) => c.kind).join(', ')}. Optional metadata a decoder may skip.`
		});
	}

	const idat = structure.chunks.filter((c) => c.kind === 'IDAT');
	if (idat.length > 0) {
		const total = idat.reduce((n, c) => n + c.length, 0);
		routine.push({
			id: 'idat',
			flagged: false,
			title: `${total.toLocaleString()} bytes of pixel data`,
			detail: `Across ${idat.length} IDAT ${idat.length === 1 ? 'chunk' : 'chunks'}.`
		});
	}

	return [...flagged, ...routine];
}

export const CHECKS_RUN = [
	'bytes after IEND',
	'chunk CRCs',
	'text chunks',
	'header validity',
	'chunk walk completeness'
];
