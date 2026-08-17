import {
	isHeaderError,
	type ChiSquare,
	type PlaneWall,
	type RsAnalysis,
	type Structure,
	type Sweep
} from '$lib/worker/protocol';

export type ToolStatus = 'hit' | 'clear' | 'ready' | 'pending';

export type Tool = {
	id: string;
	name: string;
	measures: string;
	status: ToolStatus;
	value: string;
};

export const STATUS_LABEL: Record<ToolStatus, string> = {
	hit: 'hit',
	clear: 'clear',
	ready: 'ready',
	pending: 'not built'
};

/** Detectors that exist, reporting what they actually measured on this file. */
export function tools(
	structure: Structure,
	sweep: Sweep | null = null,
	wall: PlaneWall | null = null,
	chi: ChiSquare | null = null,
	rs: RsAnalysis | null = null
): Tool[] {
	const badCrc = structure.chunks.filter((c) => !c.crcOk).length;
	const headerBroken = isHeaderError(structure.header);
	const credible = structure.flags.filter((f) => f.credible);
	const sweepHits = sweep?.candidates.length ?? 0;

	return [
		{
			id: 'flags',
			name: 'Flag scan',
			measures: 'Looks for flag{...} text in the file',
			status: credible.length ? 'hit' : 'clear',
			value: credible.length
				? `${credible.length} candidate${credible.length === 1 ? '' : 's'}`
				: 'none in container'
		},
		{
			id: 'lsb',
			name: 'LSB sweep',
			measures: 'Tries every way of reading hidden bits',
			status: sweepHits ? 'hit' : sweep ? 'clear' : 'pending',
			value: sweepHits
				? `${sweepHits} of ${sweep?.combinations} combinations`
				: sweep
					? `${sweep.combinations} swept, none carried data`
					: 'pixels unavailable'
		},
		{
			id: 'chi',
			name: 'Chi-square attack',
			measures: 'Statistical test for a hidden payload',
			status: chi?.detected ? 'hit' : chi ? 'clear' : 'pending',
			value: chi?.detected
				? `${(chi.embeddedFraction * 100).toFixed(0)}% embedded`
				: chi
					? `peak p ${chi.peakProbability.toFixed(2)}`
					: 'pixels unavailable'
		},
		{
			id: 'rs',
			name: 'RS analysis',
			measures: 'Second opinion on how much is hidden',
			status: rs?.detected ? 'hit' : rs?.reliable ? 'clear' : rs ? 'ready' : 'pending',
			value: rs?.detected
				? `${(rs.rate * 100).toFixed(0)}% of low bits`
				: rs?.reliable
					? 'nothing in the low bits'
					: rs
						? 'no fit on this image'
						: 'pixels unavailable'
		},
		{
			id: 'planes',
			name: 'Bit-plane wall',
			measures: 'Shows each layer of bits as a picture',
			status: wall ? 'ready' : 'pending',
			value: wall ? `${wall.planes.length} planes` : 'pixels unavailable'
		},
		{
			id: 'trailing',
			name: 'Post-IEND data',
			measures: 'Extra bytes stuck on the end of the file',
			status: structure.trailing ? 'hit' : 'clear',
			value: structure.trailing ? `${structure.trailing.length.toLocaleString()} bytes` : 'none'
		},
		{
			id: 'text',
			name: 'Text chunks',
			measures: 'Comments and labels saved inside the image',
			status: structure.text.length ? 'hit' : 'clear',
			value: structure.text.length ? `${structure.text.length} found` : 'none'
		},
		{
			id: 'crc',
			name: 'Chunk CRC',
			measures: 'Checks each part against its own checksum',
			status: badCrc ? 'hit' : 'clear',
			value: badCrc ? `${badCrc} mismatch${badCrc === 1 ? '' : 'es'}` : 'all valid'
		},
		{
			id: 'chunks',
			name: 'Chunk walk',
			measures: 'Lists every part of the file',
			status: headerBroken ? 'hit' : 'ready',
			value: headerBroken ? 'header unreadable' : `${structure.chunks.length} chunks`
		},
		{
			id: 'strings',
			name: 'ASCII strings',
			measures: 'Readable text anywhere in the file',
			status: 'ready',
			value: structure.strings.total.toLocaleString()
		},
		{
			id: 'pixels',
			name: 'Pixel decode',
			measures: 'Reads exact pixel values, nothing altered',
			status: headerBroken ? 'pending' : 'ready',
			value: headerBroken ? 'blocked' : 'verified'
		}
	];
}

/** Named so the rack shows the whole instrument, not only the parts that work. */
export const PLANNED: Tool[] = [
	{
		id: 'entropy',
		name: 'Entropy window',
		measures: 'Finds compressed or encrypted regions',
		status: 'pending',
		value: ''
	},
	{
		id: 'exif',
		name: 'EXIF / TIFF',
		measures: 'Camera and editing metadata',
		status: 'pending',
		value: ''
	}
];
