import {
	isHeaderError,
	type ChiSquare,
	type FlagHit,
	type PlaneWall,
	type RsAnalysis,
	type Structure,
	type Survey,
	type Sweep
} from '$lib/worker/protocol';

export type ToolStatus = 'hit' | 'clear' | 'ready' | 'pending';

/** `bytes` tools read raw data and run on anything; `png` tools need the walker. */
export type ToolScope = 'bytes' | 'png';

export type Tool = {
	id: string;
	name: string;
	measures: string;
	scope: ToolScope;
	status: ToolStatus;
	value: string;
};

export const STATUS_LABEL: Record<ToolStatus, string> = {
	hit: 'hit',
	clear: 'clear',
	ready: 'ready',
	pending: 'not built'
};

/**
 * The PNG walker knows which chunks are compressed, so it judges a flag match
 * more precisely than entropy can. Entropy is the fallback for formats whose
 * structure we cannot read.
 */
export function flagsOf(survey: Survey, structure: Structure | null): FlagHit[] {
	return structure ? structure.flags : survey.flags;
}

const UNAVAILABLE = 'PNG only, for now';

export function tools(
	survey: Survey,
	structure: Structure | null = null,
	sweep: Sweep | null = null,
	wall: PlaneWall | null = null,
	chi: ChiSquare | null = null,
	rs: RsAnalysis | null = null
): Tool[] {
	const credible = flagsOf(survey, structure).filter((f) => f.credible);
	const embedded = survey.magic.filter((m) => m.embedded);
	const peakEntropy = survey.entropy.values.length ? Math.max(...survey.entropy.values) : 0;

	const headerBroken = !structure || isHeaderError(structure.header);
	const badCrc = structure?.chunks.filter((c) => !c.crcOk).length ?? 0;
	const sweepHits = sweep?.candidates.length ?? 0;

	/** Format-level tools report why they stood down rather than disappearing. */
	const png = (tool: Omit<Tool, 'scope'>): Tool =>
		structure
			? { ...tool, scope: 'png' }
			: { ...tool, scope: 'png', status: 'pending', value: UNAVAILABLE };

	return [
		{
			id: 'flags',
			name: 'Flag scan',
			measures: 'Looks for flag{...} text in the file',
			scope: 'bytes',
			status: credible.length ? 'hit' : 'clear',
			value: credible.length
				? `${credible.length} candidate${credible.length === 1 ? '' : 's'}`
				: 'none in readable data'
		},
		{
			id: 'magic',
			name: 'Embedded files',
			measures: 'Finds other files hidden inside this one',
			scope: 'bytes',
			status: embedded.length ? 'hit' : 'clear',
			value: embedded.length ? `${embedded.length} found` : 'none'
		},
		png({
			id: 'lsb',
			name: 'LSB sweep',
			measures: 'Tries every way of reading hidden bits',
			status: sweepHits ? 'hit' : sweep ? 'clear' : 'pending',
			value: sweepHits
				? `${sweepHits} of ${sweep?.combinations} combinations`
				: sweep
					? `${sweep.combinations} swept, none carried data`
					: 'pixels unavailable'
		}),
		png({
			id: 'chi',
			name: 'Chi-square attack',
			measures: 'Statistical test for a hidden payload',
			status: chi?.detected ? 'hit' : chi ? 'clear' : 'pending',
			value: chi?.detected
				? `${(chi.embeddedFraction * 100).toFixed(0)}% embedded`
				: chi
					? `peak p ${chi.peakProbability.toFixed(2)}`
					: 'pixels unavailable'
		}),
		png({
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
		}),
		png({
			id: 'planes',
			name: 'Bit-plane wall',
			measures: 'Shows each layer of bits as a picture',
			status: wall ? 'ready' : 'pending',
			value: wall ? `${wall.planes.length} planes` : 'pixels unavailable'
		}),
		{
			id: 'entropy',
			name: 'Entropy window',
			measures: 'Finds compressed or encrypted regions',
			scope: 'bytes',
			status: 'ready',
			value: `peak ${peakEntropy.toFixed(2)} of 8`
		},
		png({
			id: 'trailing',
			name: 'Post-IEND data',
			measures: 'Extra bytes stuck on the end of the file',
			status: structure?.trailing ? 'hit' : 'clear',
			value: structure?.trailing ? `${structure.trailing.length.toLocaleString()} bytes` : 'none'
		}),
		png({
			id: 'text',
			name: 'Text chunks',
			measures: 'Comments and labels saved inside the image',
			status: structure?.text.length ? 'hit' : 'clear',
			value: structure?.text.length ? `${structure.text.length} found` : 'none'
		}),
		png({
			id: 'crc',
			name: 'Chunk CRC',
			measures: 'Checks each part against its own checksum',
			status: badCrc ? 'hit' : 'clear',
			value: badCrc ? `${badCrc} mismatch${badCrc === 1 ? '' : 'es'}` : 'all valid'
		}),
		png({
			id: 'chunks',
			name: 'Chunk walk',
			measures: 'Lists every part of the file',
			status: headerBroken ? 'hit' : 'ready',
			value: headerBroken ? 'header unreadable' : `${structure?.chunks.length} chunks`
		}),
		{
			id: 'strings',
			name: 'ASCII strings',
			measures: 'Readable text anywhere in the file',
			scope: 'bytes',
			status: 'ready',
			value: survey.strings.total.toLocaleString()
		},
		png({
			id: 'pixels',
			name: 'Pixel decode',
			measures: 'Reads exact pixel values, nothing altered',
			status: headerBroken ? 'pending' : 'ready',
			value: headerBroken ? 'blocked' : 'verified'
		})
	];
}

/** Named so the rack shows the whole instrument, not only the parts that work. */
export const PLANNED: Tool[] = [
	{
		id: 'exif',
		name: 'EXIF / TIFF',
		measures: 'Camera and editing metadata',
		scope: 'bytes',
		status: 'pending',
		value: ''
	},
	{
		id: 'carve',
		name: 'File carving',
		measures: 'Pulls embedded files out to save',
		scope: 'bytes',
		status: 'pending',
		value: ''
	},
	{
		id: 'jpeg',
		name: 'JPEG segments',
		measures: 'Walks comments and app data in a JPEG',
		scope: 'bytes',
		status: 'pending',
		value: ''
	}
];
