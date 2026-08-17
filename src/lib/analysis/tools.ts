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
 * Every flag candidate, from whichever scan found it.
 *
 * The PNG walker judges a raw-byte match more precisely than entropy can,
 * because it knows which chunks are compressed, so its verdict wins where the
 * two overlap. But the survey also finds things the chunk walk structurally
 * cannot: UTF-16 text, and anything recovered by inflating a compressed chunk.
 * Returning one list or the other silently dropped those.
 */
export function flagsOf(survey: Survey, structure: Structure | null): FlagHit[] {
	if (!structure) return survey.flags;

	const judged = new Set(structure.flags.map((f) => f.offset));
	return [...structure.flags, ...survey.flags.filter((f) => !judged.has(f.offset))];
}

const UNAVAILABLE = 'PNG only, for now';

/** Metadata fields a person types into, as opposed to ones a camera fills in. */
export const WRITTEN_BY_HAND = new Set([
	'ImageDescription',
	'UserComment',
	'Artist',
	'Copyright',
	'Software',
	'ImageUniqueID',
	'CameraOwnerName',
	'MakerNote'
]);

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
	const writtenFields = (survey.exif ?? []).filter(
		(e) => e.textual && WRITTEN_BY_HAND.has(e.name) && e.value.trim() !== ''
	);
	const jpegish = survey.jpegSegments.length > 0;
	const duplicateColours = structure?.palette?.duplicates.length ?? 0;

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
			id: 'exif',
			name: 'Metadata',
			measures: 'Camera details and notes saved with the photo',
			scope: 'bytes',
			status: writtenFields.length ? 'hit' : survey.exif?.length ? 'ready' : 'clear',
			value: writtenFields.length
				? `${writtenFields.length} written field${writtenFields.length === 1 ? '' : 's'}`
				: survey.exif?.length
					? `${survey.exif.length} fields`
					: 'none'
		},
		{
			id: 'jpeg',
			name: 'JPEG segments',
			measures: 'Lists every part of a JPEG',
			scope: 'bytes',
			status:
				survey.jpegComments.length || survey.jpegTrailing ? 'hit' : jpegish ? 'ready' : 'clear',
			value: survey.jpegComments.length
				? `${survey.jpegComments.length} comment${survey.jpegComments.length === 1 ? '' : 's'}`
				: survey.jpegTrailing
					? `${survey.jpegTrailing.length.toLocaleString()} bytes past EOI`
					: jpegish
						? `${survey.jpegSegments.length} segments`
						: 'not a JPEG'
		},
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
			id: 'palette',
			name: 'Palette',
			measures: 'Repeated colours that could carry hidden bits',
			status: duplicateColours ? 'hit' : structure?.palette ? 'ready' : 'clear',
			value: duplicateColours
				? `${duplicateColours} duplicated`
				: structure?.palette
					? `${structure.palette.entries} colours`
					: 'not an indexed image'
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
			name: 'Readable text',
			measures: 'Text anywhere in the file, plain or wide',
			scope: 'bytes',
			status: 'ready',
			value: survey.strings.wide
				? `${survey.strings.total.toLocaleString()}, ${survey.strings.wide} wide`
				: survey.strings.total.toLocaleString()
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
		id: 'carve',
		name: 'File carving',
		measures: 'Pulls embedded files out to save',
		scope: 'bytes',
		status: 'pending',
		value: ''
	},
	{
		id: 'wav',
		name: 'Audio analysis',
		measures: 'Hidden data and pictures inside sound files',
		scope: 'bytes',
		status: 'pending',
		value: ''
	}
];
