import { isHeaderError, type Structure, type Sweep } from '$lib/worker/protocol';

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
export function tools(structure: Structure, sweep: Sweep | null = null): Tool[] {
	const badCrc = structure.chunks.filter((c) => !c.crcOk).length;
	const headerBroken = isHeaderError(structure.header);
	const credible = structure.flags.filter((f) => f.credible);
	const sweepHits = sweep?.candidates.length ?? 0;

	return [
		{
			id: 'flags',
			name: 'Flag scan',
			measures: 'tag{payload} outside compressed streams',
			status: credible.length ? 'hit' : 'clear',
			value: credible.length
				? `${credible.length} candidate${credible.length === 1 ? '' : 's'}`
				: 'none in container'
		},
		{
			id: 'lsb',
			name: 'LSB sweep',
			measures: 'channel order, bit plane and bit order, brute-forced',
			status: sweepHits ? 'hit' : sweep ? 'clear' : 'pending',
			value: sweepHits
				? `${sweepHits} of ${sweep?.combinations} combinations`
				: sweep
					? `${sweep.combinations} swept, none carried data`
					: 'pixels unavailable'
		},
		{
			id: 'trailing',
			name: 'Post-IEND data',
			measures: 'bytes past the terminator no decoder reads',
			status: structure.trailing ? 'hit' : 'clear',
			value: structure.trailing ? `${structure.trailing.length.toLocaleString()} bytes` : 'none'
		},
		{
			id: 'text',
			name: 'Text chunks',
			measures: 'tEXt, zTXt and iTXt metadata',
			status: structure.text.length ? 'hit' : 'clear',
			value: structure.text.length ? `${structure.text.length} found` : 'none'
		},
		{
			id: 'crc',
			name: 'Chunk CRC',
			measures: 'stored checksum against chunk contents',
			status: badCrc ? 'hit' : 'clear',
			value: badCrc ? `${badCrc} mismatch${badCrc === 1 ? '' : 'es'}` : 'all valid'
		},
		{
			id: 'chunks',
			name: 'Chunk walk',
			measures: 'every chunk typed, sized and located',
			status: headerBroken ? 'hit' : 'ready',
			value: headerBroken ? 'header unreadable' : `${structure.chunks.length} chunks`
		},
		{
			id: 'strings',
			name: 'ASCII strings',
			measures: 'printable runs of six characters or more',
			status: 'ready',
			value: structure.strings.total.toLocaleString()
		},
		{
			id: 'pixels',
			name: 'Pixel decode',
			measures: 'exact RGBA, no premultiply, no colour management',
			status: headerBroken ? 'pending' : 'ready',
			value: headerBroken ? 'blocked' : 'verified'
		}
	];
}

/** Named so the rack shows the whole instrument, not only the parts that work. */
export const PLANNED: Tool[] = [
	{
		id: 'bitplanes',
		name: 'Bit-plane wall',
		measures: '8 planes across every channel at once',
		status: 'pending',
		value: ''
	},
	{
		id: 'chisquare',
		name: 'Chi-square attack',
		measures: 'pair-of-values frequencies over rising prefixes',
		status: 'pending',
		value: ''
	},
	{
		id: 'rs',
		name: 'RS analysis',
		measures: 'regular and singular groups under flipping masks',
		status: 'pending',
		value: ''
	},
	{
		id: 'entropy',
		name: 'Entropy window',
		measures: 'Shannon entropy across a sliding window',
		status: 'pending',
		value: ''
	},
	{
		id: 'exif',
		name: 'EXIF / TIFF',
		measures: 'IFD walk over embedded metadata',
		status: 'pending',
		value: ''
	}
];
