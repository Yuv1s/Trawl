export type Chunk = {
	kind: string;
	offset: number;
	length: number;
	dataOffset: number;
	crcOk: boolean;
	ancillary: boolean;
};

export type TextChunk = {
	kind: string;
	keyword: string;
	text: string;
	compressed: boolean;
	/** Where the zlib stream sits, so the worker can inflate it. */
	payloadOffset: number;
	payloadLength: number;
	/** Set when inflation was attempted and failed. */
	error?: string;
};

export type Palette = {
	entries: number;
	unused: number;
	capacityBits: number;
	duplicates: { colour: string; count: number }[];
};

export type Header =
	| { width: number; height: number; bitDepth: number; colorType: number; interlace: number }
	| { error: string };

export type Found = {
	offset: number;
	text: string;
};

export type MagicHit = {
	offset: number;
	label: string;
	embedded: boolean;
};

export type ExifEntry = {
	ifd: string;
	tag: number;
	name: string;
	value: string;
	/** True when the value is text a person could have written. */
	textual: boolean;
};

export type JpegSegment = {
	name: string;
	marker: number;
	offset: number;
	length: number;
};

/** What can be read from any file, whatever its format. */
export type Survey = {
	size: number;
	format: string | null;
	flags: FlagHit[];
	magic: MagicHit[];
	/** Null when the file carries no metadata block at all. */
	exif: ExifEntry[] | null;
	jpegSegments: JpegSegment[];
	jpegComments: Found[];
	jpegTrailing: { offset: number; length: number } | null;
	strings: { total: number; wide: number; sample: Found[] };
	entropy: { window: number; values: number[] };
};

export type FlagHit = Found & {
	region: string;
	credible: boolean;
};

export type SweepCandidate = {
	channels: string;
	bit: number;
	msbFirst: boolean;
	reason: string;
	preview: string;
	/** Length of the readable run, which exceeds the preview when it clipped. */
	readable: number;
	bytesRead: number;
	flags: string[];
};

export type Sweep = {
	pixels: number;
	combinations: number;
	candidates: SweepCandidate[];
};

export type Structure = {
	signature: boolean;
	size: number;
	header: Header;
	chunks: Chunk[];
	text: TextChunk[];
	flags: FlagHit[];
	trailing: { offset: number; length: number } | null;
	/** Filled in by the worker for indexed images. */
	palette?: Palette | null;
};

export type ChiPoint = {
	fraction: number;
	p: number;
	chiSquare: number;
	degrees: number;
};

export type ChiSquare = {
	detected: boolean;
	embeddedFraction: number;
	peakProbability: number;
	samples: number;
	points: ChiPoint[];
};

export type RsAnalysis = {
	rate: number;
	reliable: boolean;
	detected: boolean;
	groups: number;
	regular: number;
	singular: number;
	regularNegated: number;
	singularNegated: number;
};

export type PlaneStat = {
	channel: number;
	bit: number;
	transitionRate: number;
};

export type PlaneWall = {
	thumbWidth: number;
	thumbHeight: number;
	channels: number;
	planes: PlaneStat[];
	thumbnails: Uint8Array;
};

export type AnalysisRequest =
	| { kind: 'analyse'; id: number; name: string; bytes: ArrayBuffer }
	| { kind: 'plane'; id: number; channel: number; bit: number }
	| { kind: 'extract'; id: number; channels: string; bit: number; msbFirst: boolean };

export type AnalysisResponse =
	| {
			id: number;
			status: 'ok';
			name: string;
			size: number;
			survey: Survey;
			/** Null when the file is not a PNG, so the format-level tools stand down. */
			structure: Structure | null;
			sweep: Sweep | null;
			wall: PlaneWall | null;
			chi: ChiSquare | null;
			rs: RsAnalysis | null;
			pixelError: string | null;
	  }
	| { id: number; status: 'plane'; channel: number; bit: number; pixels: Uint8Array }
	| { id: number; status: 'extract'; label: string; bytes: Uint8Array }
	| { id: number; status: 'error'; name: string; size: number; detail: string };

export const CHANNEL_NAMES = ['R', 'G', 'B', 'A'];

export function isHeaderError(header: Header): header is { error: string } {
	return 'error' in header;
}

export const COLOR_TYPES: Record<number, string> = {
	0: 'grayscale',
	2: 'truecolour',
	3: 'indexed',
	4: 'grayscale + alpha',
	6: 'truecolour + alpha'
};
