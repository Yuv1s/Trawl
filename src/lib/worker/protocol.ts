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
};

export type Header =
	| { width: number; height: number; bitDepth: number; colorType: number; interlace: number }
	| { error: string };

export type Found = {
	offset: number;
	text: string;
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
	strings: { total: number; sample: Found[] };
	trailing: { offset: number; length: number } | null;
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
	| { kind: 'plane'; id: number; channel: number; bit: number };

export type AnalysisResponse =
	| {
			id: number;
			status: 'ok';
			name: string;
			size: number;
			structure: Structure;
			sweep: Sweep | null;
			wall: PlaneWall | null;
			chi: ChiSquare | null;
			rs: RsAnalysis | null;
			pixelError: string | null;
	  }
	| { id: number; status: 'plane'; channel: number; bit: number; pixels: Uint8Array }
	| { id: number; status: 'unsupported' | 'error'; name: string; size: number; detail: string };

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
