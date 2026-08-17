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

export type AnalysisRequest = {
	id: number;
	name: string;
	bytes: ArrayBuffer;
};

export type AnalysisResponse =
	| {
			id: number;
			status: 'ok';
			name: string;
			size: number;
			structure: Structure;
			sweep: Sweep | null;
			sweepError: string | null;
	  }
	| { id: number; status: 'unsupported' | 'error'; name: string; size: number; detail: string };

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
