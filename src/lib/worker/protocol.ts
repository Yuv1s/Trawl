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
	/** How many bytes to carve out. */
	length: number;
	/** True when a real end marker was found; false means the length is a guess. */
	bounded: boolean;
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

export type JpegCandidate = {
	/** The original JSteg embeds in DC too; most later variants skip it. */
	includeDc: boolean;
	msbFirst: boolean;
	reason: string;
	preview: string;
	readable: number;
	bytesRead: number;
	flags: string[];
};

/** What the JPEG coefficient tools found. Null for anything that is not a JPEG. */
export type JpegStego = {
	width: number;
	height: number;
	components: number;
	blocks: number;
	/** One for baseline, several for progressive. */
	scans: number;
	progressive: boolean;
	/** True when a scan ran out of data, so the tail blocks read as zero. */
	truncated: boolean;
	combinations: number;
	chi: ChiSquare;
	/** Counts of each small coefficient value, AC only. */
	histogram: { value: number; count: number }[];
	candidates: JpegCandidate[];
};

/** Returned instead when the file is a JPEG this decoder will not read. */
export type JpegError = { error: string };

export function isJpegError(jpeg: JpegStego | JpegError): jpeg is JpegError {
	return 'error' in jpeg;
}

export type PaletteGroup = {
	colour: string;
	copies: number;
	/** Bits a pixel painted with this colour can carry. */
	bits: number;
};

export type PaletteCandidate = {
	msbFirst: boolean;
	reason: string;
	preview: string;
	readable: number;
	bytesRead: number;
	flags: string[];
};

/** Null unless the file is an indexed image whose pixels could be read. */
export type PaletteStego = {
	combinations: number;
	capacityBits: number;
	groups: PaletteGroup[];
	candidates: PaletteCandidate[];
};

export type RiffChunk = {
	id: string;
	offset: number;
	length: number;
	/** False when the declared length ran past the end of the file. */
	complete: boolean;
};

/** What the RIFF walk found. Null for anything that is not a WAV. */
export type WavStructure = {
	encoding: string;
	channels: number;
	sampleRate: number;
	bitsPerSample: number;
	frames: number;
	seconds: number;
	dataOffset: number;
	dataLength: number;
	chunks: RiffChunk[];
	text: { chunk: string; offset: number; text: string }[];
	trailing: { offset: number; length: number } | null;
};

/** Returned instead of the above when the signature matched but the walk did not. */
export type WavError = { error: string; chunks: RiffChunk[] };

export function isWavError(wav: WavStructure | WavError): wav is WavError {
	return 'error' in wav;
}

export type AudioCandidate = {
	channels: string;
	/** Null when the read covered every channel interleaved. */
	channelIndex: number | null;
	bit: number;
	msbFirst: boolean;
	reason: string;
	preview: string;
	readable: number;
	bytesRead: number;
	flags: string[];
};

export type AudioSweep = {
	samples: number;
	combinations: number;
	candidates: AudioCandidate[];
};

export type Spectrogram = {
	width: number;
	height: number;
	window: number;
	hop: number;
	/** The top row of the image, in Hz. The bottom row is 0. */
	maxFrequency: number;
	seconds: number;
	/** One grayscale byte per pixel, row 0 at the top. */
	pixels: Uint8Array;
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
	/** Source dimensions, so the 1:1 view works without a format header. */
	width: number;
	height: number;
	channels: number;
	planes: PlaneStat[];
	thumbnails: Uint8Array;
};

export type AnalysisRequest =
	| { kind: 'analyse'; id: number; name: string; bytes: ArrayBuffer }
	| { kind: 'plane'; id: number; channel: number; bit: number }
	| { kind: 'extract'; id: number; channels: string; bit: number; msbFirst: boolean }
	| { kind: 'extractPalette'; id: number; msbFirst: boolean }
	| {
			kind: 'extractJpeg';
			id: number;
			includeDc: boolean;
			msbFirst: boolean;
	  }
	| {
			kind: 'extractAudio';
			id: number;
			label: string;
			channelIndex: number | null;
			bit: number;
			msbFirst: boolean;
	  };

export type AnalysisResponse =
	| {
			id: number;
			status: 'ok';
			name: string;
			size: number;
			survey: Survey;
			/** Null when the file is not a PNG, so the format-level tools stand down. */
			structure: Structure | null;
			/** Null when the file is not a WAV, likewise. */
			wav: WavStructure | WavError | null;
			/** Null when the file is not a JPEG, likewise. */
			jpeg: JpegStego | JpegError | null;
			/** Null unless the file is an indexed image. */
			paletteStego: PaletteStego | null;
			sweep: Sweep | null;
			wall: PlaneWall | null;
			chi: ChiSquare | null;
			rs: RsAnalysis | null;
			audio: AudioSweep | null;
			spectrogram: Spectrogram | null;
			pixelError: string | null;
			audioError: string | null;
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
