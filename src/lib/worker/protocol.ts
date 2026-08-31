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

export type IhdrRepair = {
	declaredWidth: number;
	declaredHeight: number;
	recoveredWidth: number;
	recoveredHeight: number;
	targetCrc: string;
	field: 'width' | 'height';
};

export type Structure = {
	signature: boolean;
	size: number;
	header: Header;
	ihdrRepair?: IhdrRepair | null;
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

/**
 * One file inside a ZIP, as both places that describe it see it.
 *
 * A ZIP says what it holds twice: a local header before each file, and a
 * central directory at the end listing them all. Readers use the directory, so
 * the two disagreeing is how an archive hides something.
 */
export type ZipEntry = {
	name: string;
	method: string;
	compressed: number;
	uncompressed: number;
	offset: number;
	/** Where the compressed data begins. Null for a phantom the directory points at with no header. */
	dataOffset: number | null;
	crc: string;
	/** The archive's own password flag. Trawl does not crack these. */
	encrypted: boolean;
	/** Only a local header names this; the directory does not, so `unzip -l` will not show it. */
	undeclared: boolean;
	comment: string;
	/** What the local header and the directory disagree about, if anything. */
	disagreement: string | null;
	/** Filled in by the worker: the decompressed content, as text, when it reads as text. */
	text?: string;
	/** Filled in by the worker: flag shapes found in the decompressed content. */
	flags?: string[];
	/** Filled in by the worker when the entry is small enough for in-memory re-analysis. */
	bytes?: Uint8Array;
	/** Set when the worker tried to decompress this entry and could not. */
	readError?: string;
};

/** One AES-CBC decryption that read as text, and where its key and IV came from. */
export type AesSolved = {
	keyHex: string;
	ivHex: string;
	/** Key length in bits: 128, 192 or 256. */
	bits: number;
	text: string;
	flags: string[];
};

export type ZipArchive = {
	entries: ZipEntry[];
	comment: string;
	/** Bytes before the first header. A polyglot puts a whole image there. */
	prefix: number;
	/** Bytes after the end-of-directory record, which a zip tool would not write. */
	trailing: number;
	/** How many files the directory claims, against how many it lists. */
	declared: number;
};

/** A stream's raw bytes inside a PDF object, wherever compression leaves them. */
export type PdfStream = {
	offset: number;
	length: number;
	/** The filter chain named in `/Filter`, joined with " then ". Empty when
	 *  the stream carries its bytes uncompressed. */
	filter: string;
	/** Filled in once the worker has inflated a FlateDecode stream. Rust
	 *  locates the bytes; inflate is a platform call. */
	text?: string;
	error?: string;
};

/** One `N G obj ... endobj` block. */
export type PdfObject = {
	number: number;
	generation: number;
	offset: number;
	type: string | null;
	subtype: string | null;
	/** True when the document's own cross-reference table no longer lists
	 *  this object's offset: bytes left over from an earlier revision that a
	 *  reader following the table would never see. */
	orphaned: boolean;
	stream: PdfStream | null;
	/** Flags found after inflating a compressed stream. Set by the worker,
	 *  never by Rust: a flag hiding in a FlateDecode stream is invisible to
	 *  any byte-level scan that ran before the stream was inflated. */
	flags?: string[];
};

export type PdfStructure = {
	/** The version named in the file's own `%PDF-` header. */
	version: string;
	/** Bytes after the last `%%EOF`, appended by something other than
	 *  whatever wrote the document. */
	trailing: number;
	encrypted: boolean;
	/** True when the cross-reference table is a stream rather than the
	 *  classic plain-text form, which this reads without decoding: it is
	 *  itself compressed, so every object's `orphaned` flag stays false
	 *  rather than guessing. */
	usesXrefStream: boolean;
	/** How many `%%EOF` markers the file holds. More than one means the
	 *  document has been incrementally updated at least once. */
	revisions: number;
	/** `/Info` dictionary fields this reads: Title, Author, Subject,
	 *  Producer, Creator, CreationDate, ModDate. */
	info: { key: string; value: string }[];
	/** Object numbers whose `/Subtype` names them as a file attachment. */
	embeddedFiles: number[];
	objects: PdfObject[];
};

/** One encoding layer removed from a pasted string. */
export type PeelStep = {
	encoding: string;
	/** Why it was kept: a gain in readability, a flag, or a file signature. */
	reason: string;
	output: string;
	/** Set when the step was a gzip or zlib decompression done by the platform. */
	compressed?: boolean;
};

/** A recovered XOR key and what it decrypted to. */
export type XorCandidate = {
	/** "single byte" or "repeating key". */
	kind: string;
	/** Quoted when the key is text, hex bytes when it is not. */
	key: string;
	keyLength: number;
	score: number;
	plaintext: string;
	flags: string[];
};

/** What a pasted string turned out to be, when it is a digest. */
export type HashMatch = {
	/** True when the string declares its own format rather than merely fitting. */
	certain: boolean;
	shape: string;
	bits: number | null;
	/** More than one whenever the shape cannot separate them. */
	candidates: string[];
};

export type PeelResult = {
	depth: number;
	/** How much the final answer reads like ordinary text, 0 to 1. */
	score: number;
	result: string;
	steps: PeelStep[];
	/** Run against whatever the peel ended with, which is where a cipher hides. */
	xor: XorCandidate[];
	/** Set when the string is a digest, which is nothing to unwrap or attack. */
	hash: HashMatch | null;
	/** Set when the text turned out to be Vigenère. */
	vigenere: { key: string; score: number; plaintext: string } | null;
	/** Set when the text turned out to be affine, which includes Caesar. */
	affine: AffineBreak | null;
	/** Set when the text turned out to be a 2x2 Hill cipher. */
	hill: HillBreak | null;
	/** Set when the letters were the right ones in the wrong order. */
	transposition: TranspositionBreak | null;
	/** Set when the alphabet was replaced wholesale. */
	substitution: SubstitutionBreak | null;
	/** The counts themselves, for when nothing above settled it. */
	frequency: FrequencyTable;
	/**
	 * Every rotation laid out, best first, when nothing else read the text.
	 *
	 * Empty whenever an attack landed. A great many answers are not English — a
	 * token, a key, a flag with no marker on it — and against those the scorer
	 * is blind rather than wrong, so the honest fallback is to hand over the
	 * readings and let the eye finish.
	 */
	shortlist: Rotation[];
	/** Set when a key from Mantis's own short wordlist read the text. */
	dictionary: KeyAttempt | null;
	/**
	 * Keys worked out of this text, one per assumed key length, best first.
	 *
	 * Nothing here is a list of common keys. Each entry is what falls out of
	 * splitting the letters into that many columns and counting each column,
	 * so a different ciphertext yields entirely different keys.
	 */
	derivedKeys: DerivedKey[];
};

/** A key recovered from the ciphertext at one assumed key length. */
export type DerivedKey = {
	key: string;
	/**
	 * Letters each key position had to work from.
	 *
	 * The whole story about how much the key is worth. Around twelve it becomes
	 * reliable; at two it is a shape the text suggested rather than a key.
	 */
	perColumn: number;
	score: number;
	/** The start of what this key deciphers to. */
	preview: string;
};

/**
 * What one cipher made of a key.
 *
 * Nothing filters these when the key came from a person: recovering a key needs
 * enough text to count letters in, and plenty of answers are tokens no scorer
 * could confirm, so the person who supplied the key is the one who judges it.
 */
export type KeyAttempt = {
	cipher: string;
	key: string;
	plaintext: string;
	score: number;
	flags: string[];
	/**
	 * Keys for the layer underneath, when this one did not reach the bottom.
	 *
	 * Enciphering twice is one cipher with a longer key, so two keys can never
	 * be recovered separately from the text alone. Given the first, the second
	 * is an ordinary problem again. Empty once the result reads.
	 */
	next: DerivedKey[];
};

/** One way of reading the input, and where that reading leads. */
export type Rotation = {
	/** What was done, in the words a person would use: "ROT 13", "base36 +21". */
	how: string;
	text: string;
	score: number;
	/** Set when this reading, or what it decodes to, carries a flag or signature. */
	found: string | null;
	/** What a further peel makes of it, when the shape alone justifies one. */
	then: { through: string[]; result: string; score: number } | null;
};

/** A recovered affine key, where each letter became `a * x + b` modulo 26. */
export type AffineBreak = {
	a: number;
	b: number;
	score: number;
	plaintext: string;
};

/**
 * A recovered Hill key: a 2x2 matrix mod 26, read left to right, top to
 * bottom, that every pair of letters was multiplied by.
 */
export type HillBreak = {
	matrix: [number, number, number, number];
	score: number;
	plaintext: string;
};

/**
 * A recovered transposition, which moved the letters without changing them.
 *
 * `rails` is set for a rail fence and `order` for a columnar, never both.
 */
export type TranspositionBreak = {
	kind: 'rail fence' | 'columnar';
	rails?: number;
	width?: number;
	/** Grid columns in the order the key read them. */
	order?: number[];
	score: number;
	plaintext: string;
};

/** A recovered substitution key: the plaintext letter for each of A to Z. */
export type SubstitutionBreak = {
	key: string;
	score: number;
	plaintext: string;
};

/** How often a letter appears, against what English would give it. */
export type LetterCount = {
	letter: string;
	count: number;
	/** Share of all letters, as a percentage. */
	share: number;
	/** English's share of the same letter, to compare against. */
	english: number;
};

/**
 * Letter counts and repeated runs, reported whether or not an attack landed.
 *
 * `coincidence` is the chance two letters drawn from the text match: English
 * runs near 0.067, and text spread across several alphabets flattens to 0.038.
 */
export type FrequencyTable = {
	total: number;
	coincidence: number;
	letters: LetterCount[];
	bigrams: { text: string; count: number }[];
	trigrams: { text: string; count: number }[];
};

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

export type ToneFinding = {
	kind: 'Morse' | 'DTMF';
	decoded: string;
	confidence: number;
	units: number;
};

export type AudioSweep = {
	samples: number;
	combinations: number;
	candidates: AudioCandidate[];
	tones?: ToneFinding[];
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

/** One compact result for a displayed GIF frame or a consecutive pair. */
export type GifSource = {
	kind: 'frame' | 'difference';
	/** One-based frame this source came from. */
	from: number;
	/** Present only for a difference: the earlier frame it is measured against. */
	to: number | null;
	/** Delay in hundredths of a second, and the disposal method, for a plain frame. */
	delay: number | null;
	disposal: string | null;
	/** LSB sweep over this exact frame or difference. */
	lsb: Sweep;
	/** The chi-square verdict over the same pixels. */
	chi: { detected: boolean; embeddedFraction: number } | null;
	/** The RS verdict over the same pixels. */
	rs: { detected: boolean; rate: number } | null;
};

/**
 * What automatic frame analysis found, for GIF files.
 *
 * Compact on purpose: the per-frame pixels and plane walls stay behind, and a
 * frame worth a closer look gets the ordinary full analysis.
 */
export type GifAnalysis = {
	width: number;
	height: number;
	declaredFrames: number;
	analysedFrames: number;
	/** True when a work budget stopped the walk before every frame. */
	capped: boolean;
	/** Why no frame could be read, when the file is a GIF this reader refuses. */
	error: string | null;
	sources: GifSource[];
};

/** One finding recovered from a nested file, headed back to the root by origin. */
export type DerivedFinding = {
	text: string;
	/** The detector that reported it, in words a person would use. */
	detector: string;
	/** Path from the root down: `outer.zip / images/clue.gif`. */
	origin: string;
	/** Short reason or preview where the detector offers one. */
	reason: string;
};

/** One automatically analysed child of the root file. */
export type NestedArtifact = {
	/** Stable across the analysis, and unique within it. */
	id: string;
	name: string;
	/** Where the child came from inside its parent. */
	source: 'zip' | 'carved';
	/** Offset in the parent: a local header for a ZIP entry, the marker for a carved file. */
	offset: number;
	format: string | null;
	size: number;
	depth: number;
	status: 'analysed' | 'skipped' | 'error';
	/** Set when status is not `analysed`: what stopped the walk. */
	reason?: string;
	/** This child's findings and everything below it. */
	findings: DerivedFinding[];
	children: NestedArtifact[];
};

/** Budget accounting for the recursive walk over embedded files. */
export type NestedAnalysis = {
	roots: NestedArtifact[];
	/** Files fully analysed, across the whole tree. */
	analysed: number;
	/** Files skipped without a full run. */
	skipped: number;
	/** Child bytes decompressed or carved, tracked against the aggregate cap. */
	expandedBytes: number;
	/** True when a depth, count, per-file, or aggregate budget stopped the walk. */
	capped: boolean;
};

export type AnalysisRequest =
	| { kind: 'analyse'; id: number; name: string; bytes: ArrayBuffer; flagTags: string }
	| { kind: 'plane'; id: number; channel: number; bit: number }
	| { kind: 'extract'; id: number; channels: string; bit: number; msbFirst: boolean }
	| { kind: 'peel'; id: number; text: string; flagTags: string }
	| { kind: 'extractPalette'; id: number; msbFirst: boolean }
	| {
			kind: 'extractJpeg';
			id: number;
			includeDc: boolean;
			msbFirst: boolean;
	  }
	| { kind: 'withKey'; id: number; text: string; key: string; flagTags: string }
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
			/** Null when the file is not a ZIP archive. */
			zip: ZipArchive | null;
			/** Null when the file is not a PDF document. */
			pdf: PdfStructure | null;
			/** AES-CBC decryptions the file's own key and payload produced. Empty for most files. */
			aes: AesSolved[];
			sweep: Sweep | null;
			wall: PlaneWall | null;
			chi: ChiSquare | null;
			rs: RsAnalysis | null;
			audio: AudioSweep | null;
			spectrogram: Spectrogram | null;
			pixelError: string | null;
			audioError: string | null;
			/** Recursive analysis of files inside this file; null only when nothing was attempted. */
			nested: NestedAnalysis | null;
			/** Automatic per-frame and per-difference analysis for GIF files. */
			gif: GifAnalysis | null;
	  }
	| { id: number; status: 'peel'; input: string; peel: PeelResult }
	| { id: number; status: 'keyed'; key: string; attempts: KeyAttempt[] }
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
