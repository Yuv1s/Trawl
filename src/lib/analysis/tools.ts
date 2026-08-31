import {
	isHeaderError,
	isJpegError,
	isWavError,
	type AesSolved,
	type AudioSweep,
	type ChiSquare,
	type FlagHit,
	type GifAnalysis,
	type JpegError,
	type JpegStego,
	type NestedAnalysis,
	type NestedArtifact,
	type PaletteStego,
	type PdfStructure,
	type PlaneWall,
	type RsAnalysis,
	type Spectrogram,
	type Structure,
	type ZipArchive,
	type Survey,
	type Sweep,
	type WavError,
	type WavStructure
} from '$lib/worker/protocol';

export type ToolStatus = 'hit' | 'clear' | 'ready' | 'pending';

/**
 * `bytes` runs on anything. `pixels` needs a format with a decoder behind it.
 * `png` needs the chunk walker, which no other format has. `audio` needs samples.
 * `jpeg` needs the coefficient decoder.
 */
export type ToolScope = 'bytes' | 'pixels' | 'png' | 'audio' | 'jpeg' | 'zip' | 'pdf' | 'gif';

/**
 * The two halves of the rack. Survey reads the file as it sits on disk;
 * Cuttlefish goes after what is hidden inside the data itself.
 */
export type ToolGroup = 'survey' | 'cuttlefish';

export const GROUP_LABEL: Record<ToolGroup, string> = {
	survey: 'Survey',
	cuttlefish: 'Cuttlefish'
};

export const GROUP_BLURB: Record<ToolGroup, string> = {
	survey: 'What the file says about itself',
	cuttlefish: 'What someone hid inside it'
};

export type Tool = {
	id: string;
	name: string;
	measures: string;
	scope: ToolScope;
	group: ToolGroup;
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

const NO_WALKER = 'PNG only, for now';
const NO_DECODER = 'no decoder for this format';
const NO_AUDIO = 'not an audio file';
const NO_ARCHIVE = 'not a ZIP archive';
const NO_PDF = 'not a PDF document';
const NO_COEFFICIENTS = 'no readable JPEG coefficients';

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

/** Everything the rack reads. All of it optional: a tool with nothing to read
 *  stands down and says why. */
export type Findings = {
	survey: Survey;
	structure?: Structure | null;
	wav?: WavStructure | WavError | null;
	jpeg?: JpegStego | JpegError | null;
	paletteStego?: PaletteStego | null;
	aes?: AesSolved[];
	sweep?: Sweep | null;
	wall?: PlaneWall | null;
	chi?: ChiSquare | null;
	rs?: RsAnalysis | null;
	audio?: AudioSweep | null;
	spectrogram?: Spectrogram | null;
	zip?: ZipArchive | null;
	pdf?: PdfStructure | null;
	nested?: NestedAnalysis | null;
	gif?: GifAnalysis | null;
};

/** Every finding anywhere in the nested tree, each carrying its full path. */
export function nestedFindings(roots: NestedArtifact[]): { text: string; origin: string }[] {
	const out: { text: string; origin: string }[] = [];
	const walk = (artifact: NestedArtifact, path: string) => {
		const here = path ? `${path} / ${artifact.name}` : artifact.name;
		for (const finding of artifact.findings)
			out.push({ text: finding.text, origin: finding.origin });
		for (const child of artifact.children) walk(child, here);
	};
	for (const root of roots) walk(root, '');
	return out;
}

/** Whether the automatic walk stopped because a budget ran out. */
function nestedCapped(nested: NestedAnalysis | null): boolean {
	return nested?.capped ?? false;
}

/**
 * Whether an archive shows any sign of having been edited.
 *
 * A ZIP describes itself twice, in a local header before each file and again in
 * the central directory at the end. Readers use the directory, so an entry
 * missing from it, or a size the two disagree about, is the whole point of
 * looking.
 */
function archiveOdd(zip: ZipArchive): boolean {
	return (
		zip.prefix > 0 ||
		zip.trailing > 0 ||
		zip.declared !== zip.entries.filter((e) => !e.undeclared).length ||
		zip.entries.some((e) => e.undeclared || e.disagreement !== null) ||
		zip.entries.some((e) => (e.flags?.length ?? 0) > 0)
	);
}

/** What to say about an archive in one line of a tool rack. */
function archiveNote(zip: ZipArchive): string {
	const withFlag = zip.entries.filter((e) => (e.flags?.length ?? 0) > 0).length;
	if (withFlag > 0) {
		return `flag in ${withFlag === 1 ? 'an entry' : `${withFlag} entries`}`;
	}
	const hidden = zip.entries.filter((e) => e.undeclared).length;
	if (hidden > 0) {
		return `${hidden} not in the directory`;
	}
	if (zip.entries.some((e) => e.disagreement !== null)) {
		return 'the two copies disagree';
	}
	if (zip.trailing > 0) {
		return `${zip.trailing.toLocaleString()} B appended`;
	}
	if (zip.prefix > 0) {
		return `starts ${zip.prefix.toLocaleString()} B in`;
	}

	const count = zip.entries.length;
	return `${count} ${count === 1 ? 'entry' : 'entries'}, nothing out of place`;
}

/**
 * Whether a PDF shows any sign of carrying more than it currently declares.
 *
 * A reader follows the trailer and the cross-reference table; it does not
 * read the file. An object those no longer list, more than one `%%EOF`, or
 * bytes past the last one are all ways a document holds something a reader
 * would never show.
 */
function pdfOdd(pdf: PdfStructure): boolean {
	return (
		pdf.objects.some((o) => o.orphaned || (o.flags?.length ?? 0) > 0) ||
		pdf.revisions > 1 ||
		pdf.trailing > 0 ||
		pdf.encrypted ||
		pdf.embeddedFiles.length > 0
	);
}

/** What to say about a PDF in one line of a tool rack. */
function pdfNote(pdf: PdfStructure): string {
	const withFlag = pdf.objects.filter((o) => (o.flags?.length ?? 0) > 0).length;
	if (withFlag > 0) {
		return `flag in ${withFlag === 1 ? 'a stream' : `${withFlag} streams`}`;
	}
	const orphaned = pdf.objects.filter((o) => o.orphaned).length;
	if (orphaned > 0) {
		return `${orphaned} not in the cross-reference table`;
	}
	if (pdf.embeddedFiles.length > 0) {
		return `${pdf.embeddedFiles.length} attached`;
	}
	if (pdf.trailing > 0) {
		return `${pdf.trailing.toLocaleString()} B appended`;
	}
	if (pdf.revisions > 1) {
		return `${pdf.revisions} revisions`;
	}
	if (pdf.encrypted) {
		return 'encrypted';
	}

	const count = pdf.objects.length;
	return `${count} object${count === 1 ? '' : 's'}, nothing out of place`;
}

export function tools(found: Findings): Tool[] {
	const { survey, structure = null, sweep = null, wall = null, chi = null, rs = null } = found;
	const { audio = null, spectrogram = null, paletteStego = null, zip = null } = found;
	const { pdf = null } = found;
	const { nested = null, gif = null } = found;
	const aes = found.aes ?? [];
	const wav = found.wav && !isWavError(found.wav) ? found.wav : null;
	const jpeg = found.jpeg && !isJpegError(found.jpeg) ? found.jpeg : null;

	const credible = flagsOf(survey, structure).filter((f) => f.credible);
	const embedded = survey.magic.filter((m) => m.embedded);
	const peakEntropy = survey.entropy.values.length ? Math.max(...survey.entropy.values) : 0;
	const writtenFields = (survey.exif ?? []).filter(
		(e) => e.textual && WRITTEN_BY_HAND.has(e.name) && e.value.trim() !== ''
	);
	const jpegish = survey.jpegSegments.length > 0;
	const duplicateColours = structure?.palette?.duplicates.length ?? 0;
	// Any format we can turn into pixels unlocks the whole pixel half of the rack.
	const decoded = wall !== null || sweep !== null;

	const headerBroken = !structure || isHeaderError(structure.header);
	const badCrc = structure?.chunks.filter((c) => !c.crcOk).length ?? 0;
	const sweepHits = sweep?.candidates.length ?? 0;

	const audioHits = audio?.candidates.length ?? 0;
	const wavText = wav?.text.length ?? 0;
	const jpegHits = jpeg?.candidates.length ?? 0;
	const paletteHits = paletteStego?.candidates.length ?? 0;

	/** Format-level tools report why they stood down rather than disappearing. */
	type Partial = Omit<Tool, 'scope' | 'group'>;

	const png = (tool: Partial, group: ToolGroup = 'survey'): Tool =>
		structure
			? { ...tool, scope: 'png', group }
			: { ...tool, scope: 'png', group, status: 'pending', value: NO_WALKER };

	const pixel = (tool: Partial): Tool =>
		decoded
			? { ...tool, scope: 'pixels', group: 'cuttlefish' }
			: { ...tool, scope: 'pixels', group: 'cuttlefish', status: 'pending', value: NO_DECODER };

	const coefficient = (tool: Partial): Tool =>
		jpeg
			? { ...tool, scope: 'jpeg', group: 'cuttlefish' }
			: { ...tool, scope: 'jpeg', group: 'cuttlefish', status: 'pending', value: NO_COEFFICIENTS };

	const archive = (tool: Partial): Tool =>
		zip
			? { ...tool, scope: 'zip', group: 'survey' }
			: { ...tool, scope: 'zip', group: 'survey', status: 'pending', value: NO_ARCHIVE };

	const pdfTool = (tool: Partial): Tool =>
		pdf
			? { ...tool, scope: 'pdf', group: 'survey' }
			: { ...tool, scope: 'pdf', group: 'survey', status: 'pending', value: NO_PDF };

	const sound = (tool: Partial, group: ToolGroup = 'cuttlefish'): Tool =>
		wav
			? { ...tool, scope: 'audio', group }
			: { ...tool, scope: 'audio', group, status: 'pending', value: NO_AUDIO };

	return [
		{
			id: 'flags',
			name: 'Flag scan',
			measures: 'Looks for flag{...} text in the file',
			scope: 'bytes',
			group: 'survey',
			status: credible.length ? 'hit' : 'clear',
			value: credible.length
				? `${credible.length} candidate${credible.length === 1 ? '' : 's'}`
				: 'none in readable data'
		},
		archive({
			id: 'archive',
			name: 'Archive entries',
			measures: 'Reads a ZIP twice and reports where the two copies disagree',
			status: zip && archiveOdd(zip) ? 'hit' : 'clear',
			value: zip ? archiveNote(zip) : ''
		}),
		pdfTool({
			id: 'pdf',
			name: 'PDF structure',
			measures:
				'Walks a PDF for every object, and reports what the cross-reference table leaves out',
			status: pdf && pdfOdd(pdf) ? 'hit' : 'clear',
			value: pdf ? pdfNote(pdf) : ''
		}),
		{
			id: 'magic',
			name: 'Embedded files',
			measures: 'Finds files hidden inside this one, and saves them',
			scope: 'bytes',
			group: 'survey',
			status: embedded.length ? 'hit' : 'clear',
			value: embedded.length ? `${embedded.length} to extract` : 'none'
		},
		{
			id: 'gif',
			name: 'GIF frames',
			measures: 'Checks every frame and the gaps between them for hidden bits',
			scope: 'gif',
			group: 'cuttlefish',
			status: gifFrameStatus(gif),
			value: gifFrameValue(gif, nested)
		},
		pixel({
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
		pixel({
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
		pixel({
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
		pixel({
			id: 'planes',
			name: 'Bit-plane wall',
			measures: 'Shows each layer of bits as a picture',
			status: wall ? 'ready' : 'pending',
			value: wall ? `${wall.planes.length} planes` : 'pixels unavailable'
		}),
		{
			id: 'aes',
			name: 'AES decrypt',
			measures: 'Finds a key and payload in the file and runs AES-CBC',
			scope: 'bytes',
			group: 'cuttlefish',
			status: aes.length ? 'hit' : 'clear',
			value: aes.length ? `${aes.length} decrypted` : 'no key and payload found'
		},
		{
			id: 'exif',
			name: 'Metadata',
			measures: 'Camera details and notes saved with the photo',
			scope: 'bytes',
			group: 'survey',
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
			group: 'survey',
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
		coefficient({
			id: 'jsteg',
			name: 'JSteg sweep',
			measures: 'Reads hidden bits out of a JPEG after compression',
			status: jpegHits ? 'hit' : jpeg ? 'clear' : 'pending',
			value: jpegHits
				? `${jpegHits} of ${jpeg?.combinations} combinations`
				: jpeg
					? `${jpeg.combinations} swept, none carried data`
					: 'coefficients unreadable'
		}),
		coefficient({
			id: 'jpeg-chi',
			name: 'Coefficient statistics',
			measures: 'Statistical test on a JPEG, plus the value counts',
			status: jpeg?.chi.detected ? 'hit' : jpeg ? 'ready' : 'pending',
			value: jpeg?.chi.detected
				? `${(jpeg.chi.embeddedFraction * 100).toFixed(0)}% embedded`
				: jpeg
					? `${jpeg.blocks.toLocaleString()} blocks over ${jpeg.scans} scan${jpeg.scans === 1 ? '' : 's'}`
					: 'coefficients unreadable'
		}),
		sound({
			id: 'spectrogram',
			name: 'Spectrogram & tones',
			measures: 'Draws the sound and reads Morse or DTMF tones',
			status: audio?.tones?.length ? 'hit' : spectrogram ? 'ready' : 'pending',
			value: audio?.tones?.length
				? audio.tones!.map((tone) => `${tone.kind}: ${tone.decoded}`).join(' · ')
				: spectrogram
					? `${spectrogram.seconds.toFixed(1)}s up to ${(spectrogram.maxFrequency / 1000).toFixed(1)} kHz`
					: 'the clip is too short to draw'
		}),
		sound({
			id: 'audio-lsb',
			name: 'Audio LSB sweep',
			measures: 'Tries every way of reading hidden bits from the samples',
			status: audioHits ? 'hit' : audio ? 'clear' : 'pending',
			value: audioHits
				? `${audioHits} of ${audio?.combinations} combinations`
				: audio
					? `${audio.combinations} swept, none carried data`
					: 'samples unreadable'
		}),
		sound(
			{
				id: 'riff',
				name: 'RIFF chunks',
				measures: 'Lists every part of the sound file',
				status: wavText || wav?.trailing ? 'hit' : 'ready',
				value: wavText
					? `${wavText} text ${wavText === 1 ? 'string' : 'strings'}`
					: wav?.trailing
						? `${wav.trailing.length.toLocaleString()} bytes past the end`
						: `${wav?.chunks.length} chunks`
			},
			'survey'
		),
		{
			id: 'entropy',
			name: 'Entropy window',
			measures: 'Finds compressed or encrypted regions',
			scope: 'bytes',
			group: 'survey',
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
		png(
			{
				id: 'palette',
				name: 'Palette',
				measures: 'Repeated colours that carry hidden bits',
				// A duplicated colour is capacity, not a finding. Only a readable
				// payload out of the index choices counts as a hit.
				status: paletteHits ? 'hit' : duplicateColours || structure?.palette ? 'ready' : 'clear',
				value: paletteHits
					? `${paletteHits} of ${paletteStego?.combinations} combinations`
					: duplicateColours
						? `${duplicateColours} duplicated, nothing read`
						: structure?.palette
							? `${structure.palette.entries} colours`
							: 'not an indexed image'
			},
			'cuttlefish'
		),
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
			group: 'survey',
			status: 'ready',
			value: survey.strings.wide
				? `${survey.strings.total.toLocaleString()}, ${survey.strings.wide} wide`
				: survey.strings.total.toLocaleString()
		},
		pixel({
			id: 'pixels',
			name: 'Pixel decode',
			measures: 'Reads exact pixel values, nothing altered',
			status: headerBroken ? 'pending' : 'ready',
			value: headerBroken ? 'blocked' : 'verified'
		})
	];
}

function gifFrameStatus(gif: GifAnalysis | null): ToolStatus {
	if (!gif) return 'pending';
	if (gif.error) return 'clear';
	if (gif.sources.length === 0) return 'clear';
	if (gif.sources.some((s) => s.lsb.candidates.length > 0 || s.chi?.detected || s.rs?.detected))
		return 'hit';
	return 'clear';
}

function gifFrameValue(gif: GifAnalysis | null, nested: NestedAnalysis | null): string {
	if (!gif) return 'pixels unavailable';
	if (gif.error) return `error: ${gif.error}`;
	if (gif.sources.length === 0) return 'no frames analysed';
	const frames = gif.sources.filter((s) => s.kind === 'frame').length;
	const diffs = gif.sources.filter((s) => s.kind === 'difference').length;
	let msg = `${frames} frame${frames === 1 ? '' : 's'} analysed`;
	if (diffs > 0) msg += `, ${diffs} difference${diffs === 1 ? '' : 's'} checked`;
	if (gif.capped) msg += ' · capped';
	if (nestedCapped(nested)) msg += ' · walk capped';
	return msg;
}

/** Named so the rack shows the whole instrument, not only the parts that work. */
export const PLANNED: Tool[] = [
	{
		id: 'zip',
		name: 'Archive walk',
		measures: 'Looks inside ZIP and PDF files',
		scope: 'bytes',
		group: 'survey',
		status: 'pending',
		value: ''
	}
];
