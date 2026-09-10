import type {
	AesSolved,
	FlagHit,
	GifAnalysis,
	NestedArtifact,
	PcapCapture,
	PdfStructure,
	Structure,
	Survey,
	ZipArchive
} from '$lib/worker/protocol';
import type { AudioSweep, JpegStego, PaletteStego, Sweep } from '$lib/worker/protocol';
import { isJpegError } from '$lib/worker/protocol';

/**
 * The route a recovered flag was reached by, as ordered steps from the file to
 * the tool that read it.
 *
 * A flag is rarely just sitting in the bytes. It is inside a zip inside a
 * picture, or under three layers of encoding, or split across packets, and the
 * Cod-end shows the answer without showing the work. This reconstructs the work:
 * the containers opened and the detector that fired, so the find can be
 * retraced rather than taken on faith.
 */
export type SolvePath = {
	text: string;
	/** File first, detector last. The flag itself is shown separately. */
	steps: string[];
};

/** Everything a solve path can be built from. All optional: a source that is
 *  absent contributes nothing. */
export type SolveInput = {
	fileName: string;
	survey?: Survey | null;
	structure?: Structure | null;
	sweep?: Sweep | null;
	audio?: AudioSweep | null;
	jpeg?: JpegStego | { error: string } | null;
	paletteStego?: PaletteStego | null;
	gif?: GifAnalysis | null;
	aes?: AesSolved[];
	zip?: ZipArchive | null;
	pdf?: PdfStructure | null;
	pcap?: PcapCapture | null;
	nested?: { roots: NestedArtifact[] } | null;
};

/** A short label for the bit-reading combination a sweep candidate used. */
function lsbLabel(channels: string, bit: number, msbFirst?: boolean): string {
	const order = msbFirst === undefined ? '' : ` ${msbFirst ? 'msb' : 'lsb'} first`;
	return `${channels} bit ${bit}${order}`;
}

/**
 * Every recovered flag paired with the route it was reached by.
 *
 * The first path found for a flag wins, so a flag reachable two ways is shown by
 * whichever source is checked first here. The order runs specific to general:
 * a nested chain says more than a bare byte offset.
 */
export function buildSolvePaths(input: SolveInput): SolvePath[] {
	const { fileName } = input;
	const seen = new Set<string>();
	const paths: SolvePath[] = [];

	const add = (text: string, steps: string[]) => {
		if (seen.has(text)) return;
		seen.add(text);
		paths.push({ text, steps });
	};

	// Nested files: the recursive chain, which is the whole reason for this view.
	// The finding's origin already reads from the root file down.
	const walk = (artifact: NestedArtifact) => {
		for (const finding of artifact.findings) {
			const hops = finding.origin.split(' / ');
			add(finding.text, [...hops, finding.detector]);
		}
		for (const child of artifact.children) walk(child);
	};
	for (const root of input.nested?.roots ?? []) walk(root);

	// A file carried whole over a connection, or a flag reassembled from one.
	for (const stream of input.pcap?.streams ?? []) {
		for (const flag of stream.flags) {
			add(flag, [fileName, `TCP ${stream.src} → ${stream.dst}`, 'reassembled stream']);
		}
	}

	// Archive entries and PDF streams: opened, then scanned as their own files.
	for (const entry of input.zip?.entries ?? []) {
		for (const flag of entry.flags ?? []) {
			add(flag, [fileName, entry.name, 'byte scan']);
		}
	}
	for (const object of input.pdf?.objects ?? []) {
		for (const flag of object.flags ?? []) {
			add(flag, [fileName, `object ${object.number}`, 'inflated stream']);
		}
	}

	// AES that decrypted to something readable.
	for (const solved of input.aes ?? []) {
		for (const flag of solved.flags) {
			add(flag, [fileName, `AES-${solved.bits} CBC`, 'decrypted']);
		}
	}

	// The pixel, audio, coefficient and palette sweeps.
	for (const candidate of input.sweep?.candidates ?? []) {
		for (const flag of candidate.flags) {
			add(flag, [
				fileName,
				'pixels',
				`LSB ${lsbLabel(candidate.channels, candidate.bit, candidate.msbFirst)}`
			]);
		}
	}
	for (const candidate of input.audio?.candidates ?? []) {
		for (const flag of candidate.flags) {
			add(flag, [
				fileName,
				'samples',
				`LSB ${lsbLabel(candidate.channels, candidate.bit, candidate.msbFirst)}`
			]);
		}
	}
	for (const tone of input.audio?.tones ?? []) {
		if (/[A-Za-z0-9_]{3,}\{[^}]{4,}\}/.test(tone.decoded)) {
			add(tone.decoded, [fileName, 'samples', `${tone.kind} tones`]);
		}
	}
	if (input.jpeg && !isJpegError(input.jpeg)) {
		for (const candidate of input.jpeg.candidates) {
			for (const flag of candidate.flags) {
				add(flag, [fileName, 'JPEG coefficients', candidate.includeDc ? 'with DC' : 'skipping DC']);
			}
		}
	}
	for (const candidate of input.paletteStego?.candidates ?? []) {
		for (const flag of candidate.flags) {
			add(flag, [fileName, 'palette', `indices ${candidate.msbFirst ? 'msb' : 'lsb'} first`]);
		}
	}

	// GIF frames and the differences between them.
	for (const source of input.gif?.sources ?? []) {
		const where =
			source.kind === 'frame'
				? `frame ${source.from}`
				: `frames ${source.to} → ${source.from} difference`;
		for (const candidate of source.lsb.candidates) {
			for (const flag of candidate.flags) {
				add(flag, [
					fileName,
					`GIF ${where}`,
					`LSB ${lsbLabel(candidate.channels, candidate.bit, candidate.msbFirst)}`
				]);
			}
		}
	}

	// Flags read straight out of the file, wherever the scan placed them.
	const raw: FlagHit[] = [...(input.structure?.flags ?? []), ...(input.survey?.flags ?? [])];
	for (const hit of raw) {
		if (hit.credible) add(hit.text, [fileName, hit.region]);
	}

	return paths;
}
