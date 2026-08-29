import {
	isHeaderError,
	isJpegError,
	isWavError,
	type AnalysisResponse,
	type FlagHit
} from '$lib/worker/protocol';

type Analysis = Extract<AnalysisResponse, { status: 'ok' }>;

const clean = (value: string) => value.replaceAll('\r', '').replaceAll('```', "''' ");
const list = (items: string[]) => items.map((item) => `- ${item}`).join('\n');

export function writeupMarkdown(
	analysis: Analysis,
	flags: FlagHit[],
	derivedFlags: { text: string; origin: string }[]
): string {
	const sections: string[] = [
		`# Trawl analysis: ${clean(analysis.name)}`,
		'',
		`- Size: ${analysis.size.toLocaleString()} bytes`,
		`- Format: ${analysis.survey.format ?? 'unidentified'}`
	];

	if (analysis.structure && !isHeaderError(analysis.structure.header)) {
		sections.push(
			`- Dimensions: ${analysis.structure.header.width} × ${analysis.structure.header.height}`
		);
	}

	const candidates = [
		...flags.map((flag) => `${flag.text} (${flag.region}, offset 0x${flag.offset.toString(16)})`),
		...derivedFlags.map((flag) => `${flag.text} (${flag.origin})`)
	];
	sections.push('', '## Recovered candidates', candidates.length ? list(candidates) : 'None.');

	const findings: string[] = [];
	const structure = analysis.structure;
	if (structure?.trailing)
		findings.push(
			`${structure.trailing.length} bytes after IEND at 0x${structure.trailing.offset.toString(16)}`
		);
	for (const chunk of structure?.chunks ?? []) {
		if (!chunk.crcOk)
			findings.push(`CRC mismatch on ${chunk.kind} at 0x${chunk.offset.toString(16)}`);
	}
	if (structure?.ihdrRepair) {
		const repair = structure.ihdrRepair;
		findings.push(
			`IHDR ${repair.field} recovers to ${repair.recoveredWidth} × ${repair.recoveredHeight} from stored CRC ${repair.targetCrc}`
		);
	}
	for (const hit of analysis.survey.magic.filter((item) => item.embedded)) {
		findings.push(`Embedded ${hit.label}, ${hit.length} bytes at 0x${hit.offset.toString(16)}`);
	}
	if (analysis.survey.jpegTrailing)
		findings.push(`${analysis.survey.jpegTrailing.length} bytes after JPEG EOI`);
	sections.push(
		'',
		'## Container findings',
		findings.length ? list(findings) : 'No structural anomalies.'
	);

	const metadata = (analysis.survey.exif ?? [])
		.filter((entry) => entry.value.trim())
		.map((entry) => `${entry.name}: ${clean(entry.value)}`);
	sections.push('', '## Metadata', metadata.length ? list(metadata) : 'No EXIF metadata.');

	const stego: string[] = [];
	for (const candidate of analysis.sweep?.candidates ?? [])
		stego.push(
			`Pixel LSB ${candidate.channels}, bit ${candidate.bit}, ${candidate.msbFirst ? 'MSB' : 'LSB'} first: ${clean(candidate.reason)}`
		);
	if (analysis.chi?.detected)
		stego.push(
			`Chi-square estimates ${(analysis.chi.embeddedFraction * 100).toFixed(1)}% embedded`
		);
	if (analysis.rs?.detected)
		stego.push(`RS estimates ${(analysis.rs.rate * 100).toFixed(1)}% of low bits embedded`);
	for (const candidate of analysis.audio?.candidates ?? [])
		stego.push(`Audio LSB ${candidate.channels}, bit ${candidate.bit}: ${clean(candidate.reason)}`);
	for (const tone of analysis.audio?.tones ?? [])
		stego.push(
			`${tone.kind}: ${clean(tone.decoded)} (${Math.round(tone.confidence * 100)}% signal fit)`
		);
	const jpeg = analysis.jpeg && !isJpegError(analysis.jpeg) ? analysis.jpeg : null;
	for (const candidate of jpeg?.candidates ?? [])
		stego.push(`JPEG coefficient sweep: ${clean(candidate.reason)}`);
	for (const candidate of analysis.paletteStego?.candidates ?? [])
		stego.push(`Palette indices: ${clean(candidate.reason)}`);
	sections.push(
		'',
		'## Steganography',
		stego.length ? list(stego) : 'No detector produced a candidate.'
	);

	const archive: string[] = [];
	for (const entry of analysis.zip?.entries ?? []) {
		archive.push(
			`${entry.name}: ${entry.uncompressed.toLocaleString()} bytes, ${entry.method}${entry.undeclared ? ', not in directory' : ''}${entry.disagreement ? `, ${entry.disagreement}` : ''}`
		);
	}
	sections.push(
		'',
		'## Carved and archived artifacts',
		archive.length ? list(archive) : 'No ZIP entries.'
	);

	const wav = analysis.wav && !isWavError(analysis.wav) ? analysis.wav : null;
	if (wav)
		sections.push(
			'',
			'## Audio',
			`- ${wav.channels} channel(s), ${wav.sampleRate.toLocaleString()} Hz, ${wav.bitsPerSample}-bit`,
			`- Duration: ${wav.seconds.toFixed(3)} seconds`
		);

	sections.push('', '_Generated locally by Trawl. Verify candidates before submitting._', '');
	return sections.join('\n');
}
