<script lang="ts">
	import { onMount } from 'svelte';
	import { getScannerToken, getTourChoice, setTourChoice } from '$lib';
	import { flagTagsParameter, matchesFlagTag, readFlagTags, writeFlagTags } from '$lib/flag-config';
	import { writeupMarkdown } from '$lib/analysis/writeup';
	import AnalysisWorker from '$lib/worker/analysis.worker?worker';
	import DropSurface from '$lib/components/DropSurface.svelte';
	import WebRecon from '$lib/components/WebRecon.svelte';
	import PeelPanel from '$lib/components/PeelPanel.svelte';
	import HeaderControls from '$lib/components/HeaderControls.svelte';
	import TourPrompt from '$lib/components/TourPrompt.svelte';
	import TourOverlay from '$lib/components/TourOverlay.svelte';
	import DownloadPrompt from '$lib/components/DownloadPrompt.svelte';
	import { buildPixelDemo, type SampleFile, type SampleOpen } from '$lib/tour/demo';
	import type { TourStep } from '$lib/tour/types';
	import { attack as attackRsa, looksLikeRsa, type Report } from '$lib/analysis/rsa';
	import Logo from '$lib/components/Logo.svelte';
	import banner from '$lib/assets/TrawlBanner.png';
	import ToolRack from '$lib/components/ToolRack.svelte';
	import Recovered from '$lib/components/Recovered.svelte';
	import ChunkList from '$lib/components/ChunkList.svelte';
	import ZipView from '$lib/components/ZipView.svelte';
	import PdfView from '$lib/components/PdfView.svelte';
	import GifFramesView from '$lib/components/GifFramesView.svelte';
	import HexView from '$lib/components/HexView.svelte';
	import StringsView from '$lib/components/StringsView.svelte';
	import SweepView from '$lib/components/SweepView.svelte';
	import SpectrogramView from '$lib/components/SpectrogramView.svelte';
	import RiffView from '$lib/components/RiffView.svelte';
	import CoefficientView from '$lib/components/CoefficientView.svelte';
	import PlaneWall from '$lib/components/PlaneWall.svelte';
	import ChiTrace from '$lib/components/ChiTrace.svelte';
	import RsView from '$lib/components/RsView.svelte';
	import EntropyTrace from '$lib/components/EntropyTrace.svelte';
	import MagicList from '$lib/components/MagicList.svelte';
	import ExifView from '$lib/components/ExifView.svelte';
	import PaletteView from '$lib/components/PaletteView.svelte';
	import JpegView from '$lib/components/JpegView.svelte';
	import { flagsOf, nestedFindings, PLANNED, tools, WRITTEN_BY_HAND } from '$lib/analysis/tools';
	import {
		COLOR_TYPES,
		isHeaderError,
		isJpegError,
		type AnalysisResponse,
		type KeyAttempt,
		type PeelResult
	} from '$lib/worker/protocol';

	/** Plane, extract and peel responses update a panel or open their own view;
	 *  none of them become the file-analysis state. */
	type Analysis = Exclude<
		AnalysisResponse,
		{ status: 'plane' } | { status: 'extract' } | { status: 'peel' } | { status: 'keyed' }
	>;

	type View =
		| { phase: 'idle' }
		| { phase: 'working'; name: string }
		| { phase: 'done'; result: Analysis; bytes: Uint8Array }
		/** A pasted string, which has no file behind it and no tool rack. */
		| { phase: 'text'; input: string; peel: PeelResult; rsa: Report | null }
		/** Reaching a live site, which runs against a scanner the person starts themselves. */
		| { phase: 'web' };

	let view = $state<View>({ phase: 'idle' });
	let activeTool = $state('flags');
	let selectedChunk = $state(-1);
	let openPlane = $state<{ channel: number; bit: number; pixels: Uint8Array | null } | null>(null);
	let extracted = $state<{ label: string; text: string } | null>(null);
	/** A key somebody typed, and what each cipher made of it. */
	let keyed = $state<{ key: string; attempts: KeyAttempt[] } | null>(null);

	let showTourPrompt = $state(false);
	let tourPending = $state(false);
	let tourActive = $state(false);
	let showDownloadPrompt = $state(false);
	let flagTags = $state<string[]>([]);

	/** Join current flag tags into the single string the worker expects. */
	function flagTagsString(): string {
		return flagTagsParameter(flagTags);
	}

	let worker: Worker | null = null;
	let ticket = 0;
	let pending: Promise<Uint8Array> = Promise.resolve(new Uint8Array());

	function ensureWorker(): Worker {
		if (!worker) {
			worker = new AnalysisWorker();
			worker.addEventListener('message', (event: MessageEvent<AnalysisResponse>) => {
				const result = event.data;
				if (result.id !== ticket) return;

				if (result.status === 'keyed') {
					keyed = { key: result.key, attempts: result.attempts };
					return;
				}

				if (result.status === 'peel') {
					// RSA runs here rather than in the worker: it needs bignum
					// arithmetic, and the platform's BigInt is the only one there is.
					view = {
						phase: 'text',
						input: result.input,
						peel: result.peel,
						rsa: looksLikeRsa(result.input) ? attackRsa(result.input) : null
					};
					return;
				}

				if (result.status === 'plane') {
					if (openPlane?.channel === result.channel && openPlane?.bit === result.bit) {
						openPlane = { ...openPlane, pixels: result.pixels };
					}
					return;
				}

				if (result.status === 'extract') {
					// Non-printable bytes become dots so a binary payload stays legible
					// as a shape rather than filling the pane with control characters.
					const text = Array.from(result.bytes, (b) =>
						b === 10 || b === 13 || (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.'
					)
						.join('')
						.replace(/\.{80,}/g, (run) => `${'.'.repeat(24)} [${run.length} unreadable bytes] `);

					extracted = { label: result.label, text };
					return;
				}

				const analysis: Analysis = result;
				pending.then((bytes) => {
					view = { phase: 'done', result: analysis, bytes };
					openPlane = null;
					extracted = null;
					if (analysis.status !== 'ok') return;

					selectedChunk = analysis.structure?.chunks[0]?.offset ?? -1;
					const flags = flagsOf(analysis.survey, analysis.structure);
					const written = (analysis.survey.exif ?? []).some(
						(e) => e.textual && WRITTEN_BY_HAND.has(e.name) && e.value.trim() !== ''
					);

					const isWav = analysis.wav !== null;

					// Open whichever tool found something, most conclusive first. An
					// audio file with nothing else to show lands on the spectrogram,
					// since that is the one panel a person has to read themselves.
					const zipFlagged = analysis.zip?.entries.some((e) => (e.flags?.length ?? 0) > 0);

					activeTool = flags.some((f) => f.credible)
						? 'flags'
						: analysis.aes.length
							? 'aes'
							: zipFlagged
								? 'archive'
								: analysis.sweep?.candidates.length
									? 'lsb'
									: analysis.audio?.candidates.length
										? 'audio-lsb'
										: analysis.jpeg &&
											  !isJpegError(analysis.jpeg) &&
											  analysis.jpeg.candidates.length
											? 'jsteg'
											: analysis.paletteStego?.candidates.length
												? 'palette'
												: written
													? 'exif'
													: analysis.survey.jpegComments.length
														? 'jpeg'
														: analysis.chi?.detected
															? 'chi'
															: analysis.rs?.detected
																? 'rs'
																: analysis.survey.magic.some((m) => m.embedded)
																	? 'magic'
																	: isWav
																		? 'spectrogram'
																		: analysis.structure
																			? 'chunks'
																			: 'strings';
				});
			});
		}
		return worker;
	}

	function acceptText(text: string) {
		const id = ++ticket;
		keyed = null;
		view = { phase: 'working', name: 'pasted text' };
		const req = {
			kind: 'peel',
			id,
			text,
			flagTags: flagTagsString()
		} satisfies import('$lib/worker/protocol').AnalysisRequest;
		ensureWorker().postMessage(req);
	}

	/** Applies a key the reader already has, which no amount of text would give up. */
	function requestKey(key: string) {
		if (view.phase !== 'text') return;
		keyed = null;
		const req = {
			kind: 'withKey',
			id: ticket,
			text: view.input,
			key,
			flagTags: flagTagsString()
		} satisfies import('$lib/worker/protocol').AnalysisRequest;
		ensureWorker().postMessage(req);
	}

	async function accept(file: File) {
		const buffer = await file.arrayBuffer();
		analyseBytes(new Uint8Array(buffer), file.name);
	}

	/**
	 * The same path a dropped file takes, from bytes already in hand. Remora uses
	 * it to hand an image it pulled off a site straight to the offline tools, so
	 * a picture on a target is analysed exactly like one from disk.
	 */
	function analyseBytes(bytes: Uint8Array, name: string) {
		const id = ++ticket;
		view = { phase: 'working', name };

		const copy = bytes.slice();
		pending = Promise.resolve(copy);
		const req = {
			kind: 'analyse',
			id,
			name,
			bytes: copy.buffer,
			flagTags: flagTagsString()
		} satisfies import('$lib/worker/protocol').AnalysisRequest;
		ensureWorker().postMessage(req);
	}

	/** Where the scanner listens, for a tab opened to analyse a target's image. */
	const SCANNER_URL = (import.meta.env.VITE_SCANNER_URL ?? 'http://localhost:8099').replace(
		/\/$/,
		''
	);

	/**
	 * A tab opened by Remora's "Check with Trawl" carries the image's address in
	 * `?analyse=`. This fetches it through the scanner, the one thing that can
	 * reach the target, and runs it through the offline tools like a dropped file,
	 * so the recon list is left untouched in the tab it came from.
	 */
	function startTour() {
		setTourChoice('tour');
		showTourPrompt = false;
		tourPending = true;
		const demo = buildPixelDemo();
		analyseBytes(demo.bytes, demo.name);
	}

	function skipTour() {
		setTourChoice('skip');
		showTourPrompt = false;
	}

	function finishTour() {
		tourActive = false;
		showDownloadPrompt = true;
	}

	/** Load a sample straight into the tools, so a newcomer can watch them run
	 *  without downloading a file and dropping it back in. A paste sample goes to
	 *  Mantis as text, exactly as if its one line had been pasted in. */
	function runSample(file: SampleFile, open: SampleOpen = 'drop') {
		showDownloadPrompt = false;
		if (open === 'paste') acceptText(new TextDecoder().decode(file.bytes).trim());
		else analyseBytes(file.bytes, file.name);
	}

	$effect(() => {
		if (view.phase === 'done' && tourPending) {
			tourPending = false;
			tourActive = true;
		}
	});

	const tourSteps: TourStep[] = [
		{
			target: '[data-tour="identity"]',
			title: 'One file, every tool at once',
			body: 'This is a sample image with a flag hidden in its low bits. Every tool in the rack already ran against it before you saw the page.'
		},
		{
			target: '[data-tour="recovered"]',
			title: 'Anything credible floats to the top',
			body: 'A flag shows up here the moment any tool finds one, no matter which tool it was. This one came out of the red channel.'
		},
		{
			target: '[data-tour="rack"]',
			title: 'Every tool that ran',
			body: "Tools that hit are marked. Tools that don't apply to this file say why instead of just disappearing. Click through any of them.",
			onenter: () => (activeTool = 'lsb')
		},
		{
			target: '[data-tour="pane"]',
			title: 'LSB sweep',
			body: 'It tries every channel, bit position and order at once: the whole space a hidden message could sit in. Hit Extract on any result to turn it into text.',
			onenter: () => (activeTool = 'lsb')
		},
		{
			target: '[data-tour="pane"]',
			title: 'Chi-square attack',
			body: "This one doesn't read the message. It estimates how much of the image carries a payload, so a flat trace just means nothing at this scale, not that nothing is hidden.",
			onenter: () => (activeTool = 'chi')
		},
		{
			target: '[data-tour="pane"]',
			title: 'Bit-plane wall',
			body: 'Every bit plane of every channel, drawn as its own picture. A hidden payload usually looks like noise where the image should have structure, or the reverse.',
			onenter: () => (activeTool = 'planes')
		},
		{
			target: '[data-tour="theme-github"]',
			title: 'Theme and source',
			body: 'Switch between light and dark from here, or open the repository on GitHub.'
		},
		{
			target: '[data-tour="new-file"]',
			title: 'New file',
			body: "This clears the current file and takes you back to the start screen, the same place you can drop a file, paste a string, or scan a live site. Finish up and we'll leave a couple more sample files for you to try, each one hiding its flag somewhere different."
		}
	];

	onMount(() => {
		flagTags = readFlagTags();
		const address = new URLSearchParams(window.location.search).get('analyse');
		if (!address) {
			if (getTourChoice() === null) showTourPrompt = true;
			return;
		}

		const name = decodeURIComponent(address.split('/').pop()?.split('?')[0] || 'image');
		view = { phase: 'working', name };

		void (async () => {
			try {
				const token = getScannerToken();
				if (!token) throw new Error('scanner is not paired');
				const res = await fetch(`${SCANNER_URL}/fetch?url=${encodeURIComponent(address)}`, {
					headers: { Authorization: `Bearer ${token}` }
				});
				if (!res.ok) throw new Error('fetch failed');
				analyseBytes(new Uint8Array(await res.arrayBuffer()), name);
			} catch {
				view = { phase: 'idle' };
			}
		})();
	});

	function updateFlagTags(tags: string[]) {
		flagTags = writeFlagTags(tags);
	}

	function requestPlane(channel: number, bit: number) {
		openPlane = { channel, bit, pixels: null };
		ensureWorker().postMessage({ kind: 'plane', id: ticket, channel, bit });
	}

	function repairIhdr() {
		if (view.phase !== 'done' || view.result.status !== 'ok') return;
		const repair = view.result.structure?.ihdrRepair;
		if (!repair) return;

		const name = `${view.result.name} · repaired`;
		const id = ++ticket;
		view = { phase: 'working', name };
		ensureWorker().postMessage({
			kind: 'patchIhdr',
			id,
			name,
			width: repair.recoveredWidth,
			height: repair.recoveredHeight
		});
	}

	function requestExtract(channels: string, bit: number, msbFirst: boolean) {
		extracted = null;
		ensureWorker().postMessage({ kind: 'extract', id: ticket, channels, bit, msbFirst });
	}

	function requestExtractPalette(msbFirst: boolean) {
		extracted = null;
		ensureWorker().postMessage({ kind: 'extractPalette', id: ticket, msbFirst });
	}

	function requestExtractJpeg(includeDc: boolean, msbFirst: boolean) {
		extracted = null;
		ensureWorker().postMessage({ kind: 'extractJpeg', id: ticket, includeDc, msbFirst });
	}

	function requestExtractAudio(
		label: string,
		channelIndex: number | null,
		bit: number,
		msbFirst: boolean
	) {
		extracted = null;
		ensureWorker().postMessage({
			kind: 'extractAudio',
			id: ticket,
			label,
			channelIndex,
			bit,
			msbFirst
		});
	}

	function reset() {
		keyed = null;
		view = { phase: 'idle' };
	}

	/** Hands the current analysis off as Markdown, to the clipboard or as a file. */
	async function exportWriteup(action: 'copy' | 'download'): Promise<void> {
		if (view.phase !== 'done' || view.result.status !== 'ok') return;
		const markdown = writeupMarkdown(view.result, allFlags, sweepFlags);

		if (action === 'copy') {
			await navigator.clipboard.writeText(markdown);
			return;
		}

		const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown' }));
		const link = document.createElement('a');
		const base = view.result.name.replace(/\.[a-z0-9]+$/i, '') || 'analysis';
		link.href = url;
		link.download = `${base}-trawl.md`;
		link.click();
		requestAnimationFrame(() => URL.revokeObjectURL(url));
	}

	function pick(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		if (file) accept(file);
		input.value = '';
	}

	function droppedFile(event: DragEvent) {
		event.preventDefault();
		const file = event.dataTransfer?.files?.[0];
		if (file) accept(file);
	}

	function pastedFile(event: ClipboardEvent) {
		const target = event.target as HTMLElement | null;
		if (target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA') return;
		const file = event.clipboardData?.files?.[0];
		if (file) accept(file);
	}

	const survey = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.survey : null
	);
	const structure = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.structure : null
	);

	const sweep = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.sweep : null
	);
	const wall = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.wall : null
	);
	const chi = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.chi : null
	);
	const rs = $derived(view.phase === 'done' && view.result.status === 'ok' ? view.result.rs : null);
	const pixelError = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.pixelError : null
	);

	const wav = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.wav : null
	);
	const audio = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.audio : null
	);
	const spectrogram = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.spectrogram : null
	);
	const jpegRaw = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.jpeg : null
	);
	const jpeg = $derived(jpegRaw && !isJpegError(jpegRaw) ? jpegRaw : null);
	const jpegError = $derived(jpegRaw && isJpegError(jpegRaw) ? jpegRaw.error : null);

	const paletteStego = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.paletteStego : null
	);

	const zip = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.zip : null
	);

	const pdf = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.pdf : null
	);

	const nested = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.nested : null
	);

	const gif = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.gif : null
	);

	const aes = $derived(view.phase === 'done' && view.result.status === 'ok' ? view.result.aes : []);

	const audioError = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.audioError : null
	);

	/** The decoder knows the size for every format; the PNG header only for one. */
	const dimensions = $derived.by(() => {
		if (wall) return { width: wall.width, height: wall.height };
		if (!structure || isHeaderError(structure.header)) return { width: 0, height: 0 };
		return { width: structure.header.width, height: structure.header.height };
	});

	const built = $derived(
		survey
			? tools({
					survey,
					structure,
					wav,
					jpeg: jpegRaw,
					paletteStego,
					sweep,
					wall,
					chi,
					rs,
					audio,
					spectrogram,
					zip,
					pdf,
					aes,
					nested,
					gif
				})
			: []
	);
	const current = $derived(built.find((t) => t.id === activeTool) ?? null);

	const allFlags = $derived(survey ? flagsOf(survey, structure) : []);
	const credibleFlags = $derived(
		allFlags.filter((f) => f.credible && matchesFlagTag(f.text, flagTags))
	);
	const suppressedFlags = $derived(allFlags.filter((f) => !f.credible));
	/** Every sweep find, each carrying the name of the sweep that turned it up. */
	/** One line per distinct flag in the cod-end. The same flag read two ways, a
	 *  GIF frame and the difference that also carries it, collapses to the first. */
	function uniqueByText<T extends { text: string }>(items: T[]): T[] {
		const out: T[] = [];
		for (const item of items) if (!out.some((kept) => kept.text === item.text)) out.push(item);
		return out;
	}

	const sweepFlags = $derived(
		uniqueByText(
			[
				...(sweep?.candidates.flatMap((c) =>
					c.flags.map((text) => ({ text, origin: 'from the pixel sweep' }))
				) ?? []),
				...(audio?.candidates.flatMap((c) =>
					c.flags.map((text) => ({ text, origin: 'from the audio sweep' }))
				) ?? []),
				...(audio?.tones?.flatMap((tone) =>
					/[A-Za-z0-9_]{3,}\{[^}]{4,}\}/.test(tone.decoded)
						? [{ text: tone.decoded, origin: `from ${tone.kind} tones` }]
						: []
				) ?? []),
				...(jpeg?.candidates.flatMap((c) =>
					c.flags.map((text) => ({ text, origin: 'from the JPEG coefficients' }))
				) ?? []),
				...(paletteStego?.candidates.flatMap((c) =>
					c.flags.map((text) => ({ text, origin: 'from the palette indices' }))
				) ?? []),
				...(gif?.sources.flatMap((source) => {
					const origin =
						source.kind === 'frame'
							? `GIF frame ${source.from}`
							: `the difference between GIF frames ${source.to} and ${source.from}`;
					return source.lsb.candidates.flatMap((c) =>
						c.flags.map((text) => ({ text, origin: `from ${origin}` }))
					);
				}) ?? []),
				...(aes?.flatMap((s) => s.flags.map((text) => ({ text, origin: 'from AES decryption' }))) ??
					[]),
				...(zip?.entries.flatMap((e) =>
					(e.flags ?? []).map((text) => ({ text, origin: `from ${e.name}, inside the archive` }))
				) ?? []),
				...(pdf?.objects.flatMap((o) =>
					(o.flags ?? []).map((text) => ({
						text,
						origin: `from object ${o.number}, inside the PDF stream`
					}))
				) ?? []),
				...nestedFindings(nested?.roots ?? []).map((found) => ({
					text: found.text,
					origin: `from ${found.origin}`
				}))
			].filter((found) => matchesFlagTag(found.text, flagTags))
		)
	);

	/** Both sweeps feed one view, so a find looks the same wherever it came from. */
	const pixelRows = $derived(
		sweep?.candidates.map((c) => ({
			key: `${c.channels}-${c.bit}-${c.msbFirst}`,
			title: c.channels,
			chips: [`bit ${c.bit}`, `${c.msbFirst ? 'msb' : 'lsb'} first`],
			reason: c.reason,
			preview: c.preview,
			readable: c.readable,
			flags: c.flags,
			onextract: () => requestExtract(c.channels, c.bit, c.msbFirst)
		})) ?? null
	);

	const jpegRows = $derived(
		jpeg?.candidates.map((c) => ({
			key: `${c.includeDc}-${c.msbFirst}`,
			title: c.includeDc ? 'all coefficients' : 'skipping DC',
			chips: [`${c.msbFirst ? 'msb' : 'lsb'} first`],
			reason: c.reason,
			preview: c.preview,
			readable: c.readable,
			flags: c.flags,
			onextract: () => requestExtractJpeg(c.includeDc, c.msbFirst)
		})) ?? null
	);

	const paletteRows = $derived(
		paletteStego?.candidates.map((c) => ({
			key: String(c.msbFirst),
			title: 'palette indices',
			chips: [`${c.msbFirst ? 'msb' : 'lsb'} first`],
			reason: c.reason,
			preview: c.preview,
			readable: c.readable,
			flags: c.flags,
			onextract: () => requestExtractPalette(c.msbFirst)
		})) ?? null
	);

	const audioRows = $derived(
		audio?.candidates.map((c) => ({
			key: `${c.channels}-${c.bit}-${c.msbFirst}`,
			title: c.channels,
			chips: [`bit ${c.bit}`, `${c.msbFirst ? 'msb' : 'lsb'} first`],
			reason: c.reason,
			preview: c.preview,
			readable: c.readable,
			flags: c.flags,
			onextract: () => requestExtractAudio(c.channels, c.channelIndex, c.bit, c.msbFirst)
		})) ?? null
	);

	const chunk = $derived(structure?.chunks.find((c) => c.offset === selectedChunk) ?? null);

	const chunkBytes = $derived.by(() => {
		if (view.phase !== 'done' || !chunk) return new Uint8Array();
		return view.bytes.subarray(chunk.dataOffset, chunk.dataOffset + chunk.length);
	});

	const trailingBytes = $derived.by(() => {
		if (view.phase !== 'done' || !structure?.trailing) return new Uint8Array();
		const { offset, length } = structure.trailing;
		return view.bytes.subarray(offset, offset + length);
	});

	/** Byte window around a hit, snapped to a 16-byte row so the hex lines up. */
	function contextAround(offset: number, length: number) {
		if (view.phase !== 'done') return { start: 0, bytes: new Uint8Array() };
		const start = Math.max(0, (offset - 32) & ~0xf);
		const end = Math.min(view.bytes.length, offset + length + 48);
		return { start, bytes: view.bytes.subarray(start, end) };
	}

	/** Names the chunk a candidate sits inside, so a hit points somewhere. */
	const flagSources = $derived.by(() => {
		const sources: Record<number, string> = {};
		for (const found of allFlags) sources[found.offset] = found.region;
		return sources;
	});

	const summary = $derived.by(() => {
		if (!structure || isHeaderError(structure.header)) return null;
		const { width, height, bitDepth, colorType } = structure.header;
		return `${width} × ${height} · ${bitDepth}-bit ${COLOR_TYPES[colorType] ?? `type ${colorType}`}`;
	});

	const hits = $derived(built.filter((t) => t.status === 'hit').length);

	const RACK_BARS = [72, 58, 80, 64, 50, 76, 60];
	const PANE_BARS = [90, 72, 96, 65, 84, 58, 92, 70, 78, 62];
</script>

<svelte:window onpaste={pastedFile} />

<svelte:head>
	<title>Trawl</title>
	<meta
		name="description"
		content="Local CTF toolkit for steganography, cryptography and forensics."
	/>
	<link rel="canonical" href="https://trawlctf.vercel.app/" />
	<meta property="og:type" content="website" />
	<meta property="og:title" content="Trawl" />
	<meta
		property="og:description"
		content="Local CTF toolkit for steganography, cryptography and forensics. Nothing leaves your machine."
	/>
	<meta property="og:url" content="https://trawlctf.vercel.app/" />
	<meta property="og:image" content="https://trawlctf.vercel.app{banner}" />
	<meta property="og:image:width" content="1600" />
	<meta property="og:image:height" content="500" />
	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:image" content="https://trawlctf.vercel.app{banner}" />
</svelte:head>

{#if view.phase === 'idle'}
	<DropSurface
		onfile={accept}
		ontext={acceptText}
		onweb={() => (view = { phase: 'web' })}
		ontour={startTour}
		ondemos={() => (showDownloadPrompt = true)}
	/>
{:else if view.phase === 'web'}
	<WebRecon onreset={reset} />
{:else if view.phase === 'text'}
	<PeelPanel
		input={view.input}
		peel={view.peel}
		rsa={view.rsa}
		{keyed}
		onkey={requestKey}
		onreset={reset}
	/>
{:else}
	<div
		class="shell"
		role="region"
		aria-label="Analysis"
		ondrop={droppedFile}
		ondragover={(e) => e.preventDefault()}
	>
		<header>
			<div class="identity" data-tour="identity">
				<button type="button" class="home" onclick={reset} aria-label="Back to Trawl">
					<Logo size={22} />
				</button>
				<span class="name">{view.phase === 'working' ? view.name : view.result.name}</span>
				{#if view.phase === 'done'}
					<span class="meta mono">{view.result.size.toLocaleString()} B</span>
					{#if summary}
						<span class="meta mono">{summary}</span>
					{:else if survey?.format}
						<span class="meta mono">
							{survey.format}{dimensions.width
								? ` · ${dimensions.width} × ${dimensions.height}`
								: ''}
						</span>
					{/if}
				{/if}
			</div>

			<div class="right">
				{#if survey}
					<span class="tally mono" class:live={hits > 0}>
						{hits} of {built.length} tools hit
					</span>
				{/if}
				<button type="button" class="reset" onclick={reset} data-tour="new-file">New file</button>
				<HeaderControls
					dataTour="theme-github"
					onDemos={() => (showDownloadPrompt = true)}
					onExport={view.phase === 'done' ? exportWriteup : undefined}
					{flagTags}
					onFlagTags={updateFlagTags}
				/>
			</div>
		</header>

		{#if view.phase === 'working'}
			<div class="body">
				<aside class="rack-pane">
					<div class="skeleton" aria-hidden="true">
						{#each RACK_BARS as width, i (i)}<span style="width: {width}%"></span>{/each}
					</div>
					<p class="working label">Reading container</p>
				</aside>
				<main class="pane">
					<div class="skeleton" aria-hidden="true">
						{#each PANE_BARS as width, i (i)}<span style="width: {width}%"></span>{/each}
					</div>
				</main>
			</div>
		{:else if view.result.status !== 'ok'}
			<div class="notice">
				<h2>Analysis failed</h2>
				<p>{view.result.detail}</p>
				<label class="pick">
					<input type="file" onchange={pick} />
					<span>Select another file</span>
				</label>
				<p class="hint">Dropping or pasting one works too.</p>
			</div>
		{:else if survey}
			{#if credibleFlags.length > 0 || sweepFlags.length > 0}
				<div data-tour="recovered">
					<Recovered
						candidates={credibleFlags}
						sources={flagSources}
						fromPixels={sweepFlags}
						onpeel={acceptText}
					/>
				</div>
			{/if}

			<div class="body">
				<aside class="rack-pane" data-tour="rack">
					<ToolRack
						{built}
						planned={PLANNED}
						active={activeTool}
						onselect={(id) => (activeTool = id)}
					/>
				</aside>

				<main class="pane" aria-label="Tool output" data-tour="pane">
					{#if current}
						<div class="pane-head">
							<h2>{current.name}</h2>
							<p>{current.measures}</p>
						</div>
					{/if}

					{#if current?.status === 'pending' && current.scope === 'png' && !structure}
						<p class="clear">
							This tool reads the PNG container, and this file is
							{survey.format ? `a ${survey.format}` : 'not a PNG'}. The byte-level tools ran
							normally.
						</p>
					{:else if current?.status === 'pending' && current.scope === 'pixels'}
						<p class="clear">
							This tool needs pixels, and there is no decoder for
							{survey.format ? `a ${survey.format}` : 'this format'} yet. PNG, BMP and GIF all decode.
							{pixelError ?? ''}
						</p>
					{:else if current?.status === 'pending' && current.scope === 'audio' && !wav}
						<p class="clear">
							This tool reads sound, and this file is
							{survey.format ? `a ${survey.format}` : 'not audio'}. WAV is the format it reads. The
							byte-level tools ran normally.
						</p>
					{:else if current?.status === 'pending' && current.scope === 'jpeg'}
						<p class="clear">
							This tool reads the numbers a JPEG stores after compression, and
							{jpegError
								? `this file could not be read: ${jpegError}`
								: survey.format
									? `this file is a ${survey.format}`
									: 'this file is not a JPEG'}. The byte-level tools ran normally.
						</p>
					{:else if activeTool === 'jsteg'}
						<SweepView
							rows={jpegRows}
							combinations={jpeg?.combinations ?? 0}
							over="{(jpeg?.blocks ?? 0).toLocaleString()} blocks"
							blocked="The coefficients could not be read, so no sweep ran."
							error={jpegError}
							{extracted}
							onpeel={acceptText}
						/>
					{:else if activeTool === 'jpeg-chi' && jpeg}
						<ChiTrace
							chi={jpeg.chi}
							error={jpegError}
							blocked="The coefficients could not be read, so the test did not run."
						/>
						<CoefficientView {jpeg} />
					{:else if activeTool === 'spectrogram'}
						<SpectrogramView {spectrogram} toneFindings={audio?.tones ?? []} error={audioError} />
					{:else if activeTool === 'audio-lsb'}
						<SweepView
							rows={audioRows}
							combinations={audio?.combinations ?? 0}
							over="{(audio?.samples ?? 0).toLocaleString()} samples"
							blocked="The samples could not be read, so no sweep ran."
							error={audioError}
							{extracted}
							onpeel={acceptText}
						/>
					{:else if activeTool === 'riff'}
						<RiffView {wav} />
					{:else if activeTool === 'archive'}
						{#if zip}
							<ZipView archive={zip} {nested} onanalyse={analyseBytes} onpeel={acceptText} />
						{:else}
							<p class="clear">This file is not a ZIP archive, so there is nothing to read.</p>
						{/if}
					{:else if activeTool === 'pdf'}
						{#if pdf}
							<PdfView doc={pdf} onpeel={acceptText} />
						{:else}
							<p class="clear">This file is not a PDF document, so there is nothing to read.</p>
						{/if}
					{:else if activeTool === 'gif'}
						<GifFramesView {gif} {nested} />
					{:else if activeTool === 'aes'}
						{#if aes.length === 0}
							<p class="clear">
								Nothing here forms a key, an IV and a payload that decrypt to anything readable. AES
								needs all three, and a wrong key turns it into noise, so a file that is not carrying
								its own key reads as nothing. When one is, the key and IV are usually hex in the
								metadata and the payload is base64 nearby.
							</p>
						{:else}
							<ul class="findings">
								{#each aes as solved, i (solved.keyHex + solved.ivHex + i)}
									<li>
										{#each solved.flags as flag (flag)}
											<span class="mono big flagged">{flag}</span>
										{/each}
										<div class="aes-meta">
											<span class="keyword">AES-{solved.bits} · CBC</span>
											<span
												><span class="label">key</span>
												<span class="mono muted">{solved.keyHex}</span></span
											>
											<span
												><span class="label">iv</span>
												<span class="mono muted">{solved.ivHex}</span></span
											>
										</div>
										<pre class="aes-plain mono">{solved.text}</pre>
									</li>
								{/each}
							</ul>
							<p class="scale-note">
								A wrong key makes AES print random bytes, so a decryption is only shown when its
								result reads as text. That filter is what lets this run on every file without
								turning up noise.
							</p>
						{/if}
					{:else if activeTool === 'magic'}
						<MagicList
							hits={survey.magic}
							size={survey.size}
							bytes={view.bytes}
							{nested}
							onanalyse={analyseBytes}
						/>
					{:else if activeTool === 'exif'}
						<ExifView entries={survey.exif} />
					{:else if activeTool === 'jpeg'}
						<JpegView
							segments={survey.jpegSegments}
							comments={survey.jpegComments}
							trailing={survey.jpegTrailing}
						/>
					{:else if activeTool === 'entropy'}
						<EntropyTrace
							values={survey.entropy.values}
							window={survey.entropy.window}
							size={survey.size}
							marker={structure?.trailing?.offset ?? null}
						/>
					{:else if activeTool === 'chi'}
						<ChiTrace {chi} error={pixelError} />
					{:else if activeTool === 'rs'}
						<RsView {rs} {chi} error={pixelError} />
					{:else if activeTool === 'planes'}
						<PlaneWall
							{wall}
							error={pixelError}
							width={dimensions.width}
							height={dimensions.height}
							open={openPlane}
							onopen={requestPlane}
							onclose={() => (openPlane = null)}
						/>
					{:else if activeTool === 'lsb'}
						<SweepView
							rows={pixelRows}
							combinations={sweep?.combinations ?? 0}
							over="{(sweep?.pixels ?? 0).toLocaleString()} pixels"
							blocked="Pixels could not be decoded, so no sweep ran."
							error={pixelError}
							{extracted}
							onpeel={acceptText}
						/>
						{#if sweep?.candidates.length && chi && !chi.detected}
							<p class="scale-note">
								Chi-square and RS stayed quiet on this file, which is consistent rather than
								contradictory. They estimate what fraction of the image carries a payload, and a
								short message occupies a tiny fraction of one. Below roughly 5% of the low bits
								there is nothing for them to measure, so the sweep is the tool that finds small
								payloads and they are the tools that size large ones.
							</p>
						{/if}
					{:else if activeTool === 'crc' && structure}
						{#if structure.ihdrRepair}
							{@const repair = structure.ihdrRepair}
							<div class="repair-callout">
								<div>
									<span class="label">Recoverable IHDR edit</span>
									<h3>
										{repair.field === 'width'
											? `${repair.declaredWidth} → ${repair.recoveredWidth}px wide`
											: `${repair.declaredHeight} → ${repair.recoveredHeight}px high`}
									</h3>
									<p>
										The stored IHDR checksum matches those recovered dimensions exactly. Apply them
										to the bytes and run every tool again.
									</p>
								</div>
								<button type="button" onclick={repairIhdr}>Repair and re-analyse</button>
							</div>
						{:else}
							<p class="clear">Every PNG chunk agrees with its stored checksum.</p>
						{/if}
					{:else if activeTool === 'flags'}
						{#if credibleFlags.length === 0}
							<p class="clear">
								No <code>tag&lbrace;payload&rbrace;</code> shape outside the compressed streams. This
								tool only reads the file as it sits on disk, so a payload written into pixel low bits
								is invisible here by construction. The LSB sweep is what reads those.
							</p>
						{:else}
							<ul class="findings">
								{#each credibleFlags as found (found.offset)}
									{@const window = contextAround(found.offset, found.text.length)}
									<li>
										<span class="mono big flagged">{found.text}</span>
										<span class="mono muted">
											0x{found.offset.toString(16)}
											{#if flagSources[found.offset]}· {flagSources[found.offset]}{/if}
										</span>
										<div class="context">
											<span class="label">Surrounding bytes</span>
											<HexView bytes={window.bytes} baseOffset={window.start} limit={256} />
										</div>
									</li>
								{/each}
							</ul>
						{/if}

						{#if suppressedFlags.length > 0}
							<details class="suppressed">
								<summary class="label">
									{suppressedFlags.length} suppressed
								</summary>
								<p class="clear">
									These matched the shape but sit inside a deflate stream, where compressed bytes
									are close to uniform and the shape turns up by chance. Reporting them as finds
									would make the detector a random number generator.
								</p>
								<ul class="quiet mono">
									{#each suppressedFlags as found (found.offset)}
										<li>
											<span>{found.text}</span>
											<span class="muted">0x{found.offset.toString(16)} · {found.region}</span>
										</li>
									{/each}
								</ul>
							</details>
						{/if}
					{:else if activeTool === 'trailing' && structure}
						{#if structure.trailing}
							<p class="lead">
								{structure.trailing.length.toLocaleString()} bytes sit past IEND, starting at
								<span class="mono">0x{structure.trailing.offset.toString(16)}</span>. A PNG is
								complete at IEND, so nothing put these here by accident.
							</p>
							<HexView bytes={trailingBytes} baseOffset={structure.trailing.offset} />
						{:else}
							<p class="clear">The file ends at IEND. Nothing is appended.</p>
						{/if}
					{:else if activeTool === 'text' && structure}
						{#if structure.text.length === 0}
							<p class="clear">No tEXt, zTXt or iTXt chunks.</p>
						{:else}
							<ul class="findings">
								{#each structure.text as text (text.kind + text.keyword)}
									<li>
										<span class="keyword mono">{text.kind} · {text.keyword || 'no keyword'}</span>
										{#if text.compressed}
											<span class="muted">Compressed, not yet inflated. Content unread.</span>
										{:else}
											<span class="mono big">{text.text}</span>
										{/if}
									</li>
								{/each}
							</ul>
						{/if}
					{:else if activeTool === 'palette' && structure}
						<PaletteView palette={structure.palette} stego={paletteStego} />
						{#if paletteStego && paletteStego.groups.length > 0}
							<div class="palette-read">
								<SweepView
									rows={paletteRows}
									combinations={paletteStego.combinations}
									over="{paletteStego.capacityBits.toLocaleString()} carried bits"
									blocked="The pixel data could not be read, so the indices were not swept."
									error={pixelError}
									{extracted}
									onpeel={acceptText}
								/>
							</div>
						{/if}
					{:else if activeTool === 'strings'}
						<StringsView
							total={survey.strings.total}
							sample={survey.strings.sample}
							onpeel={acceptText}
						/>
					{:else if activeTool === 'pixels'}
						<p class="lead">
							Pixels decode through a hand-written PNG decoder rather than the browser, because a
							canvas readback premultiplies alpha and destroys bit 0. On this file that is
							{summary ?? 'unavailable'}.
						</p>
						<p class="clear">
							{sweep
								? `The LSB sweep and the bit-plane wall both read those pixels. Chi-square and RS analysis are next.`
								: `Decoding failed on this file, so no pixel tool can run. ${pixelError ?? ''}`}
						</p>
					{:else if structure}
						<ChunkList
							chunks={structure.chunks}
							selected={selectedChunk}
							onselect={(offset) => (selectedChunk = offset)}
						/>
						{#if chunk}
							<div class="hex-head">
								<span class="mono">{chunk.kind}</span>
								<span class="mono muted">
									0x{chunk.offset.toString(16)} · {chunk.length.toLocaleString()} bytes
								</span>
							</div>
							<HexView bytes={chunkBytes} baseOffset={chunk.dataOffset} />
						{/if}
					{/if}
				</main>
			</div>
		{/if}
	</div>
{/if}

{#if showTourPrompt}
	<TourPrompt ontour={startTour} onskip={skipTour} />
{/if}

{#if tourActive}
	<TourOverlay steps={tourSteps} onfinish={finishTour} />
{/if}

{#if showDownloadPrompt}
	<DownloadPrompt onclose={() => (showDownloadPrompt = false)} onrun={runSample} />
{/if}

<style>
	.shell {
		height: 100dvh;
		display: grid;
		grid-template-rows: auto auto minmax(0, 1fr);
	}

	header {
		position: sticky;
		top: 0;
		z-index: 2;
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s5);
		align-items: baseline;
		justify-content: space-between;
		padding: var(--s3) var(--s5);
		border-bottom: 1px solid var(--rule);
		background: var(--panel-deep);
	}

	.identity {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s2) var(--s4);
		min-width: 0;
	}

	.identity :global(.logo) {
		color: var(--muted);
	}

	.home {
		display: flex;
		background: none;
		border: none;
		padding: 0;
		margin: 0;
		cursor: pointer;
		border-radius: var(--radius);
		transition: opacity 120ms var(--ease);
	}

	.home:hover {
		opacity: 0.72;
	}

	.name {
		font-weight: 600;
		font-size: var(--t-mid);
		max-width: 40ch;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.meta {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.right {
		display: flex;
		align-items: center;
		gap: var(--s4);
	}

	.tally {
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--muted);
	}

	.tally.live {
		color: var(--signal);
	}

	.reset {
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s1) var(--s3);
		cursor: pointer;
		transition: background-color 120ms var(--ease);
	}

	.reset:hover {
		background: var(--panel-lift);
	}

	.body {
		display: grid;
		grid-template-columns: minmax(280px, 26rem) minmax(0, 1fr);
		min-height: 0;
	}

	.rack-pane {
		border-right: 1px solid var(--rule);
		overflow-y: auto;
		min-height: 0;
	}

	.pane {
		background: var(--panel);
		padding: var(--s4) var(--s5) var(--s6);
		overflow: auto;
		min-height: 0;
	}

	.pane-head {
		padding-bottom: var(--s3);
		margin-bottom: var(--s4);
		border-bottom: 1px solid var(--rule);
	}

	.pane-head h2 {
		margin: 0;
		font-size: var(--t-title);
		font-weight: 600;
	}

	.pane-head p {
		margin: var(--s1) 0 0;
		color: var(--muted);
	}

	.lead {
		margin: 0 0 var(--s4);
		max-width: 72ch;
		line-height: 1.6;
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.findings {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s4);
	}

	.findings li {
		display: grid;
		gap: var(--s1);
		padding-bottom: var(--s3);
		border-bottom: 1px solid var(--rule);
	}

	.big {
		font-size: var(--t-mid);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.palette-read {
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}

	.aes-meta {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s4);
		align-items: baseline;
	}

	.aes-meta > span {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.aes-meta .label {
		margin-right: var(--s1);
	}

	.aes-plain {
		margin: var(--s2) 0 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		line-height: 1.55;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text);
		user-select: all;
	}

	.repair-callout {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		gap: var(--s5);
		align-items: end;
		padding: var(--s4);
		background: var(--panel-deep);
		border: 1px solid var(--rule);
	}

	.repair-callout h3 {
		margin: var(--s1) 0 var(--s2);
		font-size: var(--t-mid);
	}

	.repair-callout p {
		margin: 0;
		max-width: 68ch;
		color: var(--muted);
		font-size: var(--t-label);
		line-height: 1.6;
	}

	.repair-callout button {
		border: 1px solid var(--signal);
		background: var(--signal);
		color: var(--ground);
		padding: var(--s2) var(--s3);
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		transition: transform 160ms cubic-bezier(0.2, 0.8, 0.2, 1);
	}

	.repair-callout button:active {
		transform: translateY(1px);
	}

	.repair-callout button:focus-visible {
		outline: 2px solid var(--signal);
		outline-offset: 3px;
	}

	.scale-note {
		margin: var(--s5) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	.suppressed {
		margin-top: var(--s5);
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
	}

	.suppressed summary {
		cursor: pointer;
		list-style: none;
	}

	.suppressed summary::-webkit-details-marker {
		display: none;
	}

	.suppressed summary::before {
		content: '+ ';
	}

	.suppressed[open] summary::before {
		content: '– ';
	}

	.suppressed .clear {
		margin: var(--s3) 0;
	}

	.quiet {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
		font-size: var(--t-data);
		opacity: 0.6;
	}

	.quiet li {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s3);
	}

	.context {
		margin-top: var(--s3);
		padding: var(--s3);
		background: var(--panel-deep);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		display: grid;
		gap: var(--s2);
	}

	.keyword {
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--muted);
	}

	.muted {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.hex-head {
		display: flex;
		gap: var(--s4);
		align-items: baseline;
		margin: var(--s5) 0 var(--s3);
		padding-bottom: var(--s2);
		border-bottom: 1px solid var(--rule);
	}

	code {
		font-family: var(--mono);
		font-size: 0.92em;
	}

	.skeleton {
		display: grid;
		gap: var(--s2);
		padding: var(--s4);
	}

	.skeleton span {
		height: 14px;
		background: var(--panel-lift);
		border-radius: var(--radius);
		animation: pulse 1.4s var(--ease) infinite;
	}

	.skeleton span:nth-child(2n) {
		animation-delay: 120ms;
	}

	.skeleton span:nth-child(3n) {
		animation-delay: 240ms;
	}

	@keyframes pulse {
		0%,
		100% {
			opacity: 0.4;
		}
		50% {
			opacity: 1;
		}
	}

	.working {
		padding: 0 var(--s4);
		color: var(--muted);
	}

	.notice {
		padding: var(--s6) var(--s5);
		max-width: 60ch;
		overflow-y: auto;
	}

	.notice h2 {
		margin: 0;
		font-size: var(--t-title);
		font-weight: 600;
	}

	.notice p {
		margin: var(--s3) 0 0;
		color: var(--muted);
	}

	.pick {
		display: inline-block;
		margin-top: var(--s4);
	}

	.pick input {
		position: absolute;
		width: 1px;
		height: 1px;
		opacity: 0;
	}

	.pick span {
		display: inline-block;
		padding: var(--s2) var(--s4);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		background: var(--panel-lift);
		cursor: pointer;
	}

	.pick:focus-within span {
		outline: 1px solid var(--text);
		outline-offset: 2px;
	}

	.hint {
		font-size: var(--t-label);
	}

	@media (max-width: 860px) {
		.shell {
			height: auto;
			min-height: 100dvh;
		}

		.body {
			grid-template-columns: 1fr;
		}

		.rack-pane,
		.pane {
			overflow: visible;
		}

		.rack-pane {
			border-right: 0;
			border-bottom: 1px solid var(--rule);
		}

		.pane {
			padding: var(--s4);
		}

		.repair-callout {
			grid-template-columns: 1fr;
			align-items: start;
		}
	}
</style>
