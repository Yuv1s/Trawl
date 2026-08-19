<script lang="ts">
	import AnalysisWorker from '$lib/worker/analysis.worker?worker';
	import DropSurface from '$lib/components/DropSurface.svelte';
	import WebRecon from '$lib/components/WebRecon.svelte';
	import PeelPanel from '$lib/components/PeelPanel.svelte';
	import { attack as attackRsa, looksLikeRsa, type Report } from '$lib/analysis/rsa';
	import Logo from '$lib/components/Logo.svelte';
	import ToolRack from '$lib/components/ToolRack.svelte';
	import Recovered from '$lib/components/Recovered.svelte';
	import ChunkList from '$lib/components/ChunkList.svelte';
	import ZipView from '$lib/components/ZipView.svelte';
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
	import { flagsOf, PLANNED, tools, WRITTEN_BY_HAND } from '$lib/analysis/tools';
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
					activeTool = flags.some((f) => f.credible)
						? 'flags'
						: analysis.sweep?.candidates.length
							? 'lsb'
							: analysis.audio?.candidates.length
								? 'audio-lsb'
								: analysis.jpeg && !isJpegError(analysis.jpeg) && analysis.jpeg.candidates.length
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
		ensureWorker().postMessage({ kind: 'peel', id, text });
	}

	/** Applies a key the reader already has, which no amount of text would give up. */
	function requestKey(key: string) {
		if (view.phase !== 'text') return;
		keyed = null;
		ensureWorker().postMessage({ kind: 'withKey', id: ticket, text: view.input, key });
	}

	async function accept(file: File) {
		const id = ++ticket;
		view = { phase: 'working', name: file.name };

		const buffer = await file.arrayBuffer();
		pending = Promise.resolve(new Uint8Array(buffer));
		ensureWorker().postMessage({ kind: 'analyse', id, name: file.name, bytes: buffer });
	}

	function requestPlane(channel: number, bit: number) {
		openPlane = { channel, bit, pixels: null };
		ensureWorker().postMessage({ kind: 'plane', id: ticket, channel, bit });
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
					zip
				})
			: []
	);
	const current = $derived(built.find((t) => t.id === activeTool) ?? null);

	const allFlags = $derived(survey ? flagsOf(survey, structure) : []);
	const credibleFlags = $derived(allFlags.filter((f) => f.credible));
	const suppressedFlags = $derived(allFlags.filter((f) => !f.credible));
	/** Every sweep find, each carrying the name of the sweep that turned it up. */
	const sweepFlags = $derived([
		...(sweep?.candidates.flatMap((c) =>
			c.flags.map((text) => ({ text, origin: 'from the pixel sweep' }))
		) ?? []),
		...(audio?.candidates.flatMap((c) =>
			c.flags.map((text) => ({ text, origin: 'from the audio sweep' }))
		) ?? []),
		...(jpeg?.candidates.flatMap((c) =>
			c.flags.map((text) => ({ text, origin: 'from the JPEG coefficients' }))
		) ?? []),
		...(paletteStego?.candidates.flatMap((c) =>
			c.flags.map((text) => ({ text, origin: 'from the palette indices' }))
		) ?? [])
	]);

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
</svelte:head>

{#if view.phase === 'idle'}
	<DropSurface onfile={accept} ontext={acceptText} onweb={() => (view = { phase: 'web' })} />
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
			<div class="identity">
				<Logo size={22} />
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
				<button type="button" class="reset" onclick={reset}>New file</button>
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
				<Recovered candidates={credibleFlags} sources={flagSources} fromPixels={sweepFlags} />
			{/if}

			<div class="body">
				<aside class="rack-pane">
					<ToolRack
						{built}
						planned={PLANNED}
						active={activeTool}
						onselect={(id) => (activeTool = id)}
					/>
				</aside>

				<main class="pane" aria-label="Tool output">
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
						/>
					{:else if activeTool === 'jpeg-chi' && jpeg}
						<ChiTrace
							chi={jpeg.chi}
							error={jpegError}
							blocked="The coefficients could not be read, so the test did not run."
						/>
						<CoefficientView {jpeg} />
					{:else if activeTool === 'spectrogram'}
						<SpectrogramView {spectrogram} error={audioError} />
					{:else if activeTool === 'audio-lsb'}
						<SweepView
							rows={audioRows}
							combinations={audio?.combinations ?? 0}
							over="{(audio?.samples ?? 0).toLocaleString()} samples"
							blocked="The samples could not be read, so no sweep ran."
							error={audioError}
							{extracted}
						/>
					{:else if activeTool === 'riff'}
						<RiffView {wav} />
					{:else if activeTool === 'archive'}
						{#if zip}
							<ZipView archive={zip} />
						{:else}
							<p class="clear">This file is not a ZIP archive, so there is nothing to read.</p>
						{/if}
					{:else if activeTool === 'magic'}
						<MagicList hits={survey.magic} size={survey.size} bytes={view.bytes} />
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
								/>
							</div>
						{/if}
					{:else if activeTool === 'strings'}
						<StringsView total={survey.strings.total} sample={survey.strings.sample} />
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

<style>
	.shell {
		height: 100dvh;
		display: grid;
		grid-template-rows: auto auto minmax(0, 1fr);
	}

	header {
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
	}
</style>
