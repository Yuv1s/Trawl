<script lang="ts">
	import AnalysisWorker from '$lib/worker/analysis.worker?worker';
	import DropSurface from '$lib/components/DropSurface.svelte';
	import ToolRack from '$lib/components/ToolRack.svelte';
	import Recovered from '$lib/components/Recovered.svelte';
	import ChunkList from '$lib/components/ChunkList.svelte';
	import HexView from '$lib/components/HexView.svelte';
	import StringsView from '$lib/components/StringsView.svelte';
	import SweepView from '$lib/components/SweepView.svelte';
	import { PLANNED, tools } from '$lib/analysis/tools';
	import { COLOR_TYPES, isHeaderError, type AnalysisResponse } from '$lib/worker/protocol';

	type View =
		| { phase: 'idle' }
		| { phase: 'working'; name: string }
		| { phase: 'done'; result: AnalysisResponse; bytes: Uint8Array };

	let view = $state<View>({ phase: 'idle' });
	let activeTool = $state('flags');
	let selectedChunk = $state(-1);

	let worker: Worker | null = null;
	let ticket = 0;
	let pending: Promise<Uint8Array> = Promise.resolve(new Uint8Array());

	function ensureWorker(): Worker {
		if (!worker) {
			worker = new AnalysisWorker();
			worker.addEventListener('message', (event: MessageEvent<AnalysisResponse>) => {
				if (event.data.id !== ticket) return;
				pending.then((bytes) => {
					const result = event.data;
					view = { phase: 'done', result, bytes };
					if (result.status === 'ok') {
						selectedChunk = result.structure.chunks[0]?.offset ?? -1;
						activeTool = result.structure.flags.some((f) => f.credible)
							? 'flags'
							: result.sweep?.candidates.length
								? 'lsb'
								: 'chunks';
					}
				});
			});
		}
		return worker;
	}

	async function accept(file: File) {
		const id = ++ticket;
		view = { phase: 'working', name: file.name };

		const buffer = await file.arrayBuffer();
		pending = Promise.resolve(new Uint8Array(buffer));
		ensureWorker().postMessage({ id, name: file.name, bytes: buffer });
	}

	function reset() {
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

	const structure = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.structure : null
	);

	const sweep = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.sweep : null
	);
	const sweepError = $derived(
		view.phase === 'done' && view.result.status === 'ok' ? view.result.sweepError : null
	);

	const built = $derived(structure ? tools(structure, sweep) : []);
	const current = $derived(built.find((t) => t.id === activeTool) ?? null);

	const credibleFlags = $derived(structure?.flags.filter((f) => f.credible) ?? []);
	const suppressedFlags = $derived(structure?.flags.filter((f) => !f.credible) ?? []);
	const sweepFlags = $derived(sweep?.candidates.flatMap((c) => c.flags) ?? []);

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
		if (!structure) return sources;

		for (const found of structure.flags) {
			const host = structure.chunks.find(
				(c) => found.offset >= c.dataOffset && found.offset < c.dataOffset + c.length
			);
			if (host) sources[found.offset] = `inside ${host.kind}`;
			else if (structure.trailing && found.offset >= structure.trailing.offset)
				sources[found.offset] = 'after IEND';
		}
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
	<DropSurface onfile={accept} />
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
				<span class="name">{view.phase === 'working' ? view.name : view.result.name}</span>
				{#if view.phase === 'done'}
					<span class="meta mono">{view.result.size.toLocaleString()} B</span>
					{#if summary}<span class="meta mono">{summary}</span>{/if}
				{/if}
			</div>

			<div class="right">
				{#if structure}
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
				<h2>{view.result.status === 'unsupported' ? 'Not analysed' : 'Analysis failed'}</h2>
				<p>{view.result.detail}</p>
				<label class="pick">
					<input type="file" onchange={pick} />
					<span>Select another file</span>
				</label>
				<p class="hint">Dropping or pasting one works too.</p>
			</div>
		{:else if structure}
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

					{#if activeTool === 'lsb'}
						<SweepView {sweep} error={sweepError} />
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
					{:else if activeTool === 'trailing'}
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
					{:else if activeTool === 'text'}
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
					{:else if activeTool === 'strings'}
						<StringsView total={structure.strings.total} sample={structure.strings.sample} />
					{:else if activeTool === 'pixels'}
						<p class="lead">
							Pixels decode through a hand-written PNG decoder rather than the browser, because a
							canvas readback premultiplies alpha and destroys bit 0. On this file that is
							{summary ?? 'unavailable'}.
						</p>
						<p class="clear">
							{sweep
								? `The LSB sweep reads those pixels. Bit planes and steganalysis are the next detectors.`
								: `Decoding failed on this file, so no pixel tool can run. ${sweepError ?? ''}`}
						</p>
					{:else}
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
		align-items: baseline;
		gap: var(--s2) var(--s4);
		min-width: 0;
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
