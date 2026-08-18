<script lang="ts">
	import { resolve } from '$app/paths';
	import Logo from '$lib/components/Logo.svelte';
	import { PLANNED } from '$lib/analysis/tools';

	let { onfile }: { onfile: (file: File) => void } = $props();

	let dragging = $state(false);
	let depth = 0;

	const READY = [
		['Flag scan', 'Looks for flag{...} text in the file'],
		['LSB sweep', 'Tries every way of reading hidden bits'],
		['Chi-square attack', 'Statistical test for a hidden payload'],
		['RS analysis', 'Second opinion on how much is hidden'],
		['Bit-plane wall', 'Shows each layer of bits as a picture'],
		['Post-IEND data', 'Extra bytes stuck on the end of the file'],
		['Text chunks', 'Comments and labels saved inside the image'],
		['Chunk CRC', 'Checks each part against its own checksum'],
		['Chunk walk', 'Lists every part of the file'],
		['ASCII strings', 'Readable text anywhere in the file'],
		['Pixel decode', 'Reads exact pixel values, nothing altered']
	];

	function enter(event: DragEvent) {
		event.preventDefault();
		depth += 1;
		dragging = true;
	}

	function leave(event: DragEvent) {
		event.preventDefault();
		depth -= 1;
		if (depth <= 0) dragging = false;
	}

	function drop(event: DragEvent) {
		event.preventDefault();
		depth = 0;
		dragging = false;
		const file = event.dataTransfer?.files?.[0];
		if (file) onfile(file);
	}

	function pick(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		if (file) onfile(file);
		input.value = '';
	}

	function paste(event: ClipboardEvent) {
		const file = event.clipboardData?.files?.[0];
		if (file) onfile(file);
	}
</script>

<svelte:window onpaste={paste} />

<section
	class="surface"
	class:dragging
	aria-label="Drop a file to analyse"
	ondragenter={enter}
	ondragleave={leave}
	ondragover={(e) => e.preventDefault()}
	ondrop={drop}
>
	<header>
		<h1><Logo size={44} /><span>Trawl</span></h1>
		<p class="lede">
			Every tool for a file-based CTF challenge, running at once, in this tab. Nothing is uploaded.
		</p>

		<label class="pick" class:armed={dragging}>
			<input type="file" onchange={pick} />
			<span>{dragging ? 'Release to analyse' : 'Select a file'}</span>
		</label>
		<span class="alt">or drop one anywhere, or paste from the clipboard</span>
	</header>

	<div class="rack">
		<div class="rack-head">
			<h2 class="label">Runs on drop</h2>
			<span class="label count mono">{READY.length} tools</span>
		</div>
		<ul>
			{#each READY as [name, measures] (name)}
				<li>
					<span class="name">{name}</span>
					<span class="measures">{measures}</span>
					<span class="state mono">idle</span>
				</li>
			{/each}
		</ul>

		<div class="rack-head sub">
			<h2 class="label">Not built yet</h2>
			<span class="label count mono">{PLANNED.length}</span>
		</div>
		<ul class="planned">
			{#each PLANNED as tool (tool.id)}
				<li>
					<span class="name">{tool.name}</span>
					<span class="measures">{tool.measures}</span>
				</li>
			{/each}
		</ul>
	</div>

	<footer>
		<p class="assurance">
			No upload, no account, no telemetry. Works offline after the first load.
		</p>
		<nav aria-label="Site">
			<a href={resolve('/privacy')}>Privacy</a>
			<a href={resolve('/terms')}>Terms</a>
		</nav>
	</footer>
</section>

<style>
	.surface {
		height: 100dvh;
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(0, 32rem);
		grid-template-rows: minmax(0, 1fr) auto;
		gap: 0 var(--s7);
		padding: var(--s5) var(--s6) var(--s3);
		transition: background-color 160ms var(--ease);
	}

	.dragging {
		background: var(--panel-deep);
	}

	header {
		align-self: center;
		max-width: 30ch;
		padding-bottom: var(--s6);
	}

	h1 {
		display: flex;
		align-items: center;
		gap: var(--s4);
		margin: 0;
		font-size: clamp(2.75rem, 7vw, 5rem);
		font-weight: 600;
		letter-spacing: -0.03em;
		line-height: 0.95;
	}

	/* The mark scales with the wordmark rather than sitting at a fixed size. */
	h1 :global(.logo) {
		width: 0.72em;
		height: 0.72em;
		color: var(--muted);
	}

	.lede {
		margin: var(--s4) 0 var(--s5);
		font-size: var(--t-mid);
		color: var(--text);
		line-height: 1.45;
		max-width: 28ch;
	}

	.pick input {
		position: absolute;
		width: 1px;
		height: 1px;
		opacity: 0;
	}

	.pick span {
		display: inline-block;
		padding: var(--s3) var(--s5);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		background: var(--panel);
		font-size: var(--t-body);
		font-weight: 600;
		cursor: pointer;
		transition: background-color 140ms var(--ease);
	}

	.pick:hover span,
	.armed span {
		background: var(--panel-lift);
	}

	.pick:focus-within span {
		outline: 1px solid var(--text);
		outline-offset: 2px;
	}

	.alt {
		display: block;
		margin-top: var(--s3);
		color: var(--muted);
	}

	.rack {
		align-self: stretch;
		min-height: 0;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		background: var(--panel);
		overflow-y: auto;
	}

	.rack-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--s4);
		padding: var(--s2) var(--s4);
		background: var(--panel-deep);
		border-bottom: 1px solid var(--rule);
		position: sticky;
		top: 0;
	}

	.sub {
		border-top: 1px solid var(--rule);
	}

	.rack-head h2 {
		margin: 0;
	}

	.count {
		color: var(--muted);
	}

	ul {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	li {
		display: grid;
		grid-template-columns: 1fr auto;
		gap: 0 var(--s3);
		padding: var(--s2) var(--s4);
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 55%, transparent);
	}

	li:last-child {
		border-bottom: 0;
	}

	.name {
		font-weight: 600;
	}

	.measures {
		grid-column: 1;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.5;
	}

	.state {
		grid-row: 1;
		grid-column: 2;
		align-self: center;
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--muted);
	}

	.planned li {
		opacity: 0.5;
	}

	.planned .name {
		font-weight: 400;
	}

	footer {
		grid-column: 1 / -1;
		display: flex;
		flex-wrap: wrap;
		justify-content: space-between;
		gap: var(--s2) var(--s5);
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		font-size: var(--t-label);
		color: var(--muted);
	}

	.assurance {
		margin: 0;
	}

	nav {
		display: flex;
		gap: var(--s4);
	}

	nav a {
		color: var(--muted);
		text-decoration: none;
		border-bottom: 1px solid transparent;
		transition: color 120ms var(--ease);
	}

	nav a:hover {
		color: var(--text);
		border-bottom-color: var(--rule-bright);
	}

	@media (max-width: 900px) {
		.surface {
			height: auto;
			min-height: 100dvh;
			grid-template-columns: minmax(0, 1fr);
			grid-template-rows: auto auto auto;
			gap: var(--s5) 0;
			padding: var(--s5) var(--s4) var(--s4);
		}

		header {
			align-self: start;
			max-width: none;
			padding-bottom: 0;
		}

		.rack {
			align-self: start;
			overflow-y: visible;
		}

		.rack-head {
			position: static;
		}
	}
</style>
