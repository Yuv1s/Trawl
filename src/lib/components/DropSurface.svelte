<script lang="ts">
	import { resolve } from '$app/paths';
	import Logo from '$lib/components/Logo.svelte';
	import HeaderControls from '$lib/components/HeaderControls.svelte';
	import { PLANNED } from '$lib/analysis/tools';

	let {
		onfile,
		ontext,
		onweb,
		ontour,
		ondemos
	}: {
		onfile: (file: File) => void;
		ontext: (text: string) => void;
		onweb: () => void;
		ontour: () => void;
		ondemos: () => void;
	} = $props();

	let dragging = $state(false);
	let depth = 0;
	let pasted = $state('');

	/** Long enough that a stray word does not launch an analysis. */
	const MIN_TEXT = 6;
	const ready = $derived(pasted.trim().length >= MIN_TEXT);

	function submit(event: SubmitEvent) {
		event.preventDefault();
		if (ready) ontext(pasted.trim());
	}

	/**
	 * What the page can actually do, grouped the way the workbench groups it.
	 *
	 * Written out rather than derived, because there is no file here to run
	 * anything against. That makes it a promise, so it has to stay true: every
	 * line below is a tool that exists.
	 */
	const GROUPS: { name: string; blurb: string; tools: [string, string][] }[] = [
		{
			name: 'Cuttlefish',
			blurb: 'Runs on an image or a sound file',
			tools: [
				['LSB sweep', 'Tries every way of reading hidden bits'],
				['Bit-plane wall', 'Shows each layer of bits as a picture'],
				['Chi-square attack', 'Statistical test for a hidden payload'],
				['RS analysis', 'Second opinion on how much is hidden'],
				['Spectrogram', 'Draws the sound, in case a picture is hiding in it'],
				['Audio LSB sweep', 'Hidden bits in the samples of a sound file'],
				['JSteg sweep', 'Reads hidden bits out of a JPEG after compression'],
				['Palette', 'Repeated colours that carry hidden bits']
			]
		},
		{
			name: 'Survey',
			blurb: 'Runs on any file you drop',
			tools: [
				['Flag scan', 'Looks for flag{...} text in the file'],
				['Embedded files', 'Finds files hidden inside this one, and saves them'],
				['Metadata', 'Camera details and notes saved with the photo'],
				['Entropy window', 'Finds compressed or encrypted regions'],
				['Chunk walk', 'Lists every part of the file'],
				['Readable text', 'Text anywhere in the file, plain or wide'],
				['Archive entries', 'Reads a ZIP twice and reports where the two copies disagree'],
				['PDF structure', 'Walks a PDF for every object, and what the index leaves out']
			]
		},
		{
			name: 'Mantis',
			blurb: 'Runs on a string you paste',
			tools: [
				['Encoding peeler', 'Unwraps base64, hex, morse and ten more, layer by layer'],
				['Caesar solver', 'Tries every shift and keeps the one that reads']
			]
		}
	];

	const total = GROUPS.reduce((n, group) => n + group.tools.length, 0);

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

	/**
	 * A file if the clipboard holds one, otherwise the text goes to the box.
	 *
	 * Pasting anywhere on the page is how people already start here, and until now
	 * that only worked for files. Typing into the box has to keep working, so a
	 * paste aimed at it is left alone.
	 */
	function paste(event: ClipboardEvent) {
		const file = event.clipboardData?.files?.[0];
		if (file) {
			onfile(file);
			return;
		}

		if ((event.target as HTMLElement | null)?.tagName === 'TEXTAREA') return;

		const text = event.clipboardData?.getData('text')?.trim();
		if (text && text.length >= MIN_TEXT) {
			event.preventDefault();
			pasted = text;
			ontext(text);
		}
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
	<div class="corner">
		<HeaderControls onTour={ontour} onDemos={ondemos} />
	</div>

	<header>
		<h1><Logo size={44} /><span>Trawl</span></h1>
		<p class="lede">
			{total} tools for a CTF challenge, running at once, in this tab. Nothing is uploaded.
		</p>

		<label class="pick" class:armed={dragging}>
			<input type="file" onchange={pick} />
			<span>{dragging ? 'Release to analyse' : 'Select a file'}</span>
		</label>
		<span class="alt">or drop one anywhere, or paste from the clipboard</span>

		<form class="decode" onsubmit={submit}>
			<label class="label" for="paste">Or paste a string to decode</label>
			<textarea
				id="paste"
				bind:value={pasted}
				rows="2"
				spellcheck="false"
				placeholder="SGVsbG8sIHdvcmxkIQ=="></textarea>
			<button type="submit" disabled={!ready}>Peel it</button>
		</form>

		<button type="button" class="web" onclick={onweb}>
			Explore a live site
			<span class="alt">a URL, scanned by a helper you run yourself</span>
		</button>
	</header>

	<div class="rack">
		{#each GROUPS as group (group.name)}
			<div class="rack-head">
				<h2 class="label">{group.name}</h2>
				<span class="label count mono">{group.blurb}</span>
			</div>
			<ul>
				{#each group.tools as [name, measures] (name)}
					<li>
						<span class="name">{name}</span>
						<span class="measures">{measures}</span>
						<span class="state mono">idle</span>
					</li>
				{/each}
			</ul>
		{/each}

		{#if PLANNED.length > 0}
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
		{/if}
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
		grid-template-rows: auto minmax(0, 1fr) auto;
		/* A row gap as well as a column one. Without it the rack's bottom border
		   lands exactly on the footer's top border, and the two 1px rules read
		   as one thick line dividing nothing. */
		gap: var(--s5) var(--s7);
		padding: var(--s5) var(--s6) var(--s3);
		transition: background-color 160ms var(--ease);
	}

	.dragging {
		background: var(--panel-deep);
	}

	/* Its own row, not floated over the rack — the rack's own header sits
	   flush with the top edge and leaves no gutter to float above. */
	.corner {
		grid-column: 1 / -1;
		display: flex;
		justify-content: flex-end;
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

	/* A third way in, alongside the file drop and the paste box. Its own line
	   rather than a button in a row, because it leads somewhere else entirely:
	   the one part of Trawl that reaches the network. */
	.web {
		display: block;
		width: 100%;
		text-align: left;
		margin-top: var(--s5);
		padding: var(--s3) var(--s4);
		background: none;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		font-weight: 600;
		cursor: pointer;
		transition: border-color 140ms var(--ease);
	}
	.web:hover {
		border-color: var(--signal);
	}
	.web .alt {
		margin-top: var(--s1);
		font-weight: 400;
		font-size: var(--t-label);
	}

	.decode {
		display: grid;
		gap: var(--s2);
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}

	.decode textarea {
		width: 100%;
		resize: vertical;
		background: var(--panel);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font-family: var(--mono);
		font-size: var(--t-data);
		line-height: 1.5;
		padding: var(--s2) var(--s3);
	}

	.decode textarea::placeholder {
		color: var(--muted);
	}

	.decode button {
		justify-self: start;
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s2) var(--s4);
		cursor: pointer;
		transition:
			background-color 140ms var(--ease),
			opacity 140ms var(--ease);
	}

	.decode button:hover:not(:disabled) {
		background: var(--panel-lift);
	}

	.decode button:disabled {
		opacity: 0.45;
		cursor: default;
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

	/* Each group after the first gets a rule above it, so the rack reads as
	   three instruments rather than one long list. */
	ul + .rack-head {
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
			grid-template-rows: auto auto auto auto;
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
