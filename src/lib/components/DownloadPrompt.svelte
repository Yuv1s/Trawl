<script lang="ts">
	import { onMount } from 'svelte';
	import { SAMPLE_FILES, downloadSample, type SampleFile } from '$lib/tour/demo';

	let { onclose, onrun }: { onclose: () => void; onrun: (file: SampleFile) => void } = $props();

	const files = SAMPLE_FILES.map((f) => ({ file: f.build(), blurb: f.blurb }));

	let closeButton: HTMLButtonElement | undefined;

	onMount(() => closeButton?.focus());

	function keydown(event: KeyboardEvent) {
		if (event.key === 'Escape') onclose();
	}

	function onScrimClick(event: MouseEvent) {
		if (event.target === event.currentTarget) onclose();
	}
</script>

<svelte:window onkeydown={keydown} />

<div class="scrim" role="presentation" onclick={onScrimClick}>
	<div class="dialog" tabindex="-1" role="dialog" aria-modal="true" aria-labelledby="dl-title">
		<h2 id="dl-title">See it work</h2>
		<p>
			Each of these is a small file with a flag hidden somewhere different. Run one to watch every
			tool go at it, or download it and drop it back in yourself. Nothing here leaves the tab.
		</p>
		<ul>
			{#each files as { file, blurb } (file.name)}
				<li>
					<div class="row-text">
						<span class="mono name">{file.name}</span>
						<span class="blurb">{blurb}</span>
					</div>
					<div class="row-actions">
						<button type="button" class="run" onclick={() => onrun(file)}>Run</button>
						<button type="button" class="get" onclick={() => downloadSample(file)}>Download</button>
					</div>
				</li>
			{/each}
		</ul>
		<div class="actions">
			<button type="button" class="ghost" bind:this={closeButton} onclick={onclose}>Close</button>
		</div>
	</div>
</div>

<style>
	.scrim {
		position: fixed;
		inset: 0;
		z-index: 60;
		display: grid;
		place-items: center;
		padding: var(--s5);
		background: color-mix(in srgb, var(--ground) 72%, transparent);
	}

	.dialog {
		width: min(30rem, 100%);
		padding: var(--s6);
		background: var(--panel-deep);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
	}

	h2 {
		margin: 0;
		font-size: var(--t-title);
		font-weight: 600;
	}

	p {
		margin: var(--s3) 0 0;
		color: var(--muted);
		line-height: 1.6;
	}

	ul {
		list-style: none;
		margin: var(--s5) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	li {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--s4);
		padding: var(--s3) var(--s4);
		background: var(--panel);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
	}

	.row-text {
		display: grid;
		gap: var(--s1);
		min-width: 0;
	}

	.name {
		font-weight: 600;
	}

	.blurb {
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.5;
	}

	.actions {
		display: flex;
		justify-content: flex-end;
		margin-top: var(--s5);
	}

	button {
		font: inherit;
		font-size: var(--t-label);
		font-weight: 600;
		padding: var(--s2) var(--s4);
		border-radius: var(--radius);
		cursor: pointer;
		transition: background-color 120ms var(--ease);
		flex: none;
	}

	.row-actions {
		display: flex;
		gap: var(--s2);
		flex: none;
	}

	.run {
		background: var(--signal);
		border: 1px solid var(--signal);
		color: var(--ground);
	}

	.run:hover {
		filter: brightness(1.08);
	}

	.get {
		background: none;
		border: 1px solid var(--rule-bright);
		color: var(--text);
	}

	.get:hover {
		background: var(--panel-lift);
	}

	.ghost {
		background: none;
		border: 1px solid var(--rule-bright);
		color: var(--text);
	}

	.ghost:hover {
		background: var(--panel-lift);
	}
</style>
