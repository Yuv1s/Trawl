<script lang="ts">
	import { onMount } from 'svelte';
	import { SAMPLE_FILES, downloadSample } from '$lib/tour/demo';

	let { onclose }: { onclose: () => void } = $props();

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
		<h2 id="dl-title">A few more to try</h2>
		<p>
			Same idea as the tour, each one hiding its flag somewhere different. Download any of them and
			drop it back in whenever you want to try Trawl on something real.
		</p>
		<ul>
			{#each files as { file, blurb } (file.name)}
				<li>
					<div class="row-text">
						<span class="mono name">{file.name}</span>
						<span class="blurb">{blurb}</span>
					</div>
					<button type="button" class="get" onclick={() => downloadSample(file)}> Download </button>
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

	.get {
		background: var(--signal);
		border: 1px solid var(--signal);
		color: var(--ground);
	}

	.get:hover {
		filter: brightness(1.08);
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
