<script lang="ts">
	import { onMount } from 'svelte';
	import {
		SAMPLE_FILES,
		downloadSample,
		loadSample,
		type SampleEntry,
		type SampleFile
	} from '$lib/tour/demo';

	let { onclose, onrun }: { onclose: () => void; onrun: (file: SampleFile) => void } = $props();

	let closeButton: HTMLButtonElement | undefined;
	let loading = $state<string | null>(null);
	let error = $state('');

	onMount(() => closeButton?.focus());

	function keydown(event: KeyboardEvent) {
		if (event.key === 'Escape') onclose();
	}

	function onScrimClick(event: MouseEvent) {
		if (event.target === event.currentTarget) onclose();
	}

	async function useSample(entry: SampleEntry, action: 'run' | 'download') {
		loading = `${action}:${entry.name}`;
		error = '';
		try {
			const file = await loadSample(entry);
			if (action === 'run') onrun(file);
			else downloadSample(file);
		} catch (cause) {
			error = cause instanceof Error ? cause.message : `Could not load ${entry.name}`;
		} finally {
			loading = null;
		}
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
		<ul aria-busy={loading !== null}>
			{#each SAMPLE_FILES as entry (entry.name)}
				<li>
					<div class="row-text">
						<span class="mono name">{entry.name}</span>
						<span class="blurb">{entry.blurb}</span>
					</div>
					<div class="row-actions">
						<button
							type="button"
							class="run"
							disabled={loading !== null}
							onclick={() => useSample(entry, 'run')}
						>
							{loading === `run:${entry.name}` ? 'Loading' : 'Run'}
						</button>
						<button
							type="button"
							class="get"
							disabled={loading !== null}
							onclick={() => useSample(entry, 'download')}
						>
							{loading === `download:${entry.name}` ? 'Loading' : 'Download'}
						</button>
					</div>
				</li>
			{/each}
		</ul>
		{#if error}<p class="error" role="alert">{error}</p>{/if}
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
		width: min(42rem, 100%);
		max-height: min(48rem, calc(100dvh - var(--s7)));
		overflow-y: auto;
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

	.error {
		color: var(--signal);
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

	button:disabled {
		cursor: wait;
		opacity: 0.6;
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

	@media (max-width: 38rem) {
		.scrim {
			padding: var(--s4);
		}

		.dialog {
			max-height: calc(100dvh - var(--s6));
			padding: var(--s5);
		}

		li {
			align-items: stretch;
			flex-direction: column;
		}

		.row-actions {
			width: 100%;
		}

		.row-actions button {
			flex: 1;
		}
	}
</style>
