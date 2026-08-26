<script lang="ts">
	import { onMount } from 'svelte';
	import Logo from '$lib/components/Logo.svelte';

	let { ontour, onskip }: { ontour: () => void; onskip: () => void } = $props();

	let primary: HTMLButtonElement | undefined;

	onMount(() => primary?.focus());

	function keydown(event: KeyboardEvent) {
		if (event.key === 'Escape') onskip();
	}

	/** Only a click on the scrim itself dismisses; one that bubbled up from the
	 *  dialog's own content should not. */
	function onScrimClick(event: MouseEvent) {
		if (event.target === event.currentTarget) onskip();
	}
</script>

<svelte:window onkeydown={keydown} />

<div class="scrim" role="presentation" onclick={onScrimClick}>
	<div
		class="dialog"
		tabindex="-1"
		role="dialog"
		aria-modal="true"
		aria-labelledby="tour-title"
		aria-describedby="tour-body"
	>
		<Logo size={28} />
		<h2 id="tour-title">New here?</h2>
		<p id="tour-body">
			Takes about two minutes. It loads a sample file with a flag already hidden in it and walks
			through what each tool turns up. Or skip it and drop your own file straight away. Nothing you
			analyse here ever leaves this tab.
		</p>
		<div class="actions">
			<button type="button" class="primary" bind:this={primary} onclick={ontour}>
				Take the tour
			</button>
			<button type="button" class="ghost" onclick={onskip}>I'll poke around myself</button>
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
		width: min(26rem, 100%);
		padding: var(--s6) var(--s6) var(--s5);
		background: var(--panel-deep);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		text-align: left;
	}

	h2 {
		margin: var(--s4) 0 0;
		font-size: var(--t-title);
		font-weight: 600;
	}

	p {
		margin: var(--s3) 0 0;
		color: var(--muted);
		line-height: 1.6;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s3);
		margin-top: var(--s5);
	}

	button {
		font: inherit;
		font-size: var(--t-label);
		font-weight: 600;
		padding: var(--s3) var(--s4);
		border-radius: var(--radius);
		cursor: pointer;
		transition:
			background-color 120ms var(--ease),
			border-color 120ms var(--ease);
	}

	.primary {
		background: var(--signal);
		border: 1px solid var(--signal);
		color: var(--ground);
	}

	.primary:hover {
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
