<script lang="ts">
	import { tick } from 'svelte';
	import type { TourStep } from '$lib/tour/types';

	let { steps, onfinish }: { steps: TourStep[]; onfinish: () => void } = $props();

	let index = $state(0);
	let rect = $state<{ top: number; left: number; width: number; height: number } | null>(null);
	let card: HTMLDivElement | undefined;

	const step = $derived(steps[index]);
	const PAD = 6;

	async function measure() {
		step.onenter?.();
		await tick();

		const el = document.querySelector(step.target);
		if (!el) {
			rect = null;
			return;
		}

		const box = el.getBoundingClientRect();
		rect = {
			top: Math.max(PAD, box.top - PAD),
			left: Math.max(PAD, box.left - PAD),
			width: Math.min(window.innerWidth - PAD * 2, box.width + PAD * 2),
			height: box.height + PAD * 2
		};

		card?.focus();
	}

	$effect(() => {
		void index;
		measure();
	});

	function onResize() {
		measure();
	}

	function next() {
		if (index < steps.length - 1) index++;
		else onfinish();
	}

	function back() {
		if (index > 0) index--;
	}

	function keydown(event: KeyboardEvent) {
		if (event.key === 'Escape') onfinish();
		else if (event.key === 'ArrowRight' || event.key === 'Enter') next();
		else if (event.key === 'ArrowLeft') back();
	}

	const cardTop = $derived.by(() => {
		if (!rect) return window.innerHeight / 2 - 90;
		const below = rect.top + rect.height + 12;
		return below + 220 < window.innerHeight ? below : Math.max(12, rect.top - 220 - 12);
	});

	const cardLeft = $derived.by(() => {
		if (!rect) return window.innerWidth / 2 - 170;
		return Math.min(Math.max(12, rect.left), window.innerWidth - 352);
	});
</script>

<svelte:window onresize={onResize} onscroll={onResize} onkeydown={keydown} />

{#if rect}
	<div class="dim" style="top:0; left:0; width:100%; height:{rect.top}px"></div>
	<div
		class="dim"
		style="top:{rect.top + rect.height}px; left:0; width:100%; height:{Math.max(
			0,
			window.innerHeight - rect.top - rect.height
		)}px"
	></div>
	<div
		class="dim"
		style="top:{rect.top}px; left:0; width:{rect.left}px; height:{rect.height}px"
	></div>
	<div
		class="dim"
		style="top:{rect.top}px; left:{rect.left + rect.width}px; width:{Math.max(
			0,
			window.innerWidth - rect.left - rect.width
		)}px; height:{rect.height}px"
	></div>
	<div
		class="ring"
		style="top:{rect.top}px; left:{rect.left}px; width:{rect.width}px; height:{rect.height}px"
	></div>
{:else}
	<div class="dim" style="inset: 0"></div>
{/if}

<div
	class="card"
	bind:this={card}
	tabindex="-1"
	role="dialog"
	aria-modal="true"
	aria-labelledby="tour-step-title"
	style="top:{cardTop}px; left:{cardLeft}px"
>
	<span class="eyebrow label mono">Step {index + 1} of {steps.length}</span>
	<h3 id="tour-step-title">{step.title}</h3>
	<p>{step.body}</p>
	<div class="row">
		<button type="button" class="ghost" onclick={onfinish}>Skip tour</button>
		<div class="nav">
			{#if index > 0}
				<button type="button" class="ghost" onclick={back}>Back</button>
			{/if}
			<button type="button" class="primary" onclick={next}>
				{index === steps.length - 1 ? 'Done' : 'Next'}
			</button>
		</div>
	</div>
</div>

<style>
	/* Position and size snap between steps rather than tween — top/left/width/
	   height are layout properties, and animating them repaints everything
	   underneath instead of compositing on the GPU. */
	.dim {
		position: fixed;
		z-index: 60;
		background: color-mix(in srgb, var(--ground) 78%, transparent);
	}

	.ring {
		position: fixed;
		z-index: 61;
		border: 1.5px solid var(--signal);
		border-radius: var(--radius);
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--signal) 20%, transparent);
	}

	.card {
		position: fixed;
		z-index: 62;
		width: 340px;
		max-width: calc(100vw - 24px);
		padding: var(--s4) var(--s5) var(--s4);
		background: var(--panel-deep);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
	}

	.card:focus-visible {
		outline: 1px solid var(--text);
		outline-offset: 3px;
	}

	.eyebrow {
		display: block;
	}

	h3 {
		margin: var(--s2) 0 0;
		font-size: var(--t-mid);
		font-weight: 600;
	}

	p {
		margin: var(--s2) 0 0;
		color: var(--muted);
		line-height: 1.55;
		font-size: var(--t-data);
	}

	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--s3);
		margin-top: var(--s4);
	}

	.nav {
		display: flex;
		gap: var(--s2);
	}

	button {
		font: inherit;
		font-size: var(--t-label);
		font-weight: 600;
		padding: var(--s2) var(--s4);
		border-radius: var(--radius);
		cursor: pointer;
		transition: background-color 120ms var(--ease);
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
