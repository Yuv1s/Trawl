<script lang="ts">
	import type { ChiSquare } from '$lib/worker/protocol';

	let { chi, error }: { chi: ChiSquare | null; error: string | null } = $props();

	const W = 720;
	const H = 220;
	const PAD = { top: 12, right: 16, bottom: 28, left: 40 };

	const usable = $derived(chi?.points.filter((p) => p.degrees > 0) ?? []);

	const x = (fraction: number) => PAD.left + fraction * (W - PAD.left - PAD.right);
	const y = (p: number) => PAD.top + (1 - p) * (H - PAD.top - PAD.bottom);

	const path = $derived(
		usable
			.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.fraction).toFixed(1)} ${y(p.p).toFixed(1)}`)
			.join(' ')
	);

	const boundary = $derived(chi && chi.detected ? chi.embeddedFraction : null);
	const percent = (v: number) => `${(v * 100).toFixed(1)}%`;
</script>

{#if !chi}
	<p class="clear">
		Pixels could not be decoded, so the test did not run.{error ? ` ${error}` : ''}
	</p>
{:else if usable.length === 0}
	<p class="clear">
		Too few samples to support the approximation. The test drops value pairs with fewer than four
		expected counts, and this image left none.
	</p>
{:else}
	<div class="verdict" class:detected={chi.detected}>
		{#if chi.detected}
			<p class="headline">
				{percent(chi.embeddedFraction)} of the image fits sequential LSB embedding.
			</p>
			<p class="detail">
				Peak probability {chi.peakProbability.toFixed(3)} across
				{chi.samples.toLocaleString()} samples. The curve holds near 1 while the payload lasts and collapses
				where it stops, which is what places the boundary.
			</p>
		{:else}
			<p class="headline">No sequential LSB embedding.</p>
			<p class="detail">
				Peak probability {chi.peakProbability.toFixed(3)} across
				{chi.samples.toLocaleString()} samples, below the 0.95 threshold at every prefix. This test sees
				sequential embedding only; scattered or keyed placement will not show here.
			</p>
		{/if}
	</div>

	<figure>
		<svg
			viewBox="0 0 {W} {H}"
			role="img"
			aria-label="Chi-square embedding probability against image prefix"
		>
			{#each [0, 0.5, 1] as tick (tick)}
				<line class="grid" x1={PAD.left} x2={W - PAD.right} y1={y(tick)} y2={y(tick)} />
				<text class="axis" x={PAD.left - 6} y={y(tick) + 3.5} text-anchor="end">
					{tick.toFixed(1)}
				</text>
			{/each}

			{#each [0, 0.25, 0.5, 0.75, 1] as tick (tick)}
				<text class="axis" x={x(tick)} y={H - 8} text-anchor="middle">{percent(tick)}</text>
			{/each}

			{#if boundary !== null}
				<line class="boundary" x1={x(boundary)} x2={x(boundary)} y1={PAD.top} y2={H - PAD.bottom} />
				<text class="boundary-label" x={x(boundary) + 5} y={PAD.top + 11}>
					{percent(boundary)}
				</text>
			{/if}

			<path class="trace" d={path} />
		</svg>
		<figcaption>
			Probability of embedding against the fraction of the image measured, 64 prefixes. Westfeld and
			Pfitzmann, 1999.
		</figcaption>
	</figure>

	<p class="caveat">
		The test asks whether the values 2i and 2i+1 occur equally often, which a random payload forces
		and an untouched image has no reason to do. So anything that already randomised the low bits
		reads as embedded here: heavy sensor noise, prior resampling, a synthetic or dithered source.
		Read a positive as "these low bits are indistinguishable from random", which is evidence, not
		proof. It also only sees embedding laid down in order from the start, so a payload confined to a
		region will not show; the bit-plane wall is where that becomes visible.
	</p>
{/if}

<style>
	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.verdict {
		border-left: 2px solid var(--rule);
		padding-left: var(--s4);
		margin-bottom: var(--s5);
	}

	.verdict.detected {
		border-left-color: var(--signal);
	}

	.headline {
		margin: 0;
		font-size: var(--t-mid);
		font-weight: 600;
	}

	.detected .headline {
		color: var(--signal);
	}

	.detail {
		margin: var(--s2) 0 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	figure {
		margin: 0;
	}

	svg {
		display: block;
		width: 100%;
		height: auto;
		max-width: 900px;
		background: var(--panel-deep);
		border: 1px solid var(--rule);
	}

	.grid {
		stroke: var(--rule);
		stroke-width: 1;
	}

	.axis {
		fill: var(--muted);
		font-family: var(--mono);
		font-size: 10px;
	}

	.trace {
		fill: none;
		stroke: var(--ink);
		stroke-width: 2;
		stroke-linejoin: round;
		stroke-linecap: round;
	}

	.boundary {
		stroke: var(--signal);
		stroke-width: 1;
		stroke-dasharray: 3 3;
	}

	.boundary-label {
		fill: var(--signal);
		font-family: var(--mono);
		font-size: 10px;
	}

	figcaption {
		margin-top: var(--s2);
		font-size: var(--t-label);
		color: var(--muted);
	}

	.caveat {
		margin: var(--s4) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}
</style>
