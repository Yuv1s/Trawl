<script lang="ts">
	let {
		values,
		window,
		size,
		marker
	}: {
		values: number[];
		window: number;
		size: number;
		/** Byte offset where the container declares itself finished, if known. */
		marker: number | null;
	} = $props();

	const W = 720;
	const H = 200;
	const PAD = { top: 12, right: 16, bottom: 26, left: 34 };

	const x = (i: number) =>
		PAD.left + (i / Math.max(1, values.length - 1)) * (W - PAD.left - PAD.right);
	const y = (v: number) => PAD.top + (1 - v / 8) * (H - PAD.top - PAD.bottom);

	const path = $derived(
		values.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ')
	);

	const peak = $derived(values.length ? Math.max(...values) : 0);
	const low = $derived(values.length ? Math.min(...values) : 0);
	const mean = $derived(values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0);

	const markerX = $derived(
		marker !== null && size > 0 ? PAD.left + (marker / size) * (W - PAD.left - PAD.right) : null
	);

	const hex = (n: number) => `0x${n.toString(16)}`;
</script>

{#if values.length === 0}
	<p class="clear">The file is too small to window.</p>
{:else}
	<dl class="stats mono">
		<div>
			<dt>peak</dt>
			<dd>{peak.toFixed(2)}</dd>
		</div>
		<div>
			<dt>mean</dt>
			<dd>{mean.toFixed(2)}</dd>
		</div>
		<div>
			<dt>low</dt>
			<dd>{low.toFixed(2)}</dd>
		</div>
		<div>
			<dt>window</dt>
			<dd>{window.toLocaleString()} B</dd>
		</div>
	</dl>

	<figure>
		<svg viewBox="0 0 {W} {H}" role="img" aria-label="Entropy across the file">
			{#each [0, 4, 8] as tick (tick)}
				<line class="grid" x1={PAD.left} x2={W - PAD.right} y1={y(tick)} y2={y(tick)} />
				<text class="axis" x={PAD.left - 6} y={y(tick) + 3.5} text-anchor="end">{tick}</text>
			{/each}

			{#if markerX !== null}
				<line class="marker" x1={markerX} x2={markerX} y1={PAD.top} y2={H - PAD.bottom} />
				<text class="marker-label" x={markerX + 5} y={PAD.top + 10}>end of container</text>
			{/if}

			<path class="trace" d={path} />

			<text class="axis" x={PAD.left} y={H - 8} text-anchor="start">0</text>
			<text class="axis" x={W - PAD.right} y={H - 8} text-anchor="end">{hex(size)}</text>
		</svg>
		<figcaption>
			Bits of entropy per byte across {values.length} windows of {window.toLocaleString()} bytes.
		</figcaption>
	</figure>

	<p class="caveat">
		8.00 means the bytes are indistinguishable from random, which is what compressed or encrypted
		data looks like. A PNG sits near 8.00 through its pixel data by design, so a high reading is not
		a finding on its own. What is worth looking at is a change: a flat stretch inside a compressed
		file, or high entropy continuing past where the container should have ended.
	</p>
{/if}

<style>
	.clear {
		margin: 0;
		color: var(--muted);
	}

	.stats {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s5);
		margin: 0 0 var(--s4);
		font-size: var(--t-data);
	}

	.stats div {
		display: flex;
		gap: var(--s2);
	}

	.stats dt {
		color: var(--muted);
	}

	.stats dd {
		margin: 0;
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
		stroke-width: 1.5;
		stroke-linejoin: round;
	}

	.marker {
		stroke: var(--signal);
		stroke-width: 1;
		stroke-dasharray: 3 3;
	}

	.marker-label {
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
