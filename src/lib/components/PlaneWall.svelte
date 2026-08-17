<script lang="ts">
	import { CHANNEL_NAMES, type PlaneStat, type PlaneWall } from '$lib/worker/protocol';

	let {
		wall,
		error,
		width,
		height,
		open,
		onopen,
		onclose
	}: {
		wall: PlaneWall | null;
		error: string | null;
		width: number;
		height: number;
		open: { channel: number; bit: number; pixels: Uint8Array | null } | null;
		onopen: (channel: number, bit: number) => void;
		onclose: () => void;
	} = $props();

	const key = (p: PlaneStat) => `${p.channel}-${p.bit}`;

	/** Expands one grayscale byte per pixel into the RGBA a canvas wants. */
	function paint(canvas: HTMLCanvasElement, grey: Uint8Array, w: number, h: number) {
		const ctx = canvas.getContext('2d');
		if (!ctx) return;

		const image = ctx.createImageData(w, h);
		for (let i = 0; i < grey.length; i++) {
			const v = grey[i];
			image.data[i * 4] = v;
			image.data[i * 4 + 1] = v;
			image.data[i * 4 + 2] = v;
			image.data[i * 4 + 3] = 255;
		}
		ctx.putImageData(image, 0, 0);
	}

	function thumbnail(canvas: HTMLCanvasElement, stat: PlaneStat) {
		$effect(() => {
			if (!wall) return;
			const cells = wall.thumbWidth * wall.thumbHeight;
			const index = stat.channel * 8 + stat.bit;
			paint(
				canvas,
				wall.thumbnails.subarray(index * cells, (index + 1) * cells),
				wall.thumbWidth,
				wall.thumbHeight
			);
		});
	}

	function fullPlane(canvas: HTMLCanvasElement) {
		$effect(() => {
			if (open?.pixels) paint(canvas, open.pixels, width, height);
		});
	}
</script>

{#if !wall}
	<p class="clear">
		Pixels could not be decoded, so no planes were built.{error ? ` ${error}` : ''}
	</p>
{:else if open}
	<div class="viewer">
		<div class="viewer-head">
			<h3 class="mono">
				{CHANNEL_NAMES[open.channel]} · bit {open.bit}
			</h3>
			<span class="muted mono">{width} × {height}, 1:1</span>
			<button type="button" onclick={onclose}>Back to the wall</button>
		</div>

		{#if open.pixels}
			<div class="canvas-scroll">
				<canvas {@attach fullPlane} {width} {height}></canvas>
			</div>
		{:else}
			<div class="building" aria-live="polite">
				<span class="label">Building plane at full resolution</span>
			</div>
		{/if}
	</div>
{:else}
	<p class="lead">
		Every plane of every channel, {wall.thumbWidth}px wide. Upper planes hold the picture, lower
		planes hold noise. A payload usually shows up as a patch of noise where structure should be, or
		as structure where noise should be.
	</p>

	<div class="wall" style="--cols: 8">
		{#each wall.planes as stat (key(stat))}
			<button type="button" class="plane" onclick={() => onopen(stat.channel, stat.bit)}>
				<canvas
					{@attach (node: HTMLCanvasElement) => thumbnail(node, stat)}
					width={wall.thumbWidth}
					height={wall.thumbHeight}
				></canvas>
				<span class="tag mono">{CHANNEL_NAMES[stat.channel]}{stat.bit}</span>
				<span class="rate mono">{stat.transitionRate.toFixed(2)}</span>
			</button>
		{/each}
	</div>

	<p class="footnote">
		The number is the fraction of neighbouring pixels whose bit differs. Around 0.50 is
		indistinguishable from noise, near 0.00 is flat. It is reported, not judged: a fine gradient
		flips bit 1 on almost every step, so a high number in an upper plane is ordinary. Chi-square and
		RS analysis are the tests that will make claims.
	</p>
{/if}

<style>
	.lead {
		margin: 0 0 var(--s4);
		max-width: 78ch;
		line-height: 1.6;
	}

	.clear {
		margin: 0;
		color: var(--muted);
		line-height: 1.6;
	}

	.wall {
		display: grid;
		grid-template-columns: repeat(var(--cols), minmax(0, 1fr));
		gap: 1px;
		background: var(--rule);
		border: 1px solid var(--rule);
	}

	.plane {
		position: relative;
		display: block;
		padding: 0;
		border: 0;
		background: var(--ground);
		cursor: pointer;
		line-height: 0;
	}

	.plane canvas {
		display: block;
		width: 100%;
		height: auto;
		image-rendering: pixelated;
	}

	.plane:hover {
		outline: 1px solid var(--rule-bright);
		outline-offset: -1px;
	}

	.plane:focus-visible {
		outline: 2px solid var(--text);
		outline-offset: -2px;
		z-index: 1;
	}

	.tag,
	.rate {
		position: absolute;
		bottom: 0;
		font-size: var(--t-label);
		line-height: 1.4;
		padding: 0 3px;
		background: color-mix(in srgb, var(--ground) 82%, transparent);
	}

	.tag {
		left: 0;
		color: var(--text);
	}

	.rate {
		right: 0;
		color: var(--muted);
	}

	.footnote {
		margin: var(--s4) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	.viewer-head {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s3) var(--s4);
		padding-bottom: var(--s3);
		margin-bottom: var(--s4);
		border-bottom: 1px solid var(--rule);
	}

	.viewer-head h3 {
		margin: 0;
		font-size: var(--t-mid);
		font-weight: 500;
	}

	.viewer-head button {
		margin-left: auto;
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s1) var(--s3);
		cursor: pointer;
	}

	.viewer-head button:hover {
		background: var(--panel-lift);
	}

	.muted {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.canvas-scroll {
		overflow: auto;
		border: 1px solid var(--rule);
		background: var(--ground);
		max-height: 70vh;
	}

	.canvas-scroll canvas {
		display: block;
		image-rendering: pixelated;
	}

	.building {
		padding: var(--s6);
		border: 1px solid var(--rule);
		background: var(--ground);
		text-align: center;
	}
</style>
