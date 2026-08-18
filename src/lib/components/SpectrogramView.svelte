<script lang="ts">
	import type { Spectrogram } from '$lib/worker/protocol';

	let { spectrogram, error }: { spectrogram: Spectrogram | null; error: string | null } = $props();

	/**
	 * A picture drawn at the bottom of the dynamic range is nearly black against
	 * a nearly black floor. Rather than pick one curve and hope, the reader gets
	 * the three that answer the three situations, named for what they do.
	 */
	const CURVES = [
		{ id: 'measured', name: 'As measured', gamma: 1 },
		{ id: 'lift', name: 'Lift the quiet', gamma: 2.6 },
		{ id: 'peaks', name: 'Loudest only', gamma: 0.32 }
	] as const;

	let curve = $state<(typeof CURVES)[number]['id']>('measured');
	let cursor = $state<{ seconds: number; hz: number } | null>(null);

	/**
	 * Level to colour. Runs from the panel's own dark through its rule colour to
	 * the body text, so the image sits in the same hue family as everything
	 * around it rather than looking pasted on.
	 *
	 * Deliberately monochrome. Tinting the loud end with the signal amber looked
	 * better and lied: the loudest thing in an ordinary recording is its own bass
	 * line, and colouring that like a finding is a claim the transform cannot
	 * make.
	 */
	function ramp(gamma: number): Uint8Array {
		const table = new Uint8Array(256 * 3);
		const stops: [number, number, number][] = [
			[0x0f, 0x14, 0x17],
			[0x3a, 0x4d, 0x55],
			[0xd8, 0xde, 0xdc]
		];

		for (let i = 0; i < 256; i++) {
			const t = Math.pow(i / 255, 1 / gamma) * (stops.length - 1);
			const low = Math.min(Math.floor(t), stops.length - 2);
			const f = t - low;

			for (let c = 0; c < 3; c++) {
				table[i * 3 + c] = Math.round(stops[low][c] + (stops[low + 1][c] - stops[low][c]) * f);
			}
		}

		return table;
	}

	function paint(canvas: HTMLCanvasElement) {
		$effect(() => {
			if (!spectrogram) return;
			const ctx = canvas.getContext('2d');
			if (!ctx) return;

			const gamma = CURVES.find((c) => c.id === curve)?.gamma ?? 1;
			const table = ramp(gamma);
			const image = ctx.createImageData(spectrogram.width, spectrogram.height);

			for (let i = 0; i < spectrogram.pixels.length; i++) {
				const at = spectrogram.pixels[i] * 3;
				image.data[i * 4] = table[at];
				image.data[i * 4 + 1] = table[at + 1];
				image.data[i * 4 + 2] = table[at + 2];
				image.data[i * 4 + 3] = 255;
			}

			ctx.putImageData(image, 0, 0);
		});
	}

	function track(event: PointerEvent) {
		if (!spectrogram) return;
		const box = (event.currentTarget as HTMLElement).getBoundingClientRect();
		const x = (event.clientX - box.left) / box.width;
		const y = (event.clientY - box.top) / box.height;

		cursor = {
			seconds: Math.max(0, Math.min(1, x)) * spectrogram.seconds,
			hz: (1 - Math.max(0, Math.min(1, y))) * spectrogram.maxFrequency
		};
	}

	const TICKS = [0, 0.25, 0.5, 0.75, 1];

	const khz = (hz: number) =>
		hz >= 1000 ? `${(hz / 1000).toFixed(1)}k` : Math.round(hz).toString();
</script>

{#if !spectrogram}
	<p class="clear">
		No spectrogram was drawn.{error
			? ` ${error}`
			: ' The file carries no samples, or the clip is shorter than one analysis window.'}
		The RIFF chunk list and the byte-level tools still ran, so start there.
	</p>
{:else}
	<div class="head">
		<p class="lead">
			Time runs left to right, frequency bottom to top. A payload drawn here is a picture, not a
			statistic, so nothing below judges it. Look at it.
		</p>

		<div class="readout mono">
			{#if cursor}
				<span class="value">{cursor.seconds.toFixed(2)} s</span>
				<span class="value">{Math.round(cursor.hz).toLocaleString()} Hz</span>
			{:else}
				<span class="muted">Point at the image to read off time and frequency</span>
			{/if}
		</div>
	</div>

	<div class="plot">
		<ul class="freq mono" aria-hidden="true">
			{#each TICKS as t (t)}
				<li>{khz(t * spectrogram.maxFrequency)}</li>
			{/each}
		</ul>

		<div
			class="well"
			role="img"
			aria-label="Spectrogram of {spectrogram.seconds.toFixed(
				1
			)} seconds of audio, from 0 to {Math.round(spectrogram.maxFrequency)} hertz"
			onpointermove={track}
			onpointerleave={() => (cursor = null)}
		>
			<canvas {@attach paint} width={spectrogram.width} height={spectrogram.height}></canvas>
		</div>

		<div class="corner"></div>

		<ul class="time mono" aria-hidden="true">
			{#each TICKS as t (t)}
				<li>{(t * spectrogram.seconds).toFixed(1)}s</li>
			{/each}
		</ul>
	</div>

	<div class="controls">
		<span class="label">Brightness curve</span>
		<div class="segmented" role="group" aria-label="Brightness curve">
			{#each CURVES as option (option.id)}
				<button
					type="button"
					class:on={curve === option.id}
					aria-pressed={curve === option.id}
					onclick={() => (curve = option.id)}
				>
					{option.name}
				</button>
			{/each}
		</div>
	</div>

	<p class="footnote">
		{spectrogram.width.toLocaleString()} × {spectrogram.height} from a {spectrogram.window}-point
		transform stepping {spectrogram.hop} samples at a time. Brightness is relative to the loudest bin
		in this file, not to an absolute level, so a quiet recording is drawn at the same contrast as a loud
		one.
	</p>
{/if}

<style>
	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--s3) var(--s5);
		margin-bottom: var(--s4);
	}

	.lead {
		margin: 0;
		max-width: 58ch;
		line-height: 1.6;
	}

	.readout {
		display: flex;
		gap: var(--s3);
		font-size: var(--t-data);
		white-space: nowrap;
	}

	/* Not amber. A cursor position is a measurement, not a finding, and the
	   accent has to keep meaning one thing. */
	.readout .value {
		color: var(--text);
		min-width: 6ch;
		text-align: right;
	}

	.readout .muted {
		color: var(--muted);
		font-size: var(--t-label);
	}

	/* Rulers sit outside the image so no tick ever covers a pixel of data. */
	.plot {
		display: grid;
		grid-template-columns: auto minmax(0, 1fr);
		grid-template-rows: minmax(0, 1fr) auto;
	}

	.freq,
	.time {
		list-style: none;
		margin: 0;
		padding: 0;
		font-size: var(--t-label);
		color: var(--muted);
	}

	.freq {
		display: flex;
		flex-direction: column-reverse;
		justify-content: space-between;
		align-items: flex-end;
		padding-right: var(--s2);
		/* Half a line at each end so a label centres on its edge. */
		margin: -0.7em 0;
	}

	.time {
		grid-column: 2;
		display: flex;
		justify-content: space-between;
		padding-top: var(--s2);
	}

	.time li:first-child {
		margin-left: -0.5ch;
	}

	.corner {
		grid-row: 2;
		grid-column: 1;
	}

	.well {
		border: 1px solid var(--rule);
		background: var(--ground);
		line-height: 0;
		cursor: crosshair;
		touch-action: none;
	}

	.well canvas {
		display: block;
		width: 100%;
		height: auto;
		max-height: 62vh;
		object-fit: fill;
	}

	.controls {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s3);
		margin-top: var(--s4);
	}

	.segmented {
		display: flex;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		overflow: hidden;
	}

	.segmented button {
		background: none;
		border: 0;
		border-left: 1px solid var(--rule);
		color: var(--muted);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s1) var(--s3);
		cursor: pointer;
		transition:
			background-color 140ms var(--ease),
			color 140ms var(--ease);
	}

	.segmented button:first-child {
		border-left: 0;
	}

	.segmented button:hover {
		color: var(--text);
	}

	.segmented button.on {
		background: var(--panel-lift);
		color: var(--text);
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

	@media (max-width: 640px) {
		.freq {
			display: none;
		}

		.plot {
			grid-template-columns: minmax(0, 1fr);
		}

		.time {
			grid-column: 1;
		}
	}
</style>
