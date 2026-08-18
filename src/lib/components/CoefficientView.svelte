<script lang="ts">
	import type { JpegStego } from '$lib/worker/protocol';

	let { jpeg }: { jpeg: JpegStego } = $props();

	/**
	 * The pairs the chi-square test compares.
	 *
	 * Flipping a low bit turns a value into `v ^ 1`, and `v >> 1` puts exactly
	 * those two together. Group 0 holds 0 and 1, the two values JSteg refuses to
	 * touch, so it is dropped: showing an untouched pair alongside the touched
	 * ones invites the wrong reading.
	 */
	const pairs = $derived.by(() => {
		const sorted = [...jpeg.histogram].sort((a, b) => a.value - b.value);

		return sorted
			.filter((bin) => bin.value % 2 === 0 && bin.value !== 0)
			.map((low) => ({
				group: low.value >> 1,
				bins: [low, sorted.find((b) => b.value === low.value + 1)]
			}))
			.filter((pair): pair is { group: number; bins: { value: number; count: number }[] } =>
				pair.bins.every(Boolean)
			);
	});

	const tallest = $derived(Math.max(1, ...pairs.flatMap((p) => p.bins.map((b) => b.count))));
	const zero = $derived(jpeg.histogram.find((b) => b.value === 0)?.count ?? 0);
</script>

<h3 class="label">Coefficient counts</h3>

<div
	class="chart"
	role="img"
	aria-label="Counts of each small coefficient value, grouped into the pairs the chi-square test compares"
>
	{#each pairs as pair (pair.group)}
		<div class="pair">
			{#each pair.bins as bin (bin.value)}
				<div class="column">
					<div class="bar" style="--fill: {(bin.count / tallest) * 100}%">
						<span class="count mono">{bin.count.toLocaleString()}</span>
					</div>
					<span class="tick mono">{bin.value}</span>
				</div>
			{/each}
		</div>
	{/each}
</div>

<p class="footnote">
	Each touching pair is one term of the chi-square test. A photograph's counts fall away from zero,
	so the two bars in a pair are plainly different heights. Replacing low bits averages them, and a
	row of level pairs is what the test is reading when it fires. Zero is excluded here along with
	one, because JSteg never writes to either: there are
	{zero.toLocaleString()} zero coefficients in this file, out of {jpeg.blocks.toLocaleString()} blocks.
</p>

<style>
	h3 {
		margin: 0 0 var(--s3);
	}

	.chart {
		display: flex;
		align-items: flex-end;
		gap: var(--s3);
		overflow-x: auto;
		padding-bottom: var(--s1);
	}

	.pair {
		display: flex;
		gap: 2px;
		flex: 1 1 0;
		min-width: 0;
	}

	.column {
		flex: 1 1 0;
		min-width: 22px;
		display: grid;
		gap: var(--s1);
	}

	.bar {
		height: 150px;
		display: flex;
		align-items: flex-end;
		justify-content: center;
		position: relative;
		background:
			linear-gradient(var(--rule-bright), var(--rule-bright)) bottom / 100% var(--fill) no-repeat,
			var(--panel-deep);
		border: 1px solid var(--rule);
	}

	.count {
		position: absolute;
		top: -1.35em;
		font-size: var(--t-label);
		color: var(--muted);
	}

	.tick {
		text-align: center;
		font-size: var(--t-label);
		color: var(--muted);
	}

	.footnote {
		margin: var(--s5) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	@media (max-width: 860px) {
		.count {
			display: none;
		}
	}
</style>
