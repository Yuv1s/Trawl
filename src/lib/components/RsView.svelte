<script lang="ts">
	import type { ChiSquare, RsAnalysis } from '$lib/worker/protocol';

	let { rs, chi, error }: { rs: RsAnalysis | null; chi: ChiSquare | null; error: string | null } =
		$props();

	const percent = (v: number) => `${(v * 100).toFixed(1)}%`;

	const bars = $derived(
		rs
			? [
					{ label: 'Rₘ', value: rs.regular, pair: 0 },
					{ label: 'R₋ₘ', value: rs.regularNegated, pair: 0 },
					{ label: 'Sₘ', value: rs.singular, pair: 1 },
					{ label: 'S₋ₘ', value: rs.singularNegated, pair: 1 }
				]
			: []
	);

	/** Two estimators from different mechanisms; a gap between them is information. */
	const crossCheck = $derived.by(() => {
		if (!rs?.detected || !chi?.detected) return null;
		const gap = Math.abs(rs.rate - chi.embeddedFraction);
		return { gap, agree: gap < 0.15 };
	});
</script>

{#if !rs}
	<p class="clear">
		Pixels could not be decoded, so the test did not run.{error ? ` ${error}` : ''}
	</p>
{:else if !rs.reliable}
	<p class="clear">
		The model did not fit this image, so no estimate is offered. That happens on images with too
		little local texture for the test to read, and a number here would be invented rather than
		measured.
	</p>
{:else}
	<div class="verdict" class:detected={rs.detected}>
		{#if rs.detected}
			<p class="headline">About {percent(rs.rate)} of the low bits carry a payload.</p>
		{:else}
			<p class="headline">No payload in the low bits.</p>
		{/if}
		<p class="detail">
			Estimated across {rs.groups.toLocaleString()} groups of four neighbouring pixels.
		</p>
	</div>

	{#if crossCheck}
		<p class="cross" class:disagree={!crossCheck.agree}>
			{#if crossCheck.agree}
				Chi-square independently estimates {percent(chi?.embeddedFraction ?? 0)}. Two different
				mechanisms agreeing is the strongest evidence this tool can offer.
			{:else}
				Chi-square estimates {percent(chi?.embeddedFraction ?? 0)}, a gap of
				{percent(crossCheck.gap)}. They disagree, which usually means the payload sits in one part
				of the image rather than spread through it. Chi-square measures length better in that case;
				RS measures rate better when the payload is scattered.
			{/if}
		</p>
	{/if}

	<h3 class="label">Group counts</h3>
	<ul class="bars">
		{#each bars as bar (bar.label)}
			<li class:second={bar.pair === 1}>
				<span class="key mono">{bar.label}</span>
				<span class="track"><span class="fill" style="width: {bar.value * 100}%"></span></span>
				<span class="num mono">{percent(bar.value)}</span>
			</li>
		{/each}
	</ul>

	<p class="caveat">
		Neighbouring pixels in a real photograph are similar, so nudging a group's low bits usually
		makes it rougher. Nudging them the other way, pairing each value with its lower neighbour
		instead of its upper one, should behave the same on an untouched image. It does not once a
		payload is present, and the size of that gap is what the estimate comes from. Fridrich, Goljan
		and Du, 2001.
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
	}

	.cross {
		margin: var(--s4) 0 0;
		padding: var(--s3) var(--s4);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		background: var(--panel-deep);
		max-width: 78ch;
		line-height: 1.6;
	}

	.cross.disagree {
		border-color: var(--rule-bright);
	}

	h3 {
		margin: var(--s5) 0 var(--s3);
	}

	.bars {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
		max-width: 46rem;
	}

	.bars li {
		display: grid;
		grid-template-columns: 4ch 1fr 6ch;
		align-items: center;
		gap: var(--s3);
	}

	.second {
		margin-bottom: 0;
	}

	.bars li:nth-child(2) {
		margin-bottom: var(--s3);
	}

	.key {
		font-size: var(--t-data);
		color: var(--muted);
	}

	.track {
		height: 10px;
		background: var(--panel-deep);
		border: 1px solid var(--rule);
	}

	.fill {
		display: block;
		height: 100%;
		background: var(--ink);
	}

	.num {
		font-size: var(--t-data);
		text-align: right;
	}

	.caveat {
		margin: var(--s5) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}
</style>
