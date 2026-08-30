<script lang="ts">
	import type { GifAnalysis, GifSource, NestedAnalysis } from '$lib/worker/protocol';

	let { gif, nested }: { gif: GifAnalysis | null; nested: NestedAnalysis | null } = $props();

	const nestedCapped = (nested: NestedAnalysis | null): boolean => nested?.capped ?? false;

	const sources = $derived(gif?.sources ?? []);
	const hasSources = $derived(sources.length > 0);
	const frames = $derived(sources.filter((s) => s.kind === 'frame'));
	const diffs = $derived(sources.filter((s) => s.kind === 'difference'));

	const framesHit = $derived(
		frames.some((f) => f.lsb.candidates.length > 0 || f.chi?.detected || f.rs?.detected)
	);
	const diffsHit = $derived(
		diffs.some((d) => d.lsb.candidates.length > 0 || d.chi?.detected || d.rs?.detected)
	);

	function formatDisposal(method: string | null): string {
		switch (method) {
			case '0':
			case 'none':
				return 'none (keep)';
			case '1':
			case 'doNotDispose':
				return 'do not dispose (keep)';
			case '2':
			case 'background':
				return 'background (clear to bg)';
			case '3':
			case 'previous':
				return 'previous (restore)';
			default:
				return method ?? 'unknown';
		}
	}

	function describeSource(source: GifSource): string {
		if (source.kind === 'frame') {
			const delayStr = source.delay ? ` · ${(source.delay / 100).toFixed(2)}s` : '';
			const dispStr = source.disposal ? ` · disposal: ${formatDisposal(source.disposal)}` : '';
			return `frame ${source.from}${delayStr}${dispStr}`;
		}
		return `frames ${source.from} → ${source.to} difference`;
	}
</script>

{#if !gif}
	<p class="clear">This file is not a GIF, so no frame analysis ran.</p>
{:else if gif.error}
	<p class="clear">
		<strong>GIF analysis failed:</strong>
		{gif.error}
	</p>
{:else if !hasSources}
	<p class="clear">
		No frames could be analysed. The file is a GIF but the decoder found no image descriptors.
		{#if gif.capped}
			<br />
			<span class="muted">The walk was capped at the frame or pixel budget.</span>
		{/if}
	</p>
{:else}
	{#if nestedCapped(nested)}
		<p class="capped">
			The recursive walk hit a depth, count, or byte budget and stopped early. Some embedded files
			were not analysed.
		</p>
	{/if}

	<div class="summary">
		<p class="lead">
			{frames.length} frame{frames.length === 1 ? '' : 's'} analysed
			{diffs.length > 0
				? `, ${diffs.length} consecutive difference${diffs.length === 1 ? '' : 's'} checked`
				: ''}
			{gif.capped ? ' · capped at work budget' : ''}.
		</p>
	</div>

	{#if framesHit || diffsHit}
		<ul class="findings">
			{#each frames as frame (frame.from)}
				{#if frame.lsb.candidates.length > 0 || frame.chi?.detected || frame.rs?.detected}
					<li>
						<h4 class="source-label">{describeSource(frame)}</h4>
						{@render sourceDetail(frame)}
					</li>
				{/if}
			{/each}
			{#each diffs as diff (diff.from)}
				{#if diff.lsb.candidates.length > 0 || diff.chi?.detected || diff.rs?.detected}
					<li>
						<h4 class="source-label">{describeSource(diff)}</h4>
						{@render sourceDetail(diff)}
					</li>
				{/if}
			{/each}
		</ul>
	{:else}
		<p class="clear">
			None of the {frames.length} frame{frames.length === 1 ? '' : 's'}
			{diffs.length > 0 ? ` or ${diffs.length} difference${diffs.length === 1 ? '' : 's'}` : ''}
			produced a candidate. LSB sweep, chi-square, and RS analysis all came up empty.
		</p>
	{/if}

	{#if gif.capped && framesHit === false && diffsHit === false}
		<p class="muted">
			The work budget capped this analysis before all frames were checked. A manual re-analysis of a
			carved frame will run without the automatic budget.
		</p>
	{/if}
{/if}

{#snippet sourceDetail(frame: GifSource)}
	<div class="detail">
		{#if frame.lsb.candidates.filter((c) => c.flags.length > 0).length > 0}
			<ul class="lsb">
				{#each frame.lsb.candidates.filter((c) => c.flags.length > 0) as cand (cand.channels + cand.bit + cand.msbFirst)}
					<li>
						<span class="channels mono">{cand.channels}</span>
						<span class="chip">{cand.bit} · {cand.msbFirst ? 'MSB' : 'LSB'} first</span>
						<span class="reason">{cand.reason}</span>
						{#if cand.flags.length > 0}
							<ul class="flags">
								{#each cand.flags as flag (flag)}
									<li class="mono flagged">{flag}</li>
								{/each}
							</ul>
						{/if}
						<pre class="preview mono">{cand.preview}</pre>
					</li>
				{/each}
			</ul>
		{/if}

		{#if frame.chi?.detected}
			<p class="detector chi">
				<strong>Chi-square:</strong> ~{(frame.chi?.embeddedFraction ?? 0) * 100}% embedded
			</p>
		{/if}

		{#if frame.rs?.detected}
			<p class="detector rs">
				<strong>RS analysis:</strong> ~{(frame.rs?.rate ?? 0) * 100}% of low bits embedded
			</p>
		{/if}
	</div>
{/snippet}

<style>
	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.capped {
		margin: 0 0 var(--s3);
		padding: var(--s2) var(--s3);
		background: var(--panel-deep);
		border: 1px solid var(--signal);
		border-radius: var(--radius);
		color: var(--text);
		font-size: var(--t-data);
		line-height: 1.6;
	}

	.summary {
		margin-bottom: var(--s4);
	}

	.lead {
		margin: 0 0 var(--s2);
		line-height: 1.6;
		font-weight: 500;
	}

	.findings {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	.findings li {
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		background: var(--panel-deep);
		padding: var(--s3) var(--s4);
	}

	.source-label {
		margin: 0 0 var(--s2);
		font-size: var(--t-mid);
		font-weight: 600;
		color: var(--signal);
	}

	.detail {
		display: grid;
		gap: var(--s2);
	}

	.lsb {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
	}

	.lsb li {
		display: grid;
		gap: var(--s1);
	}

	.channels {
		font-size: var(--t-mid);
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.08em;
	}

	.chip {
		font-size: var(--t-label);
		color: var(--muted);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		padding: 1px var(--s2);
		display: inline-block;
	}

	.reason {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.flags {
		list-style: none;
		margin: var(--s2) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s1);
	}

	.flags li {
		font-size: var(--t-mid);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.flags li.flagged {
		color: var(--signal);
	}

	.preview {
		margin: var(--s2) 0 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		line-height: 1.5;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text);
		user-select: all;
		max-height: 12rem;
		overflow: auto;
	}

	.detector {
		margin: 0;
		font-size: var(--t-data);
		color: var(--muted);
	}

	.detector.chi {
		color: var(--signal);
	}

	.detector.rs {
		color: var(--signal);
	}

	@media (max-width: 640px) {
		.findings li {
			padding: var(--s2) var(--s3);
		}
	}
</style>
