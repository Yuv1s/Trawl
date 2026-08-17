<script lang="ts">
	import type { Sweep } from '$lib/worker/protocol';

	let { sweep, error }: { sweep: Sweep | null; error: string | null } = $props();

	const label = (c: { channels: string; bit: number; msbFirst: boolean }) =>
		`${c.channels} · bit ${c.bit} · ${c.msbFirst ? 'msb' : 'lsb'} first`;
</script>

{#if !sweep}
	<p class="clear">
		Pixels could not be decoded, so no sweep ran.{error ? ` ${error}` : ''}
	</p>
{:else if sweep.candidates.length === 0}
	<p class="clear">
		Swept {sweep.combinations} parameter combinations across
		{sweep.pixels.toLocaleString()} pixels. None produced a file signature, printable text, or a flag
		shape. That does not rule out an encrypted or non-sequential payload.
	</p>
{:else}
	<p class="lead">
		{sweep.candidates.length} of {sweep.combinations} combinations carried something readable.
	</p>

	<ul class="hits">
		{#each sweep.candidates as candidate (label(candidate))}
			<li>
				<div class="params">
					<span class="mono channels">{candidate.channels}</span>
					<span class="mono chip">bit {candidate.bit}</span>
					<span class="mono chip">{candidate.msbFirst ? 'msb' : 'lsb'} first</span>
				</div>

				<p class="reason">{candidate.reason}</p>

				{#if candidate.flags.length}
					<ul class="flags">
						{#each candidate.flags as flag (flag)}
							<li class="mono flagged">{flag}</li>
						{/each}
					</ul>
				{/if}

				<pre class="preview mono">{candidate.preview}</pre>
			</li>
		{/each}
	</ul>
{/if}

<style>
	.lead {
		margin: 0 0 var(--s4);
		line-height: 1.6;
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.hits {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s4);
	}

	.hits > li {
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		background: var(--panel-deep);
		padding: var(--s3) var(--s4);
	}

	.params {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2);
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
	}

	.reason {
		margin: var(--s2) 0 0;
		color: var(--muted);
		font-size: var(--t-data);
	}

	.flags {
		list-style: none;
		margin: var(--s3) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s1);
	}

	.flags li {
		font-size: var(--t-mid);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.preview {
		margin: var(--s3) 0 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		line-height: 1.5;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text);
	}
</style>
