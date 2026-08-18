<script lang="ts">
	import { isWavError, type WavError, type WavStructure } from '$lib/worker/protocol';

	let { wav }: { wav: WavStructure | WavError | null } = $props();

	const walked = $derived(wav && !isWavError(wav) ? wav : null);
	const failed = $derived(wav && isWavError(wav) ? wav : null);

	const hex = (n: number) => `0x${n.toString(16).padStart(6, '0')}`;

	/** Chunks a player reads to make sound, as opposed to ones it steps over. */
	const KNOWN = new Set(['fmt ', 'data', 'fact']);

	const duration = (seconds: number) => {
		const minutes = Math.floor(seconds / 60);
		const rest = seconds - minutes * 60;
		return minutes ? `${minutes}m ${rest.toFixed(1)}s` : `${seconds.toFixed(2)}s`;
	};
</script>

{#if failed}
	<p class="lead">
		This file starts as a RIFF/WAVE but the walk stopped: {failed.error}.
	</p>
	{#if failed.chunks.length}
		<p class="clear">The chunks it did reach are below.</p>
	{/if}
{/if}

{#if walked}
	<dl class="facts">
		<div>
			<dt class="label">Encoding</dt>
			<dd class="mono">{walked.encoding}</dd>
		</div>
		<div>
			<dt class="label">Channels</dt>
			<dd class="mono">
				{walked.channels === 1 ? 'mono' : walked.channels === 2 ? 'stereo' : walked.channels}
			</dd>
		</div>
		<div>
			<dt class="label">Sample rate</dt>
			<dd class="mono">{walked.sampleRate.toLocaleString()} Hz</dd>
		</div>
		<div>
			<dt class="label">Length</dt>
			<dd class="mono">{duration(walked.seconds)}</dd>
		</div>
		<div>
			<dt class="label">Samples</dt>
			<dd class="mono">{(walked.frames * walked.channels).toLocaleString()}</dd>
		</div>
	</dl>
{/if}

{#if walked || failed?.chunks.length}
	{@const chunks = walked ? walked.chunks : (failed?.chunks ?? [])}
	<table>
		<thead>
			<tr>
				<th scope="col" class="label">Chunk</th>
				<th scope="col" class="label">Offset</th>
				<th scope="col" class="label num">Length</th>
				<th scope="col" class="label">Read by a player</th>
			</tr>
		</thead>
		<tbody>
			{#each chunks as chunk (chunk.offset)}
				<tr>
					<td class="mono id">{chunk.id}</td>
					<td class="mono muted">{hex(chunk.offset)}</td>
					<td class="mono num">{chunk.length.toLocaleString()}</td>
					<td class:flagged={!chunk.complete}>
						{#if !chunk.complete}
							runs past the end of the file
						{:else if KNOWN.has(chunk.id)}
							yes
						{:else}
							skipped
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

{#if walked?.text.length}
	<section class="found">
		<h3 class="label">Text in the chunks a player skips</h3>
		<ul>
			{#each walked.text as found (found.offset)}
				<li>
					<span class="mono big" class:flagged={found.text.includes('{')}>{found.text}</span>
					<span class="mono muted">{found.chunk} · {hex(found.offset)}</span>
				</li>
			{/each}
		</ul>
	</section>
{:else if walked}
	<p class="footnote">
		Nothing readable in the chunks outside the audio. A comment chunk is the audio equivalent of a
		PNG tEXt, so it is the first place worth checking.
	</p>
{/if}

{#if walked?.trailing}
	<section class="found">
		<h3 class="label">Past the declared end</h3>
		<p class="clear">
			The RIFF header says the file is {walked.trailing.offset.toLocaleString()} bytes long, and
			{walked.trailing.length.toLocaleString()} more sit after that. A player stops at the declared length
			and never reads them.
		</p>
	</section>
{/if}

<style>
	.lead {
		margin: 0 0 var(--s4);
		max-width: 72ch;
		line-height: 1.6;
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.facts {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s6);
		margin: 0 0 var(--s5);
		padding-bottom: var(--s4);
		border-bottom: 1px solid var(--rule);
	}

	.facts div {
		display: grid;
		gap: 2px;
	}

	.facts dt {
		margin: 0;
	}

	.facts dd {
		margin: 0;
		font-size: var(--t-mid);
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	th {
		text-align: left;
		padding: var(--s2) var(--s3) var(--s2) 0;
		border-bottom: 1px solid var(--rule);
	}

	.num {
		text-align: right;
	}

	td {
		padding: var(--s1) var(--s3) var(--s1) 0;
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
	}

	.id {
		font-weight: 500;
		white-space: pre;
	}

	.muted {
		color: var(--muted);
	}

	.found {
		margin-top: var(--s5);
	}

	.found h3 {
		margin: 0 0 var(--s3);
	}

	.found ul {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	.found li {
		display: grid;
		gap: 2px;
	}

	.big {
		font-size: var(--t-mid);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.found .muted {
		font-size: var(--t-label);
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
</style>
