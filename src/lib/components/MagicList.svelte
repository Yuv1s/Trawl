<script lang="ts">
	import type { MagicHit } from '$lib/worker/protocol';

	let { hits, size }: { hits: MagicHit[]; size: number } = $props();

	const embedded = $derived(hits.filter((h) => h.embedded));
	const header = $derived(hits.find((h) => !h.embedded) ?? null);

	const hex = (n: number) => `0x${n.toString(16)}`;
</script>

{#if header}
	<p class="lead">
		This file starts with a <strong>{header.label}</strong> signature.
	</p>
{/if}

{#if embedded.length === 0}
	<p class="clear">
		No other file signatures anywhere in the {size.toLocaleString()} bytes. Signatures shorter than four
		bytes are checked against a field the format constrains before being reported, so a match by chance
		is unlikely.
	</p>
{:else}
	<ul class="hits">
		{#each embedded as hit (hit.offset)}
			<li>
				<span class="label-text">{hit.label}</span>
				<span class="mono muted">
					at {hex(hit.offset)} · {((hit.offset / size) * 100).toFixed(1)}% into the file
				</span>
			</li>
		{/each}
	</ul>

	<p class="caveat">
		A file signature this far into another file did not get there by accident. What follows each
		offset is usually a complete, extractable file. Carving them out to save is not built yet.
	</p>
{/if}

<style>
	.lead {
		margin: 0 0 var(--s4);
		line-height: 1.6;
	}

	.lead strong {
		font-weight: 600;
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
		gap: var(--s3);
	}

	.hits li {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2) var(--s4);
		padding-bottom: var(--s3);
		border-bottom: 1px solid var(--rule);
	}

	.label-text {
		font-size: var(--t-mid);
		font-weight: 600;
		color: var(--signal);
	}

	.muted {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.caveat {
		margin: var(--s4) 0 0;
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}
</style>
