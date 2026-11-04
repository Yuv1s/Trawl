<script lang="ts">
	import type { Chunk } from '$lib/worker/protocol';

	let {
		chunks,
		total = chunks.length,
		selected,
		onselect
	}: {
		chunks: Chunk[];
		/** How many the file holds, which `chunks` can be a capped copy of. */
		total?: number;
		selected: number;
		onselect: (offset: number) => void;
	} = $props();

	/** Rows drawn. A chunk is twelve bytes of file. */
	const ROWS_SHOWN = 500;
</script>

<table class="chunks">
	<thead>
		<tr>
			<th scope="col" class="label">Type</th>
			<th scope="col" class="label">Offset</th>
			<th scope="col" class="label num">Length</th>
			<th scope="col" class="label">Class</th>
			<th scope="col" class="label">CRC</th>
		</tr>
	</thead>
	<tbody>
		{#each chunks.slice(0, ROWS_SHOWN) as chunk (chunk.offset)}
			<tr class:current={chunk.offset === selected}>
				<td>
					<button type="button" onclick={() => onselect(chunk.offset)}>{chunk.kind}</button>
				</td>
				<td class="mono muted">0x{chunk.offset.toString(16).padStart(6, '0')}</td>
				<td class="mono num">{chunk.length.toLocaleString()}</td>
				<td class="muted">{chunk.ancillary ? 'ancillary' : 'critical'}</td>
				<td class="mono" class:flagged={!chunk.crcOk}>{chunk.crcOk ? 'ok' : 'mismatch'}</td>
			</tr>
		{/each}
	</tbody>
</table>

{#if total > ROWS_SHOWN}
	<p class="capped label">Showing the first {ROWS_SHOWN} of {total.toLocaleString()} chunks.</p>
{/if}

<style>
	.capped {
		margin: var(--s3) 0 0;
		color: var(--muted);
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	th {
		text-align: left;
		padding: var(--s2) var(--s3);
		border-bottom: 1px solid var(--rule);
		position: sticky;
		top: 0;
		background: var(--panel);
	}

	.num {
		text-align: right;
	}

	td {
		padding: var(--s1) var(--s3);
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
	}

	tr.current {
		background: var(--panel-lift);
	}

	button {
		background: none;
		border: 0;
		padding: 0;
		color: inherit;
		font-family: var(--mono);
		font-size: var(--t-data);
		font-weight: 500;
		cursor: pointer;
	}

	button:hover {
		color: var(--signal);
	}

	.muted {
		color: var(--muted);
	}
</style>
