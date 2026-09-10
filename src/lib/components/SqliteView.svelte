<script lang="ts">
	import type { SqliteDatabase, SqliteValue } from '$lib/worker/protocol';

	let { db }: { db: SqliteDatabase } = $props();

	const deletedTotal = $derived(db.tables.reduce((n, t) => n + t.deleted.length, 0));

	const summary = $derived([
		{ key: 'Page size', value: `${db.pageSize.toLocaleString()} B` },
		{ key: 'Pages', value: db.pageCount.toLocaleString() },
		{ key: 'Encoding', value: db.encoding },
		{ key: 'Tables', value: db.tableCount.toLocaleString() },
		...(db.freelistPages > 0
			? [
					{
						key: 'On the freelist',
						value: `${db.freelistPages} page${db.freelistPages === 1 ? '' : 's'}`
					}
				]
			: [])
	]);

	/** A column head for each column, falling back to positional names when the
	 *  CREATE statement did not spell them out. */
	function heads(columns: string[], width: number): string[] {
		if (columns.length >= width) return columns.slice(0, width);
		return Array.from({ length: width }, (_, i) => columns[i] ?? `col ${i + 1}`);
	}

	const cellText = (value: SqliteValue) => (value.kind === 'null' ? 'NULL' : value.text);
</script>

<div class="sqlite">
	{#if deletedTotal > 0}
		<ul class="findings">
			{#each db.tables.filter((t) => t.deleted.length > 0) as table (table.name)}
				<li class="flagged">
					{table.deleted.length} row{table.deleted.length === 1 ? '' : 's'} deleted from
					<span class="mono">{table.name}</span>, still in the file's free space
				</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			Every row in every table is one a query would still return, and no deleted row is left in the
			free space. That is what an untouched database looks like.
		</p>
	{/if}

	<div class="info">
		<h3 class="label">Database</h3>
		<dl>
			{#each summary as field (field.key)}
				<div>
					<dt class="label">{field.key}</dt>
					<dd class="mono">{field.value}</dd>
				</div>
			{/each}
		</dl>
	</div>

	{#each db.tables as table (table.name)}
		{@const width = Math.max(
			table.columns.length,
			table.rows[0]?.length ?? 0,
			table.deleted[0]?.length ?? 0,
			1
		)}
		{@const cols = heads(table.columns, width)}
		{@const cells = [...Array(width).keys()]}
		<div class="table">
			<div class="table-scroll">
				<table>
					<caption class="label">
						<span class="mono name">{table.name}</span>
						<span class="count"
							>{table.rowCount.toLocaleString()} row{table.rowCount === 1 ? '' : 's'}{table.deleted
								.length > 0
								? `, ${table.deleted.length} deleted`
								: ''}</span
						>
					</caption>
					<thead>
						<tr>
							{#each cols as column, i (i)}
								<th scope="col" class="label">{column}</th>
							{/each}
						</tr>
					</thead>
					<tbody>
						{#each table.rows as row, r (r)}
							<tr>
								{#each cells as c (c)}
									{@const value = row[c]}
									<td class="mono" class:muted={!value || value.kind === 'null'}>
										{value ? cellText(value) : ''}
									</td>
								{/each}
							</tr>
						{/each}
						{#each table.deleted as row, r (`d${r}`)}
							<tr class="deleted">
								{#each cells as c (c)}
									{@const value = row[c]}
									<td class="mono" class:muted={!value || value.kind === 'null'}>
										{value ? cellText(value) : ''}
									</td>
								{/each}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if table.rowCount > table.rows.length}
				<p class="capped label">
					Showing the first {table.rows.length} of {table.rowCount.toLocaleString()} rows.
				</p>
			{/if}
		</div>
	{/each}

	<p class="footnote">
		A row shown in the accent was deleted and is still in the file: SQLite unlinks a deleted row
		from its page but leaves the bytes in the free space until something reuses them. Recovered from
		that space, so it can be a row a query would never return. Anything the freeblock header
		overwrote, usually the id, is gone.
	</p>
</div>

<style>
	.sqlite {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: var(--s4);
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
		text-wrap: pretty;
	}

	.findings {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
	}

	.findings li {
		padding-left: var(--s3);
		border-left: 1px solid var(--signal);
		color: var(--text);
		line-height: 1.5;
		max-width: 78ch;
		text-wrap: pretty;
	}

	.info dl {
		margin: var(--s2) 0 0;
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--s1) var(--s3);
	}

	.info dt {
		color: var(--muted);
	}

	.info dd {
		margin: 0;
		color: var(--text);
	}

	.table-scroll {
		overflow-x: auto;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	caption {
		display: flex;
		align-items: baseline;
		gap: var(--s3);
		text-align: left;
		padding-bottom: var(--s2);
	}

	caption .name {
		font-weight: 600;
		color: var(--text);
	}

	.count {
		font-variant-numeric: tabular-nums;
		color: var(--muted);
	}

	th {
		text-align: left;
		padding: var(--s2) var(--s3);
		border-bottom: 1px solid var(--rule);
		white-space: nowrap;
	}

	td {
		padding: var(--s1) var(--s3);
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
		vertical-align: baseline;
		max-width: 40ch;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* A deleted row reads like a finding: the accent, and its own left stripe the
	   way every other panel marks the byte worth looking at. */
	tr.deleted td {
		color: var(--signal);
	}

	tr.deleted td:first-child {
		box-shadow: inset 2px 0 0 var(--signal);
	}

	.muted {
		color: var(--muted);
	}

	.capped {
		margin: var(--s2) 0 0;
		color: var(--muted);
	}

	.footnote {
		margin: 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
		text-wrap: pretty;
	}
</style>
