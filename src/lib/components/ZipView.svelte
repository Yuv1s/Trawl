<script lang="ts">
	import type { ZipArchive } from '$lib/worker/protocol';

	let { archive }: { archive: ZipArchive } = $props();

	const listed = $derived(archive.entries.filter((e) => !e.undeclared).length);
	const hidden = $derived(archive.entries.filter((e) => e.undeclared));
	const locked = $derived(archive.entries.filter((e) => e.encrypted));
	const arguing = $derived(archive.entries.filter((e) => e.disagreement !== null));
	/** Entries whose decompressed content carried a flag shape. */
	const carrying = $derived(archive.entries.filter((e) => (e.flags?.length ?? 0) > 0));

	/** Everything about the archive itself that a zip tool would not have written. */
	const notes = $derived(
		[
			archive.prefix > 0 &&
				`${archive.prefix.toLocaleString()} bytes sit before the first header, so the archive starts partway into the file`,
			archive.trailing > 0 &&
				`${archive.trailing.toLocaleString()} bytes follow the end of the directory, which no zip tool writes`,
			archive.declared !== listed &&
				`the directory says it holds ${archive.declared} but lists ${listed}`
		].filter((note): note is string => typeof note === 'string')
	);

	const bytes = (n: number) => `${n.toLocaleString()} B`;
	const hex = (n: number) => `0x${n.toString(16).padStart(6, '0')}`;
</script>

<div class="zip">
	{#if hidden.length > 0 || arguing.length > 0 || notes.length > 0 || carrying.length > 0}
		<ul class="findings">
			{#each carrying as entry (entry.offset)}
				{#each entry.flags ?? [] as flag (flag)}
					<li class="flagged">
						<span class="mono big">{flag}</span>
						<span class="muted"> inside <span class="mono">{entry.name}</span></span>
					</li>
				{/each}
			{/each}
			{#each hidden as entry (entry.offset)}
				<li class="flagged">
					<span class="mono">{entry.name}</span> is in the file but not in the directory, so no ordinary
					reader will list it
				</li>
			{/each}
			{#each arguing as entry (entry.offset)}
				<li class="flagged">
					<span class="mono">{entry.name}</span>: {entry.disagreement}
				</li>
			{/each}
			{#each notes as note (note)}
				<li>{note}</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			The directory and the headers agree on every entry, nothing sits outside the archive, and no
			entry is hidden from a listing. That is what an untouched archive looks like.
		</p>
	{/if}

	{#if archive.comment}
		<div class="comment">
			<h3 class="label">Archive comment</h3>
			<pre class="mono">{archive.comment}</pre>
		</div>
	{/if}

	<table>
		<caption class="label"
			>{archive.entries.length} entries{locked.length > 0
				? `, ${locked.length} encrypted`
				: ''}</caption
		>
		<thead>
			<tr>
				<th scope="col" class="label">Name</th>
				<th scope="col" class="label">Method</th>
				<th scope="col" class="label num">Stored</th>
				<th scope="col" class="label num">Actual</th>
				<th scope="col" class="label">Offset</th>
			</tr>
		</thead>
		<tbody>
			{#each archive.entries as entry (entry.offset)}
				<tr class:odd={entry.undeclared || entry.disagreement !== null}>
					<td>
						<span class="mono name">{entry.name}</span>
						{#if entry.undeclared}
							<span class="mono chip flagged">not in the directory</span>
						{/if}
						{#if entry.encrypted}
							<span class="mono chip">encrypted</span>
						{/if}
					</td>
					<td class="muted">{entry.method}</td>
					<td class="mono num">{bytes(entry.compressed)}</td>
					<td class="mono num">{bytes(entry.uncompressed)}</td>
					<td class="mono muted">{hex(entry.offset)}</td>
				</tr>
				{#if entry.comment}
					<tr class="aside">
						<td colspan="5"><span class="label">comment</span> {entry.comment}</td>
					</tr>
				{/if}
				{#if entry.text}
					<tr class="aside">
						<td colspan="5">
							<span class="label">content</span>
							<pre class="content mono">{entry.text}</pre>
						</td>
					</tr>
				{:else if entry.readError}
					<tr class="aside">
						<td colspan="5">
							<span class="label">content</span>
							<span class="muted">could not read: {entry.readError}</span>
						</td>
					</tr>
				{/if}
			{/each}
		</tbody>
	</table>

	{#if locked.length > 0}
		<p class="footnote">
			Trawl does not crack archive passwords. Reversing one means guessing until a checksum matches,
			which belongs on hardware you control running something built for it.
		</p>
	{/if}
</div>

<style>
	.zip {
		display: grid;
		gap: var(--s4);
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	/* What is wrong with the archive, before the list of what is in it. Someone
	   opening this pane is looking for the odd one out, not an inventory. */
	.findings {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
	}

	.findings li {
		padding-left: var(--s3);
		border-left: 1px solid var(--rule);
		color: var(--muted);
		line-height: 1.5;
		max-width: 78ch;
	}

	.findings li.flagged {
		border-left-color: var(--signal);
		color: var(--text);
	}

	.comment pre {
		margin: var(--s2) 0 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text);
		user-select: all;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	caption {
		text-align: left;
		padding-bottom: var(--s2);
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
		vertical-align: baseline;
	}

	.name {
		overflow-wrap: anywhere;
	}

	/* A row worth a second look, marked on the edge rather than by filling it,
	   so a long listing still reads as one table. */
	tr.odd td:first-child {
		box-shadow: inset 2px 0 0 var(--signal);
	}

	tr.aside td {
		padding-top: 0;
		color: var(--muted);
		overflow-wrap: anywhere;
	}

	tr.aside .label {
		margin-right: var(--s2);
	}

	.content {
		margin: var(--s1) 0 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		max-height: 20rem;
		overflow: auto;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text);
		line-height: 1.5;
		user-select: all;
	}

	.muted {
		color: var(--muted);
	}

	.chip {
		margin-left: var(--s2);
		font-size: var(--t-label);
		color: var(--muted);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		padding: 1px var(--s2);
		white-space: nowrap;
	}

	.chip.flagged {
		color: var(--signal);
		border-color: var(--signal);
	}

	.footnote {
		margin: 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	@media (max-width: 640px) {
		/* Five columns of numbers do not fit a phone. The table scrolls inside
		   its own box rather than pushing the page sideways. */
		table {
			display: block;
			overflow-x: auto;
			white-space: nowrap;
		}
		.name {
			overflow-wrap: normal;
		}
	}
</style>
