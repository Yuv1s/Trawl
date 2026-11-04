<script lang="ts">
	import type { NestedAnalysis, NestedArtifact, ZipArchive, ZipEntry } from '$lib/worker/protocol';
	import { firstOfEach, tally } from './tally';

	let {
		archive,
		onanalyse,
		onpeel,
		nested
	}: {
		archive: ZipArchive;
		onanalyse?: (bytes: Uint8Array, name: string) => void;
		onpeel?: (text: string) => void;
		nested?: NestedAnalysis | null;
	} = $props();

	/** Rows drawn. An archive can list sixty-five thousand, and past a few hundred a table
	 *  stops being something a person reads and starts being what freezes the tab. */
	const ROWS_SHOWN = 500;
	/** How many rows also show what the entry holds. */
	const CONTENTS_SHOWN = 100;
	/** Lines each kind of finding gets above the table. */
	const FINDINGS_SHOWN = 50;

	const listed = $derived(archive.entries.filter((e) => !e.undeclared).length);
	const hidden = $derived(archive.entries.filter((e) => e.undeclared));
	const locked = $derived(archive.entries.filter((e) => e.encrypted));
	const arguing = $derived(archive.entries.filter((e) => e.disagreement !== null));

	/** Every distinct flag the entries carried, with the first entry that had it. */
	const carried = $derived(firstOfEach(archive.entries, (entry) => entry.flags));

	/** Why entries were not opened, with how many of them for each reason. */
	const unopened = $derived([...tally(archive.entries, (entry) => entry.notOpened).counts]);

	/** Everything about the archive itself that a zip tool would not have written. */
	const notes = $derived(
		[
			archive.prefix > 0 &&
				`${archive.prefix.toLocaleString()} bytes sit before the first header, so the archive starts partway into the file`,
			archive.trailing > 0 &&
				`${archive.trailing.toLocaleString()} bytes follow the end of the directory, which no zip tool writes`,
			archive.declared !== listed &&
				`the directory says it holds ${archive.declared} but lists ${listed}`,
			archive.capped &&
				`Trawl stopped walking headers at ${archive.entries.length.toLocaleString()}, so this file may hold more than the directory lists`
		].filter((note): note is string => typeof note === 'string')
	);

	const bytes = (n: number) => `${n.toLocaleString()} B`;
	const hex = (n: number) => `0x${n.toString(16).padStart(6, '0')}`;

	/** What the walk made of each entry, by where its header sits. */
	const children = $derived(
		new Map(
			(nested?.roots ?? [])
				.filter((child) => child.source === 'zip')
				.map((child) => [child.offset, child])
		)
	);

	function findingsCount(artifact: NestedArtifact): number {
		let count = artifact.findings.length;
		for (const child of artifact.children) count += findingsCount(child);
		return count;
	}

	/** Found once per child, rather than walking its whole tree again for every row. */
	const findingsOf = $derived(
		new Map([...children].map(([offset, child]) => [offset, findingsCount(child)]))
	);

	const worthAlook = (entry: ZipEntry) =>
		entry.undeclared ||
		entry.disagreement !== null ||
		(entry.flags?.length ?? 0) > 0 ||
		(findingsOf.get(entry.offset) ?? 0) > 0;

	/** The rows drawn. When they cannot all be, the ones with something to say go first. */
	const rows = $derived(
		archive.entries.length <= ROWS_SHOWN
			? archive.entries
			: [
					...archive.entries.filter(worthAlook),
					...archive.entries.filter((entry) => !worthAlook(entry))
				].slice(0, ROWS_SHOWN)
	);

	function statusChip(status: 'analysed' | 'skipped' | 'error', reason?: string): string {
		switch (status) {
			case 'analysed':
				return 'analysed';
			case 'skipped':
				return reason ? `skipped: ${reason}` : 'skipped';
			case 'error':
				return reason ? `error: ${reason}` : 'error';
		}
	}
</script>

<div class="zip">
	{#if hidden.length > 0 || arguing.length > 0 || notes.length > 0 || carried.length > 0}
		<ul class="findings">
			{#each carried.slice(0, FINDINGS_SHOWN) as [flag, entry] (flag)}
				<li class="flagged">
					<span class="mono big">{flag}</span>
					<span class="muted"> inside <span class="mono">{entry.name}</span></span>
				</li>
			{/each}
			{#if carried.length > FINDINGS_SHOWN}
				<li>Showing the first {FINDINGS_SHOWN} of {carried.length.toLocaleString()} flags.</li>
			{/if}
			{#each hidden.slice(0, FINDINGS_SHOWN) as entry, i (i)}
				<li class="flagged">
					<span class="mono">{entry.name}</span> is in the file but not in the directory, so no ordinary
					reader will list it
				</li>
			{/each}
			{#if hidden.length > FINDINGS_SHOWN}
				<li>
					Showing the first {FINDINGS_SHOWN} of {hidden.length.toLocaleString()} entries missing from
					the directory.
				</li>
			{/if}
			{#each arguing.slice(0, FINDINGS_SHOWN) as entry, i (i)}
				<li class="flagged">
					<span class="mono">{entry.name}</span>: {entry.disagreement}
				</li>
			{/each}
			{#if arguing.length > FINDINGS_SHOWN}
				<li>
					Showing the first {FINDINGS_SHOWN} of {arguing.length.toLocaleString()} entries the two descriptions
					disagree about.
				</li>
			{/if}
			{#each notes as note (note)}
				<li>{note}</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			The directory and the headers agree on every entry, nothing sits outside the archive, and no
			entry is hidden from a listing. This looks like an untouched archive.
		</p>
	{/if}

	{#if unopened.length > 0}
		<ul class="findings">
			{#each unopened as [reason, count] (reason)}
				<li>
					{count.toLocaleString()}
					{count === 1 ? 'entry' : 'entries'} not opened: {reason}
				</li>
			{/each}
		</ul>
	{/if}

	{#if archive.comment}
		<div class="comment">
			<h3 class="label">Archive comment</h3>
			<pre class="mono">{archive.comment}</pre>
		</div>
	{/if}

	<table>
		<caption class="label"
			>{archive.entries.length.toLocaleString()}
			{archive.entries.length === 1 ? 'entry' : 'entries'}{locked.length > 0
				? `, ${locked.length.toLocaleString()} encrypted`
				: ''}</caption
		>
		<thead>
			<tr>
				<th scope="col" class="label">Name</th>
				<th scope="col" class="label">Method</th>
				<th scope="col" class="label num">Stored</th>
				<th scope="col" class="label num">Actual</th>
				<th scope="col" class="label">Offset</th>
				<th scope="col" class="label">Auto-analysis</th>
			</tr>
		</thead>
		<tbody>
			{#each rows as entry, i (i)}
				{@const child = children.get(entry.offset)}
				{@const childFindings = findingsOf.get(entry.offset) ?? 0}
				<tr class:odd={entry.undeclared || entry.disagreement !== null}>
					<td>
						<span class="mono name">{entry.name}</span>
						{#if entry.bytes && onanalyse}
							<button
								class="entry-action"
								type="button"
								onclick={() => onanalyse?.(entry.bytes!, entry.name)}
							>
								Analyse
							</button>
						{/if}
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
					<td class="muted">
						{#if child}
							<span class="chip wraps">{statusChip(child.status, child.reason)}</span>
							{#if childFindings > 0}
								<span class="mono chip flagged"
									>{childFindings} finding{childFindings === 1 ? '' : 's'}</span
								>
							{/if}
						{:else if entry.notOpened}
							<span class="muted">not opened: {entry.notOpened}</span>
						{:else if (entry.readLength ?? entry.compressed) === 0}
							<span class="muted">empty</span>
						{:else}
							<span class="muted">not analysed</span>
						{/if}
					</td>
				</tr>
				{#if entry.comment}
					<tr class="aside">
						<td colspan="6"><span class="label">comment</span> {entry.comment}</td>
					</tr>
				{/if}
				{#if entry.text && i < CONTENTS_SHOWN}
					<tr class="aside">
						<td colspan="6">
							<div class="content-head">
								<span class="label">content</span>
								{#if onpeel}
									<button type="button" onclick={() => onpeel?.(entry.text!)}>Send to Mantis</button
									>
								{/if}
							</div>
							<pre class="content mono">{entry.text}</pre>
						</td>
					</tr>
				{/if}
				{#if entry.readError}
					<tr class="aside">
						<td colspan="6">
							<span class="label">content</span>
							<span class="muted">
								{#if entry.flags}
									read as far as it goes: {entry.readError}
								{:else}
									could not read: {entry.readError}
								{/if}
							</span>
						</td>
					</tr>
				{/if}
			{/each}
		</tbody>
	</table>

	{#if archive.entries.length > rows.length}
		<p class="capped label">
			Showing the first {rows.length} of {archive.entries.length.toLocaleString()} entries, with anything
			out of the ordinary moved to the top.
		</p>
	{/if}

	{#if locked.length > 0}
		<p class="footnote">
			Trawl doesn't crack archive passwords. That means guessing until a checksum matches, which is
			a job for dedicated software on your own hardware.
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

	.entry-action,
	.content-head button {
		margin-left: var(--s2);
		background: none;
		border: 1px solid var(--rule-bright);
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: 1px var(--s2);
		cursor: pointer;
	}

	.entry-action:focus-visible,
	.content-head button:focus-visible {
		outline: 2px solid var(--signal);
		outline-offset: 2px;
	}

	.content-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--s3);
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

	/* A reason can run to a whole path, and the column is not worth the table's width. */
	.chip.wraps {
		white-space: normal;
		overflow-wrap: anywhere;
	}

	.capped {
		margin: 0;
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
