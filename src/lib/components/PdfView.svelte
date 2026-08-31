<script lang="ts">
	import type { PdfStructure, PdfObject } from '$lib/worker/protocol';

	let {
		doc,
		onpeel
	}: {
		doc: PdfStructure;
		onpeel?: (text: string) => void;
	} = $props();

	const orphaned = $derived(doc.objects.filter((o) => o.orphaned));
	/** Objects whose decompressed stream carried a flag shape. */
	const carrying = $derived(doc.objects.filter((o) => (o.flags?.length ?? 0) > 0));
	const embedded = $derived(doc.objects.filter((o) => doc.embeddedFiles.includes(o.number)));

	const notes = $derived(
		[
			doc.revisions > 1 &&
				`this file has been incrementally updated ${doc.revisions - 1} time${doc.revisions - 1 === 1 ? '' : 's'}, each %%EOF a saved revision`,
			doc.trailing > 0 &&
				`${doc.trailing.toLocaleString()} bytes follow the last %%EOF, which nothing that wrote this document put there`,
			doc.encrypted &&
				'the trailer names an /Encrypt dictionary, so this document is password protected',
			doc.usesXrefStream &&
				'the cross-reference table is a compressed stream rather than plain text, so objects cannot be checked against it here'
		].filter((note): note is string => typeof note === 'string')
	);

	const objectLabel = (o: PdfObject) => `${o.number} ${o.generation} obj`;
</script>

<div class="pdf">
	{#if orphaned.length > 0 || carrying.length > 0 || notes.length > 0}
		<ul class="findings">
			{#each carrying as object (object.offset)}
				{#each object.flags ?? [] as flag (flag)}
					<li class="flagged">
						<span class="mono big">{flag}</span>
						<span class="muted"> inside <span class="mono">{objectLabel(object)}</span></span>
					</li>
				{/each}
			{/each}
			{#each orphaned as object (object.offset)}
				<li class="flagged">
					<span class="mono">{objectLabel(object)}</span> is in the file but the cross-reference table
					no longer points at it, so no ordinary reader will open it
				</li>
			{/each}
			{#each notes as note (note)}
				<li>{note}</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			The cross-reference table lists every object in the file, there is one revision, and nothing
			follows the last %%EOF. That is what an untouched PDF looks like.
		</p>
	{/if}

	{#if doc.info.length > 0}
		<div class="info">
			<h3 class="label">Document info</h3>
			<dl>
				{#each doc.info as field (field.key)}
					<div>
						<dt class="label">{field.key}</dt>
						<dd class="mono">{field.value}</dd>
					</div>
				{/each}
			</dl>
		</div>
	{/if}

	<table>
		<caption class="label">
			{doc.objects.length} object{doc.objects.length === 1 ? '' : 's'}, PDF {doc.version}
			{embedded.length > 0 ? `, ${embedded.length} attached` : ''}
		</caption>
		<thead>
			<tr>
				<th scope="col" class="label">Object</th>
				<th scope="col" class="label">Type</th>
				<th scope="col" class="label">Stream</th>
				<th scope="col" class="label num">Length</th>
				<th scope="col" class="label">Offset</th>
			</tr>
		</thead>
		<tbody>
			{#each doc.objects as object (object.offset)}
				<tr class:odd={object.orphaned || (object.flags?.length ?? 0) > 0}>
					<td>
						<span class="mono name">{objectLabel(object)}</span>
						{#if object.orphaned}
							<span class="mono chip flagged">not in xref</span>
						{/if}
						{#if doc.embeddedFiles.includes(object.number)}
							<span class="mono chip">attachment</span>
						{/if}
					</td>
					<td class="muted">{object.type ?? '—'}{object.subtype ? ` / ${object.subtype}` : ''}</td>
					<td class="muted">{object.stream?.filter || (object.stream ? 'uncompressed' : '—')}</td>
					<td class="mono num"
						>{object.stream ? `${object.stream.length.toLocaleString()} B` : '—'}</td
					>
					<td class="mono muted">0x{object.offset.toString(16)}</td>
				</tr>
				{#if object.stream?.text}
					<tr class="aside">
						<td colspan="5">
							<div class="content-head">
								<span class="label">stream content</span>
								{#if onpeel}
									<button type="button" onclick={() => onpeel?.(object.stream!.text!)}
										>Send to Mantis</button
									>
								{/if}
							</div>
							<pre class="content mono">{object.stream.text}</pre>
						</td>
					</tr>
				{:else if object.stream?.error}
					<tr class="aside">
						<td colspan="5">
							<span class="label">stream content</span>
							<span class="muted">could not read: {object.stream.error}</span>
						</td>
					</tr>
				{/if}
			{/each}
		</tbody>
	</table>

	{#if doc.encrypted}
		<p class="footnote">
			Trawl does not crack document passwords. Reversing one means guessing until a checksum
			matches, which belongs on hardware you control running something built for it.
		</p>
	{/if}
</div>

<style>
	.pdf {
		display: grid;
		gap: var(--s4);
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
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
		border-left: 1px solid var(--rule);
		color: var(--muted);
		line-height: 1.5;
		max-width: 78ch;
	}

	.findings li.flagged {
		border-left-color: var(--signal);
		color: var(--text);
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
		overflow-wrap: anywhere;
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
