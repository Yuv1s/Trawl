<script lang="ts">
	import type { ExifEntry } from '$lib/worker/protocol';

	let { entries }: { entries: ExifEntry[] | null } = $props();

	/** Fields a person types, which is where a hidden note ends up. */
	const WRITEABLE = new Set([
		'ImageDescription',
		'UserComment',
		'Artist',
		'Copyright',
		'Software',
		'ImageUniqueID',
		'CameraOwnerName',
		'MakerNote'
	]);

	const notable = $derived(
		(entries ?? []).filter((e) => e.textual && WRITEABLE.has(e.name) && e.value.trim() !== '')
	);
	const rest = $derived((entries ?? []).filter((e) => !notable.includes(e)));

	const label = (e: ExifEntry) => e.name || `Tag 0x${e.tag.toString(16).padStart(4, '0')}`;
</script>

{#if entries === null}
	<p class="clear">
		This file carries no metadata block. JPEG keeps it in an APP1 segment and PNG in an eXIf chunk;
		neither is present here.
	</p>
{:else if entries.length === 0}
	<p class="clear">A metadata block is present but could not be parsed. Its header is malformed.</p>
{:else}
	{#if notable.length > 0}
		<h3 class="label">Written by a person</h3>
		<ul class="notable">
			{#each notable as entry (entry.ifd + entry.tag)}
				<li>
					<span class="key mono">{label(entry)}</span>
					<span class="value mono">{entry.value}</span>
				</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			Nothing in the free-text fields. The camera and timestamp values below are still worth
			reading, since they place the file.
		</p>
	{/if}

	<h3 class="label spaced">All {entries.length} fields</h3>
	<table>
		<thead>
			<tr>
				<th scope="col" class="label">Field</th>
				<th scope="col" class="label">Value</th>
				<th scope="col" class="label">Where</th>
			</tr>
		</thead>
		<tbody>
			{#each rest as entry (entry.ifd + entry.tag)}
				<tr>
					<td class="mono">{label(entry)}</td>
					<td class="mono value-cell">{entry.value}</td>
					<td class="mono muted">{entry.ifd}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	h3 {
		margin: 0 0 var(--s3);
	}

	.spaced {
		margin-top: var(--s5);
	}

	.notable {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	.notable li {
		display: grid;
		gap: var(--s1);
		padding-bottom: var(--s3);
		border-bottom: 1px solid var(--rule);
	}

	.key {
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--muted);
	}

	.notable .value {
		font-size: var(--t-mid);
		color: var(--signal);
		overflow-wrap: anywhere;
		user-select: all;
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

	td {
		padding: var(--s1) var(--s3) var(--s1) 0;
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
		vertical-align: top;
	}

	.value-cell {
		overflow-wrap: anywhere;
		max-width: 60ch;
	}

	.muted {
		color: var(--muted);
	}
</style>
