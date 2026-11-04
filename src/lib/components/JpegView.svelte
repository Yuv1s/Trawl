<script lang="ts">
	import type { Found, JpegSegment } from '$lib/worker/protocol';

	let {
		segments,
		comments,
		trailing
	}: {
		segments: JpegSegment[];
		comments: Found[];
		trailing: { offset: number; length: number } | null;
	} = $props();

	/** Rows drawn. A segment can be four bytes, so a file can hold tens of thousands. */
	const ROWS_SHOWN = 500;
	const COMMENTS_SHOWN = 50;

	const hex = (n: number) => `0x${n.toString(16)}`;
</script>

{#if segments.length === 0}
	<p class="clear">Not a JPEG, so there are no segments to walk.</p>
{:else}
	{#if comments.length > 0}
		<h3 class="label">Comments</h3>
		<ul class="comments">
			{#each comments.slice(0, COMMENTS_SHOWN) as comment (comment.offset)}
				<li>
					<span class="mono text">{comment.text}</span>
					<span class="mono muted">at {hex(comment.offset)}</span>
				</li>
			{/each}
		</ul>
		{#if comments.length > COMMENTS_SHOWN}
			<p class="capped label">
				Showing the first {COMMENTS_SHOWN} of {comments.length.toLocaleString()} comments.
			</p>
		{/if}
	{/if}

	{#if trailing}
		<p class="trailing">
			{trailing.length.toLocaleString()} bytes sit past the end-of-image marker, starting at
			<span class="mono">{hex(trailing.offset)}</span>. A JPEG is complete at EOI.
		</p>
	{/if}

	<h3 class="label spaced">{segments.length.toLocaleString()} segments</h3>
	<table>
		<thead>
			<tr>
				<th scope="col" class="label">Marker</th>
				<th scope="col" class="label">Offset</th>
				<th scope="col" class="label num">Length</th>
			</tr>
		</thead>
		<tbody>
			{#each segments.slice(0, ROWS_SHOWN) as segment (segment.offset)}
				<tr>
					<td class="mono">{segment.name}</td>
					<td class="mono muted">{hex(segment.offset)}</td>
					<td class="mono num">{segment.length.toLocaleString()}</td>
				</tr>
			{/each}
		</tbody>
	</table>
	{#if segments.length > ROWS_SHOWN}
		<p class="capped label">
			Showing the first {ROWS_SHOWN} of {segments.length.toLocaleString()} segments.
		</p>
	{/if}

	<p class="caveat">
		A JPEG is a run of marker segments. Most declare their own length, which makes them cheap to
		walk without decoding anything. The scan data after SOS declares nothing, so finding what comes
		next means searching for the next marker while skipping the byte stuffing that lets a literal
		0xFF appear inside image data.
	</p>
{/if}

<style>
	.clear {
		margin: 0;
		color: var(--muted);
		line-height: 1.6;
	}

	h3 {
		margin: 0 0 var(--s3);
	}

	.spaced {
		margin-top: var(--s5);
	}

	.comments {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	.comments li {
		display: grid;
		gap: var(--s1);
		padding-bottom: var(--s3);
		border-bottom: 1px solid var(--rule);
	}

	.text {
		font-size: var(--t-mid);
		color: var(--signal);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.trailing {
		margin: var(--s4) 0 0;
		max-width: 72ch;
		line-height: 1.6;
	}

	table {
		width: 100%;
		max-width: 44rem;
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

	.muted {
		color: var(--muted);
	}

	.capped {
		margin: var(--s3) 0 0;
		color: var(--muted);
	}

	.caveat {
		margin: var(--s4) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}
</style>
