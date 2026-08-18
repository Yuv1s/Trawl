<script lang="ts">
	type Row = {
		key: string;
		/** The channel selection, shown large. */
		title: string;
		/** Everything else about the read: bit plane, bit order, traversal. */
		chips: string[];
		reason: string;
		preview: string;
		/** True length of the readable run, which exceeds the preview when it clipped. */
		readable: number;
		flags: string[];
		onextract: () => void;
	};

	let {
		rows,
		combinations,
		over,
		blocked,
		error,
		extracted
	}: {
		/** Null when the sweep could not run at all. */
		rows: Row[] | null;
		combinations: number;
		/** What was swept, already counted: "480,000 pixels". */
		over: string;
		/** Why nothing ran, when nothing ran. */
		blocked: string;
		error: string | null;
		extracted: { label: string; text: string } | null;
	} = $props();
</script>

{#if !rows}
	<p class="clear">{blocked}{error ? ` ${error}` : ''}</p>
{:else if rows.length === 0}
	<p class="clear">
		Swept {combinations} parameter combinations across {over}. None produced a file signature,
		printable text, or a flag shape. That does not rule out an encrypted or non-sequential payload.
	</p>
{:else}
	<p class="lead">
		{rows.length} of {combinations} combinations carried something readable.
	</p>

	<ul class="hits">
		{#each rows as row (row.key)}
			<li>
				<div class="params">
					<span class="mono channels">{row.title}</span>
					{#each row.chips as chip (chip)}
						<span class="mono chip">{chip}</span>
					{/each}
					<button type="button" onclick={row.onextract}>Extract everything</button>
				</div>

				<p class="reason">{row.reason}</p>

				{#if row.flags.length}
					<ul class="flags">
						{#each row.flags as flag (flag)}
							<li class="mono flagged">{flag}</li>
						{/each}
					</ul>
				{/if}

				<pre class="preview mono">{row.preview}</pre>

				{#if row.readable > row.preview.length}
					<p class="clip">
						Showing {row.preview.length.toLocaleString()} of
						{row.readable.toLocaleString()} readable characters. Extract everything for the rest.
					</p>
				{/if}
			</li>
		{/each}
	</ul>

	{#if extracted}
		<section class="extracted">
			<h3 class="label">Full extraction · {extracted.label}</h3>
			<pre class="dump mono">{extracted.text}</pre>
		</section>
	{/if}
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

	.params button {
		margin-left: auto;
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s1) var(--s3);
		cursor: pointer;
		transition: background-color 120ms var(--ease);
	}

	.params button:hover {
		background: var(--panel-lift);
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

	.preview,
	.dump {
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
		user-select: all;
	}

	.clip {
		margin: var(--s2) 0 0;
		font-size: var(--t-label);
		color: var(--signal);
	}

	.extracted {
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}

	.extracted h3 {
		margin: 0;
	}

	.dump {
		max-height: 26rem;
		overflow: auto;
	}
</style>
