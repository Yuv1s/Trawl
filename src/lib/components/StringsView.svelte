<script lang="ts">
	import type { Found } from '$lib/worker/protocol';

	let {
		total,
		sample,
		onpeel
	}: { total: number; sample: Found[]; onpeel?: (text: string) => void } = $props();

	let filter = $state('');

	const shown = $derived(
		filter.trim()
			? sample.filter((s) => s.text.toLowerCase().includes(filter.trim().toLowerCase()))
			: sample
	);
</script>

<div class="strings">
	<label class="search">
		<span class="label">Filter</span>
		<input
			type="text"
			bind:value={filter}
			placeholder="substring"
			spellcheck="false"
			autocomplete="off"
		/>
	</label>

	{#if shown.length === 0}
		<p class="empty">
			{sample.length === 0
				? 'No printable runs of six characters or more.'
				: `Nothing in the first ${sample.length.toLocaleString()} strings matches that.`}
		</p>
	{:else}
		<ul class="mono">
			{#each shown as found (found.offset)}
				<li>
					<span class="offset">{found.offset.toString(16).padStart(6, '0')}</span>
					<span class="text">{found.text}</span>
					{#if onpeel}
						<button type="button" onclick={() => onpeel?.(found.text)}>Peel</button>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}

	{#if total > sample.length}
		<p class="more">
			Showing {sample.length.toLocaleString()} of {total.toLocaleString()}.
		</p>
	{/if}
</div>

<style>
	.strings {
		display: grid;
		align-content: start;
		gap: var(--s3);
	}

	.search {
		display: flex;
		align-items: center;
		gap: var(--s3);
	}

	input {
		flex: 1;
		max-width: 32ch;
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--text);
		font-family: var(--mono);
		font-size: var(--t-data);
		padding: var(--s1) var(--s2);
	}

	input:focus-visible {
		border-color: var(--rule-bright);
	}

	ul {
		list-style: none;
		margin: 0;
		padding: 0;
		font-size: var(--t-data);
	}

	li {
		display: grid;
		grid-template-columns: 7ch minmax(0, 1fr) auto;
		gap: var(--s3);
		padding: 2px 0;
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
	}

	.offset {
		color: var(--muted);
	}

	.text {
		overflow-wrap: anywhere;
	}

	li button {
		background: none;
		border: 0;
		color: var(--muted);
		font: inherit;
		font-size: var(--t-label);
		padding: 0 var(--s1);
		cursor: pointer;
	}

	li button:focus-visible {
		outline: 2px solid var(--signal);
		outline-offset: 2px;
	}

	.empty,
	.more {
		margin: 0;
		font-size: var(--t-label);
		color: var(--muted);
	}
</style>
