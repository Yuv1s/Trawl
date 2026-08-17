<script lang="ts">
	import type { Found } from '$lib/worker/protocol';

	let { total, sample }: { total: number; sample: Found[] } = $props();

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
		grid-template-columns: 7ch 1fr;
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

	.empty,
	.more {
		margin: 0;
		font-size: var(--t-label);
		color: var(--muted);
	}
</style>
