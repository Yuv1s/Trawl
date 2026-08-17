<script lang="ts">
	import { CHECKS_RUN, type Finding } from '$lib/analysis/findings';

	let { items }: { items: Finding[] } = $props();

	const flagged = $derived(items.filter((f) => f.flagged));
	const routine = $derived(items.filter((f) => !f.flagged));
</script>

<div class="triage">
	{#if flagged.length === 0}
		<p class="clean">
			Nothing flagged. Checked {CHECKS_RUN.join(', ')}.
		</p>
	{:else}
		<ul class="list">
			{#each flagged as item (item.id)}
				<li>
					<h3 class="flagged">{item.title}</h3>
					<p>{item.detail}</p>
				</li>
			{/each}
		</ul>
	{/if}

	{#if routine.length > 0}
		<details>
			<summary class="label">{routine.length} routine</summary>
			<ul class="list routine">
				{#each routine as item (item.id)}
					<li>
						<h3>{item.title}</h3>
						<p>{item.detail}</p>
					</li>
				{/each}
			</ul>
		</details>
	{/if}
</div>

<style>
	.triage {
		display: grid;
		gap: var(--s4);
	}

	.list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	li {
		border-left: 1px solid var(--rule);
		padding-left: var(--s3);
	}

	h3 {
		margin: 0;
		font-size: var(--t-body);
		font-weight: 600;
	}

	p {
		margin: var(--s1) 0 0;
		color: var(--muted);
		font-size: var(--t-label);
		line-height: 1.6;
		overflow-wrap: anywhere;
	}

	.clean {
		margin: 0;
		color: var(--muted);
		font-size: var(--t-label);
		line-height: 1.6;
	}

	details {
		border-top: 1px solid var(--rule);
		padding-top: var(--s3);
	}

	summary {
		cursor: pointer;
		list-style: none;
	}

	summary::-webkit-details-marker {
		display: none;
	}

	summary::before {
		content: '+ ';
	}

	details[open] summary::before {
		content: '– ';
	}

	.routine {
		margin-top: var(--s3);
	}
</style>
