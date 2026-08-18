<script lang="ts">
	import type { Found } from '$lib/worker/protocol';

	let {
		candidates,
		sources,
		fromPixels = []
	}: {
		candidates: Found[];
		sources: Record<number, string>;
		/** Finds from a sweep, each naming which sweep turned it up. */
		fromPixels?: { text: string; origin: string }[];
	} = $props();

	const total = $derived(candidates.length + fromPixels.length);
</script>

<section class="recovered" aria-label="Cod-end, recovered candidates">
	<div class="head">
		<h2 class="label">Cod-end</h2>
		<span class="count mono">
			{total} candidate{total === 1 ? '' : 's'}
		</span>
	</div>

	<ul>
		{#each candidates as found (found.offset)}
			<li>
				<output class="value mono">{found.text}</output>
				<span class="origin mono">
					0x{found.offset.toString(16)}
					{#if sources[found.offset]}· {sources[found.offset]}{/if}
				</span>
			</li>
		{/each}
		{#each fromPixels as found (found.origin + found.text)}
			<li>
				<output class="value mono">{found.text}</output>
				<span class="origin mono">{found.origin}</span>
			</li>
		{/each}
	</ul>

	<p class="caveat">
		The cod-end is the closed end of a trawl net, where the catch collects. Everything here matched
		on shape alone, so Trawl has not verified that any of it is the answer.
	</p>
</section>

<style>
	.recovered {
		border-bottom: 1px solid var(--rule);
		background: var(--panel-deep);
		padding: var(--s4) var(--s5) var(--s4);
	}

	.head {
		display: flex;
		align-items: baseline;
		gap: var(--s4);
	}

	h2 {
		margin: 0;
		color: var(--signal);
	}

	.count {
		font-size: var(--t-label);
		color: var(--muted);
	}

	ul {
		list-style: none;
		margin: var(--s3) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	li {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2) var(--s4);
	}

	.value {
		font-size: var(--t-mid);
		font-weight: 500;
		color: var(--signal);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.origin {
		font-size: var(--t-label);
		color: var(--muted);
	}

	.caveat {
		margin: var(--s3) 0 0;
		font-size: var(--t-label);
		color: var(--muted);
	}
</style>
