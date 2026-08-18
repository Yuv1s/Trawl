<script lang="ts">
	import { resolve } from '$app/paths';
	import Logo from '$lib/components/Logo.svelte';

	let { title, children }: { title: string; children: import('svelte').Snippet } = $props();
</script>

<main>
	<a class="back" href={resolve('/')}><Logo size={16} />Back to Trawl</a>
	<h1>{title}</h1>
	<div class="body">
		{@render children()}
	</div>
</main>

<style>
	main {
		max-width: 62ch;
		margin: 0 auto;
		padding: var(--s6) var(--s5) var(--s7);
	}

	.back {
		display: inline-flex;
		align-items: center;
		gap: var(--s2);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		color: var(--muted);
		text-decoration: none;
		border-bottom: 1px solid var(--rule);
		padding-bottom: 2px;
	}

	.back:hover {
		color: var(--text);
		border-color: var(--rule-bright);
	}

	h1 {
		margin: var(--s5) 0 0;
		font-size: var(--t-title);
		font-weight: 600;
		letter-spacing: 0.02em;
	}

	.body {
		margin-top: var(--s5);
		border-top: 1px solid var(--rule);
		padding-top: var(--s5);
	}

	.body :global(h2) {
		margin: var(--s6) 0 var(--s2);
		font-size: var(--t-body);
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.14em;
		color: var(--muted);
	}

	.body :global(p) {
		margin: 0 0 var(--s3);
		line-height: 1.7;
		color: var(--text);
	}

	.body :global(code) {
		font-family: var(--mono);
		font-size: 0.92em;
		color: var(--muted);
	}
</style>
