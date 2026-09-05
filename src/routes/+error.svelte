<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import Logo from '$lib/components/Logo.svelte';

	// A 404 has its own page with its own joke; this is for the errors nobody
	// planned, so it says the one thing that is always true here and stays out
	// of the way.
	const status = $derived(page.status);
	const detail = $derived(page.error?.message ?? '');
</script>

<svelte:head>
	<title>Something broke — Trawl</title>
	<meta name="robots" content="noindex" />
</svelte:head>

<main>
	<Logo size={40} />
	<span class="eyebrow mono">{status}</span>
	<h1>Something in Trawl broke, not anything you dropped.</h1>
	<p>
		Whatever went wrong stayed on this machine, the same as everything else here. Nothing was
		uploaded and nothing was sent anywhere. Reloading usually clears it; if it does not, the file
		you were reading is still on your disk, untouched.
	</p>
	{#if detail}
		<p class="detail mono">{detail}</p>
	{/if}
	<a class="home" href={resolve('/')}>Back to Trawl</a>
</main>

<style>
	main {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		max-width: 40ch;
		min-height: 100dvh;
		margin: 0 auto;
		padding: var(--s7) var(--s5);
		justify-content: center;
	}

	:global(.logo) {
		color: var(--muted);
	}

	.eyebrow {
		margin-top: var(--s5);
		font-size: var(--t-label);
		font-weight: 600;
		letter-spacing: 0.14em;
		color: var(--signal);
	}

	h1 {
		margin: var(--s2) 0 0;
		font-size: var(--t-title);
		font-weight: 600;
		letter-spacing: 0.02em;
	}

	p {
		margin: var(--s4) 0 0;
		line-height: 1.7;
		color: var(--muted);
	}

	.detail {
		font-size: var(--t-label);
		color: var(--muted);
		padding: var(--s2) var(--s3);
		border-left: 1px solid var(--rule-bright);
		overflow-wrap: anywhere;
	}

	.home {
		display: inline-flex;
		margin-top: var(--s6);
		font-size: var(--t-label);
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.14em;
		color: var(--text);
		text-decoration: none;
		padding: var(--s2) var(--s4);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		transition: background-color 120ms var(--ease);
	}

	.home:hover {
		background: var(--panel-lift);
	}
</style>
