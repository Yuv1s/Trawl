<script lang="ts">
	import { resolve } from '$app/paths';
	import Logo from '$lib/components/Logo.svelte';
</script>

<svelte:head>
	<title>Not found — Trawl</title>
	<meta name="description" content="This address doesn't lead anywhere in Trawl." />
	<meta name="robots" content="noindex" />
</svelte:head>

<main>
	<Logo size={40} />
	<span class="eyebrow mono">404</span>
	<h1>Trawl finds hidden things. This page isn't one of them.</h1>
	<p>
		No bit-plane wall, no chi-square attack, no palette trick turns up a route that was never built.
		Nothing was checked and nothing was sent anywhere, the address just doesn't exist. Whatever link
		brought you here is out of date or mistyped.
	</p>
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
