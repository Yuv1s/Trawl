<script lang="ts">
	import { onMount } from 'svelte';
	import '$lib/styles/tokens.css';
	import favicon from '$lib/assets/favicon.svg';
	import touchIcon from '$lib/assets/logoSizes/logo-256.png';
	import { applyTheme } from '$lib/theme';

	let { children } = $props();

	// The blocking script in app.html already set the attribute before paint,
	// so this only brings the theme-color meta in line with it.
	onMount(() => {
		applyTheme(document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<link rel="apple-touch-icon" href={touchIcon} />
	<meta name="theme-color" content="#0f1417" />
</svelte:head>

{@render children()}
