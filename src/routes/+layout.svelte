<script lang="ts">
	import '$lib/styles/tokens.css';
	import favicon from '$lib/assets/favicon.svg';
	import touchIcon from '$lib/assets/logoSizes/logo-256.png';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<link rel="apple-touch-icon" href={touchIcon} />
	<meta name="theme-color" content="#0f1417" />
</svelte:head>

{@render children()}
