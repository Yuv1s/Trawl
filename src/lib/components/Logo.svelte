<script lang="ts">
	let { size = 32, label = '' }: { size?: number; label?: string } = $props();
</script>

<svg
	class="logo"
	viewBox="0 0 32 32"
	width={size}
	height={size}
	fill="none"
	role={label ? 'img' : 'presentation'}
	aria-label={label || undefined}
	aria-hidden={label ? undefined : 'true'}
>
	<g class="ink" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
		<path d="M4 11V4h7" />
		<path d="M21 4h7v7" />
		<path d="M28 21v7h-7" />
		<path d="M11 28H4v-7" />
	</g>
	<g class="grid">
		<circle cx="10" cy="10" r="1.5" />
		<circle cx="16" cy="10" r="1.5" />
		<circle cx="22" cy="10" r="1.5" />
		<circle cx="10" cy="16" r="1.5" />
		<circle cx="22" cy="16" r="1.5" />
		<circle cx="10" cy="22" r="1.5" />
		<circle cx="16" cy="22" r="1.5" />
		<circle cx="22" cy="22" r="1.5" />
	</g>
	<circle class="signal" cx="16" cy="16" r="3" />
</svg>

<style>
	.logo {
		display: block;
		flex: none;
	}

	/* Inherits from whatever it sits in, so one mark works on every surface. */
	.ink {
		stroke: currentColor;
	}

	.grid {
		fill: currentColor;
		opacity: 0.55;
	}

	/* The one fixed colour: the centre is the same yellow a finding gets. */
	.signal {
		fill: var(--signal);
	}
</style>
