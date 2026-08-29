<script lang="ts">
	import { onMount } from 'svelte';
	import { applyTheme, storedTheme, systemTheme, type Theme } from '$lib/theme';
	import FlagTagEditor from '$lib/components/FlagTagEditor.svelte';

	let {
		onTour,
		onDemos,
		onExport,
		flagTags = [],
		onFlagTags,
		dataTour
	}: {
		onTour?: () => void;
		onDemos?: () => void;
		/** Hands a writeup Markdown off, either to the clipboard or as a file. */
		onExport?: (action: 'copy' | 'download') => Promise<void>;
		/** Flag prefix presets, so detection and key recovery know the prize shape. */
		flagTags?: string[];
		onFlagTags?: (tags: string[]) => void;
		dataTour?: string;
	} = $props();

	const REPO_URL = 'https://github.com/Yuv1s/Trawl';

	let theme = $state<Theme>('dark');

	onMount(() => {
		theme =
			(document.documentElement.dataset.theme as Theme | undefined) ??
			storedTheme() ??
			systemTheme();
	});

	function toggleTheme() {
		theme = theme === 'dark' ? 'light' : 'dark';
		applyTheme(theme);
	}

	let open = $state(false);
	let tagsOpen = $state(false);
	let copied = $state(false);
	let timer: ReturnType<typeof setTimeout> | undefined;
	let firstItem: HTMLButtonElement | undefined = $state();
	let addInput: HTMLInputElement | undefined = $state();

	$effect(() => () => clearTimeout(timer));

	$effect(() => {
		if (open && firstItem) firstItem.focus();
	});

	$effect(() => {
		if (tagsOpen && addInput) addInput.focus();
	});

	$effect(() => {
		if (!open && !tagsOpen) return;
		const close = (event: KeyboardEvent) => {
			if (event.key === 'Escape') {
				open = false;
				tagsOpen = false;
			}
		};
		window.addEventListener('keydown', close);
		return () => window.removeEventListener('keydown', close);
	});

	async function pick(action: 'copy' | 'download') {
		open = false;
		if (action === 'download') {
			await onExport?.('download');
			return;
		}
		await onExport?.('copy');
		copied = true;
		clearTimeout(timer);
		timer = setTimeout(() => (copied = false), 1600);
	}
</script>

<div class="controls" data-tour={dataTour}>
	{#if onTour}
		<button type="button" class="ctrl" onclick={onTour} aria-label="Take the tour">
			<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
				<circle cx="9" cy="9" r="6.5" stroke="currentColor" stroke-width="1.5" />
				<path
					d="M11.5 6.5 9.8 9.8 6.5 11.5 8.2 8.2z"
					stroke="currentColor"
					stroke-width="1.3"
					stroke-linejoin="round"
				/>
			</svg>
			<span class="ctrl-label">Tour</span>
		</button>
	{/if}

	{#if onDemos}
		<button type="button" class="ctrl" onclick={onDemos} aria-label="Try a sample file">
			<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
				<path
					d="M6.5 5.2v7.6l6.2-3.8z"
					stroke="currentColor"
					stroke-width="1.4"
					stroke-linejoin="round"
				/>
			</svg>
			<span class="ctrl-label">Demos</span>
		</button>
	{/if}

	{#if onExport}
		<div class="wrap">
			<button
				type="button"
				class="ctrl"
				aria-haspopup="menu"
				aria-expanded={open}
				onclick={() => (open = !open)}
				aria-label={copied ? 'Writeup copied' : 'Export a writeup'}
			>
				{#if copied}
					<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
						<path
							d="M4 9.2l3.2 3.2L14 6.2"
							stroke="currentColor"
							stroke-width="1.5"
							stroke-linecap="round"
							stroke-linejoin="round"
						/>
					</svg>
				{:else}
					<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
						<path
							d="M5.25 2.5h4.75l3.5 3.5V15.5H5.25z"
							stroke="currentColor"
							stroke-width="1.4"
							stroke-linejoin="round"
						/>
						<path
							d="M10 2.5v3.75h3.5"
							stroke="currentColor"
							stroke-width="1.4"
							stroke-linejoin="round"
						/>
						<path
							d="M7.6 9.3l2.4-2.4 2.4 2.4M10 6.9v5"
							stroke="currentColor"
							stroke-width="1.3"
							stroke-linecap="round"
							stroke-linejoin="round"
						/>
					</svg>
				{/if}
				<span class="ctrl-label">{copied ? 'Copied' : 'Writeup'}</span>
			</button>

			{#if open}
				<div class="menu" role="menu" aria-label="Writeup options">
					<button
						role="menuitem"
						bind:this={firstItem}
						onclick={() => pick('copy')}
						aria-label="Copy the writeup as Markdown"
					>
						Copy markdown
					</button>
					<button
						role="menuitem"
						onclick={() => pick('download')}
						aria-label="Download the writeup as a Markdown file"
					>
						Download .md
					</button>
				</div>
				<button
					type="button"
					class="backdrop"
					aria-label="Close menu"
					onclick={() => (open = false)}
				></button>
			{/if}
		</div>
	{/if}

	{#if onFlagTags}
		<div class="wrap">
			<button
				type="button"
				class="ctrl"
				aria-haspopup="menu"
				aria-expanded={tagsOpen}
				onclick={() => (tagsOpen = !tagsOpen)}
				aria-label="Configure flag formats"
			>
				<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
					<path d="M5.5 2.5v13" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
					<path
						d="M5.5 3.5h6.4l-1.7 2.5 1.7 2.5H5.5z"
						stroke="currentColor"
						stroke-width="1.4"
						stroke-linejoin="round"
					/>
				</svg>
				<span class="ctrl-label">Flag formats</span>
			</button>

			{#if tagsOpen}
				<div class="menu wide" role="menu" aria-label="Flag format presets">
					<FlagTagEditor tags={flagTags ?? []} onchange={(tags) => onFlagTags?.(tags)} />
				</div>
				<button
					type="button"
					class="backdrop"
					aria-label="Close menu"
					onclick={() => (tagsOpen = false)}
				></button>
			{/if}
		</div>
	{/if}

	<button
		type="button"
		class="ctrl icon-only"
		onclick={toggleTheme}
		aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
	>
		{#if theme === 'dark'}
			<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
				<circle cx="9" cy="9" r="3.5" stroke="currentColor" stroke-width="1.5" />
				<g stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
					<path d="M9 2v1.6M9 14.4V16M16 9h-1.6M3.6 9H2" />
					<path d="M13.7 4.3l-1.1 1.1M5.4 12.6l-1.1 1.1M13.7 13.7l-1.1-1.1M5.4 5.4 4.3 4.3" />
				</g>
			</svg>
		{:else}
			<svg viewBox="0 0 18 18" width="16" height="16" fill="none" aria-hidden="true">
				<path
					d="M14.8 10.6A5.8 5.8 0 0 1 7.4 3.2a5.8 5.8 0 1 0 7.4 7.4z"
					stroke="currentColor"
					stroke-width="1.5"
					stroke-linejoin="round"
				/>
			</svg>
		{/if}
	</button>

	<a
		class="ctrl icon-only"
		href={REPO_URL}
		target="_blank"
		rel="noreferrer"
		aria-label="View source on GitHub"
	>
		<svg viewBox="0 0 18 18" width="16" height="16" aria-hidden="true">
			<path
				fill="currentColor"
				fill-rule="evenodd"
				clip-rule="evenodd"
				d="M9 1.2a7.8 7.8 0 0 0-2.47 15.2c.39.07.53-.17.53-.38v-1.48c-2.17.47-2.63-.94-2.63-.94-.35-.9-.87-1.14-.87-1.14-.7-.49.06-.48.06-.48.78.06 1.19.8 1.19.8.7 1.19 1.82.85 2.27.65.07-.5.27-.85.49-1.05-1.73-.2-3.55-.87-3.55-3.86 0-.85.3-1.55.8-2.1-.08-.2-.35-1 .08-2.1 0 0 .65-.21 2.14.8a7.3 7.3 0 0 1 3.9 0c1.48-1.01 2.13-.8 2.13-.8.43 1.1.16 1.9.08 2.1.5.55.8 1.25.8 2.1 0 3-1.83 3.65-3.57 3.85.28.24.53.72.53 1.46v2.16c0 .21.14.46.54.38A7.8 7.8 0 0 0 9 1.2z"
			/>
		</svg>
	</a>
</div>

<style>
	.controls {
		display: flex;
		align-items: center;
		gap: var(--s2);
	}

	.ctrl {
		display: inline-flex;
		align-items: center;
		gap: var(--s1);
		height: 30px;
		padding: 0 var(--s2);
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--muted);
		text-decoration: none;
		cursor: pointer;
		transition:
			background-color 120ms var(--ease),
			color 120ms var(--ease);
	}

	.ctrl.icon-only {
		width: 30px;
		padding: 0;
		justify-content: center;
	}

	.ctrl:hover {
		background: var(--panel-lift);
		color: var(--text);
	}

	.ctrl-label {
		font-size: var(--t-label);
		font-weight: 600;
		padding-right: var(--s1);
	}

	.wrap {
		position: relative;
		z-index: 10;
	}

	.menu {
		position: absolute;
		top: calc(100% + var(--s1));
		right: 0;
		z-index: 1;
		min-width: 160px;
		padding: var(--s1);
		background: var(--panel-deep);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
	}

	.menu.wide {
		min-width: 240px;
	}

	.menu button {
		display: block;
		width: 100%;
		text-align: left;
		padding: var(--s2) var(--s2);
		background: none;
		border: none;
		border-radius: var(--radius);
		color: var(--muted);
		font-size: var(--t-label);
		cursor: pointer;
		transition:
			background-color 120ms var(--ease),
			color 120ms var(--ease);
	}

	.menu button:hover,
	.menu button:focus-visible {
		background: var(--panel-lift);
		color: var(--text);
		outline: none;
	}

	.backdrop {
		position: fixed;
		inset: 0;
		border: none;
		background: none;
		cursor: default;
	}
</style>
