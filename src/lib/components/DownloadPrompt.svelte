<script lang="ts">
	import { onMount } from 'svelte';
	import {
		SAMPLE_GROUPS,
		downloadSample,
		loadSample,
		type SampleEntry,
		type SampleFile,
		type SampleOpen
	} from '$lib/tour/demo';

	let {
		onclose,
		onrun
	}: { onclose: () => void; onrun: (file: SampleFile, open: SampleOpen) => void } = $props();

	let searchInput: HTMLInputElement | undefined;
	let query = $state('');
	let loading = $state<string | null>(null);
	let error = $state('');

	const total = SAMPLE_GROUPS.reduce((n, group) => n + group.entries.length, 0);

	const filtered = $derived.by(() => {
		const q = query.trim().toLowerCase();
		if (!q) return SAMPLE_GROUPS;
		return SAMPLE_GROUPS.map((group) => {
			if (group.title.toLowerCase().includes(q)) return group;
			const entries = group.entries.filter(
				(entry) => entry.name.toLowerCase().includes(q) || entry.blurb.toLowerCase().includes(q)
			);
			return { ...group, entries };
		}).filter((group) => group.entries.length > 0);
	});

	onMount(() => searchInput?.focus());

	function keydown(event: KeyboardEvent) {
		if (event.key === 'Escape') onclose();
	}

	function onScrimClick(event: MouseEvent) {
		if (event.target === event.currentTarget) onclose();
	}

	async function useSample(entry: SampleEntry, action: 'run' | 'download') {
		loading = `${action}:${entry.name}`;
		error = '';
		try {
			const file = await loadSample(entry);
			if (action === 'run') onrun(file, entry.open ?? 'drop');
			else downloadSample(file);
		} catch (cause) {
			error = cause instanceof Error ? cause.message : `Could not load ${entry.name}`;
		} finally {
			loading = null;
		}
	}
</script>

<svelte:window onkeydown={keydown} />

<div class="scrim" role="presentation" onclick={onScrimClick}>
	<div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dl-title">
		<header class="head">
			<span class="eyebrow">{total} samples</span>
			<h2 id="dl-title">See it work</h2>
			<p class="lede">
				The whole corpus, grouped by what it exercises. Check one to watch the tools run in place,
				or download it to drop back in yourself. Nothing here leaves the tab.
			</p>
			<div class="search">
				<input
					bind:this={searchInput}
					bind:value={query}
					type="search"
					placeholder="Filter by name or what it hides"
					aria-label="Filter samples"
					autocomplete="off"
					spellcheck="false"
				/>
			</div>
		</header>

		<div class="body" aria-busy={loading !== null}>
			{#each filtered as group (group.title)}
				<section class="group">
					<div class="group-head">
						<h3>{group.title}</h3>
						<span class="count">{group.entries.length}</span>
					</div>
					{#if group.note}<p class="note">{group.note}</p>{/if}
					<ul>
						{#each group.entries as entry (entry.name)}
							<li>
								<div class="row-text">
									<div class="name-line">
										<span class="mono name">{entry.name}</span>
										<span class="tag" class:paste={entry.open === 'paste'}>
											{entry.open === 'paste' ? 'Paste' : 'Drop'}
										</span>
									</div>
									<span class="blurb">{entry.blurb}</span>
								</div>
								<div class="row-actions">
									<button
										type="button"
										class="run"
										disabled={loading !== null}
										onclick={() => useSample(entry, 'run')}
									>
										{loading === `run:${entry.name}` ? 'Loading' : 'Run'}
									</button>
									<button
										type="button"
										class="get"
										disabled={loading !== null}
										onclick={() => useSample(entry, 'download')}
									>
										{loading === `download:${entry.name}` ? 'Loading' : 'Download'}
									</button>
								</div>
							</li>
						{/each}
					</ul>
				</section>
			{/each}

			{#if filtered.length === 0}
				<div class="empty" role="status">
					<p>
						No sample matches <span class="mono">{query.trim()}</span>. Try a tool name, a format,
						or part of a flag.
					</p>
					<button type="button" class="get" onclick={() => (query = '')}>Clear filter</button>
				</div>
			{/if}
		</div>

		{#if error}<p class="error" role="alert">{error}</p>{/if}

		<div class="actions">
			<button type="button" class="ghost" onclick={onclose}>Close</button>
		</div>
	</div>
</div>

<style>
	.scrim {
		position: fixed;
		inset: 0;
		z-index: 60;
		display: grid;
		place-items: center;
		padding: var(--s5);
		background: color-mix(in srgb, var(--ground) 72%, transparent);
	}

	.dialog {
		display: flex;
		flex-direction: column;
		width: min(44rem, 100%);
		max-height: min(48rem, calc(100dvh - var(--s7)));
		background: var(--panel-deep);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		overflow: hidden;
	}

	.head {
		flex: none;
		padding: var(--s6) var(--s6) var(--s4);
	}

	.eyebrow {
		display: block;
		font-size: 0.6875rem;
		font-weight: 600;
		font-variant-numeric: tabular-nums;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--muted);
	}

	h2 {
		margin: var(--s2) 0 0;
		font-size: var(--t-title);
		font-weight: 600;
	}

	.lede {
		margin: var(--s3) 0 0;
		max-width: 46ch;
		color: var(--muted);
		line-height: 1.6;
		text-wrap: pretty;
	}

	.search {
		margin-top: var(--s4);
	}

	input[type='search'] {
		width: 100%;
		font: inherit;
		font-size: var(--t-body);
		color: var(--text);
		padding: var(--s3) var(--s4);
		background: var(--panel);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		transition: border-color 120ms var(--ease);
	}

	input[type='search']::placeholder {
		color: var(--muted);
	}

	input[type='search']:focus-visible {
		outline: none;
		border-color: var(--signal);
	}

	.body {
		flex: 1 1 auto;
		min-height: 0;
		overflow-y: auto;
		border-top: 1px solid var(--rule);
	}

	.group-head {
		position: sticky;
		top: 0;
		z-index: 1;
		display: flex;
		align-items: baseline;
		gap: var(--s2);
		padding: var(--s4) var(--s6) var(--s2);
		background: var(--panel-deep);
		border-bottom: 1px solid var(--rule);
	}

	h3 {
		margin: 0;
		font-size: var(--t-label);
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--text);
	}

	.count {
		font-size: 0.6875rem;
		font-weight: 600;
		font-variant-numeric: tabular-nums;
		color: var(--muted);
	}

	.note {
		margin: var(--s3) 0 0;
		padding: 0 var(--s6);
		font-size: var(--t-label);
		line-height: 1.55;
		color: var(--muted);
		text-wrap: pretty;
	}

	ul {
		list-style: none;
		margin: 0;
		padding: var(--s3) var(--s6) var(--s5);
		display: grid;
		gap: var(--s2);
	}

	li {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--s4);
		padding: var(--s3) var(--s4);
		background: var(--panel);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
	}

	.row-text {
		display: grid;
		gap: var(--s1);
		min-width: 0;
	}

	.name-line {
		display: flex;
		align-items: center;
		gap: var(--s2);
		min-width: 0;
	}

	.name {
		font-weight: 600;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.tag {
		flex: none;
		font-size: 0.625rem;
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		padding: 2px var(--s2);
		color: var(--muted);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
	}

	.tag.paste {
		color: var(--signal);
		border-color: color-mix(in srgb, var(--signal) 45%, transparent);
		background: color-mix(in srgb, var(--signal) 12%, transparent);
	}

	.blurb {
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.5;
	}

	.empty {
		display: grid;
		gap: var(--s4);
		justify-items: start;
		margin: 0;
		padding: var(--s6);
		color: var(--muted);
		line-height: 1.6;
	}

	.empty p {
		margin: 0;
		text-wrap: pretty;
	}

	.error {
		flex: none;
		margin: 0;
		padding: var(--s3) var(--s6);
		color: var(--signal);
		border-top: 1px solid var(--rule);
	}

	.actions {
		flex: none;
		display: flex;
		justify-content: flex-end;
		padding: var(--s4) var(--s6);
		border-top: 1px solid var(--rule);
	}

	button {
		font: inherit;
		font-size: var(--t-label);
		font-weight: 600;
		padding: var(--s2) var(--s4);
		border-radius: var(--radius);
		cursor: pointer;
		transition: background-color 120ms var(--ease);
		flex: none;
	}

	button:disabled {
		cursor: wait;
		opacity: 0.6;
	}

	.row-actions {
		display: flex;
		gap: var(--s2);
		flex: none;
	}

	.run {
		background: var(--signal);
		border: 1px solid var(--signal);
		color: var(--ground);
	}

	.run:hover {
		filter: brightness(1.08);
	}

	.get {
		background: none;
		border: 1px solid var(--rule-bright);
		color: var(--text);
	}

	.get:hover {
		background: var(--panel-lift);
	}

	.ghost {
		background: none;
		border: 1px solid var(--rule-bright);
		color: var(--text);
	}

	.ghost:hover {
		background: var(--panel-lift);
	}

	@media (max-width: 38rem) {
		.scrim {
			padding: var(--s4);
		}

		.dialog {
			max-height: calc(100dvh - var(--s6));
		}

		.head {
			padding: var(--s5) var(--s5) var(--s4);
		}

		.group-head,
		.note,
		ul {
			padding-left: var(--s5);
			padding-right: var(--s5);
		}

		.actions,
		.error {
			padding-left: var(--s5);
			padding-right: var(--s5);
		}

		li {
			align-items: stretch;
			flex-direction: column;
		}

		.row-actions {
			width: 100%;
		}

		.row-actions button {
			flex: 1;
		}
	}
</style>
