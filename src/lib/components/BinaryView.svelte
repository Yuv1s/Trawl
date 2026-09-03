<script lang="ts">
	import type { ElfStructure } from '$lib/worker/protocol';

	let { binary }: { binary: ElfStructure } = $props();

	/** Each protection, with the state the file actually declares. `weak` is
	 *  what makes a binary worth a second look, and is the only state given
	 *  the accent, since it is the same kind of thing as a flag in a stream:
	 *  the reason you would care about this file. */
	type Guard = { label: string; value: string; weak: boolean; unknown: boolean };

	const guards = $derived<Guard[]>([
		{
			label: 'NX',
			value: binary.nx,
			weak: binary.nx === 'off',
			unknown: binary.nx === 'not declared'
		},
		{
			label: 'PIE',
			value: binary.pie,
			weak: binary.pie === 'no',
			unknown: binary.pie === 'shared object'
		},
		{
			label: 'RELRO',
			value: binary.relro,
			weak: binary.relro === 'none',
			unknown: false
		},
		{
			label: 'Canary',
			value: binary.canary ? 'on' : 'none found',
			weak: !binary.canary,
			unknown: false
		},
		{
			label: 'Fortify',
			value: binary.fortify ? 'on' : 'none found',
			weak: !binary.fortify,
			unknown: false
		}
	]);

	const notes = $derived(
		[
			binary.nx === 'off' &&
				'the stack is marked executable, so bytes written there can be run as code',
			binary.nx === 'not declared' &&
				'no PT_GNU_STACK header, so the file makes no claim either way and the kernel decides',
			binary.pie === 'no' &&
				'a fixed load address, so every address in this binary is the same on every run',
			binary.relro === 'none' && 'the relocation table stays writable for the life of the process',
			!binary.canary &&
				'no __stack_chk_fail is linked, so nothing here was compiled with a stack guard',
			binary.stripped && 'stripped: only the dynamic symbols a linker needs are left',
			binary.runpath !== null && `a library search path is baked in: ${binary.runpath}`
		].filter((note): note is string => typeof note === 'string')
	);

	/** A position-independent executable and a library are the same `e_type`,
	 *  so naming the type alone reads as a contradiction next to a PIE of
	 *  yes. Saying which kind of shared object it is resolves that without
	 *  changing what the field reports. */
	const kind = $derived(
		binary.kind === 'shared object' && binary.interpreter
			? 'shared object, run as a program'
			: binary.kind
	);

	const summary = $derived([
		{ key: 'Class', value: `${binary.class} ${binary.endianness}-endian` },
		{ key: 'Machine', value: binary.machine },
		{ key: 'Type', value: kind },
		{ key: 'Entry', value: binary.entry },
		...(binary.interpreter ? [{ key: 'Interpreter', value: binary.interpreter }] : [])
	]);

	const bytes = (n: number) => `${n.toLocaleString()} B`;
	const hex = (n: number) => `0x${n.toString(16)}`;
</script>

<div class="binary">
	{#if notes.length > 0}
		<ul class="findings">
			{#each notes as note (note)}
				<li>{note}</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			Every protection this format can declare is declared and on, and the symbol table is intact.
			That is what a hardened build looks like.
		</p>
	{/if}

	<div class="guards">
		<h3 class="label">What the file declares about its own defences</h3>
		<div class="rack">
			{#each guards as guard (guard.label)}
				<div class="guard" class:weak={guard.weak} class:unknown={guard.unknown}>
					<span class="guard-label">{guard.label}</span>
					<span class="guard-value mono">{guard.value}</span>
				</div>
			{/each}
		</div>
	</div>

	<div class="info">
		<h3 class="label">Header</h3>
		<dl>
			{#each summary as field (field.key)}
				<div>
					<dt class="label">{field.key}</dt>
					<dd class="mono">{field.value}</dd>
				</div>
			{/each}
		</dl>
	</div>

	{#if binary.needed.length > 0}
		<div class="info">
			<h3 class="label">Needs at run time</h3>
			<ul class="chips">
				{#each binary.needed as library (library)}
					<li class="mono chip">{library}</li>
				{/each}
			</ul>
		</div>
	{/if}

	{#if binary.imports.length > 0}
		<div class="info">
			<h3 class="label">
				Calls out to
				<span class="count"
					>{binary.importCount.toLocaleString()}{binary.imports.length < binary.importCount
						? `, first ${binary.imports.length}`
						: ''}</span
				>
			</h3>
			<ul class="chips">
				{#each binary.imports as symbol (symbol.name)}
					<li class="mono chip" title={symbol.name}>{symbol.name}</li>
				{/each}
			</ul>
		</div>
	{/if}

	{#if binary.exports.length > 0}
		<div class="info">
			<h3 class="label">
				Offers
				<span class="count"
					>{binary.exportCount.toLocaleString()}{binary.exports.length < binary.exportCount
						? `, first ${binary.exports.length}`
						: ''}</span
				>
			</h3>
			<ul class="chips">
				{#each binary.exports as symbol (symbol.name)}
					<li class="mono chip" title={symbol.name}>
						{symbol.name} <span class="muted">{symbol.address}</span>
					</li>
				{/each}
			</ul>
		</div>
	{/if}

	{#if binary.sections.length > 0}
		<table>
			<caption class="label">{binary.sections.length} sections</caption>
			<thead>
				<tr>
					<th scope="col" class="label">Section</th>
					<th scope="col" class="label">Kind</th>
					<th scope="col" class="label">Holds</th>
					<th scope="col" class="label">Address</th>
					<th scope="col" class="label num">Size</th>
					<th scope="col" class="label">Offset</th>
				</tr>
			</thead>
			<tbody>
				{#each binary.sections as section, index (index)}
					<tr class:odd={section.flags.includes('execute') && section.flags.includes('write')}>
						<td><span class="mono name">{section.name || '—'}</span></td>
						<td class="muted">{section.kind}</td>
						<td class="muted">{section.flags || '—'}</td>
						<td class="mono muted">{section.address}</td>
						<td class="mono num">{bytes(section.size)}</td>
						<td class="mono muted">{hex(section.offset)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	{#if binary.segments.length > 0}
		<table>
			<caption class="label">{binary.segments.length} segments, as the loader maps them</caption>
			<thead>
				<tr>
					<th scope="col" class="label">Segment</th>
					<th scope="col" class="label">Permissions</th>
					<th scope="col" class="label">Address</th>
					<th scope="col" class="label num">In file</th>
					<th scope="col" class="label num">In memory</th>
				</tr>
			</thead>
			<tbody>
				{#each binary.segments as segment, index (index)}
					<tr class:odd={segment.permissions === 'rwx'}>
						<td><span class="mono name">{segment.kind}</span></td>
						<td class="mono">{segment.permissions}</td>
						<td class="mono muted">{segment.address}</td>
						<td class="mono num">{bytes(segment.fileSize)}</td>
						<td class="mono num">{bytes(segment.memorySize)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<p class="footnote">
		Every line here is a field in one of the file's own tables. Nothing is disassembled: what the
		code does is a different question, and answering it needs a tool built around a session that
		lasts longer than one file.
	</p>
</div>

<style>
	/* A grid item will not shrink below its content by default, so one long
	   symbol name would otherwise set the width of the whole panel. */
	.binary {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: var(--s4);
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
		text-wrap: pretty;
	}

	.findings {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
	}

	.findings li {
		padding-left: var(--s3);
		border-left: 1px solid var(--signal);
		color: var(--text);
		line-height: 1.5;
		max-width: 78ch;
		text-wrap: pretty;
	}

	/* Inset against the pane the way a stream's own content is, so the rack
	   reads as an instrument set into the panel rather than another card
	   floating on it. */
	.guards {
		padding: var(--s3) var(--s4) var(--s4);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
	}

	.rack {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2);
		margin-top: var(--s3);
	}

	.guard {
		display: grid;
		gap: 2px;
		padding: var(--s2) var(--s3);
		min-width: 7rem;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		background: var(--panel);
	}

	/* A protection that is on is unremarkable, so it recedes. */
	.guard-label {
		font-size: 0.6875rem;
		font-weight: 600;
		letter-spacing: 0.12em;
		text-transform: uppercase;
		color: var(--muted);
	}

	.guard-value {
		font-size: var(--t-data);
		color: var(--text);
	}

	/* Off is the finding, and gets the same accent a flag does. */
	.guard.weak {
		border-color: var(--signal);
		background: color-mix(in srgb, var(--signal) 10%, var(--panel));
	}

	.guard.weak .guard-value {
		color: var(--signal);
	}

	/* Neither on nor off: the file does not say, and a dashed rule reads as
	   an absent answer rather than a bad one. */
	.guard.unknown {
		border-style: dashed;
		border-color: var(--rule-bright);
	}

	.guard.unknown .guard-value {
		color: var(--muted);
	}

	.info dl {
		margin: var(--s2) 0 0;
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--s1) var(--s3);
	}

	.info dt {
		color: var(--muted);
	}

	.info dd {
		margin: 0;
		color: var(--text);
		overflow-wrap: anywhere;
	}

	.count {
		font-weight: 400;
		font-variant-numeric: tabular-nums;
		letter-spacing: normal;
		text-transform: none;
		color: var(--muted);
	}

	.chips {
		list-style: none;
		display: flex;
		flex-wrap: wrap;
		gap: var(--s1) var(--s2);
		margin: var(--s2) 0 0;
		padding: 0;
	}

	/* A mangled C++ name runs to hundreds of characters, and a trivial source
	   file produces them, so a chip is capped at a width that stays readable
	   and holds its full name in a title rather than dragging the panel
	   sideways. The cap is a length rather than a percentage so the ellipsis
	   has something definite to resolve against. */
	.chip {
		font-size: var(--t-label);
		color: var(--text);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		padding: 1px var(--s2);
		white-space: nowrap;
		max-width: min(100%, 52ch);
		overflow: hidden;
		text-overflow: ellipsis;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	caption {
		text-align: left;
		padding-bottom: var(--s2);
	}

	th {
		text-align: left;
		padding: var(--s2) var(--s3);
		border-bottom: 1px solid var(--rule);
		position: sticky;
		top: 0;
		background: var(--panel);
	}

	.num {
		text-align: right;
	}

	td {
		padding: var(--s1) var(--s3);
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
		vertical-align: baseline;
	}

	.name {
		overflow-wrap: anywhere;
	}

	tr.odd td:first-child {
		box-shadow: inset 2px 0 0 var(--signal);
	}

	.muted {
		color: var(--muted);
	}

	.footnote {
		margin: 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
		text-wrap: pretty;
	}

	@media (max-width: 640px) {
		table {
			display: block;
			overflow-x: auto;
			white-space: nowrap;
		}

		.name {
			overflow-wrap: normal;
		}

		.guard {
			flex: 1 1 8rem;
		}
	}
</style>
