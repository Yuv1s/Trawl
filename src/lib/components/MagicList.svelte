<script lang="ts">
	import type { MagicHit, NestedArtifact, NestedAnalysis } from '$lib/worker/protocol';
	import { tally } from './tally';

	let {
		hits,
		size,
		bytes,
		onanalyse,
		nested,
		omitted = 0
	}: {
		hits: MagicHit[];
		size: number;
		bytes: Uint8Array;
		onanalyse?: (bytes: Uint8Array, name: string) => void;
		nested?: NestedAnalysis | null;
		/** Signatures the scan itself left out, past its allowance for their kind. */
		omitted?: number;
	} = $props();

	/** Rows drawn for each kind of signature, so a file of one kind cannot bury another. */
	const SHOWN_OF_EACH_KIND = 50;

	const embedded = $derived(hits.filter((h) => h.embedded));
	const header = $derived(hits.find((h) => !h.embedded) ?? null);

	/** The rows drawn, in file order, and how many of each kind there were to draw. */
	const kinds = $derived(tally(embedded, (hit) => hit.label, SHOWN_OF_EACH_KIND));
	const overflowing = $derived([...kinds.counts].filter(([, count]) => count > SHOWN_OF_EACH_KIND));

	const startsWithVowel = /^[aeiou]/i;
	const hex = (n: number) => `0x${n.toString(16)}`;

	/** What the walk made of each signature, by where it sits. */
	const children = $derived(
		new Map(
			(nested?.roots ?? [])
				.filter((child) => child.source === 'carved')
				.map((child) => [child.offset, child])
		)
	);

	function statusChip(status: 'analysed' | 'skipped' | 'error', reason?: string): string {
		switch (status) {
			case 'analysed':
				return 'analysed';
			case 'skipped':
				return reason ? `skipped: ${reason}` : 'skipped';
			case 'error':
				return reason ? `error: ${reason}` : 'error';
		}
	}

	function findingsCount(artifact: NestedArtifact): number {
		let count = artifact.findings.length;
		for (const child of artifact.children) count += findingsCount(child);
		return count;
	}

	const EXTENSIONS: Record<string, string> = {
		'PNG image': 'png',
		'JPEG image': 'jpg',
		'GIF image': 'gif',
		'BMP image': 'bmp',
		'ZIP archive': 'zip',
		'gzip stream': 'gz',
		'bzip2 stream': 'bz2',
		'7-Zip archive': '7z',
		'RAR archive': 'rar',
		'PDF document': 'pdf',
		'ELF binary': 'elf',
		'RIFF container': 'wav'
	};

	/**
	 * Hands the carved bytes to the browser as a download.
	 *
	 * The object URL is revoked on the next frame rather than immediately, since
	 * revoking before the browser has started reading cancels the save.
	 */
	function sliceOf(hit: MagicHit) {
		return bytes.slice(hit.offset, hit.offset + hit.length);
	}

	function carve(hit: MagicHit) {
		const slice = sliceOf(hit);
		const url = URL.createObjectURL(new Blob([slice as Uint8Array<ArrayBuffer>]));

		const link = document.createElement('a');
		link.href = url;
		link.download = `carved-${hex(hit.offset)}.${EXTENSIONS[hit.label] ?? 'bin'}`;
		link.click();

		requestAnimationFrame(() => URL.revokeObjectURL(url));
	}

	const kb = (n: number) =>
		n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n.toLocaleString()} bytes`;
</script>

{#if header}
	<p class="lead">
		This file starts with {startsWithVowel.test(header.label) ? 'an' : 'a'}
		<strong>{header.label}</strong> signature.
	</p>
{/if}

{#if embedded.length === 0}
	<p class="clear">
		No other file signatures anywhere in the {size.toLocaleString()} bytes. Signatures shorter than four
		bytes are checked against a field the format constrains before being reported, so a match by chance
		is unlikely.
	</p>
{:else}
	<ul class="hits">
		{#each kinds.kept as hit, i (i)}
			{@const child = children.get(hit.offset)}
			{@const beneath = child ? findingsCount(child) : 0}
			<li>
				<div class="head">
					<span class="label-text">{hit.label}</span>
					<div class="actions">
						{#if onanalyse}
							<button
								type="button"
								onclick={() =>
									onanalyse?.(
										sliceOf(hit),
										`carved-${hex(hit.offset)}.${EXTENSIONS[hit.label] ?? 'bin'}`
									)}
							>
								Analyse here
							</button>
						{/if}
						<button type="button" onclick={() => carve(hit)}>Save file</button>
					</div>
				</div>
				<span class="mono muted">
					{kb(hit.length)} at {hex(hit.offset)}, {((hit.offset / size) * 100).toFixed(1)}% into the
					file
				</span>
				{#if child}
					<span class="status">
						<span class="chip">{statusChip(child.status, child.reason)}</span>
						{#if beneath > 0}
							<span class="chip flagged">{beneath} finding{beneath === 1 ? '' : 's'} beneath</span>
						{/if}
					</span>
				{/if}
				{#if !hit.bounded}
					<span class="guess">
						This format carries no end marker, so the length runs to whatever comes next. The saved
						file may have a tail of unrelated bytes on it.
					</span>
				{/if}
			</li>
		{/each}
	</ul>

	{#each overflowing as [label, count] (label)}
		<p class="capped label">
			Showing the first {SHOWN_OF_EACH_KIND} of {count.toLocaleString()}
			{label} signatures.
		</p>
	{/each}
	{#if omitted > 0}
		<p class="capped label">
			Another {omitted.toLocaleString()} were left out of the scan, past the first 4,096 of their kind.
		</p>
	{/if}

	<p class="caveat">
		A file signature this far into another file is rarely an accident. PNG, JPEG, ZIP and PDF mark
		their own end, so for those formats the saved bytes stop exactly there.
	</p>
{/if}

<style>
	.lead {
		margin: 0 0 var(--s4);
		line-height: 1.6;
	}

	.lead strong {
		font-weight: 600;
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.hits {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s4);
	}

	.hits li {
		display: grid;
		gap: var(--s2);
		padding-bottom: var(--s3);
		border-bottom: 1px solid var(--rule);
	}

	.head {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s3) var(--s4);
	}

	.label-text {
		font-size: var(--t-mid);
		font-weight: 600;
		color: var(--signal);
	}

	.actions {
		margin-left: auto;
		display: flex;
		gap: var(--s2);
	}

	.head button {
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s1) var(--s3);
		cursor: pointer;
		transition: background-color 120ms var(--ease);
	}

	.head button:hover {
		background: var(--panel-lift);
	}

	.muted {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.guess {
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
		max-width: 72ch;
	}

	.status {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2);
	}

	.chip {
		font-size: var(--t-label);
		color: var(--muted);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		padding: 1px var(--s2);
		white-space: nowrap;
		width: fit-content;
	}

	.chip.flagged {
		color: var(--signal);
		border-color: var(--signal);
	}

	.capped {
		margin: var(--s3) 0 0;
		color: var(--muted);
	}

	.caveat {
		margin: var(--s4) 0 0;
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}
</style>
