<script lang="ts">
	let {
		bytes,
		baseOffset = 0,
		limit = 2048
	}: { bytes: Uint8Array; baseOffset?: number; limit?: number } = $props();

	const shown = $derived(bytes.subarray(0, limit));
	const hidden = $derived(Math.max(0, bytes.length - limit));

	const rows = $derived(
		Array.from({ length: Math.ceil(shown.length / 16) }, (_, r) => {
			const slice = shown.subarray(r * 16, r * 16 + 16);
			// Padded to 16 so a short final row keeps the ASCII gutter aligned.
			return {
				offset: (baseOffset + r * 16).toString(16).padStart(8, '0'),
				hex: Array.from({ length: 16 }, (_, i) =>
					i < slice.length ? slice[i].toString(16).padStart(2, '0') : ''
				),
				ascii: Array.from(slice, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'))
			};
		})
	);
</script>

{#if bytes.length === 0}
	<p class="empty">This chunk carries no data.</p>
{:else}
	<div class="hex mono">
		{#each rows as row (row.offset)}
			<div class="row">
				<span class="offset">{row.offset}</span>
				<span class="bytes">
					{#each row.hex as pair, i (i)}
						<span class="pair" class:gap={i === 7}>{pair || '  '}</span>
					{/each}
				</span>
				<span class="ascii">
					{#each row.ascii as ch, i (i)}<span class:printable={ch !== '.'}>{ch}</span>{/each}
				</span>
			</div>
		{/each}
	</div>

	{#if hidden > 0}
		<p class="truncated">
			{hidden.toLocaleString()} further bytes not shown.
		</p>
	{/if}
{/if}

<style>
	.hex {
		font-size: var(--t-label);
		line-height: 1.7;
		overflow-x: auto;
	}

	.row {
		display: flex;
		gap: var(--s4);
		white-space: nowrap;
	}

	.offset {
		color: var(--muted);
	}

	.pair {
		display: inline-block;
		width: 2ch;
		margin-right: 0.5ch;
		white-space: pre;
	}

	.pair.gap {
		margin-right: 1.5ch;
	}

	.ascii {
		color: var(--muted);
	}

	.ascii .printable {
		color: var(--text);
	}

	.empty,
	.truncated {
		margin: 0;
		color: var(--muted);
		font-size: var(--t-label);
	}

	.truncated {
		margin-top: var(--s3);
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
	}
</style>
