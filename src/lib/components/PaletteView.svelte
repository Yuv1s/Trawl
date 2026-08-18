<script lang="ts">
	import type { Palette, PaletteStego } from '$lib/worker/protocol';

	let { palette, stego }: { palette: Palette | null | undefined; stego: PaletteStego | null } =
		$props();

	const bytes = $derived(palette ? Math.round(palette.capacityBits / 8) : 0);
	const read = $derived(stego?.candidates.length ?? 0);
</script>

{#if !palette}
	<p class="clear">
		This image stores a colour for every pixel rather than picking from a numbered list, so there is
		no palette to compare. Only indexed images can hide data this way.
	</p>
{:else}
	<p class="lead">
		{palette.entries} colours in the list, {palette.unused} of them used by no pixel.
	</p>

	{#if palette.duplicates.length === 0}
		<p class="clear">
			Every entry is a different colour. Two entries painting the same colour would let an encoder
			pick either one, changing the file without changing the picture, and there is none of that
			here.
		</p>
	{:else}
		<ul class="dupes">
			{#each palette.duplicates as dup (dup.colour)}
				<li>
					<span class="swatches" aria-hidden="true">
						{#each { length: dup.count }, i (i)}
							<span class="swatch" style="background: {dup.colour}"></span>
						{/each}
					</span>
					<span class="mono value">{dup.colour}</span>
					<span class="mono note">
						{dup.count} separate entries, one colour
					</span>
				</li>
			{/each}
		</ul>

		<p class="capacity">
			Roughly <strong>{palette.capacityBits.toLocaleString()} bits</strong>, about
			{bytes.toLocaleString()} bytes, could be hidden by choosing between these entries. Every choice
			paints the same colour, so the picture would look identical.
		</p>
	{/if}

	{#if read > 0}
		<p class="caveat found">
			Something used that capacity. The choices between entries were read back and produced
			something legible, which is below.
		</p>
	{:else if palette.duplicates.length > 0}
		<p class="caveat">
			The choices between these entries were read back in both bit orders and produced nothing
			legible. The capacity is real; either nothing used it, or what did is encrypted.
		</p>
	{:else}
		<p class="caveat">
			With no repeated colour there is no free choice to make, so there is nothing here to read.
		</p>
	{/if}
{/if}

<style>
	.lead {
		margin: 0 0 var(--s4);
		line-height: 1.6;
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.caveat.found {
		color: var(--signal);
	}

	.dupes {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	.dupes li {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s2) var(--s4);
		padding-bottom: var(--s3);
		border-bottom: 1px solid var(--rule);
	}

	.swatches {
		display: flex;
		gap: 3px;
	}

	.swatch {
		width: 26px;
		height: 26px;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
	}

	.value {
		font-size: var(--t-mid);
		color: var(--signal);
	}

	.note {
		font-size: var(--t-label);
		color: var(--muted);
	}

	.capacity {
		margin: var(--s4) 0 0;
		max-width: 72ch;
		line-height: 1.6;
	}

	.capacity strong {
		color: var(--signal);
		font-weight: 600;
	}

	.caveat {
		margin: var(--s4) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}
</style>
