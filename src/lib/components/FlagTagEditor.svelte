<script lang="ts">
	let { tags = [], onchange }: { tags?: string[]; onchange?: (tags: string[]) => void } = $props();

	let draft = $state('');

	function add(event: SubmitEvent) {
		event.preventDefault();
		const tag = draft.trim();
		if (!/^[A-Za-z0-9_]{2,20}$/.test(tag)) return;
		if (!tags.some((known) => known.toLowerCase() === tag.toLowerCase())) {
			onchange?.([...tags, tag]);
		}
		draft = '';
	}
</script>

<div class="editor">
	<div class="tags" role="group" aria-label="Active flag formats">
		{#each tags as tag (tag.toLowerCase())}
			<button
				type="button"
				aria-label={`Remove ${tag} flag format`}
				onclick={() => onchange?.(tags.filter((item) => item !== tag))}
			>
				{tag}<span class="brace">&lbrace;…&rbrace;</span><span class="x">&nbsp;×</span>
			</button>
		{/each}
	</div>

	<form onsubmit={add}>
		<label class="label" for="flag-tag">Add prefix</label>
		<input
			id="flag-tag"
			bind:value={draft}
			placeholder="eventCTF"
			maxlength="20"
			autocomplete="off"
			spellcheck="false"
		/>
		<button type="submit">Add</button>
	</form>

	<p class="hint">
		A named format matches first and steers key recovery; unlabelled&nbsp;&lbrace;…&rbrace; shapes
		still match on shape alone.
	</p>
</div>

<style>
	.editor {
		display: grid;
		gap: var(--s3);
	}

	.tags {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2);
	}

	.tags button,
	form button {
		border: 1px solid var(--rule-bright);
		background: none;
		color: var(--text);
		font: inherit;
		font-size: var(--t-label);
		padding: var(--s1) var(--s2);
		cursor: pointer;
	}

	.tags button:focus-visible,
	form button:focus-visible {
		outline: 2px solid var(--signal);
		outline-offset: 2px;
	}

	.brace {
		color: var(--muted);
	}

	.x {
		color: var(--signal);
	}

	form {
		display: flex;
		align-items: center;
		gap: var(--s2);
	}

	input {
		background: var(--ground);
		border: 1px solid var(--rule-bright);
		color: var(--text);
		font: inherit;
		font-family: var(--mono);
		padding: var(--s1) var(--s2);
		width: min(18ch, 100%);
	}

	.hint {
		margin: 0;
		font-size: var(--t-label);
		color: var(--muted);
	}
</style>
