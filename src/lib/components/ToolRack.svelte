<script lang="ts">
	import { STATUS_LABEL, type Tool } from '$lib/analysis/tools';

	let {
		built,
		planned,
		active,
		onselect
	}: {
		built: Tool[];
		planned: Tool[];
		active: string;
		onselect: (id: string) => void;
	} = $props();
</script>

<div class="rack">
	<h2 class="label">Tools</h2>
	<ul>
		{#each built as tool (tool.id)}
			<li>
				<button
					type="button"
					class="tool"
					class:current={tool.id === active}
					aria-current={tool.id === active}
					onclick={() => onselect(tool.id)}
				>
					<span class="name">{tool.name}</span>
					<span class="status mono" class:hit={tool.status === 'hit'}>
						{tool.status === 'hit' ? STATUS_LABEL.hit : tool.value || STATUS_LABEL[tool.status]}
					</span>
					<span class="measures">{tool.measures}</span>
					{#if tool.status === 'hit'}
						<span class="detail mono">{tool.value}</span>
					{/if}
				</button>
			</li>
		{/each}
	</ul>

	<h2 class="label planned-head">Not built yet</h2>
	<ul class="planned">
		{#each planned as tool (tool.id)}
			<li>
				<span class="name">{tool.name}</span>
				<span class="measures">{tool.measures}</span>
			</li>
		{/each}
	</ul>
</div>

<style>
	.rack {
		display: grid;
		align-content: start;
	}

	h2.label {
		margin: 0;
		padding: var(--s3) var(--s4);
		border-bottom: 1px solid var(--rule);
		background: var(--panel-deep);
	}

	.planned-head {
		margin-top: var(--s5);
		border-top: 1px solid var(--rule);
	}

	ul {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	li {
		border-bottom: 1px solid var(--rule);
	}

	.tool {
		width: 100%;
		display: grid;
		grid-template-columns: 1fr auto;
		gap: 0 var(--s3);
		padding: var(--s3) var(--s4);
		background: none;
		border: 0;
		color: inherit;
		font: inherit;
		text-align: left;
		cursor: pointer;
		transition: background-color 120ms var(--ease);
	}

	.tool:hover {
		background: var(--panel-lift);
	}

	.current {
		background: var(--panel-lift);
		box-shadow: inset 3px 0 0 var(--ink);
	}

	.name {
		font-weight: 600;
		font-size: var(--t-body);
	}

	.status {
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--muted);
		align-self: center;
	}

	.status.hit {
		color: var(--signal);
	}

	.measures {
		grid-column: 1 / -1;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.5;
	}

	.detail {
		grid-column: 1 / -1;
		margin-top: var(--s1);
		font-size: var(--t-label);
		color: var(--signal);
	}

	.planned li {
		display: grid;
		gap: var(--s1);
		padding: var(--s2) var(--s4);
		opacity: 0.55;
	}

	.planned .name {
		font-weight: 400;
	}
</style>
