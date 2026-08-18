<script lang="ts">
	import Logo from '$lib/components/Logo.svelte';
	import type { PeelResult } from '$lib/worker/protocol';

	let { input, peel, onreset }: { input: string; peel: PeelResult; onreset: () => void } = $props();

	/** A step that found the answer rather than merely getting closer to it. */
	const conclusive = (reason: string) =>
		reason.includes('flag shape') || reason.includes('signature');

	const flags = $derived(
		peel.steps
			.filter((step) => step.reason.startsWith('flag shape, '))
			.map((step) => step.reason.slice('flag shape, '.length))
	);

	const PREVIEW = 240;
	const clip = (text: string) => (text.length > PREVIEW ? `${text.slice(0, PREVIEW)}…` : text);

	let copied = $state(false);
	let timer: ReturnType<typeof setTimeout> | undefined;

	$effect(() => () => clearTimeout(timer));

	function copy() {
		navigator.clipboard.writeText(peel.result).then(() => {
			copied = true;
			clearTimeout(timer);
			timer = setTimeout(() => (copied = false), 1600);
		});
	}
</script>

<div class="shell">
	<header>
		<div class="identity">
			<Logo size={22} />
			<span class="name">Pasted text</span>
			<span class="meta mono">{input.length.toLocaleString()} characters</span>
		</div>

		<div class="right">
			<span class="tally mono" class:live={flags.length > 0}>
				{peel.depth}
				{peel.depth === 1 ? 'layer' : 'layers'} peeled
			</span>
			<button type="button" class="reset" onclick={onreset}>New</button>
		</div>
	</header>

	{#if flags.length > 0}
		<section class="codend" aria-label="Cod-end, recovered candidates">
			<div class="codend-head">
				<h2 class="label">Cod-end</h2>
				<span class="count mono">{flags.length} candidate{flags.length === 1 ? '' : 's'}</span>
			</div>
			<ul class="found">
				{#each flags as flag (flag)}
					<li>
						<output class="value mono">{flag}</output>
						<span class="origin mono">from the encoding chain</span>
					</li>
				{/each}
			</ul>
		</section>
	{/if}

	<main class="pane">
		{#if peel.depth === 0}
			<div class="pane-head">
				<h2>Nothing to peel</h2>
				<p>Mantis tried every encoding it knows and none of them made this more readable.</p>
			</div>

			<p class="clear">
				That is a result, not a failure. It means the text is either already plain, or encrypted
				rather than encoded, or uses a scheme Mantis does not have yet. Decoding it anyway would
				have turned it into noise and called that progress.
			</p>

			<h3 class="label section">What you gave it</h3>
			<pre class="dump mono">{input}</pre>

			<button type="button" class="again" onclick={onreset}>Try something else</button>
		{:else}
			<div class="pane-head">
				<h2>Peeled {peel.depth} {peel.depth === 1 ? 'layer' : 'layers'}</h2>
				<p>Each layer was kept because of what fell out of it, not because of how it looked.</p>
			</div>

			<ol class="chain">
				<li class="start">
					<span class="marker mono">in</span>
					<div class="body">
						<span class="encoding">What you pasted</span>
						<pre class="excerpt mono">{clip(input)}</pre>
					</div>
				</li>

				{#each peel.steps as step, i (i)}
					<li class:last={i === peel.steps.length - 1}>
						<span class="marker mono">{i + 1}</span>
						<div class="body">
							<span class="encoding">{step.encoding}</span>
							<span class="reason" class:found={conclusive(step.reason)}>{step.reason}</span>
							<pre class="excerpt mono">{clip(step.output)}</pre>
						</div>
					</li>
				{/each}
			</ol>

			<section class="result">
				<div class="result-head">
					<h3 class="label">Result</h3>
					<button type="button" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
				</div>
				<pre class="answer mono" class:flagged={flags.length > 0}>{peel.result}</pre>
			</section>

			<p class="footnote">
				Mantis reads {(peel.score * 100).toFixed(0)}% of this as ordinary text. That number decided
				where to stop, and it is a rough measure rather than a verdict. If the answer looks half
				peeled, the layer underneath may use something not in the list yet.
			</p>
		{/if}
	</main>
</div>

<style>
	.shell {
		min-height: 100dvh;
		display: grid;
		grid-template-rows: auto auto minmax(0, 1fr);
	}

	header {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s5);
		align-items: baseline;
		justify-content: space-between;
		padding: var(--s3) var(--s5);
		border-bottom: 1px solid var(--rule);
		background: var(--panel-deep);
	}

	.identity {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s2) var(--s4);
		min-width: 0;
	}

	.identity :global(.logo) {
		color: var(--muted);
	}

	.name {
		font-weight: 600;
		font-size: var(--t-mid);
	}

	.meta {
		color: var(--muted);
		font-size: var(--t-data);
	}

	.right {
		display: flex;
		align-items: center;
		gap: var(--s4);
	}

	.tally {
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--muted);
	}

	.tally.live {
		color: var(--signal);
	}

	.reset,
	.result-head button {
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

	.reset:hover,
	.result-head button:hover {
		background: var(--panel-lift);
	}

	.codend {
		border-bottom: 1px solid var(--rule);
		background: var(--panel-deep);
		padding: var(--s4) var(--s5);
	}

	.codend-head {
		display: flex;
		align-items: baseline;
		gap: var(--s4);
	}

	.codend h2 {
		margin: 0;
		color: var(--signal);
	}

	.count {
		font-size: var(--t-label);
		color: var(--muted);
	}

	.found {
		list-style: none;
		margin: var(--s3) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}

	.found li {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2) var(--s4);
	}

	.value {
		font-size: var(--t-mid);
		font-weight: 500;
		color: var(--signal);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.origin {
		font-size: var(--t-label);
		color: var(--muted);
	}

	.pane {
		background: var(--panel);
		padding: var(--s4) var(--s5) var(--s6);
		overflow: auto;
		min-height: 0;
	}

	.pane-head {
		padding-bottom: var(--s3);
		margin-bottom: var(--s4);
		border-bottom: 1px solid var(--rule);
	}

	.pane-head h2 {
		margin: 0;
		font-size: var(--t-title);
		font-weight: 600;
	}

	.pane-head p {
		margin: var(--s1) 0 0;
		color: var(--muted);
	}

	.clear {
		margin: 0;
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.section {
		display: block;
		margin: var(--s5) 0 var(--s2);
	}

	/* The chain reads as one continuous descent, so the rule runs through the
	   markers rather than boxing each step separately. */
	.chain {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	.chain li {
		display: grid;
		grid-template-columns: auto minmax(0, 1fr);
		gap: 0 var(--s4);
		position: relative;
		padding-bottom: var(--s4);
	}

	.chain li::before {
		content: '';
		position: absolute;
		left: 11px;
		top: 1.6em;
		bottom: 0;
		width: 1px;
		background: var(--rule-bright);
	}

	.chain li.last::before {
		display: none;
	}

	.marker {
		width: 23px;
		height: 23px;
		display: grid;
		place-items: center;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		background: var(--panel-deep);
		font-size: var(--t-label);
		color: var(--muted);
	}

	.start .marker {
		color: var(--muted);
	}

	.body {
		display: grid;
		gap: var(--s1);
		min-width: 0;
		padding-bottom: var(--s2);
	}

	.encoding {
		font-size: var(--t-mid);
		font-weight: 600;
	}

	.reason {
		font-size: var(--t-label);
		color: var(--muted);
	}

	.reason.found {
		color: var(--signal);
	}

	.excerpt,
	.dump,
	.answer {
		margin: var(--s2) 0 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		line-height: 1.5;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--muted);
		user-select: all;
	}

	.dump {
		color: var(--text);
		max-height: 24rem;
		overflow: auto;
	}

	.again {
		justify-self: start;
		margin-top: var(--s4);
		background: none;
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font: inherit;
		padding: var(--s2) var(--s4);
		cursor: pointer;
		transition: background-color 140ms var(--ease);
	}

	.again:hover {
		background: var(--panel-lift);
	}

	.result {
		margin-top: var(--s3);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}

	.result-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--s4);
	}

	.result-head h3 {
		margin: 0;
	}

	.answer {
		color: var(--text);
		font-size: var(--t-mid);
		max-height: 28rem;
		overflow: auto;
	}

	.answer.flagged {
		color: var(--signal);
	}

	.footnote {
		margin: var(--s5) 0 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	@media (max-width: 860px) {
		.shell {
			height: auto;
		}

		.pane {
			padding: var(--s4);
			overflow: visible;
		}
	}
</style>
