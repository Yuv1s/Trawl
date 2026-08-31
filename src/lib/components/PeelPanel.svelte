<script lang="ts">
	import Logo from '$lib/components/Logo.svelte';
	import HeaderControls from '$lib/components/HeaderControls.svelte';
	import type { KeyAttempt, PeelResult, Rotation } from '$lib/worker/protocol';
	import type { Report } from '$lib/analysis/rsa';

	let {
		input,
		peel,
		rsa,
		keyed,
		onkey,
		onreset
	}: {
		input: string;
		peel: PeelResult;
		rsa: Report | null;
		keyed: { key: string; attempts: KeyAttempt[] } | null;
		onkey: (key: string) => void;
		onreset: () => void;
	} = $props();

	let typedKey = $state('');
	let browsing = $state(false);

	/**
	 * Where a derived key stops being a shape the text suggested and starts
	 * being a reading. On a short ciphertext the right key led the field at
	 * 0.711 with the rest at 0.53 and below, and marking those as readable
	 * pointed at the wrong rows.
	 */
	const READS = 0.65;

	function tryKey(event: SubmitEvent) {
		event.preventDefault();
		if (typedKey.trim()) onkey(typedKey.trim());
	}

	function pick(key: string) {
		typedKey = key;
		onkey(key);
	}

	const broken = $derived(rsa?.recovered ?? []);

	/** A big number, shortened so it does not swallow the page. */
	const short = (value: bigint) => {
		const text = value.toString();
		return text.length > 60
			? `${text.slice(0, 30)}…${text.slice(-20)} (${text.length} digits)`
			: text;
	};

	/** A step that found the answer rather than merely getting closer to it. */
	const conclusive = (reason: string) =>
		reason.includes('flag shape') || reason.includes('signature');

	const flags = $derived([
		...peel.steps
			.filter((step) => step.reason.startsWith('flag shape, '))
			.map((step) => step.reason.slice('flag shape, '.length)),
		...peel.xor.flatMap((c) => c.flags)
	]);

	/** True when the peel alone got nowhere and the cipher attack found nothing. */
	const empty = $derived(
		peel.depth === 0 &&
			peel.xor.length === 0 &&
			!peel.hash &&
			!peel.vigenere &&
			!peel.affine &&
			!peel.transposition &&
			!peel.substitution &&
			broken.length === 0
	);

	/** How the columns were read, as the keyword order a person would write. */
	const columns = (order: number[]) => order.map((c) => c + 1).join(' ');

	/**
	 * Tallest bar in the letter chart, measured across both the text and English
	 * so the two stay on one scale and can be compared by eye.
	 */
	const peak = $derived(
		Math.max(...peel.frequency.letters.map((l) => Math.max(l.share, l.english)), 1)
	);

	/** Where a coincidence index sits between evenly spread and English. */
	const FLAT = 0.038;
	const ENGLISH_IC = 0.067;
	const along = $derived(
		Math.min(100, Math.max(0, ((peel.frequency.coincidence - 0.03) / 0.045) * 100))
	);

	/** Below this the counts are a curiosity rather than evidence. */
	const COUNTABLE = 20;

	/** How many readings to lay out before folding the rest away. */
	const LEADING = 8;

	const leading = $derived(peel.shortlist.slice(0, LEADING));
	const trailing = $derived(peel.shortlist.slice(LEADING));

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

{#snippet offer()}
	{#if peel.shortlist.length > 0}
		<section class="offer">
			<h3 class="label">{peel.shortlist.length} readings, since it could not choose</h3>
			<p class="clear">
				Every rotation Mantis knows, laid out. It picks answers by what they read like, and a token
				or a key reads like nothing, so on this it cannot pick for you. What it can do is lead with
				the rotations that decode onward into something printable. Plenty of these can be forced
				through a decoder; almost none come out the other side as text.
			</p>

			<ul class="readings">
				{#each leading as reading (reading.how)}
					{@render row(reading)}
				{/each}
			</ul>

			{#if trailing.length > 0}
				<details class="rest">
					<summary class="label">{trailing.length} more</summary>
					<ul class="readings">
						{#each trailing as reading (reading.how)}
							{@render row(reading)}
						{/each}
					</ul>
				</details>
			{/if}
		</section>
	{/if}
{/snippet}

{#snippet keybox()}
	<section class="keying">
		<h3 class="label">Try a key</h3>
		<p class="clear">
			Type a key and Mantis applies it, showing every result whether or not it reads, because your
			answer may be a token and a token reads like nothing. If you have no key, it will work out
			what your text suggests: Vigenère only commits to a key when it can stand behind one, and
			short text never gets there, but the working is still worth reading.
		</p>

		<form class="key-form" onsubmit={tryKey}>
			<label class="label" for="cipher-key">Key</label>
			<input
				id="cipher-key"
				bind:value={typedKey}
				spellcheck="false"
				autocomplete="off"
				placeholder="KEY"
			/>
			<button type="submit" disabled={!typedKey.trim()}>Apply</button>
			{#if peel.derivedKeys.length > 0}
				<button
					type="button"
					class="browse"
					aria-expanded={browsing}
					onclick={() => (browsing = !browsing)}
				>
					{browsing ? 'Hide suggestions' : "I don't have one"}
				</button>
			{/if}
		</form>

		{#if browsing}
			<div class="suggestions">
				<p class="clear">
					Not a list of common keys. Each of these was worked out of your text: split the letters
					into that many columns, and every column was enciphered by one key letter, so counting the
					letters in a column gives that letter back. The number is how many letters each column had
					to work from. Around twelve that is reliable, at two it is a coin toss.
				</p>
				<ul class="keylist">
					{#each peel.derivedKeys as derived (derived.key)}
						<li>
							<button
								type="button"
								class:reads={derived.score >= READS}
								class:chosen={typedKey.trim().toLowerCase() === derived.key}
								onclick={() => pick(derived.key)}
							>
								<span class="mono name">{derived.key}</span>
								<span class="mono count">{derived.perColumn}</span>
								<span class="mono preview">{derived.preview}</span>
							</button>
						</li>
					{/each}
				</ul>
			</div>
		{/if}

		{#if keyed}
			<ul class="attempts">
				{#each keyed.attempts as attempt (attempt.cipher)}
					<li class:found={attempt.flags.length > 0}>
						<div class="reading-head">
							<span class="mono how">{attempt.cipher}</span>
							{#each attempt.flags as flag (flag)}
								<span class="mono chip flagged">{flag}</span>
							{/each}
						</div>
						<pre class="excerpt mono" class:flagged={attempt.flags.length > 0}>{clip(
								attempt.plaintext
							)}</pre>

						{#if attempt.next.length > 0}
							<details class="deeper">
								<summary class="label"
									>Still enciphered, {attempt.next.length} keys for the layer under it</summary
								>
								<p class="clear">
									Two keys applied in turn are one cipher with a longer key, so nothing could have
									recovered them separately from the text alone. With the first one off, the second
									is an ordinary problem again, and these come out of what it left behind.
								</p>
								<ul class="keylist">
									{#each attempt.next as under (under.key)}
										<li>
											<button
												type="button"
												class:reads={under.score >= READS}
												onclick={() => pick(under.key)}
											>
												<span class="mono name">{under.key}</span>
												<span class="mono count">{under.perColumn}</span>
												<span class="mono preview">{under.preview}</span>
											</button>
										</li>
									{/each}
								</ul>
							</details>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</section>
{/snippet}

{#snippet row(reading: Rotation)}
	<li class:leads={reading.then !== null} class:found={reading.found !== null}>
		<div class="reading-head">
			<span class="mono how">{reading.how}</span>
			{#if reading.found}
				<span class="mono chip flagged">{reading.found}</span>
			{:else if reading.then}
				<span class="mono chip">then {reading.then.through.join(' → ')}</span>
			{/if}
		</div>
		<pre class="excerpt mono" class:flagged={reading.found !== null}>{clip(reading.text)}</pre>
		{#if reading.then}
			<pre class="excerpt mono onward">{clip(reading.then.result)}</pre>
		{/if}
	</li>
{/snippet}

<div class="shell">
	<header>
		<div class="identity">
			<button type="button" class="home" onclick={onreset} aria-label="Back to Trawl">
				<Logo size={22} />
			</button>
			<span class="name">Pasted text</span>
			<span class="meta mono">{input.length.toLocaleString()} characters</span>
		</div>

		<div class="right">
			<span class="tally mono" class:live={flags.length > 0}>
				{peel.depth}
				{peel.depth === 1 ? 'layer' : 'layers'} peeled
			</span>
			<button type="button" class="reset" onclick={onreset}>New</button>
			<HeaderControls />
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
		{#if broken.length > 0}
			<div class="pane-head">
				<h2>{broken.length === 1 ? 'One weakness' : `${broken.length} weaknesses`}</h2>
				<p>
					None of this breaks RSA. Each one breaks a key that was built wrong, which is what a
					competition hands you.
				</p>
			</div>

			<ul class="breaks">
				{#each broken as found (found.attack)}
					<li>
						<span class="encoding">{found.attack}</span>
						<span class="reason found">{found.because}</span>

						<dl class="recovered">
							{#if found.p !== undefined}
								<div>
									<dt class="label">p</dt>
									<dd class="mono">{short(found.p)}</dd>
								</div>
							{/if}
							{#if found.q !== undefined}
								<div>
									<dt class="label">q</dt>
									<dd class="mono">{short(found.q)}</dd>
								</div>
							{/if}
							{#if found.d !== undefined}
								<div>
									<dt class="label">Private exponent</dt>
									<dd class="mono">{short(found.d)}</dd>
								</div>
							{/if}
						</dl>

						{#if found.message}
							<pre class="answer mono flagged">{found.message}</pre>
						{/if}
					</li>
				{/each}
			</ul>

			<p class="footnote">
				A key generated properly defeats every one of these. When that is what you have, Trawl says
				so rather than grinding away at it.
			</p>

			<button type="button" class="again" onclick={onreset}>Try something else</button>
		{:else if peel.hash}
			<div class="pane-head">
				<h2>
					{peel.hash.certain ? peel.hash.candidates[0] : 'A hash, but of what'}
				</h2>
				<p>
					{peel.hash.certain
						? 'The string says so itself, so there is nothing to guess.'
						: 'The shape narrows it this far and no further.'}
				</p>
			</div>

			<ul class="guesses">
				{#each peel.hash.candidates as name (name)}
					<li class="mono" class:sure={peel.hash.certain}>{name}</li>
				{/each}
			</ul>

			<dl class="facts">
				<div>
					<dt class="label">Shape</dt>
					<dd class="mono">{peel.hash.shape}</dd>
				</div>
				{#if peel.hash.bits}
					<div>
						<dt class="label">Digest size</dt>
						<dd class="mono">{peel.hash.bits} bits</dd>
					</div>
				{/if}
			</dl>

			{#if !peel.hash.certain && peel.hash.candidates.length > 1}
				<p class="footnote">
					These produce digests of the same length, and there is nothing in the string that tells
					them apart. A tool that prints one name and stops is guessing without saying so.
				</p>
			{/if}

			<p class="footnote">
				Trawl does not crack hashes and will not. Reversing one means guessing inputs until a digest
				matches, which belongs on hardware you control running something built for it.
			</p>

			<button type="button" class="again" onclick={onreset}>Try something else</button>
		{:else if empty}
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

			{@render keybox()}

			{@render offer()}

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

			{#if peel.vigenere}
				<section class="cipher">
					<h3 class="label">Vigenère underneath</h3>
					<p class="clear">
						The letters were shifted by a repeating keyword. Splitting them by key position turns
						each group back into a plain shift, which letter counting solves.
					</p>

					<div class="key-head">
						<span class="mono key">{peel.vigenere.key}</span>
						<span class="mono chip">{peel.vigenere.key.length} letters</span>
					</div>
					<pre class="excerpt mono">{clip(peel.vigenere.plaintext)}</pre>
				</section>
			{/if}

			{#if peel.dictionary}
				<section class="cipher">
					<h3 class="label">A guessed key read it</h3>
					<p class="clear">
						There was not enough text to work the key out by counting letters, so Mantis tried a
						short list of words people reach for when inventing one. This is a guess that happened
						to land, not a recovery, and it is only reported because the result reads.
					</p>

					<div class="key-head">
						<span class="mono key">{peel.dictionary.key}</span>
						<span class="mono chip">{peel.dictionary.cipher}</span>
						{#each peel.dictionary.flags as flag (flag)}
							<span class="mono chip flagged">{flag}</span>
						{/each}
					</div>
					<pre class="excerpt mono">{clip(peel.dictionary.plaintext)}</pre>
				</section>
			{/if}

			{#if peel.affine}
				<section class="cipher">
					<h3 class="label">Affine underneath</h3>
					<p class="clear">
						Each letter was multiplied and then shifted. Only twelve multipliers can be undone at
						all, so there are 312 keys in total and every one of them was tried.
					</p>

					<div class="key-head">
						<span class="mono key">{peel.affine.a}x + {peel.affine.b}</span>
						<span class="mono chip">mod 26</span>
						{#if peel.affine.a === 1}
							<span class="mono chip">a shift, so also Caesar</span>
						{/if}
					</div>
					<pre class="excerpt mono">{clip(peel.affine.plaintext)}</pre>
				</section>
			{/if}

			{#if peel.transposition}
				<section class="cipher">
					<h3 class="label">Transposition underneath</h3>
					<p class="clear">
						The letters were never changed, only moved, which is why the letter counts already
						matched English while the text read as nothing. Putting them back in order is what made
						it readable.
					</p>

					<div class="key-head">
						{#if peel.transposition.kind === 'rail fence'}
							<span class="mono key">{peel.transposition.rails} rails</span>
							<span class="mono chip">rail fence</span>
						{:else}
							<span class="mono key">{columns(peel.transposition.order ?? [])}</span>
							<span class="mono chip">columnar</span>
							<span class="mono chip">{peel.transposition.width} columns</span>
						{/if}
					</div>
					<pre class="excerpt mono">{clip(peel.transposition.plaintext)}</pre>
				</section>
			{/if}

			{#if peel.substitution}
				<section class="cipher">
					<h3 class="label">Substitution underneath</h3>
					<p class="clear">
						The whole alphabet was replaced. There are too many keys to try, so this one was climbed
						to: swap two letters, keep the swap if the text reads better, repeat. Below about 200
						letters the answer comes back readable with a few letters still crossed.
					</p>

					<dl class="alphabet">
						<div>
							<dt class="label">Cipher</dt>
							<dd class="mono">abcdefghijklmnopqrstuvwxyz</dd>
						</div>
						<div>
							<dt class="label">Plain</dt>
							<dd class="mono key">{peel.substitution.key}</dd>
						</div>
					</dl>
					<pre class="excerpt mono">{clip(peel.substitution.plaintext)}</pre>
				</section>
			{/if}

			{#if peel.xor.length > 0}
				<section class="cipher">
					<h3 class="label">XOR underneath</h3>
					<p class="clear">
						What the layers came off to was not readable, so Mantis tried XOR against it. These keys
						produced something that was.
					</p>

					<ul class="keys">
						{#each peel.xor as found (found.kind + found.key)}
							<li>
								<div class="key-head">
									<span class="mono key">{found.key}</span>
									<span class="mono chip">{found.kind}</span>
									<span class="mono chip">
										{found.keyLength}
										{found.keyLength === 1 ? 'byte' : 'bytes'}
									</span>
								</div>
								<pre class="excerpt mono" class:flagged={found.flags.length > 0}>{clip(
										found.plaintext
									)}</pre>
							</li>
						{/each}
					</ul>
				</section>
			{/if}

			{#if peel.frequency.total > 0}
				<details class="counts">
					<summary class="label">Letter counts</summary>

					{#if peel.frequency.total < COUNTABLE}
						<p class="clear">
							{peel.frequency.total}
							{peel.frequency.total === 1 ? 'letter' : 'letters'}, which is too few to read anything
							into. The shape below is shown because you asked for it, not because it means
							something.
						</p>
					{:else}
						<p class="clear">
							What the solvers were working from. The bar is this text, the amber tick is what
							English would give the same letter. A cipher that swapped the alphabet moves the bars
							around; one that only moved the letters leaves them where English put them.
						</p>
					{/if}

					<ul class="bars">
						{#each peel.frequency.letters as count (count.letter)}
							<li style="--share: {count.share / peak}; --english: {(count.english / peak) * 100}%">
								<div class="column" aria-hidden="true">
									<div class="fill" class:none={count.count === 0}></div>
									<div class="tick"></div>
								</div>
								<span class="glyph mono" aria-hidden="true">{count.letter}</span>
								<span class="reading">
									{count.letter}, {count.count}
									{count.count === 1 ? 'time' : 'times'}, {count.share.toFixed(1)}% against English {count.english.toFixed(
										1
									)}%
								</span>
							</li>
						{/each}
					</ul>

					<div class="ioc">
						<div class="ioc-head">
							<h4 class="label">Index of coincidence</h4>
							<span class="mono value">{peel.frequency.coincidence.toFixed(4)}</span>
						</div>
						<p class="clear">
							The chance that two letters picked out of this text are the same one. It says how many
							alphabets were in play, which no amount of staring at the bars will tell you.
						</p>
						<div class="track">
							<div class="here" style="--at: {along}%"></div>
						</div>
						<div class="ends">
							<span class="mono">{FLAT.toFixed(3)} evenly spread</span>
							<span class="mono">{ENGLISH_IC.toFixed(3)} English</span>
						</div>
					</div>

					{#if peel.frequency.trigrams.length > 0 || peel.frequency.bigrams.length > 0}
						<div class="repeats">
							{#if peel.frequency.trigrams.length > 0}
								<h4 class="label">Repeated triples</h4>
								<ul class="runs">
									{#each peel.frequency.trigrams as run (run.text)}
										<li class="mono chip">{run.text}<span class="times">{run.count}</span></li>
									{/each}
								</ul>
							{/if}
							{#if peel.frequency.bigrams.length > 0}
								<h4 class="label">Repeated pairs</h4>
								<ul class="runs">
									{#each peel.frequency.bigrams as run (run.text)}
										<li class="mono chip">{run.text}<span class="times">{run.count}</span></li>
									{/each}
								</ul>
							{/if}
						</div>
					{:else}
						<p class="clear">
							Nothing repeats. In a text this length that is itself a reading: ordinary English
							repeats constantly, so letters that never do have usually been spread across more than
							one alphabet.
						</p>
					{/if}
				</details>
			{/if}

			{@render keybox()}

			{@render offer()}

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
		position: sticky;
		top: 0;
		z-index: 2;
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

	.home {
		display: flex;
		background: none;
		border: none;
		padding: 0;
		margin: 0;
		cursor: pointer;
		border-radius: var(--radius);
		transition: opacity 120ms var(--ease);
	}

	.home:hover {
		opacity: 0.72;
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

	.breaks {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s5);
	}

	.breaks li {
		display: grid;
		gap: var(--s1);
		padding-bottom: var(--s4);
		border-bottom: 1px solid var(--rule);
	}

	.recovered {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s5);
		margin: var(--s3) 0 0;
	}

	.recovered div {
		display: grid;
		gap: 2px;
		min-width: 0;
	}

	.recovered dt,
	.recovered dd {
		margin: 0;
	}

	.recovered dd {
		font-size: var(--t-data);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.guesses {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2);
	}

	.guesses li {
		font-size: var(--t-mid);
		padding: var(--s1) var(--s3);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		background: var(--panel-deep);
	}

	.guesses li.sure {
		color: var(--signal);
	}

	.facts {
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2) var(--s6);
		margin: var(--s5) 0 0;
	}

	.facts div {
		display: grid;
		gap: 2px;
	}

	.facts dt,
	.facts dd {
		margin: 0;
	}

	.facts dd {
		font-size: var(--t-mid);
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

	.cipher {
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}

	.cipher h3 {
		margin: 0 0 var(--s2);
	}

	.keys {
		list-style: none;
		margin: var(--s4) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s4);
	}

	.key-head {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2) var(--s3);
	}

	.key {
		font-size: var(--t-mid);
		font-weight: 500;
		user-select: all;
	}

	.chip {
		font-size: var(--t-label);
		color: var(--muted);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		padding: 1px var(--s2);
	}

	.excerpt.flagged {
		color: var(--signal);
	}

	/* The two alphabets stacked, so a swapped letter is found by reading down
	   rather than by counting along. */
	.alphabet {
		margin: var(--s3) 0 0;
		display: grid;
		gap: var(--s1);
	}
	.alphabet div {
		display: grid;
		grid-template-columns: 5.5rem 1fr;
		align-items: baseline;
		gap: var(--s3);
	}
	.alphabet dt {
		margin: 0;
	}
	.alphabet dd {
		margin: 0;
		font-size: var(--t-data);
		letter-spacing: 0.08em;
		color: var(--muted);
		overflow-wrap: anywhere;
	}
	.alphabet .key {
		color: var(--text);
	}

	.counts {
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}
	.counts summary {
		cursor: pointer;
		list-style: none;
	}
	.counts summary::-webkit-details-marker {
		display: none;
	}
	/* A caret that turns, rather than the browser's triangle in a font that
	   matches nothing else here. */
	.counts summary::before {
		content: '';
		display: inline-block;
		width: 5px;
		height: 5px;
		margin-right: var(--s2);
		border-right: 1px solid var(--muted);
		border-bottom: 1px solid var(--muted);
		transform: translateY(-2px) rotate(-45deg);
		transition: transform 160ms var(--ease);
	}
	.counts[open] summary::before {
		transform: translateY(-1px) rotate(45deg);
	}
	.counts summary:hover::before {
		border-color: var(--text);
	}
	.counts .clear {
		margin-top: var(--s3);
	}

	.bars {
		list-style: none;
		margin: var(--s4) 0 0;
		padding: 0;
		display: grid;
		grid-template-columns: repeat(26, 1fr);
		gap: 2px;
		align-items: end;
	}
	.bars li {
		display: grid;
		justify-items: center;
		gap: var(--s1);
		min-width: 0;
	}
	.column {
		position: relative;
		width: 100%;
		height: 88px;
		background: var(--panel-deep);
		border-bottom: 1px solid var(--rule);
	}
	.fill {
		position: absolute;
		inset: 0;
		transform-origin: bottom;
		transform: scaleY(var(--share));
		background: var(--rule-bright);
		transition: transform 180ms var(--ease);
	}
	/* A letter that never appears is a fact worth seeing, not an empty column
	   that reads as a rendering fault. */
	.fill.none {
		inset: auto 0 0;
		height: 1px;
		transform: none;
		background: var(--rule);
	}
	/* Where English would have put the top of that bar. */
	.tick {
		position: absolute;
		inset: auto 0 var(--english);
		height: 1px;
		background: var(--signal);
		opacity: 0.75;
	}
	.glyph {
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1;
	}

	/* Read out to assistive tech, since the bars themselves are decoration over
	   numbers that are the actual content. */
	.reading {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	.ioc {
		margin-top: var(--s5);
	}
	.ioc-head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: var(--s3);
	}
	.ioc-head h4 {
		margin: 0;
	}
	.ioc .value {
		font-size: var(--t-mid);
		color: var(--text);
	}
	.track {
		position: relative;
		margin-top: var(--s3);
		height: 3px;
		background: var(--panel-deep);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
	}
	.here {
		position: absolute;
		top: -4px;
		left: var(--at);
		width: 1px;
		height: 11px;
		background: var(--signal);
	}
	.ends {
		display: flex;
		justify-content: space-between;
		gap: var(--s3);
		margin-top: var(--s2);
		font-size: var(--t-label);
		color: var(--muted);
	}

	.repeats {
		margin-top: var(--s5);
	}
	.repeats h4 {
		margin: 0 0 var(--s2);
	}
	.repeats h4 ~ h4 {
		margin-top: var(--s4);
	}
	.runs {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--s2);
	}
	.runs li {
		display: inline-flex;
		align-items: baseline;
		gap: var(--s2);
		color: var(--text);
	}
	.times {
		color: var(--muted);
		font-size: var(--t-label);
	}

	/* Twenty-six columns stop being readable long before the panel does. */
	@media (max-width: 640px) {
		.column {
			height: 64px;
		}
		.glyph {
			font-size: 0.625rem;
		}
		.alphabet div {
			grid-template-columns: 1fr;
			gap: var(--s1);
		}
	}

	.offer {
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}
	.offer h3 {
		margin: 0 0 var(--s2);
	}
	.readings {
		list-style: none;
		margin: var(--s4) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}
	.readings li {
		padding-left: var(--s3);
		/* A rule rather than a card. Sixty of these stacked as cards would read
		   as sixty answers, and none of them is an answer yet. */
		border-left: 1px solid var(--rule);
	}
	.readings li.leads {
		border-left-color: var(--rule-bright);
	}
	.readings li.found {
		border-left-color: var(--signal);
	}
	.reading-head {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2) var(--s3);
	}
	.how {
		font-size: var(--t-data);
		color: var(--text);
	}
	.readings .excerpt {
		margin-top: var(--s1);
	}
	/* What the reading decodes to, stepped in so the pair reads as one thing. */
	.onward {
		margin-left: var(--s4);
		border-left-width: 1px;
		color: var(--text);
	}
	.rest {
		margin-top: var(--s4);
	}
	.rest summary {
		cursor: pointer;
		list-style: none;
	}
	.rest summary::-webkit-details-marker {
		display: none;
	}
	.rest summary::before {
		content: '';
		display: inline-block;
		width: 5px;
		height: 5px;
		margin-right: var(--s2);
		border-right: 1px solid var(--muted);
		border-bottom: 1px solid var(--muted);
		transform: translateY(-2px) rotate(-45deg);
		transition: transform 160ms var(--ease);
	}
	.rest[open] summary::before {
		transform: translateY(-1px) rotate(45deg);
	}
	.rest summary:hover::before {
		border-color: var(--text);
	}

	.keying {
		margin-top: var(--s5);
		padding-top: var(--s4);
		border-top: 1px solid var(--rule);
	}
	.keying h3 {
		margin: 0 0 var(--s2);
	}
	.key-form {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s2) var(--s3);
		margin-top: var(--s4);
	}
	.key-form label {
		flex: none;
	}
	.key-form input {
		flex: 1 1 14ch;
		min-width: 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--text);
		font-family: var(--mono);
		font-size: var(--t-data);
		letter-spacing: 0.06em;
	}
	.key-form input:focus-visible {
		border-color: var(--rule-bright);
	}
	.key-form input::placeholder {
		color: var(--muted);
	}
	.key-form button {
		flex: none;
		padding: var(--s2) var(--s4);
		background: var(--panel-lift);
		border: 1px solid var(--rule-bright);
		border-radius: var(--radius);
		color: var(--text);
		font-family: var(--sans);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		cursor: pointer;
		transition: background-color 140ms var(--ease);
	}
	.key-form button:hover:not(:disabled) {
		background: var(--rule);
	}
	.key-form button:disabled {
		color: var(--muted);
		border-color: var(--rule);
		cursor: default;
	}
	.key-form .browse {
		background: transparent;
		border-color: var(--rule);
		letter-spacing: 0.1em;
		color: var(--muted);
	}
	.key-form .browse:hover {
		background: transparent;
		border-color: var(--rule-bright);
		color: var(--text);
	}
	.suggestions {
		margin-top: var(--s4);
	}
	.suggestions .clear {
		font-size: var(--t-label);
	}
	/* One per row rather than wrapped chips. Each of these carries a key, the
	   evidence behind it and a preview of what it produced, which is three
	   columns of information and not a label. */
	.keylist {
		list-style: none;
		margin: var(--s3) 0 0;
		padding: 0;
		display: grid;
		gap: 2px;
	}
	.keylist button {
		display: grid;
		grid-template-columns: minmax(7ch, max-content) 3ch 1fr;
		align-items: baseline;
		gap: var(--s3);
		width: 100%;
		padding: var(--s2) var(--s3);
		background: var(--panel-deep);
		border: 1px solid transparent;
		border-left: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--muted);
		font-size: var(--t-data);
		text-align: left;
		cursor: pointer;
		transition:
			color 140ms var(--ease),
			border-color 140ms var(--ease);
	}
	.keylist button:hover {
		color: var(--text);
		border-left-color: var(--rule-bright);
	}
	.keylist .name {
		color: var(--text);
		overflow-wrap: anywhere;
	}
	/* How many letters the column had. The number that decides whether the key
	   beside it is worth anything. */
	.keylist .count {
		color: var(--muted);
		font-size: var(--t-label);
		text-align: right;
	}
	.keylist .preview {
		min-width: 0;
		overflow: hidden;
		white-space: nowrap;
		text-overflow: ellipsis;
	}
	.keylist button.reads {
		border-left-color: var(--signal);
	}
	.keylist button.reads .preview {
		color: var(--text);
	}
	.keylist button.chosen {
		background: var(--panel-lift);
		border-left-color: var(--rule-bright);
	}

	@media (max-width: 640px) {
		.keylist button {
			grid-template-columns: 1fr 3ch;
		}
		.keylist .preview {
			grid-column: 1 / -1;
		}
	}

	.attempts {
		list-style: none;
		margin: var(--s4) 0 0;
		padding: 0;
		display: grid;
		gap: var(--s3);
	}
	.attempts li {
		padding-left: var(--s3);
		border-left: 1px solid var(--rule);
	}
	.attempts li.found {
		border-left-color: var(--signal);
	}
	/* Brighter than the excerpts elsewhere. These are the answer somebody asked
	   for by name, not context around one. */
	/* Nested a step in, so a second layer reads as underneath the first rather
	   than beside it. */
	.deeper {
		margin: var(--s3) 0 0 var(--s4);
		padding-left: var(--s3);
		border-left: 1px solid var(--rule);
	}
	.deeper summary {
		cursor: pointer;
		list-style: none;
	}
	.deeper summary::-webkit-details-marker {
		display: none;
	}
	.deeper summary::before {
		content: '';
		display: inline-block;
		width: 5px;
		height: 5px;
		margin-right: var(--s2);
		border-right: 1px solid var(--muted);
		border-bottom: 1px solid var(--muted);
		transform: translateY(-2px) rotate(-45deg);
		transition: transform 160ms var(--ease);
	}
	.deeper[open] summary::before {
		transform: translateY(-1px) rotate(45deg);
	}
	.deeper summary:hover::before {
		border-color: var(--text);
	}
	.deeper .clear {
		margin-top: var(--s2);
		font-size: var(--t-label);
	}

	.attempts .excerpt {
		margin-top: var(--s1);
		color: var(--text);
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
