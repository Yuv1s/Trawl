<script lang="ts">
	import Logo from '$lib/components/Logo.svelte';

	let { onreset }: { onreset: () => void } = $props();

	/**
	 * Where the scanner listens. The scanner is a separate program the person
	 * runs on their own machine; the offline half of Trawl never touches the
	 * network, and this half only ever talks to a server they started themselves.
	 */
	const scannerUrl = (import.meta.env.VITE_SCANNER_URL ?? 'http://localhost:8099').replace(
		/\/$/,
		''
	);

	/** How often to look for the scanner, in ms. Gentle: this runs until it answers. */
	const POLL = 2500;

	type Os = 'windows' | 'macos' | 'linux';

	const OS_LABEL: Record<Os, string> = {
		windows: 'Windows',
		macos: 'macOS',
		linux: 'Linux'
	};

	/**
	 * The install scripts live next to this page, so the one-liner points at
	 * whatever origin the person is actually on: a Vercel deployment, a preview,
	 * a custom domain. It works wherever Trawl is served from, unchanged.
	 */
	let origin = $state('');
	let os = $state<Os>('linux');

	/** One line per system: fetch the installer from this site and run it. */
	const commands = $derived<Record<Os, string>>({
		windows: `irm ${origin}/install.ps1 | iex`,
		macos: `curl -fsSL ${origin}/install.sh | sh`,
		linux: `curl -fsSL ${origin}/install.sh | sh`
	});
	const command = $derived(commands[os]);

	let connected = $state(false);
	let copied = $state(false);
	let copyTimer: ReturnType<typeof setTimeout> | undefined;

	function detectOs(): Os {
		const hint = (
			(navigator as { userAgentData?: { platform?: string } }).userAgentData?.platform ??
			navigator.platform ??
			navigator.userAgent
		).toLowerCase();
		if (hint.includes('win')) return 'windows';
		if (hint.includes('mac')) return 'macos';
		return 'linux';
	}

	async function ping() {
		try {
			const res = await fetch(`${scannerUrl}/health`, {
				method: 'GET',
				mode: 'cors',
				signal: AbortSignal.timeout(2000)
			});
			connected = res.ok;
		} catch {
			connected = false;
		}
	}

	$effect(() => {
		origin = window.location.origin;
		os = detectOs();
		ping();
		const timer = setInterval(ping, POLL);
		return () => clearInterval(timer);
	});

	$effect(() => () => clearTimeout(copyTimer));

	function copy() {
		navigator.clipboard.writeText(command).then(() => {
			copied = true;
			clearTimeout(copyTimer);
			copyTimer = setTimeout(() => (copied = false), 1600);
		});
	}
</script>

<section class="recon" aria-label="Web exploration">
	<header>
		<div class="identity">
			<Logo size={22} />
			<span class="name">Web exploration</span>
		</div>
		<button type="button" class="reset" onclick={onreset}>Back</button>
	</header>

	<main class="pane">
		{#if connected}
			<div class="pane-head">
				<h2>Scanner connected</h2>
				<p>
					Reached the scanner at <span class="mono">{scannerUrl}</span>. Paste a URL to work on.
				</p>
			</div>

			<form class="target" onsubmit={(e) => e.preventDefault()}>
				<label class="label" for="target-url">Target URL</label>
				<input
					id="target-url"
					type="url"
					spellcheck="false"
					autocomplete="off"
					placeholder="https://chal.some-ctf.example/"
				/>
				<button type="submit" disabled>Scan</button>
			</form>

			<p class="footnote">
				The scan itself lands with the scanner build. It fetches the target, reads what it serves,
				and runs it through the same flag and cipher detection the offline tools use.
			</p>
		{:else}
			<div class="pane-head">
				<h2>Waiting for the scanner</h2>
				<p>
					Reaching a live site is the one thing a browser tab cannot do, so this half runs a small
					program on your own machine. Paste the line for your system into any terminal. It
					downloads the scanner and starts it, no repository and no setup. Nothing about the target
					reaches Trawl, because there is nothing to reach: the scanner is yours and runs where you
					run it.
				</p>
			</div>

			<div class="start">
				<div class="switch" role="tablist" aria-label="Your system">
					{#each ['windows', 'macos', 'linux'] as const as choice (choice)}
						<button
							type="button"
							role="tab"
							aria-selected={os === choice}
							class:on={os === choice}
							onclick={() => (os = choice)}>{OS_LABEL[choice]}</button
						>
					{/each}
				</div>

				<div class="command">
					<pre class="mono">{command}</pre>
					<button type="button" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
				</div>

				<p class="hint">
					It runs a short script served from this page, which fetches the scanner for {OS_LABEL[os]} and
					starts it. Read it first if you like, at
					<span class="mono">{origin}/{os === 'windows' ? 'install.ps1' : 'install.sh'}</span>.
				</p>
			</div>

			<div class="status" aria-live="polite">
				<span class="dot"></span>
				<span class="mono">Watching for it at {scannerUrl}</span>
			</div>

			<p class="footnote">
				This switches over the moment the scanner answers, so start it and leave this open. Building
				from a clone of the repo instead? Run <span class="mono">npm run scanner</span> in the Trawl
				folder. Either way a different port is fine: point Trawl at it with
				<span class="mono">VITE_SCANNER_URL</span>.
			</p>
		{/if}
	</main>
</section>

<style>
	.recon {
		max-width: 62rem;
		margin: 0 auto;
		padding: var(--s5);
	}

	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--s3);
		padding-bottom: var(--s4);
		border-bottom: 1px solid var(--rule);
	}

	.identity {
		display: flex;
		align-items: center;
		gap: var(--s2);
	}

	.name {
		font-weight: 600;
	}

	.reset {
		background: none;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--muted);
		font-family: var(--sans);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		padding: var(--s1) var(--s3);
		cursor: pointer;
		transition:
			color 140ms var(--ease),
			border-color 140ms var(--ease);
	}
	.reset:hover {
		color: var(--text);
		border-color: var(--rule-bright);
	}

	.pane {
		padding-top: var(--s5);
		display: grid;
		gap: var(--s5);
	}

	.pane-head h2 {
		margin: 0 0 var(--s2);
		font-size: var(--t-title);
	}
	.pane-head p {
		margin: 0;
		color: var(--muted);
		max-width: 70ch;
		line-height: 1.6;
	}

	/* Three systems, one selected. A row of plain buttons rather than a styled
	   control, so it reads as a quiet switch and not a call to action. */
	.switch {
		display: flex;
		gap: var(--s1);
		margin-bottom: var(--s3);
	}
	.switch button {
		background: none;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--muted);
		font-family: var(--sans);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		padding: var(--s1) var(--s3);
		cursor: pointer;
		transition:
			color 140ms var(--ease),
			border-color 140ms var(--ease);
	}
	.switch button:hover {
		color: var(--text);
	}
	.switch button.on {
		color: var(--text);
		border-color: var(--signal);
	}

	/* The command sits in the ground colour like the other code blocks, with the
	   copy control flush inside its right edge rather than floating beside it. */
	.command {
		display: flex;
		align-items: stretch;
		gap: 1px;
		background: var(--rule);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		overflow: hidden;
	}
	.command pre {
		flex: 1;
		margin: 0;
		padding: var(--s3);
		background: var(--ground);
		font-size: var(--t-data);
		color: var(--text);
		user-select: all;
		overflow-x: auto;
	}
	.command button {
		flex: none;
		padding: 0 var(--s4);
		background: var(--panel-lift);
		border: 0;
		color: var(--muted);
		font-family: var(--sans);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		cursor: pointer;
		transition: color 140ms var(--ease);
	}
	.command button:hover {
		color: var(--text);
	}

	.hint {
		margin: var(--s2) 0 0;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	.status {
		display: flex;
		align-items: center;
		gap: var(--s2);
		color: var(--muted);
		font-size: var(--t-data);
	}
	/* Amber and breathing the whole time the panel is up, because it really is
	   watching the whole time: the poll never stops until the scanner answers. */
	.dot {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: var(--signal);
		flex: none;
		animation: pulse 1400ms var(--ease) infinite;
	}
	@keyframes pulse {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.3;
		}
	}

	.target {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--s2) var(--s3);
	}
	.target label {
		flex: none;
	}
	.target input {
		flex: 1 1 24ch;
		min-width: 0;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--text);
		font-family: var(--mono);
		font-size: var(--t-data);
	}
	.target input:focus-visible {
		border-color: var(--rule-bright);
	}
	.target button {
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
	}
	.target button:disabled {
		color: var(--muted);
		border-color: var(--rule);
		cursor: default;
	}

	.footnote {
		margin: 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
	}

	@media (max-width: 640px) {
		.recon {
			padding: var(--s4);
		}
	}
</style>
