<script lang="ts">
	import Logo from '$lib/components/Logo.svelte';
	import HeaderControls from '$lib/components/HeaderControls.svelte';
	import { getOrCreateScannerToken } from '$lib';
	import { SvelteSet } from 'svelte/reactivity';

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
	type CopyTarget = 'install' | 'restart';

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
	let scannerToken = $state('');
	/** Off by default, the same as the scanner itself: reaching local and
	 *  private targets is a choice the person installing it makes. */
	let allowLocal = $state(false);

	/** One line per system: fetch the installer from this site and run it. */
	const commands = $derived<Record<Os, string>>({
		windows: `$env:TRAWL_TOKEN='${scannerToken}'; $env:TRAWL_ORIGIN='${origin}';${allowLocal ? " $env:TRAWL_ALLOW_LOCAL='1';" : ' Remove-Item Env:TRAWL_ALLOW_LOCAL -ErrorAction SilentlyContinue;'} irm ${origin}/install.ps1 | iex`,
		macos: `curl -fsSL ${origin}/install.sh | TRAWL_TOKEN='${scannerToken}' TRAWL_ORIGIN='${origin}'${allowLocal ? " TRAWL_ALLOW_LOCAL='1'" : ''} sh`,
		linux: `curl -fsSL ${origin}/install.sh | TRAWL_TOKEN='${scannerToken}' TRAWL_ORIGIN='${origin}'${allowLocal ? " TRAWL_ALLOW_LOCAL='1'" : ''} sh`
	});
	const command = $derived(commands[os]);
	const scannerAddress = new URL(scannerUrl);
	const scannerPort = scannerAddress.port || (scannerAddress.protocol === 'https:' ? '443' : '80');
	const restartCommands = $derived<Record<Os, string>>({
		windows: `$env:TRAWL_TOKEN='${scannerToken}'; $env:TRAWL_ORIGIN='${origin}'; $env:PORT='${scannerPort}'; & "$env:LOCALAPPDATA\\trawl\\trawl-scan.exe" --allow-local`,
		macos: `TRAWL_TOKEN='${scannerToken}' TRAWL_ORIGIN='${origin}' PORT='${scannerPort}' "$HOME/.trawl/bin/trawl-scan" --allow-local`,
		linux: `TRAWL_TOKEN='${scannerToken}' TRAWL_ORIGIN='${origin}' PORT='${scannerPort}' "$HOME/.trawl/bin/trawl-scan" --allow-local`
	});
	const restartCommand = $derived(restartCommands[os]);

	let connected = $state(false);
	/** Whether the scanner will reach local and private targets, from /health. */
	let localMode = $state(false);
	let copied = $state<CopyTarget | null>(null);
	let copyError = $state<CopyTarget | null>(null);
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
		if (!scannerToken) return;
		try {
			const res = await fetch(`${scannerUrl}/health`, {
				method: 'GET',
				mode: 'cors',
				headers: { Authorization: `Bearer ${scannerToken}` },
				signal: AbortSignal.timeout(2000)
			});
			connected = res.ok;
			if (res.ok) {
				const health = (await res.json()) as { allow_local?: boolean };
				const nextLocalMode = health.allow_local === true;
				if (nextLocalMode && localRefusal) scanError = null;
				localMode = nextLocalMode;
			}
		} catch {
			connected = false;
		}
	}

	$effect(() => {
		origin = window.location.origin;
		scannerToken = getOrCreateScannerToken();
		os = detectOs();
		ping();
		const timer = setInterval(ping, POLL);
		return () => clearInterval(timer);
	});

	$effect(() => () => clearTimeout(copyTimer));

	async function copy(value: string, target: CopyTarget) {
		clearTimeout(copyTimer);
		copied = null;
		copyError = null;
		try {
			await navigator.clipboard.writeText(value);
			copied = target;
			copyTimer = setTimeout(() => (copied = null), 1600);
		} catch {
			copyError = target;
		}
	}

	async function copyLocalRestart() {
		allowLocal = true;
		await copy(restartCommand, 'restart');
	}

	// The shape the scanner returns: a crawl, grouped the way a person looks.
	type Located = { value: string; source: string; note: string };
	type PageResult = { url: string; status: number };
	type ScanResult = {
		target: string;
		pages: PageResult[];
		images: string[];
		scripts: string[];
		assets: string[];
		external: string[];
		flags: Located[];
		comments: Located[];
	};

	// One thing in the tree, and the thing the preview shows when it is picked.
	type Item =
		| { kind: 'flag'; id: string; label: string; source: string; note: string }
		| { kind: 'comment'; id: string; label: string; source: string }
		| { kind: 'page'; id: string; label: string; status: number }
		| { kind: 'image'; id: string; label: string }
		| { kind: 'script'; id: string; label: string }
		| { kind: 'asset'; id: string; label: string }
		| { kind: 'external'; id: string; label: string };

	type Category = { key: string; label: string; items: Item[] };

	let target = $state('');
	/** Send the active battery, which the person must affirm they may run. */
	let activeChecks = $state(false);
	/** The person's own leads, one per line, woven into the active checks. */
	let hintText = $state('');
	let scanning = $state(false);
	let scanError = $state<string | null>(null);
	let result = $state<ScanResult | null>(null);
	let selected = $state<Item | null>(null);
	const closed = new SvelteSet<string>();

	/** A refusal that a local-mode scanner would not have given. */
	const localRefusal = $derived(
		scanError !== null &&
			!localMode &&
			/loopback|private network|unique local address/i.test(scanError)
	);

	function fileName(url: string): string {
		try {
			const u = new URL(url);
			const seg = u.pathname.split('/').filter(Boolean).pop() ?? u.pathname;
			return decodeURIComponent(seg) || u.hostname;
		} catch {
			return url;
		}
	}

	/** A page's path, for a tree that would be all origin otherwise. */
	function shortPath(url: string): string {
		try {
			const u = new URL(url);
			return decodeURIComponent(u.pathname + u.search) || '/';
		} catch {
			return url;
		}
	}

	/** The scanner's own fetch of a target resource, so the browser never has to. */
	function proxied(url: string): string {
		return `${scannerUrl}/fetch?url=${encodeURIComponent(url)}&token=${encodeURIComponent(scannerToken)}`;
	}

	const categories = $derived.by<Category[]>(() => {
		if (!result) return [];
		const cats: Category[] = [
			{
				key: 'flags',
				label: 'Flags',
				items: result.flags.map((f) => ({
					kind: 'flag',
					id: f.value,
					label: f.value,
					source: f.source,
					note: f.note
				}))
			},
			{
				key: 'pages',
				label: 'Pages',
				items: result.pages.map((p) => ({
					kind: 'page',
					id: p.url,
					label: shortPath(p.url),
					status: p.status
				}))
			},
			{
				key: 'images',
				label: 'Images',
				items: result.images.map((u) => ({ kind: 'image', id: u, label: fileName(u) }))
			},
			{
				key: 'scripts',
				label: 'Scripts',
				items: result.scripts.map((u) => ({ kind: 'script', id: u, label: fileName(u) }))
			},
			{
				key: 'assets',
				label: 'Assets',
				items: result.assets.map((u) => ({ kind: 'asset', id: u, label: fileName(u) }))
			},
			{
				key: 'comments',
				label: 'Comments',
				items: result.comments.map((c) => ({
					kind: 'comment',
					id: c.value,
					label: c.value,
					source: c.source
				}))
			},
			{
				key: 'external',
				label: 'External',
				items: result.external.map((u) => ({ kind: 'external', id: u, label: u }))
			}
		];
		return cats.filter((c) => c.items.length > 0);
	});

	/** Flags and comments the preview attributes to the page being looked at. */
	const onThisPage = $derived.by(() => {
		if (selected?.kind !== 'page' || !result) return { flags: [], comments: [] };
		const url = selected.id;
		return {
			flags: result.flags.filter((f) => f.source === url),
			comments: result.comments.filter((c) => c.source === url)
		};
	});

	function toggle(key: string) {
		if (closed.has(key)) closed.delete(key);
		else closed.add(key);
	}

	async function runScan(event: SubmitEvent) {
		event.preventDefault();
		const url = target.trim();
		if (!url || scanning) return;

		scanning = true;
		scanError = null;
		result = null;
		selected = null;

		try {
			const res = await fetch(`${scannerUrl}/scan`, {
				method: 'POST',
				mode: 'cors',
				headers: {
					Authorization: `Bearer ${scannerToken}`,
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					url,
					active: activeChecks,
					hints: activeChecks
						? hintText
								.split(/[\n,]/)
								.map((hint) => hint.trim())
								.filter(Boolean)
						: []
				})
			});
			if (!res.ok) {
				scanError = (await res.text()) || `the scan failed (${res.status})`;
				return;
			}
			result = (await res.json()) as ScanResult;
			// Land on the first flag if there is one, otherwise the entry page.
			selected = categories[0]?.items[0] ?? null;
			closed.clear();
		} catch {
			scanError = 'lost the scanner mid-scan; is it still running?';
		} finally {
			scanning = false;
		}
	}

	/** Open the offline tools on a target's image in a new tab, results left intact. */
	function checkWithTrawl(url: string) {
		const base = window.location.origin + window.location.pathname;
		window.open(`${base}?analyse=${encodeURIComponent(url)}`, '_blank', 'noopener,noreferrer');
	}
</script>

<section class="recon" aria-label="Web exploration">
	<header>
		<div class="identity">
			<Logo size={22} />
			<span class="name">Web exploration</span>
		</div>
		<div class="right">
			<button type="button" class="reset" onclick={onreset}>Back</button>
			<HeaderControls />
		</div>
	</header>

	<main class="pane">
		{#if connected}
			<div class="pane-head">
				<h2>Scanner connected</h2>
				<p>
					Reached the scanner at <span class="mono">{scannerUrl}</span>{localMode
						? ', in local mode'
						: ''}. Give it a target you are allowed to test, and Remora pulls the page apart into
					what Trawl already reads.
				</p>
			</div>

			<form class="target" onsubmit={runScan} aria-busy={scanning}>
				<label class="label" for="target-url">Target URL</label>
				<input
					id="target-url"
					type="url"
					bind:value={target}
					aria-describedby={scanError ? 'scan-error-text' : undefined}
					aria-invalid={localRefusal}
					spellcheck="false"
					autocomplete="off"
					placeholder="https://chal.some-ctf.example/"
				/>
				<button type="submit" disabled={!target.trim() || scanning}>
					{scanning ? 'Scanning' : 'Scan'}
				</button>
			</form>

			<label class="active-gate">
				<input type="checkbox" bind:checked={activeChecks} />
				<span>
					<span class="gate-title">Active checks</span>
					<span class="gate-note"
						>Sends crafted requests, an injection quote, a privilege field, a timestamp, rather than
						only reading. Tick only for a target you are authorized to test.</span
					>
				</span>
			</label>

			{#if activeChecks}
				<div class="hints">
					<label class="label" for="hints">Already have a clue where a flag might be?</label>
					<textarea
						id="hints"
						bind:value={hintText}
						rows="2"
						spellcheck="false"
						autocomplete="off"
						placeholder="a parameter, field, header or path you suspect (one per line)"></textarea>
					<p class="gate-note">
						Optional. Each line is tried in every position at once, as an endpoint, a parameter, a
						form field and a header, on top of the built-in checks. Leave empty to run the general
						checks alone.
					</p>
				</div>
			{/if}

			{#if scanError}
				<div class="scan-failure">
					<p id="scan-error-text" class="scan-error mono" role="alert">{scanError}</p>
					{#if localRefusal}
						<section class="local-restart" aria-labelledby="local-restart-title">
							<div class="local-restart-copy">
								<h3 id="local-restart-title">Restart in local mode</h3>
								<p>
									Copy this command first. Then stop the scanner with <span class="mono"
										>Ctrl+C</span
									>
									and paste it into the same terminal. Trawl reconnects when it starts.
								</p>
							</div>

							<div class="command">
								<input
									class="command-text mono"
									type="text"
									readonly
									aria-label={`${OS_LABEL[os]} local-mode restart command`}
									value={restartCommand}
								/>
								<button
									type="button"
									onclick={copyLocalRestart}
									aria-describedby="local-restart-note"
								>
									{copied === 'restart' ? 'Copied' : 'Copy restart command'}
								</button>
							</div>

							<p class="copy-status" role="status" aria-live="polite" aria-atomic="true">
								{copied === 'restart' ? 'Restart command copied.' : ''}
							</p>
							{#if copyError === 'restart'}
								<p class="copy-error" role="alert">
									Clipboard access failed. Select the command and copy it manually.
								</p>
							{/if}
							<p id="local-restart-note" class="local-restart-note">
								Local mode can reach this machine and private networks. Cloud metadata stays
								blocked.
							</p>
						</section>
					{/if}
				</div>
			{/if}

			{#if scanning}
				<div class="status" role="status" aria-live="polite">
					<span class="dot" aria-hidden="true"></span>
					<span class="mono">reaching {target}</span>
				</div>
			{/if}

			{#if result}
				{@const r = result}
				<p class="summary">
					<span class="mono">{r.target}</span>, {r.pages.length}
					{r.pages.length === 1 ? 'page' : 'pages'} crawled.
				</p>

				<div class="workbench">
					<nav class="tree" aria-label="Findings">
						{#each categories as cat (cat.key)}
							<section class="cat">
								<button
									type="button"
									class="cat-head"
									aria-expanded={!closed.has(cat.key)}
									onclick={() => toggle(cat.key)}
								>
									<span class="caret" class:open={!closed.has(cat.key)} aria-hidden="true"></span>
									<span class="cat-label label">{cat.label}</span>
									<span class="cat-count mono">{cat.items.length}</span>
								</button>

								{#if !closed.has(cat.key)}
									<ul class="items">
										{#each cat.items as item (item.id)}
											<li>
												<button
													type="button"
													class="item"
													class:on={selected?.kind === item.kind && selected?.id === item.id}
													onclick={() => (selected = item)}
												>
													{#if item.kind === 'image'}
														<img class="thumb" src={proxied(item.id)} alt="" loading="lazy" />
													{/if}
													<span class="item-label mono" class:flagged={item.kind === 'flag'}
														>{item.label}</span
													>
													{#if item.kind === 'page' && item.status !== 200}
														<span class="chip mono">{item.status}</span>
													{/if}
												</button>
											</li>
										{/each}
									</ul>
								{/if}
							</section>
						{/each}
					</nav>

					<div class="preview">
						{#if selected}
							{@const s = selected}
							{#if s.kind === 'flag'}
								<span class="d-kind label">Flag</span>
								<p class="d-value mono flagged">{s.label}</p>
								<p class="where">
									Found on
									<a href={s.source} target="_blank" rel="external noreferrer noopener" class="mono"
										>{shortPath(s.source)}</a
									>
								</p>
								{#if s.note}
									<p class="how"><span class="label">how</span> {s.note}</p>
								{/if}
							{:else if s.kind === 'comment'}
								<span class="d-kind label">Comment</span>
								<pre class="d-block mono">{s.label}</pre>
								<p class="where">
									On
									<a href={s.source} target="_blank" rel="external noreferrer noopener" class="mono"
										>{shortPath(s.source)}</a
									>
								</p>
							{:else if s.kind === 'page'}
								<div class="d-head">
									<span class="d-kind label">Page</span>
									<span class="chip mono" class:bad={s.status >= 400}>{s.status}</span>
								</div>
								<p class="d-value mono">{shortPath(s.id)}</p>
								{#if onThisPage.flags.length > 0}
									<div class="d-list">
										<h4 class="label">Flags here</h4>
										<ul class="plain">
											{#each onThisPage.flags as f (f.value)}
												<li class="mono flagged">{f.value}</li>
											{/each}
										</ul>
									</div>
								{/if}
								{#if onThisPage.comments.length > 0}
									<div class="d-list">
										<h4 class="label">Comments here</h4>
										<ul class="plain">
											{#each onThisPage.comments as c (c.value)}
												<li class="mono comment">{c.value}</li>
											{/each}
										</ul>
									</div>
								{/if}
								<a class="open" href={s.id} target="_blank" rel="external noreferrer noopener"
									>Open in a tab</a
								>
							{:else if s.kind === 'image'}
								<span class="d-kind label">Image</span>
								<div class="shot"><img src={proxied(s.id)} alt={fileName(s.id)} /></div>
								<p class="where mono">{shortPath(s.id)}</p>
								<div class="actions">
									<button type="button" class="do" onclick={() => checkWithTrawl(s.id)}>
										Check with Trawl
									</button>
									<a class="open" href={s.id} target="_blank" rel="external noreferrer noopener"
										>Open</a
									>
								</div>
								<p class="hint">
									Check with Trawl opens a new tab and runs it through the same tools a dropped
									image gets: the LSB sweeps, the metadata, and anything hidden past the end of the
									file.
								</p>
							{:else}
								<span class="d-kind label">{s.kind}</span>
								<p class="d-value mono">{s.kind === 'external' ? s.id : shortPath(s.id)}</p>
								<a class="open" href={s.id} target="_blank" rel="external noreferrer noopener"
									>Open</a
								>
							{/if}
						{:else}
							<p class="clear">Pick something on the left to look at it.</p>
						{/if}
					</div>
				</div>
			{/if}
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
				<div class="switch" role="group" aria-label="Your operating system">
					{#each ['windows', 'macos', 'linux'] as const as choice (choice)}
						<button
							type="button"
							aria-pressed={os === choice}
							class:on={os === choice}
							onclick={() => (os = choice)}>{OS_LABEL[choice]}</button
						>
					{/each}
				</div>

				<div class="command">
					<input
						class="command-text mono"
						type="text"
						readonly
						aria-label={`${OS_LABEL[os]} scanner install command`}
						value={command}
					/>
					<button type="button" onclick={() => copy(command, 'install')}>
						{copied === 'install' ? 'Copied' : 'Copy'}
					</button>
				</div>
				<p class="copy-status" role="status" aria-live="polite" aria-atomic="true">
					{copied === 'install' ? 'Install command copied.' : ''}
				</p>
				{#if copyError === 'install'}
					<p class="copy-error" role="alert">
						Clipboard access failed. Select the command and copy it manually.
					</p>
				{/if}

				<label class="active-gate">
					<input type="checkbox" bind:checked={allowLocal} />
					<span>
						<span class="gate-title">Allow local targets</span>
						<span class="gate-note"
							>Lets the scanner reach a challenge on this machine or your private network. The cloud
							metadata address stays blocked either way. Leave this off unless the target is yours
							and local.</span
						>
					</span>
				</label>

				<p class="hint">
					It runs a short script served from this page, which fetches the scanner for {OS_LABEL[os]} and
					starts it. Read it first if you like, at
					<span class="mono">{origin}/{os === 'windows' ? 'install.ps1' : 'install.sh'}</span>.
				</p>
			</div>

			<div class="status" role="status" aria-live="polite">
				<span class="dot" aria-hidden="true"></span>
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
		max-width: 84rem;
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

	.right {
		display: flex;
		align-items: center;
		gap: var(--s3);
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
	.start {
		min-width: 0;
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

	.command {
		display: flex;
		min-width: 0;
		max-width: 100%;
		align-items: stretch;
		gap: 1px;
		background: var(--rule);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		overflow: hidden;
	}
	.command:focus-within {
		border-color: var(--rule-bright);
	}
	.command-text {
		flex: 1;
		width: 100%;
		min-width: 0;
		margin: 0;
		padding: var(--s3);
		background: var(--ground);
		border: 0;
		font-size: var(--t-data);
		color: var(--text);
		user-select: all;
	}
	.command-text:focus-visible,
	.command button:focus-visible {
		outline-offset: -3px;
	}
	.command button {
		flex: none;
		min-height: 44px;
		padding: 0 var(--s4);
		background: var(--panel-lift);
		border: 0;
		color: var(--text);
		font-family: var(--sans);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		cursor: pointer;
		transition: color 140ms var(--ease);
	}
	.command button:hover {
		color: var(--signal);
	}

	.copy-status {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
	.copy-error {
		margin: var(--s2) 0 0;
		font-size: var(--t-label);
		line-height: 1.5;
		color: var(--text);
	}

	.hint {
		margin: var(--s2) 0 0;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
		max-width: 74ch;
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
	.active-gate {
		display: flex;
		gap: var(--s3);
		align-items: flex-start;
		margin-top: var(--s4);
		max-width: 72ch;
		cursor: pointer;
	}
	.active-gate input {
		margin-top: 3px;
		flex: none;
		accent-color: var(--signal);
	}
	.active-gate span {
		display: grid;
		gap: 2px;
	}
	.gate-title {
		color: var(--text);
		font-size: var(--t-data);
	}
	.gate-note {
		color: var(--muted);
		font-size: var(--t-label);
		line-height: 1.5;
	}
	.hints {
		display: grid;
		gap: var(--s2);
		margin-top: var(--s3);
		max-width: 72ch;
	}
	.hints textarea {
		width: 100%;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		color: var(--text);
		font-family: var(--mono);
		font-size: var(--t-data);
		line-height: 1.5;
		resize: vertical;
	}
	.hints textarea:focus-visible {
		border-color: var(--rule-bright);
		outline: none;
	}
	.hints .gate-note {
		margin: 0;
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

	.scan-failure {
		display: grid;
		gap: var(--s3);
		max-width: 78ch;
	}

	.scan-error {
		margin: 0;
		padding: var(--s2) var(--s3);
		border: 1px solid var(--ink);
		border-radius: var(--radius);
		background: var(--panel-deep);
		color: var(--text);
		font-size: var(--t-data);
		overflow-wrap: anywhere;
	}

	.local-restart {
		display: grid;
		gap: var(--s3);
		padding: var(--s4);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		background: var(--panel-deep);
	}
	.local-restart-copy {
		display: grid;
		gap: var(--s1);
	}
	.local-restart h3,
	.local-restart p {
		margin: 0;
	}
	.local-restart h3 {
		font-size: var(--t-mid);
	}
	.local-restart-copy p,
	.local-restart-note {
		color: var(--text);
		font-size: var(--t-data);
		line-height: 1.5;
	}
	.local-restart .copy-error {
		font-size: var(--t-label);
	}

	.summary {
		margin: 0;
		color: var(--muted);
		font-size: var(--t-data);
		overflow-wrap: anywhere;
	}

	/* The workbench: a tree on the left, a preview on the right, the two halves
	   of a machined panel rather than a scrolling list. Depth comes from a
	   hairline and a shift of the panel hue, never a shadow. */
	.workbench {
		display: grid;
		grid-template-columns: minmax(240px, 22rem) 1fr;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		overflow: hidden;
		min-height: 26rem;
	}

	.tree {
		border-right: 1px solid var(--rule);
		background: var(--panel-deep);
		overflow-y: auto;
		max-height: 34rem;
	}

	.cat:not(:first-child) .cat-head {
		border-top: 1px solid var(--rule);
	}
	.cat-head {
		display: flex;
		align-items: center;
		gap: var(--s2);
		width: 100%;
		padding: var(--s2) var(--s3);
		background: none;
		border: 0;
		color: var(--text);
		cursor: pointer;
		text-align: left;
	}
	.cat-head:hover {
		background: var(--panel);
	}
	.cat-label {
		flex: 1;
		color: var(--text);
	}
	.cat-count {
		color: var(--muted);
		font-size: var(--t-label);
	}
	.caret {
		width: 5px;
		height: 5px;
		border-right: 1px solid var(--muted);
		border-bottom: 1px solid var(--muted);
		transform: translateY(-1px) rotate(-45deg);
		transition: transform 160ms var(--ease);
	}
	.caret.open {
		transform: translateY(-2px) rotate(45deg);
	}

	.items {
		list-style: none;
		margin: 0;
		padding: 0 0 var(--s2);
	}
	.item {
		display: flex;
		align-items: center;
		gap: var(--s2);
		width: 100%;
		padding: var(--s1) var(--s3) var(--s1) var(--s5);
		background: none;
		border: 0;
		border-left: 2px solid transparent;
		color: var(--muted);
		font-size: var(--t-label);
		text-align: left;
		cursor: pointer;
		transition: color 140ms var(--ease);
	}
	.item:hover {
		color: var(--text);
	}
	.item.on {
		color: var(--text);
		background: var(--panel);
		border-left-color: var(--signal);
	}
	.item-label {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.item-label.flagged {
		color: var(--signal);
	}
	.thumb {
		width: 18px;
		height: 18px;
		object-fit: cover;
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		flex: none;
		background: var(--ground);
	}

	.preview {
		padding: var(--s5);
		overflow-y: auto;
		max-height: 34rem;
		display: flex;
		flex-direction: column;
		gap: var(--s3);
	}
	.d-head {
		display: flex;
		align-items: center;
		gap: var(--s2);
	}
	.d-kind {
		color: var(--muted);
	}
	.d-value {
		margin: 0;
		font-size: var(--t-mid);
		color: var(--text);
		overflow-wrap: anywhere;
	}
	.d-value.flagged {
		color: var(--signal);
	}
	.where {
		margin: 0;
		color: var(--muted);
		font-size: var(--t-data);
	}
	.where a {
		color: var(--muted);
		transition: color 140ms var(--ease);
	}
	.where a:hover {
		color: var(--text);
	}
	.how {
		margin: var(--s2) 0 0;
		color: var(--muted);
		font-size: var(--t-data);
	}
	.how .label {
		margin-right: var(--s2);
	}
	.d-block {
		margin: 0;
		padding: var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		color: var(--text);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		user-select: all;
	}
	.d-list h4 {
		margin: 0 0 var(--s2);
	}
	.plain {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s1);
	}
	.plain li {
		font-size: var(--t-data);
		overflow-wrap: anywhere;
	}
	.plain .flagged {
		color: var(--signal);
	}
	.plain .comment {
		color: var(--muted);
		padding: var(--s1) var(--s2);
		border-left: 1px solid var(--rule);
		white-space: pre-wrap;
	}

	.shot {
		display: flex;
		justify-content: center;
		padding: var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
	}
	.shot img {
		max-width: 100%;
		max-height: 22rem;
		object-fit: contain;
	}

	.actions {
		display: flex;
		align-items: center;
		gap: var(--s3);
	}
	.do {
		padding: var(--s2) var(--s4);
		background: var(--panel-lift);
		border: 1px solid var(--signal);
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
	.do:hover:not(:disabled) {
		background: var(--rule);
	}
	.do:disabled {
		color: var(--muted);
		border-color: var(--rule);
		cursor: default;
	}
	.open {
		color: var(--muted);
		font-size: var(--t-label);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-weight: 600;
		transition: color 140ms var(--ease);
	}
	.open:hover {
		color: var(--text);
	}
	.chip {
		font-size: var(--t-label);
		color: var(--muted);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		padding: 0 var(--s1);
	}
	.chip.bad {
		color: var(--signal);
		border-color: var(--ink);
	}
	.clear {
		margin: auto;
		color: var(--muted);
		font-size: var(--t-data);
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

	@media (max-width: 768px) {
		.workbench {
			grid-template-columns: 1fr;
		}
		.tree {
			border-right: 0;
			border-bottom: 1px solid var(--rule);
			max-height: 16rem;
		}
	}

	@media (max-width: 640px) {
		.recon {
			padding: var(--s4);
		}
		.command {
			flex-direction: column;
		}
		.command button {
			padding: var(--s3) var(--s4);
		}
	}
</style>
