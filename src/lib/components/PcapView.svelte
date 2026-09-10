<script lang="ts">
	import type { PcapCapture, PcapStream } from '$lib/worker/protocol';

	let { cap }: { cap: PcapCapture } = $props();

	const findings = $derived(
		cap.streams.filter((s) => s.flags.length > 0 || s.embeddedFile !== null)
	);

	function bytes(n: number): string {
		if (n < 1024) return `${n} B`;
		if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
		return `${(n / (1024 * 1024)).toFixed(1)} MB`;
	}

	const summary = $derived([
		{ key: 'Format', value: cap.format },
		{ key: 'Link layer', value: cap.linkType },
		{ key: 'Packets', value: cap.packetCount.toLocaleString() },
		{ key: 'On the wire', value: bytes(cap.captureBytes) },
		...(cap.duration ? [{ key: 'Span', value: cap.duration }] : [])
	]);

	const peakPackets = $derived(Math.max(1, ...cap.protocols.map((p) => p.packets)));

	function finding(stream: PcapStream): boolean {
		return stream.flags.length > 0 || stream.embeddedFile !== null;
	}
</script>

<div class="pcap">
	{#if findings.length > 0}
		<ul class="findings">
			{#each findings as stream (stream.src + stream.dst)}
				<li class="flagged">
					{#if stream.flags.length > 0}
						{stream.flags.length === 1 ? 'A flag' : `${stream.flags.length} flags`} reassembled from the
						stream <span class="mono">{stream.src} → {stream.dst}</span>, split across packets in
						the file
					{:else}
						A <span class="mono">{stream.embeddedFile}</span> carried whole over
						<span class="mono">{stream.src} → {stream.dst}</span>, its signature sitting mid-packet
					{/if}
				</li>
			{/each}
		</ul>
	{:else}
		<p class="clear">
			Every packet that carried a flag would carry it whole, and the byte scan already reads those.
			No stream reassembled into one, and no connection carried a file whose signature the file scan
			could not see. That is what an ordinary capture looks like.
		</p>
	{/if}

	<div class="info">
		<h3 class="label">Capture</h3>
		<dl>
			{#each summary as field (field.key)}
				<div>
					<dt class="label">{field.key}</dt>
					<dd class="mono">{field.value}</dd>
				</div>
			{/each}
		</dl>
	</div>

	{#if cap.protocols.length > 0}
		<section>
			<h3 class="label">Protocols</h3>
			<ul class="protocols">
				{#each cap.protocols as proto (proto.name)}
					<li>
						<span class="proto-name">{proto.name}</span>
						<span class="track" aria-hidden="true">
							<span class="fill" style="width: {(proto.packets / peakPackets) * 100}%"></span>
						</span>
						<span class="proto-count mono"
							>{proto.packets.toLocaleString()} · {bytes(proto.bytes)}</span
						>
					</li>
				{/each}
			</ul>
		</section>
	{/if}

	{#if cap.conversations.length > 0}
		<section>
			<h3 class="label">
				Conversations
				{#if cap.conversationCount > cap.conversations.length}
					<span class="count">top {cap.conversations.length} of {cap.conversationCount}</span>
				{/if}
			</h3>
			<div class="table-scroll">
				<table>
					<thead>
						<tr>
							<th scope="col" class="label">Endpoint</th>
							<th scope="col" class="label">Endpoint</th>
							<th scope="col" class="label">Via</th>
							<th scope="col" class="label num">Packets</th>
							<th scope="col" class="label num">Bytes</th>
						</tr>
					</thead>
					<tbody>
						{#each cap.conversations as conv (conv.a + conv.b + conv.protocol)}
							<tr>
								<td class="mono">{conv.a}</td>
								<td class="mono">{conv.b}</td>
								<td class="mono muted">{conv.protocol}</td>
								<td class="mono num">{conv.packets.toLocaleString()}</td>
								<td class="mono num">{bytes(conv.bytes)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}

	{#if cap.dns.length > 0}
		<section>
			<h3 class="label">DNS questions</h3>
			<ul class="dns">
				{#each cap.dns as query (query.name + query.type)}
					<li>
						<span class="mono name">{query.name}</span>
						<span class="mono muted">{query.type}</span>
					</li>
				{/each}
			</ul>
		</section>
	{/if}

	{#if cap.streams.length > 0}
		<section>
			<h3 class="label">
				Reassembled streams
				{#if cap.streamCount > cap.streams.length}
					<span class="count">{cap.streams.length} of {cap.streamCount}</span>
				{/if}
			</h3>
			<div class="streams">
				{#each cap.streams as stream (stream.src + stream.dst)}
					<article class="stream" class:hit={finding(stream)}>
						<header>
							<span class="mono flow" class:flagged={finding(stream)}
								>{stream.src} → {stream.dst}</span
							>
							<span class="mono muted">{bytes(stream.bytes)}</span>
							{#if stream.embeddedFile}
								<span class="mono chip">{stream.embeddedFile}</span>
							{/if}
						</header>
						{#each stream.flags as flag (flag)}
							<span class="mono big flagged">{flag}</span>
						{/each}
						<pre class="transcript mono" class:binary={stream.printable < 0.7}>{stream.text}</pre>
					</article>
				{/each}
			</div>
		</section>
	{/if}

	<p class="footnote">
		A flag shown in the accent came out of a reassembled stream, not the file. TCP breaks a stream
		into segments, and in the file the payload of one segment is followed by the headers of the
		packet carrying the next, so a flag crossing that boundary is interrupted by bytes that are not
		part of it. Following the sequence numbers and laying the payloads back in order is the only way
		it reads again.
	</p>
</div>

<style>
	.pcap {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: var(--s5);
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
		max-width: 82ch;
		text-wrap: pretty;
	}

	section {
		display: grid;
		gap: var(--s3);
	}

	h3.label {
		display: flex;
		align-items: baseline;
		gap: var(--s3);
		margin: 0;
	}

	.count {
		font-variant-numeric: tabular-nums;
		color: var(--muted);
		text-transform: none;
		letter-spacing: 0;
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
	}

	.protocols {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
	}

	.protocols li {
		display: grid;
		grid-template-columns: 6rem minmax(0, 1fr) auto;
		align-items: center;
		gap: var(--s3);
	}

	.proto-name {
		font-size: var(--t-data);
		color: var(--text);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.track {
		height: 4px;
		background: var(--panel-deep);
		border: 1px solid var(--rule);
		overflow: hidden;
	}

	.fill {
		display: block;
		height: 100%;
		background: var(--muted);
	}

	.proto-count {
		color: var(--muted);
		font-size: var(--t-data);
		font-variant-numeric: tabular-nums;
	}

	.table-scroll {
		overflow-x: auto;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	th {
		text-align: left;
		padding: var(--s1) var(--s3) var(--s2) 0;
		border-bottom: 1px solid var(--rule);
		white-space: nowrap;
	}

	td {
		padding: var(--s1) var(--s3) var(--s1) 0;
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
		vertical-align: baseline;
		white-space: nowrap;
	}

	.num {
		text-align: right;
		font-variant-numeric: tabular-nums;
		padding-right: 0;
	}

	.dns {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s1);
	}

	.dns li {
		display: flex;
		align-items: baseline;
		gap: var(--s3);
		font-size: var(--t-data);
	}

	.dns .name {
		overflow-wrap: anywhere;
	}

	.streams {
		display: grid;
		gap: var(--s4);
	}

	.stream {
		display: grid;
		gap: var(--s2);
		padding: var(--s3);
		background: var(--panel-deep);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
	}

	/* A stream that carried a flag or a file reads like a finding, marked with
	   the accent stripe the way every other panel marks the byte worth reading. */
	.stream.hit {
		border-left: 2px solid var(--signal);
	}

	.stream header {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--s2) var(--s3);
	}

	.flow {
		font-weight: 600;
		color: var(--text);
	}

	.chip {
		font-size: var(--t-label);
		padding: 0 var(--s2);
		border: 1px solid var(--signal);
		color: var(--signal);
	}

	.big {
		font-size: var(--t-mid);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.flagged {
		color: var(--signal);
	}

	.muted {
		color: var(--muted);
	}

	.transcript {
		margin: 0;
		max-height: 16rem;
		overflow: auto;
		padding: var(--s2) var(--s3);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-data);
		line-height: 1.5;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text);
	}

	.transcript.binary {
		color: var(--muted);
	}

	.footnote {
		margin: 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 82ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
		text-wrap: pretty;
	}
</style>
