<script lang="ts">
	import type { RegistryHive } from '$lib/worker/protocol';

	let { hive }: { hive: RegistryHive } = $props();

	const devices = $derived(hive.devices);

	/** A device's model in one line, from whichever of the parts the key
	 *  actually named. A USB key names a device numerically, so there may be
	 *  nothing but the vendor field to show. */
	const model = (device: RegistryHive['devices'][number]) =>
		[device.vendor, device.product].filter(Boolean).join(' ') || device.serial;

	const summary = $derived([
		{ key: 'Hive', value: hive.kind },
		{ key: 'Version', value: hive.version },
		...(hive.fileName ? [{ key: 'Path', value: hive.fileName }] : []),
		...(hive.written ? [{ key: 'Written', value: hive.written }] : []),
		{ key: 'Root', value: hive.root }
	]);
</script>

<div class="hive">
	{#if devices.length > 0}
		<ul class="findings">
			{#each devices as device, index (index)}
				<li class="flagged">
					<span class="mono big">{model(device)}</span>
					<span class="muted">
						last written <span class="mono"
							>{device.lastWritten || 'at a time the key does not say'}</span
						>, out of <span class="mono">{device.source}</span>
					</span>
				</li>
			{/each}
		</ul>
	{:else}
		<div class="clear">
			<p>
				{#if hive.searched.length > 0}
					This hive keeps device history and has none in it. Nothing was ever plugged into the
					machine it came from, or the keys were cleared.
				{:else}
					A {hive.kind} does not keep USB history, so there is nothing here to find. The hive that does
					is SYSTEM, and the per-user half of it is in an NTUSER.DAT.
				{/if}
			</p>
			{#if hive.searched.length > 0}
				<ul class="paths">
					{#each hive.searched as path (path)}
						<li class="mono">{path}</li>
					{/each}
				</ul>
			{/if}
		</div>
	{/if}

	<div class="info">
		<h3 class="label">Header</h3>
		<dl>
			{#each summary as field (field.key)}
				<div>
					<dt class="label">{field.key}</dt>
					<dd class="mono">{field.value}</dd>
				</div>
			{/each}
		</dl>
	</div>

	{#if devices.length > 0}
		<table>
			<caption class="label">
				{devices.length} device{devices.length === 1 ? '' : 's'}, as the hive remembers them
			</caption>
			<thead>
				<tr>
					<th scope="col" class="label">Device</th>
					<th scope="col" class="label">Revision</th>
					<th scope="col" class="label">Serial</th>
					<th scope="col" class="label">Last written</th>
					<th scope="col" class="label">From</th>
				</tr>
			</thead>
			<tbody>
				{#each devices as device, index (index)}
					<tr class="odd">
						<td>
							<span class="mono name">{model(device)}</span>
							{#if device.friendlyName}
								<div class="muted sub">{device.friendlyName}</div>
							{/if}
						</td>
						<td class="mono muted">{device.revision || '—'}</td>
						<td>
							<span class="mono name">{device.serial}</span>
							{#if device.generatedSerial}
								<span
									class="chip"
									title="Windows generated this, so it names the port rather than the device"
									>not the device's own</span
								>
							{/if}
						</td>
						<td class="mono">{device.lastWritten || '—'}</td>
						<td class="mono muted">{device.source}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	{#if hive.top.length > 0}
		<table>
			<caption class="label">{hive.top.length} keys at the root</caption>
			<thead>
				<tr>
					<th scope="col" class="label">Key</th>
					<th scope="col" class="label num">Subkeys</th>
					<th scope="col" class="label num">Values</th>
					<th scope="col" class="label">Last written</th>
				</tr>
			</thead>
			<tbody>
				{#each hive.top as key (key.name)}
					<tr>
						<td><span class="mono name">{key.name}</span></td>
						<td class="mono num">{key.subkeys.toLocaleString()}</td>
						<td class="mono num">{key.values.toLocaleString()}</td>
						<td class="mono muted">{key.written || '—'}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<p class="footnote">
		A timestamp here is when Windows last wrote the key, which for a device key is normally a
		connection and occasionally a driver doing something else. It is evidence of when, not a log of
		what: nothing in a hive says a device was ever unplugged.
		{#if devices.some((d) => d.generatedSerial)}
			A serial marked as not the device's own was invented by Windows because the device reported
			none, so it belongs to the port it was plugged into rather than travelling with the stick.
		{/if}
	</p>
</div>

<style>
	.hive {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: var(--s4);
	}

	.clear {
		display: grid;
		gap: var(--s3);
		color: var(--muted);
		max-width: 72ch;
		line-height: 1.6;
	}

	.clear p {
		margin: 0;
		text-wrap: pretty;
	}

	/* Where it looked, which is what makes an empty result mean something. */
	.paths {
		list-style: none;
		margin: 0;
		padding: var(--s3);
		display: grid;
		gap: var(--s1);
		background: var(--ground);
		border: 1px solid var(--rule);
		border-radius: var(--radius);
		font-size: var(--t-label);
		overflow-wrap: anywhere;
	}

	.findings {
		list-style: none;
		margin: 0;
		padding: 0;
		display: grid;
		gap: var(--s2);
	}

	.findings li {
		display: grid;
		gap: 2px;
		padding-left: var(--s3);
		border-left: 1px solid var(--rule);
		color: var(--muted);
		line-height: 1.5;
		max-width: 78ch;
		text-wrap: pretty;
	}

	.findings li.flagged {
		border-left-color: var(--signal);
		color: var(--text);
	}

	.big {
		font-size: var(--t-mid);
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
		overflow-wrap: anywhere;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--t-data);
	}

	caption {
		text-align: left;
		padding-bottom: var(--s2);
	}

	th {
		text-align: left;
		padding: var(--s2) var(--s3);
		border-bottom: 1px solid var(--rule);
		position: sticky;
		top: 0;
		background: var(--panel);
	}

	.num {
		text-align: right;
	}

	td {
		padding: var(--s1) var(--s3);
		border-bottom: 1px solid color-mix(in srgb, var(--rule) 45%, transparent);
		vertical-align: baseline;
	}

	.name {
		overflow-wrap: anywhere;
	}

	.sub {
		font-size: var(--t-label);
	}

	tr.odd td:first-child {
		box-shadow: inset 2px 0 0 var(--signal);
	}

	/* The one inference this panel makes outright, so it is marked on the
	   field it changes the meaning of rather than left to the footnote. */
	.chip {
		margin-left: var(--s2);
		font-size: var(--t-label);
		color: var(--muted);
		border: 1px dashed var(--rule-bright);
		border-radius: var(--radius);
		padding: 1px var(--s2);
		white-space: nowrap;
	}

	.muted {
		color: var(--muted);
	}

	.footnote {
		margin: 0;
		padding-top: var(--s3);
		border-top: 1px solid var(--rule);
		max-width: 78ch;
		font-size: var(--t-label);
		color: var(--muted);
		line-height: 1.6;
		text-wrap: pretty;
	}

	@media (max-width: 640px) {
		table {
			display: block;
			overflow-x: auto;
			white-space: nowrap;
		}

		.name {
			overflow-wrap: normal;
		}
	}
</style>
