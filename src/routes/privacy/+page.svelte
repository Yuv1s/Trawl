<script lang="ts">
	import Legal from '$lib/components/Legal.svelte';
</script>

<svelte:head>
	<title>Privacy — Trawl</title>
	<meta name="description" content="Trawl collects nothing. There is no server to collect it." />
</svelte:head>

<Legal title="Privacy">
	<p>
		Trawl collects nothing, because there is nowhere for it to send anything. The site is a set of
		static files. It has no backend, no API, no database and no analytics.
	</p>

	<h2>Your files</h2>
	<p>
		Files you open are read into browser memory and analysed there. They are never uploaded, never
		written to disk by this app, and never modified. Closing the tab discards them.
	</p>

	<h2>What is stored on your machine</h2>
	<p>
		Nothing. Trawl sets no cookies, writes no <code>localStorage</code>, and keeps no history of
		what you analysed. Your browser may cache the application files themselves so it keeps working
		offline, which is standard browser behaviour and holds no information about your files.
	</p>

	<h2>Network requests</h2>
	<p>
		After the page and its fonts load, Trawl makes no further network requests. Fonts are served
		from this same site rather than a third party, so no outside service sees that you visited. You
		can verify all of this in your browser's network panel, or by pulling the network cable and
		continuing to work.
	</p>

	<h2>Third parties</h2>
	<p>There are none. No embeds, no trackers, no advertising, no error reporting service.</p>

	<h2>Hosting</h2>
	<p>
		Whoever hosts these static files may keep standard server logs, such as IP addresses and
		requested paths. That is the host's doing and covers page loads only. The contents of files you
		analyse never reach the network, so they cannot appear in any log.
	</p>
</Legal>
