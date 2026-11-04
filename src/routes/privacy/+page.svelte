<script lang="ts">
	import Legal from '$lib/components/Legal.svelte';
</script>

<svelte:head>
	<title>Privacy · Trawl</title>
	<meta name="description" content="Trawl has no server and collects nothing." />
</svelte:head>

<Legal title="Privacy">
	<p>
		Trawl collects nothing about you or your files. The site is a set of static files, with no
		backend, API, database or analytics behind it.
	</p>

	<h2>Your files</h2>
	<p>
		Files you open are read into browser memory and analysed there. Trawl never uploads them or
		changes them, and it only writes to disk when you choose to save something. Closing the tab
		discards them.
	</p>

	<h2>What is stored on your machine</h2>
	<p>
		Trawl sets no cookies and keeps no history of what you analysed. It keeps four small settings in
		your browser's <code>localStorage</code>: your theme, whether you took the tour, your flag
		formats, and the token that pairs this page with the Remora scanner. None of them says anything
		about your files, and clearing this site's data removes them. When you open an image in a new
		tab from Web exploration, its address sits there too until that tab reads it. Your browser may
		also cache the application files, as it does for any site.
	</p>

	<h2>Network requests</h2>
	<p>
		The page loads its code and fonts from this site, so no outside service sees that you visited.
		Analysing a file or a pasted string makes no network requests after that, and the open tab keeps
		working if you pull the network cable. The demos panel fetches a sample from this site when you
		run one. You can check all of this in your browser's network panel.
	</p>

	<h2>Web exploration</h2>
	<p>
		Remora is the one part of Trawl that reaches other sites, and it only runs if you start its
		scanner yourself. The install line downloads the scanner from GitHub. After that the page talks
		to the scanner on your own machine, and the scanner talks to the target you name. None of that
		traffic reaches this site.
	</p>

	<h2>Third parties</h2>
	<p>Trawl has no embeds, trackers, advertising or error reporting services.</p>

	<h2>Hosting</h2>
	<p>
		Whoever hosts these static files may keep standard server logs, such as IP addresses and
		requested paths. Those logs cover page loads only. The contents of files you analyse never reach
		the network, so they can't appear in any log.
	</p>
</Legal>
