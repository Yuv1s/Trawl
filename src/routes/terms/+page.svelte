<script lang="ts">
	import Legal from '$lib/components/Legal.svelte';
</script>

<svelte:head>
	<title>Terms · Trawl</title>
	<meta name="description" content="MIT licensed, provided as is, and yours to use responsibly." />
</svelte:head>

<Legal title="Terms">
	<h2>Licence</h2>
	<p>
		Trawl is released under the MIT licence. You may use, copy, modify and redistribute it,
		including commercially, provided the copyright notice and licence text travel with it.
	</p>

	<h2>No warranty</h2>
	<p>
		The software is provided as is, without warranty of any kind. Analysis results come from
		statistical tests and parsers, and they can be wrong. Treat a finding as evidence to check. An
		empty result means the checks that ran found nothing, and the file may still hide something.
		Verify anything you intend to rely on.
	</p>

	<h2>Responsible use</h2>
	<p>
		Only analyse files you are permitted to analyse, and only scan sites you are authorised to test.
		Competition rules, disclosure agreements and local law are your responsibility. Trawl is built
		for capture-the-flag work, security education and forensics on material you have authorisation
		to examine.
	</p>

	<h2>No liability</h2>
	<p>
		The authors are not liable for any claim, damage or other liability arising from the software or
		its use, to the fullest extent permitted by law.
	</p>

	<h2>No service</h2>
	<p>
		Trawl comes with no account, support obligation or uptime commitment. If this site goes away,
		the source code stays available under the MIT licence and you can run your own copy.
	</p>
</Legal>
