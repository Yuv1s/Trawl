import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),

	compilerOptions: {
		// Force runes mode everywhere except libraries, so no legacy `$:` reactivity
		// creeps in. Can be removed in Svelte 6, where runes are the only mode.
		runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true)
	},

	kit: {
		// Every route is prerendered (see src/routes/+layout.ts) and all analysis runs in
		// the browser, so the output is plain static files. There is no server to deploy.
		adapter: adapter()
	}
};

export default config;
