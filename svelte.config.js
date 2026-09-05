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
		adapter: adapter(),

		// A content-security policy, which matters more here than on an ordinary site:
		// this tool decodes untrusted files and renders what falls out of them, a flag
		// pulled from a stream, a string peeled from an encoding, a name read out of a
		// binary. If any of that ever reached the DOM as markup, the policy is what keeps
		// it from running. Prerendered pages get SHA-256 hashes for the one inline script
		// (the pre-paint theme switch in app.html) and the framework's own, so nothing
		// else executes.
		//
		// script-src carries no 'unsafe-inline'; that is the whole point. wasm-unsafe-eval
		// is for the analysis engine, which is WebAssembly. style-src keeps 'unsafe-inline'
		// because the data-driven bars and the tour's spotlight set dimensions through the
		// style attribute, and Svelte externalises component CSS so no style hash is added
		// that would cancel it. connect-src reaches the loopback scanner Remora runs, and
		// nowhere else off-origin.
		csp: {
			mode: 'hash',
			directives: {
				'default-src': ['self'],
				'script-src': ['self', 'wasm-unsafe-eval'],
				'style-src': ['self', 'unsafe-inline'],
				'img-src': ['self', 'data:', 'blob:'],
				'font-src': ['self'],
				'connect-src': ['self', 'http://127.0.0.1:*', 'http://localhost:*'],
				'worker-src': ['self', 'blob:'],
				'manifest-src': ['self'],
				'object-src': ['none'],
				'base-uri': ['self'],
				'form-action': ['self'],
				'frame-ancestors': ['none']
			}
		}
	}
};

export default config;
