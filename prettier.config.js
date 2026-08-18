/** @type {import("prettier").Config} */
const config = {
	useTabs: true,
	singleQuote: true,
	trailingComma: 'none',
	printWidth: 100,
	// Git is set to check out CRLF on Windows, so pinning this to lf would make
	// `npm run lint` fail on a clean tree. What gets committed is lf either way.
	endOfLine: 'auto',
	plugins: ['prettier-plugin-svelte'],
	overrides: [{ files: '*.svelte', options: { parser: 'svelte' } }]
};

export default config;
