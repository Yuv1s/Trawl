// Fails if the production build hands a browser something it should not have: source maps,
// secrets, private paths or addresses, debug calls, or comments left for the next editor.
//
//   npm run build && npm run exposure
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';

const BUILD = 'build';
const TEXT = new Set(['.html', '.js', '.css', '.json', '.svg', '.txt', '.md']);

const SECRETS = [
	['an AWS key', /AKIA[0-9A-Z]{16}/],
	['a GitHub token', /gh[pousr]_[A-Za-z0-9]{36}/],
	['a private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
	['an API key', /\bsk-[A-Za-z0-9_-]{32,}/],
	['a Slack token', /xox[baprs]-[A-Za-z0-9-]{20,}/]
];

const PRIVATE = [
	['a Windows user path', /[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+/],
	['a home directory', /\/(?:home|Users)\/[a-z0-9._-]+\/[A-Za-z.]/],
	['an email address', /[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|proton)\.[a-z]+/]
];

const DEBUG = [
	['a debugger statement', /\bdebugger;/],
	['a console.log call', /\bconsole\.(?:log|debug)\(/]
];

// Svelte's hydration markers and head anchors are the only comments a page should carry.
const COMMENT = /<!--(?!\[|\]|-*>|[a-z0-9]{5,9}-->)[\s\S]*?-->/;

// The samples are test data, and hold planted strings on purpose.
const isSample = (path) => relative(BUILD, path).startsWith('samples');

function* files(dir) {
	for (const name of readdirSync(dir)) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) yield* files(path);
		else yield path;
	}
}

const problems = [];
const report = (path, what) => problems.push(`${relative(BUILD, path)}: ${what}`);
let checked = 0;

for (const path of files(BUILD)) {
	if (isSample(path)) continue;
	checked += 1;

	const extension = extname(path).toLowerCase();
	if (extension === '.map') report(path, 'a source map');
	if (/(^|[\\/])\.env/.test(path)) report(path, 'an env file');

	// Compiled wasm is read for secrets too. Its panic messages name the paths it was built
	// from, which say nothing private on a build server and are not worth failing a local build.
	if (extension === '.wasm') {
		const bytes = readFileSync(path).toString('latin1');
		for (const [what, shape] of SECRETS) if (shape.test(bytes)) report(path, what);
		continue;
	}
	if (!TEXT.has(extension)) continue;

	const text = readFileSync(path, 'utf8');
	if (text.includes('sourceMappingURL')) report(path, 'a source map reference');
	for (const [what, shape] of [...SECRETS, ...PRIVATE, ...DEBUG]) {
		if (shape.test(text)) report(path, what);
	}
	if (extension === '.html' && COMMENT.test(text)) report(path, 'an HTML comment');
}

if (checked === 0) {
	console.error('Nothing to check. Run npm run build first.');
	process.exit(1);
}

if (problems.length > 0) {
	console.error(`The build exposes ${problems.length} thing(s) it should not:`);
	for (const problem of problems) console.error(`  ${problem}`);
	process.exit(1);
}

console.log(`Checked ${checked} files. Nothing exposed.`);
